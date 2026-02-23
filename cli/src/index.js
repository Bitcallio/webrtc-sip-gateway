"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { Command } = require("commander");

const {
  GATEWAY_DIR,
  SERVICE_NAME,
  SERVICE_FILE,
  ACME_WEBROOT,
  SSL_DIR,
  ENV_PATH,
  COMPOSE_PATH,
  DEFAULT_GATEWAY_IMAGE,
  DEFAULT_PROVIDER_HOST,
  DEFAULT_WEBPHONE_ORIGIN,
  RENEW_HOOK_PATH,
} = require("../lib/constants");
const { run, runShell, output, commandExists } = require("../lib/shell");
const { loadEnvFile, parseEnv, writeEnvFile } = require("../lib/envfile");
const { Prompter } = require("../lib/prompt");
const {
  parseOsRelease,
  isSupportedDistro,
  detectPublicIp,
  resolveDomainIpv4,
  diskFreeGb,
  memoryTotalMb,
  portInUse,
  ensureDockerInstalled,
  ensureComposePlugin,
} = require("../lib/system");
const { readTemplate, renderTemplate } = require("../lib/template");

const PACKAGE_VERSION = "0.2.0";

function detectComposeCommand() {
  if (run("docker", ["compose", "version"], { check: false }).status === 0) {
    return { command: "docker", prefixArgs: ["compose"] };
  }
  if (run("docker-compose", ["version"], { check: false }).status === 0) {
    return { command: "docker-compose", prefixArgs: [] };
  }
  throw new Error("docker compose not found. Install Docker compose plugin.");
}

function runCompose(args, options = {}) {
  const compose = detectComposeCommand();
  return run(compose.command, [...compose.prefixArgs, ...args], {
    cwd: GATEWAY_DIR,
    ...options,
  });
}

function ensureInitialized() {
  if (!fs.existsSync(ENV_PATH) || !fs.existsSync(COMPOSE_PATH)) {
    throw new Error("Gateway is not initialized. Run: sudo bitcall-gateway init");
  }
}

function ensureDir(target, mode) {
  fs.mkdirSync(target, { recursive: true, mode });
  fs.chmodSync(target, mode);
}

function writeFileWithMode(filePath, content, mode) {
  fs.writeFileSync(filePath, content, { mode });
  fs.chmodSync(filePath, mode);
}

function maskValue(key, value) {
  if (/secret|token|password|key/i.test(key)) {
    return value ? "***" : "";
  }
  return value;
}

function envOrder() {
  return [
    "GATEWAY_VERSION",
    "BITCALL_GATEWAY_IMAGE",
    "DOMAIN",
    "PUBLIC_IP",
    "DEPLOY_MODE",
    "SIP_PROVIDER_URI",
    "SIP_UPSTREAM_TRANSPORT",
    "SIP_UPSTREAM_PORT",
    "ALLOWED_SIP_DOMAINS",
    "SIP_TRUSTED_IPS",
    "TURN_MODE",
    "TURN_SECRET",
    "TURN_TTL",
    "TURN_API_TOKEN",
    "WEBPHONE_ORIGIN",
    "WEBPHONE_ORIGIN_PATTERN",
    "TLS_MODE",
    "TLS_CERT",
    "TLS_KEY",
    "ACME_EMAIL",
    "ACME_LISTEN_PORT",
    "WSS_LISTEN_PORT",
    "INTERNAL_WSS_PORT",
    "INTERNAL_WS_PORT",
    "RTPENGINE_MIN_PORT",
    "RTPENGINE_MAX_PORT",
    "WITH_REVERSE_PROXY",
    "WITH_SIP_TLS",
  ];
}

function asEnvEntries(envMap) {
  const keys = Object.keys(envMap);
  const order = envOrder();
  const sorted = [];

  for (const key of order) {
    if (Object.prototype.hasOwnProperty.call(envMap, key)) {
      sorted.push({ key, value: envMap[key] });
    }
  }

  const extra = keys
    .filter((key) => !order.includes(key))
    .sort((a, b) => a.localeCompare(b));

  for (const key of extra) {
    sorted.push({ key, value: envMap[key] });
  }

  return sorted;
}

function saveGatewayEnv(envMap) {
  writeEnvFile(ENV_PATH, asEnvEntries(envMap), 0o600);
  fs.chmodSync(ENV_PATH, 0o600);
}

function updateGatewayEnv(changes) {
  const envMap = loadEnvFile(ENV_PATH);
  Object.assign(envMap, changes);
  saveGatewayEnv(envMap);
}

function buildSystemdService() {
  const dockerPath = output("sh", ["-lc", "command -v docker"]);
  return `[Unit]
Description=Bitcall WebRTC-to-SIP Gateway
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${GATEWAY_DIR}
ExecStart=${dockerPath} compose up -d --remove-orphans
ExecStop=${dockerPath} compose down
ExecReload=${dockerPath} compose restart
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
`;
}

function installSystemdService() {
  writeFileWithMode(SERVICE_FILE, buildSystemdService(), 0o644);
  run("systemctl", ["daemon-reload"], { stdio: "inherit" });
  run("systemctl", ["enable", SERVICE_NAME], { stdio: "inherit" });
}

function configureFirewall(config) {
  if (!commandExists("ufw")) {
    return;
  }

  const rules = [
    ["22/tcp", "SSH"],
    ["80/tcp", "Bitcall ACME"],
    ["443/tcp", "Bitcall WSS"],
    ["5060/udp", "Bitcall SIP UDP"],
    ["5060/tcp", "Bitcall SIP TCP"],
    [`${config.rtpMin}:${config.rtpMax}/udp`, "Bitcall RTP"],
  ];

  if (config.sipTransport === "tls") {
    rules.push(["5061/tcp", "Bitcall SIP TLS"]);
  }

  for (const [port, label] of rules) {
    run("ufw", ["allow", port, "comment", label], {
      check: false,
      stdio: "ignore",
    });
  }

  run("ufw", ["--force", "enable"], { check: false, stdio: "ignore" });
  run("ufw", ["reload"], { check: false, stdio: "ignore" });
}

function generateSelfSigned(certPath, keyPath, domain, days = 1) {
  ensureDir(path.dirname(certPath), 0o700);
  run(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-days",
      String(days),
      "-nodes",
      "-subj",
      `/CN=${domain}`,
    ],
    { stdio: "inherit" }
  );
  fs.chmodSync(certPath, 0o644);
  fs.chmodSync(keyPath, 0o600);
}

function validateCustomCert(certPath, keyPath, domain) {
  if (!fs.existsSync(certPath)) {
    throw new Error(`Certificate file not found: ${certPath}`);
  }
  if (!fs.existsSync(keyPath)) {
    throw new Error(`Private key file not found: ${keyPath}`);
  }

  const certMod = output("sh", ["-lc", `openssl x509 -noout -modulus -in '${certPath}' | md5sum | awk '{print $1}'`]);
  const keyMod = output("sh", ["-lc", `openssl rsa -noout -modulus -in '${keyPath}' | md5sum | awk '{print $1}'`]);

  if (!certMod || certMod !== keyMod) {
    throw new Error("Certificate and private key do not match.");
  }

  const certCheck = run("openssl", ["x509", "-checkend", "0", "-noout", "-in", certPath], {
    check: false,
  });
  if (certCheck.status !== 0) {
    throw new Error("Certificate is expired.");
  }

  const sans = output("sh", ["-lc", `openssl x509 -noout -text -in '${certPath}' | grep -o 'DNS:[^,]*' | tr '\n' ',' || true`]);
  if (domain && sans && !sans.includes(`DNS:${domain}`)) {
    console.log(`Warning: certificate SANs do not explicitly include ${domain}`);
  }
}

function certStatusFromPath(certPath) {
  if (!certPath || !fs.existsSync(certPath)) {
    return null;
  }

  const issuer = output("openssl", ["x509", "-in", certPath, "-noout", "-issuer"]);
  const subject = output("openssl", ["x509", "-in", certPath, "-noout", "-subject"]);
  const endDateRaw = output("openssl", ["x509", "-in", certPath, "-noout", "-enddate"]);
  const endDate = endDateRaw.replace(/^notAfter=/, "").trim();

  const endMs = Date.parse(endDate);
  const days = Number.isFinite(endMs) ? Math.floor((endMs - Date.now()) / 86400000) : null;

  return {
    issuer,
    subject,
    endDate,
    days,
  };
}

function installRenewHook() {
  ensureDir(path.dirname(RENEW_HOOK_PATH), 0o755);
  const script = `#!/bin/sh
set -eu
systemctl reload ${SERVICE_NAME}
`;
  writeFileWithMode(RENEW_HOOK_PATH, script, 0o755);
}

function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function toOriginPattern(origin) {
  if (!origin || origin === "*") {
    return ".*";
  }
  return `^${escapeRegex(origin)}$`;
}

async function runPreflight() {
  if (process.platform !== "linux") {
    throw new Error("bitcall-gateway supports Linux hosts only.");
  }

  const os = parseOsRelease();
  if (!isSupportedDistro()) {
    console.log(
      `Warning: unsupported distro ${os.PRETTY_NAME || "unknown"}. Expected Ubuntu 22+ or Debian 12+.`
    );
  }

  run("apt-get", ["update"], { stdio: "inherit" });
  run("apt-get", ["install", "-y", "curl", "ca-certificates", "lsof", "openssl", "gnupg"], {
    stdio: "inherit",
  });

  ensureDockerInstalled();
  ensureComposePlugin();

  const freeGb = diskFreeGb("/");
  if (freeGb < 2) {
    throw new Error(`At least 2GB free disk space required. Available: ${freeGb}GB`);
  }

  const ramMb = memoryTotalMb();
  if (ramMb < 1024) {
    console.log(`Warning: low memory detected (${ramMb}MB).`);
  }

  const p80 = portInUse(80);
  const p443 = portInUse(443);
  const p5060 = portInUse(5060);

  if (p5060.inUse) {
    throw new Error(`Port 5060 is already in use:\n${p5060.detail}`);
  }

  return {
    p80,
    p443,
  };
}

async function runWizard(existing = {}, preflight = {}) {
  const prompt = new Prompter();

  try {
    const detectedIp = detectPublicIp();
    const domain = await prompt.askText("Gateway domain", existing.DOMAIN || "", { required: true });
    const publicIp = await prompt.askText("Public IP", existing.PUBLIC_IP || detectedIp, {
      required: true,
    });

    const resolved = resolveDomainIpv4(domain);
    if (resolved.length > 0 && !resolved.includes(publicIp)) {
      console.log(`Warning: DNS for ${domain} resolves to ${resolved.join(", ")}, not ${publicIp}.`);
    }

    const conflictModeDefault =
      (preflight.p80 && preflight.p80.inUse) || (preflight.p443 && preflight.p443.inUse)
        ? 1
        : 0;
    const deployMode = await prompt.askChoice(
      "Deployment mode",
      ["standalone", "reverse-proxy"],
      conflictModeDefault
    );

    if (deployMode === "reverse-proxy") {
      console.log("Note: forward /turn-credentials and websocket upgrade to 127.0.0.1:8443, and ACME path to 127.0.0.1:8080.");
    }

    const tlsMode = await prompt.askChoice(
      "TLS certificate mode",
      ["letsencrypt", "custom", "dev-self-signed"],
      0
    );

    let acmeEmail = existing.ACME_EMAIL || "";
    let customCertPath = "";
    let customKeyPath = "";

    if (tlsMode === "letsencrypt") {
      acmeEmail = await prompt.askText("Let's Encrypt email", acmeEmail, { required: true });
    } else if (tlsMode === "custom") {
      customCertPath = await prompt.askText("Path to TLS certificate (PEM)", existing.TLS_CERT || "", {
        required: true,
      });
      customKeyPath = await prompt.askText("Path to TLS private key (PEM)", existing.TLS_KEY || "", {
        required: true,
      });
    }

    const sipProviderHost = await prompt.askText(
      "SIP provider host",
      existing.SIP_PROVIDER_URI
        ? existing.SIP_PROVIDER_URI.replace(/^sip:/, "").split(":")[0]
        : DEFAULT_PROVIDER_HOST,
      { required: true }
    );

    const sipTransportChoice = await prompt.askChoice(
      "SIP provider transport",
      ["udp", "tcp", "tls", "custom"],
      0
    );

    let sipTransport = sipTransportChoice;
    let sipPort = "5060";

    if (sipTransportChoice === "tcp" || sipTransportChoice === "udp") {
      sipPort = "5060";
    } else if (sipTransportChoice === "tls") {
      sipPort = "5061";
    } else {
      sipTransport = await prompt.askChoice("Custom transport", ["udp", "tcp", "tls"], 0);
      const defaultPort = sipTransport === "tls" ? "5061" : "5060";
      sipPort = await prompt.askText("Custom SIP port", defaultPort, { required: true });
    }

    const sipProviderUri = `sip:${sipProviderHost}:${sipPort};transport=${sipTransport}`;

    const allowedDomains = await prompt.askText(
      "Allowed SIP domains (comma-separated; blank enables dev mode)",
      existing.ALLOWED_SIP_DOMAINS || sipProviderHost
    );

    if (!allowedDomains.trim()) {
      console.log("Warning: ALLOWED_SIP_DOMAINS is empty (dev mode, open relay risk).");
    }

    const sipTrustedIps = await prompt.askText(
      "Trusted SIP source IPs (optional, comma-separated)",
      existing.SIP_TRUSTED_IPS || ""
    );

    const turnMode = await prompt.askChoice("TURN mode", ["none", "external", "coturn"], 0);

    let turnSecret = existing.TURN_SECRET || "";
    let turnTtl = existing.TURN_TTL || "86400";
    let turnApiToken = existing.TURN_API_TOKEN || "";
    let turnExternalUrls = "";
    let turnExternalUsername = "";
    let turnExternalCredential = "";

    if (turnMode === "external") {
      turnExternalUrls = await prompt.askText("External TURN urls", existing.TURN_EXTERNAL_URLS || "", {
        required: true,
      });
      turnExternalUsername = await prompt.askText(
        "External TURN username",
        existing.TURN_EXTERNAL_USERNAME || ""
      );
      turnExternalCredential = await prompt.askText(
        "External TURN credential",
        existing.TURN_EXTERNAL_CREDENTIAL || ""
      );
    }

    if (turnMode === "coturn") {
      turnSecret = crypto.randomBytes(32).toString("hex");
      turnTtl = await prompt.askText("TURN credential TTL seconds", turnTtl, { required: true });
      turnApiToken = await prompt.askText("TURN API token (optional)", turnApiToken);
    } else {
      turnSecret = "";
      turnApiToken = "";
    }

    const webphoneOrigin = await prompt.askText(
      "Allowed webphone origin (* for any)",
      existing.WEBPHONE_ORIGIN || DEFAULT_WEBPHONE_ORIGIN
    );

    const configureUfw = await prompt.askYesNo("Configure ufw firewall rules now", true);

    const config = {
      domain,
      publicIp,
      deployMode,
      tlsMode,
      acmeEmail,
      customCertPath,
      customKeyPath,
      sipProviderHost,
      sipTransport,
      sipPort,
      sipProviderUri,
      allowedDomains,
      sipTrustedIps,
      turnMode,
      turnSecret,
      turnTtl,
      turnApiToken,
      turnExternalUrls,
      turnExternalUsername,
      turnExternalCredential,
      webphoneOrigin,
      rtpMin: "10000",
      rtpMax: "20000",
      acmeListenPort: deployMode === "reverse-proxy" ? "8080" : "80",
      wssListenPort: deployMode === "reverse-proxy" ? "8443" : "443",
      internalWssPort: "8443",
      internalWsPort: "8080",
      configureUfw,
    };

    console.log("\nSummary:");
    console.log(`  Domain: ${config.domain}`);
    console.log(`  Public IP: ${config.publicIp}`);
    console.log(`  Deploy mode: ${config.deployMode}`);
    console.log(`  TLS mode: ${config.tlsMode}`);
    console.log(`  SIP provider URI: ${config.sipProviderUri}`);
    console.log(`  Allowed SIP domains: ${config.allowedDomains || "(empty/dev-mode)"}`);
    console.log(`  TURN mode: ${config.turnMode}`);

    const proceed = await prompt.askYesNo("Proceed with provisioning", true);
    if (!proceed) {
      throw new Error("Initialization canceled.");
    }

    return config;
  } finally {
    prompt.close();
  }
}

function ensureInstallLayout() {
  ensureDir(GATEWAY_DIR, 0o700);
  ensureDir(ACME_WEBROOT, 0o755);
  ensureDir(path.join(ACME_WEBROOT, ".well-known/acme-challenge"), 0o755);
  ensureDir(SSL_DIR, 0o700);

  const marker = path.join(ACME_WEBROOT, ".well-known/acme-challenge/healthcheck");
  writeFileWithMode(marker, "ok\n", 0o644);
}

function renderEnvContent(config, tlsCert, tlsKey) {
  const content = renderTemplate(".env.template", {
    GATEWAY_VERSION: PACKAGE_VERSION,
    BITCALL_GATEWAY_IMAGE: DEFAULT_GATEWAY_IMAGE,
    DOMAIN: config.domain,
    PUBLIC_IP: config.publicIp,
    DEPLOY_MODE: config.deployMode,
    SIP_PROVIDER_URI: config.sipProviderUri,
    SIP_UPSTREAM_TRANSPORT: config.sipTransport,
    SIP_UPSTREAM_PORT: config.sipPort,
    ALLOWED_SIP_DOMAINS: config.allowedDomains,
    SIP_TRUSTED_IPS: config.sipTrustedIps,
    TURN_MODE: config.turnMode,
    TURN_SECRET: config.turnSecret,
    TURN_TTL: config.turnTtl,
    TURN_API_TOKEN: config.turnApiToken,
    WEBPHONE_ORIGIN: config.webphoneOrigin,
    WEBPHONE_ORIGIN_PATTERN: toOriginPattern(config.webphoneOrigin),
    TLS_MODE: config.tlsMode,
    TLS_CERT: tlsCert,
    TLS_KEY: tlsKey,
    ACME_EMAIL: config.acmeEmail,
    ACME_LISTEN_PORT: config.acmeListenPort,
    WSS_LISTEN_PORT: config.wssListenPort,
    INTERNAL_WSS_PORT: config.internalWssPort,
    INTERNAL_WS_PORT: config.internalWsPort,
  });

  let extra = "";
  extra += `RTPENGINE_MIN_PORT=${config.rtpMin}\n`;
  extra += `RTPENGINE_MAX_PORT=${config.rtpMax}\n`;

  if (config.deployMode === "reverse-proxy") {
    extra += "WITH_REVERSE_PROXY=1\n";
  }
  if (config.sipTransport === "tls") {
    extra += "WITH_SIP_TLS=1\n";
  }
  if (config.turnMode === "external") {
    extra += `TURN_EXTERNAL_URLS=${config.turnExternalUrls}\n`;
    extra += `TURN_EXTERNAL_USERNAME=${config.turnExternalUsername}\n`;
    extra += `TURN_EXTERNAL_CREDENTIAL=${config.turnExternalCredential}\n`;
  }

  return content + extra;
}

function writeComposeTemplate() {
  const compose = readTemplate("docker-compose.yml.template");
  writeFileWithMode(COMPOSE_PATH, compose, 0o644);
}

function provisionCustomCert(config) {
  validateCustomCert(config.customCertPath, config.customKeyPath, config.domain);

  const certOut = path.join(SSL_DIR, "custom-cert.pem");
  const keyOut = path.join(SSL_DIR, "custom-key.pem");
  fs.copyFileSync(config.customCertPath, certOut);
  fs.copyFileSync(config.customKeyPath, keyOut);
  fs.chmodSync(certOut, 0o644);
  fs.chmodSync(keyOut, 0o600);

  return { certPath: certOut, keyPath: keyOut };
}

function startGatewayStack() {
  runCompose(["pull"], { stdio: "inherit" });
  runCompose(["up", "-d", "--remove-orphans"], { stdio: "inherit" });
}

function runLetsEncrypt(config) {
  run("apt-get", ["update"], { stdio: "inherit" });
  run("apt-get", ["install", "-y", "certbot"], { stdio: "inherit" });

  run(
    "certbot",
    [
      "certonly",
      "--webroot",
      "-w",
      ACME_WEBROOT,
      "-d",
      config.domain,
      "--email",
      config.acmeEmail,
      "--agree-tos",
      "--non-interactive",
    ],
    { stdio: "inherit" }
  );

  const liveCert = `/etc/letsencrypt/live/${config.domain}/fullchain.pem`;
  const liveKey = `/etc/letsencrypt/live/${config.domain}/privkey.pem`;

  updateGatewayEnv({
    TLS_CERT: liveCert,
    TLS_KEY: liveKey,
  });

  installRenewHook();
  runCompose(["up", "-d", "--remove-orphans"], { stdio: "inherit" });
}

function installGatewayService() {
  installSystemdService();
  run("systemctl", ["enable", "--now", SERVICE_NAME], { stdio: "inherit" });
}

async function initCommand() {
  const preflight = await runPreflight();

  let existingEnv = {};
  if (fs.existsSync(ENV_PATH)) {
    existingEnv = loadEnvFile(ENV_PATH);
  }

  const config = await runWizard(existingEnv, preflight);

  ensureInstallLayout();

  let tlsCertPath;
  let tlsKeyPath;

  if (config.tlsMode === "custom") {
    const custom = provisionCustomCert(config);
    tlsCertPath = custom.certPath;
    tlsKeyPath = custom.keyPath;
  } else if (config.tlsMode === "dev-self-signed") {
    tlsCertPath = path.join(SSL_DIR, "dev-fullchain.pem");
    tlsKeyPath = path.join(SSL_DIR, "dev-privkey.pem");
    generateSelfSigned(tlsCertPath, tlsKeyPath, config.domain, 30);
  } else {
    tlsCertPath = path.join(SSL_DIR, "bootstrap-fullchain.pem");
    tlsKeyPath = path.join(SSL_DIR, "bootstrap-privkey.pem");
    generateSelfSigned(tlsCertPath, tlsKeyPath, config.domain, 1);
  }

  const envContent = renderEnvContent(config, tlsCertPath, tlsKeyPath);
  writeFileWithMode(ENV_PATH, envContent, 0o600);
  writeComposeTemplate();

  if (config.configureUfw) {
    configureFirewall(config);
  }

  startGatewayStack();

  if (config.tlsMode === "letsencrypt") {
    runLetsEncrypt(config);
  }

  installGatewayService();

  console.log("\nGateway initialized.");
  console.log(`WSS URL: wss://${config.domain}`);
  if (config.turnMode !== "none") {
    console.log(`TURN credentials URL: https://${config.domain}/turn-credentials`);
  }
}

function runSystemctl(args, fallbackComposeArgs) {
  const result = run("systemctl", args, { check: false, stdio: "inherit" });
  if (result.status !== 0 && fallbackComposeArgs) {
    ensureInitialized();
    runCompose(fallbackComposeArgs, { stdio: "inherit" });
  }
}

function upCommand() {
  ensureInitialized();
  runSystemctl(["start", SERVICE_NAME], ["up", "-d", "--remove-orphans"]);
}

function downCommand() {
  ensureInitialized();
  runSystemctl(["stop", SERVICE_NAME], ["down"]);
}

function restartCommand() {
  ensureInitialized();
  runSystemctl(["reload", SERVICE_NAME], ["restart"]);
}

function logsCommand(service, options) {
  ensureInitialized();
  const args = ["logs", "--tail", String(options.tail || 200)];
  if (options.follow) {
    args.push("-f");
  }
  if (service) {
    args.push(service);
  }
  runCompose(args, { stdio: "inherit" });
}

function formatMark(state) {
  return state ? "✓" : "✗";
}

function statusCommand() {
  ensureInitialized();
  const envMap = loadEnvFile(ENV_PATH);

  const active = run("systemctl", ["is-active", "--quiet", SERVICE_NAME], {
    check: false,
  }).status === 0;
  const enabled = run("systemctl", ["is-enabled", "--quiet", SERVICE_NAME], {
    check: false,
  }).status === 0;
  const containerStatus = output("sh", [
    "-lc",
    "docker ps --filter name=^bitcall-gateway$ --format '{{.Status}}'",
  ]);

  const p80 = portInUse(Number.parseInt(envMap.ACME_LISTEN_PORT || "80", 10));
  const p443 = portInUse(Number.parseInt(envMap.WSS_LISTEN_PORT || "443", 10));
  const p5060 = portInUse(5060);

  const cert = certStatusFromPath(envMap.TLS_CERT);
  const rtpReady =
    run("docker", ["exec", "bitcall-gateway", "rtpengine-ctl", "-ip", "127.0.0.1", "-port", "7722", "list", "numsessions"], {
      check: false,
    }).status === 0;

  let turnReady = false;
  if (envMap.TURN_MODE && envMap.TURN_MODE !== "none") {
    turnReady =
      run("docker", ["exec", "bitcall-gateway", "curl", "-fsS", "http://127.0.0.1:8880/turn-credentials"], {
        check: false,
      }).status === 0;
  }

  console.log("Bitcall Gateway Status\n");
  console.log(`Gateway service: ${formatMark(active)} ${active ? "running" : "stopped"}`);
  console.log(`Auto-start: ${formatMark(enabled)} ${enabled ? "enabled" : "disabled"}`);
  console.log(`Container: ${containerStatus || "not running"}`);
  console.log("");
  console.log(`Port ${envMap.ACME_LISTEN_PORT || "80"}: ${formatMark(p80.inUse)} listening`);
  console.log(`Port ${envMap.WSS_LISTEN_PORT || "443"}: ${formatMark(p443.inUse)} listening`);
  console.log(`Port 5060: ${formatMark(p5060.inUse)} listening`);
  console.log(`rtpengine control: ${formatMark(rtpReady)} reachable`);
  if (envMap.TURN_MODE && envMap.TURN_MODE !== "none") {
    console.log(`/turn-credentials: ${formatMark(turnReady)} reachable`);
  }

  if (cert) {
    console.log("");
    console.log(`Certificate: ${cert.subject}`);
    console.log(`${cert.issuer}`);
    console.log(`Expires: ${cert.endDate}${cert.days !== null ? ` (${cert.days} days)` : ""}`);
  }

  console.log("\nConfig summary:");
  console.log(`DOMAIN=${envMap.DOMAIN || ""}`);
  console.log(`SIP_PROVIDER_URI=${envMap.SIP_PROVIDER_URI || ""}`);
  console.log(`DEPLOY_MODE=${envMap.DEPLOY_MODE || ""}`);
  console.log(`ALLOWED_SIP_DOMAINS=${envMap.ALLOWED_SIP_DOMAINS || ""}`);
  console.log(`TURN_MODE=${envMap.TURN_MODE || "none"}`);
}

function certStatusCommand() {
  ensureInitialized();
  const envMap = loadEnvFile(ENV_PATH);
  const certPath = envMap.TLS_CERT;

  if (!certPath) {
    throw new Error("TLS_CERT not set in .env");
  }

  const status = certStatusFromPath(certPath);
  if (!status) {
    throw new Error(`Certificate not found at ${certPath}`);
  }

  console.log(`Certificate path: ${certPath}`);
  console.log(status.subject);
  console.log(status.issuer);
  console.log(`Expires: ${status.endDate}`);
  if (status.days !== null) {
    console.log(`Days remaining: ${status.days}`);
  }
}

function certRenewCommand() {
  ensureInitialized();
  const envMap = loadEnvFile(ENV_PATH);
  if (envMap.TLS_MODE !== "letsencrypt") {
    throw new Error("cert renew is only supported when TLS_MODE=letsencrypt");
  }

  run("certbot", ["renew"], { stdio: "inherit" });
  run("systemctl", ["reload", SERVICE_NAME], { stdio: "inherit" });
}

async function certInstallCommand(options) {
  ensureInitialized();

  const prompt = new Prompter();
  try {
    const certIn = options.cert || (await prompt.askText("Certificate path", "", { required: true }));
    const keyIn = options.key || (await prompt.askText("Private key path", "", { required: true }));

    const envMap = loadEnvFile(ENV_PATH);
    const domain = envMap.DOMAIN || "";

    validateCustomCert(certIn, keyIn, domain);

    ensureDir(SSL_DIR, 0o700);
    const certOut = path.join(SSL_DIR, "custom-cert.pem");
    const keyOut = path.join(SSL_DIR, "custom-key.pem");
    fs.copyFileSync(certIn, certOut);
    fs.copyFileSync(keyIn, keyOut);
    fs.chmodSync(certOut, 0o644);
    fs.chmodSync(keyOut, 0o600);

    updateGatewayEnv({
      TLS_MODE: "custom",
      TLS_CERT: certOut,
      TLS_KEY: keyOut,
      ACME_EMAIL: "",
    });

    runSystemctl(["reload", SERVICE_NAME], ["up", "-d", "--remove-orphans"]);
    console.log("Custom certificate installed.");
  } finally {
    prompt.close();
  }
}

function updateCommand() {
  ensureInitialized();
  runCompose(["pull"], { stdio: "inherit" });
  runSystemctl(["reload", SERVICE_NAME], ["up", "-d", "--remove-orphans"]);
}

async function uninstallCommand(options) {
  if (!options.yes) {
    const prompt = new Prompter();
    try {
      const token = await prompt.askText("Type 'uninstall' to confirm", "", { required: true });
      if (token !== "uninstall") {
        throw new Error("Uninstall canceled.");
      }
    } finally {
      prompt.close();
    }
  }

  run("systemctl", ["stop", SERVICE_NAME], { check: false, stdio: "inherit" });
  run("systemctl", ["disable", SERVICE_NAME], { check: false, stdio: "inherit" });

  if (fs.existsSync(SERVICE_FILE)) {
    fs.rmSync(SERVICE_FILE, { force: true });
    run("systemctl", ["daemon-reload"], { check: false, stdio: "inherit" });
  }

  if (fs.existsSync(COMPOSE_PATH)) {
    runCompose(["down", "--rmi", "all", "--volumes"], {
      check: false,
      stdio: "inherit",
    });
  }

  if (fs.existsSync(RENEW_HOOK_PATH)) {
    fs.rmSync(RENEW_HOOK_PATH, { force: true });
  }

  if (fs.existsSync(GATEWAY_DIR)) {
    fs.rmSync(GATEWAY_DIR, { recursive: true, force: true });
  }

  console.log("Gateway uninstalled.");
}

function configCommand() {
  ensureInitialized();
  const envMap = loadEnvFile(ENV_PATH);
  for (const key of envOrder()) {
    if (Object.prototype.hasOwnProperty.call(envMap, key)) {
      console.log(`${key}=${maskValue(key, envMap[key])}`);
    }
  }
}

function buildProgram() {
  const program = new Command();

  program
    .name("bitcall-gateway")
    .description("Install and operate Bitcall WebRTC-to-SIP gateway")
    .version(PACKAGE_VERSION);

  program.command("init").description("Run setup wizard and provision gateway").action(initCommand);
  program.command("up").description("Start gateway services").action(upCommand);
  program.command("down").description("Stop gateway services").action(downCommand);
  program.command("stop").description("Alias for down").action(downCommand);
  program.command("restart").description("Restart gateway services").action(restartCommand);
  program.command("status").description("Show diagnostic status").action(statusCommand);

  program
    .command("logs [service]")
    .description("Show container logs")
    .option("-f, --follow", "Follow logs", true)
    .option("--no-follow", "Print and exit")
    .option("--tail <lines>", "Number of lines", "200")
    .action(logsCommand);

  const cert = program.command("cert").description("Certificate operations");
  cert.command("status").description("Show current certificate info").action(certStatusCommand);
  cert.command("renew").description("Run certbot renew and reload gateway").action(certRenewCommand);
  cert
    .command("install")
    .description("Install custom certificate and restart gateway")
    .option("--cert <path>", "Certificate path")
    .option("--key <path>", "Private key path")
    .action(certInstallCommand);

  program.command("update").description("Pull latest image and restart service").action(updateCommand);
  program.command("config").description("Print active configuration (secrets hidden)").action(configCommand);
  program
    .command("uninstall")
    .description("Remove gateway service and files")
    .option("-y, --yes", "Skip confirmation prompt")
    .action(uninstallCommand);

  return program;
}

async function main(argv = process.argv) {
  const program = buildProgram();
  await program.parseAsync(argv);
}

module.exports = {
  main,
};

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
