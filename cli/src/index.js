"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

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
const { loadEnvFile, writeEnvFile } = require("../lib/envfile");
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
const {
  detectFirewallBackend,
  applyMediaIpv4OnlyRules,
  removeMediaIpv4OnlyRules,
  isMediaIpv4OnlyRulesPresent,
} = require("../lib/firewall");

const PACKAGE_VERSION = require("../package.json").version;
// -- ANSI color helpers (zero dependencies) --
const _c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
};
const _color = process.stdout.isTTY && !process.env.NO_COLOR;
function clr(style, text) {
  return _color ? `${style}${text}${_c.reset}` : text;
}

const INSTALL_LOG_PATH = "/var/log/bitcall-gateway-install.log";

function printBanner() {
  const v = `v${PACKAGE_VERSION}`;

  if (!_color) {
    console.log("\n  BITCALL\n  WebRTC → SIP Gateway  " + v);
    console.log("  one-line deploy · any provider\n");
    return;
  }

  // Block-letter BITCALL — each line is one string, do not modify
  const art = [
    "██████  ██ ████████  ██████  █████  ██      ██",
    "██   ██ ██    ██    ██      ██   ██ ██      ██",
    "██████  ██    ██    ██      ███████ ██      ██",
    "██   ██ ██    ██    ██      ██   ██ ██      ██",
    "██████  ██    ██     ██████ ██   ██ ███████ ███████",
  ];

  const W = 55; // inner box width
  const top = `  ${_c.cyan}╔${"═".repeat(W)}╗${_c.reset}`;
  const bot = `  ${_c.cyan}╚${"═".repeat(W)}╝${_c.reset}`;
  const blank = `  ${_c.cyan}║${_c.reset}${" ".repeat(W)}${_c.cyan}║${_c.reset}`;

  function row(content, pad) {
    const visible = content.replace(/\x1b\[[0-9;]*m/g, "");
    const fill = Math.max(0, W - (pad || 0) - visible.length);
    return `  ${_c.cyan}║${_c.reset}${"".padEnd(pad || 0)}${content}${" ".repeat(fill)}${_c.cyan}║${_c.reset}`;
  }

  console.log("");
  console.log(top);
  console.log(blank);
  for (const line of art) {
    console.log(row(`${_c.bold}${_c.white}${line}${_c.reset}`, 3));
  }
  console.log(blank);
  console.log(row(`${_c.dim}WebRTC → SIP Gateway${_c.reset}`, 3));
  console.log(row(`${_c.dim}one-line deploy · any provider${_c.reset}        ${_c.dim}${v}${_c.reset}`, 3));
  console.log(blank);
  console.log(bot);
  console.log("");
}

function createInstallContext(options = {}) {
  const verbose = Boolean(options.verbose);
  const steps = ["Checks", "Config", "Firewall", "TLS", "Start", "Done"];
  const state = { index: 0 };

  if (!verbose) {
    fs.writeFileSync(INSTALL_LOG_PATH, "", { mode: 0o600 });
    fs.chmodSync(INSTALL_LOG_PATH, 0o600);
  }

  function logLine(line) {
    if (!verbose) {
      fs.appendFileSync(INSTALL_LOG_PATH, `${line}\n`);
    }
  }

  function formatCommand(command, args) {
    const joined = [command, ...(args || [])].join(" ").trim();
    return joined;
  }

  function exec(command, args = [], commandOptions = {}) {
    const stdio = verbose ? "inherit" : "pipe";
    const result = run(command, args, {
      ...commandOptions,
      check: false,
      stdio,
    });

    if (!verbose) {
      logLine(`$ ${formatCommand(command, args)}`);
      if (result.stdout) {
        fs.appendFileSync(INSTALL_LOG_PATH, result.stdout);
      }
      if (result.stderr) {
        fs.appendFileSync(INSTALL_LOG_PATH, result.stderr);
      }
      logLine("");
    }

    if (commandOptions.check !== false && result.status !== 0) {
      throw new Error(`Command failed: ${formatCommand(command, args)}`);
    }

    return result;
  }

  function shell(script, commandOptions = {}) {
    return exec("sh", ["-lc", script], commandOptions);
  }

  async function step(label, fn) {
    state.index += 1;
    console.log(`  ${clr(_c.dim, `[${state.index}/${steps.length}]`)} ${clr(_c.bold, label)}...`);
    const started = Date.now();
    try {
      const value = await fn();
      const elapsed = ((Date.now() - started) / 1000).toFixed(1);
      console.log(`  ${clr(_c.green, "✓")} ${clr(_c.bold, label)} ${clr(_c.dim, `(${elapsed}s)`)}\n`);
      return value;
    } catch (error) {
      console.error(`  ${clr(_c.red, "✗")} ${clr(_c.bold + _c.red, label + " failed:")} ${error.message}`);
      if (!verbose) {
        console.error(`Install log: ${INSTALL_LOG_PATH}`);
      }
      throw error;
    }
  }

  return {
    verbose,
    logPath: INSTALL_LOG_PATH,
    exec,
    shell,
    step,
    logLine,
  };
}

function detectComposeCommand(exec = run) {
  if (exec("docker", ["compose", "version"], { check: false }).status === 0) {
    return { command: "docker", prefixArgs: ["compose"] };
  }
  if (exec("docker-compose", ["version"], { check: false }).status === 0) {
    const composePath = output("sh", ["-lc", "command -v docker-compose || true"]).trim();
    if (composePath.startsWith("/snap/")) {
      throw new Error(
        "Detected snap docker-compose only. Install Docker compose plugin (`docker compose`) " +
          "because snap docker-compose cannot access /opt/bitcall-gateway."
      );
    }
    return { command: "docker-compose", prefixArgs: [] };
  }
  throw new Error("docker compose not found. Install Docker compose plugin.");
}

function runCompose(args, options = {}, exec = run) {
  const compose = detectComposeCommand(exec);
  return exec(compose.command, [...compose.prefixArgs, "-f", COMPOSE_PATH, ...args], {
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
    "BITCALL_ENV",
    "DOMAIN",
    "PUBLIC_IP",
    "DEPLOY_MODE",
    "ROUTING_MODE",
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
    "MEDIA_IPV4_ONLY",
    "TURN_UDP_PORT",
    "TURNS_TCP_PORT",
    "TURN_RELAY_MIN_PORT",
    "TURN_RELAY_MAX_PORT",
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

function installSystemdService(exec = run) {
  writeFileWithMode(SERVICE_FILE, buildSystemdService(), 0o644);
  exec("systemctl", ["daemon-reload"]);
  exec("systemctl", ["enable", SERVICE_NAME]);
}

function buildUfwRules(config) {
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

  if (config.turnMode === "coturn") {
    rules.push([`${config.turnUdpPort}/udp`, "Bitcall TURN UDP"]);
    rules.push([`${config.turnUdpPort}/tcp`, "Bitcall TURN TCP"]);
    rules.push([`${config.turnsTcpPort}/tcp`, "Bitcall TURNS TCP"]);
    rules.push([
      `${config.turnRelayMinPort}:${config.turnRelayMaxPort}/udp`,
      "Bitcall TURN relay UDP",
    ]);
  }

  return rules;
}

function printRequiredPorts(config) {
  console.log("Open these ports in your host/cloud firewall:");
  for (const [port, label] of buildUfwRules(config)) {
    console.log(`  - ${port} (${label})`);
  }
}

function configureFirewall(config, exec = run) {
  for (const [port, label] of buildUfwRules(config)) {
    exec("ufw", ["allow", port, "comment", label], {
      check: false,
    });
  }

  exec("ufw", ["--force", "enable"], { check: false });
  exec("ufw", ["reload"], { check: false });
}

function isSingleProviderConfigured(config) {
  return config.routingMode === "single-provider" && Boolean((config.sipProviderUri || "").trim());
}

function isOriginWildcard(originPattern) {
  const value = (originPattern || "").trim();
  return value === ".*" || value === "^.*$" || value === "*";
}

function validateProductionConfig(config) {
  // In production, validate that the config is internally consistent.
  // Universal mode (open domains, open origin) is a valid production config.

  // Single-provider mode requires a valid SIP_PROVIDER_URI
  if (config.routingMode === "single-provider") {
    if (!(config.sipProviderUri || "").trim()) {
      throw new Error(
        "Single-provider mode requires SIP_PROVIDER_URI. " +
          "Re-run: bitcall-gateway init --advanced --production"
      );
    }
  }

  // If custom cert mode, paths are required (already validated elsewhere)
  // No other hard requirements for production.
}

function buildSecurityNotes(config) {
  const notes = [];
  if (countAllowedDomains(config.allowedDomains) === 0) {
    notes.push("SIP domains: unrestricted (universal mode)");
  }
  if (isOriginWildcard(toOriginPattern(config.webphoneOrigin))) {
    notes.push("Webphone origin: unrestricted");
  }
  if (!(config.sipTrustedIps || "").trim()) {
    notes.push("SIP source IPs: unrestricted");
  }
  return notes;
}

function buildQuickFlowDefaults(initProfile, existing = {}) {
  const defaults = {
    bitcallEnv: initProfile,
    routingMode: "universal",
    sipProviderUri: "",
    sipTransport: "udp",
    sipPort: "5060",
    allowedDomains: existing.ALLOWED_SIP_DOMAINS || "",
    webphoneOrigin: existing.WEBPHONE_ORIGIN || DEFAULT_WEBPHONE_ORIGIN,
    sipTrustedIps: existing.SIP_TRUSTED_IPS || "",
  };

  // Dev mode: explicitly open everything (ignore existing restrictions)
  if (initProfile === "dev") {
    defaults.allowedDomains = "";
    defaults.webphoneOrigin = "*";
    defaults.sipTrustedIps = "";
  }

  // Production mode: use existing values or defaults (already universal)
  // Do not force restrictions here.
  return defaults;
}

function countAllowedDomains(raw) {
  if (!raw) {
    return 0;
  }
  return raw
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean).length;
}

function mediaFirewallOptionsFromConfig(config) {
  return {
    rtpMin: Number.parseInt(config.rtpMin || "10000", 10),
    rtpMax: Number.parseInt(config.rtpMax || "20000", 10),
    turnEnabled: config.turnMode === "coturn",
    turnUdpPort: Number.parseInt(config.turnUdpPort || "3478", 10),
    turnsTcpPort: Number.parseInt(config.turnsTcpPort || "5349", 10),
    turnRelayMin: Number.parseInt(config.turnRelayMinPort || "49152", 10),
    turnRelayMax: Number.parseInt(config.turnRelayMaxPort || "49252", 10),
  };
}

function mediaFirewallOptionsFromEnv(envMap) {
  return {
    rtpMin: Number.parseInt(envMap.RTPENGINE_MIN_PORT || "10000", 10),
    rtpMax: Number.parseInt(envMap.RTPENGINE_MAX_PORT || "20000", 10),
    turnEnabled: (envMap.TURN_MODE || "none") === "coturn",
    turnUdpPort: Number.parseInt(envMap.TURN_UDP_PORT || "3478", 10),
    turnsTcpPort: Number.parseInt(envMap.TURNS_TCP_PORT || "5349", 10),
    turnRelayMin: Number.parseInt(envMap.TURN_RELAY_MIN_PORT || "49152", 10),
    turnRelayMax: Number.parseInt(envMap.TURN_RELAY_MAX_PORT || "49252", 10),
  };
}

async function confirmContinueWithoutMediaBlock() {
  const prompt = new Prompter();
  try {
    return await prompt.askYesNo(
      "Continue without IPv6 media block (may cause no-audio on some networks)?",
      false
    );
  } finally {
    prompt.close();
  }
}

async function confirmInstallUfw() {
  const prompt = new Prompter();
  try {
    return await prompt.askYesNo("ufw is not installed. Install ufw now?", true);
  } finally {
    prompt.close();
  }
}

async function ensureUfwAvailable(ctx) {
  if (commandExists("ufw")) {
    return true;
  }

  const installNow = await confirmInstallUfw();
  if (!installNow) {
    return false;
  }

  ctx.exec("apt-get", ["update"]);
  ctx.exec("apt-get", ["install", "-y", "ufw"]);
  return commandExists("ufw");
}

function generateSelfSigned(certPath, keyPath, domain, days = 1, exec = run) {
  ensureDir(path.dirname(certPath), 0o700);
  exec(
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
    {}
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

function normalizeInitProfile(initOptions = {}, existing = {}) {
  if (initOptions.dev && initOptions.production) {
    throw new Error("Use only one mode: --dev or --production.");
  }
  if (initOptions.production) {
    return "production";
  }
  if (initOptions.dev) {
    return "dev";
  }
  return existing.BITCALL_ENV || "production";
}

async function runPreflight(ctx) {
  if (process.platform !== "linux") {
    throw new Error("bitcall-gateway supports Linux hosts only.");
  }

  const os = parseOsRelease();
  if (!isSupportedDistro()) {
    console.log(
      `Warning: unsupported distro ${os.PRETTY_NAME || "unknown"}. Expected Ubuntu 22+ or Debian 12+.`
    );
  }

  ctx.exec("apt-get", ["update"]);
  ctx.exec("apt-get", ["install", "-y", "curl", "ca-certificates", "lsof", "openssl", "gnupg"]);

  ensureDockerInstalled({ exec: ctx.exec, shell: ctx.shell });
  ensureComposePlugin({ exec: ctx.exec });

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
    os,
    p80,
    p443,
  };
}

function printSummary(config, notes) {
  const allowedCount = countAllowedDomains(config.allowedDomains);
  console.log(`\n${clr(_c.bold + _c.cyan, "  ┌─ Configuration ──────────────────────────────┐")}`);
  console.log(`${clr(_c.cyan, "  │")}  ${clr(_c.dim, "Domain:")}         ${config.domain}`);
  console.log(`${clr(_c.cyan, "  │")}  ${clr(_c.dim, "Environment:")}    ${config.bitcallEnv}`);
  console.log(`${clr(_c.cyan, "  │")}  ${clr(_c.dim, "Routing:")}        ${config.routingMode}`);
  console.log(`${clr(_c.cyan, "  │")}  ${clr(_c.dim, "Allowlist:")}      ${allowedCount > 0 ? config.allowedDomains : "(any)"}`);
  console.log(`${clr(_c.cyan, "  │")}  ${clr(_c.dim, "Origin:")}         ${config.webphoneOrigin === "*" ? "(any)" : config.webphoneOrigin}`);
  console.log(`${clr(_c.cyan, "  │")}  ${clr(_c.dim, "SIP source IPs:")} ${(config.sipTrustedIps || "").trim() ? config.sipTrustedIps : "(any)"}`);
  console.log(`${clr(_c.cyan, "  │")}  ${clr(_c.dim, "TLS:")}            ${config.tlsMode === "letsencrypt" ? "Let's Encrypt" : config.tlsMode}`);
  console.log(`${clr(_c.cyan, "  │")}  ${clr(_c.dim, "TURN:")}           ${config.turnMode === "coturn" ? "enabled (coturn)" : config.turnMode}`);
  console.log(`${clr(_c.cyan, "  │")}  ${clr(_c.dim, "Media:")}          ${config.mediaIpv4Only === "1" ? "IPv4-only (IPv6 media blocked)" : "dual-stack"}`);
  if (config.configureUfw) {
    console.log(`${clr(_c.cyan, "  │")}  ${clr(_c.dim, "Firewall:")}       UFW enabled`);
  }
  console.log(`${clr(_c.bold + _c.cyan, "  └─────────────────────────────────────────────┘")}`);

  if (notes.length > 0) {
    console.log("");
    for (const note of notes) {
      console.log(`  ${clr(_c.dim, "ℹ")} ${clr(_c.dim, note)}`);
    }
  }
}

function shouldRequireAllowlist(bitcallEnv, routingMode) {
  void bitcallEnv;
  void routingMode;
  return false;
}

function parseProviderFromUri(uri = "") {
  const clean = uri.replace(/^sip:/, "");
  const [hostPort, transportPart] = clean.split(";");
  const [host, port] = hostPort.split(":");
  let transport = "udp";
  if (transportPart && transportPart.includes("transport=")) {
    transport = transportPart.split("transport=")[1] || "udp";
  }
  return {
    host: host || DEFAULT_PROVIDER_HOST,
    port: port || (transport === "tls" ? "5061" : "5060"),
    transport,
  };
}

async function runWizard(existing = {}, preflight = {}, initOptions = {}) {
  const prompt = new Prompter();

  try {
    const initProfile = normalizeInitProfile(initOptions, existing);
    const advanced = Boolean(initOptions.advanced);

    const detectedIp = detectPublicIp();
    const domainDefault = initOptions.domain || existing.DOMAIN || "";
    const domain = domainDefault
      ? domainDefault
      : await prompt.askText("Gateway domain", existing.DOMAIN || "", { required: true });
    let publicIp = existing.PUBLIC_IP || detectedIp || "";
    if (!publicIp) {
      publicIp = await prompt.askText("Public IPv4 (auto-detect failed)", "", { required: true });
    }

    const resolved = resolveDomainIpv4(domain);
    if (initProfile !== "dev" && resolved.length > 0 && !resolved.includes(publicIp)) {
      console.log(`Warning: DNS for ${domain} resolves to ${resolved.join(", ")}, not ${publicIp}.`);
    }

    const detectedDeployMode =
      (preflight.p80 && preflight.p80.inUse) || (preflight.p443 && preflight.p443.inUse)
        ? "reverse-proxy"
        : "standalone";

    const existingDeployMode =
      existing.DEPLOY_MODE === "standalone" || existing.DEPLOY_MODE === "reverse-proxy"
        ? existing.DEPLOY_MODE
        : "";
    let deployMode = existingDeployMode || detectedDeployMode;
    let tlsMode = "letsencrypt";
    let acmeEmail = initOptions.email || existing.ACME_EMAIL || "";
    let customCertPath = "";
    let customKeyPath = "";
    const quickDefaults = buildQuickFlowDefaults(initProfile, existing);
    let bitcallEnv = quickDefaults.bitcallEnv;
    let routingMode = "universal";
    const providerFromEnv = parseProviderFromUri(existing.SIP_PROVIDER_URI || "");
    let sipProviderHost = providerFromEnv.host || DEFAULT_PROVIDER_HOST;
    let sipTransport = "udp";
    let sipPort = "5060";
    let sipProviderUri = "";
    let allowedDomains = "";
    let sipTrustedIps = "";
    let turnMode = "coturn";
    let turnSecret = "";
    let turnTtl = existing.TURN_TTL || "86400";
    let turnApiToken = "";
    let turnExternalUrls = "";
    let turnExternalUsername = "";
    let turnExternalCredential = "";
    let webphoneOrigin = "*";
    let configureUfw = true;
    let mediaIpv4Only = existing.MEDIA_IPV4_ONLY ? existing.MEDIA_IPV4_ONLY === "1" : true;
    let rtpMin = existing.RTPENGINE_MIN_PORT || "10000";
    let rtpMax = existing.RTPENGINE_MAX_PORT || "20000";
    let turnUdpPort = existing.TURN_UDP_PORT || "3478";
    let turnsTcpPort = existing.TURNS_TCP_PORT || "5349";
    let turnRelayMinPort = existing.TURN_RELAY_MIN_PORT || "49152";
    let turnRelayMaxPort = existing.TURN_RELAY_MAX_PORT || "49252";

    if (initProfile === "dev") {
      tlsMode = "dev-self-signed";
      acmeEmail = "";
      turnMode = "coturn";
      routingMode = quickDefaults.routingMode;
      sipProviderUri = quickDefaults.sipProviderUri;
      sipTransport = quickDefaults.sipTransport;
      sipPort = quickDefaults.sipPort;
      allowedDomains = quickDefaults.allowedDomains;
      webphoneOrigin = quickDefaults.webphoneOrigin;
      sipTrustedIps = quickDefaults.sipTrustedIps;
      configureUfw = true;
      mediaIpv4Only = true;
    } else {
      tlsMode = await prompt.askChoice(
        "TLS certificate mode",
        ["letsencrypt", "custom"],
        existing.TLS_MODE === "custom" ? 1 : 0
      );

      if (tlsMode === "custom") {
        customCertPath = await prompt.askText("Path to TLS certificate (PEM)", existing.TLS_CERT || "", {
          required: true,
        });
        customKeyPath = await prompt.askText("Path to TLS private key (PEM)", existing.TLS_KEY || "", {
          required: true,
        });
        acmeEmail = "";
      } else {
        acmeEmail = await prompt.askText("Let's Encrypt email", acmeEmail, { required: true });
      }

      turnMode = await prompt.askYesNo("Enable built-in TURN (coturn)?", true) ? "coturn" : "none";
      routingMode = "universal";
      sipProviderUri = "";
      sipTransport = "udp";
      sipPort = "5060";
      allowedDomains = "";
      webphoneOrigin = "*";
      sipTrustedIps = "";
      turnApiToken = "";

      if (advanced) {
        const restrictToSingleProvider = await prompt.askYesNo(
          "Restrict to single SIP provider?",
          existing.ROUTING_MODE === "single-provider"
        );

        if (restrictToSingleProvider) {
          routingMode = "single-provider";
          sipProviderHost = await prompt.askText(
            "SIP provider host",
            providerFromEnv.host || DEFAULT_PROVIDER_HOST,
            { required: true }
          );
          sipTransport = await prompt.askChoice(
            "SIP provider transport",
            ["udp", "tcp", "tls"],
            providerFromEnv.transport === "tcp" ? 1 : providerFromEnv.transport === "tls" ? 2 : 0
          );
          const defaultProviderPort =
            providerFromEnv.port || (sipTransport === "tls" ? "5061" : "5060");
          sipPort = await prompt.askText("SIP provider port", defaultProviderPort, { required: true });
          sipProviderUri = `sip:${sipProviderHost}:${sipPort};transport=${sipTransport}`;
        }

        allowedDomains = await prompt.askText(
          "SIP domain allowlist (optional, comma-separated)",
          existing.ALLOWED_SIP_DOMAINS || ""
        );
        webphoneOrigin = await prompt.askText(
          "Webphone origin restriction (optional, * for any)",
          existing.WEBPHONE_ORIGIN || "*"
        );
        webphoneOrigin = webphoneOrigin.trim() ? webphoneOrigin : "*";
        sipTrustedIps = await prompt.askText(
          "SIP trusted source IPs (optional, comma-separated)",
          existing.SIP_TRUSTED_IPS || ""
        );

        if (turnMode === "coturn") {
          turnApiToken = await prompt.askText("TURN API token (optional)", existing.TURN_API_TOKEN || "");
        }

        const customizePorts = await prompt.askYesNo("Customize RTP/TURN ports?", false);
        if (customizePorts) {
          rtpMin = await prompt.askText("RTP minimum port", rtpMin, { required: true });
          rtpMax = await prompt.askText("RTP maximum port", rtpMax, { required: true });
          if (turnMode === "coturn") {
            turnUdpPort = await prompt.askText("TURN UDP/TCP port", turnUdpPort, { required: true });
            turnsTcpPort = await prompt.askText("TURNS TCP port", turnsTcpPort, { required: true });
            turnRelayMinPort = await prompt.askText("TURN relay minimum port", turnRelayMinPort, {
              required: true,
            });
            turnRelayMaxPort = await prompt.askText("TURN relay maximum port", turnRelayMaxPort, {
              required: true,
            });
          }
        }
      }
    }

    if (turnMode === "coturn") {
      turnSecret = crypto.randomBytes(32).toString("hex");
    }

    if (deployMode === "reverse-proxy") {
      console.log(
        "Note: forward /turn-credentials and websocket upgrade to 127.0.0.1:8443, and ACME path to 127.0.0.1:8080."
      );
    }

    const config = {
      domain,
      publicIp,
      deployMode,
      tlsMode,
      acmeEmail,
      customCertPath,
      customKeyPath,
      bitcallEnv,
      routingMode,
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
      mediaIpv4Only: mediaIpv4Only ? "1" : "0",
      rtpMin,
      rtpMax,
      turnUdpPort,
      turnsTcpPort,
      turnRelayMinPort,
      turnRelayMaxPort,
      acmeListenPort: deployMode === "reverse-proxy" ? "8080" : "80",
      wssListenPort: deployMode === "reverse-proxy" ? "8443" : "443",
      internalWssPort: "8443",
      internalWsPort: "8080",
      configureUfw,
    };

    if (config.bitcallEnv === "production") {
      validateProductionConfig(config);
    }

    const securityNotes = buildSecurityNotes(config);
    printSummary(config, securityNotes);

    if (initProfile !== "dev") {
      const proceed = await prompt.askYesNo("Proceed with provisioning", true);
      if (!proceed) {
        throw new Error("Initialization canceled.");
      }
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
    BITCALL_ENV: config.bitcallEnv,
    DOMAIN: config.domain,
    PUBLIC_IP: config.publicIp,
    DEPLOY_MODE: config.deployMode,
    ROUTING_MODE: config.routingMode,
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
    MEDIA_IPV4_ONLY: config.mediaIpv4Only,
    TURN_UDP_PORT: config.turnUdpPort,
    TURNS_TCP_PORT: config.turnsTcpPort,
    TURN_RELAY_MIN_PORT: config.turnRelayMinPort,
    TURN_RELAY_MAX_PORT: config.turnRelayMaxPort,
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

function writeComposeTemplate(config = {}) {
  let compose = readTemplate("docker-compose.yml.template").trimEnd();
  if (config.turnMode === "coturn") {
    const coturn = readTemplate("coturn-service.yml.template").trimEnd();
    compose = `${compose}\n\n${coturn}`;
  }
  writeFileWithMode(COMPOSE_PATH, `${compose}\n`, 0o644);
}

function stripLegacyKamailioVolume(composeContent) {
  const lines = composeContent.split(/\r?\n/);
  const filtered = lines.filter((line) => !line.includes("/etc/kamailio"));
  if (filtered.length === lines.length) {
    return { changed: false, content: composeContent };
  }
  const content = `${filtered.join("\n").replace(/\n*$/, "")}\n`;
  return { changed: true, content };
}

function migrateLegacyComposeIfNeeded() {
  if (!fs.existsSync(COMPOSE_PATH)) {
    return false;
  }
  const original = fs.readFileSync(COMPOSE_PATH, "utf8");
  const migrated = stripLegacyKamailioVolume(original);
  if (!migrated.changed) {
    return false;
  }
  writeFileWithMode(COMPOSE_PATH, migrated.content, 0o644);
  console.log("Detected legacy /etc/kamailio compose volume override. Removed automatically.");
  return true;
}

function updateComposeUpArgs() {
  return ["up", "-d", "--force-recreate", "--renew-anon-volumes", "--remove-orphans"];
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

function startGatewayStack(exec = run) {
  runCompose(["pull"], {}, exec);
  runCompose(["up", "-d", "--remove-orphans"], {}, exec);
}

function runLetsEncrypt(config, exec = run) {
  exec("apt-get", ["update"]);
  exec("apt-get", ["install", "-y", "certbot"]);

  exec(
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
    {}
  );

  const liveCert = `/etc/letsencrypt/live/${config.domain}/fullchain.pem`;
  const liveKey = `/etc/letsencrypt/live/${config.domain}/privkey.pem`;

  updateGatewayEnv({
    TLS_CERT: liveCert,
    TLS_KEY: liveKey,
  });

  installRenewHook();
  runCompose(["up", "-d", "--remove-orphans"], {}, exec);
}

function installGatewayService(exec = run) {
  installSystemdService(exec);
  exec("systemctl", ["enable", "--now", SERVICE_NAME]);
}

function backupExistingGatewayConfig() {
  if (!fs.existsSync(ENV_PATH) || !fs.existsSync(COMPOSE_PATH)) {
    return null;
  }
  return {
    envContent: fs.readFileSync(ENV_PATH, "utf8"),
    composeContent: fs.readFileSync(COMPOSE_PATH, "utf8"),
  };
}

function restoreGatewayConfigFromBackup(backup, contextLabel = "Operation") {
  if (!backup || backup.envContent == null || backup.composeContent == null) {
    return;
  }
  try {
    ensureInstallLayout();
    writeFileWithMode(ENV_PATH, backup.envContent, 0o600);
    writeFileWithMode(COMPOSE_PATH, backup.composeContent, 0o644);
    runCompose(["up", "-d", "--remove-orphans"], { check: false, stdio: "pipe" });
    console.error(`${contextLabel} failed. Restored previous gateway config and attempted restart.`);
  } catch (restoreError) {
    console.error(
      `${contextLabel} failed and automatic restore also failed: ${restoreError.message}`
    );
  }
}

async function initCommand(initOptions = {}) {
  printBanner();
  const previousConfig = backupExistingGatewayConfig();

  // If re-running init on an existing installation, stop the current
  // gateway so our own ports don't fail the preflight check.
  if (previousConfig) {
    console.log("Existing gateway detected. Stopping for re-initialization...\n");
    try {
      runCompose(["down"], { stdio: "pipe" });
    } catch (_e) {
      // Ignore — gateway may already be stopped or config may be corrupted
    }
  }

  const ctx = createInstallContext(initOptions);
  try {
    let preflight;
    await ctx.step("Checks", async () => {
      preflight = await runPreflight(ctx);
    });

    let existingEnv = {};
    if (fs.existsSync(ENV_PATH)) {
      existingEnv = loadEnvFile(ENV_PATH);
    }

    let config;
    await ctx.step("Config", async () => {
      config = await runWizard(existingEnv, preflight, initOptions);
    });

    ensureInstallLayout();

    let tlsCertPath;
    let tlsKeyPath;

    await ctx.step("Firewall", async () => {
      if (config.configureUfw) {
        const ufwReady = await ensureUfwAvailable(ctx);
        if (ufwReady) {
          configureFirewall(config, ctx.exec);
        } else {
          console.log("Skipping UFW configuration by request.");
          config.configureUfw = false;
          printRequiredPorts(config);
        }
      } else {
        printRequiredPorts(config);
      }

      if (config.mediaIpv4Only === "1") {
        try {
          const applied = applyMediaIpv4OnlyRules(mediaFirewallOptionsFromConfig(config));
          console.log(`Applied IPv6 media block rules (${applied.backend}).`);
        } catch (error) {
          console.error(`IPv6 media block setup failed: ${error.message}`);
          const proceed = await confirmContinueWithoutMediaBlock();
          if (!proceed) {
            throw new Error(
              "Initialization stopped because media IPv4-only firewall rules were not applied."
            );
          }
          config.mediaIpv4Only = "0";
          console.log("Continuing without IPv6 media block rules.");
        }
      }
    });

    await ctx.step("TLS", async () => {
      if (config.tlsMode === "custom") {
        const custom = provisionCustomCert(config);
        tlsCertPath = custom.certPath;
        tlsKeyPath = custom.keyPath;
      } else if (config.tlsMode === "dev-self-signed") {
        tlsCertPath = path.join(SSL_DIR, "dev-fullchain.pem");
        tlsKeyPath = path.join(SSL_DIR, "dev-privkey.pem");
        generateSelfSigned(tlsCertPath, tlsKeyPath, config.domain, 30, ctx.exec);
        console.log("WARNING: Self-signed certificates do not work with browsers.");
        console.log("WebSocket connections will be rejected. Use --dev for local testing only.");
        console.log("For browser access, re-run with Let's Encrypt: sudo bitcall-gateway init");
      } else {
        tlsCertPath = path.join(SSL_DIR, "bootstrap-fullchain.pem");
        tlsKeyPath = path.join(SSL_DIR, "bootstrap-privkey.pem");
        generateSelfSigned(tlsCertPath, tlsKeyPath, config.domain, 1, ctx.exec);
      }

      const envContent = renderEnvContent(config, tlsCertPath, tlsKeyPath);
      writeFileWithMode(ENV_PATH, envContent, 0o600);
      writeComposeTemplate(config);
    });

    await ctx.step("Start", async () => {
      startGatewayStack(ctx.exec);
      if (config.tlsMode === "letsencrypt") {
        runLetsEncrypt(config, ctx.exec);
      }
      installGatewayService(ctx.exec);
    });

    await ctx.step("Done", async () => {});

    console.log("");
    console.log(clr(_c.bold + _c.green, "  ╔══════════════════════════════════════╗"));
    console.log(
      clr(_c.bold + _c.green, "  ║") +
        "  Gateway is " +
        clr(_c.bold + _c.green, "READY") +
        "                  " +
        clr(_c.bold + _c.green, "║")
    );
    console.log(clr(_c.bold + _c.green, "  ╚══════════════════════════════════════╝"));
    console.log("");
    console.log(`  ${clr(_c.bold, "WSS")}   ${clr(_c.cyan, `wss://${config.domain}`)}`);
    if (config.turnMode === "coturn") {
      console.log(`  ${clr(_c.bold, "TURN")}  ${clr(_c.cyan, `https://${config.domain}/turn-credentials`)}`);
      console.log(`  ${clr(_c.bold, "STUN")}  ${clr(_c.cyan, `stun:${config.domain}:${config.turnUdpPort}`)}`);
      console.log(`  ${clr(_c.bold, "TURN")}  ${clr(_c.cyan, `turn:${config.domain}:${config.turnUdpPort}`)}`);
      console.log(
        `  ${clr(_c.bold, "TURNS")} ${clr(_c.cyan, `turns:${config.domain}:${config.turnsTcpPort}`)}`
      );
    }
    if (!ctx.verbose) {
      console.log(`  ${clr(_c.dim, `Log:   ${ctx.logPath}`)}`);
    }
    console.log("");
  } catch (error) {
    if (previousConfig) {
      restoreGatewayConfigFromBackup(previousConfig, "Initialization");
    }
    throw error;
  }
}

async function reconfigureCommand(options) {
  ensureInitialized();
  printBanner();
  const previousConfig = backupExistingGatewayConfig();

  // Stop the running gateway so ports are free for preflight.
  if (previousConfig) {
    console.log("Stopping current gateway for reconfiguration...\n");
    try {
      runCompose(["down"], { stdio: "pipe" });
    } catch (_e) {
      // Ignore — gateway may already be stopped or config may be corrupted
    }
  }

  const ctx = createInstallContext(options);
  try {
    let preflight;
    await ctx.step("Checks", async () => {
      preflight = await runPreflight(ctx);
    });

    const existingEnv = fs.existsSync(ENV_PATH) ? loadEnvFile(ENV_PATH) : {};

    let config;
    await ctx.step("Config", async () => {
      config = await runWizard(existingEnv, preflight, options);
    });

    ensureInstallLayout();

    let tlsCertPath;
    let tlsKeyPath;

    await ctx.step("Firewall", async () => {
      if (config.configureUfw) {
        const ufwReady = await ensureUfwAvailable(ctx);
        if (ufwReady) {
          configureFirewall(config, ctx.exec);
        } else {
          config.configureUfw = false;
          printRequiredPorts(config);
        }
      } else {
        printRequiredPorts(config);
      }

      if (config.mediaIpv4Only === "1") {
        try {
          const applied = applyMediaIpv4OnlyRules(mediaFirewallOptionsFromConfig(config));
          console.log(`Applied IPv6 media block rules (${applied.backend}).`);
        } catch (error) {
          console.error(`IPv6 media block setup failed: ${error.message}`);
          config.mediaIpv4Only = "0";
        }
      }
    });

    await ctx.step("TLS", async () => {
      if (config.tlsMode === "custom") {
        const custom = provisionCustomCert(config);
        tlsCertPath = custom.certPath;
        tlsKeyPath = custom.keyPath;
      } else if (config.tlsMode === "dev-self-signed") {
        tlsCertPath = path.join(SSL_DIR, "dev-fullchain.pem");
        tlsKeyPath = path.join(SSL_DIR, "dev-privkey.pem");
        generateSelfSigned(tlsCertPath, tlsKeyPath, config.domain, 30, ctx.exec);
      } else {
        // Keep existing LE cert only when domain is unchanged and cert files still exist.
        const envMap = loadEnvFile(ENV_PATH);
        const sameDomain =
          (envMap.DOMAIN || "").trim().toLowerCase() === (config.domain || "").trim().toLowerCase();
        if (
          envMap.TLS_MODE === "letsencrypt" &&
          sameDomain &&
          envMap.TLS_CERT &&
          envMap.TLS_KEY &&
          fs.existsSync(envMap.TLS_CERT) &&
          fs.existsSync(envMap.TLS_KEY)
        ) {
          tlsCertPath = envMap.TLS_CERT;
          tlsKeyPath = envMap.TLS_KEY;
        } else {
          tlsCertPath = path.join(SSL_DIR, "bootstrap-fullchain.pem");
          tlsKeyPath = path.join(SSL_DIR, "bootstrap-privkey.pem");
          generateSelfSigned(tlsCertPath, tlsKeyPath, config.domain, 1, ctx.exec);
        }
      }

      const envContent = renderEnvContent(config, tlsCertPath, tlsKeyPath);
      writeFileWithMode(ENV_PATH, envContent, 0o600);
      writeComposeTemplate(config);
    });

    await ctx.step("Start", async () => {
      startGatewayStack(ctx.exec);
      if (config.tlsMode === "letsencrypt" && (!tlsCertPath || !tlsCertPath.includes("letsencrypt"))) {
        runLetsEncrypt(config, ctx.exec);
      }
    });

    await ctx.step("Done", async () => {});

    console.log("");
    console.log(clr(_c.bold + _c.green, "  ╔══════════════════════════════════════╗"));
    console.log(
      clr(_c.bold + _c.green, "  ║") +
        "  Gateway is " +
        clr(_c.bold + _c.green, "READY") +
        "                  " +
        clr(_c.bold + _c.green, "║")
    );
    console.log(clr(_c.bold + _c.green, "  ╚══════════════════════════════════════╝"));
    console.log("");
    console.log(`  ${clr(_c.bold, "WSS")}   ${clr(_c.cyan, `wss://${config.domain}`)}`);
    if (config.turnMode === "coturn") {
      console.log(`  ${clr(_c.bold, "TURN")}  ${clr(_c.cyan, `https://${config.domain}/turn-credentials`)}`);
      console.log(`  ${clr(_c.bold, "STUN")}  ${clr(_c.cyan, `stun:${config.domain}:${config.turnUdpPort}`)}`);
      console.log(`  ${clr(_c.bold, "TURN")}  ${clr(_c.cyan, `turn:${config.domain}:${config.turnUdpPort}`)}`);
      console.log(
        `  ${clr(_c.bold, "TURNS")} ${clr(_c.cyan, `turns:${config.domain}:${config.turnsTcpPort}`)}`
      );
    }
    if (!ctx.verbose) {
      console.log(`  ${clr(_c.dim, `Log:   ${ctx.logPath}`)}`);
    }
    console.log("");
  } catch (error) {
    if (previousConfig) {
      restoreGatewayConfigFromBackup(previousConfig, "Reconfigure");
    }
    throw error;
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
  migrateLegacyComposeIfNeeded();
  runSystemctl(["start", SERVICE_NAME], ["up", "-d", "--remove-orphans"]);
}

function downCommand() {
  ensureInitialized();
  runSystemctl(["stop", SERVICE_NAME], ["down"]);
}

function restartCommand() {
  ensureInitialized();
  migrateLegacyComposeIfNeeded();
  runSystemctl(["reload", SERVICE_NAME], ["restart"]);
}

function pauseCommand() {
  ensureInitialized();
  runCompose(["pause"], { stdio: "inherit" });
  console.log("Gateway paused.");
}

function resumeCommand() {
  ensureInitialized();
  runCompose(["unpause"], { stdio: "inherit" });
  console.log("Gateway resumed.");
}

function enableCommand() {
  ensureInitialized();
  run("systemctl", ["enable", SERVICE_NAME], { stdio: "inherit" });
  console.log("Gateway will start on boot.");
}

function disableCommand() {
  ensureInitialized();
  run("systemctl", ["disable", SERVICE_NAME], { stdio: "inherit" });
  console.log("Gateway will NOT start on boot.");
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

function sipTraceCommand() {
  ensureInitialized();
  const serviceName = "gateway";
  const containerNameFallback = "bitcall-gateway";

  // Check if sngrep is available in the container
  let check = runCompose(
    ["exec", "-T", serviceName, "which", "sngrep"],
    { check: false, stdio: "pipe" }
  );

  // Backward-compatible fallback for stacks where service naming diverged.
  if (check.status !== 0) {
    check = run("docker", ["exec", containerNameFallback, "which", "sngrep"], {
      check: false,
      stdio: "pipe",
    });
  }

  if (check.status !== 0) {
    console.error("sngrep is not available in this gateway image.");
    console.error("Update to the latest image: sudo bitcall-gateway update");
    process.exit(1);
  }

  // Run sngrep interactively inside the container
  const result = runCompose(["exec", serviceName, "sngrep"], {
    check: false,
    stdio: "inherit",
  });

  process.exit(result.status || 0);
}

function formatMark(state) {
  return state ? clr(_c.green, "✓") : clr(_c.red, "✗");
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
  const containerUp = Boolean(containerStatus);
  const coturnStatus = output("sh", [
    "-lc",
    "docker ps --filter name=^bitcall-coturn$ --format '{{.Status}}'",
  ]);
  const coturnUp = Boolean(coturnStatus);

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

  const mediaStatus = isMediaIpv4OnlyRulesPresent();

  console.log(`\n${clr(_c.bold + _c.cyan, "  Bitcall Gateway Status")}\n`);
  console.log(`Gateway service: ${formatMark(active)} ${active ? "running" : "stopped"}`);
  console.log(`Auto-start: ${formatMark(enabled)} ${enabled ? "enabled" : "disabled"}`);
  console.log(`Container: ${formatMark(containerUp)} ${containerStatus || "not running"}`);
  if (envMap.TURN_MODE === "coturn") {
    console.log(`Coturn container: ${formatMark(coturnUp)} ${coturnStatus || "not running"}`);
  }
  console.log("");
  console.log(`Port ${envMap.ACME_LISTEN_PORT || "80"}: ${formatMark(p80.inUse)} listening`);
  console.log(`Port ${envMap.WSS_LISTEN_PORT || "443"}: ${formatMark(p443.inUse)} listening`);
  console.log(`Port 5060: ${formatMark(p5060.inUse)} listening`);
  console.log(`rtpengine control: ${formatMark(rtpReady)} reachable`);
  if (mediaStatus.backend) {
    console.log(`Media IPv4-only: ${mediaStatus.enabled ? "enabled" : "disabled"}`);
    console.log(`Media firewall backend: ${mediaStatus.backend}`);
  } else {
    console.log(`Media IPv4-only: disabled (backend unavailable)`);
  }
  if (!mediaStatus.enabled) {
    console.log(
      "Warning: IPv6 media may cause no-audio on some clients; enable via `bitcall-gateway media ipv4-only on`"
    );
  }
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
  console.log(`BITCALL_ENV=${envMap.BITCALL_ENV || "production"}`);
  console.log(`ROUTING_MODE=${envMap.ROUTING_MODE || "universal"}`);
  console.log(`SIP_PROVIDER_URI=${envMap.SIP_PROVIDER_URI || ""}`);
  console.log(`DEPLOY_MODE=${envMap.DEPLOY_MODE || ""}`);
  console.log(`ALLOWED_SIP_DOMAINS=${envMap.ALLOWED_SIP_DOMAINS || ""}`);
  console.log(`TURN_MODE=${envMap.TURN_MODE || "none"}`);
  console.log(`MEDIA_IPV4_ONLY=${envMap.MEDIA_IPV4_ONLY || "1"}`);
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
  migrateLegacyComposeIfNeeded();
  const envMap = loadEnvFile(ENV_PATH);
  const currentImage = envMap.BITCALL_GATEWAY_IMAGE || "";
  const targetImage = DEFAULT_GATEWAY_IMAGE;

  if (currentImage === targetImage) {
    console.log(`${clr(_c.green, "✓")} Image is current: ${clr(_c.dim, targetImage)}`);
    console.log("Checking for newer image layers...");
  } else {
    console.log(`${clr(_c.yellow, "→")} Updating: ${clr(_c.dim, currentImage || "(none)")} → ${clr(_c.bold, targetImage)}`);
    updateGatewayEnv({ BITCALL_GATEWAY_IMAGE: targetImage });
  }

  runCompose(["pull"], { stdio: "inherit" });
  runCompose(updateComposeUpArgs(), { stdio: "inherit" });
  run("systemctl", ["start", SERVICE_NAME], { check: false, stdio: "ignore" });

  console.log(`\n${clr(_c.green, "✓")} Gateway updated to ${clr(_c.bold, PACKAGE_VERSION)}.`);
  console.log(clr(_c.dim, "  To update the CLI: sudo npm i -g @bitcall/webrtc-sip-gateway@latest"));
}

function mediaStatusCommand() {
  ensureInitialized();
  const envMap = loadEnvFile(ENV_PATH);
  const desired = (envMap.MEDIA_IPV4_ONLY || "1") === "1";
  const state = isMediaIpv4OnlyRulesPresent();

  console.log("Media firewall status\n");
  console.log(`Configured mode: ${desired ? "IPv4-only" : "dual-stack"}`);
  if (!state.backend) {
    console.log(`Backend: unavailable (${state.error || "not detected"})`);
    console.log("Rules active: no");
    return;
  }

  console.log(`Backend: ${state.backend}`);
  console.log(`Rules active: ${state.enabled ? "yes" : "no"}`);
}

function mediaIpv4OnlyOnCommand() {
  ensureInitialized();
  const envMap = loadEnvFile(ENV_PATH);
  const options = mediaFirewallOptionsFromEnv(envMap);
  const applied = applyMediaIpv4OnlyRules(options);
  updateGatewayEnv({ MEDIA_IPV4_ONLY: "1" });
  console.log(`Enabled IPv6 media block rules (${applied.backend}).`);
}

function mediaIpv4OnlyOffCommand() {
  ensureInitialized();
  const envMap = loadEnvFile(ENV_PATH);
  const options = mediaFirewallOptionsFromEnv(envMap);
  const removed = removeMediaIpv4OnlyRules(options);
  updateGatewayEnv({ MEDIA_IPV4_ONLY: "0" });
  console.log(`Disabled IPv6 media block rules (${removed.backend}).`);
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

  let uninstallEnv = {};
  if (fs.existsSync(ENV_PATH)) {
    uninstallEnv = loadEnvFile(ENV_PATH);
  }

  try {
    const backend = detectFirewallBackend();
    removeMediaIpv4OnlyRules(mediaFirewallOptionsFromEnv(uninstallEnv), { backend });
  } catch (error) {
    console.log(`Warning: failed to remove IPv6 media firewall rules automatically: ${error.message}`);
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

  // Remove Bitcall-tagged UFW rules.
  if (commandExists("ufw")) {
    const ufwOutput = output("ufw", ["status", "numbered"]);
    const lines = (ufwOutput || "").split("\n");
    const ruleNumbers = [];
    for (const line of lines) {
      const match = line.match(/^\[\s*(\d+)\]/);
      if (match && line.includes("Bitcall")) {
        ruleNumbers.push(match[1]);
      }
    }

    // Delete in reverse order so indices do not shift.
    for (const num of ruleNumbers.reverse()) {
      run("ufw", ["--force", "delete", num], { check: false, stdio: "inherit" });
    }
    if (ruleNumbers.length > 0) {
      run("ufw", ["reload"], { check: false, stdio: "inherit" });
      console.log(`Removed ${ruleNumbers.length} UFW rule(s).`);
    }
  }

  if (fs.existsSync(GATEWAY_DIR)) {
    fs.rmSync(GATEWAY_DIR, { recursive: true, force: true });
  }

  console.log(`\n${clr(_c.green, "✓")} ${clr(_c.bold, "Gateway uninstalled.")}`);
  const domain = uninstallEnv.DOMAIN || "";
  console.log(`\n${clr(_c.dim, "To remove the CLI:")}`);
  console.log("  sudo npm uninstall -g @bitcall/webrtc-sip-gateway");
  if (domain && uninstallEnv.TLS_MODE === "letsencrypt") {
    console.log(`\n${clr(_c.dim, "To remove Let's Encrypt certificate:")}`);
    console.log(`  sudo certbot delete --cert-name ${domain}`);
  }
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
  const { Command } = require("commander");
  const program = new Command();

  program
    .name("bitcall-gateway")
    .description("Install and operate Bitcall WebRTC-to-SIP gateway")
    .version(PACKAGE_VERSION);

  program
    .command("init")
    .description("Run setup wizard and provision gateway")
    .option("--advanced", "Show advanced configuration prompts")
    .option("--dev", "Quick dev setup (minimal prompts, permissive defaults)")
    .option("--production", "Production setup profile")
    .option("--domain <domain>", "Gateway domain")
    .option("--email <email>", "Let's Encrypt email")
    .option("--verbose", "Stream full installer command output")
    .action(initCommand);
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
  program
    .command("sip-trace")
    .description("Live SIP message viewer (sngrep)")
    .action(sipTraceCommand);

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
  program.command("pause").description("Pause gateway containers").action(pauseCommand);
  program.command("resume").description("Resume paused gateway containers").action(resumeCommand);
  program.command("enable").description("Enable auto-start on boot").action(enableCommand);
  program.command("disable").description("Disable auto-start on boot").action(disableCommand);
  program
    .command("reconfigure")
    .description("Re-run wizard with current values as defaults")
    .option("--advanced", "Show advanced configuration prompts")
    .option("--dev", "Dev mode")
    .option("--production", "Production mode")
    .option("--verbose", "Verbose output")
    .action(reconfigureCommand);

  const media = program.command("media").description("Media firewall operations");
  media.command("status").description("Show media IPv4-only firewall state").action(mediaStatusCommand);
  const mediaIpv4Only = media.command("ipv4-only").description("Toggle IPv6 media block");
  mediaIpv4Only.command("on").description("Enable IPv4-only media mode").action(mediaIpv4OnlyOnCommand);
  mediaIpv4Only.command("off").description("Disable IPv4-only media mode").action(mediaIpv4OnlyOffCommand);

  program
    .command("uninstall")
    .description("Remove gateway service and files")
    .option("-y, --yes", "Skip confirmation prompt")
    .action(uninstallCommand);

  return program;
}

async function main(argv = process.argv) {
  const program = buildProgram();
  const normalizedArgv = argv.map((value, index) => {
    if (index <= 1) {
      return value;
    }
    if (value === "--sip-trace" || value === "-sip-trace") {
      return "sip-trace";
    }
    return value;
  });
  await program.parseAsync(normalizedArgv);
}

module.exports = {
  main,
  normalizeInitProfile,
  validateProductionConfig,
  buildSecurityNotes,
  buildQuickFlowDefaults,
  shouldRequireAllowlist,
  stripLegacyKamailioVolume,
  updateComposeUpArgs,
  isOriginWildcard,
  isSingleProviderConfigured,
  printRequiredPorts,
};

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
