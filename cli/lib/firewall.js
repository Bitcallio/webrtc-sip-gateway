"use strict";

const fs = require("fs");
const path = require("path");

const { run, runShell, output, commandExists } = require("./shell");

const MARKER = "bitcall-gateway media ipv6 block";
const NFT_TABLE = "bitcall_gateway_media_ipv6";
const NFT_RULE_FILE = "/etc/nftables.d/bitcall-gateway.nft";
const NFT_MAIN_CONF = "/etc/nftables.conf";
const NFT_INCLUDE_LINE = `include "${NFT_RULE_FILE}"`;

function withDeps(deps = {}) {
  return {
    fs,
    run,
    runShell,
    output,
    commandExists,
    ...deps,
  };
}

function toInt(value, fallback) {
  const parsed = Number.parseInt(String(value), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeOptions(options = {}) {
  const rtpMin = toInt(options.rtpMin, 10000);
  const rtpMax = toInt(options.rtpMax, 20000);
  const turnEnabled = Boolean(options.turnEnabled);
  const turnUdpPort = toInt(options.turnUdpPort, 3478);
  const turnsTcpPort = toInt(options.turnsTcpPort, 5349);
  const turnRelayMin = toInt(options.turnRelayMin, 49152);
  const turnRelayMax = toInt(options.turnRelayMax, 49252);

  return {
    rtpMin,
    rtpMax,
    turnEnabled,
    turnUdpPort,
    turnsTcpPort,
    turnRelayMin,
    turnRelayMax,
  };
}

function detectFirewallBackend(deps = {}) {
  const d = withDeps(deps);
  let ufwActive = false;
  if (d.commandExists("ufw")) {
    const ufwStatus = d.run("ufw", ["status"], { check: false, stdio: "pipe" });
    ufwActive = ufwStatus.status === 0 && ((ufwStatus.stdout || "").toLowerCase().includes("status: active"));
  }

  if (ufwActive && d.commandExists("ip6tables")) {
    return "ip6tables";
  }

  if (d.commandExists("nft")) {
    return "nft";
  }
  if (d.commandExists("ip6tables")) {
    return "ip6tables";
  }
  throw new Error(
    "No IPv6 firewall backend found. Install nftables or ip6tables/netfilter-persistent."
  );
}

function buildIp6tablesRules(options = {}) {
  const cfg = normalizeOptions(options);
  const rules = [
    { proto: "udp", dport: `${cfg.rtpMin}:${cfg.rtpMax}` },
  ];

  if (cfg.turnEnabled) {
    rules.push({ proto: "udp", dport: String(cfg.turnUdpPort) });
    rules.push({ proto: "tcp", dport: String(cfg.turnsTcpPort) });
    rules.push({ proto: "udp", dport: `${cfg.turnRelayMin}:${cfg.turnRelayMax}` });
  }

  return rules;
}

function buildNftRuleset(options = {}) {
  const rules = buildIp6tablesRules(options);
  const lines = [
    `table inet ${NFT_TABLE} {`,
    "  chain input {",
    "    type filter hook input priority 0; policy accept;",
  ];

  for (const rule of rules) {
    lines.push(
      `    meta nfproto ipv6 ${rule.proto} dport ${rule.dport} comment \"${MARKER}\" drop`
    );
  }

  lines.push("  }");
  lines.push("}");
  lines.push("");

  return lines.join("\n");
}

function persistIp6tables(d) {
  const aptEnv = {
    ...process.env,
    DEBIAN_FRONTEND: "noninteractive",
    NEEDRESTART_MODE: "a",
  };

  if (!d.commandExists("netfilter-persistent")) {
    d.run("apt-get", ["update"], { stdio: "inherit", env: aptEnv });
    d.run("apt-get", ["install", "-y", "netfilter-persistent", "iptables-persistent"], {
      check: false,
      stdio: "inherit",
      env: aptEnv,
    });
  }

  if (!d.commandExists("netfilter-persistent")) {
    throw new Error("Unable to persist ip6tables rules: netfilter-persistent not available.");
  }

  const saved = d.run("netfilter-persistent", ["save"], {
    check: false,
    stdio: "inherit",
  });
  if (saved.status !== 0) {
    throw new Error("Failed to persist ip6tables rules with netfilter-persistent save.");
  }
}

function ensureNftInclude(d) {
  let content = "";
  if (d.fs.existsSync(NFT_MAIN_CONF)) {
    content = d.fs.readFileSync(NFT_MAIN_CONF, "utf8");
  } else {
    content = "#!/usr/sbin/nft -f\n\n";
  }

  if (!content.includes(NFT_INCLUDE_LINE)) {
    const suffix = content.endsWith("\n") ? "" : "\n";
    content = `${content}${suffix}${NFT_INCLUDE_LINE}\n`;
    d.fs.writeFileSync(NFT_MAIN_CONF, content, { mode: 0o644 });
    d.fs.chmodSync(NFT_MAIN_CONF, 0o644);
  }
}

function removeNftInclude(d) {
  if (!d.fs.existsSync(NFT_MAIN_CONF)) {
    return;
  }

  const content = d.fs.readFileSync(NFT_MAIN_CONF, "utf8");
  const lines = content.split("\n").filter((line) => line.trim() !== NFT_INCLUDE_LINE);
  const next = `${lines.join("\n").replace(/\n+$/g, "")}\n`;
  d.fs.writeFileSync(NFT_MAIN_CONF, next, { mode: 0o644 });
  d.fs.chmodSync(NFT_MAIN_CONF, 0o644);
}

function applyNftRules(options, d) {
  d.fs.mkdirSync(path.dirname(NFT_RULE_FILE), { recursive: true, mode: 0o755 });
  d.fs.writeFileSync(NFT_RULE_FILE, buildNftRuleset(options), { mode: 0o644 });
  d.fs.chmodSync(NFT_RULE_FILE, 0o644);

  d.run("nft", ["delete", "table", "inet", NFT_TABLE], {
    check: false,
    stdio: "ignore",
  });
  d.run("nft", ["-f", NFT_RULE_FILE], { stdio: "inherit" });

  ensureNftInclude(d);

  const enabled = d.run("systemctl", ["enable", "--now", "nftables"], {
    check: false,
    stdio: "inherit",
  });
  if (enabled.status !== 0) {
    throw new Error("Failed to enable nftables service for persistent IPv6 media block rules.");
  }
}

function removeNftRules(d) {
  d.run("nft", ["delete", "table", "inet", NFT_TABLE], {
    check: false,
    stdio: "ignore",
  });

  if (d.fs.existsSync(NFT_RULE_FILE)) {
    d.fs.rmSync(NFT_RULE_FILE, { force: true });
  }
  removeNftInclude(d);

  d.run("systemctl", ["reload", "nftables"], {
    check: false,
    stdio: "ignore",
  });
}

function ip6tableRuleArgs(rule) {
  return [
    "-p",
    rule.proto,
    "--dport",
    rule.dport,
    "-m",
    "comment",
    "--comment",
    MARKER,
    "-j",
    "DROP",
  ];
}

function applyIp6tablesRules(options, d) {
  const rules = buildIp6tablesRules(options);

  for (const rule of rules) {
    const args = ip6tableRuleArgs(rule);
    const exists = d.run("ip6tables", ["-C", "INPUT", ...args], {
      check: false,
      stdio: "ignore",
    }).status === 0;

    if (!exists) {
      d.run("ip6tables", ["-I", "INPUT", "1", ...args], {
        stdio: "inherit",
      });
    }
  }

  persistIp6tables(d);
}

function removeIp6tablesRules(options, d) {
  const rules = buildIp6tablesRules(options);

  for (const rule of rules) {
    const args = ip6tableRuleArgs(rule);
    for (;;) {
      const exists = d.run("ip6tables", ["-C", "INPUT", ...args], {
        check: false,
        stdio: "ignore",
      }).status === 0;

      if (!exists) {
        break;
      }

      d.run("ip6tables", ["-D", "INPUT", ...args], {
        stdio: "inherit",
      });
    }
  }

  persistIp6tables(d);
}

function isNftPresent(d) {
  const res = d.run("nft", ["list", "table", "inet", NFT_TABLE], {
    check: false,
    stdio: "pipe",
  });
  if (res.status !== 0) {
    return false;
  }
  return (res.stdout || "").includes(MARKER);
}

function isIp6tablesPresent(d) {
  const rules = d.output("sh", ["-lc", "ip6tables-save 2>/dev/null || true"]);
  return rules.includes(MARKER);
}

function applyMediaIpv4OnlyRules(options = {}, runtime = {}) {
  const d = withDeps(runtime.deps);
  const backend = runtime.backend || detectFirewallBackend(d);

  if (backend === "nft") {
    applyNftRules(options, d);
    return { backend };
  }

  if (backend === "ip6tables") {
    applyIp6tablesRules(options, d);
    return { backend };
  }

  throw new Error(`Unsupported firewall backend: ${backend}`);
}

function removeMediaIpv4OnlyRules(options = {}, runtime = {}) {
  const d = withDeps(runtime.deps);
  const backend = runtime.backend || detectFirewallBackend(d);

  if (backend === "nft") {
    removeNftRules(d);
    return { backend };
  }

  if (backend === "ip6tables") {
    removeIp6tablesRules(options, d);
    return { backend };
  }

  throw new Error(`Unsupported firewall backend: ${backend}`);
}

function isMediaIpv4OnlyRulesPresent(runtime = {}) {
  const d = withDeps(runtime.deps);
  let backend = runtime.backend;

  try {
    backend = backend || detectFirewallBackend(d);
  } catch (error) {
    return {
      enabled: false,
      backend: null,
      error: error.message,
    };
  }

  if (backend === "nft") {
    return {
      enabled: isNftPresent(d),
      backend,
      marker: MARKER,
    };
  }

  if (backend === "ip6tables") {
    return {
      enabled: isIp6tablesPresent(d),
      backend,
      marker: MARKER,
    };
  }

  return {
    enabled: false,
    backend,
    marker: MARKER,
  };
}

module.exports = {
  MARKER,
  NFT_TABLE,
  NFT_RULE_FILE,
  NFT_MAIN_CONF,
  NFT_INCLUDE_LINE,
  normalizeOptions,
  detectFirewallBackend,
  buildIp6tablesRules,
  buildNftRuleset,
  applyMediaIpv4OnlyRules,
  removeMediaIpv4OnlyRules,
  isMediaIpv4OnlyRulesPresent,
};
