"use strict";

const fs = require("fs");
const { output, run, runShell, commandExists } = require("./shell");

function pickExec(options = {}) {
  if (typeof options.exec === "function") {
    return options.exec;
  }
  return (command, args = [], execOptions = {}) => run(command, args, execOptions);
}

function pickShell(options = {}) {
  if (typeof options.shell === "function") {
    return options.shell;
  }
  return (script, execOptions = {}) => runShell(script, execOptions);
}

function parseOsRelease() {
  const info = {};
  const content = fs.readFileSync("/etc/os-release", "utf8");

  for (const line of content.split(/\r?\n/)) {
    if (!line || line.startsWith("#")) {
      continue;
    }
    const idx = line.indexOf("=");
    if (idx < 0) {
      continue;
    }
    const key = line.slice(0, idx);
    const value = line.slice(idx + 1).replace(/^"|"$/g, "");
    info[key] = value;
  }

  return info;
}

function isSupportedDistro() {
  const os = parseOsRelease();
  const id = (os.ID || "").toLowerCase();
  const version = Number.parseFloat(os.VERSION_ID || "0");

  if (id === "ubuntu") {
    return version >= 22;
  }

  if (id === "debian") {
    return version >= 12;
  }

  return false;
}

function detectPublicIp() {
  const probes = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
  ];

  for (const url of probes) {
    const result = run("curl", ["-fsS", "--max-time", "5", url], {
      check: false,
      stdio: "pipe",
    });

    if (result.status === 0) {
      const ip = (result.stdout || "").trim();
      if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
        return ip;
      }
    }
  }

  return "";
}

function resolveDomainIpv4(domain) {
  const result = run("getent", ["ahostsv4", domain], { check: false });
  if (result.status !== 0) {
    return [];
  }

  const values = new Set();
  for (const line of (result.stdout || "").split(/\r?\n/)) {
    const ip = line.trim().split(/\s+/)[0];
    if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
      values.add(ip);
    }
  }

  return [...values];
}

function diskFreeGb(targetPath = "/") {
  const text = output("df", ["-Pk", targetPath]);
  const lines = text.split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) {
    return 0;
  }

  const parts = lines[1].trim().split(/\s+/);
  const availableKb = Number.parseInt(parts[3], 10);
  return Math.floor(availableKb / 1024 / 1024);
}

function memoryTotalMb() {
  const content = fs.readFileSync("/proc/meminfo", "utf8");
  const match = content.match(/^MemTotal:\s+(\d+)\s+kB$/m);
  if (!match) {
    return 0;
  }
  return Math.floor(Number.parseInt(match[1], 10) / 1024);
}

function portInUse(port) {
  const result = runShell(`ss -H -ltnup | grep -E '[:.]${port}\\b'`, {
    check: false,
  });

  return {
    inUse: result.status === 0,
    detail: (result.stdout || "").trim(),
  };
}

function ensureDockerInstalled(options = {}) {
  const exec = pickExec(options);
  const shell = pickShell(options);

  if (commandExists("docker") && run("docker", ["info"], { check: false }).status === 0) {
    return;
  }

  exec("apt-get", ["update"]);
  exec("apt-get", ["install", "-y", "curl", "ca-certificates", "gnupg"]);
  shell("curl -fsSL https://get.docker.com | sh");
  exec("systemctl", ["enable", "docker.service"]);
  exec("systemctl", ["enable", "containerd.service"]);
  exec("systemctl", ["start", "docker"]);
}

function ensureComposePlugin(options = {}) {
  const exec = pickExec(options);

  if (run("docker", ["compose", "version"], { check: false }).status === 0) {
    return;
  }

  exec("apt-get", ["update"]);
  exec("apt-get", ["install", "-y", "docker-compose-plugin"]);
}

module.exports = {
  parseOsRelease,
  isSupportedDistro,
  detectPublicIp,
  resolveDomainIpv4,
  diskFreeGb,
  memoryTotalMb,
  portInUse,
  ensureDockerInstalled,
  ensureComposePlugin,
};
