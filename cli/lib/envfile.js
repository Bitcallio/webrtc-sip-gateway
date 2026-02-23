"use strict";

const fs = require("fs");

function parseEnv(content) {
  const data = {};

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const idx = line.indexOf("=");
    if (idx < 0) {
      continue;
    }

    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1);
    data[key] = value;
  }

  return data;
}

function loadEnvFile(filePath) {
  return parseEnv(fs.readFileSync(filePath, "utf8"));
}

function serializeEnv(entries) {
  return entries
    .filter((entry) => entry && entry.key)
    .map((entry) => `${entry.key}=${entry.value === undefined || entry.value === null ? "" : entry.value}`)
    .join("\n") + "\n";
}

function writeEnvFile(filePath, entries, mode = 0o600) {
  const payload = serializeEnv(entries);
  fs.writeFileSync(filePath, payload, { mode });
}

module.exports = {
  parseEnv,
  loadEnvFile,
  serializeEnv,
  writeEnvFile,
};
