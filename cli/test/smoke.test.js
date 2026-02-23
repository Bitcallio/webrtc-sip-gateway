#!/usr/bin/env node
const assert = require("assert").strict;
const fs = require("fs");
const path = require("path");

function expectExists(target) {
  assert.equal(fs.existsSync(target), true, `${target} should exist`);
}

(function main() {
  const templateDir = path.resolve(__dirname, "../templates");
  expectExists(path.join(templateDir, ".env.template"));
  expectExists(path.join(templateDir, "docker-compose.yml.template"));

  expectExists(path.resolve(__dirname, "../bin/bitcall-gateway.js"));
  expectExists(path.resolve(__dirname, "../src/index.js"));

  const libDir = path.resolve(__dirname, "../lib");
  expectExists(path.join(libDir, "constants.js"));
  expectExists(path.join(libDir, "shell.js"));
  expectExists(path.join(libDir, "envfile.js"));
  expectExists(path.join(libDir, "prompt.js"));
  expectExists(path.join(libDir, "system.js"));
  expectExists(path.join(libDir, "template.js"));

  console.log("smoke tests passed");
})();
