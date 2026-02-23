const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("required templates exist", () => {
  const templateDir = path.resolve(__dirname, "../templates");
  const envTemplate = path.join(templateDir, ".env.template");
  const composeTemplate = path.join(templateDir, "docker-compose.yml.template");

  assert.equal(fs.existsSync(envTemplate), true);
  assert.equal(fs.existsSync(composeTemplate), true);
});
