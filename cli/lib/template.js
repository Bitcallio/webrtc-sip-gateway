"use strict";

const fs = require("fs");
const path = require("path");

const TEMPLATE_DIR = path.resolve(__dirname, "../templates");

function readTemplate(name) {
  return fs.readFileSync(path.join(TEMPLATE_DIR, name), "utf8");
}

function renderTemplate(name, values) {
  let content = readTemplate(name);
  for (const [key, value] of Object.entries(values)) {
    const token = `__${key}__`;
    content = content.split(token).join(String(value === undefined || value === null ? "" : value));
  }
  return content;
}

module.exports = {
  readTemplate,
  renderTemplate,
};
