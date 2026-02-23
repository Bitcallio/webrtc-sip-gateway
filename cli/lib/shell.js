"use strict";

const { spawnSync } = require("child_process");

function run(command, args = [], options = {}) {
  const {
    cwd,
    env,
    stdio = "pipe",
    check = true,
    input,
    quiet = false,
  } = options;

  const result = spawnSync(command, args, {
    cwd,
    env,
    input,
    stdio,
    encoding: "utf8",
  });

  if (result.error) {
    throw result.error;
  }

  if (check && typeof result.status === "number" && result.status !== 0) {
    const detail = [result.stdout, result.stderr]
      .filter(Boolean)
      .join("\n")
      .trim();
    const suffix = detail ? `\n${detail}` : "";
    throw new Error(`Command failed: ${command} ${args.join(" ")}${suffix}`);
  }

  if (!quiet && stdio === "inherit") {
    return result;
  }

  return result;
}

function runShell(script, options = {}) {
  return run("sh", ["-lc", script], options);
}

function commandExists(command) {
  const result = spawnSync("sh", ["-lc", `command -v ${command}`], {
    stdio: "ignore",
  });
  return result.status === 0;
}

function output(command, args = [], options = {}) {
  const result = run(command, args, { ...options, stdio: "pipe" });
  return (result.stdout || "").trim();
}

module.exports = {
  run,
  runShell,
  output,
  commandExists,
};
