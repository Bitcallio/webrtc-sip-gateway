#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { Command } = require("commander");

const GATEWAY_DIR = "/opt/bitcall-gateway";
const TEMPLATE_DIR = path.resolve(__dirname, "../templates");

function readTemplate(name) {
  return fs.readFileSync(path.join(TEMPLATE_DIR, name), "utf8");
}

function writeFileIfNeeded(filePath, content, force) {
  if (!force && fs.existsSync(filePath)) {
    return false;
  }

  fs.writeFileSync(filePath, content, { mode: 0o640 });
  return true;
}

function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    stdio: "inherit",
    ...options,
  });

  if (result.error) {
    throw result.error;
  }

  if (typeof result.status === "number" && result.status !== 0) {
    process.exit(result.status);
  }
}

function detectComposeCommand() {
  const dockerCompose = spawnSync("docker", ["compose", "version"], {
    stdio: "ignore",
  });

  if (dockerCompose.status === 0) {
    return { command: "docker", prefixArgs: ["compose"] };
  }

  const dockerComposeLegacy = spawnSync("docker-compose", ["version"], {
    stdio: "ignore",
  });

  if (dockerComposeLegacy.status === 0) {
    return { command: "docker-compose", prefixArgs: [] };
  }

  throw new Error(
    "docker compose is required but was not found. Install Docker Engine with compose plugin."
  );
}

function runCompose(compose, args) {
  runCommand(compose.command, [...compose.prefixArgs, ...args], {
    cwd: GATEWAY_DIR,
  });
}

function ensureInitialized() {
  const composeFilePath = path.join(GATEWAY_DIR, "docker-compose.yml");
  if (!fs.existsSync(composeFilePath)) {
    throw new Error(
      "Gateway environment is not initialized. Run: sudo bitcall-gateway init"
    );
  }
}

function initCommand(options) {
  const compose = detectComposeCommand();

  fs.mkdirSync(GATEWAY_DIR, { recursive: true, mode: 0o750 });

  const envTemplate = readTemplate(".env.template");
  const composeTemplate = readTemplate("docker-compose.yml.template");

  const envPath = path.join(GATEWAY_DIR, ".env");
  const composePath = path.join(GATEWAY_DIR, "docker-compose.yml");

  const envWritten = writeFileIfNeeded(envPath, envTemplate, options.force);
  const composeWritten = writeFileIfNeeded(composePath, composeTemplate, options.force);

  if (envWritten) {
    console.log(`Wrote ${envPath}`);
  } else {
    console.log(`Kept existing ${envPath}`);
  }

  if (composeWritten) {
    console.log(`Wrote ${composePath}`);
  } else {
    console.log(`Kept existing ${composePath}`);
  }

  if (!options.start) {
    console.log("Initialization complete. Start manually with: sudo bitcall-gateway up");
    return;
  }

  runCompose(compose, ["up", "-d"]);
}

function upCommand() {
  ensureInitialized();
  const compose = detectComposeCommand();
  runCompose(compose, ["up", "-d"]);
}

function downCommand() {
  ensureInitialized();
  const compose = detectComposeCommand();
  runCompose(compose, ["down"]);
}

function statusCommand() {
  ensureInitialized();
  const compose = detectComposeCommand();
  runCompose(compose, ["ps"]);
}

function logsCommand(service, options) {
  ensureInitialized();
  const compose = detectComposeCommand();

  const args = ["logs", "--tail", options.tail];
  if (options.follow) {
    args.push("-f");
  }

  if (service) {
    args.push(service);
  }

  runCompose(compose, args);
}

function main() {
  const program = new Command();

  program
    .name("bitcall-gateway")
    .description("Manage the Bitcall WebRTC-SIP Gateway deployment")
    .version("0.1.0");

  program
    .command("init")
    .description("Initialize /opt/bitcall-gateway with compose assets and start services")
    .option("--force", "Overwrite existing .env and docker-compose.yml")
    .option("--no-start", "Create files only, do not run docker compose")
    .action(initCommand);

  program.command("up").description("Start gateway services").action(upCommand);

  program.command("down").description("Stop gateway services").action(downCommand);

  program.command("status").description("Show service status").action(statusCommand);

  program
    .command("logs [service]")
    .description("Show gateway logs")
    .option("--tail <lines>", "Number of log lines", "200")
    .option("--follow", "Follow log output", true)
    .option("--no-follow", "Print logs and exit")
    .action(logsCommand);

  program.parse(process.argv);
}

try {
  main();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
