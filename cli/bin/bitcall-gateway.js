#!/usr/bin/env node
if (process.getuid && process.getuid() !== 0) {
  console.error("Error: bitcall-gateway requires root privileges.");
  console.error(`Run with: sudo bitcall-gateway ${process.argv.slice(2).join(" ")}`);
  process.exit(1);
}

require("../src/index").main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
