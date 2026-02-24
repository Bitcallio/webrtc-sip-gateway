#!/usr/bin/env node
"use strict";

const assert = require("assert").strict;

const {
  MARKER,
  detectFirewallBackend,
  buildIp6tablesRules,
  buildNftRuleset,
  applyMediaIpv4OnlyRules,
  removeMediaIpv4OnlyRules,
  isMediaIpv4OnlyRulesPresent,
} = require("../lib/firewall");

function createIp6MockDeps() {
  const installed = new Set();
  const calls = [];

  function keyForCheck(args) {
    return args.slice(1).join(" ");
  }

  function keyForInsert(args) {
    return [args[1], ...args.slice(3)].join(" ");
  }

  function keyForDelete(args) {
    return args.slice(1).join(" ");
  }

  return {
    calls,
    commandExists(command) {
      return command === "ip6tables" || command === "netfilter-persistent";
    },
    run(command, args = []) {
      calls.push({ command, args: [...args] });

      if (command === "ip6tables") {
        const action = args[0];
        if (action === "-C") {
          return { status: installed.has(keyForCheck(args)) ? 0 : 1, stdout: "", stderr: "" };
        }
        if (action === "-I") {
          installed.add(keyForInsert(args));
          return { status: 0, stdout: "", stderr: "" };
        }
        if (action === "-D") {
          installed.delete(keyForDelete(args));
          return { status: 0, stdout: "", stderr: "" };
        }
      }

      return { status: 0, stdout: "", stderr: "" };
    },
    output(command, args = []) {
      if (command === "sh" && args.includes("ip6tables-save 2>/dev/null || true")) {
        return Array.from(installed)
          .map((line) => `-A ${line}`)
          .join("\n");
      }
      return "";
    },
  };
}

(function testDetectBackendPreference() {
  const backend = detectFirewallBackend({
    commandExists(command) {
      return command === "nft" || command === "ip6tables";
    },
  });
  assert.equal(backend, "nft");
})();

(function testDetectBackendUsesIp6tablesWhenUfwActive() {
  const backend = detectFirewallBackend({
    commandExists(command) {
      return command === "nft" || command === "ip6tables" || command === "ufw";
    },
    run(command, args = []) {
      if (command === "ufw" && args[0] === "status") {
        return { status: 0, stdout: "Status: active\\n", stderr: "" };
      }
      return { status: 0, stdout: "", stderr: "" };
    },
  });

  assert.equal(backend, "ip6tables");
})();

(function testRuleBuilders() {
  const rules = buildIp6tablesRules({
    rtpMin: 10000,
    rtpMax: 20000,
    turnEnabled: true,
    turnUdpPort: 3478,
    turnsTcpPort: 5349,
    turnRelayMin: 49152,
    turnRelayMax: 49252,
  });

  assert.equal(rules.length, 4);
  assert.equal(rules[0].dport, "10000:20000");
  assert.equal(rules[1].dport, "3478");
  assert.equal(rules[2].dport, "5349");
  assert.equal(rules[3].dport, "49152:49252");

  const nft = buildNftRuleset({ turnEnabled: true });
  assert.match(nft, /table inet bitcall_gateway_media_ipv6/);
  assert.match(nft, /meta nfproto ipv6 udp dport 10000:20000/);
  assert.match(nft, /meta nfproto ipv6 tcp dport 5349/);
  assert.match(nft, new RegExp(MARKER));
})();

(function testIp6tablesApplyIsIdempotentAndRemovable() {
  const deps = createIp6MockDeps();
  const options = {
    rtpMin: 10000,
    rtpMax: 20000,
    turnEnabled: true,
    turnUdpPort: 3478,
    turnsTcpPort: 5349,
    turnRelayMin: 49152,
    turnRelayMax: 49252,
  };

  applyMediaIpv4OnlyRules(options, { backend: "ip6tables", deps });
  const insertsAfterFirstApply = deps.calls.filter(
    (entry) => entry.command === "ip6tables" && entry.args[0] === "-I"
  ).length;
  assert.equal(insertsAfterFirstApply, 4);

  applyMediaIpv4OnlyRules(options, { backend: "ip6tables", deps });
  const insertsAfterSecondApply = deps.calls.filter(
    (entry) => entry.command === "ip6tables" && entry.args[0] === "-I"
  ).length;
  assert.equal(insertsAfterSecondApply, 4, "second apply must not add duplicate rules");

  const presentBeforeRemove = isMediaIpv4OnlyRulesPresent({ backend: "ip6tables", deps });
  assert.equal(presentBeforeRemove.enabled, true);

  removeMediaIpv4OnlyRules(options, { backend: "ip6tables", deps });
  const presentAfterRemove = isMediaIpv4OnlyRulesPresent({ backend: "ip6tables", deps });
  assert.equal(presentAfterRemove.enabled, false);
})();

console.log("firewall tests passed");
