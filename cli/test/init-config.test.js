#!/usr/bin/env node
"use strict";

const assert = require("assert").strict;

const {
  normalizeInitProfile,
  validateProductionConfig,
  buildSecurityNotes,
  buildQuickFlowDefaults,
  shouldRequireAllowlist,
} = require("../src/index");

(function testNormalizeInitProfile() {
  assert.equal(normalizeInitProfile({}, {}), "production");
  assert.equal(normalizeInitProfile({ dev: true }, {}), "dev");
  assert.equal(normalizeInitProfile({ production: true }, {}), "production");
  assert.equal(normalizeInitProfile({}, { BITCALL_ENV: "production" }), "production");
})();

(function testQuickFlowDefaultsDev() {
  const defaults = buildQuickFlowDefaults("dev", {
    ALLOWED_SIP_DOMAINS: "sip.example.com",
    WEBPHONE_ORIGIN: "https://app.example.com",
    SIP_TRUSTED_IPS: "198.51.100.10",
  });

  assert.equal(defaults.bitcallEnv, "dev");
  assert.equal(defaults.routingMode, "universal");
  assert.equal(defaults.sipProviderUri, "");
  assert.equal(defaults.allowedDomains, "");
  assert.equal(defaults.webphoneOrigin, "*");
  assert.equal(defaults.sipTrustedIps, "");
})();

(function testQuickFlowDefaultsProduction() {
  const defaults = buildQuickFlowDefaults("production", {
    ALLOWED_SIP_DOMAINS: "sip.example.com",
    WEBPHONE_ORIGIN: "https://app.example.com",
    SIP_TRUSTED_IPS: "198.51.100.10",
  });

  assert.equal(defaults.bitcallEnv, "production");
  assert.equal(defaults.routingMode, "universal");
  assert.equal(defaults.sipProviderUri, "");
  assert.equal(defaults.allowedDomains, "sip.example.com");
  assert.equal(defaults.webphoneOrigin, "https://app.example.com");
  assert.equal(defaults.sipTrustedIps, "198.51.100.10");
})();

(function testSecurityNotes() {
  const notes = buildSecurityNotes({
    allowedDomains: "",
    webphoneOrigin: "*",
    sipTrustedIps: "",
  });
  assert.equal(notes.length, 3);
})();

(function testAllowlistRequirementRules() {
  assert.equal(shouldRequireAllowlist("production", "universal"), false);
  assert.equal(shouldRequireAllowlist("production", "single-provider"), false);
  assert.equal(shouldRequireAllowlist("dev", "universal"), false);
})();

(function testProductionValidationFailsSingleProviderWithoutUri() {
  assert.throws(
    () =>
      validateProductionConfig({
        routingMode: "single-provider",
        sipProviderUri: "",
        allowedDomains: "",
        webphoneOrigin: "*",
        turnApiToken: "",
      }),
    /Single-provider mode requires SIP_PROVIDER_URI/
  );
})();

(function testProductionValidationAllowsSingleProviderWithUri() {
  assert.doesNotThrow(() =>
    validateProductionConfig({
      routingMode: "single-provider",
      sipProviderUri: "sip:provider.example:5060;transport=udp",
      allowedDomains: "",
      webphoneOrigin: "*",
      turnApiToken: "token",
    })
  );
})();

(function testProductionValidationAllowsUniversalWildcard() {
  assert.doesNotThrow(() =>
    validateProductionConfig({
      routingMode: "universal",
      sipProviderUri: "",
      allowedDomains: "",
      webphoneOrigin: "*",
      turnApiToken: "",
    })
  );
})();

console.log("init config tests passed");
