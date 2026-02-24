#!/usr/bin/env node
"use strict";

const assert = require("assert").strict;

const {
  normalizeInitProfile,
  validateProductionConfig,
  buildDevWarnings,
  buildQuickFlowDefaults,
} = require("../src/index");

(function testNormalizeInitProfile() {
  assert.equal(normalizeInitProfile({}, {}), "dev");
  assert.equal(normalizeInitProfile({ dev: true }, {}), "dev");
  assert.equal(normalizeInitProfile({ production: true }, {}), "production");
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

(function testDevWarnings() {
  const warnings = buildDevWarnings({
    allowedDomains: "",
    webphoneOrigin: "*",
    sipTrustedIps: "",
  });
  assert.equal(warnings.length, 3);
})();

(function testProductionValidationFailsWithoutAllowlistOrProvider() {
  assert.throws(
    () =>
      validateProductionConfig({
        routingMode: "universal",
        sipProviderUri: "",
        allowedDomains: "",
        webphoneOrigin: "https://app.example.com",
        turnApiToken: "",
      }),
    /ALLOWED_SIP_DOMAINS or single-provider routing/
  );
})();

(function testProductionValidationFailsWithoutOriginOrToken() {
  assert.throws(
    () =>
      validateProductionConfig({
        routingMode: "universal",
        sipProviderUri: "",
        allowedDomains: "sip.example.com",
        webphoneOrigin: "*",
        turnApiToken: "",
      }),
    /WEBPHONE_ORIGIN_PATTERN or TURN_API_TOKEN/
  );
})();

(function testProductionValidationAllowsSingleProviderAndToken() {
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

console.log("init config tests passed");
