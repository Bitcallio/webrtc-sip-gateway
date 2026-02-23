"use strict";

const path = require("path");

const GATEWAY_DIR = "/opt/bitcall-gateway";
const SERVICE_NAME = "bitcall-gateway";
const SERVICE_FILE = `/etc/systemd/system/${SERVICE_NAME}.service`;

module.exports = {
  GATEWAY_DIR,
  SERVICE_NAME,
  SERVICE_FILE,
  ACME_WEBROOT: path.join(GATEWAY_DIR, "acme-webroot"),
  SSL_DIR: path.join(GATEWAY_DIR, "ssl"),
  ENV_PATH: path.join(GATEWAY_DIR, ".env"),
  COMPOSE_PATH: path.join(GATEWAY_DIR, "docker-compose.yml"),
  DEFAULT_GATEWAY_IMAGE: "ghcr.io/bitcallio/webrtc-sip-gateway:0.2.0",
  DEFAULT_PROVIDER_HOST: "sip.example.com",
  DEFAULT_WEBPHONE_ORIGIN: "*",
  RENEW_HOOK_PATH: "/etc/letsencrypt/renewal-hooks/deploy/bitcall-gateway.sh",
};
