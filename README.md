# webrtc-sip-gateway

Bitcall WebRTC-to-SIP gateway repository.

## Components

- `docker/`: Gateway image (Kamailio + rtpengine + healthcheck responder)
- `cli/`: Linux npm CLI `@bitcall/webrtc-sip-gateway`
- `.github/workflows/`: CI

## End-user install (VPS)

```bash
sudo apt-get update && sudo apt-get install -y curl ca-certificates
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
sudo npm i -g @bitcall/webrtc-sip-gateway@0.2.8
sudo bitcall-gateway init --dev
```

Default `init` behavior is dev-friendly and uses permissive defaults:
- `BITCALL_ENV=dev`
- `ROUTING_MODE=universal`
- `ALLOWED_SIP_DOMAINS=""` (any provider domains, dev warning shown)
- `WEBPHONE_ORIGIN="*"` (any origin, dev warning shown)
- `SIP_TRUSTED_IPS=""` (any source IPs)

For hardened installs use `sudo bitcall-gateway init --production` (or add
`--advanced` for full control). In production + universal routing, provider
allowlist is required.
Use `--verbose` to stream installer command output; default output is concise
and full command logs are written to `/var/log/bitcall-gateway-install.log`.

Default media behavior keeps host IPv6 enabled but blocks IPv6 traffic for media
ports only (RTP/TURN) using nftables or ip6tables rules with marker:
`bitcall-gateway media ipv6 block`.
Backend selection: prefer `nftables` on non-UFW hosts; use `ip6tables` when UFW
is active to avoid ruleset conflicts.

After setup, manage with:

```bash
sudo bitcall-gateway status
sudo bitcall-gateway logs -f
sudo bitcall-gateway restart
sudo bitcall-gateway init --production
sudo bitcall-gateway media status
sudo bitcall-gateway media ipv4-only on
sudo bitcall-gateway media ipv4-only off
```

## Developer quickstart

```bash
npm --prefix cli install
npm --prefix cli run lint
npm --prefix cli test
docker build -t webrtc-sip-gateway:test ./docker
```

## Manual VPS verification (post-init)

1. Systemd and container state

```bash
sudo systemctl status bitcall-gateway --no-pager
sudo docker ps --filter name=bitcall-gateway
```

2. TURN credentials endpoint (if TURN enabled)

```bash
curl -k --resolve "$(grep '^DOMAIN=' /opt/bitcall-gateway/.env | cut -d= -f2):443:127.0.0.1" \
  "https://$(grep '^DOMAIN=' /opt/bitcall-gateway/.env | cut -d= -f2)/turn-credentials"
```

3. WebSocket handshake should return `101 Switching Protocols`

```bash
DOMAIN="$(grep '^DOMAIN=' /opt/bitcall-gateway/.env | cut -d= -f2)"
curl -k -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Protocol: sip" \
  "https://${DOMAIN}/" | head -n 30
```

4. SIP listeners and service

```bash
sudo ss -ltnup | grep -E ':(443|5060|5061)\b'
sudo systemctl is-enabled bitcall-gateway
```

## Release operations

Docker image publish is automated on git tag push (`v*`) via `.github/workflows/publish-image.yml`.
NPM package publish is automated on git tag push (`v*`) via `.github/workflows/publish-npm.yml`.

Before creating a tag:
1. Test on a fresh VPS with `bitcall-gateway init`.
2. Confirm `bitcall-gateway status` shows `Media IPv4-only: enabled`.
3. Confirm IPv6 media drop rules exist (`nft list ruleset` or `ip6tables-save`).
4. Place a real call and verify audio both directions.

```bash
# 1) bump cli/package.json version
# 2) commit
# 3) tag vX.Y.Z
# 4) push main + tags
git push origin main --tags
```
