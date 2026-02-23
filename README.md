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
sudo npm i -g @bitcall/webrtc-sip-gateway@0.2.2
sudo bitcall-gateway init
```

After setup, manage with:

```bash
sudo bitcall-gateway status
sudo bitcall-gateway logs -f
sudo bitcall-gateway restart
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

```bash
# 1) bump cli/package.json version
# 2) commit
# 3) tag vX.Y.Z
# 4) push main + tags
git push origin main --tags
```
