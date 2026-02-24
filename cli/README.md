# @bitcall/webrtc-sip-gateway

Linux-only CLI to install and operate the Bitcall WebRTC-to-SIP gateway.

Latest updates:
- `init` and `reconfigure` stop an existing stack before preflight checks so
  the gateway's own `:5060` listener does not trigger false port conflicts.
- `update` now syncs `BITCALL_GATEWAY_IMAGE` to the CLI target image tag
  before pulling and restarting.
- Docker image includes `sngrep` and `tcpdump` for SIP troubleshooting.

## Install

```bash
sudo npm i -g @bitcall/webrtc-sip-gateway
```

## Main workflow

```bash
sudo bitcall-gateway init
sudo bitcall-gateway status
sudo bitcall-gateway logs -f
sudo bitcall-gateway media status
```

Default media policy is IPv4-only via IPv6 media firewall drops on RTP/TURN
ports only. Host IPv6 remains enabled for signaling and non-media traffic.
Backend selection prefers nftables on non-UFW hosts and uses ip6tables when UFW
is active.

Default `init` runs in production profile with universal routing:
- `BITCALL_ENV=production`
- `ROUTING_MODE=universal`
- provider allowlist/origin/source IPs are permissive by default

Use `sudo bitcall-gateway init --advanced` for full security/provider controls.
Use `sudo bitcall-gateway init --dev` for local testing only.
Use `--verbose` to stream apt/docker output during install. Default mode keeps
console output concise and writes command details to
`/var/log/bitcall-gateway-install.log`.

## Commands

- `sudo bitcall-gateway init`
- `sudo bitcall-gateway init --dev`
- `sudo bitcall-gateway init --production`
- `sudo bitcall-gateway init --advanced`
- `sudo bitcall-gateway init --verbose`
- `sudo bitcall-gateway up`
- `sudo bitcall-gateway down`
- `sudo bitcall-gateway restart`
- `sudo bitcall-gateway pause`
- `sudo bitcall-gateway resume`
- `sudo bitcall-gateway enable`
- `sudo bitcall-gateway disable`
- `sudo bitcall-gateway reconfigure`
- `sudo bitcall-gateway status`
- `sudo bitcall-gateway logs [-f] [service]`
- `sudo bitcall-gateway cert status`
- `sudo bitcall-gateway cert renew`
- `sudo bitcall-gateway cert install --cert /path/cert.pem --key /path/key.pem`
- `sudo bitcall-gateway update`
- `sudo bitcall-gateway media status`
- `sudo bitcall-gateway media ipv4-only on`
- `sudo bitcall-gateway media ipv4-only off`
- `sudo bitcall-gateway uninstall`

## Files created by init

- `/opt/bitcall-gateway/.env`
- `/opt/bitcall-gateway/docker-compose.yml`
- `/opt/bitcall-gateway/acme-webroot/.well-known/acme-challenge/healthcheck`
- `/etc/systemd/system/bitcall-gateway.service`

## Publishing npm package

1. Bump version in `cli/package.json`.
2. Commit the change.
3. Create tag `vX.Y.Z`.
4. Push tags; GitHub Actions publishes automatically.
