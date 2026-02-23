# @bitcall/webrtc-sip-gateway

Linux-only CLI to install and operate the Bitcall WebRTC-to-SIP gateway.

## Install

```bash
sudo npm i -g @bitcall/webrtc-sip-gateway@0.2.5
```

## Main workflow

```bash
sudo bitcall-gateway init
sudo bitcall-gateway status
sudo bitcall-gateway logs -f
```

Default media policy is IPv4-only (`MEDIA_IPV6=0` and `MEDIA_FORCE_IPV4=1`),
including IPv6 candidate stripping on SIP->WebRTC SDP. Set `MEDIA_IPV6=1`
and `MEDIA_FORCE_IPV4=0` in `/opt/bitcall-gateway/.env` only if you want
IPv6 candidates.

## Commands

- `sudo bitcall-gateway init`
- `sudo bitcall-gateway up`
- `sudo bitcall-gateway down`
- `sudo bitcall-gateway restart`
- `sudo bitcall-gateway status`
- `sudo bitcall-gateway logs [-f] [service]`
- `sudo bitcall-gateway cert status`
- `sudo bitcall-gateway cert renew`
- `sudo bitcall-gateway cert install --cert /path/cert.pem --key /path/key.pem`
- `sudo bitcall-gateway update`
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
