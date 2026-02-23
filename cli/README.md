# @bitcall/webphone-gateway

Linux-only CLI to install and operate the Bitcall WebRTC-to-SIP gateway.

## Install

```bash
sudo npm i -g @bitcall/webphone-gateway
```

## Main workflow

```bash
sudo bitcall-gateway init
sudo bitcall-gateway status
sudo bitcall-gateway logs -f
```

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
