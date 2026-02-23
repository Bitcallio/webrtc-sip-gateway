# webrtc-sip-gateway

Production-grade monorepo for a baseline WebRTC-to-SIP gateway stack.

## What is included

- `docker/`: container image build context for gateway image `v0.1`
  - Kamailio 5.7
  - rtpengine in userspace mode
  - Python HTTP responder on port `80` for ACME healthcheck path
  - `s6-overlay` process supervision for all services
- `cli/`: npm package `@bitcall/webrtc-sip-gateway` with global binary `bitcall-gateway`
- `.github/workflows/`: CI for CLI checks and Docker build/smoke validation

## Quickstart

### 1. Build and tag the image

```bash
docker build -t ghcr.io/bitcall/webrtc-sip-gateway:0.1.0 ./docker
```

### 2. Install the CLI globally

```bash
sudo npm install -g ./cli
```

### 3. Initialize and start the stack

```bash
sudo bitcall-gateway init
```

This creates `/opt/bitcall-gateway/.env` and `/opt/bitcall-gateway/docker-compose.yml`, then starts the container with Docker Compose.

### 4. Manage runtime

```bash
sudo bitcall-gateway status
sudo bitcall-gateway logs
sudo bitcall-gateway down
```

### 5. Verify healthcheck

```bash
curl -fsS http://127.0.0.1/.well-known/acme-challenge/healthcheck
```

Expected response:

```text
ok
```
