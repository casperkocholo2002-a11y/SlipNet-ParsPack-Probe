# ParsPack PaaS ingress probe

Public-safe diagnostic service for testing a ParsPack PaaS ingress. It contains no
SlipNet credentials and does not proxy arbitrary destinations.

Endpoints:

- `GET /health` — liveness JSON.
- `POST /echo` — returns received byte count and SHA-256, max 16 MiB.
- `GET /stream?bytes=1048576&chunk=16384&delay_ms=0` — bounded deterministic stream.
- `GET /hold?seconds=30` — one small chunk per second, max 120 seconds.
- `WS /ws` — bounded WebSocket text/binary echo, max 1 MiB/frame.

The container listens on `$PORT` (default 3000). Use this only as a temporary
capability probe, not as a production proxy.
