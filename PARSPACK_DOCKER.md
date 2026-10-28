# ParsPack Docker Green

This branch is the isolated Go/Docker green deployment for the existing ParsPack relay.

## Runtime

- Container port: `8080`
- Entrypoint: `/slipnet-relay`
- Runtime user: `10001:10001`
- Final image: scratch + CA certificates only
- Primary relay path: inherited from `RELAY_PATH` (default: `/tunnel`)

## Environment variables

Copy the existing live ParsPack values into the green app without printing or committing secret values.

Primary relay:
- `ORIGIN_HOST`
- `ORIGIN_PORT`
- `ORIGIN_SERVERNAME`
- `RELAY_PATH`

Concurrent-IP guard:
- `CONCURRENCY_GUARD=1`
- `SESSION_TELEMETRY_URL`

Direct relay, when enabled:
- `DIRECT_RELAY_PATH`
- `DIRECT_ORIGIN_HOST`
- `DIRECT_ORIGIN_PORT`
- `DIRECT_ORIGIN_SERVERNAME`
- `DIRECT_ORIGIN_PATH`

Worker relay compatibility, when overridden:
- `WORKER_DIRECT_RELAY_PATH`
- `WORKER_DIRECT_HOST`
- `WORKER_DIRECT_PATH`
- `WORKER_FIXED_RELAY_PATH`
- `WORKER_FIXED_HOST`
- `WORKER_FIXED_PATH`

## Validation gate

Do not cut production traffic to this app until all of these pass:

1. `GET /health`
2. `GET /origin-check`
3. WebSocket `/tunnel`
4. Real VLESS end-to-end
5. Telemetry open / heartbeat / close
6. Same-IP multi-session counts as one concurrent IP
7. Fourth distinct overlapping IP locks
8. Manual unlock restores access
