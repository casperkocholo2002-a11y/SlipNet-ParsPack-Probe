# SlipNet ParsPack PaaS ingress probe/relay

Public-safe diagnostic and fixed-destination WebSocket relay for validating a
ParsPack PaaS ingress. The repository intentionally contains no live SlipNet
credentials, origin IPs, UUIDs or TLS private keys.

## Diagnostic endpoints

- `GET /health`
- `POST /echo` — bounded to 16 MiB
- `GET /stream?bytes=1048576&chunk=16384&delay_ms=0`
- `GET /hold?seconds=30`
- `WS /ws` — bounded echo probe
- `GET /origin-check` — bounded TCP reachability check to the configured origin

## Fixed WebSocket relay

The production relay path defaults to:

```text
/tunnel
```

The HTTP caller cannot select an arbitrary destination. The relay destination is
read only from server-side environment variables:

```text
ORIGIN_HOST=<private operator value>
ORIGIN_PORT=<private operator value>
ORIGIN_SERVERNAME=<private operator value>
RELAY_PATH=/tunnel
```

The relay accepts a WebSocket upgrade, opens a verified TLS connection to the
fixed origin, forwards WebSocket payload bytes to that TLS stream and returns
origin bytes as binary WebSocket frames.

The application listens on `$PORT` supplied by the PaaS, defaulting to 3000 for
local testing.

Do not commit live values for ORIGIN_HOST, credentials, UUIDs, certificates or
private infrastructure inventory to this repository.
