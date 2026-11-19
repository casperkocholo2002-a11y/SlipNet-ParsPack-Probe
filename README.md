# SlipNet Frankfurt Standalone Failover

Emergency-only, standalone SlipNet exit for ParsPack PaaS Frankfurt.

## Architecture

```text
Client
  -> TLS / WebSocket (ParsPack PaaS public endpoint)
  -> Native Rust VLESS server
  -> Direct TCP egress from Frankfurt
  -> Internet
```

There is deliberately **no runtime dependency** on:

- Server95
- Server155
- Arvan
- existing ParsPack relay/origin services
- Cloudflare Worker
- Xray
- Docker

This branch is intended only as the last-resort path when the normal SlipNet fabric is unavailable.

## Protocol

- VLESS over WebSocket
- TCP command supported
- TLS is terminated by the PaaS public endpoint
- Direct destination dialing is performed by the Rust process
- UDP/MUX are intentionally not implemented in v1
- private/local destination ranges are blocked by default

Browsers and most normal HTTPS applications use TCP and are suitable for this emergency route. QUIC/UDP-dependent traffic may fall back to TCP at the application layer; applications that require UDP-only transport are out of scope for v1.

## Required environment

```text
VLESS_USERS=ME=11111111-1111-1111-1111-111111111111,USER2=22222222-2222-2222-2222-222222222222
WS_PATH=/a-long-random-failover-path
```

Do not commit real UUIDs or the production WebSocket path.

## Optional environment

```text
PORT=8080
MAX_SESSIONS=128
MAX_IPS_PER_USER=3
CONNECT_TIMEOUT_SECS=10
ALLOW_PRIVATE_TARGETS=false
TRUST_PROXY_HEADERS=true
```

`PORT` is normally injected by the PaaS platform.

## Client template

```text
vless://UUID@PAAS_HOST:443?encryption=none&security=tls&type=ws&host=PAAS_HOST&path=%2FYOUR_PATH&sni=PAAS_HOST&alpn=http%2F1.1&fp=chrome#SlipNet-Frankfurt-Failover
```

## Health

`GET /health` returns only non-secret runtime data: build, session count, limits, and byte counters.

## Security defaults

- UUID authentication is mandatory.
- Maximum distinct active source IPs per UUID defaults to 3.
- Global active sessions default to 128.
- RFC1918, loopback, link-local, multicast, unspecified and documentation IPv4 targets are blocked.
- IPv6 loopback, unspecified, multicast, unique-local and link-local targets are blocked.
- No UUID, path secret or user name is returned by the health endpoint.

## PaaS source settings

- Runtime: Rust
- Repository: `casperkocholo2002-a11y/SlipNet-ParsPack-Probe`
- Branch: `frankfurt-standalone-failover-v1`
- Process: `web: target/release/slipnet-frankfurt-failover`

## Capacity policy

Do not treat the configured `MAX_SESSIONS` as proven capacity. Start with the minimum Frankfurt plan, then load-test the deployed endpoint with realistic concurrent sessions and throughput. The failover should remain unused in normal operation.

## Release gate

A GitHub Actions build/test run must pass before this branch is deployed to PaaS.
