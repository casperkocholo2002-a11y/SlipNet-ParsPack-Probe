# No-95 Emergency Fabric Shadow

This branch is isolated from production. It keeps the existing public `/tunnel` contract but terminates VLESS inside the ingress container and sends traffic through the same three egress routes currently used behind Server95.

Safety rules:
- no production deploy from this branch;
- no change to current public hostnames, paths, UUIDs, subscriptions, or dashboard API;
- no direct Server155 origin exposure;
- egress routes continue through the existing ArvanEdge / Arvan CaaS / ParsPack PaaS fronts;
- user authority is supplied by a cached manifest;
- an unavailable manifest source does not delete the last valid cache;
- missing cache on first boot fails closed with zero admitted users;
- GHCR publishing uses only the `no95-shadow-<sha>` tag.

Processes inside the shadow image:
1. public Node relay + real-IP/session guard;
2. local Xray VLESS ingress;
3. worker-route Xray client;
4. Arvan/ParsPack direct-route Xray client;
5. Smart Egress selector copied from the current Server95 implementation;
6. manifest controller.

Authority shadow:
- preserves Dashboard `command_id -> pending -> done/result` semantics;
- reconstructs existing UUIDs from completed command history;
- aggregates usage independently from Arvan and ParsPack nodes;
- enforces enabled / expiry / quota in the shared manifest;
- preserves the existing public VLESS links and `/tunnel` path;
- distributes route preference to both selectors;
- accepts authenticated usage + selector reports from both ingress nodes.

Production cutover remains forbidden until the Hub patch is staged and both provider-side shadow apps pass E2E with the exact current user configurations.