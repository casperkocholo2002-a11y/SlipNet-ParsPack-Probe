# No-95 Emergency Fabric Shadow

This branch is isolated from production. It keeps the existing public `/tunnel` contract but terminates VLESS inside the ingress container and sends traffic through the same three egress routes currently used behind Server95.

Safety rules:
- no production deploy from this branch;
- no change to current public hostnames, paths, UUIDs, subscriptions, or dashboard API;
- no direct Server155 origin exposure;
- egress routes continue through the existing ArvanEdge / Arvan CaaS / ParsPack PaaS fronts;
- user authority is supplied by a cached manifest;
- an unavailable manifest source does not delete the last valid cache;
- missing cache on first boot fails closed with zero admitted users.

Processes inside the shadow image:
1. public Node relay + real-IP/session guard;
2. local Xray VLESS ingress;
3. worker-route Xray client;
4. Arvan/ParsPack direct-route Xray client;
5. Smart Egress selector copied from the current Server95 implementation;
6. manifest controller.

The production cutover is forbidden until two-container quota aggregation and dashboard desired-state persistence are proven separately.