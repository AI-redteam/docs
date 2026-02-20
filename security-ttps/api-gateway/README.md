# API Gateway

## Overview

Yandex API Gateway is an OpenAPI-based API management service that routes requests to Cloud Functions, Serverless Containers, Object Storage, and other backends. It supports JWT authorization, function-based authorization with result caching, and WebSocket connections.

## Authentication Mechanisms

### JWT Authorization
- Validates tokens from JWKS endpoint
- Supports RS256, RS384, RS512, ES256, ES384, ES512
- Validates `exp`, `nbf`, `iat`, `iss`, `aud` claims
- Authorization context passed to downstream services in `requestContext.authorizer`

### Function-Based Authorization
- Invokes a Cloud Function to make auth decisions
- Supports HTTP Basic, Bearer, and API Key auth types
- Function returns `{"isAuthorized": boolean, "context": {...}}`
- Results are **cached** by TTL

---

## Privilege Escalation

### Authorization Cache Poisoning

Cache keys are composed of: path/URI + HTTP method + Authorization header.

**Exploit scenarios:**
- Cached auth results persist **beyond token revocation** — revoked tokens remain "authorized" until cache TTL expires
- In `path` mode (route template-based), different actual URLs sharing the same route template share the same cache entry
- A valid token authorizes the cache, then a different (invalid) token with the same cache key inherits the authorization

### Function Authorizer Logic Bypass

Custom authorization functions may have:
- SQL injection in credential validation
- Missing input sanitization
- Logic flaws allowing always-true conditions
- Timing side-channels revealing valid credentials

### JWKS Endpoint Compromise

If the JWKS endpoint is compromised, forged tokens with attacker-controlled signing keys pass validation.

---

## Persistence

### Route Injection

Add malicious routes to the API Gateway OpenAPI spec:

```yaml
paths:
  /api/backdoor:
    get:
      x-yc-apigateway-integration:
        type: cloud-functions
        function_id: <attacker-function-id>
        service_account_id: <sa-id>
```

This route silently proxies requests to an attacker-controlled function.

### WebSocket C2

WebSocket connections provide persistent bidirectional communication:
- Establish connection with valid auth
- Maintain long-lived C2 channel
- Messages bypass request-level auth if only connection auth is checked

---

## Post-Exploitation

### Traffic Interception

Modify gateway spec to route existing paths through an attacker function that logs requests before forwarding:

```yaml
/api/sensitive:
  post:
    x-yc-apigateway-integration:
      type: cloud-functions
      function_id: <interceptor-function>
```

The interceptor function logs headers (including `Authorization`), body, and query parameters.

---

## Enumeration

```bash
yc serverless api-gateway list --folder-id <folder-id>
yc serverless api-gateway get <gw-id>
yc serverless api-gateway get-spec <gw-id>  # Full OpenAPI spec
```

---

## Detection

| Event | Audit Key |
|---|---|
| Gateway spec update | `serverless.apiGateways.update` |
| Gateway creation | `serverless.apiGateways.create` |

## Defensive Recommendations

1. Keep authorization cache TTL short
2. Use `uri` caching mode instead of `path` mode
3. Validate all inputs in custom authorization functions
4. Monitor gateway spec changes in Audit Trails
5. Use JWT with short expiration over function-based auth where possible
