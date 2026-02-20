# Yandex Cloud - Audit Trails Techniques

## Service Overview

Yandex Audit Trails collects audit logs of events across Yandex Cloud resources. Logs are delivered to Object Storage buckets, Cloud Logging log groups, or Data Streams. Two event types exist: **management events** (control plane — resource CRUD, role changes, configuration) and **data events** (data plane — secret reads, encryption operations, object access). Management events are collected by default; data events must be explicitly enabled per service.

**Key Concepts:**
- **Trail**: The core resource — collects logs from a defined scope and delivers to a single destination
- **Collection Scope**: Organization, Cloud, or Folder level
- **Management Events**: Logged by default for all supported services
- **Data Events**: Disabled by default, must be enabled per service. Supported for: IAM, KMS, Lockbox, Object Storage, Compute, DNS, K8s, Certificate Manager, and others
- **Delivery**: ~5 min batches to S3, near real-time to Cloud Logging/Data Streams
- **Limitation**: Authentication failures are NOT logged — only authorization failures are captured

---

## Enumeration

### Enumerate Trails

```bash
# List all trails in the folder
yc audit-trails trail list

# Get trail details (scope, destination, filters)
yc audit-trails trail get <trail_name_or_id>

# List trail access bindings
yc audit-trails trail list-access-bindings <trail_name_or_id>
```

### Identify Log Destinations

Trails deliver to one of three destinations:
- **Object Storage bucket**: Logs as JSON files, ~5 min batches
- **Cloud Logging log group**: Near real-time, single JSON objects
- **Data Streams**: Near real-time, JSON objects in stream

```bash
# Get trail to see its destination
yc audit-trails trail get <trail_name> --format json | \
  jq '{destination: .destination, status: .status}'
```

### Check What's Being Monitored

```bash
# Get full trail configuration (shows scope, event filters)
yc audit-trails trail get <trail_name> --format json
# Look at:
# - filtering.path_filter: management event scope
# - filtering.event_filters: data event scope per service
```

---

## Understanding the Audit Log Schema

### Event Structure

```json
{
  "event_id": "<unique_event_id>",
  "event_source": "compute",
  "event_type": "yandex.cloud.audit.compute.CreateInstance",
  "event_time": "2024-01-15T10:30:00Z",
  "authentication": {
    "authenticated": true,
    "subject_type": "SERVICE_ACCOUNT",
    "subject_id": "<sa_id>",
    "subject_name": "<sa_name>",
    "token_info": {
      "masked_iam_token": "<masked>",
      "iam_token_id": "<token_id>",
      "impersonator_id": "<impersonator_id>",
      "impersonator_type": "YANDEX_PASSPORT_USER_ACCOUNT"
    }
  },
  "authorization": {
    "authorized": true
  },
  "resource_metadata": {
    "path": [
      {"resource_type": "organization-manager.organization", "resource_id": "<org_id>"},
      {"resource_type": "resource-manager.cloud", "resource_id": "<cloud_id>"},
      {"resource_type": "resource-manager.folder", "resource_id": "<folder_id>"}
    ]
  },
  "request_metadata": {
    "remote_address": "<source_ip>",
    "user_agent": "<user_agent>",
    "request_id": "<request_id>"
  },
  "event_status": "DONE",
  "details": { ... }
}
```

### Key Fields for Analysis

| Field | Significance |
|---|---|
| `authentication.subject_type` | `YANDEX_PASSPORT_USER_ACCOUNT`, `SERVICE_ACCOUNT`, `FEDERATED_USER_ACCOUNT` |
| `authentication.subject_id` | Who performed the action |
| `authentication.token_info.impersonator_id` | Reveals SA impersonation |
| `authorization.authorized` | `false` = failed authorization attempt |
| `request_metadata.remote_address` | Source IP (`cloud.yandex` = internal Yandex service) |
| `event_status` | `DONE`, `ERROR`, `STARTED`, `CANCELLED` |
| `resource_metadata.path` | Full resource hierarchy (org → cloud → folder) |

---

## Defense Evasion

### Exploit Logging Gaps

**Authentication failures are NOT logged**:
- API calls without an IAM token produce no audit trail entry
- Invalid tokens produce no entry
- Only **authorization** failures (valid token, insufficient permissions) are logged

**Data events are disabled by default**:
- Lockbox secret reads (`GetPayload`) — not logged unless data events enabled for Lockbox
- KMS encrypt/decrypt operations — not logged unless data events enabled for KMS
- S3 object reads (`GetObject`) — not logged unless data events enabled for Object Storage
- Compute serial port connections — not logged unless data events enabled for Compute

### Disable or Modify Trails

With `audit-trails.editor`, trails can be modified or deleted:

```bash
# Delete a trail (stops all logging from its scope)
yc audit-trails trail delete <trail_name>

# Modify trail to narrow scope (reduce what's logged)
yc audit-trails trail update <trail_name> \
  --filter-some-cloud-folder-ids <limited_folder_id>
```

### Disable Data Event Collection

Data events can be selectively disabled per service:

```bash
# Update trail to stop collecting data events for a specific service
yc audit-trails trail update <trail_name> \
  --filtering ...  # Remove specific service from event filters
```

### Tamper with Log Destination

If you have access to the destination bucket or log group:

```bash
# Delete audit log files from the destination bucket
aws s3 rm s3://<audit_bucket>/<prefix>/ --recursive \
  --endpoint-url https://storage.yandexcloud.net

# Or modify lifecycle rules to auto-delete logs
aws s3api put-bucket-lifecycle-configuration \
  --bucket <audit_bucket> \
  --endpoint-url https://storage.yandexcloud.net \
  --lifecycle-configuration '{
    "Rules": [{"ID": "cleanup", "Status": "Enabled", "Filter": {"Prefix": ""}, "Expiration": {"Days": 1}}]
  }'
```

### Exploit Delivery Delays

- S3 delivery: ~5 minute batches. Actions within a 5-minute window may not yet be in logs
- Near real-time (Cloud Logging/Data Streams): Lower latency but still not instantaneous
- If trail encounters errors (destination unavailable), events may be lost

### Actions That Leave Minimal Traces

- **IMDS token retrieval** (`169.254.169.254`): Not logged in Audit Trails at all
- **Object Storage reads** (without data events enabled): No audit trail
- **Lockbox payload reads** (without data events): No audit trail
- **DNS queries**: Not logged
- **Network traffic**: Not logged (no VPC flow logs in Audit Trails)
- **Console/SSH sessions**: Not logged (only the connection event, not commands)

---

## Detection Techniques (Blue Team / Forensics)

### Key Management Events to Monitor

**IAM Events** (`event_source: iam`):
- `CreateServiceAccount` / `DeleteServiceAccount` — SA lifecycle
- `CreateAccessKey` / `CreateApiKey` / `CreateKey` — new credentials
- `DeleteAccessKey` / `DeleteApiKey` / `DeleteKey` — credential rotation/cleanup
- `SetAccessBindings` / `UpdateAccessBindings` — permission changes
- `CreateIamToken` — token generation
- `ImpersonateServiceAccount` — SA impersonation

**Compute Events** (`event_source: compute`):
- `CreateInstance` — new VMs
- `UpdateInstanceMetadata` — SSH key additions, serial console enable
- `ConnectSerialPort` — serial console access
- `CreateSnapshot` — disk snapshotting
- `AttachInstanceDisk` / `DetachInstanceDisk` — disk manipulation
- `AddInstanceOneToOneNat` — public IP assignment
- `MoveInstance` — VM folder moves

**VPC Events** (`event_source: vpc`):
- `UpdateSecurityGroupRules` — firewall rule changes
- `CreateSubnet` / `UpdateSubnet` — network changes
- `CreateRouteTable` — routing changes

**Audit Trails Events** (`event_source: audittrails`):
- `CreateTrail` / `DeleteTrail` / `UpdateTrail` — trail modifications (meta-monitoring)

**Serverless Events** (`event_source: serverless`):
- `CreateFunctionVersion` — new code deployed
- `AllowUnauthenticatedInvoke` — function made public
- `CreateTrigger` — new event trigger

### Key Data Events to Monitor (When Enabled)

**Lockbox** (`event_source: lockbox`):
- `GetPayload` / `GetPayloadEx` — secret value reads

**KMS** (`event_source: kms`):
- `Encrypt` / `Decrypt` / `ReEncrypt` / `GenerateDataKey` — crypto operations

**Object Storage** (`event_source: storage`):
- `GetObject` / `PutObject` / `DeleteObject` — object operations
- `PutBucketPolicy` / `PutBucketAcl` — access control changes

**Compute** (`event_source: compute`):
- `SerialPortOutput` — serial port reads

**IAM** (`event_source: iam`):
- `CreateIamToken` / `RevokeIamToken` — token lifecycle

### Sample Detection Queries

**Detect unauthorized access attempts**:
```
event_status = "ERROR" AND authorization.authorized = false
```

**Detect new service account keys (persistence indicator)**:
```
event_type IN ("yandex.cloud.audit.iam.CreateAccessKey", "yandex.cloud.audit.iam.CreateApiKey", "yandex.cloud.audit.iam.CreateKey")
```

**Detect security group changes**:
```
event_type = "yandex.cloud.audit.vpc.UpdateSecurityGroupRules"
```

**Detect trail tampering**:
```
event_type IN ("yandex.cloud.audit.audittrails.DeleteTrail", "yandex.cloud.audit.audittrails.UpdateTrail")
```

**Detect impersonation**:
```
authentication.token_info.impersonator_id IS NOT NULL
```

---

## Trail Configuration for Attackers

### Understand Trail Scope

Trails only collect events from their configured scope. If a trail monitors Folder A but the attacker operates in Folder B (same cloud), those events may not be collected:

```bash
# Check which folders/clouds a trail monitors
yc audit-trails trail get <trail_name> --format json
# Examine filtering.path_filter for management events
# Examine filtering.event_filters for data events
```

### Identify Blind Spots

- **No trail for a folder**: Events in that folder go unmonitored
- **Data events not enabled**: Secret reads, crypto operations, object access are invisible
- **Organization-level trail missing**: Cross-cloud events may not be captured
- **Trail errors**: If the destination is unavailable, events are dropped

---

## Key IAM Roles

| Role | What it Enables |
|---|---|
| `audit-trails.auditor` | View trail metadata |
| `audit-trails.viewer` | View trails and collect/view audit events |
| `audit-trails.configViewer` | View trail configuration |
| `audit-trails.editor` | Create, modify, **delete** trails |
| `audit-trails.admin` | Full control + manage access bindings |

---

## Event Type Format Reference

```
yandex.cloud.audit.<service_name>.<event_name>
```

### Services with Management Events

API Gateway, ALB, Audit Trails, Bare Metal, Certificate Manager, Cloud Apps, Backup, Billing, CDN, Compute, Container Registry, DataLens, DataProc, DataSphere, Data Streams, Data Transfer, DNS, Managed Databases (PostgreSQL, MySQL, ClickHouse, MongoDB, Kafka, OpenSearch, Greenplum, Valkey), IAM, K8s, KMS, Load Balancer, Lockbox, Logging, Marketplace, Monitoring, Network, Object Storage, Organization Manager, Resource Manager, Serverless (Functions, Containers), SmartWebSecurity, VPC, YDB, and more.

### Services with Data Events

ALB, Certificate Manager, Cloud Desktop, DNS, Compute, AI Studio, Organization Manager, IAM, KMS, Lockbox, Managed K8s, Object Storage, SmartCaptcha, SmartWebSecurity, SpeechSense, Wiki.

---

## Log File Location (S3 Destination)

```
<bucket>/<prefix>/kms_encrypted_aes_256_<folder_id>/<trail_id>/
  <year>/<month>/<day>/
  <trail_id>_<timestamp>_<index>.json
```

---

## Detection Evasion Summary

| Technique | Why it Works |
|---|---|
| Use stolen token without calling APIs that have data events | Data events disabled by default |
| Access IMDS from inside VM | IMDS access is not logged |
| Operate in folders without trail coverage | No events collected outside trail scope |
| Act quickly within 5-min S3 batch window | Logs not yet delivered |
| Delete trail before acting | No subsequent events collected |
| Tamper with destination bucket | Historical logs destroyed |
| Use authentication-only operations | Auth failures produce no log entry |

---

## References

- Audit Trails Documentation: `en/audit-trails/`
- Trail Concepts: `en/audit-trails/concepts/trail.md`
- Management Events Reference: `en/audit-trails/concepts/events.md`
- Data Events Reference: `en/audit-trails/concepts/events-data-plane.md`
- Log Format: `en/audit-trails/concepts/format.md`
- Security Roles: `en/audit-trails/security/index.md`
