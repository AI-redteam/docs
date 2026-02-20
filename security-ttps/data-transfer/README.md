# Data Transfer

## Overview

Data Transfer moves data between databases, object storage, and streaming systems. It stores source/target connection credentials and supports full copy, replication (CDC), and incremental modes. Credential storage and cross-service data flow make it a high-value pivot point.

## Credential Access

### Endpoint Credential Extraction

With `data-transfer.admin`:
- View source/target endpoint configurations
- Extract database connection strings, usernames, passwords
- Access replication credentials (CDC users often have elevated DB privileges)

**Supported sources/targets:** PostgreSQL, MySQL, ClickHouse, MongoDB, Oracle, Greenplum, Object Storage, YDB, Data Streams.

### CDC User Privileges

Change Data Capture (CDC) replication requires database users with:
- `REPLICATION` privilege (PostgreSQL)
- `SUPER` or `REPLICATION SLAVE` (MySQL)
- `OPLOG` access (MongoDB)

These users have broader access than typical application users.

---

## Lateral Movement

### Data Transfer as Pivot

Create or modify a transfer to exfiltrate data:

1. **Source:** Target internal database
2. **Target:** Attacker-controlled external endpoint or S3 bucket
3. **Mode:** Copy (one-time full snapshot)

```bash
# The transfer authenticates to the source DB with stored credentials
# and writes all data to the attacker-controlled target
```

### Cross-Service Credential Reuse

Transfer endpoint credentials may be the same as application database credentials. Extracting them provides direct database access.

---

## Defense Evasion

### Blend with Legitimate Traffic

Data Transfer creates high-volume data flows. Exfiltration through a transfer job blends with normal database replication traffic and may not trigger anomaly detection.

---

## Enumeration

```bash
yc datatransfer endpoint list --folder-id <folder-id>
yc datatransfer transfer list --folder-id <folder-id>
```

---

## Detection

| Event | Audit Key |
|---|---|
| Transfer creation | `data-transfer.transfers.create` |
| Endpoint creation | `data-transfer.endpoints.create` |
| Transfer activation | `data-transfer.transfers.activate` |

## Defensive Recommendations

1. Use dedicated transfer users with minimum required privileges
2. Restrict `data-transfer.admin` role
3. Monitor for unexpected transfer or endpoint creation
4. Audit endpoint target addresses
5. Use separate credentials for transfer vs application access
