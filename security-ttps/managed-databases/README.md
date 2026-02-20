# Managed Databases

## Overview

Yandex Cloud offers managed database services: PostgreSQL, MySQL, ClickHouse, MongoDB, Greenplum, Valkey (Redis-compatible), OpenSearch, Kafka, and YDB. These services manage clusters with built-in user management, security groups, backups, and extensions.

## Credential Access

### User Enumeration

```bash
# PostgreSQL
yc managed-postgresql cluster list --folder-id <folder-id>
yc managed-postgresql user list --cluster-id <cluster-id>
yc managed-postgresql database list --cluster-id <cluster-id>

# MySQL
yc managed-mysql cluster list --folder-id <folder-id>
yc managed-mysql user list --cluster-id <cluster-id>

# ClickHouse
yc managed-clickhouse cluster list --folder-id <folder-id>
yc managed-clickhouse user list --cluster-id <cluster-id>

# YDB
yc ydb database list --folder-id <folder-id>
```

### Password Extraction from Lockbox/Config

Database passwords are often stored in:
- Lockbox secrets
- Cloud Function environment variables
- Terraform state files
- Application config files in Object Storage
- CI/CD variables in Managed GitLab

### Direct Connection

If security groups permit network access:

```bash
# PostgreSQL
psql "host=<cluster-host> port=6432 dbname=<db> user=<user> sslmode=verify-full"

# MySQL
mysql -h <cluster-host> -P 3306 -u <user> -p --ssl-mode=REQUIRED

# ClickHouse
clickhouse-client --host <cluster-host> --port 9440 --user <user> --password <pass> --secure
```

---

## Privilege Escalation

### PostgreSQL Extensions

Managed PostgreSQL supports extensions that can be security-relevant:
- `pg_stat_statements` — query history (may reveal credentials in queries)
- `dblink` / `postgres_fdw` — connect to other databases from within PostgreSQL
- Custom extensions may provide file system or OS access

### Database User Privilege Escalation

If the managed user has `CREATEDB` or `CREATEROLE`:
- Create new databases for data staging
- Create new roles with broader permissions
- Modify role membership

---

## Post-Exploitation

### Data Extraction

Direct SQL access enables:
- Full table dumps
- Schema extraction
- Stored procedure/function code review (may contain credentials)
- Query log analysis (`pg_stat_statements`)

### Backup Abuse

With `managed-postgresql.admin` or equivalent:

```bash
yc managed-postgresql backup list --cluster-id <cluster-id>
```

Restoring from backup to a new cluster provides offline data analysis.

---

## Lateral Movement

### Cross-Database Links

PostgreSQL `dblink` and `postgres_fdw` enable queries to other database servers from within a compromised database session.

### Credential Reuse

Database credentials are frequently reused across environments (dev/staging/prod) and across different database types.

---

## Detection

| Event | Audit Key |
|---|---|
| Cluster creation | `managed-postgresql.clusters.create` |
| User creation | `managed-postgresql.users.create` |
| User modification | `managed-postgresql.users.update` |
| Backup creation | `managed-postgresql.clusters.backup` |
| Access binding changes | `managed-postgresql.clusters.updateAccessBindings` |

## Defensive Recommendations

1. Use security groups to restrict database network access
2. Store credentials in Lockbox, not application config
3. Use separate database users per application with minimum privileges
4. Enable audit logging (pg_audit for PostgreSQL)
5. Restrict extension usage
6. Monitor connection patterns — alert on unusual source IPs
7. Use encrypted connections (SSL/TLS) for all database access
