# Serverless Containers

## Overview

Serverless Containers runs Docker containers on demand with auto-scaling. Like Cloud Functions, containers execute with a bound service account's permissions and have access to the metadata service.

## Techniques

All techniques from [Cloud Functions](../cloud-functions/) apply — metadata token theft, SA binding escalation, environment variable extraction, trigger-based persistence, and code injection (via container image replacement).

### Container-Specific Vectors

#### Image Replacement

Push a modified container image to the same registry path and tag. When the serverless container scales up or redeploys, it pulls the backdoored image.

```bash
docker build -t cr.yandex/<registry-id>/<image>:latest -f Dockerfile.backdoor .
docker push cr.yandex/<registry-id>/<image>:latest
```

#### Runtime Secrets in Container

Containers may have secrets mounted as files or environment variables:

```bash
# From inside the container
env | grep -iE 'key|secret|token|password'
ls /run/secrets/ 2>/dev/null
ls /etc/secrets/ 2>/dev/null
```

---

## Enumeration

```bash
yc serverless container list --folder-id <folder-id>
yc serverless container get <container-id>
yc serverless container revision list --container-id <container-id>
yc serverless container revision get <revision-id>
```

---

## Detection

| Event | Audit Key |
|---|---|
| Revision creation | `serverless.containers.createRevision` |
| Container invocation | Container logs in Cloud Logging |

## Defensive Recommendations

1. Pin container images by digest, not tag
2. Bind minimum-privilege SAs
3. Use Lockbox for secrets, not env vars
4. Enable vulnerability scanning in Container Registry
