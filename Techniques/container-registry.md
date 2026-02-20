# Yandex Cloud - Container Registry Techniques

## Service Overview

Yandex Container Registry is a Docker Registry HTTP API V2-compatible service for storing and distributing Docker images and Helm charts. Registries are created at the folder level. Standard Docker CLI commands work natively with the endpoint `cr.yandex`. Authentication uses OAuth tokens, IAM tokens, or the `docker-credential-yc` helper. Tags are mutable (supply chain risk), digests are immutable.

**Key Concepts:**
- **Hierarchy**: Cloud → Folder → Registry → Repository → Docker Image (tags/digests)
- **Registry Endpoint**: `cr.yandex/<registry_id>/<image_name>:<tag>`
- **Authentication**: `docker login cr.yandex` with username `oauth` or `iam` + corresponding token
- **Tags**: Mutable — pushing a new image with an existing tag silently replaces it
- **Digests**: Immutable, content-addressable (`sha256:...`)
- **IP Restrictions**: Optional per-registry allowlists for PULL and PUSH separately

---

## Enumeration

### Enumerate Registries

```bash
# List all registries in the current folder
yc container registry list

# Get registry details
yc container registry get <registry_name_or_id>

# List access bindings (check for public access)
yc container registry list-access-bindings <registry_name_or_id>

# List IP restrictions
yc container registry list-ip-permissions <registry_name_or_id>
```

### Enumerate Repositories and Images

```bash
# List repositories in a registry
yc container repository list --registry-id <registry_id>

# List images in a repository
yc container image list --repository-name=<registry_id>/<image_name>

# Get image details (digest, size, tags)
yc container image get <image_id>

# List repository-level access bindings
yc container repository list-access-bindings <repo_name_or_id>
```

### Enumerate Lifecycle and Scan Policies

```bash
# List lifecycle policies for a repository
yc container repository lifecycle-policy list --repository-name <registry_id>/<image_name>

# List scan results
yc container image list-scan-results --repository-name=<registry_id>/<image_name>

# List vulnerabilities from a scan
yc container image list-vulnerabilities --scan-result-id=<scan_result_id>
```

### Check for Public Access

```bash
# Check access bindings for allUsers or allAuthenticatedUsers
yc container registry list-access-bindings <registry_id>
# Look for: subject type "system" with ID "allUsers" or "allAuthenticatedUsers"

# Test anonymous pull (if allUsers has puller role)
docker pull cr.yandex/<registry_id>/<image_name>:<tag>
```

### API-Based Enumeration

```bash
# List registries
curl -s -H "Authorization: Bearer <IAM_TOKEN>" \
  "https://container-registry.api.cloud.yandex.net/container-registry/v1/registries?folderId=<folder_id>"

# List images
curl -s -H "Authorization: Bearer <IAM_TOKEN>" \
  "https://container-registry.api.cloud.yandex.net/container-registry/v1/images?registryId=<registry_id>"

# List access bindings
curl -s -H "Authorization: Bearer <IAM_TOKEN>" \
  "https://container-registry.api.cloud.yandex.net/container-registry/v1/registries/<registry_id>:listAccessBindings"

# List IP permissions
curl -s -H "Authorization: Bearer <IAM_TOKEN>" \
  "https://container-registry.api.cloud.yandex.net/container-registry/v1/registries/<registry_id>:listIpPermission"
```

---

## Credential Access

### Steal Docker Credentials

```bash
# Docker credentials stored after login
# ~/.docker/config.json — may contain base64-encoded tokens
cat ~/.docker/config.json

# YC CLI profiles (OAuth tokens, SA keys)
# ~/.config/yandex-cloud/
ls ~/.config/yandex-cloud/

# K8s image pull secrets
kubectl get secrets --all-namespaces -o json | \
  jq '.items[] | select(.type == "kubernetes.io/dockerconfigjson") | {namespace: .metadata.namespace, name: .metadata.name, data: (.data[".dockerconfigjson"] | @base64d)}'

# CI/CD pipeline variables (GitLab, etc.)
# Often contain OAuth tokens or SA keys for push access
```

### Authentication Methods Reference

```bash
# OAuth token (12-month lifetime)
echo <OAuth_token> | docker login --username oauth --password-stdin cr.yandex

# IAM token (12-hour lifetime)
echo <IAM_token> | docker login --username iam --password-stdin cr.yandex

# Credential helper (uses current yc profile)
yc container registry configure-docker
# Writes to ~/.docker/config.json: {"credHelpers": {"cr.yandex": "yc"}}
```

---

## Lateral Movement / Supply Chain

### Image Tag Replacement (Supply Chain Attack)

Tags are mutable. With `container-registry.images.pusher`, replace any image tag with a backdoored version:

```bash
# Build a backdoored image
docker build -t cr.yandex/<registry_id>/<image_name>:<target_tag> -f Dockerfile.backdoor .

# Push — silently replaces the existing tag
docker push cr.yandex/<registry_id>/<image_name>:<target_tag>
```

**Impact**: All pods/VMs pulling this tag will get the backdoored image on next pull. The `latest` tag is the most common target.

**Mitigation check**: If cosign verification is enforced via admission controllers (Kyverno, OPA Gatekeeper), the pushed image must also be signed. Without enforcement, tag replacement is trivial.

### Pull and Analyze Target Images

Extract deployed images for vulnerability analysis or secret discovery:

```bash
# Pull target image
docker pull cr.yandex/<registry_id>/<image_name>:<tag>

# Inspect layers for secrets
docker history cr.yandex/<registry_id>/<image_name>:<tag> --no-trunc
docker inspect cr.yandex/<registry_id>/<image_name>:<tag>

# Extract filesystem
docker save cr.yandex/<registry_id>/<image_name>:<tag> -o image.tar
tar xf image.tar
# Search layers for credentials, API keys, config files
```

### Scan Images for Known Vulnerabilities

```bash
# Scan an image (requires container-registry.images.scanner)
yc container image scan <image_id>

# List vulnerabilities by severity
yc container image list-vulnerabilities --scan-result-id=<result_id> \
  --filter "severity=CRITICAL"
```

Scan results reveal internal package versions — useful for crafting targeted exploits against deployed containers.

---

## Persistence

### Maintain Registry Access via Access Bindings

```bash
# Grant persistent pull access to a compromised SA
yc container registry add-access-binding <registry_id> \
  --role container-registry.images.puller \
  --service-account-id <sa_id>

# Grant push access for ongoing supply chain manipulation
yc container registry add-access-binding <registry_id> \
  --role container-registry.images.pusher \
  --service-account-id <sa_id>
```

### Remove IP Restrictions

If IP allowlists are blocking access:

```bash
# Remove IP restrictions (requires admin role)
yc container registry remove-ip-permissions <registry_name> \
  --pull <blocked_ip> --push <blocked_ip>
```

### Disable Vulnerability Scanning

```bash
# Disable scan policy via API (requires editor role)
# This suppresses automatic detection of backdoored images
```

### Create Lifecycle Policy for Delayed Destruction

```bash
# Create an aggressive lifecycle policy to delete images
yc container repository lifecycle-policy create \
  --repository-name <registry_id>/<image_name> \
  --name cleanup \
  --rules '[{"description": "delete all", "tag_regexp": ".*", "expire_period": "24h", "retained_top": 0}]'

# Activate it
yc container repository lifecycle-policy update <policy_id> --active
```

---

## Impact

### Delete Images (Denial of Service)

```bash
# Delete a specific image (requires pusher role)
yc container image delete <image_id>

# Delete all images in a repository
for img in $(yc container image list --repository-name=<registry_id>/<image_name> --format json | jq -r '.[].id'); do
  yc container image delete "$img"
done
```

### Delete Registry

```bash
# Delete entire registry (requires editor role)
# Registry must be empty first
yc container registry delete <registry_id>
```

### Grant Public Write Access

The most dangerous misconfiguration — allow anyone to push images:

```bash
# DO NOT DO THIS (shown for detection purposes)
yc container registry add-access-binding <registry_id> \
  --role container-registry.images.pusher \
  --all-authenticated-users
```

---

## Key IAM Roles

| Role | What it Enables |
|---|---|
| `container-registry.images.puller` | Pull images, list registries/images |
| `container-registry.images.pusher` | Push, pull, update, **delete** images; create/delete repositories |
| `container-registry.images.scanner` | Scan images, view scan results, pull images |
| `container-registry.viewer` | Read-only: list registries, images, repos, policies, scan history |
| `container-registry.editor` | Create/modify/delete registries, images, repos, lifecycle/scan policies |
| `container-registry.admin` | Full control: editor + manage access bindings and IP permissions |

**Note**: `pusher` allows both push AND delete — an attacker with pusher access can replace and destroy images.

---

## Credential Locations

| Location | Content |
|---|---|
| `~/.docker/config.json` | Stored Docker login tokens (OAuth/IAM) or credential helper config |
| `~/.config/yandex-cloud/` | YC CLI profiles, OAuth tokens, SA keys |
| K8s secrets (`kubernetes.io/dockerconfigjson`) | Image pull secrets |
| CI/CD variables (GitLab, etc.) | Registry credentials for push operations |
| Terraform state files | Registry IDs, SA details |
| SA key JSON files | Long-lived credentials for programmatic access |

---

## Detection and Logging

### Audit Trail Events

All Container Registry operations are logged as `yandex.cloud.audit.containerregistry.<event_name>`:

- `CreateRegistry` / `DeleteRegistry` — registry lifecycle
- `CreateImage` / `DeleteImage` — image push/delete
- `CreateImageTag` / `DeleteImageTag` — tag operations
- `SetAccessBindings` / `UpdateAccessBindings` — permission changes
- `SetIpPermission` / `UpdateIpPermission` — IP restriction changes
- `ScanImage` — vulnerability scans

### Key Detection Opportunities

- Image tag overwrites (same tag, different digest) — supply chain attack indicator
- `DeleteImage` bursts — image destruction
- `UpdateAccessBindings` adding `allUsers` or `allAuthenticatedUsers` — public exposure
- `RemoveIpPermission` — removing network restrictions
- Push from unexpected IPs or service accounts — unauthorized access
- Lifecycle policy creation with aggressive deletion rules — evidence destruction

---

## References

- Container Registry Documentation: `en/container-registry/`
- Authentication: `en/container-registry/operations/authentication.md`
- Security Roles: `en/container-registry/security/index.md`
- Vulnerability Scanner: `en/container-registry/concepts/vulnerability-scanner.md`
- Lifecycle Policies: `en/container-registry/concepts/lifecycle-policy.md`
