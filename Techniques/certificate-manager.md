# Yandex Cloud - Certificate Manager Techniques

## Service Overview

Yandex Certificate Manager manages TLS/SSL certificates for cloud services. It supports Let's Encrypt (managed) certificates with auto-renewal, user-imported certificates, and a Private CA (Beta) for internal PKI. Certificates integrate directly with ALB, API Gateway, CDN, Object Storage, and Smart Web Security — replacement propagates automatically to all dependent services.

**Key Concepts:**
- **Let's Encrypt Certificates**: Domain Validation, 90-day validity, auto-renewed 30 days before expiry. Verification via HTTP or DNS (CNAME/TXT)
- **Imported Certificates**: Custom certificates (self-signed or third-party CA). Must be PEM-encoded, X.509 v3, RSA-2048/4096, unencrypted private key. No domain ownership validation on import
- **Private CA (Beta)**: Full private Certificate Authority infrastructure for issuing, managing, and revoking internal certificates
- **Certificate Statuses**: `Validating`, `Issued`, `Invalid`, `Renewing`, `Renewal_failed`, `Revoked`
- **Automatic Propagation**: Certificate updates propagate automatically to all integrated services (ALB near-immediate, Object Storage up to 30 min)
- **Quotas**: 20 certificates per cloud, 10 domains per cloud

**CLI Alias**: `yc cm` (shorthand for `yc certificate-manager`)

---

## Enumeration

### Enumerate Certificates

```bash
# List all certificates in current folder
yc cm certificate list
yc cm certificate list --folder-id <folder-id>

# Get detailed certificate metadata
yc cm certificate get <certificate-name>
yc cm certificate get --id <certificate-id>

# Output as JSON for parsing
yc cm certificate list --format json

# List operations (audit trail of actions on cert)
yc cm certificate list-operations --id <certificate-id>

# List who has access to a certificate
yc cm certificate list-access-bindings --id <certificate-id>

# List certificate versions (beta)
yc beta certificate-manager certificate list-versions --id <certificate-id>
```

### Enumerate Private CA (Beta)

```bash
# List Private CAs
yc beta certificate-manager private-certificate-authority list --folder-id <folder-id>

# Get CA details
yc beta certificate-manager private-certificate-authority get --id <ca-id>

# List certificates issued by a CA
yc beta certificate-manager private-certificate list --certificate-authority-id <ca-id>

# List certificate templates
yc beta certificate-manager template list --folder-id <folder-id>

# List issuance policies
yc beta certificate-manager policy list --certificate-authority-id <ca-id>
```

---

## Credential Access

### Extract Certificate Private Keys

With `certificate-manager.certificates.downloader` or `certificate-manager.admin`, extract TLS private keys:

```bash
# Download certificate chain and private key
yc cm certificate content \
  --id <certificate-id> \
  --chain chain.pem \
  --key private-key.pem

# Specify key format
yc cm certificate content --id <id> --chain chain.pem --key key.pem --key-format pkcs8

# Extract all private keys in a folder
for CERT_ID in $(yc cm certificate list --format json | jq -r '.[].id'); do
  yc cm certificate content --id $CERT_ID \
    --chain ${CERT_ID}_chain.pem --key ${CERT_ID}_key.pem
done

# Get content including expired certificates (beta)
yc beta certificate-manager certificate-content get --certificate-id <id>
yc beta certificate-manager certificate-content get-ex --certificate-id <id>
```

**Impact**: Stolen private keys enable decryption of captured TLS traffic (if not using forward secrecy), service impersonation, and MITM attacks.

### Extract Private CA Key

The highest-value target — compromising the CA key allows signing arbitrary certificates trusted by the organization:

```bash
# Extract CA private key and passphrase
yc beta certificate-manager private-certificate-authority-content get-private-key \
  --certificate-authority-id <ca-id>

# Extract CA certificate chain
yc beta certificate-manager private-certificate-authority-content get-chain \
  --certificate-authority-id <ca-id>

# Extract issued certificate private key
yc beta certificate-manager private-certificate-content get-private-key \
  --certificate-id <cert-id>
```

### Terraform State Extraction

The `yandex_cm_certificate` resource for `self_managed` certificates stores private keys in plaintext in Terraform state:

```hcl
resource "yandex_cm_certificate" "example" {
  self_managed {
    certificate = "..."
    private_key = "..."    # plaintext in state file
  }
}
```

### Lockbox Integration

Private keys may also be stored in Yandex Lockbox. Extract via `yc lockbox payload get <secret_id>` if you have `lockbox.payloadViewer`.

---

## Privilege Escalation

### Access Binding Manipulation

With `certificate-manager.admin`, grant a backdoor service account the downloader role:

```bash
# Grant downloader access to a specific certificate
yc cm certificate add-access-binding \
  --id <cert-id> \
  --role certificate-manager.certificates.downloader \
  --service-account-id <attacker-sa>

# Overwrite all access bindings (locks out legitimate users)
yc cm certificate set-access-bindings \
  --id <cert-id> \
  --access-binding role=certificate-manager.admin,service-account-id=<attacker-sa>
```

Roles can be assigned at the individual certificate level, making targeted access grants harder to notice.

---

## Lateral Movement

### Certificate Replacement for MITM

With `certificate-manager.editor`, replace a legitimate certificate with an attacker-controlled one. Integrated services automatically pick up the change:

```bash
# Replace existing certificate with attacker-controlled one
yc cm certificate update --id <target-cert-id> \
  --chain attacker-cert.pem --key attacker-key.pem
```

**Propagation timing:**
- ALB / API Gateway / Smart Web Security: Near-immediate
- Object Storage (static websites): Up to 30 minutes
- CDN: Variable propagation across edge nodes

**Most effective for**: Internal services using Private CA certificates, or services where clients trust a custom CA. Public-facing services will trigger browser certificate warnings for self-signed certs.

### Service Integration Attack Surface

| Integrated Service | Certificate Usage | Impact of Replacement |
|---|---|---|
| Application Load Balancer (ALB) | TLS termination in L7 listeners | MITM all traffic through ALB |
| API Gateway | TLS for custom domains | MITM API traffic |
| Object Storage | HTTPS for static website hosting | MITM static site visitors (30 min delay) |
| CDN | HTTPS for CDN endpoints | MITM CDN-delivered content |
| Smart Web Security | HTTPS for domain-to-proxy | Undermine L7 DDoS/WAF protection |
| Kubernetes (External Secrets Operator) | Syncs cert content to K8s secrets | Pods receive replaced certificates |

---

## Persistence

### Backdoor Certificate Creation

Create additional imported certificates that persist access even if the primary one is rotated:

```bash
# Import a backdoor certificate (no domain ownership validation)
yc cm certificate create --name "monitoring-cert" \
  --chain backdoor.pem --key backdoor-key.pem
```

### Private CA Abuse

Issue long-lived backdoor certificates from the organization's CA:

```bash
# Issue a new certificate from the CA
yc beta certificate-manager private-certificate issue-certificate \
  --certificate-authority-id <ca-id> \
  --name "infra-monitoring"

# Issue certificate from a CSR
yc beta certificate-manager private-certificate issue-certificate-by-csr \
  --certificate-authority-id <ca-id> \
  --csr-file attacker.csr

# Import a rogue sub-CA under the existing CA hierarchy
yc beta certificate-manager private-certificate-authority import-certificate-authority \
  --folder-id <folder-id>
```

### Persistent Downloader Access

Grant a stealthy service account long-term access to certificate private keys:

```bash
yc cm certificate add-access-binding \
  --id <cert-id> \
  --role certificate-manager.certificates.downloader \
  --service-account-id <persistent-sa>
```

### Let's Encrypt Certificate Request

Request new Let's Encrypt certificates for domains the organization controls:

```bash
yc cm certificate request --name "new-cert" --domains "target.example.com"
```

---

## Post-Exploitation

### Service Disruption via Certificate Deletion

Delete certificates to break TLS for all dependent services:

```bash
# Delete a certificate (breaks TLS for dependent ALB, API Gateway, etc.)
yc cm certificate delete --id <cert-id>

# Revoke certificates issued by Private CA
yc beta certificate-manager private-certificate revoke-certificate \
  --certificate-id <cert-id>

# Delete an entire CA
yc beta certificate-manager private-certificate-authority delete --id <ca-id>
```

### Domain Manipulation

Certificate Manager has a Domain resource (Preview) for assigning primary certificates to domains:

```bash
# Change which certificate a domain uses (via API: SetDomainPrimaryCertificate)
```

---

## Key IAM Roles

| Role | Capabilities |
|---|---|
| `certificate-manager.auditor` | View certificate list, dependent resources, access bindings, quotas |
| `certificate-manager.viewer` | All of auditor + view access permission details |
| `certificate-manager.editor` | All of viewer + create/modify/update/delete certificates |
| `certificate-manager.admin` | All of editor + modify access bindings + **get certificate contents (chain + private key)** |
| `certificate-manager.certificates.downloader` | View certificate list + **get certificate contents (chain + private key)** |

**Key insight**: `certificates.downloader` is a narrow role granting only private key download — no management capabilities. However, `certificate-manager.admin` inherently includes the downloader capability.

---

## Detection and Logging

### Audit Trail Events

**Control Plane Events** (source: `yandex.cloud.audit.certificatemanager`):

| Event | Security Relevance |
|---|---|
| `CreateCertificate` | Backdoor certificate creation |
| `UpdateCertificate` | Certificate replacement for MITM |
| `DeleteCertificate` | Service disruption |
| `CreateDomain` / `UpdateDomain` / `DeleteDomain` | Domain manipulation |
| `SetDomainPrimaryCertificate` | Certificate swap on domain |
| `SetCertificateAccessBindings` | Privilege escalation / backdoor access |
| `UpdateCertificateAccessBindings` | Privilege escalation / backdoor access |

**Data Plane Events** (must be explicitly enabled in trail configuration):

| Event | Security Relevance |
|---|---|
| `GetCertificateContent` | **Private key extraction** |
| `GetExCertificateContent` | **Expired certificate key extraction** |

### Critical Detection Gap

Data plane events for `GetCertificateContent` must be **explicitly enabled** in the Audit Trails trail configuration. If only control plane events are collected (the default), **private key downloads will NOT appear in audit logs**. This is a significant blind spot.

### Detection Queries

**Detect private key downloads**:
```
event_type LIKE "%GetCertificateContent%"
```

**Detect certificate replacement**:
```
event_type LIKE "%UpdateCertificate%"
```

**Detect access binding changes on certificates**:
```
event_type LIKE "%CertificateAccessBindings%"
```

### Monitoring Metrics

- `certificate.is_out_of_order` = 1 indicates `Invalid`, `Revoked`, or expired
- `certificate.days_until_expiration` for lifecycle anomalies
- `quota.certificates_count.usage` for detecting mass certificate creation

---

## References

- Certificate Manager Documentation: `en/certificate-manager/`
- Certificate Manager Security: `en/certificate-manager/security/`
- Certificate Manager CLI: `en/cli/cli-ref/certificate-manager/`
- Private CA CLI (Beta): `en/cli/cli-ref-beta/certificate-manager/`
- Audit Trail Events: `en/certificate-manager/at-ref.md`
- Service Integrations: `en/certificate-manager/concepts/services.md`
