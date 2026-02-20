# Certificate Manager

## Overview

Certificate Manager manages TLS/SSL certificates for Yandex Cloud services (API Gateway, Application Load Balancer, CDN, Object Storage website hosting). It handles Let's Encrypt automatic certificates and user-uploaded certificates with private keys.

## Credential Access

### Private Key Extraction

With `certificate-manager.admin`:
- Access managed certificates including private key material
- Private keys for custom (user-uploaded) certificates are stored in the service
- Let's Encrypt certificates have auto-managed keys

### Certificate for Domain Impersonation

With access to a certificate and its private key:
- Impersonate the domain (MITM)
- Decrypt captured TLS traffic
- Set up convincing phishing endpoints with valid TLS

---

## Privilege Escalation

### Certificate Issuance for Domain Takeover

If you can modify DNS records and have `certificate-manager.editor`:
1. Create a Let's Encrypt certificate for a target domain
2. Complete DNS challenge using your DNS access
3. Use the issued certificate to impersonate services

---

## Persistence

### Certificate Replacement

Replace a legitimate certificate with an attacker-controlled one:
- Traffic encrypted with the new cert can be decrypted by the attacker
- Services using the certificate (ALB, API Gateway) automatically pick up the new cert

---

## Enumeration

```bash
yc certificate-manager certificate list --folder-id <folder-id>
yc certificate-manager certificate get <cert-id>
```

---

## Detection

| Event | Audit Key |
|---|---|
| Certificate creation | `certificate-manager.certificates.create` |
| Certificate update | `certificate-manager.certificates.update` |
| Certificate deletion | `certificate-manager.certificates.delete` |

## Defensive Recommendations

1. Restrict `certificate-manager.admin` to infrastructure team
2. Monitor certificate changes — alert on unexpected updates
3. Use Certificate Transparency (CT) log monitoring
4. Audit which services reference each certificate
5. Prefer Let's Encrypt auto-managed certs over manually uploaded
