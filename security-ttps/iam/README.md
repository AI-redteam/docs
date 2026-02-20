# IAM — Identity and Access Management

## Overview

IAM is the central identity service for Yandex Cloud. It manages authentication, authorization, service accounts, tokens, roles, federation, and workload identity. Compromising IAM access is the highest-value target in any Yandex Cloud engagement.

## Credential Types

### IAM Tokens
- **Lifetime:** 12 hours
- **Format:** `t1.[A-Z0-9a-z_-]+[=]{0,2}.[A-Z0-9a-z_-]{86}[=]{0,2}`
- **Header:** `Authorization: Bearer <IAM-token>`
- **Issuance:** For Yandex accounts, service accounts, federated users, local accounts
- **Revocation:** Can be revoked before expiration via CLI/API
- **Cookie dependency:** If created via cookie auth, lifetime bounded by cookie lifetime

### API Keys
- **Lifetime:** Configurable (can set expiration)
- **Header:** `Authorization: Api-Key <key>`
- **Scope control:** 28+ scopes available (e.g., `yc.serverless.functions.invoke`, `yc.ydb.tables.manage`)
- **Default scope:** If unscoped, grants broad default permissions
- **Supported services:** Object Storage, Cloud Functions, Serverless Containers, YDB, Monitoring, Logging, and more

### Static Access Keys (AWS-Compatible)
- **Lifetime:** **Unlimited** — no expiration
- **Format:**
  - Key ID: 25 chars, starts with `YC` (e.g., `YCchbYEDdcsYFBnxSWbcjDJDn`)
  - Secret: 40 chars, starts with `YC` (e.g., `YCVdheub7w9bImcGAnd3dZnf08FRbvjeUFvehGvc`)
- **Services:** Object Storage (S3), Message Queue, YDB, Data Streams, Postbox
- **One-time retrieval:** Secret shown only at creation

### Authorized Keys (RSA)
- **Lifetime:** **Unlimited**
- **Algorithms:** RSA-2048 or RSA-4096
- **Format:** JSON file with public + private key
- **Private key header:** `PLEASE DO NOT REMOVE THIS LINE! Yandex.Cloud SA Key ID <key-id>`
- **One-time retrieval:** Private key shown only at creation
- **Purpose:** JWT-based IAM token generation for service accounts

### OAuth Tokens
- **Format:** Starts with `y`, random digit 0-3, underscore: `y[0-3]_[A-Za-z0-9_-]+`
- **Used by:** CLI, Container Registry, Terraform, Packer, GitLab CI

### Refresh Tokens
- **Lifetime:** 31 days
- **Auto-reissue:** Reissued when used if < 7 days remain
- **DPoP protection:** RFC 9449 — can be bound to YubiKey
- **Storage:** Filesystem (default, less secure) or YubiKey (hardware)

### ID Tokens (OIDC)
- **Lifetime:** 1 hour
- **Format:** JWT (header.body.signature)
- **Issuer:** `https://auth.cloud.yandex.ru`
- **Use:** External OIDC-compatible systems only — cannot access Yandex Cloud APIs

### STS Ephemeral Keys
- **Lifetime:** Temporary (configurable)
- **Scope:** AWS S3-compatible operations only
- **Generated from:** Static access keys

---

## Privilege Escalation

### SA Impersonation via tokenCreator

With `iam.serviceAccounts.tokenCreator` on a service account:

```bash
yc iam create-token --impersonate-service-account-id <sa-id>
```

**Impact:** `tokenCreator` on an SA with `admin` role = effective `admin` access.

### Role Inheritance Exploitation

Roles cascade: Organization → Cloud → Folder → Resource. Getting `editor` on a Cloud gives `editor` on **every** folder and resource under it. Inherited permissions **cannot be revoked** at lower levels.

### SA → Cloud Admin Chain

1. Compromise SA (metadata, leaked key)
2. `yc resource-manager folder list-access-bindings --id <folder-id>`
3. If SA has `admin` → create new SA with broader roles
4. If SA has `iam.serviceAccounts.admin` → create keys for other SAs
5. If SA has `resource-manager.clouds.owner` → full cloud control

### Authorization Policy Bypass

Deny policies are checked **before** role checks but must be explicitly configured at each level. If deny exists at folder but not cloud level, cloud-level operations bypass the folder deny.

---

## Credential Access

### Key Enumeration

```bash
yc iam service-account list --folder-id <folder-id>
yc iam api-key list --service-account-id <sa-id>
yc iam access-key list --service-account-id <sa-id>
yc iam key list --service-account-id <sa-id>
```

### Key Creation (Persistence)

With `iam.serviceAccounts.keyAdmin` (or specific sub-roles):

```bash
yc iam api-key create --service-account-id <sa-id>
yc iam access-key create --service-account-id <sa-id>
yc iam key create --service-account-id <sa-id> --output key.json
```

SAs support **multiple keys** of each type — extra keys go unnoticed without active monitoring.

### IAM Token from Authorized Key

```bash
yc iam create-token --service-account-key-file key.json
```

Or: sign JWT with RSA private key → POST to `https://iam.api.cloud.yandex.net/iam/v1/tokens`.

### Refresh Token Theft

Stored at `~/.config/yandex-cloud/`. Without DPoP enforcement, yields 31 days of IAM token generation.

---

## Persistence

### New Service Account with Unlimited Keys

```bash
yc iam service-account create --name svc-monitor --folder-id <folder-id>
yc resource-manager folder add-access-binding \
  --id <folder-id> --role editor --service-account-id <new-sa-id>
yc iam access-key create --service-account-id <new-sa-id>    # unlimited lifetime
yc iam key create --service-account-id <new-sa-id> -o key.json  # unlimited lifetime
```

### Add Keys to Existing SA

Less visible than new SA creation:
```bash
yc iam api-key create --service-account-id <existing-sa-id>
yc iam access-key create --service-account-id <existing-sa-id>
```

### Workload Identity Federation Binding

```bash
yc iam workload-identity federated-credential create \
  --service-account-id <sa-id> \
  --federation-id <fed-id> \
  --external-subject-id <attacker-subject>
```

Attacker's external identity (GitHub Actions, GitLab CI, etc.) exchanges tokens for cloud IAM tokens indefinitely.

### Organization-Level Role Binding

```bash
yc organization-manager organization add-access-binding \
  --id <org-id> --role editor --service-account-id <backdoor-sa-id>
```

Propagates to **all** clouds, folders, and resources.

---

## Post-Exploitation / Enumeration

```bash
yc iam service-account list --folder-id <folder-id>
yc iam service-account get <sa-id>
yc resource-manager cloud list-access-bindings --id <cloud-id>
yc resource-manager folder list-access-bindings --id <folder-id>
yc organization-manager federation saml list --organization-id <org-id>
```

---

## Key IAM Roles

| Role | Capability |
|---|---|
| `iam.serviceAccounts.user` | View SA info |
| `iam.serviceAccounts.admin` | Full SA management |
| `iam.serviceAccounts.tokenCreator` | Create IAM tokens for SAs |
| `iam.serviceAccounts.keyAdmin` | Manage all key types |
| `iam.serviceAccounts.accessKeyAdmin` | Manage static keys only |
| `iam.serviceAccounts.apiKeyAdmin` | Manage API keys only |
| `iam.serviceAccounts.authorizedKeyAdmin` | Manage RSA keys only |
| `iam.serviceAccounts.federatedCredentialEditor` | Manage WIF bindings |
| `iam.admin` | Full IAM service control |
| `resource-manager.clouds.owner` | Full cloud control |

---

## Authorization Deny Policies

| Policy | Effect |
|---|---|
| `iam.denyServiceAccountCreation` | Block SA creation |
| `iam.denyServiceAccountAccessKeysCreation` | Block static key creation |
| `iam.denyServiceAccountApiKeysCreation` | Block API key creation |
| `iam.denyServiceAccountAuthorizedKeysCreation` | Block RSA key creation |
| `iam.denyServiceAccountCredentialsCreation` | Block ALL credential types |
| `iam.denyServiceAccountImpersonation` | Block SA impersonation |

---

## Detection

| Event | Audit Trail Key |
|---|---|
| SA creation | `iam.serviceAccounts.create` |
| Key creation | `iam.keys.create`, `iam.apiKeys.create`, `iam.accessKeys.create` |
| Role binding changes | `*.updateAccessBindings` |
| WIF credential creation | `iam.workloadIdentityFederatedCredentials.create` |
| Token creation | `iam.tokens.create` |

## Defensive Recommendations

1. Enforce `iam.denyServiceAccountCredentialsCreation` at organization level
2. Always use scoped API keys — never leave unscoped
3. Monitor static key "last used" timestamps
4. Enforce DPoP with YubiKey for refresh tokens
5. Audit SA key counts regularly — flag SAs with multiple keys
6. Use short-lived IAM tokens and STS ephemeral keys over static keys
