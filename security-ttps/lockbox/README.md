# Lockbox — Secret Management

## Overview

Lockbox stores sensitive data (passwords, API keys, TLS keys, tokens) as encrypted key-value secrets with versioning. It is the primary secret management service and a high-value target for credential theft.

## Credential Access

### Secret Extraction

With `lockbox.payloadViewer` or `lockbox.admin`:

```bash
# List all secrets
yc lockbox secret list --folder-id <folder-id>

# Get current version payload
yc lockbox payload get --secret-id <secret-id>

# Get specific version
yc lockbox payload get --secret-id <secret-id> --version-id <ver-id>

# Dump all secrets in a folder
for id in $(yc lockbox secret list --folder-id <fid> --format json | jq -r '.[].id'); do
  echo "=== $id ==="
  yc lockbox payload get --secret-id $id
done
```

### Version History

Lockbox maintains version history. Even if the current version is rotated, previous versions may still be accessible.

---

## Persistence

### Secret Modification

With `lockbox.editor`, modify secrets to inject attacker-controlled values:

```bash
yc lockbox secret add-version --id <secret-id> \
  --payload '[{"key": "DB_PASSWORD", "text_value": "attacker_password"}]'
```

Applications reading from Lockbox will receive the attacker's values.

---

## Post-Exploitation

Lockbox secrets commonly contain:
- Database connection passwords
- API keys for external services
- TLS/SSL private keys
- Service account credentials
- OAuth client secrets
- Encryption passphrases

---

## Enumeration

```bash
yc lockbox secret list --folder-id <folder-id>
yc lockbox secret get <secret-id>  # Metadata only, no payload
yc lockbox secret list-versions --id <secret-id>
```

---

## Detection

| Event | Audit Key |
|---|---|
| Secret payload read | `lockbox.payloads.get` |
| Secret creation | `lockbox.secrets.create` |
| Version addition | `lockbox.secrets.addVersion` |
| Secret deletion | `lockbox.secrets.delete` |

## Defensive Recommendations

1. Restrict `lockbox.payloadViewer` to minimum required principals
2. Monitor payload access events — alert on unusual access patterns
3. Rotate secrets regularly and deactivate old versions
4. Use IAM deny policies to prevent unauthorized access
5. Integrate Lockbox with Cloud Functions/Containers instead of embedding secrets
