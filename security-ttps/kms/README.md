# KMS — Key Management Service

## Overview

KMS manages symmetric encryption keys used for encrypting disks, Object Storage objects, Lockbox secrets, and database encryption. Compromising KMS access enables decryption of all data protected by those keys.

## Credential Access

### Decrypt with KMS Key

With `kms.keys.encrypterDecrypter`:

```bash
yc kms symmetric-crypto decrypt \
  --key-id <key-id> \
  --ciphertext-file encrypted.bin \
  --plaintext-file decrypted.bin
```

### Encrypt for Ransom

With the same role, encrypt data and delete the originals:

```bash
yc kms symmetric-crypto encrypt \
  --key-id <key-id> \
  --plaintext-file sensitive.bin \
  --ciphertext-file ransomed.bin
```

---

## Privilege Escalation

### KMS Access Unlocks Other Services

KMS keys protect:
- **Compute disks** — encrypted disks require KMS for read/write
- **Object Storage** — SSE-KMS server-side encryption
- **Lockbox secrets** — secrets encrypted with KMS keys
- **Database encryption** — managed DB transparent encryption

Access to a KMS key effectively grants access to all data encrypted with it.

---

## Impact

### Key Destruction

```bash
yc kms symmetric-key delete <key-id>
```

Deleting a KMS key makes **all data encrypted with it permanently unrecoverable**.

### Key Version Rotation Abuse

Create a new key version and make it primary. Data encrypted with old versions can't be decrypted without explicitly specifying the old version.

---

## Enumeration

```bash
yc kms symmetric-key list --folder-id <folder-id>
yc kms symmetric-key get <key-id>
yc kms symmetric-key list-versions --id <key-id>
```

---

## Detection

| Event | Audit Key |
|---|---|
| Key usage (decrypt) | `kms.symmetricCrypto.decrypt` |
| Key usage (encrypt) | `kms.symmetricCrypto.encrypt` |
| Key deletion | `kms.symmetricKeys.delete` |
| Key creation | `kms.symmetricKeys.create` |

## Defensive Recommendations

1. Restrict `kms.keys.encrypterDecrypter` to minimum required principals
2. Enable key deletion protection
3. Monitor decrypt operations — alert on unusual volumes
4. Use separate keys for different data classification levels
5. Enable key rotation policies
