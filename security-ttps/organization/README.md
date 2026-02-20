# Organization Management

## Overview

Organization is the top-level resource in Yandex Cloud. It manages identity federations (SAML/OIDC SSO), user directories, groups, MFA policies, OS-Login, password policies, and SSO applications. Compromising organization-level access provides the broadest possible scope.

## Initial Access

### SAML Federation Compromise

**SAML authentication flow:**
1. User clicks login → redirected to IdP
2. IdP authenticates user → returns signed SAML assertion
3. Yandex Cloud validates assertion signature → creates session

**Attack vectors:**
- **IdP certificate compromise:** Forge valid SAML assertions for any user
- **Expired IdP certificate:** Validation may fail open or be bypassed
- **No certificate pinning:** MITM the IdP endpoint
- **SAML assertion injection:** XML signature bypass if validation is weak
- **Group claim spoofing:** Inject group memberships in SAML attributes

### OIDC Application Exploitation

**OAuth 2.0 Authorization Code Flow:**
- `state` parameter enforcement not explicitly documented — CSRF risk
- PKCE not explicitly documented — code interception risk
- Client secret shown once at creation — if captured, impersonate the application
- Redirect URI mismatch can leak authorization codes

### Password Policy Weaknesses

Default password policy before configuration:
- Brute force threshold: 15 attempts in 10 minutes → 10 minute lockout
- **User enumeration:** Lockout timing differences reveal valid usernames
- **Lockout DoS:** Attacker locks legitimate users out intentionally
- No password history enforcement documented

---

## Privilege Escalation

### Organization-Level Role Assignment

```bash
yc organization-manager organization add-access-binding \
  --id <org-id> --role admin --service-account-id <attacker-sa>
```

Organization `admin` inherits to **every** cloud, folder, and resource.

### Group Membership Manipulation

If SAML group mapping is configured, inject group claims in SAML assertions to gain roles assigned to those groups.

### MFA Recovery Bypass

Organization admins can remove MFA factors for any user. A compromised admin account can:
1. Remove target user's MFA
2. Reset their password or take over their session
3. Access all resources the target user has access to

---

## Persistence

### Federation Backdoor

Create or modify an identity federation to trust an attacker-controlled IdP:

```bash
yc organization-manager federation saml create \
  --name backup-idp \
  --organization-id <org-id> \
  --issuer https://attacker-idp.com \
  --sso-url https://attacker-idp.com/sso \
  --cookie-max-age 12h
```

Any user created in the attacker's IdP can now authenticate to the organization.

### OS-Login SSH Key Persistence

Add SSH keys to OS-Login profiles stored in IAM:
- Keys persist across VM recreations
- Apply to all OS-Login-enabled VMs in the organization
- Multiple keys per profile supported

### Authorization Policy Manipulation

Remove deny policies to re-enable previously blocked operations:
- Remove `iam.denyServiceAccountCredentialsCreation` to allow SA key creation
- Remove `iam.denyServiceAccountImpersonation` to allow SA impersonation

---

## Post-Exploitation

### User Directory Enumeration

```bash
yc organization-manager organization list
yc organization-manager user list --organization-id <org-id>
yc organization-manager group list --organization-id <org-id>
yc organization-manager federation saml list --organization-id <org-id>
```

Unless `organization.denyUserListing` policy is set, any org member can list all users.

### MFA Configuration Review

Understand MFA enforcement scope to identify users without MFA.

---

## OS-Login Techniques

### SSH Certificate Export

With `compute.osLoginAdmin`:

```bash
yc compute ssh certificate export --organization-id <org-id>
# Certificate valid for 1 hour
ssh -i ~/cert/yc-org-id-<org-id>-<username> <username>@<vm-ip>
```

### SSH Key Authentication

OS-Login profiles also support persistent SSH public keys:
- Admin-managed or user self-managed keys
- Standard OpenSSH format
- Apply to all OS-Login VMs

### Sudo Escalation

OS-Login does **not** manage sudo. If the OS-Login user has sudo group membership on the VM → root access.

---

## Detection

| Event | Audit Key |
|---|---|
| Federation creation/modification | `organization-manager.federations.create/update` |
| User listing | `organization-manager.users.list` |
| Group changes | `organization-manager.groups.update` |
| Role binding changes | `organization-manager.organizations.updateAccessBindings` |
| MFA changes | Organization audit events |

## Defensive Recommendations

1. Use MFA enforcement (WebAuthn/FIDO2 preferred over SMS)
2. Restrict organization `admin` to minimum users
3. Monitor federation creation/modification events
4. Enable `organization.denyUserListing` and `organization.denyMemberInvitation` policies
5. Audit OS-Login profiles and SSH keys regularly
6. Use short-lived SSH certificates (OS-Login) instead of static keys
7. Implement SAML assertion encryption, not just signing
