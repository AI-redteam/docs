# Yandex Cloud Security Techniques Wiki

> Tactics, Techniques, and Procedures for Yandex Cloud — organized per service. For authorized security testing and defensive research.

## Platform Overview

### Resource Hierarchy

```
Organization
└── Cloud
    └── Folder
        └── Resources (VMs, DBs, buckets, functions, etc.)
```

- Roles assigned at any level **inherit downward** — organization roles propagate to all children.
- **Cannot restrict inherited permissions** — child resources cannot revoke parent-level access.
- Default policy is **deny-all** — no access without explicit role binding.

### Credential Types At a Glance

| Type | Lifetime | Prefix/Format | Risk |
|---|---|---|---|
| IAM Token | 12 hours | `t1.` + Base64URL | Medium |
| API Key | Configurable | Opaque | Medium |
| Static Access Key (AWS-compat) | **Unlimited** | `YC` + 25/40 chars | **High** |
| Authorized Key (RSA) | **Unlimited** | RSA-2048/4096 PEM | **High** |
| OAuth Token | Variable | `y[0-3]_` prefix | Medium |
| Refresh Token | 31 days | Opaque | Medium-High |
| ID Token (OIDC) | 1 hour | JWT | Low |
| STS Ephemeral Key | Temporary | AWS-compat | Low |

## Service Writeups

| Service | Description |
|---|---|
| [IAM](iam/) | Identity, roles, service accounts, tokens, federation |
| [Compute](compute/) | VMs, metadata service, serial console, OS-Login |
| [Managed Kubernetes](managed-kubernetes/) | Cluster RBAC, pod SA, network policies |
| [Object Storage](object-storage/) | Bucket policies, ACLs, pre-signed URLs, encryption |
| [Cloud Functions](cloud-functions/) | Serverless code execution, SA binding, env vars |
| [Serverless Containers](serverless-containers/) | Container execution, SA binding |
| [API Gateway](api-gateway/) | Auth bypass, caching, route injection |
| [VPC](vpc/) | Security groups, routing, NAT |
| [KMS](kms/) | Encryption key management and abuse |
| [Lockbox](lockbox/) | Secret storage and extraction |
| [Managed GitLab](managed-gitlab/) | CI/CD pipelines, runners, secrets |
| [Container Registry](container-registry/) | Image poisoning, credential extraction |
| [DataSphere](datasphere/) | ML notebooks, secret access |
| [IoT Core](iot-core/) | Device auth, MQTT interception |
| [Data Transfer](data-transfer/) | Cross-service credential flows |
| [DNS](dns/) | Zone manipulation, traffic redirection |
| [Managed Databases](managed-databases/) | PostgreSQL, MySQL, ClickHouse, YDB |
| [Audit Trails](audit-trails/) | Event logging, evasion |
| [Organization](organization/) | Federation, SSO, MFA, OS-Login |
| [Certificate Manager](certificate-manager/) | TLS certs, private key access |

## MITRE ATT&CK Mapping

| Tactic | Key Services |
|---|---|
| Initial Access | IAM (stolen creds), Object Storage (public buckets), Compute (SSRF/metadata) |
| Credential Access | IAM (key creation), Compute (metadata), Lockbox, KMS, GitLab CI/CD |
| Privilege Escalation | IAM (role inheritance, SA impersonation), Cloud Functions (SA binding), K8s |
| Lateral Movement | VPC (security groups), DNS, Data Transfer, Container Registry |
| Persistence | IAM (new SA/keys, WIF), Compute (cloud-init, SSH keys), Functions (triggers) |
| Defense Evasion | Audit Trails (disable), Logging (retention), ephemeral creds |
| Exfiltration | Object Storage, Data Transfer, DNS, Serverless Functions, Postbox |

---

> **Disclaimer:** For authorized security testing, defensive research, and education only.
