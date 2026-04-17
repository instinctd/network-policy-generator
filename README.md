# Hubble Network Flow Collector

A tool for collecting network interactions between pods via Hubble and automatically generating CiliumNetworkPolicy based on real traffic.

## Features

- Automatic generation of egress and ingress rules based on real traffic
- Detection of internal and external IPs using Pod CIDR and Service CIDR
- Automatic filtering of Kubernetes/Cilium service labels (including commit, pod-template-hash, and others)
- Support for external sources (LoadBalancer, Ingress Controller)
- Automatic DNS rule addition
- Default port substitution for popular services
- Policy validation before saving

## Download Pre-built Binaries

You can use pre-built binaries for your operating system:

### macOS

**Intel (x64):**
```bash
# Download hubble-collector-darwin
chmod +x hubble-collector-darwin
./hubble-collector-darwin -n production -o flows.json
```

**Apple Silicon (M1/M2/M3):**
```bash
# Download hubble-collector-darwin-arm64
chmod +x hubble-collector-darwin-arm64
./hubble-collector-darwin-arm64 -n production -o flows.json
```

### Linux (AMD64)

```bash
# Download hubble-collector-linux
chmod +x hubble-collector-linux
./hubble-collector-linux -n production -o flows.json
```

### Windows

```bash
# Download hubble-collector.exe
hubble-collector.exe -n production -o flows.json
```

## Build from Source (optional)

If you want to build the binary yourself:

```bash
# Install dependencies
go mod download

# Build
go build -o hubble-collector hubble-collector.go

# Or cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o hubble-collector-linux hubble-collector.go
```

## Requirements

1. Hubble CLI:

```bash
# macOS
brew install cilium-cli

# Linux
HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
curl -L --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-amd64.tar.gz
tar xzvf hubble-linux-amd64.tar.gz
sudo mv hubble /usr/local/bin
```

2. Port-forward to Hubble Relay (if required):

```bash
kubectl port-forward -n kube-system svc/hubble-relay 4245:80
```

## Usage

### Basic Commands

```bash
# Collect flows for the last 60 seconds
./hubble-collector -n production -o flows.json

# Collect flows for 30 minutes
./hubble-collector -n production -o flows.json --duration 1800

# Continuous monitoring (Ctrl+C to stop)
./hubble-collector -n production -o flows.json --follow
```

### Generating CiliumNetworkPolicy

```bash
# Collect flows and create policies
./hubble-collector -n production -o flows.json \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"

# For a specific application
./hubble-collector -n production -o flows.json \
  --from-label "app=backend-api" \
  --cilium true

# Long collection for better accuracy
./hubble-collector -n production -o flows.json \
  --duration 3600 \
  --cilium true
```

### Filtering

```bash
# By source label
./hubble-collector -n dev01 -o flows.json \
  --from-label "app.kubernetes.io/name=notifications-push"

# By destination label
./hubble-collector -n prod -o flows.json \
  --to-label "app=postgres"

# Only dropped connections
./hubble-collector -n prod -o dropped.json --verdict DROPPED

# Combined filters
./hubble-collector -n dev01 -o flows.json \
  --from-label "app=api" \
  --to-label "app=database" \
  --verdict FORWARDED
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-n`, `--namespace` | Namespace to monitor | required |
| `-o`, `--output` | Output JSON file | required |
| `--duration` | Seconds to collect flows | 60 |
| `--follow` | Continuous monitoring | false |
| `--from-label` | Filter by source label | none |
| `--to-label` | Filter by destination label | none |
| `--verdict` | Filter by verdict (FORWARDED, DROPPED, ERROR, AUDIT, REDIRECTED, TRACED) | none |
| `--cilium` | Create CiliumNetworkPolicy (true/false) | false |
| `--cilium-output-dir` | Directory for policies | ./cilium-policies |
| `--pod-cidr` | Cluster Pod CIDR (critical for correct policies) | 10.39.0.0/16 |
| `--service-cidr` | Cluster Service CIDR (critical for correct policies) | 10.40.0.0/16 |
| `--debug-flows` | Save raw flows for debugging | none |

## Critical Parameters

### Pod CIDR and Service CIDR

The `--pod-cidr` and `--service-cidr` parameters are critical for correct policy generation.

#### Why They're Needed

The script must distinguish between:
- Pod IPs (internal pod IPs)
- Service IPs (ClusterIP services)
- External public IPs

Without specifying CIDRs, the script uses standard private network ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), which may lead to incorrect IP classification.

#### How to Find Your Cluster's CIDR

```bash
# Method 1: Via kube-controller-manager
kubectl -n kube-system get pod -l component=kube-controller-manager -o yaml | grep -E "cluster-cidr|service-cluster-ip-range"

# Example output:
#   - --cluster-cidr=10.39.0.0/16
#   - --service-cluster-ip-range=10.40.0.0/16

# Method 2: Via cluster-info
kubectl cluster-info dump | grep -m 1 cluster-cidr
kubectl cluster-info dump | grep -m 1 service-cluster-ip-range

# Method 3: From configmap (if available)
kubectl -n kube-system get cm kubeadm-config -o yaml | grep -E "podSubnet|serviceSubnet"
```

#### Correct Usage

```bash
# With CIDR specified (recommended)
./hubble-collector -n production -o flows.json \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"
```

#### What Happens Without CIDR

If `--pod-cidr` and `--service-cidr` are not specified, the script uses default ranges:
- 10.39.0.0/16 (Pod CIDR)
- 10.40.0.0/16 (Service CIDR)
- 172.16.0.0/12 (RFC1918)
- 192.168.0.0/16 (RFC1918)
- 100.64.0.0/10 (Shared address space)

This works for most clusters, but if your CIDRs differ:
1. IPs may be misclassified
2. `toCIDR` rules are created instead of `toEndpoints`
3. Policies become unstable (break when pods restart)

**Example problem:**

Without CIDR:
```yaml
egress:
- toCIDR:
  - 10.39.36.20/32  # Pod IP - unstable!
  toPorts:
  - protocol: TCP
    ports:
    - port: '8080'
```

With correct CIDR:
```yaml
egress:
- toEndpoints:
  - matchLabels:
      app: backend-api  # Stable, not dependent on IP
  toPorts:
  - protocol: TCP
    ports:
    - port: '8080'
```

### Optimal Collection Duration

The `--duration` parameter determines how long to collect flows.

#### Recommendations

| Scenario | Duration | Reason |
|----------|----------|--------|
| Script testing | 60-300 sec | Quick check |
| Production policies | 300-600 sec | Balance of coverage and relevance |
| Full coverage | 1800-3600 sec | All scenarios, but risk of dead pods |
| Live pods only | 300 sec | Minimum dead IPs |

#### Dead Pod Problem

Hubble stores historical flows. If during `--duration`:
- A pod was deleted
- A pod restarted and got a new IP

The script will see flows with the old IP, but no pod with that IP will exist.

**Result:** The script will print a warning and skip such flows:
```
Warning: unknown internal IP 10.39.36.20 (port 14816) - pod may have been deleted
```

#### Recommended Approach

For production, use a short period with CIDR specified:

```bash
./hubble-collector -n production -o flows.json \
  --duration 300 \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"
```

For more coverage — run multiple times at different times and merge policies manually.

#### Follow Mode

For continuous monitoring use `--follow`:

```bash
./hubble-collector -n production -o flows.json \
  --follow \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"

# Stop with Ctrl+C when enough flows have been collected
```

## Example Scenarios

### 1. Creating Policies Based on Real Traffic

```bash
# Step 1: Collect flows
./hubble-collector -n production -o flows.json \
  --duration 3600 \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"

# Step 2: Review created policies
ls -la ./cilium-policies/
cat ./cilium-policies/backend-api-cnp.yaml

# Step 3: Dry-run apply
kubectl apply -f ./cilium-policies/ --dry-run=server

# Step 4: Apply
kubectl apply -f ./cilium-policies/
```

### 2. Network Policy Audit

```bash
# Collect actual traffic
./hubble-collector -n production -o actual.json --duration 1800

# Check dropped connections
./hubble-collector -n production -o blocked.json --verdict DROPPED

# Find what is being blocked from a specific service
./hubble-collector -n prod -o api-blocked.json \
  --from-label "app=api" --verdict DROPPED
```

### 3. Monitoring a Specific Application

```bash
# Outgoing connections (egress)
./hubble-collector -n prod -o api-outbound.json \
  --from-label "app=backend-api" --follow

# Incoming connections (ingress)
./hubble-collector -n prod -o db-clients.json \
  --to-label "app=postgres" --follow

# Full picture for a service
./hubble-collector -n prod -o service-flows.json \
  --from-label "app=api" \
  --cilium true \
  --duration 600
```

### 4. Migration to CiliumNetworkPolicy

```bash
# Step 1: Collect flows
./hubble-collector -n production -o flows.json \
  --duration 7200 --cilium true

# Step 2: Apply in test namespace
for policy in ./cilium-policies/*.yaml; do
  sed 's/namespace: production/namespace: test/' "$policy" | kubectl apply -f -
done

# Step 3: Monitor dropped flows
./hubble-collector -n test -o validation.json \
  --verdict DROPPED --duration 600

# Step 4: If OK, apply in production
kubectl apply -f ./cilium-policies/
```

## Output Format

### JSON (connections graph)
2
```json
{
  "namespace": "production",
  "collected_at": "2024-12-31T10:30:00Z",
  "total_flows": 1234,
  "filters": {
    "from_label": "app=api",
    "to_label": null,
    "verdict": "FORWARDED"
  },
  "connections": [
    {
      "source": "backend-api-7d9f8b6c5-x9k2m",
      "destination": "postgres-0:5432/TCP",
      "flows_count": 245
    }
  ]
}
```

### CiliumNetworkPolicy (auto-generated)

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: backend-api
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: backend-api

  egress:
  - toEndpoints:
    - matchLabels:
        app: postgres
    toPorts:
    - protocol: TCP
      ports:
      - port: "5432"

  - toCIDR:
    - "8.8.8.8/32"
    toPorts:
    - protocol: UDP
      ports:
      - port: "53"

  - toEndpoints:
    - matchLabels:
        io.kubernetes.pod.namespace: kube-system
        k8s-app: kube-dns
    toPorts:
    - protocol: UDP
      ports:
      - port: "53"

  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - protocol: TCP
      ports:
      - port: "8080"

  - fromCIDR:
    - "203.0.113.5/32"
    toPorts:
    - protocol: TCP
      ports:
      - port: "8080"
```

## How Policy Generation Works

The script analyzes flows and automatically generates **egress and ingress rules** based on real traffic.

### Egress and Ingress

A comprehensive policy is created for each pod:

**Egress (outbound traffic):**
- Controls where a pod can connect
- `toEndpoints` rules for pod-to-pod
- `toCIDR` rules for external IPs
- DNS is automatically added

**Ingress (inbound traffic):**
- Controls who can connect to the pod
- `fromEndpoints` rules for pod-to-pod
- `fromCIDR` rules for external sources (loadbalancer, ingress-controller)
- Accounts for real ports and protocols

**Example generated policy:**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: backend-api
spec:
  endpointSelector:
    matchLabels:
      app: backend-api

  egress:
  - toEndpoints:
    - matchLabels:
        app: postgres
    toPorts:
    - protocol: TCP
      ports:
      - port: "5432"

  - toCIDR:
    - "8.8.8.8/32"
    toPorts:
    - protocol: UDP
      ports:
      - port: "53"

  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - protocol: TCP
      ports:
      - port: "8080"

  - fromCIDR:
    - "203.0.113.5/32"
    toPorts:
    - protocol: TCP
      ports:
      - port: "8080"
```

### Destination Type Detection Logic

The script intelligently determines the destination type and uses correct selectors:

| Connection Type | IP Address | Egress Selector | Ingress Selector |
|----------------|------------|----------------|-----------------|
| Pod in same NS | 10.39.1.20 | toEndpoints + matchLabels | fromEndpoints + matchLabels |
| Pod in other NS | 10.39.2.30 | toEndpoints + matchExpressions | fromEndpoints + matchExpressions |
| Pod by IP | 10.39.3.40 | toEndpoints + matchLabels | fromEndpoints + matchLabels |
| External API/LB | 8.8.8.8 | toCIDR | fromCIDR |
| Dead pod | 10.39.36.20 | skipped | skipped |

### External IP Detection

With `--pod-cidr` and `--service-cidr` parameters:
- Real cluster CIDR is checked
- Accurate Pod vs External IP classification

Without parameters (default for typical clusters):
- 10.39.0.0/16 (Pod CIDR)
- 10.40.0.0/16 (Service CIDR)
- 172.16.0.0/12 (RFC1918)
- 192.168.0.0/16 (RFC1918)
- 100.64.0.0/10 (Shared address space)

**Important:** If your cluster uses different ranges, you must specify `--pod-cidr` and `--service-cidr`.

### Ingress Rule Generation

The script automatically creates ingress rules based on flows:

**External sources (LoadBalancer, Ingress Controller):**
```yaml
ingress:
- fromCIDR:
  - "203.0.113.5/32"
  toPorts:
  - protocol: TCP
    ports:
    - port: "8080"
```

**Internal sources (pod-to-pod):**
```yaml
ingress:
- fromEndpoints:
  - matchLabels:
      app: frontend
  toPorts:
  - protocol: TCP
    ports:
    - port: "8080"
```

**Benefits:**
- Full isolation (control of both inbound and outbound traffic)
- Protection from unauthorized connections
- Explicit allowance for LoadBalancer and Ingress Controller
- Automatic egress and ingress synchronization (from the same flows)

### Default Ports for Infrastructure

If Hubble cannot determine the port (e.g., connection was interrupted before establishment), the script automatically substitutes known ports for popular components:

| Component | Port | Protocol |
|-----------|------|----------|
| RabbitMQ | 5672 | TCP |
| RabbitMQ Management | 15672 | TCP |
| Redis | 6379 | TCP |
| Redis Sentinel | 26379 | TCP |
| PostgreSQL | 5432 | TCP |
| VictoriaMetrics (vmagent) | 8429 | TCP |
| VictoriaMetrics (vmsingle) | 8429 | TCP |
| VictoriaMetrics (vmselect) | 8481 | TCP |
| VictoriaMetrics (vminsert) | 8480 | TCP |
| VictoriaMetrics (vmstorage) | 8482 | TCP |
| Prometheus | 9090 | TCP |
| Alertmanager | 9093 | TCP |
| Grafana | 3000 | TCP |
| DNS (kube-dns, coredns) | 53 | UDP |

**Detection by labels:**
The script analyzes `app`, `app.kubernetes.io/name`, `app.kubernetes.io/component`, `k8s-app` to substitute the default port.

**Example:**
```
Using default port 6379/TCP for pod:dev01/redis-sentinel-0
Using default port 8429/TCP for ingress from pod:monitoring/vmagent-0
```

**Important:** Default ports are only used when Hubble could not determine the real port. If the port is known, the real port from flows is used.

### Label Filtering

The tool automatically excludes service and temporary labels from policies:

**Excluded:**
- `io.cilium.*` — Cilium service labels
- `io.kubernetes.pod.*` — internal Kubernetes labels
- `k8s.namespace.labels.*` — namespace metadata
- `k8s.policy.*` — policy metadata
- `pod-template-hash` — changes with every deployment
- `controller-revision-hash` — changes on StatefulSet update
- `statefulset.kubernetes.io/pod-name` — specific to individual pod
- `commit` — unique to each deployment version

**Stable user labels are used:**
- `app`, `version`, `component`, `tier`, `environment`
- `app.kubernetes.io/name`, `app.kubernetes.io/component`
- other custom labels

## Applying Policies

```bash
# Validate before applying
kubectl apply -f ./cilium-policies/ --dry-run=server

# View a specific policy
cat ./cilium-policies/backend-api-cnp.yaml

# Apply
kubectl apply -f ./cilium-policies/

# Check status
kubectl get ciliumnetworkpolicies -n production
kubectl describe ciliumnetworkpolicy backend-api -n production

# Monitor after applying
./hubble-collector -n production -o dropped.json \
  --verdict DROPPED --follow
```

## Troubleshooting

### Error: hubble: command not found

```bash
# Install Hubble CLI (see Requirements section)
which hubble
```

### Error: failed to connect to Hubble

```bash
# Check that Hubble Relay is running
kubectl get pods -n kube-system | grep hubble

# Port-forward
kubectl port-forward -n kube-system svc/hubble-relay 4245:80
```

### Empty Output (no flows)

```bash
# Check that the namespace has traffic
kubectl get pods -n <namespace>

# Check that Hubble sees flows
hubble observe --namespace <namespace> --last 10

# Increase --duration
./hubble-collector -n prod -o flows.json --duration 300
```

### No Labels for Pod

```
Skip pod 'some-pod' - no labels
```

Solution: add labels to pods in Deployment/StatefulSet or use `--from-label` for filtering.

### Policy Blocks Required Traffic

```bash
# Delete the policy
kubectl delete ciliumnetworkpolicy <name> -n <namespace>

# Re-collect flows with a longer period
./hubble-collector -n production -o flows.json \
  --duration 7200 --cilium true
```

## Recommendations

### Collection Period

Recommended flow collection duration:

```bash
# Testing: 5-10 minutes
--duration 300

# Production: 30-60 minutes
--duration 1800

# Full coverage: 2-4 hours (including peak load)
--duration 7200
```

### Filtering

Use filters for large namespaces:

```bash
# Only a specific application
--from-label "app=backend-api"

# Only a tier
--from-label "tier=backend"
```

### Testing

Order of applying policies in production:

1. Apply in test namespace
2. Monitor dropped flows
3. Verify all services work correctly
4. Verify ingress works (LoadBalancer, Ingress Controller)
5. Apply in production

### Monitoring After Applying

```bash
# Monitor dropped flows after applying
./hubble-collector -n production -o dropped.json \
  --verdict DROPPED --follow
```

## References

- [Hubble Documentation](https://docs.cilium.io/en/stable/observability/hubble/)
- [Cilium Network Policies](https://docs.cilium.io/en/stable/policy/)
- [Network Policy Best Practices](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
