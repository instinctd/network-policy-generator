# Hubble Network Flow Collector

A tool for collecting network interactions between pods via Hubble and automatically generating CiliumNetworkPolicy based on real traffic.

## Features

- Native gRPC connection to Hubble Relay (no `hubble` CLI required)
- Automatic port-forward to `svc/hubble-relay` — no manual setup needed
- Automatic generation of egress and ingress rules based on real traffic
- Detection of internal and external IPs using Pod CIDR and Service CIDR
- Multi-namespace support: `-n prod -n staging`
- Smart label selection: prefers `app.kubernetes.io/name` → `app` → other stable labels
- Merge-on-write: new rules merged into existing policy files, ports deduplicated
- Cluster-dedup (`--cluster-dedup`): skips policies already matching live cluster state
- Unhandled flow summary: skipped flows reported by reason at end of run
- Automatic filtering of Kubernetes/Cilium service labels (commit, pod-template-hash, etc.)
- Support for external sources (LoadBalancer, Ingress Controller)
- Automatic DNS rule addition
- Default port substitution for popular infrastructure components
- Policy validation before saving

## Download Pre-built Binaries

### macOS

**Intel (x64):**
```bash
chmod +x kubectl-hubble-collector-darwin-amd64
./kubectl-hubble-collector-darwin-amd64 -n production -o flows.json
```

**Apple Silicon (M1/M2/M3):**
```bash
chmod +x kubectl-hubble-collector-darwin-arm64
./kubectl-hubble-collector-darwin-arm64 -n production -o flows.json
```

### Linux (AMD64)

```bash
chmod +x kubectl-hubble-collector-linux-amd64
./kubectl-hubble-collector-linux-amd64 -n production -o flows.json
```

### Windows

```bash
kubectl-hubble-collector-windows-amd64.exe -n production -o flows.json
```

## Build from Source

```bash
# Install dependencies
go mod download

# Build for current platform
make build

# Or manually
go build -o kubectl-hubble-collector ./cmd/collector

# Cross-compile for Linux
make build-linux
# Or manually
GOOS=linux GOARCH=amd64 go build -o kubectl-hubble-collector-linux-amd64 ./cmd/collector

# Build for all platforms
make build-all
```

## Requirements

- `kubectl` configured with access to the cluster
- Hubble enabled in the cluster (Cilium with Hubble Relay)
- `hubble` CLI — optional, used only as fallback if auto port-forward fails

## Usage

### Basic Commands

```bash
# Collect flows for the last 60 seconds (auto port-forward to Hubble Relay)
./kubectl-hubble-collector -n production -o flows.json

# Collect flows for 30 minutes
./kubectl-hubble-collector -n production -o flows.json --duration 1800

# Continuous monitoring (Ctrl+C to stop)
./kubectl-hubble-collector -n production -o flows.json --follow

# Multiple namespaces
./kubectl-hubble-collector -n production -n staging -o flows.json

# All namespaces
./kubectl-hubble-collector -A -o flows.json

# Connect to Hubble Relay directly (skip auto port-forward)
./kubectl-hubble-collector -n production -o flows.json --server localhost:4245
```

### Generating CiliumNetworkPolicy

```bash
# Collect flows and generate policies
./kubectl-hubble-collector -n production -o flows.json \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"

# For a specific application
./kubectl-hubble-collector -n production -o flows.json \
  --from-label "app=backend-api" \
  --cilium true

# Generate policies across multiple namespaces
./kubectl-hubble-collector -n production -n staging -o flows.json \
  --cilium true

# Skip policies already matching live cluster state
./kubectl-hubble-collector -n production -o flows.json \
  --cilium true \
  --cluster-dedup
```

### Filtering

```bash
# By source label
./kubectl-hubble-collector -n dev01 -o flows.json \
  --from-label "app.kubernetes.io/name=notifications-push"

# By destination label
./kubectl-hubble-collector -n prod -o flows.json \
  --to-label "app=postgres"

# Only dropped connections
./kubectl-hubble-collector -n prod -o dropped.json --verdict DROPPED

# Combined filters
./kubectl-hubble-collector -n dev01 -o flows.json \
  --from-label "app=api" \
  --to-label "app=database" \
  --verdict FORWARDED
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-n` | Namespace to monitor (repeatable: `-n prod -n staging`) | required (or use `-A`) |
| `-A` | Observe all namespaces | false |
| `-o` | Output JSON file | required |
| `--server` | Hubble Relay gRPC address; omit for auto port-forward | auto |
| `--duration` | Seconds to collect flows | 60 |
| `--follow` | Continuous monitoring until Ctrl+C | false |
| `--from-label` | Filter by source pod label | none |
| `--to-label` | Filter by destination pod label | none |
| `--verdict` | Filter by verdict (FORWARDED, DROPPED, ERROR, AUDIT, REDIRECTED, TRACED) | none |
| `--cilium` | Generate CiliumNetworkPolicy files (true/false) | false |
| `--cilium-output-dir` | Directory for generated policy files | ./cilium-policies |
| `--cluster-dedup` | Skip policies whose spec already matches live cluster state | false |
| `--pod-cidr` | Cluster Pod CIDR | 10.39.0.0/16 |
| `--service-cidr` | Cluster Service CIDR | 10.40.0.0/16 |
| `--debug-flows` | Save raw flows to this file for debugging | none |

## Hubble Connection

The tool connects to Hubble Relay via gRPC. Three modes, tried in order:

**1. Explicit server (`--server`)**
```bash
./kubectl-hubble-collector -n production -o flows.json --server localhost:4245
```
Uses the specified address directly. Set this if you already have a port-forward running.

**2. Auto port-forward (default)**
```bash
./kubectl-hubble-collector -n production -o flows.json
```
Automatically runs `kubectl port-forward -n kube-system svc/hubble-relay <random-port>:80`, waits for it to be ready, then connects. Cleans up on exit. No manual setup required.

**3. Hubble CLI fallback**
If auto port-forward fails (e.g. `hubble-relay` is not present), the tool falls back to running `hubble observe` as a subprocess. Requires the `hubble` CLI to be installed.

## Cluster-Dedup

`--cluster-dedup` is useful when running the tool repeatedly or from different machines where local policy files may not exist.

```bash
./kubectl-hubble-collector -n production -o flows.json \
  --cilium true \
  --cluster-dedup
```

Before writing each policy file, the tool fetches all live `CiliumNetworkPolicy` objects from the cluster. If the generated spec matches what is already deployed, the file is skipped:

```
Loading live CiliumNetworkPolicy objects from cluster...
  Loaded 12 live policies from cluster
Skipped (matches cluster): production/backend-api
Skipped (matches cluster): production/postgres
Created policy: production/new-service-cnp.yaml (egress: 3, ingress: 1)

Created/updated 1 policy files in "./cilium-policies"
```

## Critical Parameters

### Pod CIDR and Service CIDR

The `--pod-cidr` and `--service-cidr` parameters are critical for correct policy generation.

The tool must distinguish between:
- Pod IPs (internal pod IPs)
- Service IPs (ClusterIP services)
- External public IPs

Without specifying CIDRs, the tool uses default ranges:
- 10.39.0.0/16 (Pod CIDR)
- 10.40.0.0/16 (Service CIDR)
- 172.16.0.0/12 (RFC1918)
- 192.168.0.0/16 (RFC1918)
- 100.64.0.0/10 (Shared address space)

If your cluster uses different ranges, specify them explicitly:

```bash
./kubectl-hubble-collector -n production -o flows.json \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"
```

#### How to find your cluster's CIDR

```bash
# Method 1: Via kube-controller-manager
kubectl -n kube-system get pod -l component=kube-controller-manager -o yaml | grep -E "cluster-cidr|service-cluster-ip-range"

# Method 2: Via cluster-info
kubectl cluster-info dump | grep -m 1 cluster-cidr
kubectl cluster-info dump | grep -m 1 service-cluster-ip-range

# Method 3: From configmap (if available)
kubectl -n kube-system get cm kubeadm-config -o yaml | grep -E "podSubnet|serviceSubnet"
```

#### Effect of wrong CIDRs

Without correct CIDRs, pod IPs are treated as external addresses, producing unstable `toCIDR` rules instead of `toEndpoints`:

```yaml
# Wrong (without CIDR):
egress:
- toCIDR:
  - 10.39.36.20/32  # Pod IP — breaks when pod restarts
```

```yaml
# Correct (with CIDR):
egress:
- toEndpoints:
  - matchLabels:
      app: backend-api  # Stable across restarts
```

### Optimal Collection Duration

| Scenario | Duration | Reason |
|----------|----------|--------|
| Quick test | 60-300 sec | Fast iteration |
| Production policies | 300-600 sec | Good coverage without stale pods |
| Full coverage | 1800-3600 sec | All traffic patterns, risk of dead pods |

#### Dead Pod Problem

Hubble stores historical flows. If a pod was restarted during collection, its old IP appears in flows but no longer has a matching pod. The tool skips such flows with a warning and tracks them in the unhandled summary.

#### Follow Mode

```bash
./kubectl-hubble-collector -n production -o flows.json \
  --follow \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"
# Stop with Ctrl+C
```

## Example Scenarios

### 1. Bootstrap Policies from Scratch

```bash
# Step 1: Collect flows for 1 hour
./kubectl-hubble-collector -n production -o flows.json \
  --duration 3600 \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"

# Step 2: Review generated policies
ls -la ./cilium-policies/production/
cat ./cilium-policies/production/backend-api-cnp.yaml

# Step 3: Dry-run
kubectl apply -f ./cilium-policies/ --dry-run=server

# Step 4: Apply
kubectl apply -f ./cilium-policies/
```

### 2. Iterative Policy Refinement

```bash
# Collect additional flows and merge into existing policy files
./kubectl-hubble-collector -n production -o flows.json \
  --duration 1800 \
  --cilium true

# New rules are merged into existing files — ports deduplicated automatically
# Use --cluster-dedup to skip policies already applied to the cluster
./kubectl-hubble-collector -n production -o flows.json \
  --duration 1800 \
  --cilium true \
  --cluster-dedup
```

### 3. Network Policy Audit

```bash
# Collect all allowed traffic
./kubectl-hubble-collector -n production -o actual.json --duration 1800

# Find blocked connections
./kubectl-hubble-collector -n production -o blocked.json --verdict DROPPED

# Find what a specific service is being blocked from
./kubectl-hubble-collector -n prod -o api-blocked.json \
  --from-label "app=api" --verdict DROPPED
```

### 4. Multi-Namespace Policy Generation

```bash
# Generate policies for multiple namespaces in one run
./kubectl-hubble-collector -n production -n staging -o flows.json \
  --duration 600 \
  --cilium true \
  --pod-cidr "10.39.0.0/16" \
  --service-cidr "10.40.0.0/16"
```

### 5. Migration to CiliumNetworkPolicy

```bash
# Step 1: Collect flows
./kubectl-hubble-collector -n production -o flows.json \
  --duration 7200 --cilium true

# Step 2: Apply in test namespace
for policy in ./cilium-policies/production/*.yaml; do
  sed 's/namespace: production/namespace: test/' "$policy" | kubectl apply -f -
done

# Step 3: Check for dropped flows in test
./kubectl-hubble-collector -n test -o validation.json \
  --verdict DROPPED --duration 600

# Step 4: Apply in production
kubectl apply -f ./cilium-policies/
```

## Output Format

### JSON (connections graph)

```json
{
  "namespace": "production",
  "collected_at": "2024-12-31T10:30:00Z",
  "total_flows": 1234,
  "filters": {
    "from_label": "app=api",
    "to_label": "",
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

### Label Selection

For `matchLabels` in endpoint selectors, stable labels are preferred in order:

1. `app.kubernetes.io/name`
2. `app.kubernetes.io/component`
3. `app`
4. All remaining non-system labels (fallback)

System labels are always excluded: `io.cilium.*`, `io.kubernetes.pod.*`, `pod-template-hash`, `controller-revision-hash`, `commit`, etc.

### Destination Type Detection

| Connection Type | IP Address | Egress Rule | Ingress Rule |
|----------------|------------|-------------|--------------|
| Pod in same NS | 10.39.1.20 | `toEndpoints` + `matchLabels` | `fromEndpoints` + `matchLabels` |
| Pod in other NS | 10.39.2.30 | `toEndpoints` + `matchExpressions` | `fromEndpoints` + `matchExpressions` |
| External IP | 8.8.8.8 | `toCIDR` | `fromCIDR` |
| Dead/unknown pod | 10.39.36.20 | skipped | skipped |

### Merge-on-Write

When a policy file already exists, incoming rules are merged rather than overwriting:
- Rules with matching selectors have their port lists merged and deduplicated
- Non-matching rules are appended
- Metadata (name, namespace) is preserved from the existing file

### Unhandled Flow Summary

At the end of each run, a summary of skipped flows is printed:

```
Skipped flows summary:
  empty_namespace:          12
  nil_endpoint:              3
  no_l4:                     8
  world_no_ip:               5
```

| Reason | Meaning |
|--------|---------|
| `nil_endpoint` | Flow has no source or destination endpoint data |
| `no_l4` | Flow has no L4 (TCP/UDP) information |
| `empty_namespace` | Both source and destination namespace are empty |
| `world_no_ip` | External flow with no resolvable IP |
| `unknown_protocol` | Protocol not supported (e.g. ICMP) |

### Default Ports for Infrastructure

When Hubble cannot determine the port, known ports are substituted for popular components:

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

Detection is based on `app`, `app.kubernetes.io/name`, `app.kubernetes.io/component`, `k8s-app` labels.

## Applying Policies

```bash
# Validate before applying
kubectl apply -f ./cilium-policies/ --dry-run=server

# Apply
kubectl apply -f ./cilium-policies/

# Check status
kubectl get ciliumnetworkpolicies -n production
kubectl describe ciliumnetworkpolicy backend-api -n production

# Monitor dropped flows after applying
./kubectl-hubble-collector -n production -o dropped.json \
  --verdict DROPPED --follow
```

## Troubleshooting

### Auto port-forward failed

```
Auto port-forward failed (...), using hubble CLI
```

Either `hubble-relay` is not running, or `kubectl` is not configured. Check:

```bash
kubectl get pods -n kube-system | grep hubble-relay
kubectl get svc -n kube-system hubble-relay
```

If hubble-relay is running but port-forward still fails, specify the address manually:

```bash
kubectl port-forward -n kube-system svc/hubble-relay 4245:80
./kubectl-hubble-collector -n production -o flows.json --server localhost:4245
```

### Empty Output (no flows)

```bash
# Check namespace has traffic
kubectl get pods -n <namespace>

# Verify Hubble sees flows
hubble observe --namespace <namespace> --last 10

# Increase collection duration
./kubectl-hubble-collector -n prod -o flows.json --duration 300
```

### No Labels for Pod

```
Skip pod 'some-pod': no labels
```

Add labels to pods in Deployment/StatefulSet, or use `--from-label` to focus on labeled workloads.

### Policy Blocks Required Traffic

```bash
# Delete the policy
kubectl delete ciliumnetworkpolicy <name> -n <namespace>

# Re-collect with longer duration to capture all traffic patterns
./kubectl-hubble-collector -n production -o flows.json \
  --duration 7200 --cilium true
```

## Recommendations

### Collection Duration

```bash
--duration 300    # Testing: 5 minutes
--duration 1800   # Production: 30 minutes
--duration 7200   # Full coverage: 2 hours (include peak load)
```

### Workflow for Production

1. Run collection during representative traffic period
2. Review generated policies before applying
3. Apply with `--dry-run=server` first
4. Apply in a test namespace, monitor for dropped flows
5. Apply in production
6. Use `--cluster-dedup` on subsequent runs to track only what changed

## References

- [Hubble Documentation](https://docs.cilium.io/en/stable/observability/hubble/)
- [Cilium Network Policies](https://docs.cilium.io/en/stable/policy/)
- [Network Policy Best Practices](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
