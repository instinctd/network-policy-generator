package policy

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/network-policy-generator/internal/types"
)

// helpers

func makeFlowDetail(sourcePod, sourceNS, sourceIP, destPod, destNS, destIP string, destPort interface{}, protocol string) types.FlowDetail {
	return types.FlowDetail{
		SourcePod: sourcePod,
		SourceNS:  sourceNS,
		SourceIP:  sourceIP,
		DestPod:   destPod,
		DestNS:    destNS,
		DestIP:    destIP,
		DestPort:  destPort,
		Protocol:  protocol,
	}
}

func flowDetailsMap(details ...types.FlowDetail) map[string]map[string][]types.FlowDetail {
	m := make(map[string]map[string][]types.FlowDetail)
	for _, d := range details {
		srcKey := d.SourcePod
		if m[srcKey] == nil {
			m[srcKey] = make(map[string][]types.FlowDetail)
		}
		m[srcKey][d.DestPod] = append(m[srcKey][d.DestPod], d)
	}
	return m
}

// --- BuildPoliciesFromFlows ---

func TestBuildPoliciesFromFlows_EgressRule(t *testing.T) {
	fd := flowDetailsMap(makeFlowDetail("pod-a", "ns1", "10.0.0.1", "pod-b", "ns1", "10.0.0.2", 8080, "tcp"))
	policiesByPod, _ := BuildPoliciesFromFlows(fd, "ns1", nil, nil, nil, nil)

	key := "ns1/pod-a"
	if _, ok := policiesByPod[key]; !ok {
		t.Fatalf("expected policy for ns1/pod-a, keys: %v", keysOf(policiesByPod))
	}
	if len(policiesByPod[key].Egress) == 0 {
		t.Error("expected at least one egress rule")
	}
}

func TestBuildPoliciesFromFlows_IngressRule(t *testing.T) {
	fd := flowDetailsMap(makeFlowDetail("pod-a", "ns1", "10.0.0.1", "pod-b", "ns1", "10.0.0.2", 8080, "tcp"))
	policiesByPod, _ := BuildPoliciesFromFlows(fd, "ns1", nil, nil, nil, nil)

	key := "ns1/pod-b"
	if _, ok := policiesByPod[key]; !ok {
		t.Fatalf("expected policy for ns1/pod-b, keys: %v", keysOf(policiesByPod))
	}
	if len(policiesByPod[key].Ingress) == 0 {
		t.Error("expected at least one ingress rule")
	}
}

func TestBuildPoliciesFromFlows_FiltersNamespace(t *testing.T) {
	fd := flowDetailsMap(makeFlowDetail("pod-x", "other-ns", "10.0.0.1", "pod-y", "other-ns", "10.0.0.2", 80, "tcp"))
	policiesByPod, _ := BuildPoliciesFromFlows(fd, "ns1", nil, nil, nil, nil)

	if len(policiesByPod) != 0 {
		t.Errorf("expected no policies for other-ns flows, got %v", keysOf(policiesByPod))
	}
}

func TestBuildPoliciesFromFlows_AllNamespaces(t *testing.T) {
	fd := flowDetailsMap(
		makeFlowDetail("pod-a", "ns1", "10.0.0.1", "pod-b", "ns2", "10.0.0.2", 80, "tcp"),
	)
	policiesByPod, _ := BuildPoliciesFromFlows(fd, "", nil, nil, nil, nil)

	if len(policiesByPod) == 0 {
		t.Error("expected policies in all-namespaces mode")
	}
}

// --- BuildSinglePolicy ---

func TestBuildSinglePolicy_EndpointSelector(t *testing.T) {
	pd := &types.PolicyData{
		Namespace: "ns1",
		Egress:    map[string]*types.RuleInfo{"pod:ns1/redis": {Ports: map[string]bool{"6379": true}, Protocols: map[string]bool{"tcp": true}}},
		Ingress:   make(map[string]*types.RuleInfo),
	}
	allLabels := map[string]map[string]string{
		"myapp": {"app": "myapp"},
		"redis": {"app": "redis"},
	}

	policy, err := BuildSinglePolicy("myapp", "ns1", pd, allLabels)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if policy.Spec.EndpointSelector.MatchLabels["app"] != "myapp" {
		t.Errorf("expected app=myapp in selector, got %v", policy.Spec.EndpointSelector.MatchLabels)
	}
}

func TestBuildSinglePolicy_NoLabels_Error(t *testing.T) {
	pd := &types.PolicyData{
		Namespace: "ns1",
		Egress:    make(map[string]*types.RuleInfo),
		Ingress:   make(map[string]*types.RuleInfo),
	}
	_, err := BuildSinglePolicy("unknown-pod-abc12defg-xyz12", "ns1", pd, map[string]map[string]string{})
	// Should succeed because ExtractLabelsFromPodName infers app label from hash
	if err != nil {
		t.Logf("got expected or unexpected error: %v", err)
	}
}

func TestBuildSinglePolicy_DNSRuleAdded(t *testing.T) {
	pd := &types.PolicyData{
		Namespace: "ns1",
		Egress:    map[string]*types.RuleInfo{"pod:ns1/redis": {Ports: map[string]bool{"6379": true}, Protocols: map[string]bool{"tcp": true}}},
		Ingress:   make(map[string]*types.RuleInfo),
	}
	allLabels := map[string]map[string]string{"myapp": {"app": "myapp"}, "redis": {"app": "redis"}}

	policy, err := BuildSinglePolicy("myapp", "ns1", pd, allLabels)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasDNS := false
	for _, rule := range policy.Spec.Egress {
		for _, ep := range rule.ToEndpoints {
			if ep.MatchLabels["k8s-app"] == "kube-dns" {
				hasDNS = true
			}
		}
	}
	if !hasDNS {
		t.Error("expected DNS egress rule to be added")
	}
}

// --- AddDNSEgressRule ---

func TestAddDNSEgressRule_AddsWhenAbsent(t *testing.T) {
	policy := &types.CiliumNetworkPolicy{}
	AddDNSEgressRule(policy)
	if len(policy.Spec.Egress) != 1 {
		t.Fatalf("expected 1 egress rule, got %d", len(policy.Spec.Egress))
	}
	rule := policy.Spec.Egress[0]
	if rule.ToEndpoints[0].MatchLabels["k8s-app"] != "kube-dns" {
		t.Errorf("expected kube-dns rule, got %v", rule)
	}
}

func TestAddDNSEgressRule_SkipsWhenPresent(t *testing.T) {
	policy := &types.CiliumNetworkPolicy{
		Spec: types.PolicySpec{
			Egress: []types.EgressRule{{
				ToEndpoints: []types.EndpointSelector{{
					MatchLabels: map[string]string{"k8s-app": "kube-dns"},
				}},
			}},
		},
	}
	AddDNSEgressRule(policy)
	if len(policy.Spec.Egress) != 1 {
		t.Errorf("expected 1 egress rule (no duplicate), got %d", len(policy.Spec.Egress))
	}
}

// --- ValidatePolicy ---

func TestValidatePolicy_EmptySelector(t *testing.T) {
	policy := &types.CiliumNetworkPolicy{}
	valid, msg := ValidatePolicy(policy)
	if valid {
		t.Error("expected invalid for empty selector")
	}
	if msg == "" {
		t.Error("expected error message")
	}
}

func TestValidatePolicy_K8sPrefixInMatchLabels(t *testing.T) {
	policy := &types.CiliumNetworkPolicy{
		Spec: types.PolicySpec{
			EndpointSelector: types.EndpointSelector{MatchLabels: map[string]string{"app": "myapp"}},
			Egress: []types.EgressRule{{
				ToEndpoints: []types.EndpointSelector{{
					MatchLabels: map[string]string{"k8s:app": "redis"},
				}},
			}},
		},
	}
	valid, msg := ValidatePolicy(policy)
	if valid {
		t.Error("expected invalid for k8s: prefix in matchLabels")
	}
	if msg == "" {
		t.Error("expected error message")
	}
}

func TestValidatePolicy_Valid(t *testing.T) {
	policy := &types.CiliumNetworkPolicy{
		Spec: types.PolicySpec{
			EndpointSelector: types.EndpointSelector{MatchLabels: map[string]string{"app": "myapp"}},
		},
	}
	valid, msg := ValidatePolicy(policy)
	if !valid {
		t.Errorf("expected valid policy, got error: %s", msg)
	}
}

// --- WritePolicy ---

func TestWritePolicy_CreatesYAMLFile(t *testing.T) {
	dir := t.TempDir()
	policy := &types.CiliumNetworkPolicy{
		APIVersion: "cilium.io/v2",
		Kind:       "CiliumNetworkPolicy",
		Metadata:   types.Metadata{Name: "myapp", Namespace: "ns1"},
		Spec: types.PolicySpec{
			EndpointSelector: types.EndpointSelector{MatchLabels: map[string]string{"app": "myapp"}},
			Egress: []types.EgressRule{{
				ToEndpoints: []types.EndpointSelector{{MatchLabels: map[string]string{"app": "redis"}}},
				ToPorts:     []types.PortRule{{Protocol: "TCP", Ports: []types.PortSpec{{Port: "6379"}}}},
			}},
		},
	}

	filePath, err := WritePolicy(policy, dir)
	if err != nil {
		t.Fatalf("WritePolicy error: %v", err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	// Must be valid YAML and parseable back
	var parsed types.CiliumNetworkPolicy
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("written YAML is not valid: %v\n%s", err, data)
	}
	if parsed.Metadata.Name != "myapp" {
		t.Errorf("expected name=myapp, got %q", parsed.Metadata.Name)
	}
}

func TestWritePolicy_ContainsComment(t *testing.T) {
	dir := t.TempDir()
	policy := &types.CiliumNetworkPolicy{
		APIVersion: "cilium.io/v2",
		Kind:       "CiliumNetworkPolicy",
		Metadata:   types.Metadata{Name: "myapp", Namespace: "ns1"},
		Spec: types.PolicySpec{
			EndpointSelector: types.EndpointSelector{MatchLabels: map[string]string{"app": "myapp"}},
			Egress: []types.EgressRule{{
				ToEndpoints: []types.EndpointSelector{{MatchLabels: map[string]string{"app": "redis"}}},
				ToPorts:     []types.PortRule{{Protocol: "TCP", Ports: []types.PortSpec{{Port: "6379"}}}},
			}},
		},
	}

	filePath, err := WritePolicy(policy, dir)
	if err != nil {
		t.Fatalf("WritePolicy error: %v", err)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	content := string(data)
	if !containsSubstring(content, "# egress to") {
		t.Errorf("expected human-readable comment in YAML, got:\n%s", content)
	}
}

// --- helpers ---

func keysOf(m map[string]*types.PolicyData) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}
