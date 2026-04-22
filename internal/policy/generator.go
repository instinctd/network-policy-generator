package policy

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/network-policy-generator/internal/labels"
	"github.com/network-policy-generator/internal/network"
	"github.com/network-policy-generator/internal/ports"
	"github.com/network-policy-generator/internal/types"
)

// BuildPoliciesFromFlows processes all collected FlowDetails and produces a map
// of podKey → PolicyData. podKey is "namespace/podName".
// Also returns the set of internal IPs that could not be resolved.
func BuildPoliciesFromFlows(
	flowDetails map[string]map[string][]types.FlowDetail,
	namespace string, // empty = all namespaces
	ipToPod map[string]types.PodInfo,
	ipToNamespace map[string]string,
	ipToService map[string]types.ServiceInfo,
	internalNetworks []*net.IPNet,
) (map[string]*types.PolicyData, map[string]bool) {
	policiesByPod := make(map[string]*types.PolicyData)
	unresolvedIPs := make(map[string]bool)

	for _, destinations := range flowDetails {
		for _, flowList := range destinations {
			for _, fl := range flowList {
				processEgress(fl, namespace, ipToPod, ipToNamespace, ipToService, internalNetworks, policiesByPod, unresolvedIPs)
				processIngress(fl, namespace, ipToPod, ipToNamespace, ipToService, internalNetworks, policiesByPod, unresolvedIPs)
			}
		}
	}
	return policiesByPod, unresolvedIPs
}

func processEgress(
	fl types.FlowDetail,
	namespace string,
	ipToPod map[string]types.PodInfo,
	ipToNamespace map[string]string,
	ipToService map[string]types.ServiceInfo,
	internalNetworks []*net.IPNet,
	policiesByPod map[string]*types.PolicyData,
	unresolvedIPs map[string]bool,
) {
	sourcePod := fl.SourcePod
	sourceNS := fl.SourceNS
	if sourcePod == "" || sourceNS == "" {
		return
	}
	if namespace != "" && sourceNS != namespace {
		return
	}

	podKey := sourceNS + "/" + sourcePod
	if policiesByPod[podKey] == nil {
		policiesByPod[podKey] = &types.PolicyData{
			Namespace: sourceNS,
			Egress:    make(map[string]*types.RuleInfo),
			Ingress:   make(map[string]*types.RuleInfo),
		}
	}

	destKey := resolveDestKey(fl.DestPod, fl.DestNS, fl.DestIP, ipToPod, ipToNamespace, ipToService, internalNetworks, unresolvedIPs, "egress", fl.DestPort)
	if destKey == "" {
		return
	}

	ri := getOrCreateRuleInfo(policiesByPod[podKey].Egress, destKey)
	addPortProto(ri, fl.DestPort, fl.Protocol)
}

func processIngress(
	fl types.FlowDetail,
	namespace string,
	ipToPod map[string]types.PodInfo,
	ipToNamespace map[string]string,
	ipToService map[string]types.ServiceInfo,
	internalNetworks []*net.IPNet,
	policiesByPod map[string]*types.PolicyData,
	unresolvedIPs map[string]bool,
) {
	destPod := fl.DestPod
	destNS := fl.DestNS
	if destPod == "" || destNS == "" {
		return
	}
	if namespace != "" && destNS != namespace {
		return
	}

	podKey := destNS + "/" + destPod
	if policiesByPod[podKey] == nil {
		policiesByPod[podKey] = &types.PolicyData{
			Namespace: destNS,
			Egress:    make(map[string]*types.RuleInfo),
			Ingress:   make(map[string]*types.RuleInfo),
		}
	}

	sourceKey := resolveSourceKey(fl.SourcePod, fl.SourceNS, fl.SourceIP, ipToPod, ipToNamespace, ipToService, internalNetworks, unresolvedIPs)
	if sourceKey == "" {
		return
	}

	ri := getOrCreateRuleInfo(policiesByPod[podKey].Ingress, sourceKey)
	addPortProto(ri, fl.DestPort, fl.Protocol)
}

// resolveDestKey maps a flow destination to a policy key ("pod:ns/name", "ns:ns", "external:IP").
func resolveDestKey(
	destPod, destNS, destIP string,
	ipToPod map[string]types.PodInfo,
	ipToNamespace map[string]string,
	ipToService map[string]types.ServiceInfo,
	internalNetworks []*net.IPNet,
	unresolvedIPs map[string]bool,
	dir string, destPort interface{},
) string {
	if destPod != "" && destNS != "" {
		return fmt.Sprintf("pod:%s/%s", destNS, destPod)
	}
	if destNS != "" {
		return fmt.Sprintf("ns:%s", destNS)
	}
	if destIP == "" || destIP == "unknown" {
		return ""
	}
	if svcInfo, ok := ipToService[destIP]; ok {
		return fmt.Sprintf("ns:%s", svcInfo.Namespace)
	}
	if podInfo, ok := ipToPod[destIP]; ok {
		return fmt.Sprintf("pod:%s/%s", podInfo.Namespace, podInfo.Name)
	}
	if network.IsExternalIP(destIP, ipToPod, ipToNamespace, internalNetworks) {
		return fmt.Sprintf("external:%s", destIP)
	}
	if ns, ok := ipToNamespace[destIP]; ok {
		return fmt.Sprintf("ns:%s", ns)
	}
	// Internal but unresolvable
	if isInternalIP(destIP, internalNetworks) {
		fmt.Printf("  Warning: skipping internal %s IP %s:%v - cannot resolve to pod/namespace\n", dir, destIP, destPort)
		unresolvedIPs[destIP] = true
		return ""
	}
	return fmt.Sprintf("external:%s", destIP)
}

func resolveSourceKey(
	sourcePod, sourceNS, sourceIP string,
	ipToPod map[string]types.PodInfo,
	ipToNamespace map[string]string,
	ipToService map[string]types.ServiceInfo,
	internalNetworks []*net.IPNet,
	unresolvedIPs map[string]bool,
) string {
	if sourcePod != "" && sourceNS != "" {
		return fmt.Sprintf("pod:%s/%s", sourceNS, sourcePod)
	}
	if sourceNS != "" {
		return fmt.Sprintf("ns:%s", sourceNS)
	}
	if sourceIP == "" || sourceIP == "unknown" {
		return ""
	}
	if svcInfo, ok := ipToService[sourceIP]; ok {
		return fmt.Sprintf("ns:%s", svcInfo.Namespace)
	}
	if podInfo, ok := ipToPod[sourceIP]; ok {
		return fmt.Sprintf("pod:%s/%s", podInfo.Namespace, podInfo.Name)
	}
	if network.IsExternalIP(sourceIP, ipToPod, ipToNamespace, internalNetworks) {
		return fmt.Sprintf("external:%s", sourceIP)
	}
	if ns, ok := ipToNamespace[sourceIP]; ok {
		return fmt.Sprintf("ns:%s", ns)
	}
	if isInternalIP(sourceIP, internalNetworks) {
		fmt.Printf("  Warning: skipping internal source IP %s - cannot resolve to pod/namespace\n", sourceIP)
		unresolvedIPs[sourceIP] = true
		return ""
	}
	return fmt.Sprintf("external:%s", sourceIP)
}

func isInternalIP(ip string, internalNetworks []*net.IPNet) bool {
	ipObj := net.ParseIP(ip)
	if ipObj == nil {
		return false
	}
	for _, n := range internalNetworks {
		if n.Contains(ipObj) {
			return true
		}
	}
	return false
}

func getOrCreateRuleInfo(m map[string]*types.RuleInfo, key string) *types.RuleInfo {
	if m[key] == nil {
		m[key] = &types.RuleInfo{
			Ports:     make(map[string]bool),
			Protocols: make(map[string]bool),
		}
	}
	return m[key]
}

func addPortProto(ri *types.RuleInfo, destPort interface{}, protocol string) {
	if destPort != nil {
		ri.Ports[fmt.Sprintf("%v", destPort)] = true
	}
	if protocol != "" {
		ri.Protocols[protocol] = true
	}
}

// BuildSinglePolicy constructs a CiliumNetworkPolicy for one pod.
func BuildSinglePolicy(
	podName string,
	podNS string,
	policyData *types.PolicyData,
	allPodLabels map[string]map[string]string,
) (*types.CiliumNetworkPolicy, error) {
	podLabels := allPodLabels[podName]
	if len(podLabels) == 0 {
		podLabels = network.ExtractLabelsFromPodName(podName)
	}
	if len(podLabels) == 0 {
		return nil, fmt.Errorf("no labels for pod %q", podName)
	}

	// Remove invalid label prefixes.
	validLabels := filterValidLabels(podLabels)
	if len(validLabels) == 0 {
		return nil, fmt.Errorf("all labels are system labels for pod %q", podName)
	}

	// Prefer stable well-known labels (app.kubernetes.io/name, etc.) for the
	// endpoint selector matchLabels.
	selectorLabels := labels.SelectLabels(validLabels)

	policy := &types.CiliumNetworkPolicy{
		APIVersion: "cilium.io/v2",
		Kind:       "CiliumNetworkPolicy",
		Metadata: types.Metadata{
			Name:      network.SanitizeName(podName),
			Namespace: podNS,
		},
		Spec: types.PolicySpec{
			EndpointSelector: types.EndpointSelector{MatchLabels: selectorLabels},
		},
	}

	// Egress rules
	for destKey, destInfo := range policyData.Egress {
		rule, destPodLabels := buildEgressRule(destKey, destInfo, allPodLabels)
		if rule == nil {
			continue
		}
		// Fill in default port if missing
		if (len(destInfo.Ports) == 0 || len(destInfo.Protocols) == 0) && destPodLabels != nil {
			if dp := ports.GetDefaultPort(destPodLabels); dp != nil {
				destInfo.Ports[dp.Port] = true
				destInfo.Protocols[dp.Protocol] = true
				fmt.Printf("  Using default port %s/%s for %s\n", dp.Port, dp.Protocol, destKey)
			}
		}
		applyPortsToEgressRule(rule, destInfo)
		if shouldAddEgressRule(rule) {
			policy.Spec.Egress = append(policy.Spec.Egress, *rule)
		}
	}

	// Ingress rules
	for sourceKey, sourceInfo := range policyData.Ingress {
		rule, sourcePodLabels := buildIngressRule(sourceKey, sourceInfo, allPodLabels)
		if rule == nil {
			continue
		}
		if (len(sourceInfo.Ports) == 0 || len(sourceInfo.Protocols) == 0) && sourcePodLabels != nil {
			if dp := ports.GetDefaultPort(sourcePodLabels); dp != nil {
				sourceInfo.Ports[dp.Port] = true
				sourceInfo.Protocols[dp.Protocol] = true
				fmt.Printf("  Using default port %s/%s for ingress from %s\n", dp.Port, dp.Protocol, sourceKey)
			}
		}
		applyPortsToIngressRule(rule, sourceInfo)
		if shouldAddIngressRule(rule) {
			policy.Spec.Ingress = append(policy.Spec.Ingress, *rule)
		}
	}

	AddDNSEgressRule(policy)
	return policy, nil
}

func buildEgressRule(
	destKey string,
	destInfo *types.RuleInfo,
	allPodLabels map[string]map[string]string,
) (*types.EgressRule, map[string]string) {
	parts := strings.SplitN(destKey, ":", 2)
	if len(parts) != 2 {
		return nil, nil
	}
	destType, destValue := parts[0], parts[1]

	rule := &types.EgressRule{}
	var destPodLabels map[string]string

	switch destType {
	case "pod":
		nsParts := strings.SplitN(destValue, "/", 2)
		if len(nsParts) != 2 {
			return nil, nil
		}
		destNS, destPod := nsParts[0], nsParts[1]
		destPodLabels = allPodLabels[destPod]
		if len(destPodLabels) > 0 {
			validDestLabels := filterValidLabels(destPodLabels)
			if len(validDestLabels) > 0 {
				rule.ToEndpoints = []types.EndpointSelector{{MatchLabels: labels.SelectLabels(validDestLabels)}}
			} else {
				rule.ToEndpoints = []types.EndpointSelector{{
					MatchExpressions: []types.MatchExpression{{
						Key:      "io.kubernetes.pod.namespace",
						Operator: "In",
						Values:   []string{destNS},
					}},
				}}
			}
		} else {
			rule.ToEndpoints = []types.EndpointSelector{{
				MatchExpressions: []types.MatchExpression{{
					Key:      "io.kubernetes.pod.namespace",
					Operator: "In",
					Values:   []string{destNS},
				}},
			}}
		}
	case "ns":
		rule.ToEndpoints = []types.EndpointSelector{{
			MatchExpressions: []types.MatchExpression{{
				Key:      "io.kubernetes.pod.namespace",
				Operator: "In",
				Values:   []string{destValue},
			}},
		}}
	case "external":
		rule.ToCIDR = []string{fmt.Sprintf("%s/32", destValue)}
	default:
		return nil, nil
	}
	return rule, destPodLabels
}

func buildIngressRule(
	sourceKey string,
	sourceInfo *types.RuleInfo,
	allPodLabels map[string]map[string]string,
) (*types.IngressRule, map[string]string) {
	parts := strings.SplitN(sourceKey, ":", 2)
	if len(parts) != 2 {
		return nil, nil
	}
	sourceType, sourceValue := parts[0], parts[1]

	rule := &types.IngressRule{}
	var sourcePodLabels map[string]string

	switch sourceType {
	case "pod":
		nsParts := strings.SplitN(sourceValue, "/", 2)
		if len(nsParts) != 2 {
			return nil, nil
		}
		sourceNS, sourcePod := nsParts[0], nsParts[1]
		sourcePodLabels = allPodLabels[sourcePod]
		if len(sourcePodLabels) > 0 {
			validSourceLabels := filterValidLabels(sourcePodLabels)
			if len(validSourceLabels) > 0 {
				rule.FromEndpoints = []types.EndpointSelector{{MatchLabels: labels.SelectLabels(validSourceLabels)}}
			} else {
				rule.FromEndpoints = []types.EndpointSelector{{
					MatchExpressions: []types.MatchExpression{{
						Key:      "io.kubernetes.pod.namespace",
						Operator: "In",
						Values:   []string{sourceNS},
					}},
				}}
			}
		} else {
			rule.FromEndpoints = []types.EndpointSelector{{
				MatchExpressions: []types.MatchExpression{{
					Key:      "io.kubernetes.pod.namespace",
					Operator: "In",
					Values:   []string{sourceNS},
				}},
			}}
		}
	case "ns":
		rule.FromEndpoints = []types.EndpointSelector{{
			MatchExpressions: []types.MatchExpression{{
				Key:      "io.kubernetes.pod.namespace",
				Operator: "In",
				Values:   []string{sourceValue},
			}},
		}}
	case "external":
		rule.FromCIDR = []string{fmt.Sprintf("%s/32", sourceValue)}
	default:
		return nil, nil
	}
	return rule, sourcePodLabels
}

func applyPortsToEgressRule(rule *types.EgressRule, info *types.RuleInfo) {
	if len(info.Ports) == 0 || len(info.Protocols) == 0 {
		return
	}
	ports := sortedKeys(info.Ports)
	for proto := range info.Protocols {
		pr := types.PortRule{Protocol: strings.ToUpper(proto)}
		for _, port := range ports {
			pr.Ports = append(pr.Ports, types.PortSpec{Port: port})
		}
		rule.ToPorts = append(rule.ToPorts, pr)
	}
}

func applyPortsToIngressRule(rule *types.IngressRule, info *types.RuleInfo) {
	if len(info.Ports) == 0 || len(info.Protocols) == 0 {
		return
	}
	sortedPorts := sortedKeys(info.Ports)
	for proto := range info.Protocols {
		pr := types.PortRule{Protocol: strings.ToUpper(proto)}
		for _, port := range sortedPorts {
			pr.Ports = append(pr.Ports, types.PortSpec{Port: port})
		}
		rule.ToPorts = append(rule.ToPorts, pr)
	}
}

func shouldAddEgressRule(rule *types.EgressRule) bool {
	hasEndpoints := len(rule.ToEndpoints) > 0
	hasCIDR := len(rule.ToCIDR) > 0
	hasPorts := len(rule.ToPorts) > 0
	return (hasEndpoints && hasPorts) || hasCIDR
}

func shouldAddIngressRule(rule *types.IngressRule) bool {
	hasEndpoints := len(rule.FromEndpoints) > 0
	hasCIDR := len(rule.FromCIDR) > 0
	hasPorts := len(rule.ToPorts) > 0
	return (hasEndpoints && hasPorts) || hasCIDR
}

// AddDNSEgressRule appends a DNS egress rule unless one already exists.
func AddDNSEgressRule(policy *types.CiliumNetworkPolicy) {
	for _, rule := range policy.Spec.Egress {
		for _, ep := range rule.ToEndpoints {
			if ep.MatchLabels != nil {
				if app := ep.MatchLabels["k8s-app"]; app == "kube-dns" || app == "coredns" {
					return
				}
			}
		}
	}
	policy.Spec.Egress = append(policy.Spec.Egress, types.EgressRule{
		ToEndpoints: []types.EndpointSelector{{
			MatchLabels: map[string]string{
				"io.kubernetes.pod.namespace": "kube-system",
				"k8s-app":                    "kube-dns",
			},
		}},
		ToPorts: []types.PortRule{{
			Protocol: "UDP",
			Ports:    []types.PortSpec{{Port: "53"}},
		}},
	})
}

// ValidatePolicy checks that the policy has valid selectors and no raw k8s: prefixes.
func ValidatePolicy(policy *types.CiliumNetworkPolicy) (bool, string) {
	sel := policy.Spec.EndpointSelector
	if sel.MatchLabels == nil && sel.MatchExpressions == nil {
		return false, "endpointSelector must have matchLabels or matchExpressions"
	}
	for idx, rule := range policy.Spec.Egress {
		for _, ep := range rule.ToEndpoints {
			if ep.MatchLabels == nil && ep.MatchExpressions == nil {
				return false, fmt.Sprintf("egress rule #%d: endpoint needs matchLabels or matchExpressions", idx)
			}
			for key := range ep.MatchLabels {
				if strings.HasPrefix(key, "k8s:") {
					return false, fmt.Sprintf("egress rule #%d: invalid label key %q with 'k8s:' prefix", idx, key)
				}
			}
		}
	}
	for idx, rule := range policy.Spec.Ingress {
		for _, ep := range rule.FromEndpoints {
			if ep.MatchLabels == nil && ep.MatchExpressions == nil {
				return false, fmt.Sprintf("ingress rule #%d: endpoint needs matchLabels or matchExpressions", idx)
			}
			for key := range ep.MatchLabels {
				if strings.HasPrefix(key, "k8s:") {
					return false, fmt.Sprintf("ingress rule #%d: invalid label key %q with 'k8s:' prefix", idx, key)
				}
			}
		}
	}
	return true, ""
}

// WritePolicy writes a CiliumNetworkPolicy to a YAML file with human-readable comments.
// The file is placed in outputDir/<namespace>/<sanitizedName>-cnp.yaml.
// If the file already exists on disk, the existing policy is loaded and merged
// with the incoming policy (rules with matching selectors are combined and
// their ports de-duplicated) before writing.
func WritePolicy(policy *types.CiliumNetworkPolicy, baseOutputDir string) (string, error) {
	outDir := filepath.Join(baseOutputDir, policy.Metadata.Namespace)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}

	filename := policy.Metadata.Name + "-cnp.yaml"
	filePath := filepath.Join(outDir, filename)

	// If a policy file already exists, load it and merge the incoming rules
	// into it instead of overwriting.
	policyToWrite := policy
	if _, err := os.Stat(filePath); err == nil {
		existingBytes, readErr := os.ReadFile(filePath)
		if readErr != nil {
			return "", fmt.Errorf("read existing policy %s: %w", filePath, readErr)
		}
		var existing types.CiliumNetworkPolicy
		if unmarshalErr := yaml.Unmarshal(existingBytes, &existing); unmarshalErr != nil {
			return "", fmt.Errorf("unmarshal existing policy %s: %w", filePath, unmarshalErr)
		}
		policyToWrite = mergePolicies(&existing, policy)
	}

	// Marshal to YAML with 2-space indent.
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(policyToWrite); err != nil {
		return "", fmt.Errorf("encode policy: %w", err)
	}
	enc.Close()

	// Post-process: insert human-readable comment lines before each rule.
	annotated := insertRuleComments(buf.Bytes(), policyToWrite)

	if err := os.WriteFile(filePath, annotated, 0644); err != nil {
		return "", err
	}
	return filePath, nil
}

// mergePolicies combines the rules of an incoming CiliumNetworkPolicy into an
// existing one. Metadata (name, namespace) is preserved from the existing
// policy; the EndpointSelector is overwritten with the incoming selector.
//
// For both egress and ingress rules, rules are matched by their selector part
// (everything except ToPorts) using reflect.DeepEqual. When a matching rule is
// found, port lists are merged and de-duplicated by "port/protocol". Non-
// matching incoming rules are appended.
func mergePolicies(existing, incoming *types.CiliumNetworkPolicy) *types.CiliumNetworkPolicy {
	merged := *existing
	merged.Spec.EndpointSelector = incoming.Spec.EndpointSelector

	// Merge egress rules.
	for _, inRule := range incoming.Spec.Egress {
		matched := false
		for i := range merged.Spec.Egress {
			if egressSelectorEqual(merged.Spec.Egress[i], inRule) {
				merged.Spec.Egress[i].ToPorts = mergePortRules(merged.Spec.Egress[i].ToPorts, inRule.ToPorts)
				matched = true
				break
			}
		}
		if !matched {
			merged.Spec.Egress = append(merged.Spec.Egress, inRule)
		}
	}

	// Merge ingress rules.
	for _, inRule := range incoming.Spec.Ingress {
		matched := false
		for i := range merged.Spec.Ingress {
			if ingressSelectorEqual(merged.Spec.Ingress[i], inRule) {
				merged.Spec.Ingress[i].ToPorts = mergePortRules(merged.Spec.Ingress[i].ToPorts, inRule.ToPorts)
				matched = true
				break
			}
		}
		if !matched {
			merged.Spec.Ingress = append(merged.Spec.Ingress, inRule)
		}
	}

	return &merged
}

// egressSelectorEqual returns true when two egress rules target the same set
// of endpoints/CIDRs (ToPorts are intentionally ignored).
func egressSelectorEqual(a, b types.EgressRule) bool {
	return reflect.DeepEqual(a.ToEndpoints, b.ToEndpoints) &&
		reflect.DeepEqual(a.ToCIDR, b.ToCIDR)
}

// ingressSelectorEqual returns true when two ingress rules source from the
// same set of endpoints/CIDRs (ToPorts are intentionally ignored).
func ingressSelectorEqual(a, b types.IngressRule) bool {
	return reflect.DeepEqual(a.FromEndpoints, b.FromEndpoints) &&
		reflect.DeepEqual(a.FromCIDR, b.FromCIDR)
}

// mergePortRules combines two lists of PortRule, de-duplicating ports by
// "port/protocol". The returned list preserves the order of existing entries
// and either appends new ports to the appropriate protocol group or creates a
// new group when the protocol was not previously present.
func mergePortRules(existing, incoming []types.PortRule) []types.PortRule {
	if len(incoming) == 0 {
		return existing
	}

	// Track all known port/protocol combinations.
	seen := make(map[string]bool)
	for _, pr := range existing {
		for _, p := range pr.Ports {
			seen[fmt.Sprintf("%s/%s", p.Port, pr.Protocol)] = true
		}
	}

	// Index existing rules by protocol so we can append to them in place.
	protoIdx := make(map[string]int)
	for i, pr := range existing {
		protoIdx[pr.Protocol] = i
	}

	result := existing
	for _, inPR := range incoming {
		idx, ok := protoIdx[inPR.Protocol]
		if !ok {
			newPR := types.PortRule{Protocol: inPR.Protocol}
			for _, p := range inPR.Ports {
				key := fmt.Sprintf("%s/%s", p.Port, inPR.Protocol)
				if seen[key] {
					continue
				}
				seen[key] = true
				newPR.Ports = append(newPR.Ports, p)
			}
			if len(newPR.Ports) > 0 {
				protoIdx[inPR.Protocol] = len(result)
				result = append(result, newPR)
			}
			continue
		}
		for _, p := range inPR.Ports {
			key := fmt.Sprintf("%s/%s", p.Port, inPR.Protocol)
			if seen[key] {
				continue
			}
			seen[key] = true
			result[idx].Ports = append(result[idx].Ports, p)
		}
	}
	return result
}

// insertRuleComments adds a comment line before each egress/ingress rule item
// in the rendered YAML output (2-space indent, so rules are at 4-space level).
func insertRuleComments(data []byte, policy *types.CiliumNetworkPolicy) []byte {
	lines := strings.Split(string(data), "\n")
	result := make([]string, 0, len(lines)+len(policy.Spec.Egress)+len(policy.Spec.Ingress))

	inEgress := false
	inIngress := false
	egressIdx := 0
	ingressIdx := 0

	for _, line := range lines {
		// Detect section transitions at the 2-space level (spec children).
		switch {
		case line == "  egress:":
			inEgress = true
			inIngress = false
		case line == "  ingress:":
			inIngress = true
			inEgress = false
		case len(line) >= 3 && line[0] == ' ' && line[1] == ' ' && line[2] != ' ':
			// Another 2-space-indented spec key — leave both sections.
			inEgress = false
			inIngress = false
		case len(line) > 0 && line[0] != ' ':
			// Top-level key — leave both sections.
			inEgress = false
			inIngress = false
		}

		// Detect rule-level sequence items: exactly 4 spaces + "- ".
		// These are the direct children of egress/ingress (not nested sub-items).
		if len(line) >= 6 && line[:4] == "    " && line[4] == '-' && line[5] == ' ' {
			if inEgress && egressIdx < len(policy.Spec.Egress) {
				result = append(result, "    # "+describeEgressRule(policy.Spec.Egress[egressIdx]))
				egressIdx++
			} else if inIngress && ingressIdx < len(policy.Spec.Ingress) {
				result = append(result, "    # "+describeIngressRule(policy.Spec.Ingress[ingressIdx]))
				ingressIdx++
			}
		}

		result = append(result, line)
	}

	return []byte(strings.Join(result, "\n"))
}

func describeEgressRule(rule types.EgressRule) string {
	var dest string
	if len(rule.ToCIDR) > 0 {
		dest = "external " + strings.Join(rule.ToCIDR, ", ")
	} else if len(rule.ToEndpoints) > 0 {
		dest = describeEndpoint(rule.ToEndpoints[0])
	}
	portStr := describePortRules(rule.ToPorts)
	if portStr != "" {
		return fmt.Sprintf("egress to %s → %s", dest, portStr)
	}
	return fmt.Sprintf("egress to %s", dest)
}

func describeIngressRule(rule types.IngressRule) string {
	var src string
	if len(rule.FromCIDR) > 0 {
		src = "external " + strings.Join(rule.FromCIDR, ", ")
	} else if len(rule.FromEndpoints) > 0 {
		src = describeEndpoint(rule.FromEndpoints[0])
	}
	portStr := describePortRules(rule.ToPorts)
	if portStr != "" {
		return fmt.Sprintf("ingress from %s → %s", src, portStr)
	}
	return fmt.Sprintf("ingress from %s", src)
}

func describeEndpoint(ep types.EndpointSelector) string {
	if ep.MatchLabels != nil {
		if ep.MatchLabels["k8s-app"] == "kube-dns" {
			return "kube-dns (DNS)"
		}
		if app, ok := ep.MatchLabels["app"]; ok {
			ns := ep.MatchLabels["io.kubernetes.pod.namespace"]
			if ns != "" {
				return app + " in " + ns
			}
			return app
		}
		// Generic label set
		lbls := make([]string, 0, len(ep.MatchLabels))
		for k, v := range ep.MatchLabels {
			lbls = append(lbls, k+"="+v)
		}
		sort.Strings(lbls)
		return "{" + strings.Join(lbls, ", ") + "}"
	}
	for _, expr := range ep.MatchExpressions {
		if expr.Key == "io.kubernetes.pod.namespace" {
			return "namespace " + strings.Join(expr.Values, ", ")
		}
	}
	return "unknown"
}

func describePortRules(rules []types.PortRule) string {
	var parts []string
	for _, pr := range rules {
		for _, p := range pr.Ports {
			parts = append(parts, p.Port+"/"+pr.Protocol)
		}
	}
	return strings.Join(parts, ", ")
}

// ExportPolicies generates and writes CiliumNetworkPolicy YAML files for all
// pods in policiesByPod using a worker pool.
func ExportPolicies(
	allPodLabels map[string]map[string]string,
	policiesByPod map[string]*types.PolicyData,
	baseOutputDir string,
) ([]string, error) {
	if err := os.MkdirAll(baseOutputDir, 0755); err != nil {
		return nil, err
	}

	type job struct {
		podKey     string
		policyData *types.PolicyData
	}

	jobs := make(chan job, len(policiesByPod))
	for podKey, pd := range policiesByPod {
		jobs <- job{podKey, pd}
	}
	close(jobs)

	var (
		policyFiles   []string
		policyFilesMu sync.Mutex
		wg            sync.WaitGroup
	)

	const numWorkers = 10
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				parts := strings.SplitN(j.podKey, "/", 2)
				if len(parts) != 2 {
					continue
				}
				podNS, podName := parts[0], parts[1]

				policy, err := BuildSinglePolicy(podName, podNS, j.policyData, allPodLabels)
				if err != nil {
					fmt.Printf("Skip pod %q: %v\n", j.podKey, err)
					continue
				}

				if valid, msg := ValidatePolicy(policy); !valid {
					fmt.Printf("Policy validation failed for %q: %s\n", j.podKey, msg)
					continue
				}

				filePath, err := WritePolicy(policy, baseOutputDir)
				if err != nil {
					fmt.Printf("Error writing policy for %q: %v\n", j.podKey, err)
					continue
				}

				policyFilesMu.Lock()
				policyFiles = append(policyFiles, filePath)
				policyFilesMu.Unlock()

				fmt.Printf("Created policy: %s (egress: %d, ingress: %d)\n",
					filePath, len(policy.Spec.Egress), len(policy.Spec.Ingress))
			}
		}()
	}
	wg.Wait()
	return policyFiles, nil
}

// filterValidLabels strips system/Cilium label key prefixes that are not
// permitted in CiliumNetworkPolicy matchLabels.
func filterValidLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if strings.HasPrefix(k, "k8s:") ||
			strings.HasPrefix(k, "io.cilium") ||
			strings.HasPrefix(k, "io.kubernetes.pod") {
			continue
		}
		out[k] = v
	}
	return out
}

// sortedKeys returns sorted keys of a map[string]bool.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
