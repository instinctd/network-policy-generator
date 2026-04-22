package k8s

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/network-policy-generator/internal/types"
)

// policyList matches the kubectl YAML list output for CiliumNetworkPolicy.
type policyList struct {
	Items []types.CiliumNetworkPolicy `yaml:"items"`
}

// FetchClusterPolicies loads all CiliumNetworkPolicy objects from the cluster
// via kubectl and returns them keyed by "namespace/name".
// Returns an empty map (not an error) when no policies exist yet.
func FetchClusterPolicies(cmd Commander) (map[string]*types.CiliumNetworkPolicy, error) {
	out, err := cmd.Output("kubectl", "get", "ciliumnetworkpolicies",
		"--all-namespaces", "-o", "yaml")
	if err != nil {
		return nil, fmt.Errorf("kubectl get ciliumnetworkpolicies: %w", err)
	}

	var list policyList
	if err := yaml.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parse ciliumnetworkpolicies yaml: %w", err)
	}

	result := make(map[string]*types.CiliumNetworkPolicy, len(list.Items))
	for i := range list.Items {
		p := &list.Items[i]
		key := p.Metadata.Namespace + "/" + p.Metadata.Name
		result[key] = p
	}
	return result, nil
}
