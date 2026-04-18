package labels

import "strings"

// excludePrefixes lists label key prefixes and exact names to filter out.
var excludePrefixes = []string{
	"io.cilium.",
	"io.kubernetes.pod.",
	"pod-template-hash",
	"controller-revision-hash",
	"statefulset.kubernetes.io/pod-name",
	"commit",
}

// shouldExclude returns true if the label key should be dropped.
func shouldExclude(key string) bool {
	for _, prefix := range excludePrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	if strings.Contains(key, "k8s.namespace.labels") {
		return true
	}
	if key == "k8s.policy.cluster" || key == "k8s.policy.serviceaccount" {
		return true
	}
	if strings.HasPrefix(key, "io.cilium.k8s.policy") {
		return true
	}
	if key == "io.kubernetes.pod.namespace" {
		return true
	}
	return false
}

// ParseHubbleLabels parses Hubble flow label strings (e.g. "k8s:app=myapp") into
// a clean key→value map, stripping system and Cilium-specific labels.
func ParseHubbleLabels(labelsList []string) map[string]string {
	labels := make(map[string]string)
	for _, label := range labelsList {
		if !strings.Contains(label, "=") || strings.HasPrefix(label, "reserved:") {
			continue
		}
		parts := strings.SplitN(label, "=", 2)
		key := parts[0]
		value := parts[1]

		if strings.HasPrefix(key, "k8s:") {
			key = key[4:]
		}

		if shouldExclude(key) {
			continue
		}
		labels[key] = value
	}
	return labels
}

// FilterK8sLabels filters a kubectl metadata.labels map (map[string]interface{}),
// removing system and Cilium-specific keys, and returning only string values.
func FilterK8sLabels(labelsDict map[string]interface{}) map[string]string {
	filtered := make(map[string]string)
	for key, value := range labelsDict {
		if shouldExclude(key) {
			continue
		}
		if str, ok := value.(string); ok {
			filtered[key] = str
		}
	}
	return filtered
}
