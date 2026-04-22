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

// priorityLabelKeys lists well-known label keys in order of preference.
// When building an endpoint selector, the first matching key wins and is
// used on its own, producing a stable single-label selector.
var priorityLabelKeys = []string{
	"app.kubernetes.io/name",
	"app.kubernetes.io/component",
	"app",
}

// SelectLabels returns a minimal label map for use as matchLabels.
// If any of the priority keys exists in filtered, a single-entry map
// containing just that key→value is returned. Otherwise the full
// filtered map is returned unchanged.
func SelectLabels(filtered map[string]string) map[string]string {
	for _, key := range priorityLabelKeys {
		if value, ok := filtered[key]; ok {
			return map[string]string{key: value}
		}
	}
	return filtered
}
