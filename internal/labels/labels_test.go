package labels

import (
	"testing"
)

// --- ParseHubbleLabels ---

func TestParseHubbleLabels_StripK8sPrefix(t *testing.T) {
	result := ParseHubbleLabels([]string{"k8s:app=myapp"})
	if v, ok := result["app"]; !ok || v != "myapp" {
		t.Errorf("expected app=myapp, got %v", result)
	}
}

func TestParseHubbleLabels_PreservesPlainLabel(t *testing.T) {
	result := ParseHubbleLabels([]string{"version=v1.2.3"})
	if v, ok := result["version"]; !ok || v != "v1.2.3" {
		t.Errorf("expected version=v1.2.3, got %v", result)
	}
}

func TestParseHubbleLabels_DropsReserved(t *testing.T) {
	result := ParseHubbleLabels([]string{"reserved:world", "reserved:health"})
	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
}

func TestParseHubbleLabels_DropsCiliumPrefix(t *testing.T) {
	result := ParseHubbleLabels([]string{"k8s:io.cilium.k8s.policy.cluster=mycluster"})
	if len(result) != 0 {
		t.Errorf("expected empty (cilium policy label dropped), got %v", result)
	}
}

func TestParseHubbleLabels_DropsPodTemplateHash(t *testing.T) {
	result := ParseHubbleLabels([]string{"k8s:pod-template-hash=abc123"})
	if _, ok := result["pod-template-hash"]; ok {
		t.Errorf("pod-template-hash should be excluded")
	}
}

func TestParseHubbleLabels_DropsControllerRevisionHash(t *testing.T) {
	result := ParseHubbleLabels([]string{"k8s:controller-revision-hash=xyz"})
	if _, ok := result["controller-revision-hash"]; ok {
		t.Errorf("controller-revision-hash should be excluded")
	}
}

func TestParseHubbleLabels_SkipsNoEquals(t *testing.T) {
	result := ParseHubbleLabels([]string{"noequalssign", "k8s:app=valid"})
	if _, ok := result["noequalssign"]; ok {
		t.Errorf("entry without = should be skipped")
	}
	if _, ok := result["app"]; !ok {
		t.Errorf("valid entry should be present")
	}
}

func TestParseHubbleLabels_ValueWithEquals(t *testing.T) {
	result := ParseHubbleLabels([]string{"k8s:app=my=complex=value"})
	if v, ok := result["app"]; !ok || v != "my=complex=value" {
		t.Errorf("expected app=my=complex=value, got %v", result)
	}
}

func TestParseHubbleLabels_Empty(t *testing.T) {
	result := ParseHubbleLabels([]string{})
	if len(result) != 0 {
		t.Errorf("expected empty map for empty input, got %v", result)
	}
}

// --- FilterK8sLabels ---

func TestFilterK8sLabels_PreservesAppLabel(t *testing.T) {
	result := FilterK8sLabels(map[string]interface{}{
		"app":     "myapp",
		"version": "v1",
	})
	if result["app"] != "myapp" || result["version"] != "v1" {
		t.Errorf("expected app+version preserved, got %v", result)
	}
}

func TestFilterK8sLabels_DropsCiliumPolicy(t *testing.T) {
	result := FilterK8sLabels(map[string]interface{}{
		"io.cilium.k8s.policy.cluster": "mycluster",
		"app":                          "keep",
	})
	if _, ok := result["io.cilium.k8s.policy.cluster"]; ok {
		t.Errorf("cilium policy label should be excluded")
	}
	if result["app"] != "keep" {
		t.Errorf("app label should be kept, got %v", result)
	}
}

func TestFilterK8sLabels_DropsPodTemplateHash(t *testing.T) {
	result := FilterK8sLabels(map[string]interface{}{
		"pod-template-hash": "abc123",
		"app":               "myapp",
	})
	if _, ok := result["pod-template-hash"]; ok {
		t.Errorf("pod-template-hash should be excluded")
	}
}

func TestFilterK8sLabels_SkipsNonStringValues(t *testing.T) {
	result := FilterK8sLabels(map[string]interface{}{
		"app":    "myapp",
		"number": 42,
		"nested": map[string]string{"x": "y"},
	})
	if _, ok := result["number"]; ok {
		t.Errorf("non-string value should be skipped")
	}
	if _, ok := result["nested"]; ok {
		t.Errorf("non-string value should be skipped")
	}
	if result["app"] != "myapp" {
		t.Errorf("string value should be preserved")
	}
}

func TestFilterK8sLabels_DropsStatefulSetLabel(t *testing.T) {
	result := FilterK8sLabels(map[string]interface{}{
		"statefulset.kubernetes.io/pod-name": "myapp-0",
		"app": "myapp",
	})
	if _, ok := result["statefulset.kubernetes.io/pod-name"]; ok {
		t.Errorf("statefulset pod-name label should be excluded")
	}
}
