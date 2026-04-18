package network

import (
	"net"
	"testing"

	"github.com/network-policy-generator/internal/types"
)

// --- IsPrivateIP ---

func TestIsPrivateIP_10(t *testing.T) {
	if !IsPrivateIP(net.ParseIP("10.0.0.1")) {
		t.Error("10.0.0.1 should be private")
	}
}

func TestIsPrivateIP_172(t *testing.T) {
	if !IsPrivateIP(net.ParseIP("172.16.0.1")) {
		t.Error("172.16.0.1 should be private")
	}
	if !IsPrivateIP(net.ParseIP("172.31.255.255")) {
		t.Error("172.31.255.255 should be private")
	}
	if IsPrivateIP(net.ParseIP("172.32.0.1")) {
		t.Error("172.32.0.1 should NOT be private")
	}
}

func TestIsPrivateIP_192(t *testing.T) {
	if !IsPrivateIP(net.ParseIP("192.168.1.1")) {
		t.Error("192.168.1.1 should be private")
	}
}

func TestIsPrivateIP_CGNAT(t *testing.T) {
	if !IsPrivateIP(net.ParseIP("100.64.0.1")) {
		t.Error("100.64.0.1 (CGNAT) should be private")
	}
}

func TestIsPrivateIP_Public(t *testing.T) {
	if IsPrivateIP(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 should NOT be private")
	}
}

// --- SanitizeName ---

func TestSanitizeName_RemovesDeploymentHash(t *testing.T) {
	got := SanitizeName("myapp-7d9f84c5b-xk8qz")
	if got != "myapp" {
		t.Errorf("expected myapp, got %s", got)
	}
}

func TestSanitizeName_RemovesReplicaSetHash(t *testing.T) {
	got := SanitizeName("myapp-abc1234567")
	if got != "myapp" {
		t.Errorf("expected myapp, got %s", got)
	}
}

func TestSanitizeName_TruncatesAt63(t *testing.T) {
	long := "a-very-long-pod-name-that-exceeds-sixty-three-characters-in-total-yes-it-does"
	got := SanitizeName(long)
	if len(got) > 63 {
		t.Errorf("length %d exceeds 63: %s", len(got), got)
	}
	if got[len(got)-1] == '-' {
		t.Errorf("truncated name must not end with hyphen: %s", got)
	}
}

func TestSanitizeName_ReplacesInvalidChars(t *testing.T) {
	got := SanitizeName("My_App.Service")
	for _, ch := range got {
		if !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' {
			t.Errorf("unexpected char %c in sanitized name %s", ch, got)
		}
	}
}

func TestSanitizeName_Lowercase(t *testing.T) {
	got := SanitizeName("MyApp")
	if got != "myapp" {
		t.Errorf("expected myapp, got %s", got)
	}
}

// --- ExtractLabelsFromPodName ---

func TestExtractLabelsFromPodName_HasHash(t *testing.T) {
	labels := ExtractLabelsFromPodName("myapp-7d9f84c5b-xk8qz")
	if labels["app"] != "myapp" {
		t.Errorf("expected app=myapp, got %v", labels)
	}
}

func TestExtractLabelsFromPodName_NoHash_Empty(t *testing.T) {
	labels := ExtractLabelsFromPodName("myapp")
	if len(labels) != 0 {
		t.Errorf("expected empty labels for clean name, got %v", labels)
	}
}

func TestExtractLabelsFromPodName_StatefulSet(t *testing.T) {
	labels := ExtractLabelsFromPodName("myapp-0")
	if labels["app"] != "myapp" {
		t.Errorf("expected app=myapp for statefulset pod, got %v", labels)
	}
}

// --- AutoDetectPodCIDR ---

func TestAutoDetectPodCIDR_FindsMostCommon(t *testing.T) {
	ips := make([]string, 0, 105)
	for i := 0; i < 100; i++ {
		ips = append(ips, "10.40.1."+string(rune('0'+i%10)))
	}
	for i := 0; i < 5; i++ {
		ips = append(ips, "10.39.0."+string(rune('1'+i)))
	}
	// Use proper IPs
	ips = nil
	for i := 0; i < 100; i++ {
		ips = append(ips, "10.40.0.1")
	}
	for i := 0; i < 5; i++ {
		ips = append(ips, "10.39.0.1")
	}

	result := AutoDetectPodCIDR(ips, nil)
	if result == nil {
		t.Fatal("expected a detected CIDR, got nil")
	}
	if result.String() != "10.40.0.0/16" {
		t.Errorf("expected 10.40.0.0/16, got %s", result.String())
	}
}

func TestAutoDetectPodCIDR_EmptyInput(t *testing.T) {
	result := AutoDetectPodCIDR(nil, nil)
	if result != nil {
		t.Errorf("expected nil for empty input, got %s", result)
	}
}

func TestAutoDetectPodCIDR_SkipsExisting(t *testing.T) {
	_, existing, _ := net.ParseCIDR("10.40.0.0/16")
	result := AutoDetectPodCIDR([]string{"10.40.0.1", "10.40.0.2"}, []*net.IPNet{existing})
	if result != nil {
		t.Errorf("should not return already-existing CIDR, got %s", result)
	}
}

// --- ParseCIDRs ---

func TestParseCIDRs_ValidCIDRs(t *testing.T) {
	nets, err := ParseCIDRs("10.244.0.0/16", "10.96.0.0/12")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 2 {
		t.Errorf("expected 2 networks, got %d", len(nets))
	}
}

func TestParseCIDRs_EmptyStrings_UsesDefaults(t *testing.T) {
	nets, _ := ParseCIDRs("", "")
	if len(nets) == 0 {
		t.Error("expected default networks for empty CIDRs")
	}
}

func TestParseCIDRs_InvalidCIDR_ReturnsError(t *testing.T) {
	_, err := ParseCIDRs("not-a-cidr", "")
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

// --- IsExternalIP ---

func TestIsExternalIP_KnownPodIP(t *testing.T) {
	ipToPod := map[string]types.PodInfo{"10.40.0.5": {Name: "mypod", Namespace: "default"}}
	if IsExternalIP("10.40.0.5", ipToPod, nil, nil) {
		t.Error("known pod IP should not be external")
	}
}

func TestIsExternalIP_KnownNamespaceIP(t *testing.T) {
	ipToNS := map[string]string{"10.96.0.1": "kube-system"}
	if IsExternalIP("10.96.0.1", nil, ipToNS, nil) {
		t.Error("known namespace IP should not be external")
	}
}

func TestIsExternalIP_Loopback(t *testing.T) {
	if IsExternalIP("127.0.0.1", nil, nil, nil) {
		t.Error("loopback should not be external")
	}
}

func TestIsExternalIP_PublicUnknown(t *testing.T) {
	if !IsExternalIP("1.2.3.4", nil, nil, nil) {
		t.Error("unknown public IP should be external")
	}
}

func TestIsExternalIP_PrivateUnknown(t *testing.T) {
	if IsExternalIP("192.168.1.1", nil, nil, nil) {
		t.Error("unknown private IP should NOT be external (private ranges are internal)")
	}
}

func TestIsExternalIP_InInternalNetwork(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.40.0.0/16")
	if IsExternalIP("10.40.5.5", nil, nil, []*net.IPNet{cidr}) {
		t.Error("IP in internal network should not be external")
	}
}

func TestIsExternalIP_Unknown(t *testing.T) {
	if IsExternalIP("unknown", nil, nil, nil) {
		t.Error("'unknown' string should not be external")
	}
}
