package flow

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/network-policy-generator/internal/k8s"
)

// --- helpers ---

func makeFlow(sourceNS, sourcePod, sourceIP, destNS, destPod, destIP string, destPort interface{}, protocol string) map[string]interface{} {
	return map[string]interface{}{
		"flow": map[string]interface{}{
			"source":      map[string]interface{}{"namespace": sourceNS, "pod_name": sourcePod, "labels": []interface{}{"k8s:app=" + sourcePod}},
			"destination": map[string]interface{}{"namespace": destNS, "pod_name": destPod, "port": destPort},
			"IP":          map[string]interface{}{"source": sourceIP, "destination": destIP},
			"l4":          map[string]interface{}{protocol: map[string]interface{}{"destination_port": destPort}},
		},
	}
}

// --- BuildSourcePodName ---

func TestBuildSourcePodName_WithWorkload(t *testing.T) {
	src := map[string]interface{}{
		"workloads": []interface{}{
			map[string]interface{}{"name": "my-deploy", "kind": "Deployment"},
		},
	}
	got := BuildSourcePodName(src, "10.0.0.1")
	if got != "my-deploy (Deployment)" {
		t.Errorf("expected 'my-deploy (Deployment)', got %q", got)
	}
}

func TestBuildSourcePodName_WithReservedLabel(t *testing.T) {
	src := map[string]interface{}{
		"labels": []interface{}{"reserved:world"},
	}
	got := BuildSourcePodName(src, "1.2.3.4")
	if got != "1.2.3.4 (world)" {
		t.Errorf("expected '1.2.3.4 (world)', got %q", got)
	}
}

func TestBuildSourcePodName_BareIP(t *testing.T) {
	got := BuildSourcePodName(map[string]interface{}{}, "1.2.3.4")
	if got != "1.2.3.4" {
		t.Errorf("expected bare IP, got %q", got)
	}
}

// --- BuildDestPodName ---

func TestBuildDestPodName_WithServiceAndNamespace(t *testing.T) {
	dest := map[string]interface{}{
		"service":   map[string]interface{}{"name": "redis"},
		"namespace": "production",
	}
	got := BuildDestPodName(dest, "10.96.0.1", 6379, nil, "TCP")
	if got != "redis.production:6379/TCP" {
		t.Errorf("expected redis.production:6379/TCP, got %q", got)
	}
}

func TestBuildDestPodName_CIDRLabel(t *testing.T) {
	dest := map[string]interface{}{
		"labels": []interface{}{"cidr:8.8.8.8/32=8.8.8.8"},
	}
	got := BuildDestPodName(dest, "8.8.8.8", 53, nil, "UDP")
	// Should contain the CIDR info
	if got == "" {
		t.Error("expected non-empty dest name")
	}
}

func TestBuildDestPodName_BareIP(t *testing.T) {
	got := BuildDestPodName(map[string]interface{}{}, "8.8.8.8", 53, nil, "UDP")
	if got != "8.8.8.8:53/UDP" {
		t.Errorf("expected '8.8.8.8:53/UDP', got %q", got)
	}
}

// --- ProcessFlow / ConnectionStore ---

func TestConnectionStore_ProcessFlow_BasicEgressIngress(t *testing.T) {
	store := NewConnectionStore()
	flow := makeFlow("ns1", "pod-a", "10.0.0.1", "ns1", "pod-b", "10.0.0.2", 8080, "TCP")
	store.ProcessFlow(flow, []string{"ns1"})

	// pod-a:8080/TCP (dest with port suffix) should be a connection from pod-a
	found := false
	for dest := range store.Connections["pod-a"] {
		if dest != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected connection from pod-a, connections: %v", store.Connections)
	}
}

func TestConnectionStore_ProcessFlow_FiltersByNamespace(t *testing.T) {
	store := NewConnectionStore()
	flow := makeFlow("other-ns", "pod-x", "10.0.0.9", "other-ns", "pod-y", "10.0.0.10", 80, "TCP")
	store.ProcessFlow(flow, []string{"ns1"})

	if len(store.Connections) != 0 {
		t.Errorf("expected no connections for out-of-namespace flow, got %v", store.Connections)
	}
}

func TestConnectionStore_ProcessFlow_AllNamespaces(t *testing.T) {
	store := NewConnectionStore()
	flow := makeFlow("ns-a", "pod-a", "10.0.0.1", "ns-b", "pod-b", "10.0.0.2", 80, "TCP")
	store.ProcessFlow(flow, nil) // nil = all namespaces

	if len(store.Connections) == 0 {
		t.Error("expected connections for all-namespaces mode")
	}
}

func TestConnectionStore_ProcessFlow_CountsMultipleFlows(t *testing.T) {
	store := NewConnectionStore()
	f := makeFlow("ns1", "pod-a", "10.0.0.1", "ns1", "pod-b", "10.0.0.2", 8080, "TCP")
	for i := 0; i < 5; i++ {
		store.ProcessFlow(f, []string{"ns1"})
	}

	var total int
	for _, dests := range store.Connections {
		for _, count := range dests {
			total += count
		}
	}
	if total != 5 {
		t.Errorf("expected 5 total flow counts, got %d", total)
	}
}

func TestConnectionStore_ProcessFlow_Concurrent(t *testing.T) {
	store := NewConnectionStore()
	f := makeFlow("ns1", "pod-a", "10.0.0.1", "ns1", "pod-b", "10.0.0.2", 80, "TCP")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.ProcessFlow(f, []string{"ns1"})
		}()
	}
	wg.Wait()
	// If we reach here without data race the test passes (run with -race)
}

// --- CollectBatch ---

func TestCollectBatch_ParsesNDJSON(t *testing.T) {
	fake := k8s.NewFakeCommander()

	flows := []map[string]interface{}{
		makeFlow("ns1", "a", "10.0.0.1", "ns1", "b", "10.0.0.2", 80, "TCP"),
		makeFlow("ns1", "c", "10.0.0.3", "ns1", "d", "10.0.0.4", 443, "TCP"),
		makeFlow("ns1", "e", "10.0.0.5", "ns1", "f", "10.0.0.6", 53, "UDP"),
	}
	var lines string
	for _, f := range flows {
		b, _ := json.Marshal(f)
		lines += string(b) + "\n"
	}
	fake.Responses["hubble"] = []byte(lines)

	store := NewConnectionStore()
	count, err := CollectBatch(fake, []string{"observe", "flows"}, store, []string{"ns1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 flows, got %d", count)
	}
}

func TestCollectBatch_SkipsMalformedLines(t *testing.T) {
	fake := k8s.NewFakeCommander()
	f := makeFlow("ns1", "a", "10.0.0.1", "ns1", "b", "10.0.0.2", 80, "TCP")
	good, _ := json.Marshal(f)
	fake.Responses["hubble"] = []byte(fmt.Sprintf("not-json\n%s\nnot-json\n", good))

	store := NewConnectionStore()
	count, err := CollectBatch(fake, []string{"observe", "flows"}, store, []string{"ns1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 valid flow, got %d", count)
	}
}
