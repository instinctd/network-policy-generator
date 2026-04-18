package collector

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/network-policy-generator/internal/k8s"
)

func podJSON(pods []struct{ name, ns, ip string }) []byte {
	items := ""
	for i, p := range pods {
		items += `{"metadata":{"name":"` + p.name + `","namespace":"` + p.ns + `","labels":{"app":"` + p.name + `"}},"status":{"podIP":"` + p.ip + `"}}`
		if i < len(pods)-1 {
			items += ","
		}
	}
	return []byte(`{"items":[` + items + `]}`)
}

func svcJSON(svcs []struct{ name, ns, ip string }) []byte {
	items := ""
	for i, s := range svcs {
		items += `{"metadata":{"name":"` + s.name + `","namespace":"` + s.ns + `"},"spec":{"clusterIP":"` + s.ip + `"}}`
		if i < len(svcs)-1 {
			items += ","
		}
	}
	return []byte(`{"items":[` + items + `]}`)
}

func newFakeCollector(t *testing.T) (*HubbleCollector, *k8s.FakeCommander) {
	t.Helper()
	fake := k8s.NewFakeCommander()
	fake.Responses["kubectl get pods --all-namespaces -o json"] = podJSON([]struct{ name, ns, ip string }{
		{"pod-a", "ns1", "10.0.0.1"},
		{"pod-b", "ns1", "10.0.0.2"},
	})
	fake.Responses["kubectl get services --all-namespaces -o json"] = svcJSON([]struct{ name, ns, ip string }{
		{"redis", "ns1", "10.96.0.10"},
	})

	hc, err := New("ns1", false, "", "", "", "", "", fake)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return hc, fake
}

func TestNew_LoadsPodAndServiceIPs(t *testing.T) {
	hc, _ := newFakeCollector(t)
	hc.store.Mu.RLock()
	defer hc.store.Mu.RUnlock()

	if len(hc.store.IPToPod) != 2 {
		t.Errorf("expected 2 pod IPs, got %d", len(hc.store.IPToPod))
	}
	if len(hc.ipToService) != 1 {
		t.Errorf("expected 1 service IP, got %d", len(hc.ipToService))
	}
}

func TestCollectFlows_BuildsConnections(t *testing.T) {
	hc, fake := newFakeCollector(t)

	flow := map[string]interface{}{
		"flow": map[string]interface{}{
			"source":      map[string]interface{}{"namespace": "ns1", "pod_name": "pod-a", "labels": []interface{}{"k8s:app=pod-a"}},
			"destination": map[string]interface{}{"namespace": "ns1", "pod_name": "pod-b", "port": float64(8080)},
			"IP":          map[string]interface{}{"source": "10.0.0.1", "destination": "10.0.0.2"},
			"l4":          map[string]interface{}{"TCP": map[string]interface{}{"destination_port": float64(8080)}},
		},
	}
	b, _ := json.Marshal(flow)
	fake.Responses["hubble observe flows --output json --namespace ns1 --last 60"] = b

	if err := hc.CollectFlows(60, false, false); err != nil {
		t.Fatalf("CollectFlows error: %v", err)
	}
	if hc.flowCount != 1 {
		t.Errorf("expected 1 flow, got %d", hc.flowCount)
	}
	if len(hc.store.Connections) == 0 {
		t.Error("expected connections after collecting flows")
	}
}

func TestExportToJSON_CorrectStructure(t *testing.T) {
	hc, _ := newFakeCollector(t)
	hc.store.Connections["pod-a"] = map[string]int{"pod-b:8080/TCP": 3}
	hc.flowCount = 3

	tmpFile := t.TempDir() + "/flows.json"
	if err := hc.ExportToJSON(tmpFile); err != nil {
		t.Fatalf("ExportToJSON error: %v", err)
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, data)
	}
	if _, ok := result["namespace"]; !ok {
		t.Error("expected 'namespace' key in JSON")
	}
	if _, ok := result["connections"]; !ok {
		t.Error("expected 'connections' key in JSON")
	}
	if result["total_flows"].(float64) != 3 {
		t.Errorf("expected total_flows=3, got %v", result["total_flows"])
	}
}

func TestExportCiliumPolicies_CreatesFiles(t *testing.T) {
	hc, _ := newFakeCollector(t)

	// Seed store with a flow
	flow := map[string]interface{}{
		"flow": map[string]interface{}{
			"source":      map[string]interface{}{"namespace": "ns1", "pod_name": "pod-a", "labels": []interface{}{"k8s:app=pod-a"}},
			"destination": map[string]interface{}{"namespace": "ns1", "pod_name": "pod-b", "port": float64(8080)},
			"IP":          map[string]interface{}{"source": "10.0.0.1", "destination": "10.0.0.2"},
			"l4":          map[string]interface{}{"TCP": map[string]interface{}{"destination_port": float64(8080)}},
		},
	}
	hc.store.ProcessFlow(flow, "ns1")

	dir := t.TempDir()
	files, err := hc.ExportCiliumPolicies(dir)
	if err != nil {
		t.Fatalf("ExportCiliumPolicies error: %v", err)
	}
	if len(files) == 0 {
		t.Error("expected at least one policy file to be created")
	}
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("policy file %q does not exist: %v", f, err)
		}
	}
}
