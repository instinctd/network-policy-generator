package k8s

import (
	"errors"
	"testing"
)

// kubectlPodsJSON returns minimal kubectl get pods JSON with the given entries.
// Each entry is (podName, namespace, podIP, labels map[string]string).
func kubectlPodsJSON(pods []struct {
	name, ns, ip string
	labels       map[string]string
}) []byte {
	items := ""
	for i, p := range pods {
		labStr := ""
		for k, v := range p.labels {
			if labStr != "" {
				labStr += ","
			}
			labStr += `"` + k + `":"` + v + `"`
		}
		items += `{
			"metadata":{"name":"` + p.name + `","namespace":"` + p.ns + `","labels":{` + labStr + `}},
			"status":{"podIP":"` + p.ip + `"}
		}`
		if i < len(pods)-1 {
			items += ","
		}
	}
	return []byte(`{"items":[` + items + `]}`)
}

func kubectlServicesJSON(svcs []struct{ name, ns, ip string }) []byte {
	items := ""
	for i, s := range svcs {
		items += `{"metadata":{"name":"` + s.name + `","namespace":"` + s.ns + `"},"spec":{"clusterIP":"` + s.ip + `"}}`
		if i < len(svcs)-1 {
			items += ","
		}
	}
	return []byte(`{"items":[` + items + `]}`)
}

func TestFetchAllPodsIPs_ParsesJSON(t *testing.T) {
	fake := NewFakeCommander()
	fake.Responses["kubectl"] = kubectlPodsJSON([]struct {
		name, ns, ip string
		labels       map[string]string
	}{
		{"pod-a", "ns1", "10.1.0.1", map[string]string{"app": "myapp"}},
		{"pod-b", "ns2", "10.1.0.2", map[string]string{"app": "other"}},
	})

	res, err := FetchAllPodsIPs(fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.IPToPod) != 2 {
		t.Errorf("expected 2 entries in IPToPod, got %d", len(res.IPToPod))
	}
	if res.IPToPod["10.1.0.1"].Name != "pod-a" {
		t.Errorf("expected pod-a at 10.1.0.1, got %v", res.IPToPod["10.1.0.1"])
	}
	if res.IPToNamespace["10.1.0.1"] != "ns1" {
		t.Errorf("expected ns1 for 10.1.0.1, got %s", res.IPToNamespace["10.1.0.1"])
	}
	if res.PodLabels["pod-a"]["app"] != "myapp" {
		t.Errorf("expected app=myapp for pod-a labels, got %v", res.PodLabels["pod-a"])
	}
	if len(res.PodIPs) != 2 {
		t.Errorf("expected 2 PodIPs, got %d", len(res.PodIPs))
	}
}

func TestFetchAllPodsIPs_SkipsPodsWithoutIP(t *testing.T) {
	fake := NewFakeCommander()
	fake.Responses["kubectl"] = kubectlPodsJSON([]struct {
		name, ns, ip string
		labels       map[string]string
	}{
		{"pod-a", "ns1", "", nil},
		{"pod-b", "ns1", "10.1.0.1", nil},
	})

	res, err := FetchAllPodsIPs(fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.IPToPod) != 1 {
		t.Errorf("expected 1 pod with IP, got %d", len(res.IPToPod))
	}
}

func TestFetchAllPodsIPs_CommandError(t *testing.T) {
	fake := NewFakeCommander()
	fake.Errors["kubectl"] = errors.New("kubectl not found")

	_, err := FetchAllPodsIPs(fake)
	if err == nil {
		t.Error("expected error when command fails")
	}
}

func TestFetchAllPodsIPs_InvalidJSON(t *testing.T) {
	fake := NewFakeCommander()
	fake.Responses["kubectl"] = []byte("not json at all")

	_, err := FetchAllPodsIPs(fake)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestFetchAllServicesIPs_ParsesClusterIP(t *testing.T) {
	fake := NewFakeCommander()
	fake.Responses["kubectl"] = kubectlServicesJSON([]struct{ name, ns, ip string }{
		{"redis", "production", "10.96.0.10"},
		{"postgres", "production", "10.96.0.11"},
	})

	res, err := FetchAllServicesIPs(fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.IPToService) != 2 {
		t.Errorf("expected 2 services, got %d", len(res.IPToService))
	}
	if res.IPToService["10.96.0.10"].Name != "redis" {
		t.Errorf("expected redis at 10.96.0.10, got %v", res.IPToService["10.96.0.10"])
	}
	if res.IPToNamespace["10.96.0.10"] != "production" {
		t.Errorf("expected production namespace, got %s", res.IPToNamespace["10.96.0.10"])
	}
}

func TestFetchAllServicesIPs_SkipsHeadless(t *testing.T) {
	fake := NewFakeCommander()
	fake.Responses["kubectl"] = kubectlServicesJSON([]struct{ name, ns, ip string }{
		{"headless-svc", "ns1", "None"},
		{"real-svc", "ns1", "10.96.0.1"},
	})

	res, err := FetchAllServicesIPs(fake)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.IPToService) != 1 {
		t.Errorf("expected 1 service (headless skipped), got %d", len(res.IPToService))
	}
}

func TestFetchAllServicesIPs_CommandError(t *testing.T) {
	fake := NewFakeCommander()
	fake.Errors["kubectl"] = errors.New("connection refused")

	_, err := FetchAllServicesIPs(fake)
	if err == nil {
		t.Error("expected error when command fails")
	}
}
