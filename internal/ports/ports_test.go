package ports

import "testing"

func TestGetDefaultPort_ExactMatch(t *testing.T) {
	cfg := GetDefaultPort(map[string]string{"app": "redis"})
	if cfg == nil {
		t.Fatal("expected non-nil config for redis")
	}
	if cfg.Port != "6379" || cfg.Protocol != "TCP" {
		t.Errorf("redis: want 6379/TCP, got %s/%s", cfg.Port, cfg.Protocol)
	}
}

func TestGetDefaultPort_ExactMatchKubernetesDotName(t *testing.T) {
	cfg := GetDefaultPort(map[string]string{"app.kubernetes.io/name": "postgresql"})
	if cfg == nil {
		t.Fatal("expected non-nil config for postgresql")
	}
	if cfg.Port != "5432" {
		t.Errorf("postgresql: want 5432, got %s", cfg.Port)
	}
}

func TestGetDefaultPort_SubstringMatch(t *testing.T) {
	cfg := GetDefaultPort(map[string]string{"app": "my-redis-cluster"})
	if cfg == nil {
		t.Fatal("expected non-nil config for my-redis-cluster (substring match)")
	}
	if cfg.Port != "6379" {
		t.Errorf("my-redis-cluster: want 6379, got %s", cfg.Port)
	}
}

func TestGetDefaultPort_NoMatch(t *testing.T) {
	cfg := GetDefaultPort(map[string]string{"app": "completely-unknown-service"})
	if cfg != nil {
		t.Errorf("expected nil for unknown service, got %+v", cfg)
	}
}

func TestGetDefaultPort_NilLabels(t *testing.T) {
	cfg := GetDefaultPort(nil)
	if cfg != nil {
		t.Errorf("expected nil for nil labels, got %+v", cfg)
	}
}

func TestGetDefaultPort_EmptyLabels(t *testing.T) {
	cfg := GetDefaultPort(map[string]string{})
	if cfg != nil {
		t.Errorf("expected nil for empty labels, got %+v", cfg)
	}
}

func TestGetDefaultPort_CaseInsensitive(t *testing.T) {
	cfg := GetDefaultPort(map[string]string{"app": "REDIS"})
	if cfg == nil {
		t.Fatal("expected match for uppercase REDIS")
	}
	if cfg.Port != "6379" {
		t.Errorf("REDIS: want 6379, got %s", cfg.Port)
	}
}

func TestGetDefaultPort_KubeDNS(t *testing.T) {
	cfg := GetDefaultPort(map[string]string{"k8s-app": "kube-dns"})
	if cfg == nil {
		t.Fatal("expected non-nil config for kube-dns")
	}
	if cfg.Port != "53" || cfg.Protocol != "UDP" {
		t.Errorf("kube-dns: want 53/UDP, got %s/%s", cfg.Port, cfg.Protocol)
	}
}
