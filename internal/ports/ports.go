package ports

import (
	"strings"

	"github.com/network-policy-generator/internal/types"
)

// DefaultPorts maps well-known service names to their default port/protocol.
var DefaultPorts = map[string]types.PortConfig{
	"rabbitmq":            {Port: "5672", Protocol: "TCP"},
	"rabbitmq-management": {Port: "15672", Protocol: "TCP"},
	"redis":               {Port: "6379", Protocol: "TCP"},
	"redis-sentinel":      {Port: "26379", Protocol: "TCP"},
	"postgresql":          {Port: "5432", Protocol: "TCP"},
	"postgres":            {Port: "5432", Protocol: "TCP"},
	"vmagent":             {Port: "8429", Protocol: "TCP"},
	"victoria-metrics":    {Port: "8428", Protocol: "TCP"},
	"vmsingle":            {Port: "8429", Protocol: "TCP"},
	"vmselect":            {Port: "8481", Protocol: "TCP"},
	"vminsert":            {Port: "8480", Protocol: "TCP"},
	"vmstorage":           {Port: "8482", Protocol: "TCP"},
	"prometheus":          {Port: "9090", Protocol: "TCP"},
	"alertmanager":        {Port: "9093", Protocol: "TCP"},
	"grafana":             {Port: "3000", Protocol: "TCP"},
	"kube-dns":            {Port: "53", Protocol: "UDP"},
	"coredns":             {Port: "53", Protocol: "UDP"},
}

// GetDefaultPort returns a default port config for the given pod labels, or nil if none matches.
func GetDefaultPort(labels map[string]string) *types.PortConfig {
	if labels == nil {
		return nil
	}

	checkNames := []string{
		strings.ToLower(labels["app"]),
		strings.ToLower(labels["app.kubernetes.io/name"]),
		strings.ToLower(labels["app.kubernetes.io/component"]),
		strings.ToLower(labels["k8s-app"]),
	}

	// Exact match first
	for _, name := range checkNames {
		if name == "" {
			continue
		}
		if config, ok := DefaultPorts[name]; ok {
			return &config
		}
	}

	// Substring match fallback
	for _, name := range checkNames {
		if name == "" {
			continue
		}
		for key, config := range DefaultPorts {
			if strings.Contains(key, name) || strings.Contains(name, key) {
				return &config
			}
		}
	}

	return nil
}
