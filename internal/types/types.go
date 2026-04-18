package types

import "net"

// PortConfig holds port and protocol for a known service.
type PortConfig struct {
	Port     string
	Protocol string
}

// PodInfo holds a pod's name and namespace.
type PodInfo struct {
	Name      string
	Namespace string
}

// ServiceInfo holds a service's name and namespace.
type ServiceInfo struct {
	Name      string
	Namespace string
}

// FlowDetail holds the parsed details of a single observed network flow.
type FlowDetail struct {
	SourcePod    string                 `json:"source_pod"`
	SourceNS     string                 `json:"source_ns"`
	SourceIP     string                 `json:"source_ip"`
	DestPod      string                 `json:"dest_pod"`
	DestNS       string                 `json:"dest_ns"`
	DestIP       string                 `json:"dest_ip"`
	DestPort     interface{}            `json:"dest_port"`
	Protocol     string                 `json:"protocol"`
	SourceLabels []string               `json:"source_labels"`
	DestLabels   []string               `json:"dest_labels"`
	RawFlow      map[string]interface{} `json:"-"`
}

// PolicyData holds aggregated egress and ingress rules for a single pod.
type PolicyData struct {
	Namespace string
	Egress    map[string]*RuleInfo
	Ingress   map[string]*RuleInfo
}

// RuleInfo aggregates ports and protocols for a single policy rule destination/source.
type RuleInfo struct {
	Ports     map[string]bool
	Protocols map[string]bool
}

// --- CiliumNetworkPolicy YAML types ---

type CiliumNetworkPolicy struct {
	APIVersion string     `yaml:"apiVersion"`
	Kind       string     `yaml:"kind"`
	Metadata   Metadata   `yaml:"metadata"`
	Spec       PolicySpec `yaml:"spec"`
}

type Metadata struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

type PolicySpec struct {
	EndpointSelector EndpointSelector `yaml:"endpointSelector"`
	Egress           []EgressRule     `yaml:"egress,omitempty"`
	Ingress          []IngressRule    `yaml:"ingress,omitempty"`
}

type EndpointSelector struct {
	MatchLabels      map[string]string `yaml:"matchLabels,omitempty"`
	MatchExpressions []MatchExpression `yaml:"matchExpressions,omitempty"`
}

type MatchExpression struct {
	Key      string   `yaml:"key"`
	Operator string   `yaml:"operator"`
	Values   []string `yaml:"values"`
}

type EgressRule struct {
	ToEndpoints []EndpointSelector `yaml:"toEndpoints,omitempty"`
	ToCIDR      []string           `yaml:"toCIDR,omitempty"`
	ToPorts     []PortRule         `yaml:"toPorts,omitempty"`
}

type IngressRule struct {
	FromEndpoints []EndpointSelector `yaml:"fromEndpoints,omitempty"`
	FromCIDR      []string           `yaml:"fromCIDR,omitempty"`
	ToPorts       []PortRule         `yaml:"toPorts,omitempty"`
}

type PortRule struct {
	Protocol string     `yaml:"protocol"`
	Ports    []PortSpec `yaml:"ports"`
}

type PortSpec struct {
	Port string `yaml:"port"`
}

// InternalNetworks is a convenience alias used in function signatures.
type InternalNetworks = []*net.IPNet
