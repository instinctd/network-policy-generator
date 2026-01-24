package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPorts contains default port configurations for known services
var DefaultPorts = map[string]PortConfig{
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

// Compiled regex patterns (cached for performance)
var (
	regexPodHash1      = regexp.MustCompile(`-[a-f0-9]{8,10}-[a-z0-9]{5}$`)
	regexPodHash2      = regexp.MustCompile(`-[a-f0-9]{9,10}$`)
	regexInvalidChars  = regexp.MustCompile(`[^a-z0-9-]`)
	regexDuplicateDash = regexp.MustCompile(`-+`)
	regexStatefulSet   = regexp.MustCompile(`-\d+$`)
)

// Exclude prefixes for label filtering (shared constant)
var excludePrefixes = []string{
	"io.cilium.",
	"io.kubernetes.pod.",
	"pod-template-hash",
	"controller-revision-hash",
	"statefulset.kubernetes.io/pod-name",
	"commit",
}

type PortConfig struct {
	Port     string
	Protocol string
}

type HubbleCollector struct {
	Namespace        string
	FromLabel        string
	ToLabel          string
	Verdict          string
	Flows            []map[string]interface{}
	Connections      map[string]map[string]int
	PodLabels        map[string]map[string]string
	FlowDetails      map[string]map[string][]FlowDetail
	IPToPod          map[string]PodInfo
	IPToNamespace    map[string]string
	IPToService      map[string]ServiceInfo
	UnresolvedIPs    map[string]bool
	InternalNetworks []*net.IPNet
	mu               sync.RWMutex // Protects concurrent access to maps
}

type PodInfo struct {
	Name      string
	Namespace string
}

type ServiceInfo struct {
	Name      string
	Namespace string
}

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

type CiliumNetworkPolicy struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   Metadata          `yaml:"metadata"`
	Spec       PolicySpec        `yaml:"spec"`
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

type PolicyData struct {
	Egress  map[string]*RuleInfo
	Ingress map[string]*RuleInfo
}

type RuleInfo struct {
	Ports     map[string]bool
	Protocols map[string]bool
}

func NewHubbleCollector(namespace, fromLabel, toLabel, verdict, podCIDR, serviceCIDR string) *HubbleCollector {
	hc := &HubbleCollector{
		Namespace:        namespace,
		FromLabel:        fromLabel,
		ToLabel:          toLabel,
		Verdict:          verdict,
		Flows:            []map[string]interface{}{},
		Connections:      make(map[string]map[string]int),
		PodLabels:        make(map[string]map[string]string),
		FlowDetails:      make(map[string]map[string][]FlowDetail),
		IPToPod:          make(map[string]PodInfo),
		IPToNamespace:    make(map[string]string),
		IPToService:      make(map[string]ServiceInfo),
		UnresolvedIPs:    make(map[string]bool),
		InternalNetworks: []*net.IPNet{},
	}

	// Parse CIDRs
	if podCIDR != "" {
		_, network, err := net.ParseCIDR(podCIDR)
		if err != nil {
			fmt.Printf("Warning: invalid pod_cidr '%s': %v\n", podCIDR, err)
		} else {
			hc.InternalNetworks = append(hc.InternalNetworks, network)
		}
	}

	if serviceCIDR != "" {
		_, network, err := net.ParseCIDR(serviceCIDR)
		if err != nil {
			fmt.Printf("Warning: invalid service_cidr '%s': %v\n", serviceCIDR, err)
		} else {
			hc.InternalNetworks = append(hc.InternalNetworks, network)
		}
	}

	// Default networks if none provided
	if len(hc.InternalNetworks) == 0 {
		defaultCIDRs := []string{
			"10.39.0.0/16",
			"10.40.0.0/16",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"100.64.0.0/10",
		}
		for _, cidr := range defaultCIDRs {
			_, network, _ := net.ParseCIDR(cidr)
			hc.InternalNetworks = append(hc.InternalNetworks, network)
		}
	}

	fmt.Println("Загрузка Pod IP mappings из кластера...")
	hc.fetchAllPodsIPs()
	fmt.Println("Загрузка Service IP mappings из кластера...")
	hc.fetchAllServicesIPs()

	return hc
}

func (hc *HubbleCollector) fetchAllPodsIPs() {
	cmd := exec.Command("kubectl", "get", "pods", "--all-namespaces", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("  Warning: не удалось получить Pod IPs через kubectl: %v\n", err)
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		fmt.Printf("  Warning: ошибка парсинга kubectl output: %v\n", err)
		return
	}

	items, ok := result["items"].([]interface{})
	if !ok {
		return
	}

	podsLoaded := 0
	podIPs := []string{}

	for _, item := range items {
		pod, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		metadata, _ := pod["metadata"].(map[string]interface{})
		status, _ := pod["status"].(map[string]interface{})

		podName, _ := metadata["name"].(string)
		podNS, _ := metadata["namespace"].(string)
		podIP, _ := status["podIP"].(string)
		labelsDict, _ := metadata["labels"].(map[string]interface{})

		if podIP != "" {
			hc.IPToPod[podIP] = PodInfo{Name: podName, Namespace: podNS}
			hc.IPToNamespace[podIP] = podNS
			podsLoaded++
			podIPs = append(podIPs, podIP)

			if podNS == hc.Namespace && labelsDict != nil {
				filteredLabels := hc.filterK8sLabels(labelsDict)
				if len(filteredLabels) > 0 {
					hc.PodLabels[podName] = filteredLabels
				}
			}
		}
	}

	fmt.Printf("  Загружено %d Pod IP mappings\n", podsLoaded)

	if len(podIPs) > 0 {
		hc.autoDetectPodCIDR(podIPs)
	}
}

func (hc *HubbleCollector) autoDetectPodCIDR(podIPs []string) {
	networkPrefixes := make(map[string]int)

	for _, ipStr := range podIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		octets := strings.Split(ipStr, ".")
		if len(octets) == 4 {
			prefix := fmt.Sprintf("%s.%s.0.0/16", octets[0], octets[1])
			networkPrefixes[prefix]++
		}
	}

	if len(networkPrefixes) > 0 {
		var mostCommonCIDR string
		maxCount := 0
		for cidr, count := range networkPrefixes {
			if count > maxCount {
				maxCount = count
				mostCommonCIDR = cidr
			}
		}

		_, detectedNetwork, err := net.ParseCIDR(mostCommonCIDR)
		if err == nil {
			alreadyExists := false
			for _, network := range hc.InternalNetworks {
				if network.String() == detectedNetwork.String() {
					alreadyExists = true
					break
				}
			}

			if !alreadyExists {
				hc.InternalNetworks = append([]*net.IPNet{detectedNetwork}, hc.InternalNetworks...)
				fmt.Printf("  Auto-detected Pod CIDR: %s (%d pods)\n", mostCommonCIDR, maxCount)
			}
		}
	}
}

func (hc *HubbleCollector) fetchAllServicesIPs() {
	cmd := exec.Command("kubectl", "get", "services", "--all-namespaces", "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("  Warning: не удалось получить Service IPs через kubectl: %v\n", err)
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		fmt.Printf("  Warning: ошибка парсинга kubectl output: %v\n", err)
		return
	}

	items, ok := result["items"].([]interface{})
	if !ok {
		return
	}

	servicesLoaded := 0
	for _, item := range items {
		svc, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		metadata, _ := svc["metadata"].(map[string]interface{})
		spec, _ := svc["spec"].(map[string]interface{})

		serviceName, _ := metadata["name"].(string)
		serviceNS, _ := metadata["namespace"].(string)
		clusterIP, _ := spec["clusterIP"].(string)

		if clusterIP != "" && clusterIP != "None" {
			hc.IPToService[clusterIP] = ServiceInfo{Name: serviceName, Namespace: serviceNS}
			hc.IPToNamespace[clusterIP] = serviceNS
			servicesLoaded++
		}
	}

	fmt.Printf("  Загружено %d Service IP mappings\n", servicesLoaded)
}

func (hc *HubbleCollector) CollectFlows(duration int, follow bool) {
	args := []string{
		"observe", "flows",
		"--namespace", hc.Namespace,
		"--output", "json",
	}

	if hc.FromLabel != "" {
		args = append(args, "--from-label", hc.FromLabel)
	}

	if hc.ToLabel != "" {
		args = append(args, "--to-label", hc.ToLabel)
	}

	if hc.Verdict != "" {
		args = append(args, "--verdict", strings.ToUpper(hc.Verdict))
	}

	if !follow {
		args = append(args, "--last", fmt.Sprintf("%d", duration))
	} else {
		args = append(args, "--follow")
	}

	fmt.Printf("Запуск: hubble %s\n", strings.Join(args, " "))

	cmd := exec.Command("hubble", args...)

	if follow {
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			os.Exit(1)
		}

		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Мониторинг flows в namespace '%s'...\n", hc.Namespace)

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				var flow map[string]interface{}
				if err := json.Unmarshal([]byte(line), &flow); err == nil {
					hc.Flows = append(hc.Flows, flow)
					hc.processFlow(flow)
				}
			}
		}

		cmd.Wait()
	} else {
		output, err := cmd.Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
			os.Exit(1)
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if line != "" {
				var flow map[string]interface{}
				if err := json.Unmarshal([]byte(line), &flow); err == nil {
					hc.Flows = append(hc.Flows, flow)
					hc.processFlow(flow)
				}
			}
		}
	}
}

func (hc *HubbleCollector) processFlow(flow map[string]interface{}) {
	flowData, ok := flow["flow"].(map[string]interface{})
	if !ok {
		return
	}

	source, _ := flowData["source"].(map[string]interface{})
	destination, _ := flowData["destination"].(map[string]interface{})
	ipInfo, _ := flowData["IP"].(map[string]interface{})

	sourceIP := getString(ipInfo, "source", "unknown")
	destIP := getString(ipInfo, "destination", "unknown")

	sourceNS := getString(source, "namespace", "")
	destNS := getString(destination, "namespace", "")

	if sourceNS != hc.Namespace && destNS != hc.Namespace {
		return
	}

	// Process source pod labels and IP mapping
	sourcePodName := getString(source, "pod_name", "")
	if sourcePodName != "" && sourceNS != "" {
		sourceLabels := getStringSlice(source, "labels")
		if len(sourceLabels) > 0 {
			parsedLabels := hc.parseLabels(sourceLabels)
			hc.mu.Lock()
			hc.PodLabels[sourcePodName] = parsedLabels
			hc.mu.Unlock()
		}
		if sourceIP != "unknown" {
			hc.mu.Lock()
			hc.IPToPod[sourceIP] = PodInfo{Name: sourcePodName, Namespace: sourceNS}
			hc.mu.Unlock()
		}
	}

	// Process dest pod labels and IP mapping
	destPodName := getString(destination, "pod_name", "")
	if destPodName != "" && destNS != "" {
		destLabels := getStringSlice(destination, "labels")
		if len(destLabels) > 0 {
			parsedLabels := hc.parseLabels(destLabels)
			hc.mu.Lock()
			hc.PodLabels[destPodName] = parsedLabels
			hc.mu.Unlock()
		}
		if destIP != "unknown" {
			hc.mu.Lock()
			hc.IPToPod[destIP] = PodInfo{Name: destPodName, Namespace: destNS}
			hc.mu.Unlock()
		}
	}

	// Build source pod string
	sourcePod := getString(source, "pod_name", "")
	if sourcePod == "" {
		sourcePod = hc.buildSourcePodName(source, sourceIP)
	}

	// Build dest pod string
	destPod := getString(destination, "pod_name", "")
	destPort := destination["port"]

	l4Proto, _ := flowData["l4"].(map[string]interface{})
	protocol := "unknown"
	if len(l4Proto) > 0 {
		for k := range l4Proto {
			protocol = strings.ToUpper(k)
			break
		}
	}

	if destPod == "" {
		destPod = hc.buildDestPodName(destination, destIP, destPort, l4Proto, protocol)
	} else if destPort != nil {
		destPod = fmt.Sprintf("%s:%v/%s", destPod, destPort, protocol)
	}

	if sourcePod != "" && destPod != "" && sourcePod != destPod {
		hc.mu.Lock()
		if hc.Connections[sourcePod] == nil {
			hc.Connections[sourcePod] = make(map[string]int)
		}
		hc.Connections[sourcePod][destPod]++

		flowDetail := FlowDetail{
			SourcePod:    sourcePodName,
			SourceNS:     sourceNS,
			SourceIP:     sourceIP,
			DestPod:      destPodName,
			DestNS:       destNS,
			DestIP:       destIP,
			DestPort:     destPort,
			Protocol:     strings.ToLower(protocol),
			SourceLabels: getStringSlice(source, "labels"),
			DestLabels:   getStringSlice(destination, "labels"),
			RawFlow:      flow,
		}

		if hc.FlowDetails[sourcePod] == nil {
			hc.FlowDetails[sourcePod] = make(map[string][]FlowDetail)
		}
		hc.FlowDetails[sourcePod][destPod] = append(hc.FlowDetails[sourcePod][destPod], flowDetail)
		hc.mu.Unlock()
	}
}

func (hc *HubbleCollector) buildSourcePodName(source map[string]interface{}, sourceIP string) string {
	workloads := getSlice(source, "workloads")
	if len(workloads) > 0 {
		if workload, ok := workloads[0].(map[string]interface{}); ok {
			workloadName := getString(workload, "name", "")
			workloadKind := getString(workload, "kind", "")
			if workloadName != "" {
				return fmt.Sprintf("%s (%s)", workloadName, workloadKind)
			}
		}
		return sourceIP
	}

	sourceLabels := getStringSlice(source, "labels")
	sourceInfo := []string{}
	for _, label := range sourceLabels {
		if strings.Contains(label, "reserved:") {
			sourceInfo = append(sourceInfo, strings.Replace(label, "reserved:", "", 1))
		}
	}

	if len(sourceInfo) > 0 {
		return fmt.Sprintf("%s (%s)", sourceIP, strings.Join(sourceInfo, ", "))
	}

	return sourceIP
}

func (hc *HubbleCollector) buildDestPodName(destination map[string]interface{}, destIP string, destPort interface{}, l4Proto map[string]interface{}, protocol string) string {
	workloads := getSlice(destination, "workloads")
	if len(workloads) > 0 {
		if workload, ok := workloads[0].(map[string]interface{}); ok {
			workloadName := getString(workload, "name", "")
			if workloadName != "" {
				return workloadName
			}
		}
	}

	destIdentity := destination["identity"]
	var destLabels []string

	if identityMap, ok := destIdentity.(map[string]interface{}); ok {
		destLabels = getStringSlice(identityMap, "labels")
	} else {
		destLabels = getStringSlice(destination, "labels")
	}

	service := destination["service"]
	var serviceName string
	if serviceMap, ok := service.(map[string]interface{}); ok {
		serviceName = getString(serviceMap, "name", "")
	}

	destNSName := getString(destination, "namespace", "")

	if destPort == nil && len(l4Proto) > 0 {
		for _, protoData := range l4Proto {
			if protoMap, ok := protoData.(map[string]interface{}); ok {
				destPort = protoMap["destination_port"]
				break
			}
		}
	}

	destInfo := []string{}
	for _, label := range destLabels {
		if strings.Contains(label, "reserved:") {
			destInfo = append(destInfo, strings.Replace(label, "reserved:", "", 1))
		} else if strings.Contains(label, "cidr:") {
			parts := strings.Split(label, "=")
			if len(parts) > 1 {
				destInfo = append(destInfo, parts[1])
			} else {
				destInfo = append(destInfo, label)
			}
		}
	}

	if serviceName != "" && destNSName != "" {
		return fmt.Sprintf("%s.%s:%v/%s", serviceName, destNSName, destPort, protocol)
	} else if serviceName != "" {
		return fmt.Sprintf("%s:%v/%s", serviceName, destPort, protocol)
	} else if len(destInfo) > 0 {
		return fmt.Sprintf("%s:%v/%s (%s)", destIP, destPort, protocol, strings.Join(destInfo, ", "))
	} else if destIP != "unknown" && destPort != nil {
		return fmt.Sprintf("%s:%v/%s", destIP, destPort, protocol)
	} else if destIP != "unknown" {
		return fmt.Sprintf("%s/%s", destIP, protocol)
	}

	return fmt.Sprintf("unknown/%s", protocol)
}

func (hc *HubbleCollector) parseLabels(labelsList []string) map[string]string {
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

		shouldExclude := false
		for _, prefix := range excludePrefixes {
			if strings.HasPrefix(key, prefix) {
				shouldExclude = true
				break
			}
		}

		if shouldExclude {
			continue
		}

		if strings.Contains(key, "k8s.namespace.labels") {
			continue
		}

		if key == "k8s.policy.cluster" || key == "k8s.policy.serviceaccount" {
			continue
		}

		if strings.HasPrefix(key, "io.cilium.k8s.policy") {
			continue
		}

		if key == "io.kubernetes.pod.namespace" {
			continue
		}

		labels[key] = value
	}

	return labels
}

func (hc *HubbleCollector) filterK8sLabels(labelsDict map[string]interface{}) map[string]string {
	filtered := make(map[string]string)
	for key, value := range labelsDict {
		shouldExclude := false
		for _, prefix := range excludePrefixes {
			if strings.HasPrefix(key, prefix) {
				shouldExclude = true
				break
			}
		}

		if shouldExclude {
			continue
		}

		if strings.Contains(key, "k8s.namespace.labels") {
			continue
		}

		if key == "k8s.policy.cluster" || key == "k8s.policy.serviceaccount" {
			continue
		}

		if strings.HasPrefix(key, "io.cilium.k8s.policy") {
			continue
		}

		if key == "io.kubernetes.pod.namespace" {
			continue
		}

		if str, ok := value.(string); ok {
			filtered[key] = str
		}
	}

	return filtered
}

func (hc *HubbleCollector) resolveIPToPod(ip string) *PodInfo {
	// This function should only read from maps, no writes
	// Note: caller must hold at least RLock
	if podInfo, ok := hc.IPToPod[ip]; ok {
		return &podInfo
	}

	if hc.UnresolvedIPs[ip] {
		return nil
	}

	if _, ok := hc.IPToService[ip]; ok {
		return nil
	}

	// IP not in cache, not a service, and not previously marked unresolved
	return nil
}

func (hc *HubbleCollector) isExternalIP(ip string) bool {
	if ip == "unknown" {
		return false
	}

	if _, ok := hc.IPToPod[ip]; ok {
		return false
	}

	if _, ok := hc.IPToNamespace[ip]; ok {
		return false
	}

	ipObj := net.ParseIP(ip)
	if ipObj == nil {
		return false
	}

	if ipObj.IsLoopback() || ipObj.IsLinkLocalUnicast() {
		return false
	}

	// Check if IP is in any internal network
	for _, network := range hc.InternalNetworks {
		if network.Contains(ipObj) {
			return false
		}
	}

	// If it's a private IP but not in our internal networks, still consider it internal
	if isPrivateIP(ipObj) {
		return false
	}

	return true
}

func isPrivateIP(ip net.IP) bool {
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
	}

	for _, block := range privateBlocks {
		_, subnet, _ := net.ParseCIDR(block)
		if subnet.Contains(ip) {
			return true
		}
	}

	return false
}

func (hc *HubbleCollector) getDefaultPort(labels map[string]string) *PortConfig {
	if labels == nil {
		return nil
	}

	checkNames := []string{
		strings.ToLower(labels["app"]),
		strings.ToLower(labels["app.kubernetes.io/name"]),
		strings.ToLower(labels["app.kubernetes.io/component"]),
		strings.ToLower(labels["k8s-app"]),
	}

	for _, name := range checkNames {
		if config, ok := DefaultPorts[name]; ok {
			return &config
		}
	}

	for _, name := range checkNames {
		for key, config := range DefaultPorts {
			if strings.Contains(key, name) || strings.Contains(name, key) {
				return &config
			}
		}
	}

	return nil
}

func (hc *HubbleCollector) ExportToJSON(filepath string) error {
	data := map[string]interface{}{
		"namespace":    hc.Namespace,
		"collected_at": time.Now().UTC().Format(time.RFC3339),
		"total_flows":  len(hc.Flows),
		"filters": map[string]string{
			"from_label": hc.FromLabel,
			"to_label":   hc.ToLabel,
			"verdict":    hc.Verdict,
		},
		"connections": []map[string]interface{}{},
	}

	sources := []string{}
	for source := range hc.Connections {
		sources = append(sources, source)
	}
	sort.Strings(sources)

	connections := []map[string]interface{}{}
	for _, source := range sources {
		destinations := hc.Connections[source]
		destKeys := []string{}
		for dest := range destinations {
			destKeys = append(destKeys, dest)
		}
		sort.Strings(destKeys)

		for _, dest := range destKeys {
			connections = append(connections, map[string]interface{}{
				"source":      source,
				"destination": dest,
				"flows_count": destinations[dest],
			})
		}
	}

	data["connections"] = connections

	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return err
	}

	fmt.Printf("Экспорт: %s\n", filepath)
	return nil
}

func (hc *HubbleCollector) PrintSummary() {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Printf("Namespace: %s\n", hc.Namespace)
	if hc.FromLabel != "" {
		fmt.Printf("From Label: %s\n", hc.FromLabel)
	}
	if hc.ToLabel != "" {
		fmt.Printf("To Label: %s\n", hc.ToLabel)
	}
	if hc.Verdict != "" {
		fmt.Printf("Verdict: %s\n", hc.Verdict)
	}
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Flows: %d\n", len(hc.Flows))

	totalConnections := 0
	for _, destinations := range hc.Connections {
		totalConnections += len(destinations)
	}
	fmt.Printf("Unique Connections: %d\n", totalConnections)
	fmt.Println("\nNetwork Connections:")
	fmt.Println(strings.Repeat("-", 70))

	sources := []string{}
	for source := range hc.Connections {
		sources = append(sources, source)
	}
	sort.Strings(sources)

	for _, source := range sources {
		destinations := hc.Connections[source]

		type destCount struct {
			dest  string
			count int
		}
		destCounts := []destCount{}
		for dest, count := range destinations {
			destCounts = append(destCounts, destCount{dest, count})
		}
		sort.Slice(destCounts, func(i, j int) bool {
			return destCounts[i].count > destCounts[j].count
		})

		for _, dc := range destCounts {
			fmt.Printf("  %-40s → %-40s (%d flows)\n", source, dc.dest, dc.count)
		}
	}

	fmt.Println(strings.Repeat("=", 70))
}

func (hc *HubbleCollector) ExportCiliumPolicies(outputDir string) ([]string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, err
	}

	policiesByPod := make(map[string]*PolicyData)
	unresolvedIPs := make(map[string]bool) // Track IPs we couldn't resolve

	// Lock for reading FlowDetails
	hc.mu.RLock()
	for _, destinations := range hc.FlowDetails {
		for _, flowList := range destinations {
			for _, flow := range flowList {
				sourcePod := flow.SourcePod
				sourceNS := flow.SourceNS
				sourceIP := flow.SourceIP
				destPod := flow.DestPod
				destNS := flow.DestNS
				destIP := flow.DestIP
				destPort := flow.DestPort
				protocol := flow.Protocol

				// Egress rules
				if sourcePod != "" && sourceNS == hc.Namespace {
					if policiesByPod[sourcePod] == nil {
						policiesByPod[sourcePod] = &PolicyData{
							Egress:  make(map[string]*RuleInfo),
							Ingress: make(map[string]*RuleInfo),
						}
					}

					var destKey string
					if destPod != "" && destNS != "" {
						destKey = fmt.Sprintf("pod:%s/%s", destNS, destPod)
					} else if destNS != "" {
						// If we have namespace info from flow, use toEndpoints even without pod name
						destKey = fmt.Sprintf("ns:%s", destNS)
					} else if destIP != "" && destIP != "unknown" {
						if svcInfo, ok := hc.IPToService[destIP]; ok {
							destKey = fmt.Sprintf("ns:%s", svcInfo.Namespace)
						} else {
							podInfo := hc.resolveIPToPod(destIP)
							if podInfo != nil {
								destKey = fmt.Sprintf("pod:%s/%s", podInfo.Namespace, podInfo.Name)
							} else if hc.isExternalIP(destIP) {
								destKey = fmt.Sprintf("external:%s", destIP)
							} else if ns, ok := hc.IPToNamespace[destIP]; ok {
								destKey = fmt.Sprintf("ns:%s", ns)
							} else {
								// IP is internal but cannot be resolved
								// Check if it's in our internal networks
								ipObj := net.ParseIP(destIP)
								isInternal := false
								if ipObj != nil {
									for _, network := range hc.InternalNetworks {
										if network.Contains(ipObj) {
											isInternal = true
											break
										}
									}
								}

								if isInternal {
									// Skip internal IPs that cannot be resolved to avoid incorrect toCIDR rules
									fmt.Printf("  Warning: skipping internal IP %s:%v - cannot resolve to pod/namespace\n", destIP, destPort)
									unresolvedIPs[destIP] = true // Track for later
									continue
								} else {
									destKey = fmt.Sprintf("external:%s", destIP)
								}
							}
						}
					} else {
						continue
					}

					if policiesByPod[sourcePod].Egress[destKey] == nil {
						policiesByPod[sourcePod].Egress[destKey] = &RuleInfo{
							Ports:     make(map[string]bool),
							Protocols: make(map[string]bool),
						}
					}

					if destPort != nil {
						policiesByPod[sourcePod].Egress[destKey].Ports[fmt.Sprintf("%v", destPort)] = true
					}
					if protocol != "" {
						policiesByPod[sourcePod].Egress[destKey].Protocols[protocol] = true
					}
				}

				// Ingress rules
				if destPod != "" && destNS == hc.Namespace {
					if policiesByPod[destPod] == nil {
						policiesByPod[destPod] = &PolicyData{
							Egress:  make(map[string]*RuleInfo),
							Ingress: make(map[string]*RuleInfo),
						}
					}

					var sourceKey string
					if sourcePod != "" && sourceNS != "" {
						sourceKey = fmt.Sprintf("pod:%s/%s", sourceNS, sourcePod)
					} else if sourceNS != "" {
						// If we have namespace info from flow, use fromEndpoints even without pod name
						sourceKey = fmt.Sprintf("ns:%s", sourceNS)
					} else if sourceIP != "" && sourceIP != "unknown" {
						if svcInfo, ok := hc.IPToService[sourceIP]; ok {
							sourceKey = fmt.Sprintf("ns:%s", svcInfo.Namespace)
						} else {
							podInfo := hc.resolveIPToPod(sourceIP)
							if podInfo != nil {
								sourceKey = fmt.Sprintf("pod:%s/%s", podInfo.Namespace, podInfo.Name)
							} else if hc.isExternalIP(sourceIP) {
								sourceKey = fmt.Sprintf("external:%s", sourceIP)
							} else if ns, ok := hc.IPToNamespace[sourceIP]; ok {
								sourceKey = fmt.Sprintf("ns:%s", ns)
							} else {
								// IP is internal but cannot be resolved
								// Check if it's in our internal networks
								ipObj := net.ParseIP(sourceIP)
								isInternal := false
								if ipObj != nil {
									for _, network := range hc.InternalNetworks {
										if network.Contains(ipObj) {
											isInternal = true
											break
										}
									}
								}

								if isInternal {
									// Skip internal IPs that cannot be resolved to avoid incorrect fromCIDR rules
									fmt.Printf("  Warning: skipping internal source IP %s - cannot resolve to pod/namespace\n", sourceIP)
									unresolvedIPs[sourceIP] = true // Track for later
									continue
								} else {
									sourceKey = fmt.Sprintf("external:%s", sourceIP)
								}
							}
						}
					} else {
						continue
					}

					if policiesByPod[destPod].Ingress[sourceKey] == nil {
						policiesByPod[destPod].Ingress[sourceKey] = &RuleInfo{
							Ports:     make(map[string]bool),
							Protocols: make(map[string]bool),
						}
					}

					if destPort != nil {
						policiesByPod[destPod].Ingress[sourceKey].Ports[fmt.Sprintf("%v", destPort)] = true
					}
					if protocol != "" {
						policiesByPod[destPod].Ingress[sourceKey].Protocols[protocol] = true
					}
				}
			}
		}
	}
	hc.mu.RUnlock()

	// Mark unresolved IPs after releasing the read lock
	if len(unresolvedIPs) > 0 {
		hc.mu.Lock()
		for ip := range unresolvedIPs {
			hc.UnresolvedIPs[ip] = true
		}
		hc.mu.Unlock()
	}

	policyFiles := []string{}
	var policyFilesMu sync.Mutex

	// Use worker pool for parallel policy generation
	type policyJob struct {
		podName    string
		policyData *PolicyData
	}

	jobs := make(chan policyJob, len(policiesByPod))
	var wg sync.WaitGroup
	numWorkers := 10 // Parallel workers

	// Worker function
	worker := func() {
		defer wg.Done()
		for job := range jobs {
			hc.processPolicyJob(job.podName, job.policyData, outputDir, &policyFiles, &policyFilesMu)
		}
	}

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker()
	}

	// Send jobs
	for podName, policyData := range policiesByPod {
		jobs <- policyJob{podName: podName, policyData: policyData}
	}
	close(jobs)

	// Wait for completion
	wg.Wait()

	return policyFiles, nil
}

func (hc *HubbleCollector) processPolicyJob(podName string, policyData *PolicyData, outputDir string, policyFiles *[]string, mu *sync.Mutex) {
	hc.mu.RLock()
	podLabels, ok := hc.PodLabels[podName]
	if !ok || len(podLabels) == 0 {
		podLabels = hc.extractLabelsFromPodName(podName)
	}
	hc.mu.RUnlock()

	if len(podLabels) == 0 {
		fmt.Printf("Skip pod '%s' - нет labels\n", podName)
		return
	}

	// Filter out invalid labels
	validLabels := make(map[string]string)
	for k, v := range podLabels {
		if !strings.HasPrefix(k, "k8s:") && !strings.HasPrefix(k, "io.cilium") && !strings.HasPrefix(k, "io.kubernetes.pod") {
			validLabels[k] = v
		}
	}

	if len(validLabels) == 0 {
		fmt.Printf("Skip pod '%s' - все labels служебные\n", podName)
		return
	}

	policy := CiliumNetworkPolicy{
		APIVersion: "cilium.io/v2",
		Kind:       "CiliumNetworkPolicy",
		Metadata: Metadata{
			Name:      hc.sanitizeName(podName),
			Namespace: hc.Namespace,
		},
		Spec: PolicySpec{
			EndpointSelector: EndpointSelector{
				MatchLabels: validLabels,
			},
			Egress:  []EgressRule{},
			Ingress: []IngressRule{},
		},
	}

	// Build egress rules
	for destKey, destInfo := range policyData.Egress {
		parts := strings.SplitN(destKey, ":", 2)
		if len(parts) != 2 {
			continue
		}

		destType := parts[0]
		destValue := parts[1]

		egressRule := EgressRule{}
		var destPodLabels map[string]string

		switch destType {
		case "pod":
			nsParts := strings.SplitN(destValue, "/", 2)
			if len(nsParts) == 2 {
				destNS := nsParts[0]
				destPod := nsParts[1]
				hc.mu.RLock()
				destPodLabels = hc.PodLabels[destPod]
				hc.mu.RUnlock()

				if len(destPodLabels) > 0 {
					egressRule.ToEndpoints = []EndpointSelector{{MatchLabels: destPodLabels}}
				} else {
					egressRule.ToEndpoints = []EndpointSelector{{
						MatchExpressions: []MatchExpression{{
							Key:      "io.kubernetes.pod.namespace",
							Operator: "In",
							Values:   []string{destNS},
						}},
					}}
				}
			}
		case "ns":
			egressRule.ToEndpoints = []EndpointSelector{{
				MatchExpressions: []MatchExpression{{
					Key:      "io.kubernetes.pod.namespace",
					Operator: "In",
					Values:   []string{destValue},
				}},
			}}
		case "external":
			egressRule.ToCIDR = []string{fmt.Sprintf("%s/32", destValue)}
		default:
			continue
		}

		// Add default ports if missing
		if len(destInfo.Ports) == 0 || len(destInfo.Protocols) == 0 {
			defaultPort := hc.getDefaultPort(destPodLabels)
			if defaultPort != nil {
				destInfo.Ports[defaultPort.Port] = true
				destInfo.Protocols[defaultPort.Protocol] = true
				fmt.Printf("  Using default port %s/%s for %s\n", defaultPort.Port, defaultPort.Protocol, destKey)
			}
		}

		if len(destInfo.Ports) > 0 && len(destInfo.Protocols) > 0 {
			egressRule.ToPorts = []PortRule{}
			for protocol := range destInfo.Protocols {
				portRule := PortRule{
					Protocol: strings.ToUpper(protocol),
					Ports:    []PortSpec{},
				}
				ports := []string{}
				for port := range destInfo.Ports {
					ports = append(ports, port)
				}
				sort.Strings(ports)
				for _, port := range ports {
					portRule.Ports = append(portRule.Ports, PortSpec{Port: port})
				}
				egressRule.ToPorts = append(egressRule.ToPorts, portRule)
			}
		}

		if len(egressRule.ToEndpoints) > 0 || len(egressRule.ToCIDR) > 0 {
			if len(destInfo.Ports) > 0 || len(egressRule.ToCIDR) > 0 {
				policy.Spec.Egress = append(policy.Spec.Egress, egressRule)
			}
		}
	}

	// Build ingress rules
	for sourceKey, sourceInfo := range policyData.Ingress {
		parts := strings.SplitN(sourceKey, ":", 2)
		if len(parts) != 2 {
			continue
		}

		sourceType := parts[0]
		sourceValue := parts[1]

		ingressRule := IngressRule{}
		var sourcePodLabels map[string]string

		switch sourceType {
		case "pod":
			nsParts := strings.SplitN(sourceValue, "/", 2)
			if len(nsParts) == 2 {
				sourceNS := nsParts[0]
				sourcePod := nsParts[1]
				hc.mu.RLock()
				sourcePodLabels = hc.PodLabels[sourcePod]
				hc.mu.RUnlock()

				if len(sourcePodLabels) > 0 {
					ingressRule.FromEndpoints = []EndpointSelector{{MatchLabels: sourcePodLabels}}
				} else {
					ingressRule.FromEndpoints = []EndpointSelector{{
						MatchExpressions: []MatchExpression{{
							Key:      "io.kubernetes.pod.namespace",
							Operator: "In",
							Values:   []string{sourceNS},
						}},
					}}
				}
			}
		case "ns":
			ingressRule.FromEndpoints = []EndpointSelector{{
				MatchExpressions: []MatchExpression{{
					Key:      "io.kubernetes.pod.namespace",
					Operator: "In",
					Values:   []string{sourceValue},
				}},
			}}
		case "external":
			ingressRule.FromCIDR = []string{fmt.Sprintf("%s/32", sourceValue)}
		default:
			continue
		}

		// Add default ports if missing
		if len(sourceInfo.Ports) == 0 || len(sourceInfo.Protocols) == 0 {
			defaultPort := hc.getDefaultPort(sourcePodLabels)
			if defaultPort != nil {
				sourceInfo.Ports[defaultPort.Port] = true
				sourceInfo.Protocols[defaultPort.Protocol] = true
				fmt.Printf("  Using default port %s/%s for ingress from %s\n", defaultPort.Port, defaultPort.Protocol, sourceKey)
			}
		}

		if len(sourceInfo.Ports) > 0 && len(sourceInfo.Protocols) > 0 {
			ingressRule.ToPorts = []PortRule{}
			for protocol := range sourceInfo.Protocols {
				portRule := PortRule{
					Protocol: strings.ToUpper(protocol),
					Ports:    []PortSpec{},
				}
				ports := []string{}
				for port := range sourceInfo.Ports {
					ports = append(ports, port)
				}
				sort.Strings(ports)
				for _, port := range ports {
					portRule.Ports = append(portRule.Ports, PortSpec{Port: port})
				}
				ingressRule.ToPorts = append(ingressRule.ToPorts, portRule)
			}
		}

		if len(ingressRule.FromEndpoints) > 0 || len(ingressRule.FromCIDR) > 0 {
			if len(sourceInfo.Ports) > 0 || len(ingressRule.FromCIDR) > 0 {
				policy.Spec.Ingress = append(policy.Spec.Ingress, ingressRule)
			}
		}
	}

	// Add DNS rule if not present
	hasDNSRule := false
	for _, rule := range policy.Spec.Egress {
		for _, endpoint := range rule.ToEndpoints {
			if endpoint.MatchLabels != nil {
				if app, ok := endpoint.MatchLabels["k8s-app"]; ok && (app == "kube-dns" || app == "coredns") {
					hasDNSRule = true
					break
				}
			}
		}
		if hasDNSRule {
			break
		}
	}

	if !hasDNSRule {
		dnsRule := EgressRule{
			ToEndpoints: []EndpointSelector{{
				MatchLabels: map[string]string{
					"io.kubernetes.pod.namespace": "kube-system",
					"k8s-app":                     "kube-dns",
				},
			}},
			ToPorts: []PortRule{{
				Protocol: "UDP",
				Ports:    []PortSpec{{Port: "53"}},
			}},
		}
		policy.Spec.Egress = append(policy.Spec.Egress, dnsRule)
	}

	// Validate policy
	if valid, err := hc.validatePolicy(&policy); !valid {
		fmt.Printf("ОШИБКА валидации политики '%s': %s\n", podName, err)
		fmt.Println("Политика пропущена. Проверь flows для этого пода.")
		return
	}

	filename := fmt.Sprintf("%s-cnp.yaml", hc.sanitizeName(podName))
	filepath := fmt.Sprintf("%s/%s", outputDir, filename)

	file, err := os.Create(filepath)
	if err != nil {
		fmt.Printf("  Error creating policy file '%s': %v\n", filepath, err)
		return
	}

	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)
	if err := encoder.Encode(&policy); err != nil {
		file.Close()
		fmt.Printf("  Error encoding policy '%s': %v\n", podName, err)
		return
	}
	file.Close()

	mu.Lock()
	*policyFiles = append(*policyFiles, filepath)
	mu.Unlock()

	egressCount := len(policy.Spec.Egress)
	ingressCount := len(policy.Spec.Ingress)
	fmt.Printf("Создана политика: %s (egress: %d rules, ingress: %d rules)\n", filepath, egressCount, ingressCount)
}


func (hc *HubbleCollector) sanitizeName(name string) string {
	// Remove pod hash suffixes using cached regex
	name = regexPodHash1.ReplaceAllString(name, "")
	name = regexPodHash2.ReplaceAllString(name, "")

	// Convert to lowercase and replace invalid chars
	name = strings.ToLower(name)
	name = regexInvalidChars.ReplaceAllString(name, "-")

	// Remove duplicate hyphens
	name = regexDuplicateDash.ReplaceAllString(name, "-")

	name = strings.Trim(name, "-")

	if len(name) > 63 {
		name = name[:63]
		name = strings.TrimRight(name, "-")
	}

	return name
}

func (hc *HubbleCollector) extractLabelsFromPodName(podName string) map[string]string {
	baseName := regexPodHash1.ReplaceAllString(podName, "")
	baseName = regexPodHash2.ReplaceAllString(baseName, "")
	baseName = regexStatefulSet.ReplaceAllString(baseName, "")

	if baseName != "" && baseName != podName {
		return map[string]string{"app": baseName}
	}

	return map[string]string{}
}

func (hc *HubbleCollector) validatePolicy(policy *CiliumNetworkPolicy) (bool, string) {
	if policy.Spec.EndpointSelector.MatchLabels == nil && policy.Spec.EndpointSelector.MatchExpressions == nil {
		return false, "endpointSelector must have matchLabels or matchExpressions"
	}

	for idx, rule := range policy.Spec.Egress {
		for _, endpoint := range rule.ToEndpoints {
			if endpoint.MatchLabels == nil && endpoint.MatchExpressions == nil {
				return false, fmt.Sprintf("Egress rule #%d: endpoint needs matchLabels or matchExpressions", idx)
			}

			for key := range endpoint.MatchLabels {
				if strings.HasPrefix(key, "k8s:") {
					return false, fmt.Sprintf("Egress rule #%d: invalid label key '%s' with 'k8s:' prefix", idx, key)
				}
			}
		}
	}

	for idx, rule := range policy.Spec.Ingress {
		for _, endpoint := range rule.FromEndpoints {
			if endpoint.MatchLabels == nil && endpoint.MatchExpressions == nil {
				return false, fmt.Sprintf("Ingress rule #%d: endpoint needs matchLabels or matchExpressions", idx)
			}

			for key := range endpoint.MatchLabels {
				if strings.HasPrefix(key, "k8s:") {
					return false, fmt.Sprintf("Ingress rule #%d: invalid label key '%s' with 'k8s:' prefix", idx, key)
				}
			}
		}
	}

	return true, ""
}

// Helper functions
func getString(m map[string]interface{}, key string, defaultValue string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultValue
}

func getStringSlice(m map[string]interface{}, key string) []string {
	if val, ok := m[key]; ok {
		if slice, ok := val.([]interface{}); ok {
			result := []string{}
			for _, item := range slice {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
	}
	return []string{}
}

func getSlice(m map[string]interface{}, key string) []interface{} {
	if val, ok := m[key]; ok {
		if slice, ok := val.([]interface{}); ok {
			return slice
		}
	}
	return []interface{}{}
}

func main() {
	namespace := flag.String("n", "", "Namespace (required)")
	output := flag.String("o", "", "Выходной JSON файл (required)")
	follow := flag.Bool("follow", false, "Режим follow")
	duration := flag.Int("duration", 60, "Секунд (default: 60)")
	fromLabel := flag.String("from-label", "", "Фильтр по source label")
	toLabel := flag.String("to-label", "", "Фильтр по destination label")
	verdict := flag.String("verdict", "", "Фильтр по verdict (FORWARDED, DROPPED, ERROR, AUDIT, REDIRECTED, TRACED)")
	debugFlows := flag.String("debug-flows", "", "Сохранить raw flows")
	cilium := flag.String("cilium", "false", "Создать CiliumNetworkPolicy (default: false)")
	ciliumOutputDir := flag.String("cilium-output-dir", "./cilium-policies", "Директория для политик (default: ./cilium-policies)")
	podCIDR := flag.String("pod-cidr", "", "Pod CIDR (например: 10.244.0.0/16)")
	serviceCIDR := flag.String("service-cidr", "", "Service CIDR (например: 10.96.0.0/12)")

	flag.Parse()

	if *namespace == "" || *output == "" {
		flag.Usage()
		os.Exit(1)
	}

	collector := NewHubbleCollector(*namespace, *fromLabel, *toLabel, *verdict, *podCIDR, *serviceCIDR)

	fmt.Printf("Сбор flows из: %s\n", *namespace)
	if *fromLabel != "" {
		fmt.Printf("   From Label: %s\n", *fromLabel)
	}
	if *toLabel != "" {
		fmt.Printf("   To Label: %s\n", *toLabel)
	}
	if *verdict != "" {
		fmt.Printf("   Verdict: %s\n", *verdict)
	}

	collector.CollectFlows(*duration, *follow)
	collector.PrintSummary()
	if err := collector.ExportToJSON(*output); err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка экспорта JSON: %v\n", err)
		os.Exit(1)
	}

	if *cilium == "true" {
		fmt.Println("\nГенерация CiliumNetworkPolicy...")
		policyFiles, err := collector.ExportCiliumPolicies(*ciliumOutputDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nОшибка создания политик: %v\n", err)
		} else {
			fmt.Printf("\nСоздано %d файлов политик в '%s'\n", len(policyFiles), *ciliumOutputDir)
		}
	}

	if *debugFlows != "" {
		file, err := os.Create(*debugFlows)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка создания debug файла: %v\n", err)
		} else {
			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")
			encoder.Encode(collector.Flows)
			file.Close()
			fmt.Printf("Debug flows: %s\n", *debugFlows)
		}
	}

	fmt.Printf("\nВсего flows: %d\n", len(collector.Flows))
}
