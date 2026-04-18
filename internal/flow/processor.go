package flow

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/network-policy-generator/internal/k8s"
	"github.com/network-policy-generator/internal/labels"
	"github.com/network-policy-generator/internal/types"
)

// ConnectionStore accumulates network flow data concurrently.
type ConnectionStore struct {
	Connections   map[string]map[string]int
	PodLabels     map[string]map[string]string
	FlowDetails   map[string]map[string][]types.FlowDetail
	IPToPod       map[string]types.PodInfo
	IPToNamespace map[string]string
	Mu            sync.RWMutex
}

// NewConnectionStore allocates an empty ConnectionStore.
func NewConnectionStore() *ConnectionStore {
	return &ConnectionStore{
		Connections:   make(map[string]map[string]int),
		PodLabels:     make(map[string]map[string]string),
		FlowDetails:   make(map[string]map[string][]types.FlowDetail),
		IPToPod:       make(map[string]types.PodInfo),
		IPToNamespace: make(map[string]string),
	}
}

// ProcessFlow parses a single Hubble flow JSON object and updates the store.
// namespace is the target namespace filter; pass "" to accept all namespaces.
func (cs *ConnectionStore) ProcessFlow(flow map[string]interface{}, namespace string) {
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

	// Filter: at least one endpoint must be in the target namespace.
	if namespace != "" && sourceNS != namespace && destNS != namespace {
		return
	}

	// Update label and IP caches from flow data.
	sourcePodName := getString(source, "pod_name", "")
	if sourcePodName != "" && sourceNS != "" {
		if sourceLabels := getStringSlice(source, "labels"); len(sourceLabels) > 0 {
			parsed := labels.ParseHubbleLabels(sourceLabels)
			cs.Mu.Lock()
			cs.PodLabels[sourcePodName] = parsed
			cs.Mu.Unlock()
		}
		if sourceIP != "unknown" {
			cs.Mu.Lock()
			cs.IPToPod[sourceIP] = types.PodInfo{Name: sourcePodName, Namespace: sourceNS}
			cs.IPToNamespace[sourceIP] = sourceNS
			cs.Mu.Unlock()
		}
	}

	destPodName := getString(destination, "pod_name", "")
	if destPodName != "" && destNS != "" {
		if destLabelsList := getStringSlice(destination, "labels"); len(destLabelsList) > 0 {
			parsed := labels.ParseHubbleLabels(destLabelsList)
			cs.Mu.Lock()
			cs.PodLabels[destPodName] = parsed
			cs.Mu.Unlock()
		}
		if destIP != "unknown" {
			cs.Mu.Lock()
			cs.IPToPod[destIP] = types.PodInfo{Name: destPodName, Namespace: destNS}
			cs.IPToNamespace[destIP] = destNS
			cs.Mu.Unlock()
		}
	}

	// Build human-readable source/dest identifiers.
	sourcePod := sourcePodName
	if sourcePod == "" {
		sourcePod = BuildSourcePodName(source, sourceIP)
	}

	l4Proto, _ := flowData["l4"].(map[string]interface{})
	protocol := parseProtocol(l4Proto)

	destPod := destPodName
	destPort := destination["port"]
	if destPod == "" {
		destPod = BuildDestPodName(destination, destIP, destPort, l4Proto, protocol)
	} else if destPort != nil {
		destPod = fmt.Sprintf("%s:%v/%s", destPod, destPort, protocol)
	}

	if sourcePod == "" || destPod == "" || sourcePod == destPod {
		return
	}

	cs.Mu.Lock()
	defer cs.Mu.Unlock()

	if cs.Connections[sourcePod] == nil {
		cs.Connections[sourcePod] = make(map[string]int)
	}
	cs.Connections[sourcePod][destPod]++

	detail := types.FlowDetail{
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

	if cs.FlowDetails[sourcePod] == nil {
		cs.FlowDetails[sourcePod] = make(map[string][]types.FlowDetail)
	}
	cs.FlowDetails[sourcePod][destPod] = append(cs.FlowDetails[sourcePod][destPod], detail)
}

// BuildSourcePodName constructs a readable source identifier from Hubble flow data.
func BuildSourcePodName(source map[string]interface{}, sourceIP string) string {
	workloads := getSlice(source, "workloads")
	if len(workloads) > 0 {
		if wl, ok := workloads[0].(map[string]interface{}); ok {
			name := getString(wl, "name", "")
			kind := getString(wl, "kind", "")
			if name != "" {
				return fmt.Sprintf("%s (%s)", name, kind)
			}
		}
		return sourceIP
	}

	sourceLabels := getStringSlice(source, "labels")
	var parts []string
	for _, lbl := range sourceLabels {
		if strings.Contains(lbl, "reserved:") {
			parts = append(parts, strings.Replace(lbl, "reserved:", "", 1))
		}
	}
	if len(parts) > 0 {
		return fmt.Sprintf("%s (%s)", sourceIP, strings.Join(parts, ", "))
	}
	return sourceIP
}

// BuildDestPodName constructs a readable destination identifier from Hubble flow data.
func BuildDestPodName(
	destination map[string]interface{},
	destIP string,
	destPort interface{},
	l4Proto map[string]interface{},
	protocol string,
) string {
	workloads := getSlice(destination, "workloads")
	if len(workloads) > 0 {
		if wl, ok := workloads[0].(map[string]interface{}); ok {
			if name := getString(wl, "name", ""); name != "" {
				return name
			}
		}
	}

	destIdentity := destination["identity"]
	var destLabels []string
	if idMap, ok := destIdentity.(map[string]interface{}); ok {
		destLabels = getStringSlice(idMap, "labels")
	} else {
		destLabels = getStringSlice(destination, "labels")
	}

	// Extract service info from the Hubble flow (not from kubectl cache).
	var serviceName string
	if svcMap, ok := destination["service"].(map[string]interface{}); ok {
		serviceName = getString(svcMap, "name", "")
	}
	destNS := getString(destination, "namespace", "")

	// Extract port from l4 proto data if not already set.
	if destPort == nil && len(l4Proto) > 0 {
		for _, protoData := range l4Proto {
			if protoMap, ok := protoData.(map[string]interface{}); ok {
				destPort = protoMap["destination_port"]
				break
			}
		}
	}

	var infoLabels []string
	for _, lbl := range destLabels {
		if strings.Contains(lbl, "reserved:") {
			infoLabels = append(infoLabels, strings.Replace(lbl, "reserved:", "", 1))
		} else if strings.Contains(lbl, "cidr:") {
			parts := strings.Split(lbl, "=")
			if len(parts) > 1 {
				infoLabels = append(infoLabels, parts[1])
			} else {
				infoLabels = append(infoLabels, lbl)
			}
		}
	}

	switch {
	case serviceName != "" && destNS != "":
		return fmt.Sprintf("%s.%s:%v/%s", serviceName, destNS, destPort, protocol)
	case serviceName != "":
		return fmt.Sprintf("%s:%v/%s", serviceName, destPort, protocol)
	case len(infoLabels) > 0:
		return fmt.Sprintf("%s:%v/%s (%s)", destIP, destPort, protocol, strings.Join(infoLabels, ", "))
	case destIP != "unknown" && destPort != nil:
		return fmt.Sprintf("%s:%v/%s", destIP, destPort, protocol)
	case destIP != "unknown":
		return fmt.Sprintf("%s/%s", destIP, protocol)
	default:
		return fmt.Sprintf("unknown/%s", protocol)
	}
}

// CollectBatch runs hubble with the given args and processes all output flows.
// Returns the number of flows processed.
func CollectBatch(
	cmd k8s.Commander,
	hubbleArgs []string,
	store *ConnectionStore,
	namespace string,
) (int, error) {
	output, err := cmd.Output("hubble", hubbleArgs...)
	if err != nil {
		return 0, fmt.Errorf("hubble observe: %w", err)
	}

	count := 0
	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		var flow map[string]interface{}
		if err := json.Unmarshal([]byte(line), &flow); err == nil {
			store.ProcessFlow(flow, namespace)
			count++
		}
	}
	return count, nil
}

// CollectStream runs hubble in follow mode, streaming flows until the pipe closes.
// Returns the number of flows processed.
func CollectStream(
	cmd k8s.Commander,
	hubbleArgs []string,
	store *ConnectionStore,
	namespace string,
) (int, error) {
	pipe, waitFn, err := cmd.StdoutPipe("hubble", hubbleArgs...)
	if err != nil {
		return 0, fmt.Errorf("hubble observe --follow: %w", err)
	}

	count := 0
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var flow map[string]interface{}
		if err := json.Unmarshal([]byte(line), &flow); err == nil {
			store.ProcessFlow(flow, namespace)
			count++
		}
	}

	if err := waitFn(); err != nil {
		return count, fmt.Errorf("hubble observe wait: %w", err)
	}
	return count, nil
}

// parseProtocol extracts the protocol name from an l4 map (first key wins).
func parseProtocol(l4Proto map[string]interface{}) string {
	for k := range l4Proto {
		return strings.ToUpper(k)
	}
	return "unknown"
}

// --- JSON map helpers ---

func getString(m map[string]interface{}, key, def string) string {
	if m == nil {
		return def
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

func getStringSlice(m map[string]interface{}, key string) []string {
	if m == nil {
		return nil
	}
	if v, ok := m[key]; ok {
		if sl, ok := v.([]interface{}); ok {
			result := make([]string, 0, len(sl))
			for _, item := range sl {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
			return result
		}
	}
	return nil
}

func getSlice(m map[string]interface{}, key string) []interface{} {
	if m == nil {
		return nil
	}
	if v, ok := m[key]; ok {
		if sl, ok := v.([]interface{}); ok {
			return sl
		}
	}
	return nil
}
