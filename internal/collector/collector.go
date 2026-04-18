package collector

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/network-policy-generator/internal/flow"
	"github.com/network-policy-generator/internal/k8s"
	"github.com/network-policy-generator/internal/network"
	"github.com/network-policy-generator/internal/policy"
	"github.com/network-policy-generator/internal/types"
)

// HubbleCollector orchestrates flow collection and policy generation.
type HubbleCollector struct {
	namespace     string
	allNamespaces bool
	fromLabel     string
	toLabel       string
	verdict       string

	commander        k8s.Commander
	internalNetworks []*net.IPNet
	ipToService      map[string]types.ServiceInfo

	store     *flow.ConnectionStore
	rawFlows  []map[string]interface{} // populated only when debug capture is requested
	flowCount int
}

// New creates a HubbleCollector, loading pod and service IP mappings from kubectl.
func New(
	namespace string,
	allNamespaces bool,
	fromLabel, toLabel, verdict string,
	podCIDR, serviceCIDR string,
	cmd k8s.Commander,
) (*HubbleCollector, error) {
	nets, err := network.ParseCIDRs(podCIDR, serviceCIDR)
	if err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	hc := &HubbleCollector{
		namespace:        namespace,
		allNamespaces:    allNamespaces,
		fromLabel:        fromLabel,
		toLabel:          toLabel,
		verdict:          verdict,
		commander:        cmd,
		internalNetworks: nets,
		ipToService:      make(map[string]types.ServiceInfo),
		store:            flow.NewConnectionStore(),
	}

	fmt.Println("Loading Pod IP mappings from cluster...")
	podRes, err := k8s.FetchAllPodsIPs(cmd)
	if err != nil {
		fmt.Printf("  Warning: %v\n", err)
	} else {
		for ip, podInfo := range podRes.IPToPod {
			hc.store.IPToPod[ip] = podInfo
			hc.store.IPToNamespace[ip] = podInfo.Namespace
		}
		for podName, lbls := range podRes.PodLabels {
			hc.store.PodLabels[podName] = lbls
		}
		fmt.Printf("  Loaded %d Pod IP mappings\n", len(podRes.IPToPod))

		if detected := network.AutoDetectPodCIDR(podRes.PodIPs, hc.internalNetworks); detected != nil {
			hc.internalNetworks = append([]*net.IPNet{detected}, hc.internalNetworks...)
			fmt.Printf("  Auto-detected Pod CIDR: %s\n", detected.String())
		}
	}

	fmt.Println("Loading Service IP mappings from cluster...")
	svcRes, err := k8s.FetchAllServicesIPs(cmd)
	if err != nil {
		fmt.Printf("  Warning: %v\n", err)
	} else {
		hc.ipToService = svcRes.IPToService
		for ip, ns := range svcRes.IPToNamespace {
			hc.store.IPToNamespace[ip] = ns
		}
		fmt.Printf("  Loaded %d Service IP mappings\n", len(svcRes.IPToService))
	}

	return hc, nil
}

// CollectFlows runs hubble observe and processes all resulting flows.
// When follow=true, streams until Ctrl-C. Otherwise collects --last duration flows.
// Set captureRaw=true to store raw flow JSON for the --debug-flows flag.
func (hc *HubbleCollector) CollectFlows(duration int, follow bool, captureRaw bool) error {
	_ = captureRaw // raw capture can be added via ProcessFlow callback if needed

	ns := hc.namespace
	if hc.allNamespaces {
		ns = ""
	}

	args := []string{"observe", "flows", "--output", "json"}
	if hc.allNamespaces {
		args = append(args, "--all-namespaces")
	} else {
		args = append(args, "--namespace", hc.namespace)
	}
	if hc.fromLabel != "" {
		args = append(args, "--from-label", hc.fromLabel)
	}
	if hc.toLabel != "" {
		args = append(args, "--to-label", hc.toLabel)
	}
	if hc.verdict != "" {
		args = append(args, "--verdict", strings.ToUpper(hc.verdict))
	}
	if follow {
		args = append(args, "--follow")
	} else {
		args = append(args, "--last", fmt.Sprintf("%d", duration))
	}

	fmt.Printf("Running: hubble %s\n", strings.Join(args, " "))

	var count int
	var err error
	if follow {
		count, err = flow.CollectStream(hc.commander, args, hc.store, ns)
	} else {
		count, err = flow.CollectBatch(hc.commander, args, hc.store, ns)
	}
	if err != nil {
		return err
	}
	hc.flowCount = count
	return nil
}

// PrintSummary prints the collected flow statistics to stdout.
func (hc *HubbleCollector) PrintSummary() {
	sep := strings.Repeat("=", 70)
	fmt.Println("\n" + sep)
	if hc.allNamespaces {
		fmt.Println("Namespace: all")
	} else {
		fmt.Printf("Namespace: %s\n", hc.namespace)
	}
	if hc.fromLabel != "" {
		fmt.Printf("From Label: %s\n", hc.fromLabel)
	}
	if hc.toLabel != "" {
		fmt.Printf("To Label: %s\n", hc.toLabel)
	}
	if hc.verdict != "" {
		fmt.Printf("Verdict: %s\n", hc.verdict)
	}
	fmt.Println(sep)
	fmt.Printf("Flows: %d\n", hc.flowCount)

	hc.store.Mu.RLock()
	totalConns := 0
	for _, dests := range hc.store.Connections {
		totalConns += len(dests)
	}
	fmt.Printf("Unique Connections: %d\n", totalConns)
	fmt.Println("\nNetwork Connections:")
	fmt.Println(strings.Repeat("-", 70))

	sources := make([]string, 0, len(hc.store.Connections))
	for src := range hc.store.Connections {
		sources = append(sources, src)
	}
	sort.Strings(sources)

	for _, src := range sources {
		type dc struct{ dest string; count int }
		var dcs []dc
		for dest, cnt := range hc.store.Connections[src] {
			dcs = append(dcs, dc{dest, cnt})
		}
		sort.Slice(dcs, func(i, j int) bool { return dcs[i].count > dcs[j].count })
		for _, d := range dcs {
			fmt.Printf("  %-40s → %-40s (%d flows)\n", src, d.dest, d.count)
		}
	}
	hc.store.Mu.RUnlock()
	fmt.Println(sep)
}

// ExportToJSON writes the connection graph to a JSON file.
func (hc *HubbleCollector) ExportToJSON(filePath string) error {
	hc.store.Mu.RLock()
	defer hc.store.Mu.RUnlock()

	sources := make([]string, 0, len(hc.store.Connections))
	for src := range hc.store.Connections {
		sources = append(sources, src)
	}
	sort.Strings(sources)

	var connections []map[string]interface{}
	for _, src := range sources {
		dests := make([]string, 0, len(hc.store.Connections[src]))
		for dest := range hc.store.Connections[src] {
			dests = append(dests, dest)
		}
		sort.Strings(dests)
		for _, dest := range dests {
			connections = append(connections, map[string]interface{}{
				"source":      src,
				"destination": dest,
				"flows_count": hc.store.Connections[src][dest],
			})
		}
	}
	if connections == nil {
		connections = []map[string]interface{}{}
	}

	data := map[string]interface{}{
		"namespace":    hc.namespace,
		"collected_at": time.Now().UTC().Format(time.RFC3339),
		"total_flows":  hc.flowCount,
		"filters": map[string]string{
			"from_label": hc.fromLabel,
			"to_label":   hc.toLabel,
			"verdict":    hc.verdict,
		},
		"connections": connections,
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return err
	}
	fmt.Printf("Exported: %s\n", filePath)
	return nil
}

// ExportCiliumPolicies generates CiliumNetworkPolicy YAML files for all observed
// pods and writes them to outputDir (organised in per-namespace subdirectories).
func (hc *HubbleCollector) ExportCiliumPolicies(outputDir string) ([]string, error) {
	hc.store.Mu.RLock()
	flowDetails := hc.store.FlowDetails
	podLabels := hc.store.PodLabels
	ipToPod := hc.store.IPToPod
	ipToNS := hc.store.IPToNamespace
	hc.store.Mu.RUnlock()

	ns := hc.namespace
	if hc.allNamespaces {
		ns = ""
	}

	policiesByPod, unresolvedIPs := policy.BuildPoliciesFromFlows(
		flowDetails, ns, ipToPod, ipToNS, hc.ipToService, hc.internalNetworks,
	)

	if len(unresolvedIPs) > 0 {
		fmt.Printf("  %d internal IPs could not be resolved to pods/namespaces\n", len(unresolvedIPs))
	}

	return policy.ExportPolicies(podLabels, policiesByPod, outputDir)
}

// SaveRawFlows writes the raw flow JSON array to filePath.
func (hc *HubbleCollector) SaveRawFlows(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(hc.rawFlows)
}

// FlowCount returns the total number of flows processed.
func (hc *HubbleCollector) FlowCount() int { return hc.flowCount }
