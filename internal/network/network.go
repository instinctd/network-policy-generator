package network

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/network-policy-generator/internal/types"
)

// Compiled regex patterns for pod name sanitization.
var (
	regexPodHash1      = regexp.MustCompile(`-[a-f0-9]{8,10}-[a-z0-9]{5}$`)
	regexPodHash2      = regexp.MustCompile(`-[a-f0-9]{9,10}$`)
	regexInvalidChars  = regexp.MustCompile(`[^a-z0-9-]`)
	regexDuplicateDash = regexp.MustCompile(`-+`)
	regexStatefulSet   = regexp.MustCompile(`-\d+$`)
)

// defaultCIDRs is the fallback list when no pod/service CIDRs are provided.
var defaultCIDRs = []string{
	"10.39.0.0/16",
	"10.40.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
}

// ParseCIDRs parses podCIDR and serviceCIDR strings into net.IPNet slices.
// If both are empty the default internal network list is returned.
func ParseCIDRs(podCIDR, serviceCIDR string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	var firstErr error

	for label, cidr := range map[string]string{"pod_cidr": podCIDR, "service_cidr": serviceCIDR} {
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("invalid %s '%s': %w", label, cidr, err)
			}
			continue
		}
		networks = append(networks, network)
	}

	if len(networks) == 0 {
		for _, cidr := range defaultCIDRs {
			_, network, _ := net.ParseCIDR(cidr)
			networks = append(networks, network)
		}
	}

	return networks, firstErr
}

// AutoDetectPodCIDR inspects a list of pod IPs and returns the most common /16 network.
// Returns nil if the input is empty or detection fails.
func AutoDetectPodCIDR(podIPs []string, existing []*net.IPNet) *net.IPNet {
	prefixCount := make(map[string]int)
	for _, ipStr := range podIPs {
		octets := strings.Split(ipStr, ".")
		if len(octets) == 4 {
			prefix := fmt.Sprintf("%s.%s.0.0/16", octets[0], octets[1])
			prefixCount[prefix]++
		}
	}

	if len(prefixCount) == 0 {
		return nil
	}

	var bestCIDR string
	maxCount := 0
	for cidr, count := range prefixCount {
		if count > maxCount {
			maxCount = count
			bestCIDR = cidr
		}
	}

	_, detected, err := net.ParseCIDR(bestCIDR)
	if err != nil {
		return nil
	}

	// Don't add if already in the existing list.
	for _, n := range existing {
		if n.String() == detected.String() {
			return nil
		}
	}
	return detected
}

// IsPrivateIP returns true if the IP falls within RFC1918 or CGNAT ranges.
func IsPrivateIP(ip net.IP) bool {
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

// IsExternalIP returns true if the IP is not a known pod/service/namespace IP,
// not loopback, not link-local, and not within any internal network.
func IsExternalIP(
	ip string,
	ipToPod map[string]types.PodInfo,
	ipToNamespace map[string]string,
	internalNetworks []*net.IPNet,
) bool {
	if ip == "unknown" {
		return false
	}
	if _, ok := ipToPod[ip]; ok {
		return false
	}
	if _, ok := ipToNamespace[ip]; ok {
		return false
	}
	ipObj := net.ParseIP(ip)
	if ipObj == nil {
		return false
	}
	if ipObj.IsLoopback() || ipObj.IsLinkLocalUnicast() {
		return false
	}
	for _, network := range internalNetworks {
		if network.Contains(ipObj) {
			return false
		}
	}
	if IsPrivateIP(ipObj) {
		return false
	}
	return true
}

// SanitizeName converts a pod name into a valid Kubernetes resource name
// (lowercase, max 63 chars, no deployment hash suffixes).
func SanitizeName(name string) string {
	name = regexPodHash1.ReplaceAllString(name, "")
	name = regexPodHash2.ReplaceAllString(name, "")
	name = strings.ToLower(name)
	name = regexInvalidChars.ReplaceAllString(name, "-")
	name = regexDuplicateDash.ReplaceAllString(name, "-")
	name = strings.Trim(name, "-")
	if len(name) > 63 {
		name = name[:63]
		name = strings.TrimRight(name, "-")
	}
	return name
}

// ExtractLabelsFromPodName tries to infer an "app" label by stripping known
// hash and index suffixes from the pod name. Returns an empty map if the name
// doesn't appear to be generated (i.e. it was already the base name).
func ExtractLabelsFromPodName(podName string) map[string]string {
	baseName := regexPodHash1.ReplaceAllString(podName, "")
	baseName = regexPodHash2.ReplaceAllString(baseName, "")
	baseName = regexStatefulSet.ReplaceAllString(baseName, "")
	if baseName != "" && baseName != podName {
		return map[string]string{"app": baseName}
	}
	return map[string]string{}
}
