package hubble

import (
	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// FlowToMap converts a protobuf *flowpb.Flow to the map[string]interface{} shape
// that flow.ConnectionStore.ProcessFlow expects (matching hubble observe --output json).
func FlowToMap(f *flowpb.Flow) map[string]interface{} {
	src := f.GetSource()
	dst := f.GetDestination()
	ip := f.GetIP()

	proto, dstPort := extractL4(f.GetL4())

	srcMap := map[string]interface{}{
		"namespace": src.GetNamespace(),
		"pod_name":  src.GetPodName(),
		"labels":    labelsToSlice(src.GetLabels()),
	}

	dstMap := map[string]interface{}{
		"namespace": dst.GetNamespace(),
		"pod_name":  dst.GetPodName(),
		"labels":    labelsToSlice(dst.GetLabels()),
	}
	if dstPort != 0 {
		dstMap["port"] = float64(dstPort)
	}

	flowMap := map[string]interface{}{
		"source":      srcMap,
		"destination": dstMap,
		"IP": map[string]interface{}{
			"source":      ip.GetSource(),
			"destination": ip.GetDestination(),
		},
	}

	// Build the l4 sub-map in the same shape as hubble JSON output:
	// {"l4": {"TCP": {"destination_port": 8080}}}
	if proto != "" && dstPort != 0 {
		flowMap["l4"] = map[string]interface{}{
			proto: map[string]interface{}{
				"destination_port": float64(dstPort),
			},
		}
	}

	return map[string]interface{}{"flow": flowMap}
}

func labelsToSlice(labels []string) []interface{} {
	out := make([]interface{}, len(labels))
	for i, l := range labels {
		out[i] = l
	}
	return out
}

func extractL4(l4 *flowpb.Layer4) (proto string, port uint32) {
	if l4 == nil {
		return "", 0
	}
	switch {
	case l4.GetTCP() != nil:
		return "TCP", l4.GetTCP().GetDestinationPort()
	case l4.GetUDP() != nil:
		return "UDP", l4.GetUDP().GetDestinationPort()
	case l4.GetSCTP() != nil:
		return "SCTP", l4.GetSCTP().GetDestinationPort()
	}
	return "", 0
}
