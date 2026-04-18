package k8s

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"

	"github.com/network-policy-generator/internal/labels"
	"github.com/network-policy-generator/internal/types"
)

// Commander abstracts subprocess execution for testability.
type Commander interface {
	// Output runs a command and returns its combined stdout.
	Output(name string, args ...string) ([]byte, error)
	// StdoutPipe starts a command and returns its stdout pipe, a Wait function,
	// and an error. The caller must call the Wait function after reading the pipe.
	StdoutPipe(name string, args ...string) (io.ReadCloser, func() error, error)
}

// ExecCommander implements Commander using os/exec.
type ExecCommander struct{}

// NewExecCommander returns the real Commander backed by os/exec.
func NewExecCommander() *ExecCommander { return &ExecCommander{} }

func (e *ExecCommander) Output(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

func (e *ExecCommander) StdoutPipe(name string, args ...string) (io.ReadCloser, func() error, error) {
	cmd := exec.Command(name, args...)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return pipe, cmd.Wait, nil
}

// PodFetchResult holds the results of fetching all pod information.
type PodFetchResult struct {
	IPToPod       map[string]types.PodInfo
	IPToNamespace map[string]string
	PodLabels     map[string]map[string]string // podName → filtered labels (all namespaces)
	PodIPs        []string
}

// FetchAllPodsIPs runs kubectl to load all pod IP mappings and labels.
func FetchAllPodsIPs(cmd Commander) (*PodFetchResult, error) {
	output, err := cmd.Output("kubectl", "get", "pods", "--all-namespaces", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("kubectl get pods: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("parse kubectl output: %w", err)
	}

	items, ok := result["items"].([]interface{})
	if !ok {
		return &PodFetchResult{
			IPToPod:       make(map[string]types.PodInfo),
			IPToNamespace: make(map[string]string),
			PodLabels:     make(map[string]map[string]string),
		}, nil
	}

	res := &PodFetchResult{
		IPToPod:       make(map[string]types.PodInfo),
		IPToNamespace: make(map[string]string),
		PodLabels:     make(map[string]map[string]string),
	}

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

		if podIP == "" {
			continue
		}
		res.IPToPod[podIP] = types.PodInfo{Name: podName, Namespace: podNS}
		res.IPToNamespace[podIP] = podNS
		res.PodIPs = append(res.PodIPs, podIP)

		if labelsDict != nil {
			filtered := labels.FilterK8sLabels(labelsDict)
			if len(filtered) > 0 {
				res.PodLabels[podName] = filtered
			}
		}
	}

	return res, nil
}

// ServiceFetchResult holds the results of fetching all service IP mappings.
type ServiceFetchResult struct {
	IPToService   map[string]types.ServiceInfo
	IPToNamespace map[string]string
}

// FetchAllServicesIPs runs kubectl to load all service ClusterIP mappings.
func FetchAllServicesIPs(cmd Commander) (*ServiceFetchResult, error) {
	output, err := cmd.Output("kubectl", "get", "services", "--all-namespaces", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("kubectl get services: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("parse kubectl output: %w", err)
	}

	items, ok := result["items"].([]interface{})
	if !ok {
		return &ServiceFetchResult{
			IPToService:   make(map[string]types.ServiceInfo),
			IPToNamespace: make(map[string]string),
		}, nil
	}

	res := &ServiceFetchResult{
		IPToService:   make(map[string]types.ServiceInfo),
		IPToNamespace: make(map[string]string),
	}

	for _, item := range items {
		svc, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		metadata, _ := svc["metadata"].(map[string]interface{})
		spec, _ := svc["spec"].(map[string]interface{})

		name, _ := metadata["name"].(string)
		ns, _ := metadata["namespace"].(string)
		clusterIP, _ := spec["clusterIP"].(string)

		if clusterIP == "" || clusterIP == "None" {
			continue
		}
		res.IPToService[clusterIP] = types.ServiceInfo{Name: name, Namespace: ns}
		res.IPToNamespace[clusterIP] = ns
	}

	return res, nil
}
