package k8s

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"time"
)

// PortForwardToRelay starts kubectl port-forward to hubble-relay in kube-system.
// Returns the local gRPC address "localhost:<port>" and a cleanup func to stop it.
func PortForwardToRelay(ctx context.Context) (addr string, cleanup func(), err error) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return "", nil, fmt.Errorf("find free port: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cmd := exec.CommandContext(ctx,
		"kubectl", "port-forward",
		"-n", "kube-system",
		"svc/hubble-relay",
		fmt.Sprintf("%d:80", port),
	)

	if startErr := cmd.Start(); startErr != nil {
		return "", nil, fmt.Errorf("start kubectl port-forward: %w", startErr)
	}

	localAddr := fmt.Sprintf("localhost:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, dialErr := net.DialTimeout("tcp", localAddr, time.Second)
		if dialErr == nil {
			conn.Close()
			return localAddr, func() { _ = cmd.Process.Kill() }, nil
		}
		time.Sleep(300 * time.Millisecond)
	}

	_ = cmd.Process.Kill()
	return "", nil, fmt.Errorf("hubble-relay not reachable at %s after 15s (is hubble-relay running?)", localAddr)
}
