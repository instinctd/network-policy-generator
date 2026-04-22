package hubble

import (
	"context"
	"fmt"
	"io"
	"time"

	flowpb     "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GRPCClient connects to Hubble Relay via gRPC.
type GRPCClient struct {
	server  string
	timeout time.Duration
}

// NewGRPCClient creates a client targeting the given server address (e.g. "localhost:4245").
func NewGRPCClient(server string, timeout time.Duration) *GRPCClient {
	return &GRPCClient{server: server, timeout: timeout}
}

// StreamFlows connects to Hubble Relay and streams flows into the returned channel.
// The channel is closed when ctx is cancelled or the stream ends.
// namespaces filters flows to those where source or destination matches; nil means all.
func (c *GRPCClient) StreamFlows(ctx context.Context, namespaces []string) (<-chan *flowpb.Flow, <-chan error) {
	flows := make(chan *flowpb.Flow, 100)
	errs := make(chan error, 1)

	go func() {
		defer close(flows)
		defer close(errs)

		dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()

		//nolint:staticcheck // grpc.DialContext deprecated in newer versions but compatible
		conn, err := grpc.DialContext(dialCtx, c.server,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		if err != nil {
			errs <- fmt.Errorf("connect to hubble relay at %s: %w", c.server, err)
			return
		}
		defer conn.Close()

		client := observerpb.NewObserverClient(conn)
		req := &observerpb.GetFlowsRequest{
			Follow:    true,
			Whitelist: buildFilters(namespaces),
		}

		stream, err := client.GetFlows(ctx, req)
		if err != nil {
			errs <- fmt.Errorf("get flows stream: %w", err)
			return
		}

		for {
			resp, err := stream.Recv()
			if err == io.EOF || ctx.Err() != nil {
				return
			}
			if err != nil {
				errs <- err
				return
			}
			if f := resp.GetFlow(); f != nil {
				select {
				case flows <- f:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return flows, errs
}

func buildFilters(namespaces []string) []*flowpb.FlowFilter {
	verdicts := []flowpb.Verdict{flowpb.Verdict_FORWARDED, flowpb.Verdict_DROPPED}
	if len(namespaces) == 0 {
		return []*flowpb.FlowFilter{{Verdict: verdicts}}
	}
	filters := make([]*flowpb.FlowFilter, 0, len(namespaces)*2)
	for _, ns := range namespaces {
		filters = append(filters,
			&flowpb.FlowFilter{
				SourcePod: []string{ns + "/"},
				Verdict:   verdicts,
			},
			&flowpb.FlowFilter{
				DestinationPod: []string{ns + "/"},
				Verdict:        verdicts,
			},
		)
	}
	return filters
}
