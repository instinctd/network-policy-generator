package flow

import (
	"fmt"
	"sort"
	"sync"
)

const (
	ReasonNilEndpoint    = "nil_endpoint"
	ReasonNoL4           = "no_l4"
	ReasonEmptyNamespace = "empty_namespace"
	ReasonWorldNoIP      = "world_no_ip"
	ReasonUnknownProto   = "unknown_protocol"
)

type UnhandledTracker struct {
	mu       sync.Mutex
	counters map[string]int64
}

func NewUnhandledTracker() *UnhandledTracker {
	return &UnhandledTracker{counters: make(map[string]int64)}
}

func (t *UnhandledTracker) Track(reason string) {
	t.mu.Lock()
	t.counters[reason]++
	t.mu.Unlock()
}

func (t *UnhandledTracker) Summary() map[string]int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]int64, len(t.counters))
	for k, v := range t.counters {
		out[k] = v
	}
	return out
}

func (t *UnhandledTracker) Print() {
	summary := t.Summary()
	if len(summary) == 0 {
		return
	}
	keys := make([]string, 0, len(summary))
	for k := range summary {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("Skipped flows summary:")
	for _, k := range keys {
		fmt.Printf("  %-25s %d\n", k+":", summary[k])
	}
}
