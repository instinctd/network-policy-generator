package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/network-policy-generator/internal/collector"
	"github.com/network-policy-generator/internal/k8s"
)

func main() {
	namespace      := flag.String("n", "", "Namespace (required unless -A is set)")
	allNamespaces  := flag.Bool("A", false, "Observe all namespaces")
	output         := flag.String("o", "", "Output JSON file (required)")
	follow         := flag.Bool("follow", false, "Follow mode (stream until Ctrl-C)")
	duration       := flag.Int("duration", 60, "Number of last flows to collect (default: 60)")
	fromLabel      := flag.String("from-label", "", "Filter by source label")
	toLabel        := flag.String("to-label", "", "Filter by destination label")
	verdict        := flag.String("verdict", "", "Filter by verdict (FORWARDED, DROPPED, ERROR, AUDIT, REDIRECTED, TRACED)")
	debugFlows     := flag.String("debug-flows", "", "Save raw flows to this file")
	cilium         := flag.String("cilium", "false", "Generate CiliumNetworkPolicy (default: false)")
	ciliumOutputDir := flag.String("cilium-output-dir", "./cilium-policies", "Directory for generated policies")
	podCIDR        := flag.String("pod-cidr", "", "Pod CIDR (e.g. 10.244.0.0/16)")
	serviceCIDR    := flag.String("service-cidr", "", "Service CIDR (e.g. 10.96.0.0/12)")

	flag.Parse()

	if *output == "" {
		fmt.Fprintln(os.Stderr, "Error: -o (output file) is required")
		flag.Usage()
		os.Exit(1)
	}
	if !*allNamespaces && *namespace == "" {
		fmt.Fprintln(os.Stderr, "Error: -n (namespace) or -A (all namespaces) is required")
		flag.Usage()
		os.Exit(1)
	}

	cmd := k8s.NewExecCommander()
	hc, err := collector.New(
		*namespace,
		*allNamespaces,
		*fromLabel, *toLabel, *verdict,
		*podCIDR, *serviceCIDR,
		cmd,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Init error: %v\n", err)
		os.Exit(1)
	}

	if *allNamespaces {
		fmt.Println("Collecting flows from all namespaces...")
	} else {
		fmt.Printf("Collecting flows from namespace: %s\n", *namespace)
	}
	if *fromLabel != "" {
		fmt.Printf("   From Label: %s\n", *fromLabel)
	}
	if *toLabel != "" {
		fmt.Printf("   To Label: %s\n", *toLabel)
	}
	if *verdict != "" {
		fmt.Printf("   Verdict: %s\n", *verdict)
	}

	if err := hc.CollectFlows(*duration, *follow, *debugFlows != ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error collecting flows: %v\n", err)
		os.Exit(1)
	}

	hc.PrintSummary()

	if err := hc.ExportToJSON(*output); err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting JSON: %v\n", err)
		os.Exit(1)
	}

	if *cilium == "true" {
		fmt.Println("\nGenerating CiliumNetworkPolicy...")
		policyFiles, err := hc.ExportCiliumPolicies(*ciliumOutputDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nError creating policies: %v\n", err)
		} else {
			fmt.Printf("\nCreated %d policy files in %q\n", len(policyFiles), *ciliumOutputDir)
		}
	}

	if *debugFlows != "" {
		if err := hc.SaveRawFlows(*debugFlows); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving debug flows: %v\n", err)
		} else {
			fmt.Printf("Debug flows saved: %s\n", *debugFlows)
		}
	}

	fmt.Printf("\nTotal flows: %d\n", hc.FlowCount())
}
