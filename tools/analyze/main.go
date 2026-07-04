package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/T0ut4t1s/portolan/pkg/graph"
	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

func main() {
	data, _ := os.ReadFile(os.Args[1])
	var snap snapshot.Snapshot
	json.Unmarshal(data, &snap)
	g := graph.Build(&snap)

	deny := map[string]bool{}
	for _, ns := range g.Namespaces {
		deny[ns.Name] = ns.DefaultDeny
	}
	nodeNS := func(id string) string {
		if strings.Contains(id, ":") && !strings.Contains(id, "/") { return "" }
		return strings.SplitN(id, "/", 2)[0]
	}

	pairs := map[string]bool{}
	dnsEdges, halfOpen, extEdges := 0, 0, 0
	touched := map[string]bool{}
	for _, e := range g.Edges {
		touched[e.Src] = true
		touched[e.Dst] = true
		s, d := nodeNS(e.Src), nodeNS(e.Dst)
		if s == "" || d == "" { extEdges++ }
		if e.Cross { pairs[s+"|"+d] = true }
		if strings.Contains(e.Dst, "kube-dns") || strings.Contains(e.Dst, "coredns") { dnsEdges++ }
		if s != "" && d != "" {
			if e.DeclaredEgress && !e.DeclaredIngress && deny[d] { halfOpen++ }
			if e.DeclaredIngress && !e.DeclaredEgress && deny[s] { halfOpen++ }
		}
	}
	uncovered := 0
	var uncoveredNames []string
	for _, ns := range g.Namespaces {
		for _, wl := range ns.Workloads {
			if !touched[wl.ID] {
				uncovered++
				if len(uncoveredNames) < 12 { uncoveredNames = append(uncoveredNames, wl.ID) }
			}
		}
	}
	noDeny := []string{}
	for _, ns := range g.Namespaces {
		if !ns.DefaultDeny && len(ns.Workloads) > 0 { noDeny = append(noDeny, ns.Name) }
	}
	fmt.Printf("cross ns-pairs (overview lines): %d\n", len(pairs))
	fmt.Printf("edges into kube-dns: %d of %d total\n", dnsEdges, len(g.Edges))
	fmt.Printf("edges touching externals: %d\n", extEdges)
	fmt.Printf("half-open (one-sided into default-deny): %d\n", halfOpen)
	fmt.Printf("workloads in NO edge at all: %d  e.g. %v\n", uncovered, uncoveredNames)
	fmt.Printf("namespaces with workloads but NO default-deny flag: %d -> %v\n", len(noDeny), noDeny)
}
