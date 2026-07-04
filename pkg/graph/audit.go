// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package graph

import "slices"

// Audit is the set of findings derivable from declared topology alone.
// Everything here is visualization-grade signal for a human to review —
// enforcement verdicts belong to whatif.
type Audit struct {
	// HalfOpen edges: egress declared per-peer, but the default-deny
	// receiving side never accepts — traffic allowed out, dropped on
	// arrival. The classic one-sided policy bug.
	HalfOpen []Edge `json:"halfOpen"`
	// NoDefaultDeny lists namespaces that contain workloads but carry no
	// detected default-deny posture.
	NoDefaultDeny []string `json:"noDefaultDeny"`
	// WorldReachable lists workloads with a declared ingress from the
	// world/all entities or an all-CIDR — review each deliberately.
	WorldReachable []string `json:"worldReachable"`
	// DeadRefs are selector references matching no live workload. Possibly
	// intentional (scaled-down nodes, future pods), possibly dead rules.
	DeadRefs []string `json:"deadRefs"`
}

// worldLike are sources wide enough that ingress from them means
// "reachable from anywhere".
var worldLike = map[string]bool{
	"entity:world": true, "entity:all": true,
	"cidr:0.0.0.0/0": true, "cidr:::/0": true,
}

// ComputeAudit derives findings from a built graph.
func ComputeAudit(g *Graph) *Audit {
	a := &Audit{DeadRefs: g.DeadRefs}

	deny := map[string]bool{}
	for _, ns := range g.Namespaces {
		deny[ns.Name] = ns.DefaultDeny
		if !ns.DefaultDeny && len(ns.Workloads) > 0 {
			a.NoDefaultDeny = append(a.NoDefaultDeny, ns.Name)
		}
	}

	world := map[string]bool{}
	for _, e := range g.Edges {
		if _, ok := nodeNS(e.Src); ok {
			if dNS, ok := nodeNS(e.Dst); ok {
				if e.DeclaredEgress && !e.BroadEgress && !e.DeclaredIngress && deny[dNS] {
					a.HalfOpen = append(a.HalfOpen, e)
				}
			}
		}
		if worldLike[e.Src] && e.DeclaredIngress {
			world[e.Dst] = true
		}
	}
	for w := range world {
		a.WorldReachable = append(a.WorldReachable, w)
	}
	slices.Sort(a.WorldReachable)
	slices.Sort(a.NoDefaultDeny)
	return a
}
