// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package graph

import (
	"testing"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

// A rule whose peer selector matches no live workload must still be
// renderable: a phantom node docked in the resolved namespace, a Dead edge
// from the real subject, and no contamination of live stats or findings.
func TestPhantomForUnmatchedSelector(t *testing.T) {
	snap := testSnap()
	snap.Policies = []snapshot.Policy{
		cnp("media", "prowlarr", `{
			"endpointSelector": {"matchLabels": {"app.kubernetes.io/name": "prowlarr"}},
			"egress": [{"toEndpoints": [{"matchLabels":
				{"k8s:io.kubernetes.pod.namespace": "qbit", "app.kubernetes.io/name": "flaresolverr"}}],
				"toPorts": [{"ports": [{"port": "8191", "protocol": "TCP"}]}]}]}`),
	}

	g := Build(snap)

	if len(g.Phantoms) != 1 {
		t.Fatalf("phantoms = %d, want 1: %+v", len(g.Phantoms), g.Phantoms)
	}
	p := g.Phantoms[0]
	if p.Namespace != "qbit" {
		t.Errorf("phantom namespace = %q, want qbit (single-ns scope)", p.Namespace)
	}
	if len(p.Policies) != 1 || p.Policies[0] != "CiliumNetworkPolicy/media/prowlarr" {
		t.Errorf("phantom policies = %v", p.Policies)
	}

	var dead *Edge
	for i := range g.Edges {
		if g.Edges[i].Dead {
			dead = &g.Edges[i]
		}
	}
	if dead == nil {
		t.Fatal("no dead edge created for the unmatched peer")
	}
	if dead.Src != "media/prowlarr" || dead.Dst != p.ID {
		t.Errorf("dead edge %s -> %s, want media/prowlarr -> %s", dead.Src, dead.Dst, p.ID)
	}
	// Dormant rules are not live topology.
	if g.Stats.Edges != 0 {
		t.Errorf("stats.edges = %d, want 0 (only edge is dead)", g.Stats.Edges)
	}
	// And never half-open findings.
	if n := len(ComputeAudit(g).HalfOpen); n != 0 {
		t.Errorf("half-open findings from a dead edge: %d", n)
	}
	// The unmatched ref is still reported for the audit list.
	if len(g.DeadRefs) != 1 {
		t.Errorf("deadRefs = %v, want 1 entry", g.DeadRefs)
	}
}
