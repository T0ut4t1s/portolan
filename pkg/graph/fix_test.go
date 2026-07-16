// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package graph

import (
	"strings"
	"testing"
	"time"
)

func fixesFor(g *Graph, a *Audit) map[string]*FixCandidate { return ComputeFixes(g, a) }

// Active denial → admit the sender. Someone is trying to make this connection
// and Cilium is dropping it; the change that clears the flag is unambiguous.
func TestActivelyDeniedHalfOpenOffersAddIngress(t *testing.T) {
	e := Edge{Src: "web/front", Dst: "db/pg", Ports: []string{"5432/TCP"},
		DeclaredEgress: true, DeclaredIngress: false, Policies: []string{"CiliumNetworkPolicy/web/front"}}
	g := &Graph{
		TakenAt: "now", Tool: "portolan", Edges: []Edge{e},
		Namespaces: []Namespace{{Name: "db", DefaultDeny: true, DefaultDenyIngress: true}},
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "24h", Watched: "24h",
			WatchedSec: 24 * 3600, Coverage: 1, BucketSec: 900, To: time.Now(),
			// traffic is being DENIED on the declared port
			Drops: []DropEdge{{Src: "web/front", Dst: "db/pg", Port: "5432/TCP",
				Reason: "POLICY_DENIED", Count: 90, Buckets: 40, LastSeen: time.Now()}},
		},
	}
	c := fixesFor(g, &Audit{HalfOpen: []Edge{e}, Drops: g.Flows.Drops})["web/front|db/pg"]
	if c == nil {
		t.Fatal("an actively-denied half-open must offer a flag-clearing candidate")
	}
	if c.Kind != "add-ingress" {
		t.Errorf("kind = %q, want add-ingress", c.Kind)
	}
	if c.Touches != "db" {
		t.Errorf("touches = %q, want the RECEIVER namespace db (not the one you audited)", c.Touches)
	}
	if len(c.Rules) != 1 || c.Rules[0].Sides != "ingress" || c.Rules[0].To != "db/pg" {
		t.Errorf("candidate should admit the sender at the receiver: %+v", c.Rules)
	}
	// Framed as what it does, never as "fix".
	if strings.Contains(strings.ToLower(c.Summary), "fix") {
		t.Errorf("summary must not claim to fix anything: %q", c.Summary)
	}
}

// Dead rule at high coverage → offer the removal. Nothing reaches the receiver
// and nothing was observed, over enough coverage that the silence means
// something.
func TestDeadHalfOpenAtHighCoverageOffersRemoval(t *testing.T) {
	e := Edge{Src: "monitoring/vlogs", Dst: "minio/minio", Ports: []string{"9000/TCP"},
		DeclaredEgress: true, DeclaredIngress: false,
		Policies: []string{"CiliumNetworkPolicy/monitoring/victoria-logs-single"}}
	g := &Graph{
		TakenAt: "now", Tool: "portolan", Edges: []Edge{e},
		Namespaces: []Namespace{{Name: "minio", DefaultDeny: true, DefaultDenyIngress: true}},
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "24h", Watched: "24h",
			WatchedSec: 24 * 3600, Coverage: 1, BucketSec: 900, To: time.Now(),
			Observed: []ObservedEdge{}, Drops: []DropEdge{},
		},
	}
	c := fixesFor(g, &Audit{HalfOpen: []Edge{e}})["monitoring/vlogs|minio/minio"]
	if c == nil || c.Kind != "remove-policy" {
		t.Fatalf("a dead passage at full coverage should offer removal, got %+v", c)
	}
	if len(c.Deletes) != 1 || c.Deletes[0] != "CiliumNetworkPolicy/monitoring/victoria-logs-single" {
		t.Errorf("removal must name the declaring policy: %+v", c.Deletes)
	}
	if c.Touches != "monitoring" {
		t.Errorf("touches = %q, want the policy's namespace monitoring", c.Touches)
	}
}

// The keycloak trap, one more time: a benign fan-out must offer NOTHING. Its
// working sibling proves the rule is live; "admit nine kube-system pods" clears
// the flag by making a change nobody wants — the authority we refuse to claim.
func TestBenignFanOutOffersNoCandidate(t *testing.T) {
	edges := []Edge{{Src: "keycloak/keycloak", Dst: "kube-system/coredns", Ports: []string{"53/UDP"},
		DeclaredEgress: true, DeclaredIngress: true}}
	var half []Edge
	for _, p := range []string{"cilium", "kube-vip", "metrics-server"} {
		e := Edge{Src: "keycloak/keycloak", Dst: "kube-system/" + p, Ports: []string{"53/UDP"},
			DeclaredEgress: true, DeclaredIngress: false, Policies: []string{"NetworkPolicy/keycloak/keycloak"}}
		edges = append(edges, e)
		half = append(half, e)
	}
	g := &Graph{
		TakenAt: "now", Tool: "portolan", Edges: edges,
		Namespaces: []Namespace{{Name: "kube-system", DefaultDeny: true, DefaultDenyIngress: true}},
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "24h", Watched: "24h",
			WatchedSec: 24 * 3600, Coverage: 1, BucketSec: 900, To: time.Now(),
			Observed: []ObservedEdge{{Src: "keycloak/keycloak", Dst: "kube-system/coredns",
				Ports: []string{"53/UDP"}, Count: 5000, Declared: true}},
		},
	}
	fixes := fixesFor(g, &Audit{HalfOpen: half})
	if len(fixes) != 0 {
		t.Errorf("a live rule with a working sibling must offer no mechanical change, got %d: %+v", len(fixes), fixes)
	}
}

// "Dead" from a low-coverage sample is not dead — it is unseen. No removal.
func TestDeadRemovalWithheldUnderLowCoverage(t *testing.T) {
	e := Edge{Src: "a/x", Dst: "b/y", Ports: []string{"80/TCP"},
		DeclaredEgress: true, DeclaredIngress: false, Policies: []string{"CiliumNetworkPolicy/a/x"}}
	g := &Graph{
		TakenAt: "now", Tool: "portolan", Edges: []Edge{e},
		Namespaces: []Namespace{{Name: "b", DefaultDeny: true, DefaultDenyIngress: true}},
		Flows: &FlowOverlay{
			Status: "ok", Source: "buffer", Window: "15m", Watched: "12s",
			WatchedSec: 12, Coverage: 0.01, BucketSec: 900, To: time.Now(),
			Observed: []ObservedEdge{}, Drops: []DropEdge{},
		},
	}
	if fixes := fixesFor(g, &Audit{HalfOpen: []Edge{e}}); len(fixes) != 0 {
		t.Errorf("must not propose deleting a rule as 'dead' from a 1%%-covered sample: %+v", fixes)
	}
}
