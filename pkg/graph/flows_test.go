// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package graph

import (
	"testing"
	"time"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

func TestAttachFlows(t *testing.T) {
	snap := testSnap()
	// One declared edge: prowlarr -> qbittorrent.
	snap.Policies = []snapshot.Policy{
		cnp("media", "prowlarr", `{
			"endpointSelector": {"matchLabels": {"app.kubernetes.io/name": "prowlarr"}},
			"egress": [{"toEndpoints": [{"matchLabels":
				{"k8s:io.kubernetes.pod.namespace": "qbit", "app.kubernetes.io/name": "qbittorrent"}}],
				"toPorts": [{"ports": [{"port": "8080", "protocol": "TCP"}]}]}]}`),
	}
	wl := func(ns, name string) snapshot.FlowPeer {
		return snapshot.FlowPeer{Namespace: ns, Name: name, Kind: "Deployment"}
	}
	last := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	snap.Flows = &snapshot.FlowCapture{
		Status: "ok", Window: "15m",
		Edges: []snapshot.FlowEdge{
			// Matches the declared edge — two port-level entries merge.
			{Src: wl("media", "prowlarr"), Dst: wl("qbit", "qbittorrent"), Port: "8080/TCP", Verdict: "FORWARDED", Count: 5},
			{Src: wl("media", "prowlarr"), Dst: wl("qbit", "qbittorrent"), Port: "9090/TCP", Verdict: "FORWARDED", Count: 2},
			// No declared edge — ghost.
			{Src: wl("media", "sonarr"), Dst: wl("qbit", "qbittorrent"), Port: "8080/TCP", Verdict: "FORWARDED", Count: 3},
			// Drop from an entity never referenced by any policy.
			{Src: snapshot.FlowPeer{Entity: "remote-node"}, Dst: wl("media", "sonarr"),
				Port: "53/UDP", Verdict: "DROPPED", DropReason: "POLICY_DENIED", Count: 4, LastSeen: last},
			// Peer that is not a node on the map.
			{Src: wl("media", "dead-pod-xyz"), Dst: wl("qbit", "qbittorrent"), Port: "1/TCP", Verdict: "FORWARDED", Count: 1},
		},
	}

	g := Build(snap)
	if g.Flows == nil || g.Flows.Status != "ok" {
		t.Fatalf("overlay missing or not ok: %+v", g.Flows)
	}
	if g.Flows.NotShown != 1 {
		t.Errorf("NotShown = %d, want 1", g.Flows.NotShown)
	}
	if len(g.Flows.Observed) != 2 {
		t.Fatalf("observed = %d, want 2: %+v", len(g.Flows.Observed), g.Flows.Observed)
	}
	var declared, ghost *ObservedEdge
	for i := range g.Flows.Observed {
		o := &g.Flows.Observed[i]
		if o.Src == "media/prowlarr" {
			declared = o
		}
		if o.Src == "media/sonarr" {
			ghost = o
		}
	}
	if declared == nil || !declared.Declared || declared.Count != 7 || len(declared.Ports) != 2 {
		t.Errorf("declared observed edge wrong: %+v", declared)
	}
	if ghost == nil || ghost.Declared {
		t.Errorf("ghost edge should not be marked declared: %+v", ghost)
	}
	if len(g.Flows.Drops) != 1 {
		t.Fatalf("drops = %d, want 1", len(g.Flows.Drops))
	}
	d := g.Flows.Drops[0]
	if d.Src != "entity:remote-node" || d.Reason != "POLICY_DENIED" || d.Count != 4 || !d.LastSeen.Equal(last) {
		t.Errorf("drop edge wrong: %+v", d)
	}
	// remote-node was never in any policy — the overlay must have added it
	// as an external so the map has a node to draw the drop at.
	found := false
	for _, x := range g.Externals {
		if x.ID == "entity:remote-node" {
			found = true
		}
	}
	if !found {
		t.Error("entity:remote-node not added to externals")
	}
	// Audit carries the drops.
	a := ComputeAudit(g)
	if len(a.Drops) != 1 {
		t.Errorf("audit drops = %d, want 1", len(a.Drops))
	}
}

// GR-5: a DROPPED flow whose endpoint vanished from the map must not be
// folded into the benign NotShown (forwarded) count — it goes to
// NotShownDrops so the honesty bar can surface the hidden denial.
func TestDroppedFlowFromVanishedPodCountedSeparately(t *testing.T) {
	snap := testSnap()
	wl := func(ns, name string) snapshot.FlowPeer {
		return snapshot.FlowPeer{Namespace: ns, Name: name, Kind: "Deployment"}
	}
	snap.Flows = &snapshot.FlowCapture{
		Status: "ok", Window: "15m",
		Edges: []snapshot.FlowEdge{
			// A forwarded flow from a vanished pod: benign, NotShown.
			{Src: wl("media", "gone-fwd"), Dst: wl("qbit", "qbittorrent"), Port: "8080/TCP", Verdict: "FORWARDED", Count: 1},
			// A dropped flow from a vanished pod: the interesting one.
			{Src: wl("media", "gone-drop"), Dst: wl("qbit", "qbittorrent"), Port: "8080/TCP", Verdict: "DROPPED", DropReason: "POLICY_DENIED", Count: 3},
		},
	}
	g := Build(snap)
	if g.Flows.NotShown != 1 {
		t.Errorf("NotShown = %d, want 1 (the forwarded one)", g.Flows.NotShown)
	}
	if g.Flows.NotShownDrops != 1 {
		t.Errorf("NotShownDrops = %d, want 1 (the dropped one)", g.Flows.NotShownDrops)
	}
}

func TestAttachFlowsDegraded(t *testing.T) {
	snap := testSnap()
	snap.Flows = &snapshot.FlowCapture{Status: "error", Reason: "relay unreachable", Window: "15m"}
	g := Build(snap)
	if g.Flows == nil || g.Flows.Status != "error" || g.Flows.Reason != "relay unreachable" {
		t.Fatalf("degraded capture must surface in overlay: %+v", g.Flows)
	}
	if g.Flows.Observed == nil || g.Flows.Drops == nil {
		t.Error("Observed/Drops must be non-nil (JSON [] not null)")
	}
}

func TestAttachFlowsAbsent(t *testing.T) {
	g := Build(testSnap())
	if g.Flows != nil {
		t.Fatal("no capture in snapshot must mean no overlay")
	}
}
