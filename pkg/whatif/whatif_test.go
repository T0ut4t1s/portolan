// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package whatif

import (
	"encoding/json"
	"testing"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

// Fixture mirrors the house pattern: default-deny CNPs with explicit
// enableDefaultDeny and sentinel selectors, per-app allow rules.

func pol(kind snapshot.PolicyKind, ns, name string, rules ...string) snapshot.Policy {
	p := snapshot.Policy{Kind: kind, Namespace: ns, Name: name}
	for _, r := range rules {
		p.Rules = append(p.Rules, json.RawMessage(r))
	}
	return p
}

const defaultDenyRule = `{
	"endpointSelector": {},
	"enableDefaultDeny": {"ingress": true, "egress": true},
	"ingress": [{"fromEndpoints": [{"matchLabels": {"io.cilium.policy/default-deny": "init"}}]}],
	"egress":  [{"toEndpoints":   [{"matchLabels": {"io.cilium.policy/default-deny": "init"}}]}]
}`

const prowlarrEgress = `{
	"endpointSelector": {"matchLabels": {"app": "prowlarr"}},
	"egress": [{
		"toEndpoints": [{"matchLabels": {"k8s:io.kubernetes.pod.namespace": "qbit", "app": "qbittorrent"}}],
		"toPorts": [{"ports": [{"port": "8080", "protocol": "TCP"}]}]
	}]
}`

const qbitIngress = `{
	"endpointSelector": {"matchLabels": {"app": "qbittorrent"}},
	"ingress": [{
		"fromEndpoints": [{"matchLabels": {"k8s:io.kubernetes.pod.namespace": "media", "app": "prowlarr"}}],
		"toPorts": [{"ports": [{"port": "8080", "protocol": "TCP"}]}]
	}]
}`

func testSnap() *snapshot.Snapshot {
	return &snapshot.Snapshot{
		Namespaces: []snapshot.Namespace{
			{Name: "media", Labels: map[string]string{"kubernetes.io/metadata.name": "media"}},
			{Name: "qbit", Labels: map[string]string{"kubernetes.io/metadata.name": "qbit"}},
		},
		Workloads: []snapshot.Workload{
			{Namespace: "media", Name: "prowlarr", Kind: "Deployment", Labels: map[string]string{"app": "prowlarr"}, Replicas: 1},
			{Namespace: "media", Name: "sonarr", Kind: "Deployment", Labels: map[string]string{"app": "sonarr"}, Replicas: 1},
			{Namespace: "qbit", Name: "qbittorrent", Kind: "Deployment", Labels: map[string]string{"app": "qbittorrent"}, Replicas: 1},
		},
		Policies: []snapshot.Policy{
			pol(snapshot.KindCNP, "media", "default-deny", defaultDenyRule),
			pol(snapshot.KindCNP, "qbit", "default-deny", defaultDenyRule),
			pol(snapshot.KindCNP, "media", "prowlarr", prowlarrEgress),
		},
	}
}

// The baseline is the classic half-open: prowlarr's egress is declared but
// qbit is default-deny with no matching ingress. The draft adds the
// ingress allow — the engine must report a new passage that heals it.
func TestHealsHalfOpen(t *testing.T) {
	snap := testSnap()
	res, err := Compute(snap, Changes{
		Apply: []snapshot.Policy{pol(snapshot.KindCNP, "qbit", "qbittorrent", qbitIngress)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 1 {
		t.Fatalf("added = %+v, want exactly the healed passage", res.Added)
	}
	a := res.Added[0]
	if a.Src != "media/prowlarr" || a.Dst != "qbit/qbittorrent" {
		t.Errorf("added pair = %s -> %s", a.Src, a.Dst)
	}
	if len(a.Ports) != 1 || a.Ports[0] != "8080/TCP" {
		t.Errorf("added ports = %v, want [8080/TCP]", a.Ports)
	}
	if !a.HealsHalfOpen {
		t.Error("addition should be flagged as healing a half-open passage")
	}
	if len(res.Removed) != 0 || len(res.HalfOpen) != 0 {
		t.Errorf("unexpected removed=%+v halfOpen=%+v", res.Removed, res.HalfOpen)
	}
	found := false
	for _, v := range a.Via {
		if v == "CiliumNetworkPolicy/qbit/qbittorrent" {
			found = true
		}
	}
	if !found {
		t.Errorf("via = %v, want the draft policy named", a.Via)
	}
}

// A draft that only declares egress toward a default-deny receiver changes
// no verdict — it introduces a half-open passage. This is the mistake
// whatif exists to catch at review time.
func TestDetectsIntroducedHalfOpen(t *testing.T) {
	snap := testSnap()
	sonarrEgress := `{
		"endpointSelector": {"matchLabels": {"app": "sonarr"}},
		"egress": [{
			"toEndpoints": [{"matchLabels": {"k8s:io.kubernetes.pod.namespace": "qbit", "app": "qbittorrent"}}],
			"toPorts": [{"ports": [{"port": "9090", "protocol": "TCP"}]}]
		}]
	}`
	res, err := Compute(snap, Changes{
		Apply: []snapshot.Policy{pol(snapshot.KindCNP, "media", "sonarr", sonarrEgress)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 0 {
		t.Errorf("no end-to-end passage should open: %+v", res.Added)
	}
	if len(res.HalfOpen) != 1 {
		t.Fatalf("halfOpen = %+v, want the sonarr->qbittorrent egress-only finding", res.HalfOpen)
	}
	h := res.HalfOpen[0]
	if h.Src != "media/sonarr" || h.Dst != "qbit/qbittorrent" || h.Side != "egress" {
		t.Errorf("halfOpen = %+v", h)
	}
}

// Deleting the ingress side of a working passage removes it.
func TestDeleteRemovesPassage(t *testing.T) {
	snap := testSnap()
	snap.Policies = append(snap.Policies, pol(snapshot.KindCNP, "qbit", "qbittorrent", qbitIngress))
	res, err := Compute(snap, Changes{Delete: []string{"CiliumNetworkPolicy/qbit/qbittorrent"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 1 {
		t.Fatalf("removed = %+v, want the torn-down passage", res.Removed)
	}
	r := res.Removed[0]
	if r.Src != "media/prowlarr" || r.Dst != "qbit/qbittorrent" {
		t.Errorf("removed pair = %s -> %s", r.Src, r.Dst)
	}
}

// Observed-flow cross-check: a draft that heals the half-open fixes the
// observed drop; a delete that tears down the working passage breaks the
// observed forwarded flow.
func TestFlowImpact(t *testing.T) {
	wl := func(ns, name string) snapshot.FlowPeer {
		return snapshot.FlowPeer{Namespace: ns, Name: name, Kind: "Deployment"}
	}
	snap := testSnap()
	snap.Flows = &snapshot.FlowCapture{
		Status: "ok", Window: "15m",
		Edges: []snapshot.FlowEdge{
			{Src: wl("media", "prowlarr"), Dst: wl("qbit", "qbittorrent"),
				Port: "8080/TCP", Verdict: "DROPPED", DropReason: "POLICY_DENIED", Count: 5},
		},
	}
	res, err := Compute(snap, Changes{
		Apply: []snapshot.Policy{pol(snapshot.KindCNP, "qbit", "qbittorrent", qbitIngress)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.FixesDrops) != 1 || res.FixesDrops[0].Count != 5 || res.FixesDrops[0].Reason != "POLICY_DENIED" {
		t.Fatalf("fixesDrops = %+v", res.FixesDrops)
	}

	// Now the passage works and traffic flows; deleting it breaks the flow.
	snap2 := testSnap()
	snap2.Policies = append(snap2.Policies, pol(snapshot.KindCNP, "qbit", "qbittorrent", qbitIngress))
	snap2.Flows = &snapshot.FlowCapture{
		Status: "ok", Window: "15m",
		Edges: []snapshot.FlowEdge{
			{Src: wl("media", "prowlarr"), Dst: wl("qbit", "qbittorrent"),
				Port: "8080/TCP", Verdict: "FORWARDED", Count: 42},
		},
	}
	res2, err := Compute(snap2, Changes{Delete: []string{"CiliumNetworkPolicy/qbit/qbittorrent"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.BreaksFlows) != 1 || res2.BreaksFlows[0].Count != 42 {
		t.Fatalf("breaksFlows = %+v", res2.BreaksFlows)
	}
}

// A broad allowance via toEntities: [cluster] must open egress to every
// in-cluster peer — including on ports no rule names (the canary probe).
// This is the check that InitEntities(cluster) actually happened.
func TestBroadClusterEntityAllowance(t *testing.T) {
	snap := testSnap()
	broad := `{
		"endpointSelector": {"matchLabels": {"app": "sonarr"}},
		"egress": [{"toEntities": ["cluster"]}]
	}`
	res, err := Compute(snap, Changes{
		Apply: []snapshot.Policy{pol(snapshot.KindCNP, "media", "sonarr-broad", broad)},
	})
	if err != nil {
		t.Fatal(err)
	}
	// End-to-end nothing opens (receivers still deny) — but the egress side
	// flips for every peer, so half-open findings must name qbittorrent.
	found := false
	for _, h := range res.HalfOpen {
		if h.Src == "media/sonarr" && h.Dst == "qbit/qbittorrent" && h.Side == "egress" {
			found = true
			for _, p := range h.Ports {
				if p == "other ports" {
					return // canary present: allowance is port-wildcard, entity resolved
				}
			}
		}
	}
	if !found {
		t.Fatalf("broad cluster egress not detected: halfOpen=%+v added=%+v", res.HalfOpen, res.Added)
	}
	t.Fatalf("canary port missing from broad allowance: %+v", res.HalfOpen)
}

func TestParseDrafts(t *testing.T) {
	yaml := `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: qbittorrent
  namespace: qbit
spec:
  endpointSelector:
    matchLabels:
      app: qbittorrent
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: np
  namespace: media
spec:
  podSelector: {}
`
	pols, err := ParseDrafts("test.yaml", []byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(pols) != 2 || pols[0].Kind != snapshot.KindCNP || pols[1].Kind != snapshot.KindNetPol {
		t.Fatalf("parsed = %+v", pols)
	}
	if _, err := ParseDrafts("bad.yaml", []byte("kind: CiliumClusterwideNetworkPolicy\nmetadata:\n  name: x\n  namespace: oops\nspec: {}")); err == nil {
		t.Fatal("CCNP with namespace must be rejected")
	}
}
