// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package graph

import (
	"encoding/json"
	"testing"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

func testSnap() *snapshot.Snapshot {
	return &snapshot.Snapshot{
		Namespaces: []snapshot.Namespace{
			{Name: "media", Labels: map[string]string{"kubernetes.io/metadata.name": "media"}},
			{Name: "qbit", Labels: map[string]string{"kubernetes.io/metadata.name": "qbit"}},
		},
		Workloads: []snapshot.Workload{
			{Namespace: "media", Name: "prowlarr", Kind: "Deployment", Labels: map[string]string{"app.kubernetes.io/name": "prowlarr"}, Replicas: 1},
			{Namespace: "media", Name: "sonarr", Kind: "Deployment", Labels: map[string]string{"app.kubernetes.io/name": "sonarr"}, Replicas: 1},
			{Namespace: "qbit", Name: "qbittorrent", Kind: "Deployment", Labels: map[string]string{"app.kubernetes.io/name": "qbittorrent"}, Replicas: 1},
		},
	}
}

func cnp(ns, name, rule string) snapshot.Policy {
	return snapshot.Policy{
		Kind: snapshot.KindCNP, Namespace: ns, Name: name,
		Rules: []json.RawMessage{json.RawMessage(rule)},
	}
}

func findEdge(g *Graph, src, dst string) *Edge {
	for i := range g.Edges {
		if g.Edges[i].Src == src && g.Edges[i].Dst == dst {
			return &g.Edges[i]
		}
	}
	return nil
}

// Egress with an explicit namespace key crosses namespaces; the same wire
// declared from the ingress side merges into one edge with both sides set.
func TestCrossNamespaceEdgeMergesBothSides(t *testing.T) {
	snap := testSnap()
	snap.Policies = []snapshot.Policy{
		cnp("media", "prowlarr", `{
			"endpointSelector": {"matchLabels": {"app.kubernetes.io/name": "prowlarr"}},
			"egress": [{
				"toEndpoints": [{"matchLabels": {"app.kubernetes.io/name": "qbittorrent", "k8s:io.kubernetes.pod.namespace": "qbit"}}],
				"toPorts": [{"ports": [{"port": "8080", "protocol": "TCP"}]}]
			}]
		}`),
		cnp("qbit", "qbittorrent", `{
			"endpointSelector": {"matchLabels": {"app.kubernetes.io/name": "qbittorrent"}},
			"ingress": [{
				"fromEndpoints": [{"matchLabels": {"k8s:io.kubernetes.pod.namespace": "media"}}],
				"toPorts": [{"ports": [{"port": "8080", "protocol": "TCP"}]}]
			}]
		}`),
	}
	g := Build(snap)

	e := findEdge(g, "media/prowlarr", "qbit/qbittorrent")
	if e == nil {
		t.Fatal("expected edge media/prowlarr -> qbit/qbittorrent")
	}
	if !e.Cross {
		t.Error("edge should be cross-namespace")
	}
	if !e.DeclaredEgress || !e.DeclaredIngress {
		t.Errorf("edge should be declared by both sides, got eg=%v in=%v", e.DeclaredEgress, e.DeclaredIngress)
	}
	if len(e.Ports) != 1 || e.Ports[0] != "8080/TCP" {
		t.Errorf("ports = %v, want [8080/TCP]", e.Ports)
	}
	// The ns-wide ingress selector also creates sonarr -> qbittorrent
	// (ingress-declared only: sonarr has no egress rule).
	se := findEdge(g, "media/sonarr", "qbit/qbittorrent")
	if se == nil || se.DeclaredEgress || !se.DeclaredIngress {
		t.Errorf("sonarr edge: %+v, want ingress-only declaration", se)
	}
}

// CNP peer selectors without a namespace key stay inside the policy's own
// namespace — never leaking across the cluster.
func TestCNPPeerImplicitNamespaceScope(t *testing.T) {
	snap := testSnap()
	snap.Policies = []snapshot.Policy{
		cnp("media", "prowlarr", `{
			"endpointSelector": {"matchLabels": {"app.kubernetes.io/name": "prowlarr"}},
			"egress": [{"toEndpoints": [{}]}]
		}`),
	}
	g := Build(snap)
	if e := findEdge(g, "media/prowlarr", "qbit/qbittorrent"); e != nil {
		t.Error("empty peer selector must not cross namespaces for a CNP")
	}
	if e := findEdge(g, "media/prowlarr", "media/sonarr"); e == nil {
		t.Error("empty peer selector should match same-namespace workloads")
	}
}

func TestDefaultDenyDetection(t *testing.T) {
	snap := testSnap()
	snap.Policies = []snapshot.Policy{
		cnp("qbit", "default-deny", `{"endpointSelector": {}}`),
	}
	g := Build(snap)
	for _, ns := range g.Namespaces {
		want := ns.Name == "qbit"
		if ns.DefaultDeny != want {
			t.Errorf("ns %s defaultDeny = %v, want %v", ns.Name, ns.DefaultDeny, want)
		}
	}
}

func TestEntitiesAndL7(t *testing.T) {
	snap := testSnap()
	snap.Policies = []snapshot.Policy{
		cnp("qbit", "qbittorrent", `{
			"endpointSelector": {"matchLabels": {"app.kubernetes.io/name": "qbittorrent"}},
			"egress": [{"toEntities": ["world"]}],
			"ingress": [{
				"fromEndpoints": [{}],
				"toPorts": [{"ports": [{"port": "8080", "protocol": "TCP"}], "rules": {"http": [{}]}}]
			}]
		}`),
	}
	g := Build(snap)
	e := findEdge(g, "qbit/qbittorrent", "entity:world")
	if e == nil {
		t.Fatal("expected edge to entity:world")
	}
	if e.Cross {
		t.Error("external edges are not namespace-crossings")
	}
	if len(g.Externals) != 1 || g.Externals[0].ID != "entity:world" {
		t.Errorf("externals = %+v", g.Externals)
	}
}

func TestNetworkPolicyNamespaceSelector(t *testing.T) {
	snap := testSnap()
	snap.Policies = []snapshot.Policy{{
		Kind: snapshot.KindNetPol, Namespace: "qbit", Name: "allow-media",
		Rules: []json.RawMessage{json.RawMessage(`{
			"podSelector": {},
			"policyTypes": ["Ingress"],
			"ingress": [{
				"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "media"}}}],
				"ports": [{"protocol": "TCP", "port": 8080}]
			}]
		}`)},
	}}
	g := Build(snap)
	e := findEdge(g, "media/prowlarr", "qbit/qbittorrent")
	if e == nil {
		t.Fatal("expected netpol-derived cross-namespace edge")
	}
	if len(e.Ports) != 1 || e.Ports[0] != "8080/TCP" {
		t.Errorf("ports = %v, want [8080/TCP]", e.Ports)
	}
}

// Deterministic output: two builds of the same snapshot are identical.
func TestBuildDeterministic(t *testing.T) {
	snap := testSnap()
	snap.Policies = []snapshot.Policy{
		cnp("media", "a", `{"endpointSelector": {}, "egress": [{"toEndpoints": [{}]}]}`),
		cnp("qbit", "b", `{"endpointSelector": {}, "ingress": [{"fromEndpoints": [{"matchLabels": {"k8s:io.kubernetes.pod.namespace": "media"}}]}]}`),
	}
	a, _ := json.Marshal(Build(snap))
	b, _ := json.Marshal(Build(snap))
	if string(a) != string(b) {
		t.Error("Build output is not deterministic")
	}
}
