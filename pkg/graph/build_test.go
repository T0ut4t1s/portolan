// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package graph

import (
	"encoding/json"
	"slices"
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

func findNS(g *Graph, name string) *Namespace {
	for i := range g.Namespaces {
		if g.Namespaces[i].Name == name {
			return &g.Namespaces[i]
		}
	}
	return nil
}

func ccnp(name, rule string) snapshot.Policy {
	return snapshot.Policy{
		Kind: snapshot.KindCCNP, Name: name,
		Rules: []json.RawMessage{json.RawMessage(rule)},
	}
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

// GR-1: a workload with a broad allowance (egress to entity:cluster) that
// covers a silent edge must have that allowance attributed to the edge, so
// the client policy's footprint counts the covered passage.
func TestBroadAllowanceCreditsProvenance(t *testing.T) {
	snap := testSnap()
	snap.Policies = []snapshot.Policy{
		cnp("media", "prowlarr-broad", `{
			"endpointSelector": {"matchLabels": {"app.kubernetes.io/name": "prowlarr"}},
			"egress": [{"toEntities": ["cluster"]}]
		}`),
		cnp("media", "sonarr-ingress", `{
			"endpointSelector": {"matchLabels": {"app.kubernetes.io/name": "sonarr"}},
			"ingress": [{"fromEndpoints": [{"matchLabels": {"app.kubernetes.io/name": "prowlarr"}}]}]
		}`),
	}
	g := Build(snap)
	e := findEdge(g, "media/prowlarr", "media/sonarr")
	if e == nil {
		t.Fatal("expected prowlarr -> sonarr edge (ingress-declared, egress-broad-credited)")
	}
	if !e.BroadEgress {
		t.Error("egress side should be credited to the broad allowance")
	}
	if !slices.Contains(e.Policies, "CiliumNetworkPolicy/media/prowlarr-broad") {
		t.Errorf("edge policies %v should include the broad-egress policy", e.Policies)
	}
	if !slices.Contains(e.Policies, "CiliumNetworkPolicy/media/sonarr-ingress") {
		t.Errorf("edge policies %v should include the per-pair ingress policy", e.Policies)
	}
}

// GR-2: a namespace matchExpression with NotIn on the reserved namespace key
// must exclude the named namespaces — not fall through to pod-label matching
// (where the key never exists) and match everything, kube-system included.
func TestNamespaceNotInExcludes(t *testing.T) {
	snap := testSnap()
	snap.Namespaces = append(snap.Namespaces, snapshot.Namespace{
		Name: "kube-system", Labels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}})
	snap.Workloads = append(snap.Workloads, snapshot.Workload{
		Namespace: "kube-system", Name: "coredns", Kind: "Deployment",
		Labels: map[string]string{"app.kubernetes.io/name": "coredns"}, Replicas: 2})
	snap.Policies = []snapshot.Policy{
		ccnp("prowlarr-not-kubesystem", `{
			"endpointSelector": {"matchLabels": {"app.kubernetes.io/name": "prowlarr", "k8s:io.kubernetes.pod.namespace": "media"}},
			"egress": [{"toEndpoints": [{"matchExpressions": [
				{"key": "k8s:io.kubernetes.pod.namespace", "operator": "NotIn", "values": ["kube-system"]}
			]}]}]
		}`),
	}
	g := Build(snap)
	if findEdge(g, "media/prowlarr", "qbit/qbittorrent") == nil {
		t.Error("NotIn kube-system should still reach qbit/qbittorrent")
	}
	if findEdge(g, "media/prowlarr", "media/sonarr") == nil {
		t.Error("NotIn kube-system should still reach media/sonarr")
	}
	if e := findEdge(g, "media/prowlarr", "kube-system/coredns"); e != nil {
		t.Error("NotIn kube-system must NOT reach kube-system/coredns")
	}
}

// GR-2: Exists on the namespace key means "any namespace", not "none".
func TestNamespaceExistsMatchesAll(t *testing.T) {
	snap := testSnap()
	snap.Policies = []snapshot.Policy{
		ccnp("prowlarr-any-ns", `{
			"endpointSelector": {"matchLabels": {"app.kubernetes.io/name": "prowlarr", "k8s:io.kubernetes.pod.namespace": "media"}},
			"egress": [{"toEndpoints": [{
				"matchLabels": {"app.kubernetes.io/name": "qbittorrent"},
				"matchExpressions": [{"key": "k8s:io.kubernetes.pod.namespace", "operator": "Exists"}]
			}]}]
		}`),
	}
	g := Build(snap)
	if findEdge(g, "media/prowlarr", "qbit/qbittorrent") == nil {
		t.Error("Exists on the namespace key should match qbittorrent in any namespace")
	}
}

// GR-3: the sentinel default-deny idiom (all-endpoints subject + an ingress
// arm selecting the impossible default-deny label) is an ingress default-deny,
// not "no default deny", and must not imply egress deny.
func TestDefaultDenySentinelIdiom(t *testing.T) {
	snap := testSnap()
	snap.Policies = []snapshot.Policy{
		cnp("qbit", "default-deny-ingress", `{
			"endpointSelector": {},
			"ingress": [{"fromEndpoints": [{"matchLabels": {"io.cilium.policy/default-deny": ""}}]}]
		}`),
	}
	g := Build(snap)
	ns := findNS(g, "qbit")
	if !ns.DefaultDenyIngress {
		t.Error("sentinel idiom should register ingress default-deny")
	}
	if ns.DefaultDenyEgress {
		t.Error("an ingress-only sentinel must not imply egress default-deny")
	}
	if !ns.DefaultDeny {
		t.Error("DefaultDeny (the OR) should be true")
	}
}

// GR-3: a half-open needs an ingress default-deny on the receiver. An
// egress-only deny does not stop the workload from being reached, so an
// egress-declared edge into it is not a half-open.
func TestHalfOpenRequiresIngressDeny(t *testing.T) {
	egressToQbit := cnp("media", "prowlarr-egress", `{
		"endpointSelector": {"matchLabels": {"app.kubernetes.io/name": "prowlarr"}},
		"egress": [{"toEndpoints": [{"matchLabels": {"app.kubernetes.io/name": "qbittorrent", "k8s:io.kubernetes.pod.namespace": "qbit"}}]}]
	}`)

	// Egress-only deny on the receiver: NOT a half-open.
	snap := testSnap()
	snap.Policies = []snapshot.Policy{egressToQbit,
		cnp("qbit", "egress-lockdown", `{
			"endpointSelector": {},
			"egress": [{"toEndpoints": [{}]}]
		}`),
	}
	a := ComputeAudit(Build(snap))
	for _, e := range a.HalfOpen {
		if e.Dst == "qbit/qbittorrent" {
			t.Error("egress-only deny on the receiver must not create a half-open")
		}
	}

	// Ingress deny on the receiver: IS a half-open.
	snap = testSnap()
	snap.Policies = []snapshot.Policy{egressToQbit,
		cnp("qbit", "ingress-lockdown", `{"endpointSelector": {}}`),
	}
	a = ComputeAudit(Build(snap))
	found := false
	for _, e := range a.HalfOpen {
		if e.Src == "media/prowlarr" && e.Dst == "qbit/qbittorrent" {
			found = true
		}
	}
	if !found {
		t.Error("ingress default-deny on the receiver should produce a half-open")
	}
}

// GR-3: an all-pods NetworkPolicy with allow rules still imposes ingress
// default-deny — allow rules poke holes, they do not lift the deny.
func TestNetpolAllPodsWithAllowIsDefaultDeny(t *testing.T) {
	snap := testSnap()
	snap.Policies = []snapshot.Policy{{
		Kind: snapshot.KindNetPol, Namespace: "qbit", Name: "allow-media",
		Rules: []json.RawMessage{json.RawMessage(`{
			"podSelector": {},
			"policyTypes": ["Ingress"],
			"ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "media"}}}]}]
		}`)},
	}}
	ns := findNS(Build(snap), "qbit")
	if !ns.DefaultDenyIngress {
		t.Error("all-pods netpol with allow rules should still be ingress default-deny")
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
