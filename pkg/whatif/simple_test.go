// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package whatif

import (
	"errors"
	"strings"
	"testing"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

// The whole point of GenerateCNPs: the objects it emits must round-trip
// through the real engine and open exactly the passage the simple rule
// asked for — both sides, so no half-open.
func TestSimpleRuleRoundTrip(t *testing.T) {
	snap := testSnap()
	pols, mans, err := GenerateCNPs(snap, []SimpleRule{
		{From: "media/sonarr", To: "qbit/qbittorrent", Ports: []string{"9090"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pols) != 2 || len(mans) != 2 {
		t.Fatalf("want 2 CNPs (egress+ingress), got %d policies / %d manifests", len(pols), len(mans))
	}

	res, err := Compute(snap, Changes{Apply: pols})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 1 {
		t.Fatalf("added = %+v, want exactly the requested passage", res.Added)
	}
	a := res.Added[0]
	if a.Src != "media/sonarr" || a.Dst != "qbit/qbittorrent" {
		t.Errorf("added pair = %s -> %s", a.Src, a.Dst)
	}
	if len(a.Ports) != 1 || a.Ports[0] != "9090/TCP" {
		t.Errorf("added ports = %v, want [9090/TCP] (bare number defaults to TCP)", a.Ports)
	}
	if len(res.HalfOpen) != 0 {
		t.Errorf("a both-sides rule must not introduce a half-open: %+v", res.HalfOpen)
	}
	if len(res.BreaksFlows) != 0 || len(res.Removed) != 0 {
		t.Errorf("an added allow must not remove anything: %+v %+v", res.Removed, res.BreaksFlows)
	}

	for _, m := range mans {
		if !strings.Contains(m.YAML, "kind: CiliumNetworkPolicy") {
			t.Errorf("manifest %s/%s is not a CNP:\n%s", m.Namespace, m.Name, m.YAML)
		}
		if strings.Contains(m.YAML, "any.") || strings.Contains(m.YAML, "any:") {
			t.Errorf("manifest %s/%s leaks internal label prefixes:\n%s", m.Namespace, m.Name, m.YAML)
		}
	}
}

// A deliberately one-sided rule must produce exactly one CNP and surface
// the half-open finding — the panel's teaching moment.
func TestSimpleRuleEgressOnlyIntroducesHalfOpen(t *testing.T) {
	snap := testSnap()
	pols, _, err := GenerateCNPs(snap, []SimpleRule{
		{From: "media/sonarr", To: "qbit/qbittorrent", Ports: []string{"9090/TCP"}, Sides: "egress"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pols) != 1 {
		t.Fatalf("egress-only rule should emit 1 CNP, got %d", len(pols))
	}
	res, err := Compute(snap, Changes{Apply: pols})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 0 || len(res.HalfOpen) != 1 {
		t.Fatalf("want the half-open finding and nothing opened; added=%+v halfOpen=%+v", res.Added, res.HalfOpen)
	}
	if res.HalfOpen[0].Side != "egress" {
		t.Errorf("side = %q, want egress", res.HalfOpen[0].Side)
	}
}

// Entity peers: an allow from world lands only on the receiver (entities
// carry no policies) and the engine honors it.
func TestSimpleRuleFromEntity(t *testing.T) {
	snap := testSnap()
	pols, mans, err := GenerateCNPs(snap, []SimpleRule{
		{From: "entity:world", To: "qbit/qbittorrent", Ports: []string{"53/UDP"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pols) != 1 {
		t.Fatalf("entity source should emit only the ingress CNP, got %d", len(pols))
	}
	if !strings.Contains(mans[0].YAML, "fromEntities") || !strings.Contains(mans[0].YAML, "world") {
		t.Errorf("manifest should allow fromEntities world:\n%s", mans[0].YAML)
	}
	res, err := Compute(snap, Changes{Apply: pols})
	if err != nil {
		t.Fatal(err)
	}
	var hit bool
	for _, a := range res.Added {
		if a.Src == "entity:world" && a.Dst == "qbit/qbittorrent" {
			hit = true
			if len(a.Ports) != 1 || a.Ports[0] != "53/UDP" {
				t.Errorf("ports = %v, want [53/UDP]", a.Ports)
			}
		}
	}
	if !hit {
		t.Errorf("added = %+v, want entity:world -> qbit/qbittorrent", res.Added)
	}
}

// Two rules from the same sender merge into one egress CNP, mirroring how
// a human authors policies.
func TestSimpleRulesMergePerWorkload(t *testing.T) {
	snap := testSnap()
	pols, _, err := GenerateCNPs(snap, []SimpleRule{
		{From: "media/sonarr", To: "qbit/qbittorrent", Ports: []string{"9090"}},
		{From: "media/sonarr", To: "media/prowlarr", Ports: []string{"9696"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// sonarr egress (merged), qbittorrent ingress, prowlarr ingress
	if len(pols) != 3 {
		names := []string{}
		for _, p := range pols {
			names = append(names, p.Namespace+"/"+p.Name)
		}
		t.Fatalf("want 3 CNPs, got %d: %v", len(pols), names)
	}
}

func TestSimpleRuleValidation(t *testing.T) {
	snap := testSnap()
	for _, tc := range []struct {
		name  string
		rules []SimpleRule
	}{
		{"unknown workload", []SimpleRule{{From: "media/nope", To: "qbit/qbittorrent"}}},
		{"unknown entity", []SimpleRule{{From: "entity:mars", To: "qbit/qbittorrent"}}},
		{"entity to entity", []SimpleRule{{From: "entity:world", To: "entity:host"}}},
		{"bad port", []SimpleRule{{From: "media/sonarr", To: "qbit/qbittorrent", Ports: []string{"http"}}}},
		{"bad sides", []SimpleRule{{From: "media/sonarr", To: "qbit/qbittorrent", Sides: "sideways"}}},
		{"empty", nil},
		// BE-5: an entity source with sides=egress produces no policy (entities
		// carry no egress) — a silent no-op the user should be told about.
		{"entity egress-only", []SimpleRule{{From: "entity:world", To: "qbit/qbittorrent", Sides: "egress"}}},
		// symmetric: entity destination with sides=ingress.
		{"entity ingress-only", []SimpleRule{{From: "media/sonarr", To: "entity:world", Sides: "ingress"}}},
	} {
		if _, _, err := GenerateCNPs(snap, tc.rules); err == nil {
			t.Errorf("%s: want error", tc.name)
		}
	}
}

// BE-4: a workload with no stable labels would generate matchLabels:{} — a
// namespace-wide allow. GenerateCNPs must refuse rather than emit that.
func TestSimpleRuleRejectsLabellessWorkload(t *testing.T) {
	snap := testSnap()
	snap.Workloads = append(snap.Workloads, snapshot.Workload{
		Namespace: "media", Name: "bare", Kind: "Deployment", Replicas: 1})

	// Label-less workload as the subject (egress side).
	if _, _, err := GenerateCNPs(snap, []SimpleRule{
		{From: "media/bare", To: "qbit/qbittorrent"},
	}); err == nil {
		t.Error("a label-less subject workload must be rejected")
	}
	// Label-less workload as the peer (would become a namespace-wide peer).
	if _, _, err := GenerateCNPs(snap, []SimpleRule{
		{From: "media/sonarr", To: "media/bare"},
	}); err == nil {
		t.Error("a label-less peer workload must be rejected")
	}
}

// BE-7: a deletion of a policy that is not in the snapshot is a caller error,
// surfaced as ErrNoSuchPolicy so the handler can map it to 400.
func TestDeleteUnknownPolicyIsErrNoSuchPolicy(t *testing.T) {
	snap := testSnap()
	_, err := Compute(snap, Changes{Delete: []string{"CiliumNetworkPolicy/media/ghost"}})
	if !errors.Is(err, ErrNoSuchPolicy) {
		t.Errorf("err = %v, want ErrNoSuchPolicy", err)
	}
}

// BE-7: an empty change set surfaces as ErrEmptyChangeSet (also a 400).
func TestEmptyChangeSetIsErrEmptyChangeSet(t *testing.T) {
	snap := testSnap()
	_, err := Compute(snap, Changes{})
	if !errors.Is(err, ErrEmptyChangeSet) {
		t.Errorf("err = %v, want ErrEmptyChangeSet", err)
	}
}
