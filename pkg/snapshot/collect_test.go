// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package snapshot

import (
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestRawRulesSpecOnly(t *testing.T) {
	item := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{"endpointSelector": map[string]any{}},
	}}
	rules, err := rawRules(item)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
}

func TestRawRulesSpecsOnly(t *testing.T) {
	item := &unstructured.Unstructured{Object: map[string]any{
		"specs": []any{map[string]any{"a": 1}, map[string]any{"b": 2}},
	}}
	rules, err := rawRules(item)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
}

// A Cilium policy may carry BOTH .spec and .specs; both are enforced, so
// both must be captured (.spec first, then .specs elements in order).
func TestRawRulesSpecAndSpecs(t *testing.T) {
	item := &unstructured.Unstructured{Object: map[string]any{
		"spec":  map[string]any{"first": true},
		"specs": []any{map[string]any{"second": true}},
	}}
	rules, err := rawRules(item)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
	var first map[string]bool
	if err := json.Unmarshal(rules[0], &first); err != nil || !first["first"] {
		t.Fatalf("rule order wrong: rules[0] = %s", rules[0])
	}
}

func TestRawRulesNeither(t *testing.T) {
	item := &unstructured.Unstructured{Object: map[string]any{}}
	if _, err := rawRules(item); err == nil {
		t.Fatal("want error for object with neither .spec nor .specs")
	}
}

// Zero collected policies must serialize as [], not null — consumers do
// policies.length and schema validators require type: array.
func TestEmptyPoliciesMarshalsAsArray(t *testing.T) {
	snap := &Snapshot{Policies: make([]Policy, 0)}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]json.RawMessage
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatal(err)
	}
	if string(round["policies"]) != "[]" {
		t.Fatalf(`want "policies": [], got %s`, round["policies"])
	}
}

func TestResolveController(t *testing.T) {
	ctrl := true
	pod := func(ns, name, ownerKind, ownerName string) *metav1.PartialObjectMetadata {
		p := &metav1.PartialObjectMetadata{}
		p.Namespace, p.Name = ns, name
		if ownerKind != "" {
			p.OwnerReferences = []metav1.OwnerReference{{Kind: ownerKind, Name: ownerName, Controller: &ctrl}}
		}
		return p
	}
	rsMap := map[nsName]string{{"app", "web-6d9f7c"}: "web"}
	jobMap := map[nsName]string{{"ops", "backup-29719155"}: "backup"}

	cases := []struct {
		pod            *metav1.PartialObjectMetadata
		wantKind, want string
	}{
		{pod("app", "web-6d9f7c-x1", "ReplicaSet", "web-6d9f7c"), "Deployment", "web"},
		// Bare ReplicaSet (not Deployment-owned) keeps its true identity —
		// never renamed by string heuristics.
		{pod("app", "legacy-worker-a1", "ReplicaSet", "legacy-worker"), "ReplicaSet", "legacy-worker"},
		{pod("ops", "backup-29719155-z9", "Job", "backup-29719155"), "CronJob", "backup"},
		// One-shot Job stays a Job.
		{pod("ops", "migrate-v2-q3", "Job", "migrate-v2"), "Job", "migrate-v2"},
		{pod("db", "pg-1", "StatefulSet", "pg"), "StatefulSet", "pg"},
		{pod("dbg", "toolbox", "", ""), "Pod", "toolbox"},
	}
	for _, tc := range cases {
		kind, name := resolveController(tc.pod, rsMap, jobMap)
		if kind != tc.wantKind || name != tc.want {
			t.Errorf("pod %s/%s: got (%s, %s), want (%s, %s)",
				tc.pod.Namespace, tc.pod.Name, kind, name, tc.wantKind, tc.want)
		}
	}
}

func TestCleanLabelsStripsChurn(t *testing.T) {
	in := map[string]string{
		"app":               "web",
		"pod-template-hash": "6d9f7c",
		"job-name":          "backup-29719155",
	}
	out := cleanLabels(in)
	if len(out) != 1 || out["app"] != "web" {
		t.Fatalf("got %v, want only app=web", out)
	}
	if len(in) != 3 {
		t.Fatal("cleanLabels must not mutate its input")
	}
}
