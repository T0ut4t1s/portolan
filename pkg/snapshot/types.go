// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

// Package snapshot defines the snapshot schema — the stable contract every
// Portolan producer and consumer speaks. A snapshot is an immutable,
// self-contained capture of the policy-relevant state of one cluster at one
// moment: namespaces, workloads, and raw policy objects.
//
// Schema stability: SchemaVersion bumps on breaking changes only. Additive
// fields are always safe. Consumers must tolerate unknown fields.
package snapshot

import (
	"encoding/json"
	"time"
)

// SchemaVersion identifies the snapshot wire format produced by this build.
const SchemaVersion = "1"

// ToolName is the canonical producer name recorded in snapshot provenance.
const ToolName = "portolan"

// PolicyKind discriminates the raw policy payloads carried in a snapshot.
// The set is open-ended by design: additional CNIs land as new kinds plus a
// matching Evaluator implementation — never as schema rewrites.
type PolicyKind string

const (
	KindCNP    PolicyKind = "CiliumNetworkPolicy"
	KindCCNP   PolicyKind = "CiliumClusterwideNetworkPolicy"
	KindNetPol PolicyKind = "NetworkPolicy"
)

// Snapshot is the root document serialized to snapshot.json.
type Snapshot struct {
	SchemaVersion string    `json:"schemaVersion"`
	TakenAt       time.Time `json:"takenAt"`
	// Cluster is a human-chosen identifier (--cluster-name); never derived
	// from anything sensitive. Empty is fine for single-cluster use.
	Cluster string `json:"cluster,omitempty"`
	// Tool records the producing binary and version for provenance.
	Tool ToolInfo `json:"tool"`

	// Sources records, per policy kind, whether collection succeeded — so a
	// degraded capture (CRD not served) is distinguishable from a healthy
	// zero-policy cluster inside the artifact itself, not just on stderr.
	Sources []SourceStatus `json:"sources"`

	Namespaces []Namespace `json:"namespaces"`
	Workloads  []Workload  `json:"workloads"`
	Policies   []Policy    `json:"policies"`
}

// ToolInfo records provenance of the snapshot.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SourceStatus reports the collection outcome for one policy kind.
type SourceStatus struct {
	Kind PolicyKind `json:"kind"`
	// Status is "ok" (listed successfully) or "skipped" (resource not served
	// by this cluster). Hard failures abort the whole snapshot instead.
	Status string `json:"status"`
	// Count is the number of policies captured (0 when skipped).
	Count int `json:"count"`
	// Reason explains a skip; empty when Status is "ok".
	Reason string `json:"reason,omitempty"`
}

// Namespace carries the labels policy selectors match against.
type Namespace struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
}

// Workload is a deduplicated group of pods sharing the same stable
// controller identity — the node granularity of the rendered map. Pods are
// resolved to the topmost stable controller: ReplicaSets collapse to their
// owning Deployment, Jobs to their owning CronJob (both via real
// ownerReference lookups, never name heuristics), so workload identity
// survives rollouts and schedule ticks.
type Workload struct {
	Namespace string `json:"namespace"`
	// Name is the resolved controller name, or the pod name for bare pods.
	Name string `json:"name"`
	// Kind is the resolved controller kind ("Deployment", "StatefulSet",
	// "CronJob", …), or "Pod" for bare pods.
	Kind string `json:"kind"`
	// Labels are the pod labels — what endpointSelectors actually match —
	// minus controller-injected churn labels (pod-template-hash, job-name,
	// controller-uid) that no policy selects on and that would otherwise
	// make every rollout look like a topology change.
	Labels map[string]string `json:"labels,omitempty"`
	// Replicas counts live (non-terminal) pods behind this workload at
	// capture time.
	Replicas int `json:"replicas"`
}

// Policy wraps one policy object. Rules carries the object's rule payloads
// verbatim, exactly as the API server returned them: consumers that
// understand a Kind parse them; consumers that don't must pass them through
// untouched. This is what keeps the schema CNI-agnostic without modeling
// every CNI's rule language.
type Policy struct {
	Kind PolicyKind `json:"kind"`
	// Namespace is empty for cluster-scoped kinds (e.g. CCNP).
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	// APIVersion as served (e.g. "cilium.io/v2", "networking.k8s.io/v1").
	APIVersion string `json:"apiVersion"`
	// Labels are the policy object's own metadata labels.
	Labels map[string]string `json:"labels,omitempty"`
	// Rules is the ordered list of rule payloads. For Cilium kinds this is
	// .spec (if set) followed by every element of .specs (if set) — both
	// forms are valid simultaneously and both are enforced, so both are
	// captured. For NetworkPolicy it is exactly one element: the .spec.
	Rules []json.RawMessage `json:"rules"`
}
