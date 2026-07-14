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

	// Flows carries optional traffic observations from Hubble Relay
	// (--flows). Nil when flow capture was not requested. Flow data is
	// inherently time-varying, so this section is exempt from the
	// byte-identical determinism the policy sections guarantee — but edges
	// are aggregated and sorted, so identical traffic yields identical edges.
	Flows *FlowCapture `json:"flows,omitempty"`
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

// FlowCapture summarizes one bounded observation window read from Hubble
// Relay. It is an OBSERVATION overlay, never an evaluation: it reports what
// the datapath actually did, aggregated to workload granularity, alongside
// enough honesty metadata to judge coverage (a relay ring buffer may not
// span the whole requested window, and events can be lost under load).
type FlowCapture struct {
	// Status is "ok" or "error". On error the snapshot is still valid —
	// flow capture degrades, it never aborts a policy capture.
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	// Server is the Hubble Relay address the capture came from.
	Server string `json:"server,omitempty"`
	// Source records HOW the window was observed, which decides how much the
	// absence of an edge is worth. The two differ by orders of magnitude and
	// must never be confused for one another.
	Source FlowSourceKind `json:"source,omitempty"`
	// Window is the requested look-back (e.g. "15m"); From/To its bounds.
	Window string    `json:"window"`
	From   time.Time `json:"from,omitzero"`
	To     time.Time `json:"to,omitzero"`
	// Watched is how much of the window was actually observed, and Coverage
	// the same as a fraction of it (0..1).
	//
	// These exist because the polled source systematically lies without them.
	// Hubble's event buffer is bounded by CAPACITY, not time (4095 events per
	// agent by default), so on a busy cluster a request for 15m of history is
	// answered with whatever few seconds still fit — and the reply carries no
	// hint that it fell short. A poller then reports 15m of observation having
	// watched perhaps 1% of it. Coverage makes that shortfall impossible to
	// miss; a streamed capture reports the truth from the other direction.
	// Watched never exceeds Window. The bucket the window starts in overhangs
	// its own start, so the raw sum of observed time can run a few minutes past
	// the window asked for — and reporting "24h9m watched, 100% of a 24h
	// window" is a self-evidently broken sentence that costs the reader trust
	// in every other number on the page. The overhang is an artifact of bucket
	// granularity, not information, so it is clamped away here exactly as the
	// ratio already was.
	Watched string `json:"watched,omitempty"`
	// WatchedSec is Watched as a number, so consumers can divide by it. Raw
	// counts are only comparable between two runs at the same coverage; a rate
	// over watched time is comparable between any two.
	WatchedSec float64 `json:"watchedSec,omitempty"`
	Coverage   float64 `json:"coverage,omitempty"`
	// BucketSec is the width of a time bucket, and the denominator for
	// FlowEdge.Buckets: "seen in 3 of the 96 buckets in this window". Zero when
	// the source is not bucketed (a one-shot buffer read).
	BucketSec float64 `json:"bucketSec,omitempty"`
	// OldestFlow is the earliest moment this capture can speak for. When it is
	// noticeably later than From, absence of an edge means "not observed", not
	// "did not happen" — even more than usual.
	OldestFlow time.Time `json:"oldestFlow,omitzero"`
	// FlowsSeen counts raw flow events consumed before aggregation.
	// Skipped counts events ignored as noise: neither endpoint resolvable
	// to a cluster workload (LAN broadcast chatter observed on node NICs)
	// or Cilium health-check traffic. LostEvents counts events the Hubble
	// pipeline itself dropped under load.
	FlowsSeen  int        `json:"flowsSeen"`
	Skipped    int        `json:"skipped,omitempty"`
	LostEvents int        `json:"lostEvents,omitempty"`
	Edges      []FlowEdge `json:"edges"`
}

// FlowCapture.Status values.
const (
	FlowStatusOK    = "ok"
	FlowStatusError = "error"
	// FlowStatusWarming means the stream is connected but has not flushed an
	// observation yet — the normal state for the first minute of a pod's life.
	// Distinct from error on purpose: a map that reports a failure every time it
	// restarts teaches its readers to ignore failures.
	FlowStatusWarming = "warming"
)

// FlowSourceKind names how a FlowCapture was obtained.
type FlowSourceKind string

const (
	// FlowSourceBuffer is a single point-in-time read of Hubble's event
	// buffer. It is all a one-shot command can do — there is no process to
	// keep listening — and on a busy cluster it sees only the last few
	// seconds however long a window it asks for. Treat its silences as
	// meaningless: it was barely looking.
	FlowSourceBuffer FlowSourceKind = "buffer"
	// FlowSourceStream is accumulated from a continuous follow-mode stream.
	// Its window means what it says, and at high coverage the absence of an
	// edge is genuine evidence that the edge went unused.
	FlowSourceStream FlowSourceKind = "stream"
)

// FlowPeer identifies one side of an observed flow at the same granularity
// as Workload: resolved controller identity when known. Exactly one of
// (Namespace+Name) or Entity is set.
type FlowPeer struct {
	Namespace string `json:"namespace,omitempty"`
	// Name is the resolved controller name (from Hubble's workload metadata
	// or the live-pod index), or the pod name with Kind "Pod" when neither
	// resolves — e.g. a pod that died before the snapshot.
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
	// Entity is a Cilium reserved identity ("world", "host", "remote-node",
	// "kube-apiserver", …) for non-pod peers.
	Entity string `json:"entity,omitempty"`
}

// FlowEdge is one aggregated observation: Count events from Src to Dst on
// Port with Verdict inside the capture window. Only the original direction
// is counted (replies are filtered), so Port is the service port.
type FlowEdge struct {
	Src FlowPeer `json:"src"`
	Dst FlowPeer `json:"dst"`
	// Port like "8080/TCP", "53/UDP", "icmp"; empty when the flow had no L4.
	Port string `json:"port,omitempty"`
	// Verdict is "FORWARDED" or "DROPPED".
	Verdict string `json:"verdict"`
	// DropReason is Cilium's drop_reason_desc (e.g. "POLICY_DENIED") for
	// DROPPED edges.
	DropReason string    `json:"dropReason,omitempty"`
	Count      int       `json:"count"`
	FirstSeen  time.Time `json:"firstSeen,omitzero"`
	LastSeen   time.Time `json:"lastSeen,omitzero"`
	// Buckets is how many distinct time buckets of the window this edge was
	// seen in — the difference between a burst and a habit, MEASURED.
	//
	// A total alone cannot tell them apart, and the two demand opposite
	// responses. 32 drops that all landed inside one 15-minute bucket
	// thirteen hours ago is a pod that had a bad startup and recovered:
	// nothing to do. 32 drops spread across every bucket in the window is
	// something bleeding right now. Printed identically — as they were —
	// the first sends you chasing a problem that already fixed itself.
	//
	// Zero when the source cannot know (a one-shot buffer read has no
	// buckets), which callers must treat as "unknown", never as "never".
	Buckets int `json:"buckets,omitempty"`
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
