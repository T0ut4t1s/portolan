// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

// Package graph turns a snapshot into a renderable policy topology: nodes
// (workloads, entities, CIDRs, FQDNs) and directional allow-edges derived
// from every policy rule.
//
// The interpretation here is VISUALIZATION-GRADE: selector matching and
// namespace scoping follow Cilium and NetworkPolicy semantics closely
// enough to draw an honest map, but this package is not a policy engine
// and never claims verdict-grade accuracy — that is what-if's job, which
// uses Cilium's own engine. Constructs the builder cannot interpret are
// counted in Graph.Warnings rather than silently dropped.
package graph

import "encoding/json"

// Graph is the JSON document embedded into the rendered map.
type Graph struct {
	Cluster    string      `json:"cluster,omitempty"`
	TakenAt    string      `json:"takenAt"`
	Tool       string      `json:"tool"`
	Namespaces []Namespace `json:"namespaces"`
	// Externals are non-workload peers referenced by policies: entities
	// (world, cluster, kube-apiserver, …), CIDRs, and FQDN groups.
	Externals []External `json:"externals"`
	Edges     []Edge     `json:"edges"`
	// Warnings counts policy constructs the builder does not interpret
	// (L7 rule bodies, deny rules, toServices, node policies). Rendered as
	// an honesty banner.
	Warnings []string `json:"warnings"`
	// DeadRefs names every selector reference that matched no live
	// workload — "policy → selector" — food for the audit view. May be
	// intentional (scaled-down node, future pods) or a dead rule.
	DeadRefs []string `json:"deadRefs,omitempty"`
	// Phantoms are the renderable form of DeadRefs: one pseudo-node per
	// distinct unmatched selector, docked in its namespace when the scope
	// resolves to exactly one. Their edges carry Dead=true; the map hides
	// both behind a toggle so dormant rules can be seen where they would
	// land instead of read as a count.
	Phantoms []Phantom `json:"phantoms,omitempty"`
	// PolicyRules carries each policy's rule payloads verbatim, keyed by
	// the same provenance strings edges use — the inspector's "show me the
	// actual policy" escape hatch. Resolved effects stay the primary view;
	// this is the raw source for the few moments that need it.
	PolicyRules map[string][]json.RawMessage `json:"policyRules,omitempty"`
	// Flows is the observed-traffic overlay, present when the snapshot
	// carried a Hubble capture (see FlowOverlay).
	Flows *FlowOverlay `json:"flows,omitempty"`
	Stats Stats        `json:"stats"`
}

// Namespace groups the workload nodes it contains.
type Namespace struct {
	Name string `json:"name"`
	// DefaultDeny is a heuristic flag: true when the namespace has a
	// default-deny posture in either direction. It is the OR of the two
	// per-direction flags below, kept for the namespace badge and backward
	// compatibility.
	DefaultDeny bool `json:"defaultDeny,omitempty"`
	// DefaultDenyIngress/DefaultDenyEgress split the posture by direction:
	// an all-endpoints policy governing that direction. The ingress flag is
	// what a half-open finding turns on — an egress-only deny does not stop
	// a workload from being reached.
	DefaultDenyIngress bool       `json:"defaultDenyIngress,omitempty"`
	DefaultDenyEgress  bool       `json:"defaultDenyEgress,omitempty"`
	PolicyCount        int        `json:"policyCount"`
	Workloads          []Workload `json:"workloads"`
}

// Workload is one node inside a namespace card.
type Workload struct {
	ID       string            `json:"id"` // "namespace/name"
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Replicas int               `json:"replicas"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// External is a pseudo-node for a non-workload peer.
type External struct {
	ID   string `json:"id"`   // "entity:world", "cidr:10.0.0.0/8", "fqdn:example.com"
	Kind string `json:"kind"` // "entity" | "cidr" | "fqdn"
	Name string `json:"name"`
}

// Phantom is a pseudo-node for a selector that matched no live workload.
type Phantom struct {
	ID string `json:"id"` // "dead:<ns>|<selector summary>"
	// Namespace is set when the selector's scope resolved to exactly one
	// namespace; phantoms without one render on the externals rail.
	Namespace string `json:"namespace,omitempty"`
	// Label is the selector summary shown on the chip.
	Label    string   `json:"label"`
	Policies []string `json:"policies"`
}

// Edge is one aggregated directional allow: src may reach dst on Ports.
type Edge struct {
	Src string `json:"s"`
	Dst string `json:"d"`
	// Ports like "8080/TCP", "53/UDP", "any"; sorted, deduplicated.
	Ports []string `json:"ports"`
	Cross bool     `json:"cross,omitempty"` // src and dst in different namespaces
	// DeclaredEgress/DeclaredIngress record which side's policy produced
	// this edge. A workload→workload edge declared by only one side, whose
	// receiving namespace is default-deny, is a likely misconfiguration
	// (traffic allowed out but dropped on arrival) and is highlighted.
	DeclaredEgress  bool `json:"eg,omitempty"`
	DeclaredIngress bool `json:"in,omitempty"`
	// BroadEgress/BroadIngress mark sides satisfied not by a per-peer rule
	// but by a broad allowance (entity:cluster, entity:all, all-CIDR) held
	// by that workload — covered, though less precisely.
	BroadEgress  bool `json:"beg,omitempty"`
	BroadIngress bool `json:"bin,omitempty"`
	// L7 marks edges whose port rules carry L7 sections (rendered as a
	// badge; rule bodies are not interpreted).
	L7 bool `json:"l7,omitempty"`
	// Dead marks edges with a phantom endpoint — a rule declared against a
	// selector matching no live workload. Excluded from stats and findings;
	// rendered only behind the unmatched-refs toggle.
	Dead bool `json:"dead,omitempty"`
	// Policies lists "kind/namespace/name" provenance, sorted.
	Policies []string `json:"policies"`
}

// Stats feed the header chips.
type Stats struct {
	Namespaces int `json:"namespaces"`
	Workloads  int `json:"workloads"`
	Policies   int `json:"policies"`
	Edges      int `json:"edges"`
	CrossEdges int `json:"crossEdges"`
}
