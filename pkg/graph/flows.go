// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package graph

import (
	"cmp"
	"slices"
	"time"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

// FlowOverlay is observed traffic joined onto the graph's node ids — what
// the datapath DID, drawn over what policy PERMITS. Pure observation: these
// are aggregated Hubble events, never a policy evaluation.
type FlowOverlay struct {
	// Status mirrors the capture: "ok", or "error" with Reason when the
	// snapshot recorded a failed capture (the overlay then renders a notice
	// instead of pretending there was no traffic).
	Status     string    `json:"status"`
	Reason     string    `json:"reason,omitempty"`
	Window     string    `json:"window"`
	From       time.Time `json:"from,omitzero"`
	To         time.Time `json:"to,omitzero"`
	OldestFlow time.Time `json:"oldestFlow,omitzero"`
	FlowsSeen  int       `json:"flowsSeen"`
	LostEvents int       `json:"lostEvents,omitempty"`
	// Observed aggregates forwarded flows per (src,dst). Declared=false
	// marks a ghost: traffic with no per-pair declared edge — riding a
	// broad allowance or a namespace without default-deny.
	Observed []ObservedEdge `json:"observed"`
	// Drops are denied flows; each is alert-grade.
	Drops []DropEdge `json:"drops"`
	// NotShown counts observed edges skipped because an endpoint is not a
	// node on this map (a pod that died before the snapshot, an
	// unresolvable peer, or a self-edge).
	NotShown int `json:"notShown,omitempty"`
}

// ObservedEdge is forwarded traffic between two map nodes.
type ObservedEdge struct {
	Src      string   `json:"s"`
	Dst      string   `json:"d"`
	Ports    []string `json:"ports,omitempty"`
	Count    int      `json:"n"`
	Declared bool     `json:"dec,omitempty"`
}

// DropEdge is denied traffic between two map nodes, kept per-port and
// per-reason (unlike Observed, aggregating drops would blur the alert).
type DropEdge struct {
	Src      string    `json:"s"`
	Dst      string    `json:"d"`
	Port     string    `json:"port,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Count    int       `json:"n"`
	LastSeen time.Time `json:"last,omitzero"`
}

// attachFlows joins a snapshot's flow capture onto the built graph. Flow
// peers already carry the same resolved controller identities the graph's
// workload nodes use, so the join is a lookup, not a heuristic. Entities
// observed in traffic but never referenced by any policy (e.g. remote-node)
// are added to Externals so the map has a node to draw them at.
func attachFlows(g *Graph, fc *snapshot.FlowCapture) {
	if fc == nil {
		return
	}
	ov := &FlowOverlay{
		Status:     fc.Status,
		Reason:     fc.Reason,
		Window:     fc.Window,
		From:       fc.From,
		To:         fc.To,
		OldestFlow: fc.OldestFlow,
		FlowsSeen:  fc.FlowsSeen,
		LostEvents: fc.LostEvents,
		Observed:   []ObservedEdge{},
		Drops:      []DropEdge{},
	}
	g.Flows = ov
	if fc.Status != "ok" {
		return
	}

	nodes := map[string]bool{}
	for _, ns := range g.Namespaces {
		for _, wl := range ns.Workloads {
			nodes[wl.ID] = true
		}
	}
	for _, ext := range g.Externals {
		nodes[ext.ID] = true
	}
	resolve := func(p snapshot.FlowPeer) (string, bool) {
		if p.Entity != "" {
			id := "entity:" + p.Entity
			if !nodes[id] {
				g.Externals = append(g.Externals, External{ID: id, Kind: "entity", Name: p.Entity})
				nodes[id] = true
			}
			return id, true
		}
		if p.Namespace == "" || p.Name == "" {
			return "", false
		}
		id := p.Namespace + "/" + p.Name
		return id, nodes[id]
	}

	declared := map[string]bool{}
	for _, e := range g.Edges {
		declared[e.Src+"|"+e.Dst] = true
	}

	type obsKey struct{ s, d string }
	type dropKey struct{ s, d, port, reason string }
	obs := map[obsKey]*ObservedEdge{}
	drops := map[dropKey]*DropEdge{}

	for _, fe := range fc.Edges {
		src, okS := resolve(fe.Src)
		dst, okD := resolve(fe.Dst)
		if !okS || !okD || src == dst {
			ov.NotShown++
			continue
		}
		switch fe.Verdict {
		case "FORWARDED":
			k := obsKey{src, dst}
			o, ok := obs[k]
			if !ok {
				o = &ObservedEdge{Src: src, Dst: dst, Declared: declared[src+"|"+dst]}
				obs[k] = o
			}
			o.Count += fe.Count
			if fe.Port != "" {
				o.Ports = append(o.Ports, fe.Port)
			}
		case "DROPPED":
			k := dropKey{src, dst, fe.Port, fe.DropReason}
			d, ok := drops[k]
			if !ok {
				d = &DropEdge{Src: src, Dst: dst, Port: fe.Port, Reason: fe.DropReason}
				drops[k] = d
			}
			d.Count += fe.Count
			if fe.LastSeen.After(d.LastSeen) {
				d.LastSeen = fe.LastSeen
			}
		}
	}

	for _, o := range obs {
		slices.Sort(o.Ports)
		o.Ports = slices.Compact(o.Ports)
		ov.Observed = append(ov.Observed, *o)
	}
	slices.SortFunc(ov.Observed, func(a, b ObservedEdge) int {
		return cmp.Or(cmp.Compare(a.Src, b.Src), cmp.Compare(a.Dst, b.Dst))
	})
	for _, d := range drops {
		ov.Drops = append(ov.Drops, *d)
	}
	slices.SortFunc(ov.Drops, func(a, b DropEdge) int {
		return cmp.Or(
			cmp.Compare(a.Src, b.Src),
			cmp.Compare(a.Dst, b.Dst),
			cmp.Compare(a.Port, b.Port),
			cmp.Compare(a.Reason, b.Reason),
		)
	})
	slices.SortFunc(g.Externals, func(a, b External) int { return cmp.Compare(a.ID, b.ID) })
}
