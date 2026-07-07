// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package whatif

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

// Sentinel errors for change-set problems the caller can act on. Both are
// user mistakes (the HTTP handler maps them to 400), so callers match with
// errors.Is rather than sniffing message text.
var (
	// ErrNoSuchPolicy is returned when a deletion names a policy that is not
	// in the snapshot.
	ErrNoSuchPolicy = errors.New("no such policy in the snapshot")
	// ErrEmptyChangeSet is returned when a change set resolves to nothing to
	// simulate.
	ErrEmptyChangeSet = errors.New("change set is empty: nothing to simulate")
)

// canaryPort probes "any port not named by any rule" so allow-all edges
// (no toPorts) surface as a delta even when no concrete port mentions them.
const canaryPort = 61357

// Changes is the draft change set applied on top of the snapshot's
// policies: Apply replaces-or-adds by (kind, namespace, name); Delete
// removes.
type Changes struct {
	Apply  []snapshot.Policy
	Delete []string // provenance form: Kind/ns/name or Kind/name
}

// Delta is one pair whose verdict changes, with the ports it changes on.
type Delta struct {
	Src   string   `json:"s"`
	Dst   string   `json:"d"`
	Ports []string `json:"ports"` // "8080/TCP"; "other ports" for the canary
	// Via names the responsible rules (draft side for additions, baseline
	// side for removals), from the engine's own rule-origin labels.
	Via []string `json:"via,omitempty"`
	// HealsHalfOpen marks additions whose baseline was the classic one-sided
	// state: egress allowed, ingress denied.
	HealsHalfOpen bool `json:"healsHalfOpen,omitempty"`
}

// HalfOpenDelta is a one-sided change that does NOT change the end-to-end
// verdict — the exact mistake whatif exists to catch before it ships.
type HalfOpenDelta struct {
	Src   string   `json:"s"`
	Dst   string   `json:"d"`
	Ports []string `json:"ports"`
	// Side is "egress" (sender may now send, receiver still denies) or
	// "ingress" (receiver would now accept, sender still can't send).
	Side string `json:"side"`
}

// FlowImpact is one observed flow whose verdict the draft changes.
type FlowImpact struct {
	Src     string `json:"s"`
	Dst     string `json:"d"`
	Port    string `json:"port"`
	Count   int    `json:"n"`
	Reason  string `json:"reason,omitempty"` // drop reason for fixes
	Verdict string `json:"verdict"`          // observed verdict in the window
}

// Result is the full blast radius of a change set.
type Result struct {
	Added    []Delta         `json:"added"`
	Removed  []Delta         `json:"removed"`
	HalfOpen []HalfOpenDelta `json:"halfOpenIntroduced"`
	// FixesDrops are observed DROPPED flows the draft would allow.
	// BreaksFlows are observed FORWARDED flows the draft would deny —
	// live traffic a tightening would cut.
	FixesDrops  []FlowImpact `json:"fixesDrops"`
	BreaksFlows []FlowImpact `json:"breaksFlows"`
	// PolicyChanges narrates what the change set did: added/replaced/deleted.
	PolicyChanges []string `json:"policyChanges"`
	Warnings      []string `json:"warnings,omitempty"`
	// Probes counts (pair, port) verdicts computed per repository.
	Probes int `json:"probes"`
}

// Compute evaluates the change set against the snapshot with two engine
// instances — baseline and draft — and diffs their verdicts over every
// workload/entity pair and every port any rule or observed flow names.
func Compute(snap *snapshot.Snapshot, ch Changes) (*Result, error) {
	res := &Result{Added: []Delta{}, Removed: []Delta{}, HalfOpen: []HalfOpenDelta{},
		FixesDrops: []FlowImpact{}, BreaksFlows: []FlowImpact{}}

	basePols := snap.Policies
	draftPols, changes, err := applyChanges(basePols, ch)
	if err != nil {
		return nil, err
	}
	res.PolicyChanges = changes

	nodes, idmap := buildNodes(snap)
	base, err := newEngine(basePols, nodes, idmap)
	if err != nil {
		return nil, fmt.Errorf("building baseline engine: %w", err)
	}
	draft, err := newEngine(draftPols, nodes, idmap)
	if err != nil {
		return nil, fmt.Errorf("building draft engine: %w", err)
	}
	res.Warnings = append(res.Warnings, base.Warnings...)
	for _, w := range draft.Warnings {
		if !slices.Contains(res.Warnings, w) {
			res.Warnings = append(res.Warnings, w)
		}
	}

	probes := probePorts(basePols, draftPols, snap.Flows, res)

	type pairKey struct{ s, d string }
	added := map[pairKey]*Delta{}
	removed := map[pairKey]*Delta{}
	halfOpen := map[pairKey]*HalfOpenDelta{}

	for _, src := range nodes {
		for _, dst := range nodes {
			if src.ID == dst.ID {
				continue
			}
			// Entity↔entity passages (world→host, …) are node-plumbing, not
			// workload topology; skip them.
			if strings.HasPrefix(src.ID, "entity:") && strings.HasPrefix(dst.ID, "entity:") {
				continue
			}
			for _, pp := range probes {
				vb, err := base.lookup(src, dst, pp.proto, pp.port)
				if err != nil {
					return nil, err
				}
				vd, err := draft.lookup(src, dst, pp.proto, pp.port)
				if err != nil {
					return nil, err
				}
				res.Probes++
				if vb.Egress == vd.Egress && vb.Ingress == vd.Ingress {
					continue
				}
				k := pairKey{src.ID, dst.ID}
				switch {
				case !vb.Allowed() && vd.Allowed():
					d := added[k]
					if d == nil {
						d = &Delta{Src: src.ID, Dst: dst.ID, HealsHalfOpen: vb.Egress && !vb.Ingress}
						added[k] = d
					}
					d.Ports = append(d.Ports, pp.label)
					d.Via = mergeVia(d.Via, vd.EgressVia, vd.IngressVia)
				case vb.Allowed() && !vd.Allowed():
					d := removed[k]
					if d == nil {
						d = &Delta{Src: src.ID, Dst: dst.ID}
						removed[k] = d
					}
					d.Ports = append(d.Ports, pp.label)
					d.Via = mergeVia(d.Via, vb.EgressVia, vb.IngressVia)
				default:
					// End-to-end verdict unchanged but a side flipped: the
					// one-sided change. Only the newly-opened-but-still-blocked
					// shape is a finding.
					if !vd.Allowed() {
						side := ""
						if !vb.Egress && vd.Egress && !vd.Ingress {
							side = "egress"
						} else if !vb.Ingress && vd.Ingress && !vd.Egress {
							side = "ingress"
						}
						if side != "" {
							h := halfOpen[k]
							if h == nil {
								h = &HalfOpenDelta{Src: src.ID, Dst: dst.ID, Side: side}
								halfOpen[k] = h
							}
							h.Ports = append(h.Ports, pp.label)
						}
					}
				}
			}
		}
	}

	// A delta that flipped on EVERY probe — all named ports plus both
	// "any other port" canaries — is an all-ports change; listing dozens
	// of port labels would bury that fact instead of stating it.
	collapse := func(ports []string) []string {
		ports = sortPorts(ports)
		if len(ports) == len(probes) {
			return []string{"all ports"}
		}
		return ports
	}
	for _, d := range added {
		d.Ports = collapse(d.Ports)
		res.Added = append(res.Added, *d)
	}
	for _, d := range removed {
		d.Ports = collapse(d.Ports)
		res.Removed = append(res.Removed, *d)
	}
	for _, h := range halfOpen {
		h.Ports = collapse(h.Ports)
		res.HalfOpen = append(res.HalfOpen, *h)
	}
	sortDeltas(res.Added)
	sortDeltas(res.Removed)
	slices.SortFunc(res.HalfOpen, func(a, b HalfOpenDelta) int {
		return cmp.Or(cmp.Compare(a.Src, b.Src), cmp.Compare(a.Dst, b.Dst))
	})

	if err := flowImpact(snap, nodes, base, draft, res); err != nil {
		return nil, err
	}
	return res, nil
}

// flowImpact cross-checks observed traffic: drops the draft would fix,
// forwarded flows the draft would break.
func flowImpact(snap *snapshot.Snapshot, nodes []node, base, draft *engine, res *Result) error {
	if snap.Flows == nil || snap.Flows.Status != "ok" {
		return nil
	}
	byID := map[string]node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	peerID := func(p snapshot.FlowPeer) string {
		if p.Entity != "" {
			return "entity:" + p.Entity
		}
		return p.Namespace + "/" + p.Name
	}
	for _, fe := range snap.Flows.Edges {
		src, okS := byID[peerID(fe.Src)]
		dst, okD := byID[peerID(fe.Dst)]
		if !okS || !okD {
			continue
		}
		proto, port, ok := parsePort(fe.Port)
		if !ok {
			continue
		}
		vb, err := base.lookup(src, dst, proto, port)
		if err != nil {
			return err
		}
		vd, err := draft.lookup(src, dst, proto, port)
		if err != nil {
			return err
		}
		imp := FlowImpact{Src: src.ID, Dst: dst.ID, Port: fe.Port, Count: fe.Count,
			Reason: fe.DropReason, Verdict: fe.Verdict}
		switch fe.Verdict {
		case "DROPPED":
			if !vb.Allowed() && vd.Allowed() {
				res.FixesDrops = append(res.FixesDrops, imp)
			}
		case "FORWARDED":
			if vb.Allowed() && !vd.Allowed() {
				res.BreaksFlows = append(res.BreaksFlows, imp)
			}
		}
	}
	return nil
}

// applyChanges produces the draft policy set and a human narration of what
// changed. Draft policies replace same-identity baseline policies.
func applyChanges(base []snapshot.Policy, ch Changes) ([]snapshot.Policy, []string, error) {
	key := func(p snapshot.Policy) string { return provenance(p) }
	deletes := map[string]bool{}
	for _, d := range ch.Delete {
		deletes[d] = true
	}
	replace := map[string]snapshot.Policy{}
	for _, p := range ch.Apply {
		replace[key(p)] = p
	}

	var out []snapshot.Policy
	var changes []string
	seenDelete := map[string]bool{}
	for _, p := range base {
		k := key(p)
		if deletes[k] {
			seenDelete[k] = true
			changes = append(changes, "deleted "+k)
			continue
		}
		if np, ok := replace[k]; ok {
			out = append(out, np)
			delete(replace, k)
			changes = append(changes, "replaced "+k)
			continue
		}
		out = append(out, p)
	}
	for _, p := range ch.Apply {
		if _, stillNew := replace[key(p)]; stillNew {
			out = append(out, p)
			changes = append(changes, "added "+key(p))
		}
	}
	for _, d := range ch.Delete {
		if !seenDelete[d] {
			return nil, nil, fmt.Errorf("delete %s: %w", d, ErrNoSuchPolicy)
		}
	}
	slices.Sort(changes)
	if len(changes) == 0 {
		return nil, nil, ErrEmptyChangeSet
	}
	return out, changes, nil
}

// portProbe is one concrete (proto, port) the diff is evaluated at.
type portProbe struct {
	proto u8proto.U8proto
	port  uint16
	label string
}

// probePorts collects every concrete port named by any rule in either
// policy set, every observed flow port, plus a canary for "any other
// port". Named (string) ports are warned about — snapshots carry no
// container port names to resolve them with.
func probePorts(base, draft []snapshot.Policy, flows *snapshot.FlowCapture, res *Result) []portProbe {
	seen := map[string]portProbe{}
	add := func(protoStr, portStr string) {
		proto := parseProto(protoStr)
		if proto == 0 {
			return
		}
		n, err := strconv.Atoi(portStr)
		if err != nil || n <= 0 || n > 65535 {
			if err != nil && portStr != "" {
				w := fmt.Sprintf("named port %q cannot be resolved from a snapshot; verdicts for it are not probed", portStr)
				if !slices.Contains(res.Warnings, w) {
					res.Warnings = append(res.Warnings, w)
				}
			}
			return
		}
		label := fmt.Sprintf("%d/%s", n, strings.ToUpper(protoStr))
		seen[label] = portProbe{proto: proto, port: uint16(n), label: label}
	}

	for _, pols := range [][]snapshot.Policy{base, draft} {
		for _, pol := range pols {
			for _, raw := range pol.Rules {
				collectRulePorts(raw, add)
			}
		}
	}
	if flows != nil {
		for _, fe := range flows.Edges {
			if proto, port, ok := parsePort(fe.Port); ok {
				seen[fe.Port] = portProbe{proto: proto, port: port, label: fe.Port}
			}
		}
	}
	out := make([]portProbe, 0, len(seen)+2)
	for _, p := range seen {
		out = append(out, p)
	}
	out = append(out,
		portProbe{proto: u8proto.TCP, port: canaryPort, label: "other ports"},
		portProbe{proto: u8proto.UDP, port: canaryPort, label: "other ports/UDP"},
	)
	slices.SortFunc(out, func(a, b portProbe) int { return cmp.Compare(a.label, b.label) })
	return out
}

func parseProto(s string) u8proto.U8proto {
	switch strings.ToUpper(s) {
	case "TCP", "", "ANY":
		return u8proto.TCP
	case "UDP":
		return u8proto.UDP
	case "SCTP":
		return u8proto.SCTP
	}
	return 0
}

// parsePort parses the snapshot's "8080/TCP" port form.
func parsePort(s string) (u8proto.U8proto, uint16, bool) {
	num, protoStr, ok := strings.Cut(s, "/")
	if !ok {
		return 0, 0, false
	}
	proto := parseProto(protoStr)
	n, err := strconv.Atoi(num)
	if proto == 0 || err != nil || n <= 0 || n > 65535 {
		return 0, 0, false
	}
	return proto, uint16(n), true
}

func mergeVia(cur []string, more ...[]string) []string {
	for _, m := range more {
		for _, v := range m {
			if !slices.Contains(cur, v) {
				cur = append(cur, v)
			}
		}
	}
	slices.Sort(cur)
	return cur
}

func sortPorts(ports []string) []string {
	slices.Sort(ports)
	return slices.Compact(ports)
}

// collectRulePorts walks one raw rule payload and reports every port it
// names. A structural walk (any object carrying a "port" key) covers both
// the Cilium toPorts form and the NetworkPolicy ports form without
// re-modeling either schema.
func collectRulePorts(raw []byte, add func(protoStr, portStr string)) {
	var doc any
	if err := jsonUnmarshal(raw, &doc); err != nil {
		return
	}
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if p, ok := t["port"]; ok {
				proto, _ := t["protocol"].(string)
				switch pv := p.(type) {
				case string:
					add(proto, pv)
				case float64:
					add(proto, strconv.Itoa(int(pv)))
				}
			}
			for _, vv := range t {
				walk(vv)
			}
		case []any:
			for _, vv := range t {
				walk(vv)
			}
		}
	}
	walk(doc)
}

func sortDeltas(ds []Delta) {
	slices.SortFunc(ds, func(a, b Delta) int {
		return cmp.Or(cmp.Compare(a.Src, b.Src), cmp.Compare(a.Dst, b.Dst))
	})
}
