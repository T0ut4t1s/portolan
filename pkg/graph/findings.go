// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package graph

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

// FindingsVersion identifies the sidecar wire format.
const FindingsVersion = "1"

// Finding is one thing worth a human's attention, with an identity that
// survives from one run to the next.
//
// The identity is the point. Without it a brief has no memory: the same 54
// selectors are re-argued every morning, a fix cannot be shown to have worked,
// and a decision ("this one is fine, it is a Job") has nowhere to live but the
// reader's head. Everything that changes run to run — counts, timestamps,
// rates, which ephemeral port it happened to pick today — is deliberately NOT
// part of the ID.
type Finding struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // drop | half-open | no-default-deny | world-reachable | dead-selector
	// Title is what the brief calls it, for a human reading the sidecar raw.
	Title string `json:"title"`

	// Identity — the fields the ID is derived from.
	Src      string   `json:"src,omitempty"`
	Dst      string   `json:"dst,omitempty"`
	Port     string   `json:"port,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Selector string   `json:"selector,omitempty"`
	Policies []string `json:"policies,omitempty"`

	// Volatile — reported, never part of the ID.
	Count    int    `json:"count,omitempty"`
	Rate     string `json:"rate,omitempty"`
	Status   string `json:"status,omitempty"`   // NEW | PERSISTING | RESOLVED
	Expected bool   `json:"expected,omitempty"` // job-like: correct to match nothing
}

// FindingSet is a run's findings, for writing beside the brief and for
// comparing against the next one.
type FindingSet struct {
	SchemaVersion string    `json:"schemaVersion"`
	Cluster       string    `json:"cluster,omitempty"`
	TakenAt       string    `json:"takenAt"`
	Findings      []Finding `json:"findings"`
}

// ID derives a stable identity from what a finding IS, never from what it
// happens to measure today.
//
// Counts move, timestamps move, rates move, and Longhorn picks a different
// ephemeral port every run — include any of those and every finding is NEW
// forever, which is the same as having no memory at all.
func findingID(kind string, parts ...string) string {
	h := sha256.New()
	h.Write([]byte(kind))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// ComputeFindings derives the identified finding set from a graph and audit,
// through exactly the same folding, grouping and ranking the brief renders — so
// an ID in the sidecar names the finding the reader is looking at, and not some
// pre-folded ghost of it.
func ComputeFindings(g *Graph, a *Audit) *FindingSet {
	p := prepare(g, a)
	set := &FindingSet{
		SchemaVersion: FindingsVersion,
		Cluster:       g.Cluster,
		TakenAt:       g.TakenAt,
		Findings:      []Finding{},
	}

	rate, _ := ratePerHour(g.Flows)
	for _, d := range p.drops {
		set.Findings = append(set.Findings, Finding{
			ID:    findingID("drop", d.Src, d.Dst, d.Port, d.Reason),
			Kind:  "drop",
			Title: fmt.Sprintf("%s → %s %s (%s)", d.Src, d.Dst, d.Port, d.Reason),
			Src:   d.Src, Dst: d.Dst, Port: d.Port, Reason: d.Reason,
			Count: d.Count, Rate: strings.TrimSpace(rate(d.Count)),
		})
	}
	for _, gr := range p.groups {
		set.Findings = append(set.Findings, Finding{
			ID: findingID("half-open", strings.Join(gr.Policies, ","),
				strings.Join(gr.Ports, ","), gr.SrcNS, gr.DstNS),
			Kind:  "half-open",
			Title: fmt.Sprintf("%s → %s on %s", gr.SrcNS, gr.DstNS, strings.Join(gr.Ports, ", ")),
			Src:   gr.SrcNS, Dst: gr.DstNS, Port: strings.Join(gr.Ports, ","),
			Policies: gr.Policies,
		})
	}
	for _, ns := range a.NoDefaultDeny {
		set.Findings = append(set.Findings, Finding{
			ID:    findingID("no-default-deny", ns),
			Kind:  "no-default-deny",
			Title: fmt.Sprintf("namespace %s has workloads but no default-deny", ns),
			Src:   ns,
		})
	}
	for _, wl := range a.WorldReachable {
		set.Findings = append(set.Findings, Finding{
			ID:    findingID("world-reachable", wl),
			Kind:  "world-reachable",
			Title: fmt.Sprintf("%s declares ingress from world/all", wl),
			Src:   wl,
		})
	}
	for _, r := range append(slices.Clone(p.deadExpected), p.deadReview...) {
		set.Findings = append(set.Findings, Finding{
			ID:       findingID("dead-selector", r.Selector),
			Kind:     "dead-selector",
			Title:    fmt.Sprintf("selector matches no live workload: %s", r.Selector),
			Selector: r.Selector,
			Policies: r.Policies,
			Expected: slices.ContainsFunc(p.deadExpected, func(e deadRefGroup) bool { return e.Selector == r.Selector }),
		})
	}
	return set
}

// Diff annotates cur with NEW / PERSISTING, and returns the findings that were
// in prev and are gone — RESOLVED.
//
// Resolved findings are the whole reward. Without them a fix is invisible: you
// change a policy, the finding stops appearing, and nothing anywhere says it
// was YOU. A tool that only ever grows its list teaches you to stop reading it.
func Diff(cur, prev *FindingSet) (resolved []Finding) {
	if prev == nil {
		for i := range cur.Findings {
			cur.Findings[i].Status = "NEW"
		}
		return nil
	}
	before := map[string]Finding{}
	for _, f := range prev.Findings {
		before[f.ID] = f
	}
	now := map[string]bool{}
	for i := range cur.Findings {
		id := cur.Findings[i].ID
		now[id] = true
		if _, seen := before[id]; seen {
			cur.Findings[i].Status = "PERSISTING"
		} else {
			cur.Findings[i].Status = "NEW"
		}
	}
	for _, f := range prev.Findings {
		if !now[f.ID] {
			f.Status = "RESOLVED"
			resolved = append(resolved, f)
		}
	}
	slices.SortFunc(resolved, func(p, q Finding) int { return strings.Compare(p.Title, q.Title) })
	return resolved
}

// LoadFindings reads a sidecar written by a previous run.
func LoadFindings(r io.Reader) (*FindingSet, error) {
	var set FindingSet
	if err := json.NewDecoder(r).Decode(&set); err != nil {
		return nil, fmt.Errorf("reading findings: %w", err)
	}
	return &set, nil
}

// Marshal renders the set as indented JSON.
func (s *FindingSet) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// LoadSuppressions reads decisions already made, so they stop being re-argued
// every morning.
//
// The format is deliberately the simplest thing that can carry a reason:
//
//	# one per line: <finding-id> <why>
//	a1b2c3d4e5f6  pgbouncer-db-init is a Job — matching nothing at rest is correct
//
// The reason is not optional decoration. A suppression without one is a lie you
// told yourself six months ago and can no longer audit, and the first person to
// find it — possibly you — will have no way to know whether it is still true.
func LoadSuppressions(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		id, why, _ := strings.Cut(text, " ")
		why = strings.TrimSpace(why)
		if why == "" {
			return nil, fmt.Errorf("suppressions line %d: %q has no reason — a suppression "+
				"without a reason cannot be audited later, and will outlive whatever made it true", line, id)
		}
		out[id] = why
	}
	return out, sc.Err()
}
