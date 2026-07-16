// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package graph

import (
	"fmt"
	"strings"

	"github.com/T0ut4t1s/portolan/pkg/whatif"
)

// FixCandidate is a policy change that would make ONE specific flag stop
// appearing. It is not a fix, a correction, or a recommendation — the tool does
// not claim to know the right thing to do. It claims only "this change would
// clear this flag", and hands the blast radius (what else it touches) to
// what-if and the reader to judge.
//
// The distinction is the whole design. We spent a month learning the tool
// cannot be authoritative about intent — the keycloak case proved the "obvious"
// fix was wrong. So a candidate is offered ONLY where the change is mechanically
// derivable from the finding's own classification, and even then it is framed as
// something to TEST, never to trust. Where intent is genuinely required (a port
// mismatch, a benign fan-out) no candidate is offered at all, and the finding
// points at the brief instead.
type FixCandidate struct {
	// Kind is "add-ingress" (admit denied traffic) or "remove-policy" (delete a
	// rule nothing is using). It decides how the verdict reads.
	Kind string `json:"kind"`
	// Summary is one plain line for the button's tooltip: what this would do.
	Summary string `json:"summary"`
	// Touches is the namespace whose policy this changes — which is often NOT
	// the namespace you are auditing (a half-open's fix edits the receiver), and
	// may belong to another team entirely. Named so that is never a surprise.
	Touches string `json:"touches"`
	// Rules / Deletes are exactly what /api/whatif takes, so the button stages
	// straight into the engine with no re-derivation.
	Rules   []whatif.SimpleRule `json:"rules,omitempty"`
	Deletes []string            `json:"deletes,omitempty"`
}

// ComputeFixes returns, per half-open pair ("src|dst"), the candidate that would
// clear that flag — or nothing, where the tool cannot honestly derive one.
//
// It reads the SAME classification the brief renders (working siblings, observed
// drops, coverage) so the button, the brief and the sidecar can never disagree
// about a finding. Every member pair of a group maps to the group's single
// candidate, so clicking any of nine keycloak rows offers the same change.
func ComputeFixes(g *Graph, a *Audit) map[string]*FixCandidate {
	p := prepare(g, a)
	out := map[string]*FixCandidate{}
	for _, gr := range p.groups {
		c := draftForGroup(g, gr, p.x)
		if c == nil {
			continue
		}
		for _, pair := range gr.Pairs {
			out[pair.Src+"|"+pair.Dst] = c
		}
	}
	return out
}

// draftForGroup derives the flag-clearing change for one half-open group, or
// nil where none is honest.
//
// Two confident cases, and only two:
//
//   - Traffic is being DENIED on the declared port. Someone is trying to make
//     this connection and Cilium is dropping it. The change that clears the
//     flag is unambiguous: admit the sender at the receiver. what-if then shows
//     the drops it would clear AND anything it would break (the first-ingress
//     footgun), so the reader sees the real cost.
//   - The passage reaches NOBODY and carried NOTHING at high coverage — a dead
//     rule. The change that clears the flag is to delete the declaring policy.
//     what-if shows the collateral of removing the whole policy, so a policy
//     that turns out to do other things cannot be quietly deleted.
//
// Everything else gets no candidate. A benign fan-out (keycloak → coredns
// works, the nine silent peers are collateral) must NOT be offered "admit nine
// kube-system pods" — that clears the flag by making a change nobody wants,
// which is exactly the authority we refuse to claim. Those point at the brief.
func draftForGroup(g *Graph, gr halfOpenGroup, x *crossRef) *FixCandidate {
	// Is this pair being actively denied on the port it declares?
	hit, _ := x.forGroup(gr)
	if len(hit) > 0 {
		var rules []whatif.SimpleRule
		for _, src := range gr.Srcs {
			for _, dst := range gr.Dsts {
				rules = append(rules, whatif.SimpleRule{
					From:  src,
					To:    dst,
					Ports: gr.Ports,
					Sides: "ingress", // admit the sender; egress already exists
				})
			}
		}
		return &FixCandidate{
			Kind: "add-ingress",
			Summary: fmt.Sprintf("Admit %s into %s on %s — the traffic being denied now",
				senderPhrase(gr), gr.DstNS, strings.Join(gr.Ports, ", ")),
			Touches: gr.DstNS,
			Rules:   rules,
		}
	}

	// Dead? Only if nothing in the receiving namespace is reachable via this
	// rule AND coverage is high enough that "nothing observed" means something.
	sibs, _ := workingSiblings(g, gr)
	coveredWell := g.Flows != nil && g.Flows.Status == "ok" && g.Flows.Coverage >= 0.8
	if len(sibs) == 0 && coveredWell {
		return &FixCandidate{
			Kind: "remove-policy",
			Summary: fmt.Sprintf("Delete %s — nothing was observed using this passage over %s at %.0f%% coverage",
				strings.Join(gr.Policies, ", "), g.Flows.Watched, g.Flows.Coverage*100),
			Touches: policyNamespace(gr.Policies),
			Deletes: gr.Policies,
		}
	}

	// Benign fan-out, or a low-coverage unknown: no honest mechanical change.
	return nil
}

func senderPhrase(gr halfOpenGroup) string {
	if len(gr.Srcs) == 1 {
		return "`" + gr.Srcs[0] + "`"
	}
	return fmt.Sprintf("%d senders", len(gr.Srcs))
}

// policyNamespace pulls the namespace out of the first provenance string
// ("Kind/ns/name"), for the Touches field. Cluster-scoped policies ("Kind/name")
// have no namespace and report empty.
func policyNamespace(policies []string) string {
	if len(policies) == 0 {
		return ""
	}
	parts := strings.Split(policies[0], "/")
	if len(parts) == 3 {
		return parts[1]
	}
	return ""
}
