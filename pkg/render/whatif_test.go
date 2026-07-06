// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package render

import (
	"bytes"
	"testing"
	"time"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
	"github.com/T0ut4t1s/portolan/pkg/whatif"
)

func TestWhatifHTML(t *testing.T) {
	snap := &snapshot.Snapshot{
		TakenAt: time.Date(2026, 7, 6, 7, 0, 0, 0, time.UTC),
		Tool:    snapshot.ToolInfo{Name: "portolan", Version: "test"},
		Workloads: []snapshot.Workload{
			{Namespace: "dns", Name: "technitium", Kind: "Deployment"},
		},
		Flows: &snapshot.FlowCapture{Status: "ok", Window: "15m0s", FlowsSeen: 42},
	}
	res := &whatif.Result{
		Added: []whatif.Delta{{
			Src: "entity:world", Dst: "dns/technitium",
			Ports:         []string{"53/TCP", "53/UDP"},
			Via:           []string{"CiliumNetworkPolicy/dns/technitium-world-dns"},
			HealsHalfOpen: true,
		}},
		Removed:       []whatif.Delta{},
		HalfOpen:      []whatif.HalfOpenDelta{},
		FixesDrops:    []whatif.FlowImpact{{Src: "entity:world", Dst: "dns/technitium", Port: "53/UDP", Count: 7, Verdict: "DROPPED"}},
		BreaksFlows:   []whatif.FlowImpact{},
		PolicyChanges: []string{"added CiliumNetworkPolicy/dns/technitium-world-dns"},
		Probes:        1234,
	}

	html, err := WhatifHTML(snap, res)
	if err != nil {
		t.Fatalf("WhatifHTML: %v", err)
	}
	for _, want := range [][]byte{
		[]byte(`"id":"dns/technitium"`),     // workload made it into the view
		[]byte(`"label":"world"`),           // entity became an external
		[]byte(`"healsHalfOpen":true`),      // delta payload intact
		[]byte(`added CiliumNetworkPolicy`), // change narration present
		[]byte(`"probes":1234`),             // probe count injected
		[]byte(`what-if`),                   // template is the delta template
	} {
		if !bytes.Contains(html, want) {
			t.Errorf("rendered HTML missing %q", want)
		}
	}
	if bytes.Contains(html, []byte(dataToken)) {
		t.Error("data token left unreplaced")
	}
}

// A delta endpoint absent from the snapshot's workload list must still
// render (as a bare Pod) so no edge dangles.
func TestWhatifHTMLUnknownEndpoint(t *testing.T) {
	snap := &snapshot.Snapshot{Tool: snapshot.ToolInfo{Name: "portolan", Version: "test"}}
	res := &whatif.Result{
		Removed: []whatif.Delta{{Src: "ghost-ns/ghost", Dst: "entity:host", Ports: []string{"80/TCP"}}},
	}
	html, err := WhatifHTML(snap, res)
	if err != nil {
		t.Fatalf("WhatifHTML: %v", err)
	}
	if !bytes.Contains(html, []byte(`"id":"ghost-ns/ghost"`)) {
		t.Error("unknown endpoint not rendered as a fallback node")
	}
}
