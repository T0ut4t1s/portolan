// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package graph

import (
	"strings"
	"testing"
)

// The brief is written to be pasted into a chatbot, which is precisely where a
// coverage mistake becomes confident, fluent and wrong. A model handed "no
// drops on this edge" will reason from it — and it has no way to know whether
// that silence came from watching all week or from blinking once. So the brief
// must always say which, and must say so loudly when the answer is "blinked".
func TestBriefStatesTheCoverageItsObservationsWereMadeAt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flows   *FlowOverlay
		want    []string
		wantNot []string
	}{
		{
			name:  "streamed and well covered — absence is evidence",
			flows: &FlowOverlay{Status: "ok", Source: "stream", Window: "24h", Watched: "23h50m", Coverage: 0.99},
			want: []string{
				"**24h** window, **99% covered**",
				"23h50m of it actually watched",
				"absence is meaningful here",
			},
			wantNot: []string{"Read this before drawing any conclusion"},
		},
		{
			name:  "streamed but barely watched — absence proves nothing",
			flows: &FlowOverlay{Status: "ok", Source: "stream", Window: "24h", Watched: "30m", Coverage: 0.02},
			want: []string{
				"**2% covered**",
				"Read this before drawing any conclusion from an absence",
				"may simply have gone unseen",
			},
			wantNot: []string{"absence is meaningful"},
		},
		{
			name:  "a buffer read is never trustworthy about absence, whatever it reports",
			flows: &FlowOverlay{Status: "ok", Source: "buffer", Window: "15m", Watched: "12s", Coverage: 0.013},
			want: []string{
				"Read this before drawing any conclusion from an absence",
				"bounded by *capacity*, not time",
				"do not propose removing a rule on that basis",
			},
			wantNot: []string{"absence is meaningful"},
		},
		{
			name:  "no observation at all — say so, do not let silence read as a clean bill",
			flows: nil,
			want: []string{
				"No traffic observation in this brief",
				"declared policy topology alone",
			},
			wantNot: []string{"covered"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &Graph{Cluster: "test", TakenAt: "now", Tool: "portolan", Flows: tc.flows}
			out := string(Brief(g, ComputeAudit(g)))
			for _, s := range tc.want {
				if !strings.Contains(out, s) {
					t.Errorf("brief is missing %q\n---\n%s", s, out)
				}
			}
			for _, s := range tc.wantNot {
				if strings.Contains(out, s) {
					t.Errorf("brief should not contain %q\n---\n%s", s, out)
				}
			}
		})
	}
}

// "Nothing found" and "nothing was looked for" read identically once pasted
// into a chat window. A clean brief must not be mistakable for a clean cluster.
func TestCleanBriefDoesNotPassOffBlindnessAsHealth(t *testing.T) {
	g := &Graph{Cluster: "test", TakenAt: "now", Tool: "portolan"}
	out := string(Brief(g, ComputeAudit(g)))
	if !strings.Contains(out, "No findings") {
		t.Fatal("want a no-findings section")
	}
	if !strings.Contains(out, "nothing was watching") {
		t.Errorf("a findings-free brief with no flow capture must say the absence of drops is not a finding\n---\n%s", out)
	}
}
