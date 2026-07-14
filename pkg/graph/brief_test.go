// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package graph

import (
	"strings"
	"testing"
	"time"
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

// The headline defect the review found: raw counts scale with coverage, so the
// SAME cluster observed at 50% and at 98% reports counts that differ ~2x with
// nothing whatsoever having changed. A reader comparing two briefs reads that
// as a cluster getting worse — "the cluster is on fire" when the truth is "the
// tool is reporting raw counts".
//
// The rate over watched time is the number that holds still. This is the
// regression test the review asked for: same cluster, different coverage,
// counts must be comparable.
func TestRateIsComparableAcrossCoverageWhileCountsAreNot(t *testing.T) {
	// One drop every two minutes — 30/h — seen through two different windows.
	const perHour = 30.0
	drops := func(watchedSec float64) *FlowOverlay {
		n := int(perHour * watchedSec / 3600)
		return &FlowOverlay{
			Status: "ok", Source: "stream", Window: "24h",
			Watched: "x", WatchedSec: watchedSec, Coverage: watchedSec / (24 * 3600),
			Drops: []DropEdge{{
				Src: "web/front", Dst: "db/pg", Port: "5432/TCP",
				Reason: "POLICY_DENIED", Count: n, LastSeen: time.Now(),
			}},
		}
	}

	half := drops(12 * 3600)   // 50% coverage
	full := drops(23.5 * 3600) // 98% coverage

	if half.Drops[0].Count == full.Drops[0].Count {
		t.Fatal("test is not exercising the problem: counts should differ with coverage")
	}

	// Both briefs must quote the same rate, because the cluster is the same.
	rateOf := func(ov *FlowOverlay) string {
		g := &Graph{TakenAt: "now", Tool: "portolan", Flows: ov}
		out := string(Brief(g, ComputeAudit(g)))
		i := strings.Index(out, "(≈")
		if i < 0 {
			t.Fatalf("brief quotes no rate — counts alone are not comparable across coverage\n%s", out)
		}
		return out[i : i+strings.Index(out[i:], ")")+1]
	}
	if a, b := rateOf(half), rateOf(full); a != b {
		t.Errorf("rate differs across coverage (%s vs %s) — it must not: the cluster did not change,"+
			" only how long we watched it", a, b)
	}

	// And the brief must tell the reader which number to compare, or they will
	// reach for the count, which is the one that lies.
	g := &Graph{TakenAt: "now", Tool: "portolan", Flows: full}
	out := string(Brief(g, ComputeAudit(g)))
	if !strings.Contains(out, "use the **per-hour rate**, not the count") {
		t.Errorf("brief must say which figure survives a change in coverage\n%s", out)
	}
}

// Timestamps without a date cannot be checked against a window that has one.
// Several drop times appeared to land after the window end simply because they
// were bare times of day being compared to a dated bound.
func TestDropTimestampsCarryTheirDate(t *testing.T) {
	seen := time.Date(2026, 7, 14, 9, 12, 33, 0, time.UTC)
	g := &Graph{TakenAt: "now", Tool: "portolan", Flows: &FlowOverlay{
		Status: "ok", Source: "stream", Window: "24h", WatchedSec: 23 * 3600, Coverage: 0.96,
		To: seen.Add(time.Hour),
		Drops: []DropEdge{{
			Src: "web/front", Dst: "db/pg", Port: "5432/TCP",
			Reason: "POLICY_DENIED", Count: 40, LastSeen: seen,
		}},
	}}
	out := string(Brief(g, ComputeAudit(g)))
	if !strings.Contains(out, "2026-07-14T09:12:33Z") {
		t.Errorf("drop time must be ISO 8601 with its date, not a bare time of day\n%s", out)
	}
	if strings.Contains(out, "last seen 09:12:33\n") {
		t.Error("drop time is still a bare time of day")
	}
}

// A rate computed over seconds of observation is extrapolation wearing a
// measurement's clothes: one drop in 30s is not "120/h".
func TestRateWithheldWhenBarelyAnythingWasWatched(t *testing.T) {
	g := &Graph{TakenAt: "now", Tool: "portolan", Flows: &FlowOverlay{
		Status: "ok", Source: "buffer", Window: "15m", WatchedSec: 12, Coverage: 0.013,
		Drops: []DropEdge{{Src: "a/b", Dst: "c/d", Port: "80/TCP", Reason: "POLICY_DENIED", Count: 1}},
	}}
	out := string(Brief(g, ComputeAudit(g)))
	if strings.Contains(out, "/h)") {
		t.Errorf("12 seconds of observation must not be extrapolated to an hourly rate\n%s", out)
	}
}
