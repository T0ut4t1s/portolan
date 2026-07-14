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

// The wrong fix, taken straight from the cluster.
//
// Longhorn's instance-manager was observed being DENIED on 38906/TCP, while the
// half-open finding for the very same pair declares 9500/TCP. The brief's old
// triage rule — "a half-open naming the same pair confirms it" — ignores the
// port, so it told the reader this was confirmed and to open 9500. That would
// not have touched the drops on 38906: policy changed, problem unchanged, an
// ingress rule added for nothing.
//
// A pair match is not a confirmation. Pair AND port is.
func TestPairMatchWithDifferentPortIsNotAConfirmation(t *testing.T) {
	const (
		im = "longhorn-system/instance-manager-b0258"
		lm = "longhorn-system/longhorn-manager"
	)
	g := &Graph{
		TakenAt: "now", Tool: "portolan",
		Namespaces: []Namespace{{Name: "longhorn-system", DefaultDeny: true}},
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "6h",
			Watched: "6h", WatchedSec: 6 * 3600, Coverage: 1, BucketSec: 900,
			To: time.Now(),
			Drops: []DropEdge{{
				Src: im, Dst: lm, Port: "38906/TCP", Reason: "POLICY_DENIED",
				Count: 1, Buckets: 1, LastSeen: time.Now().Add(-3 * time.Hour),
			}},
		},
	}
	a := &Audit{
		Drops: g.Flows.Drops,
		HalfOpen: []Edge{{
			Src: im, Dst: lm, Ports: []string{"9500/TCP"},
			Policies: []string{"CiliumNetworkPolicy/longhorn-system/longhorn-instance-manager"},
		}},
	}
	out := string(Brief(g, a))

	// Assert on the drop LINE: "CONFIRMED" also appears in the agent-instruction
	// glossary, where it means something else entirely.
	if line := lineWith(t, out, "38906"); strings.Contains(line, "CONFIRMED") {
		t.Errorf("a pair match on a DIFFERENT port must not be reported as confirmed:\n  %s", line)
	}
	for _, want := range []string{
		"PORT MISMATCH",
		"Denied on a port no policy declares",
		"denied on 38906/TCP",
		"Do not apply the fix suggested below to that traffic",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("brief is missing %q — the wrong fix is still reachable\n---\n%s", want, out)
		}
	}
}

// The other half of the same join: when the port DOES match, that is the
// strongest finding in the brief and it should say so.
func TestPairAndPortMatchIsConfirmed(t *testing.T) {
	g := &Graph{
		TakenAt: "now", Tool: "portolan",
		Namespaces: []Namespace{{Name: "db", DefaultDeny: true}},
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "6h",
			Watched: "6h", WatchedSec: 6 * 3600, Coverage: 1, BucketSec: 900,
			To: time.Now(),
			Drops: []DropEdge{{
				Src: "web/front", Dst: "db/pg", Port: "5432/TCP", Reason: "POLICY_DENIED",
				Count: 90, Buckets: 24, LastSeen: time.Now(),
			}},
		},
	}
	a := &Audit{
		Drops:    g.Flows.Drops,
		HalfOpen: []Edge{{Src: "web/front", Dst: "db/pg", Ports: []string{"5432/TCP"}}},
	}
	out := string(Brief(g, a))
	if !strings.Contains(out, "CONFIRMED") {
		t.Errorf("a pair AND port match is the strongest finding here; say so\n---\n%s", out)
	}
	if strings.Contains(out, "PORT MISMATCH") {
		t.Errorf("matching port wrongly flagged as a mismatch\n---\n%s", out)
	}
}

// A burst that ended and a wound that is still bleeding used to print
// identically. The count cannot tell them apart; the spread across time buckets
// can. Sending someone to investigate a problem that fixed itself thirteen
// hours ago is a real cost.
func TestFinishedDropsAreNotDressedUpAsOngoing(t *testing.T) {
	now := time.Now()
	g := &Graph{
		TakenAt: "now", Tool: "portolan",
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "24h",
			Watched: "24h", WatchedSec: 24 * 3600, Coverage: 1, BucketSec: 900,
			To: now,
			Drops: []DropEdge{
				{ // a startup burst: 32 drops, all inside ONE bucket, 13h ago
					Src: "cloudflared/cloudflared", Dst: "entity:world", Port: "443/TCP",
					Reason: "POLICY_DENIED", Count: 32, Buckets: 1,
					LastSeen: now.Add(-13 * time.Hour),
				},
				{ // still bleeding: seen in every bucket, seconds ago
					Src: "media-management/cleanuparr", Dst: "entity:world", Port: "443/TCP",
					Reason: "POLICY_DENIED", Count: 343, Buckets: 96,
					LastSeen: now.Add(-30 * time.Second),
				},
			},
		},
	}
	out := string(Brief(g, &Audit{Drops: g.Flows.Drops}))

	burst := lineWith(t, out, "cloudflared")
	live := lineWith(t, out, "cleanuparr")

	if !strings.Contains(burst, "stopped") || !strings.Contains(burst, "single burst") {
		t.Errorf("a 32-drop burst that ended 13h ago must say so:\n  %s", burst)
	}
	if strings.Contains(burst, "ongoing") {
		t.Errorf("finished burst reported as ongoing:\n  %s", burst)
	}
	if !strings.Contains(live, "ongoing") {
		t.Errorf("a drop seen in every window, seconds ago, is ongoing:\n  %s", live)
	}
	if strings.Contains(live, "stopped") {
		t.Errorf("live bleed reported as stopped:\n  %s", live)
	}
	// And the reader must be told not to act on a stopped drop.
	if !strings.Contains(out, "Do not open a rule for traffic that is no longer being attempted") {
		t.Error("triage must warn against fixing drops that already stopped")
	}
}

// A one-shot buffer read has no time buckets, so it cannot know whether a drop
// is ongoing. It must say nothing rather than guess — silence beats a confident
// wrong label.
func TestActivityWithheldWhenTheSourceCannotKnow(t *testing.T) {
	g := &Graph{
		TakenAt: "now", Tool: "portolan",
		Flows: &FlowOverlay{
			Status: "ok", Source: "buffer", Window: "15m", WatchedSec: 12, Coverage: 0.01,
			To:    time.Now(),
			Drops: []DropEdge{{Src: "a/b", Dst: "c/d", Port: "80/TCP", Reason: "POLICY_DENIED", Count: 3}},
		},
	}
	out := string(Brief(g, &Audit{Drops: g.Flows.Drops}))
	line := lineWith(t, out, "a/b")
	if strings.Contains(line, "ongoing") || strings.Contains(line, "stopped") {
		t.Errorf("a bucketless source must not claim to know whether a drop is ongoing:\n  %s", line)
	}
}

// Policy is sampled; traffic is streamed and re-read per request. They are two
// clocks and always will be — but two UNLABELLED clocks made a drop last-seen
// after the "snapshot taken" line look impossible.
func TestBriefLabelsItsTwoClocks(t *testing.T) {
	g := &Graph{
		TakenAt: "2026-07-14 19:36 UTC", Tool: "portolan",
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "6h", Watched: "6h",
			WatchedSec: 6 * 3600, Coverage: 1, BucketSec: 900,
			To: time.Date(2026, 7, 14, 19, 47, 44, 0, time.UTC),
		},
	}
	out := string(Brief(g, ComputeAudit(g)))
	for _, want := range []string{
		"**Policy** sampled at `2026-07-14 19:36 UTC`",
		"**Traffic** observed through `2026-07-14T19:47:44Z`",
		"Drop timestamps later than the policy sample are expected, not errors",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q — the two clocks are still unexplained\n---\n%s", want, out)
		}
	}
}

func lineWith(t *testing.T, out, needle string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "- `") && strings.Contains(l, needle) {
			return l
		}
	}
	t.Fatalf("no drop line mentioning %q\n---\n%s", needle, out)
	return ""
}

// Caught by running against the real cluster, not by reasoning.
//
// With seven minutes watched and fifteen-minute buckets, the "how many windows
// could this have appeared in" denominator rounded to ZERO — so "seen in every
// window" was trivially true, and a single ×1 Longhorn drop came out labelled
// "ongoing, continuously (every window since it began)". A pattern claimed from
// one sighting in one window is not a measurement. Below a few windows of
// history the tool must decline to characterise, and say why.
func TestNoHabitClaimedFromTooLittleHistory(t *testing.T) {
	now := time.Now()
	g := &Graph{
		TakenAt: "now", Tool: "portolan",
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "1h",
			Watched: "7m", WatchedSec: 7 * 60, Coverage: 0.12, BucketSec: 900,
			To: now,
			Drops: []DropEdge{{
				Src: "longhorn-system/instance-manager-7d0", Dst: "longhorn-system/longhorn-manager",
				Port: "33582/TCP", Reason: "POLICY_DENIED", Count: 1, Buckets: 1,
				LastSeen: now.Add(-13 * time.Minute),
			}},
		},
	}
	line := lineWith(t, string(Brief(g, &Audit{Drops: g.Flows.Drops})), "33582")
	if strings.Contains(line, "continuously") || strings.Contains(line, "ongoing") {
		t.Errorf("one drop, in one window, over seven minutes is not an ongoing pattern:\n  %s", line)
	}
	if !strings.Contains(line, "too little history") {
		t.Errorf("must say why it is declining to characterise:\n  %s", line)
	}
}

// The middle state is real and useful: a drop that keeps coming back but not
// constantly. Neither "ongoing, continuously" nor "stopped" describes it.
func TestIntermittentDropsAreNamedAsSuch(t *testing.T) {
	now := time.Now()
	g := &Graph{
		TakenAt: "now", Tool: "portolan",
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "24h", Watched: "24h",
			WatchedSec: 24 * 3600, Coverage: 1, BucketSec: 900, To: now,
			Drops: []DropEdge{{
				Src: "onlyoffice/dragonfly", Dst: "entity:world", Port: "443/TCP",
				Reason: "POLICY_DENIED", Count: 11, Buckets: 11, // 11 of 96 windows
				LastSeen: now.Add(-2 * time.Minute),
			}},
		},
	}
	line := lineWith(t, string(Brief(g, &Audit{Drops: g.Flows.Drops})), "dragonfly")
	if !strings.Contains(line, "intermittently") || !strings.Contains(line, "11 of 96 windows") {
		t.Errorf("a drop in 11 of 96 windows is intermittent — say so, with the numbers:\n  %s", line)
	}
}
