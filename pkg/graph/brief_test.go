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

	// 38906 is above the ephemeral floor, so it is folded to `ephemeral/TCP` —
	// which is the whole point: the number changes every run, the fact does not.
	// Assert on the drop LINE, because "CONFIRMED" also appears in the
	// agent-instruction glossary where it means something else.
	if line := lineWith(t, out, "ephemeral/TCP"); strings.Contains(line, "CONFIRMED") {
		t.Errorf("a pair match on a DIFFERENT port must not be reported as confirmed:\n  %s", line)
	}
	if strings.Contains(out, "38906") {
		t.Error("a dynamically-allocated port number is noise: it must be folded, not printed")
	}
	for _, want := range []string{
		"PORT MISMATCH",
		"Denied on a port no policy declares",
		"denied on ephemeral/TCP",
		"The fix above does not apply to that traffic",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("brief is missing %q — the wrong fix is still reachable\n---\n%s", want, out)
		}
	}
}

// Longhorn's instance managers are denied on a fresh high port every run —
// 37164, then 38906, then 33582. Printed literally, the same standing problem
// looks brand new every day: nothing matches between two briefs, so there can
// be no diff, no suppression, no memory. The number carries no information;
// that it is ephemeral does.
func TestEphemeralPortsFoldIntoOneStableRow(t *testing.T) {
	now := time.Now()
	const im, lm = "longhorn-system/instance-manager-b0258", "longhorn-system/longhorn-manager"
	drop := func(port string, n int) DropEdge {
		return DropEdge{Src: im, Dst: lm, Port: port, Reason: "POLICY_DENIED",
			Count: n, Buckets: 1, LastSeen: now.Add(-time.Hour)}
	}
	g := &Graph{
		TakenAt: "now", Tool: "portolan",
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "24h", Watched: "24h",
			WatchedSec: 24 * 3600, Coverage: 1, BucketSec: 900, To: now,
			// Three runs' worth of churn, plus one real service port.
			Drops: []DropEdge{drop("37164/TCP", 1), drop("38906/TCP", 2), drop("33582/TCP", 1), drop("9500/TCP", 5)},
		},
	}
	out := string(Brief(g, &Audit{Drops: g.Flows.Drops}))

	for _, gone := range []string{"37164", "38906", "33582"} {
		if strings.Contains(out, gone) {
			t.Errorf("ephemeral port %s still printed — the row will churn again tomorrow", gone)
		}
	}
	line := lineWith(t, out, "ephemeral/TCP")
	if !strings.Contains(line, "×4") {
		t.Errorf("the three ephemeral drops must fold into ONE row summing their counts (×4):\n  %s", line)
	}
	// A real service port is information and must survive untouched.
	if !strings.Contains(out, "9500/TCP") {
		t.Errorf("a real service port must not be folded away\n---\n%s", out)
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
	if !strings.Contains(out, "Do not open a rule for traffic nobody is attempting") {
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
	// 33582 folds to ephemeral/TCP — see TestEphemeralPortsFoldIntoOneStableRow.
	line := lineWith(t, string(Brief(g, &Audit{Drops: g.Flows.Drops})), "ephemeral/TCP")
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

// Keycloak's ONE DNS egress rule became NINE findings — one per pod that
// happens to live in kube-system — each with the same policy, the same port,
// the same diagnosis and the same nine-line verify recipe. That is one fact
// stated nine times, and a brief that repeats itself is a brief that gets
// skimmed.
func TestHalfOpenFanOutIsOneFindingNotNine(t *testing.T) {
	peers := []string{"cilium", "cilium-envoy", "cilium-operator", "hubble-relay",
		"intel-gpu-plugin", "kube-vip", "local-path-provisioner", "metrics-server", "nvidia-device-plugin"}
	var edges []Edge
	for _, p := range peers {
		edges = append(edges, Edge{
			Src: "keycloak/keycloak", Dst: "kube-system/" + p,
			Ports:    []string{"53/UDP"},
			Policies: []string{"NetworkPolicy/keycloak/keycloak"},
		})
	}
	g := &Graph{TakenAt: "now", Tool: "portolan"}
	out := string(Brief(g, &Audit{HalfOpen: edges}))

	if n := strings.Count(out, "### Finding "); n != 1 {
		t.Errorf("nine peers behind one policy+port is ONE finding, got %d\n---\n%s", n, out)
	}
	if !strings.Contains(out, "**Unreachable peers (9)**") {
		t.Errorf("the nine peers must appear as a list INSIDE the finding\n---\n%s", out)
	}
	for _, p := range peers {
		if !strings.Contains(out, "kube-system/"+p) {
			t.Errorf("peer %q was lost in the grouping — dedup must not drop information", p)
		}
	}
	// The recipe is identical for every half-open, so it is stated once.
	if n := strings.Count(out, "hubble observe --from-namespace <SRC-NS>"); n != 1 {
		t.Errorf("the verify recipe must be printed once, parameterised, got %d copies", n)
	}
}

// A drop bleeding 57/hour right now sat BELOW a blip that happened once and
// stopped, because "c" comes before "j". The top of the list is the only part
// most readers reach.
func TestDropsAreRankedByConsequenceNotAlphabet(t *testing.T) {
	now := time.Now()
	g := &Graph{
		TakenAt: "now", Tool: "portolan",
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "24h", Watched: "24h",
			WatchedSec: 24 * 3600, Coverage: 1, BucketSec: 900, To: now,
			Drops: []DropEdge{
				// alphabetically first, but dead for hours and utterly trivial
				{Src: "aaa/blip", Dst: "entity:world", Port: "65001/UDP", Reason: "POLICY_DENIED",
					Count: 1, Buckets: 1, LastSeen: now.Add(-6 * time.Hour)},
				// alphabetically last, but bleeding right now
				{Src: "zzz/cleanuparr", Dst: "entity:world", Port: "443/TCP", Reason: "POLICY_DENIED",
					Count: 343, Buckets: 96, LastSeen: now.Add(-10 * time.Second)},
			},
		},
	}
	out := string(Brief(g, &Audit{Drops: g.Flows.Drops}))
	live := strings.Index(out, "zzz/cleanuparr")
	dead := strings.Index(out, "aaa/blip")
	if live < 0 || dead < 0 {
		t.Fatalf("both drops should appear\n---\n%s", out)
	}
	if live > dead {
		t.Error("a drop still bleeding must outrank one that stopped six hours ago, whatever its name sorts as")
	}
}

// 54 dead-selector lines, of which the overwhelming majority were
// `pgbouncer-db-init` — ONE Job deployed into fourteen namespaces, correctly
// matching nothing because it is not running. Burying the handful of real
// questions under that is how a brief teaches its reader to skip a section.
func TestDeadRefsGroupBySelectorAndSeparateTheExpected(t *testing.T) {
	var refs []string
	for _, ns := range []string{"authentik", "freeradius", "immich", "keycloak", "monitoring", "n8n"} {
		refs = append(refs, "CiliumNetworkPolicy/"+ns+"/pgbouncer-db-init → app=pgbouncer-db-init")
	}
	refs = append(refs,
		"CiliumNetworkPolicy/open-webui/searxng → app.kubernetes.io/name=searxng",
		"CiliumNetworkPolicy/hermes-agent/hindsight → k8s:io.kubernetes.pod.namespace=coder",
	)
	out := string(Brief(&Graph{TakenAt: "now", Tool: "portolan"}, &Audit{DeadRefs: refs}))

	if !strings.Contains(out, "(3 selectors)") {
		t.Errorf("8 lines are 3 selectors — group by selector, not policy\n---\n%s", out)
	}
	if !strings.Contains(out, "app=pgbouncer-db-init` — 6 policies") {
		t.Errorf("the shared selector must be stated once with its policy count\n---\n%s", out)
	}
	if !strings.Contains(out, "Expected — run-to-completion workloads") {
		t.Errorf("job-like selectors must be split off as expected\n---\n%s", out)
	}
	// The two that are NOT job-like are the ones actually worth reading.
	look := out[strings.Index(out, "Worth a look"):]
	for _, want := range []string{"searxng", "hindsight"} {
		if !strings.Contains(look, want) {
			t.Errorf("%q is not job-like and belongs under 'worth a look'\n---\n%s", want, out)
		}
	}
	if strings.Contains(look, "pgbouncer-db-init") {
		t.Error("a Job selector matching nothing at rest is CORRECT — it must not be in the review pile")
	}
}

// The wrong fix I INTRODUCED in 0.25.0, caught by review before it hurt anyone.
//
// Keycloak's DNS egress rule names the kube-system NAMESPACE, so it fans out to
// every pod in it. It reaches coredns, which declares ingress — a complete
// passage, so it never appears as a half-open at all. What DOES appear are the
// nine other pods in kube-system that were never DNS servers and were never
// going to receive a DNS query: cilium, kube-vip, metrics-server and friends.
//
// Reporting only on those, the conclusion wrote itself — wrongly: "nothing
// observed across 24h at 100% coverage, therefore the rule is dead; propose
// removing it." Follow that and you delete a LIVE DNS egress rule, and Keycloak
// stops resolving. OpenCloud login breaks.
//
// A rule with a working sibling is not dead. It is working, and merely loose.
func TestALiveRuleWithFanOutIsNotCalledDead(t *testing.T) {
	deadPeers := []string{"cilium", "kube-vip", "metrics-server", "nvidia-device-plugin"}

	// The working passage: keycloak → coredns, ingress declared, carrying traffic.
	edges := []Edge{{
		Src: "keycloak/keycloak", Dst: "kube-system/coredns", Ports: []string{"53/UDP"},
		DeclaredEgress: true, DeclaredIngress: true,
	}}
	var halfOpen []Edge
	for _, p := range deadPeers {
		e := Edge{
			Src: "keycloak/keycloak", Dst: "kube-system/" + p, Ports: []string{"53/UDP"},
			DeclaredEgress: true, DeclaredIngress: false,
			Policies: []string{"NetworkPolicy/keycloak/keycloak"},
		}
		edges = append(edges, e)
		halfOpen = append(halfOpen, e)
	}

	g := &Graph{
		TakenAt: "now", Tool: "portolan", Edges: edges,
		Namespaces: []Namespace{{Name: "kube-system", DefaultDeny: true, DefaultDenyIngress: true}},
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "24h", Watched: "24h",
			WatchedSec: 24 * 3600, Coverage: 1, BucketSec: 900, To: time.Now(),
			// DNS is flowing to coredns, right now, in this very window.
			Observed: []ObservedEdge{{
				Src: "keycloak/keycloak", Dst: "kube-system/coredns",
				Ports: []string{"53/UDP"}, Count: 90210, Declared: true,
			}},
			Drops: []DropEdge{},
		},
	}
	out := string(Brief(g, &Audit{HalfOpen: halfOpen}))

	// The load-bearing assertion: it must NOT tell anyone to remove this rule.
	if strings.Contains(out, "propose removing it") {
		t.Errorf("a rule that is demonstrably carrying DNS to coredns must never be called dead — "+
			"acting on this would break Keycloak login\n---\n%s", out)
	}
	for _, want := range []string{
		"NOT dead — it is too loose",
		"kube-system/coredns",
		"traffic was observed flowing on it in this very window",
		"Do not propose removing this rule",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("brief is missing %q — the fan-out is still being read as a dead rule\n---\n%s", want, out)
		}
	}
}

// The other side of the same coin: a rule that reaches NOBODY really is dead,
// and the tool must still say so. Fixing the false positive must not blind it.
func TestARuleThatReachesNobodyIsStillCalledDead(t *testing.T) {
	e := Edge{
		Src: "old/sender", Dst: "gone/receiver", Ports: []string{"8080/TCP"},
		DeclaredEgress: true, DeclaredIngress: false,
		Policies: []string{"CiliumNetworkPolicy/old/sender"},
	}
	g := &Graph{
		TakenAt: "now", Tool: "portolan", Edges: []Edge{e},
		Namespaces: []Namespace{{Name: "gone", DefaultDeny: true, DefaultDenyIngress: true}},
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "24h", Watched: "24h",
			WatchedSec: 24 * 3600, Coverage: 1, BucketSec: 900, To: time.Now(),
			Observed: []ObservedEdge{}, Drops: []DropEdge{},
		},
	}
	out := string(Brief(g, &Audit{HalfOpen: []Edge{e}}))
	if !strings.Contains(out, "reaches nobody") || !strings.Contains(out, "propose removing it") {
		t.Errorf("a rule with no working sibling and no traffic at full coverage IS dead — say so\n---\n%s", out)
	}
}

// "seen in 97 of 96 windows" — a number that cannot be true.
//
// The count came from the buckets the query actually READ, while the
// denominator came from the window that was ASKED for. `from` snaps outward to
// a bucket boundary, so a 24h window reads up to 97 fifteen-minute buckets.
// Cosmetic, right up until you notice that an impossible number poisons every
// number beside it — and these numbers now carry instructions.
func TestBucketCountNeverExceedsItsDenominator(t *testing.T) {
	now := time.Date(2026, 7, 14, 21, 22, 0, 0, time.UTC)
	from := now.Add(-24 * time.Hour).Truncate(15 * time.Minute) // snaps outward: 97 buckets
	g := &Graph{
		TakenAt: "now", Tool: "portolan",
		Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "24h", Watched: "24h",
			WatchedSec: 24 * 3600, Coverage: 1, BucketSec: 900, From: from, To: now,
			Drops: []DropEdge{{
				Src: "media-management/cleanuparr", Dst: "entity:world", Port: "443/TCP",
				Reason: "POLICY_DENIED", Count: 343, Buckets: 97, LastSeen: now.Add(-time.Minute),
			}},
		},
	}
	line := lineWith(t, string(Brief(g, &Audit{Drops: g.Flows.Drops})), "cleanuparr")
	if strings.Contains(line, "of 96 windows") {
		t.Errorf("97 buckets reported against a 96 denominator — impossible, and it discredits "+
			"every other figure on the line:\n  %s", line)
	}
	if !strings.Contains(line, "97 of 97 windows") {
		t.Errorf("want the denominator to be the range actually read:\n  %s", line)
	}
}

// The flapping bug, with the reviewer's own numbers.
//
// longhorn-manager → world appears in 48 of 96 windows: by definition it is
// idle half the time, so its typical gap is ~30 minutes. Judged against a FIXED
// 30-minute cutoff, any snapshot has a coin-flip chance of landing mid-gap and
// calling it "stopped" — and "stopped" carries a strong instruction in the
// triage text ("do not open a rule, find out what changed"). Two briefs 22
// minutes apart flipped it from ongoing to stopped with nothing whatsoever
// having changed on the cluster. That is the tool inventing an incident.
//
// Silence must be judged against the signal's own cadence, not a constant.
func TestBurstyDropsDoNotFlipToStoppedInTheirOwnQuietGap(t *testing.T) {
	now := time.Now()
	drop := func(buckets int, age time.Duration) *Graph {
		return &Graph{TakenAt: "now", Tool: "portolan", Flows: &FlowOverlay{
			Status: "ok", Source: "stream", Window: "24h", Watched: "24h",
			WatchedSec: 24 * 3600, Coverage: 1, BucketSec: 900,
			From: now.Add(-24 * time.Hour), To: now,
			Drops: []DropEdge{{
				Src: "longhorn-system/longhorn-manager", Dst: "entity:world", Port: "443/TCP",
				Reason: "POLICY_DENIED", Count: 378, Buckets: buckets, LastSeen: now.Add(-age),
			}},
		}}
	}

	// 48 of 96 windows over 24h → a burst roughly every 30 minutes.
	// 33 minutes of quiet is utterly unremarkable for that signal.
	g1 := drop(48, 33*time.Minute)
	line := lineWith(t, string(Brief(g1, auditOf(g1))), "longhorn-manager")
	if strings.Contains(line, "**stopped**") {
		t.Errorf("33m of silence from a signal that fires every ~30m is NOT a stop — calling it one "+
			"tells the reader to go hunt for a change that never happened:\n  %s", line)
	}
	if !strings.Contains(line, "~30m") {
		t.Errorf("the brief must state the cadence it is judging against:\n  %s", line)
	}

	// Silent for many times its own rhythm: that IS a stop, and must still be called one.
	g2 := drop(48, 6*time.Hour)
	line = lineWith(t, string(Brief(g2, auditOf(g2))), "longhorn-manager")
	if !strings.Contains(line, "**stopped**") {
		t.Errorf("6h of silence from a signal that fires every ~30m is a real stop:\n  %s", line)
	}
	if !strings.Contains(line, "usual") {
		t.Errorf("say how many times its own gap it has been silent for:\n  %s", line)
	}

	// A CONTINUOUS signal is different: half an hour of quiet from something
	// seen in every window really does mean something.
	cont := drop(96, 45*time.Minute)
	line = lineWith(t, string(Brief(cont, auditOf(cont))), "longhorn-manager")
	if !strings.Contains(line, "**stopped**") || !strings.Contains(line, "real change") {
		t.Errorf("a continuous signal going quiet IS a change — say so:\n  %s", line)
	}
}

// The middle state must exist, or every ambiguous case gets forced into a label
// that carries an instruction it has not earned.
func TestAmbiguousSilenceGetsItsOwnLabelRatherThanAGuess(t *testing.T) {
	now := time.Now()
	// 26 of 96 windows → fires roughly every ~55m. Quiet for 2h: longer than
	// usual, but not yet damning.
	g := &Graph{TakenAt: "now", Tool: "portolan", Flows: &FlowOverlay{
		Status: "ok", Source: "stream", Window: "24h", Watched: "24h",
		WatchedSec: 24 * 3600, Coverage: 1, BucketSec: 900,
		From: now.Add(-24 * time.Hour), To: now,
		Drops: []DropEdge{{
			Src: "home-automation/home-assistant", Dst: "entity:world", Port: "5353/UDP",
			Reason: "POLICY_DENIED", Count: 14, Buckets: 26, LastSeen: now.Add(-2 * time.Hour),
		}},
	}}
	line := lineWith(t, string(Brief(g, &Audit{Drops: g.Flows.Drops})), "home-assistant")
	if !strings.Contains(line, "**intermittent**") {
		t.Errorf("neither clearly ongoing nor clearly stopped — say that, do not guess:\n  %s", line)
	}
	if !strings.Contains(line, "not* evidence it has stopped") {
		t.Errorf("the label must disarm the instruction that 'stopped' would carry:\n  %s", line)
	}
}

// auditOf is the audit for a graph whose findings are its own observed drops.
func auditOf(g *Graph) *Audit { return &Audit{Drops: g.Flows.Drops} }
