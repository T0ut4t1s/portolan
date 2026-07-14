// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package graph

import (
	"strings"
	"testing"
	"time"
)

func flowsWith(drops ...DropEdge) *FlowOverlay {
	return &FlowOverlay{
		Status: "ok", Source: "stream", Window: "24h", Watched: "24h",
		WatchedSec: 24 * 3600, Coverage: 1, BucketSec: 900,
		To: time.Now(), Drops: drops,
	}
}

// The ID is the whole point of the sidecar, and it is only worth anything if it
// survives the things that change every single run.
//
// Longhorn picks a fresh ephemeral port daily; counts move with coverage;
// timestamps move with the clock. Fold any of those into the identity and every
// finding is NEW forever — which is exactly the same as having no memory at all,
// only with more JSON.
func TestFindingIDsSurviveEverythingThatChangesEveryRun(t *testing.T) {
	const im, lm = "longhorn-system/instance-manager-b0258", "longhorn-system/longhorn-manager"

	monday := &Graph{Cluster: "c", TakenAt: "monday", Tool: "portolan",
		Flows: flowsWith(DropEdge{Src: im, Dst: lm, Port: "37164/TCP", Reason: "POLICY_DENIED",
			Count: 3, Buckets: 2, LastSeen: time.Now()})}
	tuesday := &Graph{Cluster: "c", TakenAt: "tuesday", Tool: "portolan",
		Flows: flowsWith(DropEdge{Src: im, Dst: lm, Port: "38906/TCP", Reason: "POLICY_DENIED",
			Count: 91, Buckets: 40, LastSeen: time.Now().Add(-time.Hour)})}

	a := ComputeFindings(monday, &Audit{Drops: monday.Flows.Drops})
	b := ComputeFindings(tuesday, &Audit{Drops: tuesday.Flows.Drops})

	if len(a.Findings) != 1 || len(b.Findings) != 1 {
		t.Fatalf("want one finding each, got %d and %d", len(a.Findings), len(b.Findings))
	}
	if a.Findings[0].ID != b.Findings[0].ID {
		t.Errorf("the SAME standing problem got two different ids across runs (%s vs %s) — "+
			"a different ephemeral port and a different count must not mint a new finding",
			a.Findings[0].ID, b.Findings[0].ID)
	}
	// And the volatile parts must still be reported, just not baked into identity.
	if b.Findings[0].Count != 91 {
		t.Errorf("count = %d, want the current 91 — stability of the ID must not freeze the data", b.Findings[0].Count)
	}
}

// Different problems must not collide onto one id, or a suppression aimed at
// one would silence the other.
func TestDifferentFindingsGetDifferentIDs(t *testing.T) {
	g := &Graph{TakenAt: "now", Tool: "portolan", Flows: flowsWith(
		DropEdge{Src: "a/x", Dst: "b/y", Port: "80/TCP", Reason: "POLICY_DENIED", Count: 1},
		DropEdge{Src: "a/x", Dst: "b/y", Port: "443/TCP", Reason: "POLICY_DENIED", Count: 1},
		DropEdge{Src: "a/x", Dst: "b/z", Port: "80/TCP", Reason: "POLICY_DENIED", Count: 1},
	)}
	set := ComputeFindings(g, &Audit{Drops: g.Flows.Drops})
	seen := map[string]bool{}
	for _, f := range set.Findings {
		if seen[f.ID] {
			t.Fatalf("id collision on %s — a suppression would silence the wrong finding", f.ID)
		}
		seen[f.ID] = true
	}
	if len(seen) != 3 {
		t.Fatalf("want 3 distinct ids, got %d", len(seen))
	}
}

// Resolved findings are the only part of the brief that says you WON. Without
// them a fix is invisible: you change a policy, the finding stops appearing, and
// nothing anywhere tells you it was you. A tool whose list only ever grows
// teaches you to stop reading it.
func TestDiffReportsWhatWasFixed(t *testing.T) {
	before := &Graph{TakenAt: "t1", Tool: "portolan", Flows: flowsWith(
		DropEdge{Src: "web/front", Dst: "db/pg", Port: "5432/TCP", Reason: "POLICY_DENIED", Count: 40, Buckets: 90},
		DropEdge{Src: "old/thing", Dst: "entity:world", Port: "443/TCP", Reason: "POLICY_DENIED", Count: 5, Buckets: 3},
	)}
	prev := ComputeFindings(before, &Audit{Drops: before.Flows.Drops})

	// The operator fixed old/thing, and a new problem turned up.
	after := &Graph{TakenAt: "t2", Tool: "portolan", Flows: flowsWith(
		DropEdge{Src: "web/front", Dst: "db/pg", Port: "5432/TCP", Reason: "POLICY_DENIED", Count: 44, Buckets: 95},
		DropEdge{Src: "new/thing", Dst: "entity:world", Port: "80/TCP", Reason: "POLICY_DENIED", Count: 2, Buckets: 1},
	)}
	a := &Audit{Drops: after.Flows.Drops}

	cur := ComputeFindings(after, a)
	resolved := Diff(cur, prev)

	if len(resolved) != 1 || !strings.Contains(resolved[0].Title, "old/thing") {
		t.Fatalf("the fixed finding must be reported RESOLVED, got %+v", resolved)
	}
	byTitle := map[string]string{}
	for _, f := range cur.Findings {
		byTitle[f.Title] = f.Status
	}
	for title, want := range map[string]string{"web/front": "PERSISTING", "new/thing": "NEW"} {
		var got string
		for tt, st := range byTitle {
			if strings.Contains(tt, title) {
				got = st
			}
		}
		if got != want {
			t.Errorf("%s: status %q, want %q", title, got, want)
		}
	}

	// And the brief must lead with the win.
	out := string(BriefWith(after, a, BriefOptions{Previous: prev}))
	if !strings.Contains(out, "✅ Resolved since the last run (1)") {
		t.Errorf("the brief must report what got fixed\n---\n%s", out)
	}
	if !strings.Contains(out, "old/thing") {
		t.Error("the resolved finding must be named")
	}
	if !strings.Contains(out, "new/thing") || !strings.Contains(out, "**NEW**") {
		t.Error("a genuinely new finding must be marked NEW")
	}
}

// With no baseline, everything is new — so shouting NEW at every line tells the
// reader nothing and trains them to ignore the word.
func TestFirstRunDoesNotShoutNewAtEverything(t *testing.T) {
	g := &Graph{TakenAt: "t", Tool: "portolan", Flows: flowsWith(
		DropEdge{Src: "web/front", Dst: "db/pg", Port: "5432/TCP", Reason: "POLICY_DENIED", Count: 40, Buckets: 90})}
	out := string(BriefWith(g, &Audit{Drops: g.Flows.Drops}, BriefOptions{Previous: nil}))
	if strings.Contains(out, "**NEW**") {
		t.Errorf("with nothing to compare against, NEW is noise\n---\n%s", out)
	}
}

// A suppressed finding is HIDDEN, never deleted, and the brief always says how
// many and why. A silent filter is indistinguishable from a blind spot.
func TestSuppressionHidesButAlwaysAccountsForItself(t *testing.T) {
	refs := []string{
		"CiliumNetworkPolicy/a/pgbouncer-db-init → app=pgbouncer-db-init",
		"CiliumNetworkPolicy/b/searxng → app.kubernetes.io/name=searxng",
	}
	a := &Audit{DeadRefs: refs}
	g := &Graph{TakenAt: "t", Tool: "portolan"}

	id := findingID("dead-selector", "app=pgbouncer-db-init")
	const why = "pgbouncer-db-init is a Job — matching nothing at rest is correct"
	out := string(BriefWith(g, a, BriefOptions{Suppressions: map[string]string{id: why}}))

	if strings.Contains(out, "- `app=pgbouncer-db-init`") {
		t.Error("a suppressed finding must not appear in the body")
	}
	if !strings.Contains(out, "### Suppressed (1)") {
		t.Errorf("suppression must account for itself\n---\n%s", out)
	}
	if !strings.Contains(out, why) {
		t.Error("the REASON must be shown — a suppression you cannot audit will outlive whatever made it true")
	}
	// The un-suppressed one is untouched.
	if !strings.Contains(out, "searxng") {
		t.Error("suppressing one finding must not hide another")
	}
}

// A suppression with no reason is a lie you told yourself six months ago and can
// no longer audit. Refuse it at load time, where it can still be fixed.
func TestSuppressionWithoutAReasonIsRejected(t *testing.T) {
	if _, err := LoadSuppressions(strings.NewReader("a1b2c3d4e5f6\n")); err == nil {
		t.Fatal("a suppression with no reason must be rejected, not silently accepted")
	}
	good := "# decisions already taken\na1b2c3d4e5f6  it is a Job, this is correct\n\n"
	got, err := LoadSuppressions(strings.NewReader(good))
	if err != nil {
		t.Fatalf("LoadSuppressions: %v", err)
	}
	if got["a1b2c3d4e5f6"] != "it is a Job, this is correct" {
		t.Errorf("reason not captured: %+v", got)
	}
}

// The sidecar must round-trip, or "feed yesterday's file back in" does not work.
func TestFindingSetRoundTrips(t *testing.T) {
	g := &Graph{Cluster: "c", TakenAt: "t", Tool: "portolan", Flows: flowsWith(
		DropEdge{Src: "web/front", Dst: "db/pg", Port: "5432/TCP", Reason: "POLICY_DENIED", Count: 40, Buckets: 90})}
	set := ComputeFindings(g, &Audit{Drops: g.Flows.Drops})
	blob, err := set.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := LoadFindings(strings.NewReader(string(blob)))
	if err != nil {
		t.Fatalf("LoadFindings: %v", err)
	}
	if len(back.Findings) != len(set.Findings) || back.Findings[0].ID != set.Findings[0].ID {
		t.Errorf("round trip lost the identity: %+v", back)
	}
}
