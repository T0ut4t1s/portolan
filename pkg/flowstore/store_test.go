// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package flowstore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

// base is an arbitrary fixed instant on a bucket boundary. Tests drive time
// explicitly — nothing here reads the clock, so nothing here is flaky.
var base = time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "flows.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func pod(ns, name string) snapshot.FlowPeer {
	return snapshot.FlowPeer{Namespace: ns, Name: name, Kind: "Deployment"}
}

// edge is the canonical test edge; vary it with the helpers below.
func edge(src, dst snapshot.FlowPeer, port string) snapshot.FlowEdgeKey {
	return snapshot.FlowEdgeKey{Src: src, Dst: dst, Port: port, Verdict: "FORWARDED"}
}

// add folds one flush of edges in, crediting the whole flush interval as
// observed so coverage lands at 100% unless a test says otherwise.
func add(t *testing.T, s *Store, at time.Time, observed time.Duration, edges map[snapshot.FlowEdgeKey]snapshot.FlowIncrement) {
	t.Helper()
	if err := s.Add(context.Background(), at, snapshot.FlowDelta{
		Edges:      edges,
		ObservedMS: observed.Milliseconds(),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
}

func capture(t *testing.T, s *Store, now time.Time, window time.Duration) *snapshot.FlowCapture {
	t.Helper()
	fc, err := s.Capture(context.Background(), now, window)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	return fc
}

// The headline property: counts for the same edge accumulate across flushes
// and across buckets. This is what makes a 24h window mean 24h — the polled
// collector could only ever report the last flush.
func TestCountsAccumulateAcrossFlushesAndBuckets(t *testing.T) {
	s := open(t)
	e := edge(pod("web", "front"), pod("api", "back"), "8080/TCP")

	// Three flushes inside one bucket, then one in the next bucket.
	for i, at := range []time.Time{
		base,
		base.Add(30 * time.Second),
		base.Add(60 * time.Second),
		base.Add(20 * time.Minute), // next 15m bucket
	} {
		add(t, s, at, 30*time.Second, map[snapshot.FlowEdgeKey]snapshot.FlowIncrement{
			e: {Count: 10, LastSeen: at},
		})
		_ = i
	}

	fc := capture(t, s, base.Add(25*time.Minute), time.Hour)
	if len(fc.Edges) != 1 {
		t.Fatalf("want the 4 flushes folded into 1 edge, got %d", len(fc.Edges))
	}
	if got := fc.Edges[0].Count; got != 40 {
		t.Errorf("count = %d, want 40 (4 flushes × 10) — increments must SUM, not replace", got)
	}
	if want := base.Add(20 * time.Minute); !fc.Edges[0].LastSeen.Equal(want) {
		t.Errorf("lastSeen = %s, want the newest %s", fc.Edges[0].LastSeen, want)
	}
	if fc.Source != snapshot.FlowSourceStream {
		t.Errorf("source = %q, want %q — a streamed capture must not be mistaken for a buffer read",
			fc.Source, snapshot.FlowSourceStream)
	}
}

// A window must exclude what falls outside it, or "observed in the last hour"
// is just "observed, ever".
func TestWindowExcludesOlderBuckets(t *testing.T) {
	s := open(t)
	old := edge(pod("cron", "nightly"), pod("db", "pg"), "5432/TCP")
	recent := edge(pod("web", "front"), pod("api", "back"), "8080/TCP")

	add(t, s, base, time.Minute, map[snapshot.FlowEdgeKey]snapshot.FlowIncrement{old: {Count: 5, LastSeen: base}})
	late := base.Add(3 * time.Hour)
	add(t, s, late, time.Minute, map[snapshot.FlowEdgeKey]snapshot.FlowIncrement{recent: {Count: 7, LastSeen: late}})

	now := base.Add(3*time.Hour + 5*time.Minute)

	fc := capture(t, s, now, time.Hour)
	if len(fc.Edges) != 1 || fc.Edges[0].Src.Name != "front" {
		t.Fatalf("1h window should hold only the recent edge, got %d: %+v", len(fc.Edges), fc.Edges)
	}

	// The wide window sees both — the old edge did not disappear, it was simply
	// out of scope. This is exactly the periodic traffic a 15m poller misses.
	fc = capture(t, s, now, 6*time.Hour)
	if len(fc.Edges) != 2 {
		t.Fatalf("6h window should hold both edges, got %d: %+v", len(fc.Edges), fc.Edges)
	}
}

// Coverage is the whole point of the rewrite: it must reflect time actually
// spent connected, so a gap reads as a gap.
func TestCoverageReportsRealObservedTime(t *testing.T) {
	e := edge(pod("web", "front"), pod("api", "back"), "8080/TCP")

	t.Run("fully connected", func(t *testing.T) {
		s := open(t)
		// One hour of wall clock, fully observed: 120 flushes × 30s.
		for i := range 120 {
			at := base.Add(time.Duration(i) * 30 * time.Second)
			add(t, s, at, 30*time.Second, map[snapshot.FlowEdgeKey]snapshot.FlowIncrement{e: {Count: 1, LastSeen: at}})
		}
		fc := capture(t, s, base.Add(time.Hour), time.Hour)
		if fc.Coverage < 0.99 {
			t.Errorf("coverage = %.3f, want ~1.0 for an hour fully streamed", fc.Coverage)
		}
	})

	t.Run("half the window spent reconnecting", func(t *testing.T) {
		s := open(t)
		// Same hour, but the stream was only up for half of each flush.
		for i := range 120 {
			at := base.Add(time.Duration(i) * 30 * time.Second)
			add(t, s, at, 15*time.Second, map[snapshot.FlowEdgeKey]snapshot.FlowIncrement{e: {Count: 1, LastSeen: at}})
		}
		fc := capture(t, s, base.Add(time.Hour), time.Hour)
		if fc.Coverage < 0.45 || fc.Coverage > 0.55 {
			t.Errorf("coverage = %.3f, want ~0.5 — a stream that was down half the time must SAY so", fc.Coverage)
		}
	})
}

// Coverage is measured against the window the caller ASKED for, not the
// bucket-snapped span the query happened to read. Those differ (`from` snaps
// outward), and dividing by the span made a stream that had watched 3m30s of a
// 15m window report 12% instead of 23% — a number answering a question nobody
// asked.
func TestCoverageIsRelativeToTheRequestedWindow(t *testing.T) {
	s := open(t)
	e := edge(pod("web", "front"), pod("api", "back"), "8080/TCP")

	// Start mid-bucket, so `from` snaps back well beyond the 15m window: at
	// 12:22 a 15m look-back snaps to 12:00, a 22-minute span.
	at := base.Add(22 * time.Minute)
	add(t, s, at, 3*time.Minute+30*time.Second, map[snapshot.FlowEdgeKey]snapshot.FlowIncrement{e: {Count: 1, LastSeen: at}})

	fc := capture(t, s, at, 15*time.Minute)
	// 3m30s of 15m is 23%. Against the 22-minute snapped span it would be 16%.
	if fc.Coverage < 0.22 || fc.Coverage > 0.24 {
		t.Errorf("coverage = %.3f, want ~0.23 (3m30s of the 15m asked for), not a ratio of the snapped span", fc.Coverage)
	}
	if fc.Watched != "3m30s" {
		t.Errorf("watched = %q, want the raw observed time %q", fc.Watched, "3m30s")
	}
}

// A fresh store must not pretend it saw an empty cluster. "No observations" and
// "nothing was observed" are different claims and only one of them is honest.
func TestEmptyStoreRefusesToClaimCoverage(t *testing.T) {
	s := open(t)
	_, err := s.Capture(context.Background(), base, time.Hour)
	if !errors.Is(err, ErrNoObservations) {
		t.Fatalf("err = %v, want ErrNoObservations — an empty store must not report a clean window", err)
	}
}

// Drops carry a reason, and two drops of the same pair for different reasons
// are different facts; folding them together would lose the diagnosis.
func TestDropReasonDiscriminatesEdges(t *testing.T) {
	s := open(t)
	src, dst := pod("web", "front"), pod("db", "pg")
	denied := snapshot.FlowEdgeKey{Src: src, Dst: dst, Port: "5432/TCP", Verdict: "DROPPED", DropReason: "POLICY_DENIED"}
	noroute := snapshot.FlowEdgeKey{Src: src, Dst: dst, Port: "5432/TCP", Verdict: "DROPPED", DropReason: "NO_ROUTE"}
	fwd := edge(src, dst, "5432/TCP")

	add(t, s, base, 30*time.Second, map[snapshot.FlowEdgeKey]snapshot.FlowIncrement{
		denied:  {Count: 3, LastSeen: base},
		noroute: {Count: 2, LastSeen: base},
		fwd:     {Count: 9, LastSeen: base},
	})

	fc := capture(t, s, base.Add(time.Minute), time.Hour)
	if len(fc.Edges) != 3 {
		t.Fatalf("want 3 distinct edges (2 drop reasons + 1 forward), got %d: %+v", len(fc.Edges), fc.Edges)
	}
	byReason := map[string]int{}
	for _, e := range fc.Edges {
		byReason[e.DropReason] = e.Count
	}
	if byReason["POLICY_DENIED"] != 3 || byReason["NO_ROUTE"] != 2 || byReason[""] != 9 {
		t.Errorf("counts collapsed across verdict/reason: %+v", byReason)
	}
}

// Retention must drop aged-out buckets AND the edge rows they were the last
// reference to, or the dimension table grows forever on a PVC.
func TestPruneDropsAgedOutBucketsAndOrphanedEdges(t *testing.T) {
	s := open(t)
	stale := edge(pod("old", "gone"), pod("db", "pg"), "5432/TCP")
	fresh := edge(pod("web", "front"), pod("api", "back"), "8080/TCP")

	add(t, s, base, time.Minute, map[snapshot.FlowEdgeKey]snapshot.FlowIncrement{stale: {Count: 5, LastSeen: base}})
	now := base.Add(MaxWindow + time.Hour)
	add(t, s, now, time.Minute, map[snapshot.FlowEdgeKey]snapshot.FlowIncrement{fresh: {Count: 5, LastSeen: now}})

	if err := s.Prune(context.Background(), now); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	var edges, counts int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM edge`).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM bucket_count`).Scan(&counts); err != nil {
		t.Fatal(err)
	}
	if counts != 1 {
		t.Errorf("bucket_count rows = %d, want 1 (the aged-out bucket must go)", counts)
	}
	if edges != 1 {
		t.Errorf("edge rows = %d, want 1 (the orphaned dimension row must go too)", edges)
	}
}

// The store outlives the process: a restart must not lose the window. This is
// the reason it is on disk at all rather than in memory.
func TestObservationsSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flows.db")
	e := edge(pod("web", "front"), pod("api", "back"), "8080/TCP")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	add(t, s, base, time.Minute, map[snapshot.FlowEdgeKey]snapshot.FlowIncrement{e: {Count: 11, LastSeen: base}})
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()

	fc := capture(t, s2, base.Add(time.Minute), time.Hour)
	if len(fc.Edges) != 1 || fc.Edges[0].Count != 11 {
		t.Fatalf("window did not survive a restart: %+v", fc.Edges)
	}
}

// A window longer than the store retains is answered with what exists, clamped
// — never with an invented span.
func TestWindowClampsToMaxWindow(t *testing.T) {
	s := open(t)
	e := edge(pod("web", "front"), pod("api", "back"), "8080/TCP")
	add(t, s, base, time.Minute, map[snapshot.FlowEdgeKey]snapshot.FlowIncrement{e: {Count: 1, LastSeen: base}})

	fc := capture(t, s, base.Add(time.Minute), 30*24*time.Hour)
	if fc.Window != snapshot.ShortDur(MaxWindow) {
		t.Errorf("window = %q, want it clamped to %q", fc.Window, snapshot.ShortDur(MaxWindow))
	}
}

// The empty-store error must be the one Collect recognises, or a freshly
// started pod reports "flow capture failed" on the map for a whole interval —
// crying wolf on every rollout.
func TestEmptyStoreReturnsTheWarmingSentinel(t *testing.T) {
	s := open(t)
	_, err := s.Capture(context.Background(), base, time.Hour)
	if !errors.Is(err, snapshot.ErrNoObservations) {
		t.Fatalf("err = %v, want snapshot.ErrNoObservations so Collect can tell warming from failure", err)
	}
}
