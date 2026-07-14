// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

// Package flowstore is the rolling observation store behind Portolan's flow
// overlay.
//
// It exists because Hubble cannot answer the question the overlay asks.
// Cilium's event buffer is bounded by CAPACITY, not by time — the default is
// 4095 events per agent — so a busy cluster drains it in seconds. Asking the
// relay for "the last 15 minutes" on such a cluster returns the last ~12
// seconds and says nothing about the difference. A collector that polls that
// buffer every 15 minutes therefore observes roughly 1% of the traffic and
// reports it as if it had seen all of it: anything periodic (a CronJob, a
// backup, a scrape) falls between the samples and is simply invisible.
//
// The fix is to stop sampling and start listening. A long-lived follow-mode
// stream feeds every observed flow into this store, aggregated to the same
// workload-granularity edges the policy map draws and bucketed in time. A
// window query ("what was observed in the last 24h?") is then a SUM over
// buckets, and the answer means what it says.
//
// Two properties are load-bearing:
//
//   - Coverage is recorded, not assumed. The store tracks how many seconds of
//     each bucket the stream was actually connected. A window's coverage is a
//     measured fact, so a gap — a relay restart, a network partition — is
//     reported as a gap instead of silently shrinking the denominator.
//
//   - Absence still is not proof. Even at full coverage an unobserved edge
//     means "not seen in this window", never "cannot happen". Only Cilium's
//     engine answers the latter, and that is what the policy map is for.
package flowstore

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
	_ "modernc.org/sqlite" // pure-Go driver: the release build is CGO_ENABLED=0
)

// BucketSize is the resolution at which observations are aggregated in time.
//
// It sets the granularity of every window query: a 15-minute bucket cannot
// distinguish traffic at 09:01 from traffic at 09:14. That is deliberate — the
// overlay answers "was this edge used in the last N hours", not "at what
// instant", and coarse buckets keep the row count (and so the PVC) bounded:
// one week of a busy cluster is a few hundred thousand rows, not tens of
// millions.
const BucketSize = 15 * time.Minute

// MaxWindow is the longest look-back the store retains. Buckets older than
// this are pruned; a query for a longer window is answered with what exists
// and reports its true span rather than inventing coverage.
const MaxWindow = 7 * 24 * time.Hour

// schema is applied on every open; every statement is idempotent.
//
// The counts are normalized away from the dimensions on purpose. An edge's
// identity (eleven text columns) repeats in every bucket it appears in, and at
// 672 buckets a week that repetition would dominate the file. Storing it once
// in `edge` and referencing it by integer id from `bucket_count` turns each
// per-bucket observation into three integers.
const schema = `
CREATE TABLE IF NOT EXISTS edge (
	id          INTEGER PRIMARY KEY,
	src_ns      TEXT NOT NULL,
	src_name    TEXT NOT NULL,
	src_kind    TEXT NOT NULL,
	src_entity  TEXT NOT NULL,
	dst_ns      TEXT NOT NULL,
	dst_name    TEXT NOT NULL,
	dst_kind    TEXT NOT NULL,
	dst_entity  TEXT NOT NULL,
	port        TEXT NOT NULL,
	verdict     TEXT NOT NULL,
	drop_reason TEXT NOT NULL,
	UNIQUE (src_ns, src_name, src_kind, src_entity,
	        dst_ns, dst_name, dst_kind, dst_entity,
	        port, verdict, drop_reason)
);

CREATE TABLE IF NOT EXISTS bucket_count (
	bucket    INTEGER NOT NULL,
	edge_id   INTEGER NOT NULL REFERENCES edge(id),
	count     INTEGER NOT NULL,
	last_seen INTEGER NOT NULL,
	PRIMARY KEY (bucket, edge_id)
) WITHOUT ROWID;

-- Coverage is a first-class fact, not an inference. observed_ms accumulates
-- only while the stream is actually connected, so a bucket the collector spent
-- reconnecting through reports the shortfall instead of hiding it.
CREATE TABLE IF NOT EXISTS coverage (
	bucket      INTEGER PRIMARY KEY,
	observed_ms INTEGER NOT NULL,
	flows_seen  INTEGER NOT NULL,
	skipped     INTEGER NOT NULL,
	lost_events INTEGER NOT NULL
) WITHOUT ROWID;
`

// Store is a SQLite-backed rolling store of observed flow edges. It is safe
// for concurrent use: writes are serialized behind a mutex (there is exactly
// one writer — the accumulator) while reads go straight to SQLite.
type Store struct {
	db *sql.DB
	mu sync.Mutex // serializes Add/flush against each other, not against reads
}

// Open opens (creating if needed) the store at path.
func Open(path string) (*Store, error) {
	// WAL lets a window query read while the accumulator is mid-flush; the busy
	// timeout covers the brief exclusive moments WAL still needs.
	//
	// temp_store(MEMORY) is not a tuning knob — it is load-bearing. A window
	// query groups and orders a join over every bucket in range, and once that
	// sort outgrows the page cache SQLite spills it to a temp FILE. Portolan
	// runs with readOnlyRootFilesystem: true and only its data volume mounted,
	// so there is nowhere to put one: SQLite returns SQLITE_IOERR_GETTEMPPATH
	// (6410) and the whole flow overlay vanishes from the map.
	//
	// It is a bomb with a delay on it, which is what makes it worth this
	// comment. A small store sorts inside the cache and never spills, so this
	// passes every test, every fresh deploy, and every local run with a
	// writable /tmp — then fails hours later once the data has grown. Sorting in
	// memory removes the need for a temp path at all; the sort is over
	// workload-granularity edges, not raw flows, so it stays small.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(NORMAL)&_pragma=temp_store(MEMORY)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening flow store %s: %w", path, err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing flow store %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// Store implements snapshot.FlowSink (Add) — the accumulator writes here — and
// backs snapshot.FlowSource through Live(), which is what Collect queries. The
// delta and edge types live in the snapshot package beside the streaming code
// that produces them, so there is exactly one definition of what an observed
// edge is.

// Add folds a delta into the bucket covering now. Counts accumulate, so a
// bucket flushed thirty times holds the sum of all thirty — the in-memory
// aggregator never has to remember what it already wrote.
func (s *Store) Add(ctx context.Context, now time.Time, d snapshot.FlowDelta) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bucket := now.UTC().Truncate(BucketSize).Unix()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("flow store: begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	// The edge dimensions are written once and reused; only the counts recur.
	insEdge, err := tx.PrepareContext(ctx, `
		INSERT INTO edge (src_ns, src_name, src_kind, src_entity,
		                  dst_ns, dst_name, dst_kind, dst_entity,
		                  port, verdict, drop_reason)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT DO UPDATE SET src_ns = src_ns
		RETURNING id`)
	if err != nil {
		return fmt.Errorf("flow store: prepare edge: %w", err)
	}
	defer insEdge.Close()

	insCount, err := tx.PrepareContext(ctx, `
		INSERT INTO bucket_count (bucket, edge_id, count, last_seen)
		VALUES (?,?,?,?)
		ON CONFLICT (bucket, edge_id) DO UPDATE SET
			count     = count + excluded.count,
			last_seen = MAX(last_seen, excluded.last_seen)`)
	if err != nil {
		return fmt.Errorf("flow store: prepare count: %w", err)
	}
	defer insCount.Close()

	for k, inc := range d.Edges {
		var id int64
		// ON CONFLICT DO UPDATE (rather than DO NOTHING) so RETURNING yields the
		// existing row's id on a repeat edge; DO NOTHING returns no row at all.
		if err := insEdge.QueryRowContext(ctx,
			k.Src.Namespace, k.Src.Name, k.Src.Kind, k.Src.Entity,
			k.Dst.Namespace, k.Dst.Name, k.Dst.Kind, k.Dst.Entity,
			k.Port, k.Verdict, k.DropReason,
		).Scan(&id); err != nil {
			return fmt.Errorf("flow store: upsert edge: %w", err)
		}
		if _, err := insCount.ExecContext(ctx, bucket, id, inc.Count, inc.LastSeen.UTC().Unix()); err != nil {
			return fmt.Errorf("flow store: upsert count: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO coverage (bucket, observed_ms, flows_seen, skipped, lost_events)
		VALUES (?,?,?,?,?)
		ON CONFLICT (bucket) DO UPDATE SET
			observed_ms = observed_ms + excluded.observed_ms,
			flows_seen  = flows_seen  + excluded.flows_seen,
			skipped     = skipped     + excluded.skipped,
			lost_events = lost_events + excluded.lost_events`,
		bucket, d.ObservedMS, d.FlowsSeen, d.Skipped, d.LostEvents); err != nil {
		return fmt.Errorf("flow store: upsert coverage: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("flow store: commit: %w", err)
	}
	return nil
}

// Prune drops buckets that have aged out of MaxWindow, and the edge
// dimensions left with no buckets pointing at them.
func (s *Store) Prune(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := now.UTC().Add(-MaxWindow).Truncate(BucketSize).Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM bucket_count WHERE bucket < ?`, cutoff); err != nil {
		return fmt.Errorf("flow store: pruning counts: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM coverage WHERE bucket < ?`, cutoff); err != nil {
		return fmt.Errorf("flow store: pruning coverage: %w", err)
	}
	// An edge nothing references is dead weight; its id is never reused, which
	// is fine — ids are internal and 64-bit.
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM edge WHERE id NOT IN (SELECT DISTINCT edge_id FROM bucket_count)`); err != nil {
		return fmt.Errorf("flow store: pruning edges: %w", err)
	}
	return nil
}

// ErrNoObservations reports that the store holds nothing for the requested
// window — a fresh store, or one whose stream has never connected. It is
// defined in the snapshot package so Collect can recognise it without
// importing this one, and tell "we have not listened yet" apart from "the
// capture failed": the first is a normal minute of a pod's life, the second
// is a fault.
var ErrNoObservations = snapshot.ErrNoObservations

// Live adapts the store to snapshot.FlowSource against the real clock, so
// Collect can ask it for a window without knowing it is a database.
func (s *Store) Live() snapshot.FlowSource { return liveSource{s} }

type liveSource struct{ s *Store }

func (l liveSource) Capture(ctx context.Context, window time.Duration) (*snapshot.FlowCapture, error) {
	return l.s.Capture(ctx, time.Now(), window)
}

// Capture answers a window query: every edge observed in the last window,
// aggregated across buckets, with the coverage actually achieved.
//
// The window is snapped outward to a bucket boundary, so a 1h query reads the
// buckets that overlap the last hour rather than silently dropping the partial
// one at the far end. From/To therefore describe the span the answer really
// covers, which is the span the map must label it with.
func (s *Store) Capture(ctx context.Context, now time.Time, window time.Duration) (*snapshot.FlowCapture, error) {
	if window <= 0 {
		return nil, fmt.Errorf("flow store: window must be positive, got %s", window)
	}
	if window > MaxWindow {
		window = MaxWindow
	}
	now = now.UTC()
	from := now.Add(-window).Truncate(BucketSize)

	fc := &snapshot.FlowCapture{
		Status: "ok",
		Source: snapshot.FlowSourceStream,
		Window: snapshot.ShortDur(window),
		From:   from,
		To:     now,
		Edges:  []snapshot.FlowEdge{},
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT e.src_ns, e.src_name, e.src_kind, e.src_entity,
		       e.dst_ns, e.dst_name, e.dst_kind, e.dst_entity,
		       e.port, e.verdict, e.drop_reason,
		       SUM(b.count), MAX(b.last_seen)
		FROM bucket_count b JOIN edge e ON e.id = b.edge_id
		WHERE b.bucket >= ?
		GROUP BY e.id
		ORDER BY e.src_ns, e.src_name, e.dst_ns, e.dst_name, e.port, e.verdict, e.drop_reason`,
		from.Unix())
	if err != nil {
		return nil, fmt.Errorf("flow store: querying edges: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			e        snapshot.FlowEdge
			lastSeen int64
		)
		if err := rows.Scan(
			&e.Src.Namespace, &e.Src.Name, &e.Src.Kind, &e.Src.Entity,
			&e.Dst.Namespace, &e.Dst.Name, &e.Dst.Kind, &e.Dst.Entity,
			&e.Port, &e.Verdict, &e.DropReason, &e.Count, &lastSeen,
		); err != nil {
			return nil, fmt.Errorf("flow store: scanning edge: %w", err)
		}
		e.LastSeen = time.Unix(lastSeen, 0).UTC()
		fc.Edges = append(fc.Edges, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("flow store: reading edges: %w", err)
	}

	// Coverage comes from the same window, and is what lets a reader tell "this
	// edge was not used" from "we were not watching".
	var (
		observedMS               sql.NullInt64
		flowsSeen, skipped, lost sql.NullInt64
		oldestBucket             sql.NullInt64
	)
	if err := s.db.QueryRowContext(ctx, `
		SELECT SUM(observed_ms), SUM(flows_seen), SUM(skipped), SUM(lost_events), MIN(bucket)
		FROM coverage WHERE bucket >= ?`, from.Unix()).
		Scan(&observedMS, &flowsSeen, &skipped, &lost, &oldestBucket); err != nil {
		return nil, fmt.Errorf("flow store: querying coverage: %w", err)
	}
	if !oldestBucket.Valid {
		return nil, ErrNoObservations
	}

	fc.FlowsSeen = int(flowsSeen.Int64)
	fc.Skipped = int(skipped.Int64)
	fc.LostEvents = int(lost.Int64)

	// Coverage answers the question the label asks — "how much of the 15m you
	// asked for did we actually watch?" — so the denominator is the REQUESTED
	// window, not the bucket-snapped span.
	//
	// Those differ: `from` snaps outward to a bucket boundary, so the span can
	// reach half a bucket further back than the window. Dividing by the span
	// would make a freshly-started stream report 12% of a 15m window when it had
	// watched 3m30s of it (23%) — understating coverage against a denominator
	// the caller never asked about. Watched can then exceed the window once the
	// oldest bucket overhangs it, so the ratio is clamped while the raw figure
	// is left alone.
	observed := time.Duration(observedMS.Int64) * time.Millisecond
	// Clamp the duration, not just the ratio. `from` snaps outward to a bucket
	// boundary, so the oldest bucket's observed time reaches back before the
	// window starts and the sum can exceed it — which printed as "24h9m29s
	// watched, 100% of a 24h window", a sentence that is visibly nonsense and
	// quietly discredits every other figure beside it. The overhang is bucket
	// granularity, not information.
	if observed > window {
		observed = window
	}
	fc.Watched = snapshot.ShortDur(observed.Round(time.Second))
	fc.WatchedSec = observed.Seconds()
	if window > 0 {
		fc.Coverage = float64(observed) / float64(window)
	}
	// OldestFlow keeps its old meaning — the earliest moment this capture can
	// speak for — so consumers written against the polled captures still work.
	fc.OldestFlow = time.Unix(oldestBucket.Int64, 0).UTC()

	return fc, nil
}
