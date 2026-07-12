// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package snapshot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// stderr is where the accumulator reports connection trouble; a variable so
// tests can capture it instead of polluting the test log.
var stderr io.Writer = os.Stderr

// FlowSource supplies flow observations for a look-back window.
//
// It exists to separate the two ways a window can be answered, because they
// are worth wildly different amounts and must never be silently swapped:
//
//   - Reading Hubble's buffer (collectFlows) is all a one-shot command can do.
//     The buffer is bounded by capacity, not time, so on a busy cluster it
//     holds seconds regardless of the window asked for. Its silences prove
//     nothing.
//   - Accumulating a continuous stream (Accumulator, via a store) actually
//     watches the window. Its silences are evidence.
//
// Every capture records which it was, in FlowCapture.Source.
type FlowSource interface {
	Capture(ctx context.Context, window time.Duration) (*FlowCapture, error)
}

// ErrNoObservations reports that a FlowSource has nothing for the window yet —
// a store whose stream has only just connected. It is not a failure: a pod's
// first collection races the stream's first flush and loses, every time.
var ErrNoObservations = errors.New("no observations in window yet")

// ShortDur formats a window the way a person writes one — "15m", "6h", "7d" —
// instead of Go's "168h0m0s". The map's window control round-trips this exact
// string, so the same spelling has to come back out as went in; ParseWindow is
// its inverse.
func ShortDur(d time.Duration) string {
	switch {
	// Days only from two days up: a day of traffic is "24h" to everyone who
	// says it out loud, and a week is "7d", never "168h". The map's buttons are
	// spelled the same way and compare against this string, so the boundary is
	// load-bearing, not cosmetic.
	case d%(24*time.Hour) == 0 && d >= 48*time.Hour:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0 && d >= time.Hour:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0 && d >= time.Minute:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return d.String()
	}
}

// ParseWindow parses a window, extending Go's duration syntax with the day
// unit that time.ParseDuration lacks — "7d" is the natural way to ask for a
// week and the map's control offers it.
func ParseWindow(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, fmt.Errorf("invalid window %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// FlowSink receives the accumulator's periodic deltas. flowstore.Store is the
// implementation; the interface keeps the streaming code here (where the
// Hubble plumbing and peer resolution already live) without dragging a SQLite
// dependency into the snapshot package.
type FlowSink interface {
	Add(ctx context.Context, now time.Time, d FlowDelta) error
}

// FlowDelta is everything the accumulator folded up since its last flush.
type FlowDelta struct {
	Edges map[FlowEdgeKey]FlowIncrement
	// ObservedMS is how many milliseconds of this flush the stream was actually
	// connected. It is what turns coverage from an assumption into a
	// measurement: time spent reconnecting contributes nothing, so a gap shows
	// up as a gap rather than quietly shrinking the denominator.
	ObservedMS int64
	FlowsSeen  int
	Skipped    int
	LostEvents int
}

// FlowEdgeKey identifies an observed edge — the same tuple the point-in-time
// aggregator uses, so streamed and sampled captures describe edges identically.
type FlowEdgeKey struct {
	Src        FlowPeer
	Dst        FlowPeer
	Port       string
	Verdict    string
	DropReason string
}

// FlowIncrement is one edge's contribution to one flush.
type FlowIncrement struct {
	Count    int
	LastSeen time.Time
}

// Accumulator keeps a follow-mode Hubble stream open and folds what it sees
// into a FlowSink.
//
// Reconnection deliberately does NOT replay Hubble's buffer. Replaying would
// let a reconnect double-count flows already folded in, trading a small honest
// gap for a silent inflation — and inflated counts are worse than admitted
// gaps in an instrument whose whole job is to be trusted. A dropped stream is
// therefore a hole, and coverage reports it as one.
type Accumulator struct {
	server  string
	sink    FlowSink
	resolve flowResolver

	mu    sync.Mutex
	edges map[FlowEdgeKey]FlowIncrement
	// connSince is when the current connection was established; zero while
	// disconnected. observedMS banks the connected time of spans that have
	// already ended.
	connSince  time.Time
	observedMS int64
	flowsSeen  int
	skipped    int
	lostEvents int
}

// NewAccumulator builds an accumulator streaming from the Hubble Relay at
// server, resolving pod peers through resolve (typically Collector.Resolve).
func NewAccumulator(server string, sink FlowSink, resolve flowResolver) *Accumulator {
	return &Accumulator{
		server:  server,
		sink:    sink,
		resolve: resolve,
		edges:   map[FlowEdgeKey]FlowIncrement{},
	}
}

// streamFlushInterval bounds how stale a window query can be, and how much
// work one failed flush can lose.
const streamFlushInterval = 30 * time.Second

const (
	streamBackoffMin = 1 * time.Second
	streamBackoffMax = 30 * time.Second
)

// Run streams until ctx is cancelled, reconnecting with backoff. It returns
// only on cancellation: a relay that is down is a degraded observation, never
// a reason to take the dashboard down with it.
func (a *Accumulator) Run(ctx context.Context) {
	go a.flushLoop(ctx)

	backoff := streamBackoffMin
	for ctx.Err() == nil {
		err := a.stream(ctx)
		if ctx.Err() != nil {
			return
		}
		// Any return is a lost connection: bank the connected time so the gap
		// that follows is charged to coverage, not hidden.
		a.disconnected()
		if err != nil {
			fmt.Fprintf(stderr, "flow stream: %v (reconnecting in %s)\n", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > streamBackoffMax {
			backoff = streamBackoffMax
		}
	}
}

// stream holds one connection open, folding every flow it receives. It returns
// when the stream ends or fails.
func (a *Accumulator) stream(ctx context.Context) error {
	conn, err := grpc.NewClient(a.server, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dialing hubble relay %s: %w", a.server, err)
	}
	defer conn.Close()

	// Follow with no Since: take flows from now on. See the type comment — we
	// do not replay the buffer, because double-counting is worse than a gap.
	req := &observerpb.GetFlowsRequest{
		Follow:    true,
		Whitelist: flowWhitelist(),
	}
	stream, err := observerpb.NewObserverClient(conn).GetFlows(ctx, req)
	if err != nil {
		return fmt.Errorf("subscribing to hubble relay %s: %w", a.server, err)
	}

	a.connected()
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("streaming flows from %s: %w", a.server, err)
		}
		a.observe(resp)
	}
}

// observe folds one relay response into the pending delta.
func (a *Accumulator) observe(resp *observerpb.GetFlowsResponse) {
	if lost := resp.GetLostEvents(); lost != nil {
		a.mu.Lock()
		a.lostEvents += int(lost.GetNumEventsLost())
		a.mu.Unlock()
		return
	}
	f := resp.GetFlow()
	if f == nil {
		return
	}

	// Peers are resolved HERE, as the flow arrives, against the pod index
	// current at that moment — a pod that dies an hour from now is still
	// correctly attributed to its controller.
	src, srcIsWorkload := peerFromEndpoint(f.GetSource(), a.resolve)
	dst, dstIsWorkload := peerFromEndpoint(f.GetDestination(), a.resolve)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.flowsSeen++
	// Same noise gates as the polled capture: flows touching no cluster
	// workload (LAN broadcast chatter on node NICs) and Cilium's own health
	// checks say nothing about the policy topology.
	if (!srcIsWorkload && !dstIsWorkload) || src.Entity == "health" || dst.Entity == "health" {
		a.skipped++
		return
	}

	key := FlowEdgeKey{Src: src, Dst: dst, Port: flowPort(f.GetL4()), Verdict: f.GetVerdict().String()}
	if f.GetVerdict() == flowpb.Verdict_DROPPED {
		key.DropReason = f.GetDropReasonDesc().String()
	}
	inc := a.edges[key]
	inc.Count++
	if t := f.GetTime().AsTime(); t.After(inc.LastSeen) {
		inc.LastSeen = t
	}
	a.edges[key] = inc
}

func (a *Accumulator) connected() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.connSince = time.Now()
}

func (a *Accumulator) disconnected() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.connSince.IsZero() {
		a.observedMS += time.Since(a.connSince).Milliseconds()
		a.connSince = time.Time{}
	}
}

// flushLoop writes the pending delta to the sink on a fixed cadence — one
// transaction per interval rather than one per event, at a few hundred events
// a second.
func (a *Accumulator) flushLoop(ctx context.Context) {
	t := time.NewTicker(streamFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// A final flush on shutdown, on a context that is not the cancelled
			// one, so the last interval's observations are not thrown away.
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			a.flush(fctx)
			cancel()
			return
		case <-t.C:
			a.flush(ctx)
		}
	}
}

// flush swaps out the pending delta and hands it to the sink. On a sink error
// the delta is dropped rather than retried: it would otherwise grow without
// bound behind a persistently failing store, and the resulting coverage
// shortfall is exactly the honest signal we want.
func (a *Accumulator) flush(ctx context.Context) {
	a.mu.Lock()
	now := time.Now()
	d := FlowDelta{
		Edges:      a.edges,
		ObservedMS: a.observedMS,
		FlowsSeen:  a.flowsSeen,
		Skipped:    a.skipped,
		LostEvents: a.lostEvents,
	}
	// Credit the still-open connection up to now, and restart its clock so the
	// next flush does not count this span twice.
	if !a.connSince.IsZero() {
		d.ObservedMS += now.Sub(a.connSince).Milliseconds()
		a.connSince = now
	}
	a.edges = map[FlowEdgeKey]FlowIncrement{}
	a.observedMS, a.flowsSeen, a.skipped, a.lostEvents = 0, 0, 0, 0
	a.mu.Unlock()

	if len(d.Edges) == 0 && d.ObservedMS == 0 {
		return
	}
	if err := a.sink.Add(ctx, now, d); err != nil {
		fmt.Fprintf(stderr, "flow stream: flush failed, dropping %d edges: %v\n", len(d.Edges), err)
	}
}
