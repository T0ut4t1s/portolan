// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package snapshot

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FlowOptions configures optional Hubble flow capture. A zero Window
// disables capture entirely.
type FlowOptions struct {
	// Server is the Hubble Relay address (plaintext gRPC — relay TLS is not
	// supported yet).
	Server string
	// Window is the look-back period requested from the relay.
	Window time.Duration
}

// flowCollectTimeout bounds one whole capture: dialing, streaming the
// window's buffered flows, and aggregation. A relay that cannot drain its
// buffer inside this budget degrades the capture instead of stalling the
// snapshot.
const flowCollectTimeout = 2 * time.Minute

// Hubble event types worth capturing. Restricting to these prevents
// double-counting: with policy-verdict events enabled, Cilium emits both a
// verdict event and a trace/drop event for the same packet.
// Values from cilium's monitor API (MessageTypeDrop/Trace/AccessLog).
const (
	msgTypeDrop      = 1
	msgTypeTrace     = 4
	msgTypeAccessLog = 129 // L7
)

// entityPriority orders Cilium reserved identities for peers carrying more
// than one. Host outranks kube-apiserver: on a control-plane node the host
// identity (1) CARRIES the kube-apiserver label, while the dedicated
// kube-apiserver identity (7) is only used for remote peers — naming such
// traffic "kube-apiserver" would point whatif at the wrong identity.
var entityPriority = []string{
	"host",
	"kube-apiserver",
	"remote-node",
	"ingress",
	"health",
	"world",
	"world-ipv4",
	"world-ipv6",
	"init",
	"unmanaged",
	"unknown",
}

// flowResolver maps a live pod to its resolved controller identity; the
// collector wires in its own pod index so flow peers land on the same
// workload nodes the policy map draws.
type flowResolver func(namespace, pod string) (kind, name string, ok bool)

// collectFlows reads one bounded window of flows from Hubble Relay and
// aggregates them to workload-granularity edges.
func collectFlows(ctx context.Context, opts FlowOptions, resolve flowResolver) (*FlowCapture, error) {
	ctx, cancel := context.WithTimeout(ctx, flowCollectTimeout)
	defer cancel()

	conn, err := grpc.NewClient(opts.Server, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dialing hubble relay %s: %w", opts.Server, err)
	}
	defer conn.Close()

	now := time.Now().UTC()
	agg := newFlowAggregator(opts, now, resolve)

	// Since+Until without Number streams every buffered flow in the window,
	// then the server ends the stream — no follow mode, bounded by design.
	//
	// Two OR'd filters, because forwarded and dropped traffic need different
	// reply handling: forwarded flows are deduplicated to the original
	// direction (reply=false), but drop events usually carry UNKNOWN reply
	// state (no conntrack entry for a denied connection) and Hubble's reply
	// filter excludes unknown — a reply constraint there would silently
	// discard most drops.
	req := &observerpb.GetFlowsRequest{
		Since: timestamppb.New(agg.capture.From),
		Until: timestamppb.New(now),
		Whitelist: []*flowpb.FlowFilter{
			{
				Reply:   []bool{false},
				Verdict: []flowpb.Verdict{flowpb.Verdict_FORWARDED},
				EventType: []*flowpb.EventTypeFilter{
					{Type: msgTypeTrace},
					{Type: msgTypeAccessLog},
				},
			},
			{
				Verdict:   []flowpb.Verdict{flowpb.Verdict_DROPPED},
				EventType: []*flowpb.EventTypeFilter{{Type: msgTypeDrop}},
			},
		},
	}

	stream, err := observerpb.NewObserverClient(conn).GetFlows(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("querying hubble relay %s: %w", opts.Server, err)
	}
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("streaming flows from %s: %w", opts.Server, err)
		}
		if lost := resp.GetLostEvents(); lost != nil {
			agg.capture.LostEvents += int(lost.GetNumEventsLost())
			continue
		}
		if f := resp.GetFlow(); f != nil {
			agg.add(f)
		}
	}
	return agg.finish(), nil
}

// flowAggregator folds raw flow events into deduplicated FlowEdges. It is
// separated from the gRPC plumbing so aggregation semantics are testable
// with fabricated flows.
type flowAggregator struct {
	capture *FlowCapture
	resolve flowResolver
	edges   map[flowEdgeKey]*flowEdgeAgg
}

type flowEdgeKey struct {
	src, dst   FlowPeer
	port       string
	verdict    string
	dropReason string
}

type flowEdgeAgg struct {
	count    int
	lastSeen time.Time
}

func newFlowAggregator(opts FlowOptions, now time.Time, resolve flowResolver) *flowAggregator {
	return &flowAggregator{
		capture: &FlowCapture{
			Status: "ok",
			Server: opts.Server,
			Window: opts.Window.String(),
			From:   now.Add(-opts.Window),
			To:     now,
		},
		resolve: resolve,
		edges:   map[flowEdgeKey]*flowEdgeAgg{},
	}
}

func (a *flowAggregator) add(f *flowpb.Flow) {
	a.capture.FlowsSeen++
	if t := f.GetTime().AsTime(); a.capture.OldestFlow.IsZero() || t.Before(a.capture.OldestFlow) {
		a.capture.OldestFlow = t
	}

	src, srcIsWorkload := peerFromEndpoint(f.GetSource(), a.resolve)
	dst, dstIsWorkload := peerFromEndpoint(f.GetDestination(), a.resolve)
	// Noise gates: flows touching no cluster workload at all (LAN broadcast
	// chatter seen on node NICs) and Cilium's own health-check traffic say
	// nothing about the policy topology.
	if (!srcIsWorkload && !dstIsWorkload) || src.Entity == "health" || dst.Entity == "health" {
		a.capture.Skipped++
		return
	}

	key := flowEdgeKey{
		src:     src,
		dst:     dst,
		port:    flowPort(f.GetL4()),
		verdict: f.GetVerdict().String(),
	}
	if f.GetVerdict() == flowpb.Verdict_DROPPED {
		key.dropReason = f.GetDropReasonDesc().String()
	}
	e, ok := a.edges[key]
	if !ok {
		e = &flowEdgeAgg{}
		a.edges[key] = e
	}
	e.count++
	if t := f.GetTime().AsTime(); t.After(e.lastSeen) {
		e.lastSeen = t
	}
}

func (a *flowAggregator) finish() *FlowCapture {
	out := make([]FlowEdge, 0, len(a.edges))
	for k, v := range a.edges {
		out = append(out, FlowEdge{
			Src:        k.src,
			Dst:        k.dst,
			Port:       k.port,
			Verdict:    k.verdict,
			DropReason: k.dropReason,
			Count:      v.count,
			LastSeen:   v.lastSeen,
		})
	}
	slices.SortFunc(out, func(x, y FlowEdge) int {
		return cmp.Or(
			comparePeer(x.Src, y.Src),
			comparePeer(x.Dst, y.Dst),
			cmp.Compare(x.Port, y.Port),
			cmp.Compare(x.Verdict, y.Verdict),
			cmp.Compare(x.DropReason, y.DropReason),
		)
	})
	a.capture.Edges = out
	return a.capture
}

func comparePeer(a, b FlowPeer) int {
	return cmp.Or(
		cmp.Compare(a.Entity, b.Entity),
		cmp.Compare(a.Namespace, b.Namespace),
		cmp.Compare(a.Kind, b.Kind),
		cmp.Compare(a.Name, b.Name),
	)
}

// peerFromEndpoint maps a Hubble endpoint to a FlowPeer and reports whether
// it is a cluster workload. Identity resolution order:
//  1. Hubble's own workload metadata — authoritative, present even for pods
//     that died since, but only populated for endpoints local to the
//     observing node;
//  2. the collector's live-pod index (same ownerReference resolution the
//     policy map uses);
//  3. the bare pod name, Kind "Pod";
//  4. for non-pod peers, the highest-priority reserved identity label.
func peerFromEndpoint(ep *flowpb.Endpoint, resolve flowResolver) (FlowPeer, bool) {
	if ep == nil {
		return FlowPeer{Entity: "unknown"}, false
	}
	if ns := ep.GetNamespace(); ns != "" {
		if wls := ep.GetWorkloads(); len(wls) > 0 {
			return FlowPeer{Namespace: ns, Name: wls[0].GetName(), Kind: wls[0].GetKind()}, true
		}
		if pod := ep.GetPodName(); pod != "" {
			if resolve != nil {
				if kind, name, ok := resolve(ns, pod); ok {
					return FlowPeer{Namespace: ns, Name: name, Kind: kind}, true
				}
			}
			return FlowPeer{Namespace: ns, Name: pod, Kind: "Pod"}, true
		}
		return FlowPeer{Namespace: ns}, true
	}
	reserved := map[string]bool{}
	for _, l := range ep.GetLabels() {
		if name, ok := strings.CutPrefix(l, "reserved:"); ok {
			reserved[name] = true
		}
	}
	for _, name := range entityPriority {
		if reserved[name] {
			return FlowPeer{Entity: name}, false
		}
	}
	return FlowPeer{Entity: "unknown"}, false
}

// flowPort renders the L4 destination as the same "port/PROTO" strings the
// policy graph uses, so observed edges join onto declared edges cleanly.
func flowPort(l4 *flowpb.Layer4) string {
	switch p := l4.GetProtocol().(type) {
	case *flowpb.Layer4_TCP:
		return fmt.Sprintf("%d/TCP", p.TCP.GetDestinationPort())
	case *flowpb.Layer4_UDP:
		return fmt.Sprintf("%d/UDP", p.UDP.GetDestinationPort())
	case *flowpb.Layer4_SCTP:
		return fmt.Sprintf("%d/SCTP", p.SCTP.GetDestinationPort())
	case *flowpb.Layer4_ICMPv4, *flowpb.Layer4_ICMPv6:
		return "icmp"
	default:
		return ""
	}
}
