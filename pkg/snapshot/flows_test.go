// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package snapshot

import (
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func testFlow(t time.Time, src, dst *flowpb.Endpoint, port uint32, verdict flowpb.Verdict) *flowpb.Flow {
	f := &flowpb.Flow{
		Time:        timestamppb.New(t),
		Source:      src,
		Destination: dst,
		Verdict:     verdict,
		L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{
			TCP: &flowpb.TCP{DestinationPort: port},
		}},
	}
	if verdict == flowpb.Verdict_DROPPED {
		f.DropReasonDesc = flowpb.DropReason_POLICY_DENIED
	}
	return f
}

func podEP(ns, pod string, workloads ...*flowpb.Workload) *flowpb.Endpoint {
	return &flowpb.Endpoint{Namespace: ns, PodName: pod, Workloads: workloads}
}

func reservedEP(labels ...string) *flowpb.Endpoint {
	return &flowpb.Endpoint{Labels: labels}
}

func TestPeerFromEndpoint(t *testing.T) {
	resolve := func(ns, pod string) (string, string, bool) {
		if ns == "media" && pod == "sonarr-abc12-x9z" {
			return "Deployment", "sonarr", true
		}
		return "", "", false
	}

	cases := []struct {
		name       string
		ep         *flowpb.Endpoint
		want       FlowPeer
		isWorkload bool
	}{
		{
			// Hubble's own workload metadata wins even when the resolver
			// would also match — it is authoritative for dead pods too.
			name:       "hubble workloads field",
			ep:         podEP("ingress-system", "traefik-546d9759d9-qp2qd", &flowpb.Workload{Name: "traefik", Kind: "Deployment"}),
			want:       FlowPeer{Namespace: "ingress-system", Name: "traefik", Kind: "Deployment"},
			isWorkload: true,
		},
		{
			name:       "resolver fallback",
			ep:         podEP("media", "sonarr-abc12-x9z"),
			want:       FlowPeer{Namespace: "media", Name: "sonarr", Kind: "Deployment"},
			isWorkload: true,
		},
		{
			name:       "bare pod fallback",
			ep:         podEP("media", "gone-pod-xyz"),
			want:       FlowPeer{Namespace: "media", Name: "gone-pod-xyz", Kind: "Pod"},
			isWorkload: true,
		},
		{
			// host+kube-apiserver both present: most specific wins.
			name:       "reserved identity priority",
			ep:         reservedEP("reserved:host", "reserved:kube-apiserver"),
			want:       FlowPeer{Entity: "kube-apiserver"},
			isWorkload: false,
		},
		{
			// world peers may also carry cidr: labels; those are not reserved.
			name:       "world with cidr label",
			ep:         reservedEP("cidr:192.168.0.0/16", "reserved:world"),
			want:       FlowPeer{Entity: "world"},
			isWorkload: false,
		},
		{
			name:       "nil endpoint",
			ep:         nil,
			want:       FlowPeer{Entity: "unknown"},
			isWorkload: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, isWL := peerFromEndpoint(tc.ep, resolve)
			if got != tc.want || isWL != tc.isWorkload {
				t.Errorf("got %+v (workload=%v), want %+v (workload=%v)", got, isWL, tc.want, tc.isWorkload)
			}
		})
	}
}

func TestFlowAggregator(t *testing.T) {
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	agg := newFlowAggregator(FlowOptions{Server: "test:80", Window: 15 * time.Minute}, now, nil)

	jellyfin := podEP("jellyfin", "jellyfin-abc-def", &flowpb.Workload{Name: "jellyfin", Kind: "Deployment"})
	traefik := podEP("ingress-system", "traefik-xyz-123", &flowpb.Workload{Name: "traefik", Kind: "Deployment"})

	// Three identical forwarded flows aggregate to one edge, count 3,
	// lastSeen = the latest of the three.
	agg.add(testFlow(now.Add(-10*time.Minute), traefik, jellyfin, 8096, flowpb.Verdict_FORWARDED))
	agg.add(testFlow(now.Add(-2*time.Minute), traefik, jellyfin, 8096, flowpb.Verdict_FORWARDED))
	agg.add(testFlow(now.Add(-5*time.Minute), traefik, jellyfin, 8096, flowpb.Verdict_FORWARDED))
	// Same pair, same port, DROPPED: separate edge (verdict in the key).
	agg.add(testFlow(now.Add(-1*time.Minute), traefik, jellyfin, 8096, flowpb.Verdict_DROPPED))
	// world→world noise: skipped, not an edge.
	agg.add(testFlow(now.Add(-3*time.Minute), reservedEP("reserved:world"), reservedEP("reserved:world"), 6667, flowpb.Verdict_DROPPED))
	// health-check traffic: skipped.
	agg.add(testFlow(now.Add(-3*time.Minute), reservedEP("reserved:remote-node"), reservedEP("reserved:health"), 4240, flowpb.Verdict_FORWARDED))
	// world→workload: kept (one side is a workload).
	agg.add(testFlow(now.Add(-4*time.Minute), reservedEP("reserved:world"), traefik, 443, flowpb.Verdict_FORWARDED))

	fc := agg.finish()

	if fc.FlowsSeen != 7 {
		t.Errorf("FlowsSeen = %d, want 7", fc.FlowsSeen)
	}
	if fc.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2", fc.Skipped)
	}
	if len(fc.Edges) != 3 {
		t.Fatalf("edges = %d, want 3: %+v", len(fc.Edges), fc.Edges)
	}
	if got := fc.OldestFlow; !got.Equal(now.Add(-10 * time.Minute)) {
		t.Errorf("OldestFlow = %v, want %v", got, now.Add(-10*time.Minute))
	}

	// Sorted: entity src ("" < "world" sorts workloads... entities compare
	// first, so entity-less peers come before entity peers).
	var fwd, drop *FlowEdge
	for i := range fc.Edges {
		e := &fc.Edges[i]
		if e.Dst.Name == "jellyfin" && e.Verdict == "FORWARDED" {
			fwd = e
		}
		if e.Dst.Name == "jellyfin" && e.Verdict == "DROPPED" {
			drop = e
		}
	}
	if fwd == nil || fwd.Count != 3 {
		t.Fatalf("forwarded traefik→jellyfin edge: %+v", fwd)
	}
	if !fwd.LastSeen.Equal(now.Add(-2 * time.Minute)) {
		t.Errorf("LastSeen = %v, want %v", fwd.LastSeen, now.Add(-2*time.Minute))
	}
	if fwd.Port != "8096/TCP" {
		t.Errorf("Port = %q, want 8096/TCP", fwd.Port)
	}
	if drop == nil || drop.DropReason != "POLICY_DENIED" {
		t.Fatalf("dropped edge should carry POLICY_DENIED: %+v", drop)
	}
	if fwd.DropReason != "" {
		t.Errorf("forwarded edge must not carry a drop reason: %q", fwd.DropReason)
	}
}

func TestFlowAggregatorEmptyEdgesMarshalsAsArray(t *testing.T) {
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	fc := newFlowAggregator(FlowOptions{Window: time.Minute}, now, nil).finish()
	if fc.Edges == nil {
		t.Fatal("Edges must be non-nil so JSON renders [] not null")
	}
}

func TestFlowPortShapes(t *testing.T) {
	udp := &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 53}}}
	if got := flowPort(udp); got != "53/UDP" {
		t.Errorf("udp = %q", got)
	}
	icmp := &flowpb.Layer4{Protocol: &flowpb.Layer4_ICMPv4{ICMPv4: &flowpb.ICMPv4{}}}
	if got := flowPort(icmp); got != "icmp" {
		t.Errorf("icmp = %q", got)
	}
	if got := flowPort(nil); got != "" {
		t.Errorf("nil L4 = %q", got)
	}
}
