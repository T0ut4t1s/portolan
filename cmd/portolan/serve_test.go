// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/T0ut4t1s/portolan/pkg/flowstore"
	"github.com/T0ut4t1s/portolan/pkg/graph"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

func testServer() *server {
	return &server{snap: &snapshot.Snapshot{
		Namespaces: []snapshot.Namespace{
			{Name: "media", Labels: map[string]string{"kubernetes.io/metadata.name": "media"}},
			{Name: "qbit", Labels: map[string]string{"kubernetes.io/metadata.name": "qbit"}},
		},
		Workloads: []snapshot.Workload{
			{Namespace: "media", Name: "sonarr", Kind: "Deployment", Labels: map[string]string{"app.kubernetes.io/name": "sonarr"}, Replicas: 1},
			{Namespace: "qbit", Name: "qbittorrent", Kind: "Deployment", Labels: map[string]string{"app.kubernetes.io/name": "qbittorrent"}, Replicas: 1},
		},
	}}
}

func postWhatif(t *testing.T, s *server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/whatif", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.whatifHandler(rec, req)
	return rec
}

// The handler must distinguish caller mistakes (400) from server faults (500).
func TestWhatifHandlerStatusCodes(t *testing.T) {
	s := testServer()
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"valid rule", `{"rules":[{"from":"media/sonarr","to":"qbit/qbittorrent","ports":["9090"]}]}`, http.StatusOK},
		{"empty", `{}`, http.StatusBadRequest},
		{"malformed json", `{`, http.StatusBadRequest},
		{"delete ghost", `{"deletes":["CiliumNetworkPolicy/media/ghost"]}`, http.StatusBadRequest},
		{"entity egress-only no-op", `{"rules":[{"from":"entity:world","to":"qbit/qbittorrent","sides":"egress"}]}`, http.StatusBadRequest},
	} {
		if got := postWhatif(t, s, tc.body).Code; got != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// No successful collection yet → 503, never a nil-snapshot panic.
func TestWhatifHandlerNoSnapshot(t *testing.T) {
	s := &server{}
	if got := postWhatif(t, s, `{"deletes":["x"]}`).Code; got != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", got)
	}
}

// --- capture window ---------------------------------------------------------

// fakeFlows stands in for the accumulated store: it records the window it was
// asked for, so the tests can assert what the handler actually requested.
type fakeFlows struct {
	asked time.Duration
	err   error
}

func (f *fakeFlows) Capture(_ context.Context, w time.Duration) (*snapshot.FlowCapture, error) {
	f.asked = w
	if f.err != nil {
		return nil, f.err
	}
	return &snapshot.FlowCapture{
		Status: "ok", Source: snapshot.FlowSourceStream,
		Window: snapshot.ShortDur(w), Coverage: 1,
		Edges: []snapshot.FlowEdge{{
			Src:     snapshot.FlowPeer{Namespace: "media", Name: "sonarr", Kind: "Deployment"},
			Dst:     snapshot.FlowPeer{Namespace: "qbit", Name: "qbittorrent", Kind: "Deployment"},
			Port:    "8080/TCP",
			Verdict: "FORWARDED", Count: 3,
		}},
	}, nil
}

func getFlows(t *testing.T, s *server, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/flows"+query, nil)
	rec := httptest.NewRecorder()
	s.flowsHandler(rec, req)
	return rec
}

// The control sends the same spelling the server hands back ("7d", not
// "168h0m0s"). If those two ever drift the button silently stops looking
// selected, so pin the round-trip.
func TestWindowStringRoundTrips(t *testing.T) {
	for _, s := range []string{"15m", "1h", "6h", "24h", "7d"} {
		d, err := snapshot.ParseWindow(s)
		if err != nil {
			t.Fatalf("ParseWindow(%q): %v", s, err)
		}
		if got := snapshot.ShortDur(d); got != s {
			t.Errorf("round trip %q -> %s -> %q; the map's buttons would stop matching", s, d, got)
		}
	}
}

func TestFlowsHandler(t *testing.T) {
	t.Run("off without --flows", func(t *testing.T) {
		if rec := getFlows(t, testServer(), ""); rec.Code != http.StatusNotFound {
			t.Errorf("code = %d, want 404 when flow observation is off", rec.Code)
		}
	})

	t.Run("serves the requested window", func(t *testing.T) {
		s := testServer()
		f := &fakeFlows{}
		s.flows, s.flowWindow = f, 15*time.Minute

		rec := getFlows(t, s, "?window=24h")
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200: %s", rec.Code, rec.Body)
		}
		if f.asked != 24*time.Hour {
			t.Errorf("store was asked for %s, want 24h — the control's choice must reach the store", f.asked)
		}
		var ov graph.FlowOverlay
		if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
			t.Fatalf("decoding overlay: %v", err)
		}
		if ov.Window != "24h" {
			t.Errorf("window = %q, want %q echoed back verbatim", ov.Window, "24h")
		}
		if len(ov.Observed) != 1 || ov.Observed[0].Src != "media/sonarr" {
			t.Errorf("overlay did not join onto the graph's node ids: %+v", ov.Observed)
		}
	})

	t.Run("falls back to the configured window", func(t *testing.T) {
		s := testServer()
		f := &fakeFlows{}
		s.flows, s.flowWindow = f, 6*time.Hour
		if rec := getFlows(t, s, ""); rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", rec.Code)
		}
		if f.asked != 6*time.Hour {
			t.Errorf("asked for %s, want the configured 6h", f.asked)
		}
	})

	t.Run("rejects bad and oversized windows", func(t *testing.T) {
		for _, q := range []string{"?window=banana", "?window=-5m", "?window=0s", "?window=30d"} {
			s := testServer()
			s.flows, s.flowWindow = &fakeFlows{}, 15*time.Minute
			if rec := getFlows(t, s, q); rec.Code != http.StatusBadRequest {
				t.Errorf("%s: code = %d, want 400", q, rec.Code)
			}
		}
	})

	// A store still warming up is the normal state for the first half-minute
	// after start — say so, rather than 500 or (worse) an empty overlay that
	// reads as "no traffic".
	t.Run("warming up is not a fault", func(t *testing.T) {
		s := testServer()
		s.flows, s.flowWindow = &fakeFlows{err: flowstore.ErrNoObservations}, 15*time.Minute
		rec := getFlows(t, s, "")
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("code = %d, want 503 while the stream warms up", rec.Code)
		}
	})
}
