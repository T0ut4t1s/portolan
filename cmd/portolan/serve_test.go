// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package main

import (
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
