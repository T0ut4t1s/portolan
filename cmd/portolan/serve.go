// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/T0ut4t1s/portolan/pkg/auth"
	"github.com/T0ut4t1s/portolan/pkg/graph"
	"github.com/T0ut4t1s/portolan/pkg/render"
	"github.com/T0ut4t1s/portolan/pkg/snapshot"
	"github.com/T0ut4t1s/portolan/pkg/whatif"
)

// server holds the latest successful collection results. Collection failures
// never evict the last good state — the dashboard keeps serving it and
// /healthz keeps reporting the staleness.
type server struct {
	mu       sync.RWMutex
	html     []byte
	snapJSON []byte
	audit    []byte
	brief    []byte
	// snap is the latest snapshot object, kept for what-if simulation.
	// Collections replace it wholesale and never mutate it in place, so a
	// handler may take the pointer under RLock and compute without the lock.
	snap    *snapshot.Snapshot
	lastOK  time.Time
	lastErr string
	// whatifMu serializes simulations: each one is a multi-second
	// full-CPU sweep, and piling them up helps nobody.
	whatifMu sync.Mutex
}

// envOr returns environment variable k if set, otherwise def.
func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// buildAuth resolves the auth flags/env into an Authenticator, failing closed
// on any misconfiguration (mode none returns a pass-through).
func buildAuth(mode, sessionKey, usersFile string, ttl time.Duration, insecure bool) (*auth.Authenticator, error) {
	cfg := auth.Config{Mode: auth.Mode(mode), SessionTTL: ttl, Insecure: insecure}
	if cfg.Mode == auth.ModeLocal {
		if sessionKey == "" {
			return nil, errors.New("auth: local mode requires --auth-session-key (or PORTOLAN_AUTH_SESSION_KEY)")
		}
		key, err := auth.DecodeKey(sessionKey)
		if err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}
		cfg.SessionKey = key
		if usersFile == "" {
			return nil, errors.New("auth: local mode requires --auth-users-file (or PORTOLAN_AUTH_USERS_FILE)")
		}
		f, err := os.Open(usersFile)
		if err != nil {
			return nil, fmt.Errorf("auth: opening users file: %w", err)
		}
		defer f.Close()
		users, err := auth.LoadUsers(f)
		if err != nil {
			return nil, fmt.Errorf("auth: users file: %w", err)
		}
		cfg.Users = users
	}
	return auth.New(cfg)
}

func cmdServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	interval := fs.Duration("interval", 15*time.Minute, "collection interval")
	collectTimeout := fs.Duration("collect-timeout", 0, "per-collection deadline (0: use the interval) — a blackholed kube-API call can otherwise stall all future collections")
	dataDir := fs.String("data", "", "directory for snapshot history (empty: no history kept)")
	keep := fs.Int("keep", 500, "snapshots to retain in the data directory")
	clusterName := fs.String("cluster-name", "", "cluster label recorded in snapshots")
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig (default: standard loading rules, then in-cluster)")
	flowWindow := fs.Duration("flows", 0, "capture Hubble flow observations over this look-back window each cycle, e.g. 15m (0: off)")
	hubbleServer := fs.String("hubble-server", defaultHubbleServer, "Hubble Relay address (plaintext gRPC)")
	// Auth (opt-in; default none). Flags default from env so secrets can be
	// injected as env vars in Kubernetes without appearing on the command line.
	authMode := fs.String("auth-mode", envOr("PORTOLAN_AUTH_MODE", "none"), "authentication: none | local")
	authSessionKey := fs.String("auth-session-key", os.Getenv("PORTOLAN_AUTH_SESSION_KEY"), "32-byte session key (base64 or hex); required when auth is enabled")
	authUsersFile := fs.String("auth-users-file", os.Getenv("PORTOLAN_AUTH_USERS_FILE"), "htpasswd-style users file (username:bcrypthash per line) for local auth")
	authSessionTTL := fs.Duration("auth-session-ttl", 12*time.Hour, "session lifetime")
	authInsecure := fs.Bool("auth-cookie-insecure", false, "drop the Secure cookie flag (plain-HTTP testing only)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Build the authenticator up front so a misconfiguration fails closed
	// before the server ever binds — a half-configured auth must never serve
	// the map open.
	authn, err := buildAuth(*authMode, *authSessionKey, *authUsersFile, *authSessionTTL, *authInsecure)
	if err != nil {
		return err
	}

	cfg, err := restConfig(*kubeconfig)
	if err != nil {
		return err
	}
	col, err := snapshot.NewCollector(cfg)
	if err != nil {
		return err
	}
	if *dataDir != "" {
		if err := os.MkdirAll(*dataDir, 0o755); err != nil {
			return err
		}
	}

	// Each cycle gets its own deadline so one hung List (a blackholed
	// kube-API endpoint has no transport timeout of its own) can't wedge the
	// collector forever — it fails this cycle, /healthz goes stale, and the
	// next tick tries again.
	cycleTimeout := *collectTimeout
	if cycleTimeout <= 0 {
		cycleTimeout = *interval
	}

	// Fixed for the life of the process: every viewer gets the same bytes, so
	// this can only carry deployment facts, never anything per-user.
	ui := render.UI{Auth: authn.Enabled()}

	s := &server{}
	collect := func() {
		cctx, cancel := context.WithTimeout(ctx, cycleTimeout)
		defer cancel()
		snap, err := col.Collect(cctx, snapshot.FlowOptions{Server: *hubbleServer, Window: *flowWindow})
		if err != nil {
			s.mu.Lock()
			s.lastErr = err.Error()
			s.mu.Unlock()
			fmt.Fprintf(os.Stderr, "collect failed: %v\n", err)
			return
		}
		snap.Cluster = *clusterName
		snap.Tool = snapshot.ToolInfo{Name: snapshot.ToolName, Version: version}

		g := graph.Build(snap)
		a := graph.ComputeAudit(g)
		html, err := render.HTML(g, ui)
		if err != nil {
			s.mu.Lock()
			s.lastErr = err.Error()
			s.mu.Unlock()
			fmt.Fprintf(os.Stderr, "render failed: %v\n", err)
			return
		}
		snapJSON, _ := json.MarshalIndent(snap, "", "  ")
		auditJSON, _ := json.MarshalIndent(a, "", "  ")

		s.mu.Lock()
		s.html = html
		s.snapJSON = snapJSON
		s.audit = auditJSON
		s.brief = graph.Brief(g, a)
		s.snap = snap
		s.lastOK = time.Now().UTC()
		s.lastErr = ""
		s.mu.Unlock()

		if *dataDir != "" {
			name := "snapshot-" + snap.TakenAt.Format("20060102T150405Z") + ".json"
			if err := os.WriteFile(filepath.Join(*dataDir, name), append(snapJSON, '\n'), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "writing %s: %v\n", name, err)
			}
			prune(*dataDir, *keep)
		}
		fmt.Fprintf(os.Stderr, "collected: %d namespaces, %d workloads, %d policies, %d edges\n",
			len(snap.Namespaces), len(snap.Workloads), len(snap.Policies), g.Stats.Edges)
		if snap.Flows != nil {
			if snap.Flows.Status == "ok" {
				fmt.Fprintf(os.Stderr, "flows: %d edges from %d events over %s\n",
					len(snap.Flows.Edges), snap.Flows.FlowsSeen, snap.Flows.Window)
			} else {
				fmt.Fprintf(os.Stderr, "flow capture failed (snapshot still valid): %s\n", snap.Flows.Reason)
			}
		}
	}

	// The listener comes up first (below); the first collection runs inside
	// this goroutine. Otherwise probes hit a refused connection during the
	// initial collect — exactly while the kube-API may be degraded — and the
	// orchestrator restart-loops the pod instead of waiting.
	go func() {
		collect()
		t := time.NewTicker(*interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				collect()
			}
		}
	}()

	mux := http.NewServeMux()
	serveBytes := func(get func() []byte, contentType string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			data := get()
			if data == nil {
				http.Error(w, "no successful collection yet", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", contentType)
			w.Write(data)
		}
	}
	rd := func(f func(*server) []byte) func() []byte {
		return func() []byte { s.mu.RLock(); defer s.mu.RUnlock(); return f(s) }
	}
	mux.HandleFunc("GET /{$}", serveBytes(rd(func(s *server) []byte { return s.html }), "text/html; charset=utf-8"))
	mux.HandleFunc("GET /snapshot.json", serveBytes(rd(func(s *server) []byte { return s.snapJSON }), "application/json"))
	mux.HandleFunc("GET /audit.json", serveBytes(rd(func(s *server) []byte { return s.audit }), "application/json"))
	mux.HandleFunc("GET /brief.md", serveBytes(rd(func(s *server) []byte { return s.brief }), "text/markdown; charset=utf-8"))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		if s.lastOK.IsZero() {
			http.Error(w, "no successful collection yet: "+s.lastErr, http.StatusServiceUnavailable)
			return
		}
		// Serving indefinitely-old data is the worst failure mode: fail the
		// probe once collections have gone quiet for several cycles so a
		// liveness check restarts the pod instead of trusting stale topology.
		if age := time.Since(s.lastOK); age > stalenessCycles*(*interval) {
			http.Error(w, fmt.Sprintf("stale: last good collection %s ago (> %d cycles); last error: %s",
				age.Round(time.Second), stalenessCycles, s.lastErr), http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintf(w, "ok — last collection %s\n", s.lastOK.Format(time.RFC3339))
	})
	if *dataDir != "" {
		mux.HandleFunc("GET /snapshots/", historyHandler(*dataDir))
	}
	mux.HandleFunc("POST /api/whatif", s.whatifHandler)
	authn.Register(mux) // /login, /logout (no-op in mode none)

	// The gate wraps every route: /healthz and the auth endpoints stay public,
	// everything else requires a valid session.
	srv := &http.Server{Addr: *addr, Handler: authn.Middleware(mux), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	fmt.Fprintf(os.Stderr, "serving on %s (interval %s)\n", *addr, *interval)
	if authn.Enabled() {
		fmt.Fprintf(os.Stderr, "auth: %s mode enabled\n", *authMode)
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// whatifRequest is the panel's simulation payload: simplified rules and
// policy deletions by provenance key — never raw manifests. The server
// derives real CNPs from the rules, so the input surface stays small and
// structured.
type whatifRequest struct {
	Rules []whatif.SimpleRule `json:"rules"`
	// Deletes name existing snapshot policies to remove, in provenance
	// form: Kind/namespace/name (or Kind/name for cluster-scoped).
	Deletes []string `json:"deletes"`
}

type whatifResponse struct {
	Result *whatif.Result `json:"result"`
	// Manifests are the CNPs that were simulated — identical objects, so
	// what the generate button shows is exactly what the verdicts cover.
	Manifests []whatif.Manifest `json:"manifests"`
}

const maxWhatifRules = 20

// stalenessCycles is how many collection intervals may elapse without a fresh
// success before /healthz fails — matches the map's own "stale" threshold.
const stalenessCycles = 3

func (s *server) whatifHandler(w http.ResponseWriter, r *http.Request) {
	var req whatifRequest
	body := http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if n := len(req.Rules) + len(req.Deletes); n == 0 || n > maxWhatifRules {
		http.Error(w, fmt.Sprintf("need 1-%d rules/deletes", maxWhatifRules), http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	snap := s.snap
	s.mu.RUnlock()
	if snap == nil {
		http.Error(w, "no successful collection yet", http.StatusServiceUnavailable)
		return
	}

	var pols []snapshot.Policy
	var mans []whatif.Manifest
	if len(req.Rules) > 0 {
		var err error
		pols, mans, err = whatif.GenerateCNPs(snap, req.Rules)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	s.whatifMu.Lock()
	res, err := whatif.Compute(snap, whatif.Changes{Apply: pols, Delete: req.Deletes})
	s.whatifMu.Unlock()
	if err != nil {
		// A delete naming no snapshot policy, or a change set that resolves to
		// nothing, is the caller's mistake, not a server fault.
		code := http.StatusInternalServerError
		if errors.Is(err, whatif.ErrNoSuchPolicy) || errors.Is(err, whatif.ErrEmptyChangeSet) {
			code = http.StatusBadRequest
		}
		http.Error(w, "simulation failed: "+err.Error(), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(whatifResponse{Result: res, Manifests: mans})
}

// historyHandler lists and serves the snapshot archive.
func historyHandler(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/snapshots/")
		if name == "" {
			names, _ := snapshotFiles(dir)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(names)
			return
		}
		// filepath.Base defuses any traversal attempt.
		clean := filepath.Base(name)
		if !strings.HasPrefix(clean, "snapshot-") || !strings.HasSuffix(clean, ".json") {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(dir, clean))
	}
}

func snapshotFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "snapshot-") && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	return names, nil
}

// prune keeps the newest keep snapshots (names sort chronologically).
func prune(dir string, keep int) {
	names, err := snapshotFiles(dir)
	if err != nil || len(names) <= keep {
		return
	}
	for _, name := range names[:len(names)-keep] {
		os.Remove(filepath.Join(dir, name))
	}
}
