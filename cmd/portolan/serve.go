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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/T0ut4t1s/portolan/pkg/auth"
	"github.com/T0ut4t1s/portolan/pkg/flowstore"
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

	// flows is the accumulated observation store (nil when --flows is off),
	// and flowWindow the look-back the map opens on. The store is what lets
	// the capture-window control mean anything: re-asking Hubble would just
	// return the same handful of seconds whatever window was picked.
	flows      snapshot.FlowSource
	flowWindow time.Duration
}

// envOr returns environment variable k if set, otherwise def.
func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// authFlags is the auth surface of `serve`. Every flag defaults from an
// environment variable so Kubernetes can inject the secrets without them ever
// appearing on the command line (where any pod in the namespace could read them
// out of /proc).
type authFlags struct {
	mode       string
	sessionKey string
	usersFile  string
	sessionTTL time.Duration
	insecure   bool

	oidcIssuer         string
	oidcBackchannelURL string
	oidcClientID       string
	oidcClientSecret   string
	oidcRedirectURL    string
	oidcScopes         string
	oidcGroupsClaim    string
	oidcAllowedGroups  string
	oidcAllowedEmails  string
	oidcAllowAny       bool
	oidcProviderName   string
	oidcAutoRedirect   bool
}

func registerAuthFlags(fs *flag.FlagSet) *authFlags {
	f := &authFlags{}
	fs.StringVar(&f.mode, "auth-mode", envOr("PORTOLAN_AUTH_MODE", "none"), "sign-in methods, comma-separated: none | local | oidc | oidc,local")
	fs.StringVar(&f.sessionKey, "auth-session-key", os.Getenv("PORTOLAN_AUTH_SESSION_KEY"), "32-byte session key (base64 or hex); required when auth is enabled")
	fs.StringVar(&f.usersFile, "auth-users-file", os.Getenv("PORTOLAN_AUTH_USERS_FILE"), "htpasswd-style users file (username:bcrypthash per line) for local auth")
	fs.DurationVar(&f.sessionTTL, "auth-session-ttl", 12*time.Hour, "session lifetime")
	fs.BoolVar(&f.insecure, "auth-cookie-insecure", false, "drop the Secure cookie flag (plain-HTTP testing only)")

	fs.StringVar(&f.oidcIssuer, "auth-oidc-issuer", os.Getenv("PORTOLAN_AUTH_OIDC_ISSUER"), "OIDC issuer URL, exactly as the provider states it in the iss claim")
	fs.StringVar(&f.oidcBackchannelURL, "auth-oidc-backchannel-url", os.Getenv("PORTOLAN_AUTH_OIDC_BACKCHANNEL_URL"), "dial this address (scheme://host, e.g. an in-cluster Service) for discovery, keys and the code exchange instead of the issuer's host; the request still carries the issuer's Host header, so URLs and token issuers stay public")
	fs.StringVar(&f.oidcClientID, "auth-oidc-client-id", os.Getenv("PORTOLAN_AUTH_OIDC_CLIENT_ID"), "OIDC client ID")
	fs.StringVar(&f.oidcClientSecret, "auth-oidc-client-secret", os.Getenv("PORTOLAN_AUTH_OIDC_CLIENT_SECRET"), "OIDC client secret (prefer the env var)")
	fs.StringVar(&f.oidcRedirectURL, "auth-oidc-redirect-url", os.Getenv("PORTOLAN_AUTH_OIDC_REDIRECT_URL"), "absolute callback URL registered with the provider, e.g. https://portolan.example.com/auth/callback")
	fs.StringVar(&f.oidcScopes, "auth-oidc-scopes", envOr("PORTOLAN_AUTH_OIDC_SCOPES", "openid,profile,email"), "comma-separated scopes to request")
	fs.StringVar(&f.oidcGroupsClaim, "auth-oidc-groups-claim", envOr("PORTOLAN_AUTH_OIDC_GROUPS_CLAIM", "groups"), "ID-token claim holding the user's groups")
	fs.StringVar(&f.oidcAllowedGroups, "auth-oidc-allowed-groups", os.Getenv("PORTOLAN_AUTH_OIDC_ALLOWED_GROUPS"), "comma-separated groups permitted to view the map")
	fs.StringVar(&f.oidcAllowedEmails, "auth-oidc-allowed-emails", os.Getenv("PORTOLAN_AUTH_OIDC_ALLOWED_EMAILS"), "comma-separated email addresses permitted to view the map")
	fs.BoolVar(&f.oidcAllowAny, "auth-oidc-allow-any-authenticated", envBool("PORTOLAN_AUTH_OIDC_ALLOW_ANY_AUTHENTICATED"), "admit every account the provider authenticates (no allowlist)")
	fs.StringVar(&f.oidcProviderName, "auth-oidc-provider-name", os.Getenv("PORTOLAN_AUTH_OIDC_PROVIDER_NAME"), "name shown on the sign-in button (default: the issuer's host)")
	fs.BoolVar(&f.oidcAutoRedirect, "auth-oidc-auto-redirect", envBool("PORTOLAN_AUTH_OIDC_AUTO_REDIRECT"), "skip the login page and go straight to the provider (cannot be combined with local login)")
	return f
}

// build resolves the flags into an Authenticator, failing closed on any
// misconfiguration (mode none returns a pass-through).
func (f *authFlags) build(ctx context.Context) (*auth.Authenticator, error) {
	var modes []auth.Mode
	for _, m := range splitList(f.mode) {
		modes = append(modes, auth.Mode(m))
	}
	cfg := auth.Config{Modes: modes, SessionTTL: f.sessionTTL, Insecure: f.insecure}
	if len(modes) == 0 || slices.Contains(modes, auth.ModeNone) {
		return auth.New(ctx, cfg) // no auth; auth.New rejects none-plus-something
	}

	// Every authenticating mode issues the same sealed session cookie, so any of
	// them needs the key.
	if f.sessionKey == "" {
		return nil, errors.New("auth: --auth-session-key (or PORTOLAN_AUTH_SESSION_KEY) is required when auth is enabled")
	}
	key, err := auth.DecodeKey(f.sessionKey)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	cfg.SessionKey = key

	if slices.Contains(modes, auth.ModeLocal) {
		if f.usersFile == "" {
			return nil, errors.New("auth: local mode requires --auth-users-file (or PORTOLAN_AUTH_USERS_FILE)")
		}
		file, err := os.Open(f.usersFile)
		if err != nil {
			return nil, fmt.Errorf("auth: opening users file: %w", err)
		}
		defer file.Close()
		users, err := auth.LoadUsers(file)
		if err != nil {
			return nil, fmt.Errorf("auth: users file: %w", err)
		}
		cfg.Users = users
	}
	if slices.Contains(modes, auth.ModeOIDC) {
		cfg.OIDC = &auth.OIDCConfig{
			Issuer:                f.oidcIssuer,
			BackchannelURL:        f.oidcBackchannelURL,
			ClientID:              f.oidcClientID,
			ClientSecret:          f.oidcClientSecret,
			RedirectURL:           f.oidcRedirectURL,
			Scopes:                splitList(f.oidcScopes),
			GroupsClaim:           f.oidcGroupsClaim,
			AllowedGroups:         splitList(f.oidcAllowedGroups),
			AllowedEmails:         splitList(f.oidcAllowedEmails),
			AllowAnyAuthenticated: f.oidcAllowAny,
			ProviderName:          f.oidcProviderName,
			AutoRedirect:          f.oidcAutoRedirect,
		}
	}
	return auth.New(ctx, cfg)
}

// envBool reads a boolean environment variable, treating anything unparseable
// as unset — a typo must not silently widen access.
func envBool(k string) bool {
	b, err := strconv.ParseBool(os.Getenv(k))
	return err == nil && b
}

// splitList parses a comma-separated flag into its non-empty, trimmed parts.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
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
	flowWindow := fs.Duration("flows", 0, "observe Hubble flows, and show this look-back window on the map by default, e.g. 24h (0: off). Serve mode streams continuously, so the window is a query over what was accumulated — not a request to Hubble, whose buffer holds only seconds")
	hubbleServer := fs.String("hubble-server", defaultHubbleServer, "Hubble Relay address (plaintext gRPC)")
	// Auth is opt-in; the default is none.
	authFlags := registerAuthFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Build the authenticator up front so a misconfiguration fails closed
	// before the server ever binds — a half-configured auth must never serve
	// the map open. In oidc mode this also reaches the provider for discovery,
	// retrying an IdP that is still coming up before giving up.
	authn, err := authFlags.build(ctx)
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

	// Continuous flow observation.
	//
	// Serve mode does NOT poll Hubble for the window: Cilium's event buffer is
	// bounded by capacity rather than time (4095 events per agent by default),
	// so on a busy cluster a request for 15m of history is answered with the
	// last few seconds and no hint that it fell short. Polling it every 15
	// minutes observes ~1% of the traffic and reports it as if it had watched
	// the lot — periodic traffic (a CronJob, a backup) lands between the
	// samples and vanishes.
	//
	// So we listen instead: one long-lived stream feeding a rolling store, and
	// the window becomes a query over what was actually seen.
	var flowSource snapshot.FlowSource
	if *flowWindow > 0 {
		if *dataDir == "" {
			return errors.New("serve: --flows needs --data: continuous flow observation accumulates to a store on disk, so the window survives a restart")
		}
		store, err := flowstore.Open(filepath.Join(*dataDir, "flows.db"))
		if err != nil {
			return err
		}
		defer store.Close()
		flowSource = store.Live()

		// Resolve peers through the collector's live pod index — as flows
		// arrive, not at snapshot time, since a pod that dies in between can no
		// longer be resolved to its controller.
		acc := snapshot.NewAccumulator(*hubbleServer, store, col.Resolve)
		go acc.Run(ctx)
		go pruneFlows(ctx, store, *interval)
		fmt.Fprintf(os.Stderr, "flows: streaming from %s, default window %s (retaining %s)\n",
			*hubbleServer, snapshot.ShortDur(*flowWindow), snapshot.ShortDur(flowstore.MaxWindow))
	}

	// Fixed for the life of the process: every viewer gets the same bytes, so
	// this can only carry deployment facts, never anything per-user.
	ui := render.UI{Auth: authn.Enabled()}

	s := &server{flows: flowSource, flowWindow: *flowWindow}
	collect := func() {
		cctx, cancel := context.WithTimeout(ctx, cycleTimeout)
		defer cancel()
		snap, err := col.Collect(cctx, snapshot.FlowOptions{
			Server: *hubbleServer,
			Window: *flowWindow,
			Source: flowSource,
		})
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
				// Report the window ACTUALLY observed, not the one requested.
				// The old line said "over 15m" whether it had watched fifteen
				// minutes or twelve seconds, which is precisely how the coverage
				// problem stayed invisible for so long.
				fmt.Fprintf(os.Stderr, "flows: %d edges from %d events — %s window, %.0f%% covered (%s observed)\n",
					len(snap.Flows.Edges), snap.Flows.FlowsSeen, snap.Flows.Window,
					snap.Flows.Coverage*100, snap.Flows.Watched)
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
		// The first collection always beats the flow stream's first flush — it
		// runs at t=0, the stream flushes every 30s — so it finds an empty store
		// and the map opens with no traffic on it. Waiting a whole interval to
		// fix that would leave every rollout showing a bare policy map for 15
		// minutes, so re-collect once the stream has had time to land something.
		if s.flowsWarming() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(warmupRecollect):
			}
			collect()
		}
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
	mux.HandleFunc("GET /brief.md", s.briefHandler)
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
	mux.HandleFunc("GET /api/flows", s.flowsHandler)
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
		fmt.Fprintf(os.Stderr, "auth: enabled — sign-in via %v\n", authn.Modes())
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

// warmupRecollect is how long to wait before the extra collection that picks up
// the flow stream's first flush. Comfortably past one flush interval (30s), so
// there is something in the store to find.
const warmupRecollect = 45 * time.Second

// flowsWarming reports whether the last collection found the flow store still
// empty — the stream connected, but had not flushed yet.
func (s *server) flowsWarming() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap != nil && s.snap.Flows != nil && s.snap.Flows.Status == snapshot.FlowStatusWarming
}

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

// maxFlowWindow bounds what the capture-window control may ask for. It matches
// the store's retention: a longer window would be answered with less than it
// claims.
const maxFlowWindow = flowstore.MaxWindow

// windowParam reads an optional ?window= look-back, defaulting to the configured
// one. Shared by the flow overlay and the brief so the two can never disagree
// about what "24h" means.
func (s *server) windowParam(r *http.Request) (time.Duration, error) {
	q := r.URL.Query().Get("window")
	if q == "" {
		return s.flowWindow, nil
	}
	d, err := snapshot.ParseWindow(q)
	if err != nil || d <= 0 {
		return 0, errors.New("window must be a positive duration, e.g. 15m, 6h, 7d")
	}
	if d > maxFlowWindow {
		return 0, fmt.Errorf("window must be at most %s (the store retains no more)",
			snapshot.ShortDur(maxFlowWindow))
	}
	return d, nil
}

// briefHandler serves the Markdown investigation brief — the document you hand
// to an LLM (or a colleague) when you want advice about what the map is showing.
//
// It is regenerated for the requested window rather than served from the cached
// default, because the brief must describe the same traffic the viewer is
// looking at. Handing someone a 24h brief while their map shows 7d of drops
// would have them reason about findings they cannot see, and miss ones they can.
func (s *server) briefHandler(w http.ResponseWriter, r *http.Request) {
	window, err := s.windowParam(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	snap, cached := s.snap, s.brief
	s.mu.RUnlock()

	// Without a flow store there is nothing to recompute against: serve the
	// brief built at the last collection.
	if s.flows == nil || snap == nil {
		if cached == nil {
			http.Error(w, "no successful collection yet", http.StatusServiceUnavailable)
			return
		}
		writeBrief(w, cached)
		return
	}

	// With one, always rebuild — even for the default window.
	//
	// The cached brief is only refreshed once per collection, so serving it
	// meant the brief could describe observations up to a whole interval (15
	// minutes) staler than the map it was opened from: same window, different
	// numbers, no explanation. A brief is read once and reasoned over hard, so
	// it has to agree with the thing it was clicked from.
	g := graph.Build(snap)
	if fc, err := s.flows.Capture(r.Context(), window); err == nil {
		// Swap in the requested window's observations; ComputeAudit reads its
		// drops straight off g.Flows, so the findings follow.
		g.Flows = graph.Overlay(g, fc)
	}
	writeBrief(w, graph.Brief(g, graph.ComputeAudit(g)))
}

func writeBrief(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Write(b)
}

// flowsHandler answers the map's capture-window control: the observed overlay
// for an arbitrary look-back, joined onto the graph the page is already
// showing.
//
// This is a query against the accumulated store, not a fresh call to Hubble —
// which is the only reason the control can exist at all. Asking Hubble for 24h
// would return the same few seconds its buffer happens to hold, so every window
// would look alike.
func (s *server) flowsHandler(w http.ResponseWriter, r *http.Request) {
	if s.flows == nil {
		http.Error(w, "flow observation is off (start with --flows)", http.StatusNotFound)
		return
	}
	window, err := s.windowParam(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	snap := s.snap
	s.mu.RUnlock()
	if snap == nil {
		http.Error(w, "no successful collection yet", http.StatusServiceUnavailable)
		return
	}

	fc, err := s.flows.Capture(r.Context(), window)
	if err != nil {
		// An empty store is the normal state for the first minute after start,
		// not a fault: say so plainly rather than 500.
		if errors.Is(err, flowstore.ErrNoObservations) {
			http.Error(w, "nothing observed yet — the flow stream is still warming up", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "flow query failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Join onto the graph the page is already drawing, so node ids line up.
	// graph.Overlay does not add nodes: an endpoint the map has no node for is
	// counted into notShown, which the map surfaces.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(graph.Overlay(graph.Build(snap), fc))
}

// pruneFlows ages observations out of the store on the collection cadence, so
// the PVC stays bounded by MaxWindow rather than by uptime.
func pruneFlows(ctx context.Context, store *flowstore.Store, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := store.Prune(ctx, time.Now()); err != nil {
				fmt.Fprintf(os.Stderr, "flow store: prune failed: %v\n", err)
			}
		}
	}
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
