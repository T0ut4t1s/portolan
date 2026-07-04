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

	"github.com/T0ut4t1s/portolan/pkg/graph"
	"github.com/T0ut4t1s/portolan/pkg/render"
	"github.com/T0ut4t1s/portolan/pkg/snapshot"
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
	lastOK   time.Time
	lastErr  string
}

func cmdServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	interval := fs.Duration("interval", 15*time.Minute, "collection interval")
	dataDir := fs.String("data", "", "directory for snapshot history (empty: no history kept)")
	keep := fs.Int("keep", 500, "snapshots to retain in the data directory")
	clusterName := fs.String("cluster-name", "", "cluster label recorded in snapshots")
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig (default: standard loading rules, then in-cluster)")
	if err := fs.Parse(args); err != nil {
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

	s := &server{}
	collect := func() {
		snap, err := col.Collect(ctx)
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
		html, err := render.HTML(g)
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
	}

	collect()
	go func() {
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
		fmt.Fprintf(w, "ok — last collection %s\n", s.lastOK.Format(time.RFC3339))
	})
	if *dataDir != "" {
		mux.HandleFunc("GET /snapshots/", historyHandler(*dataDir))
	}

	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	fmt.Fprintf(os.Stderr, "serving on %s (interval %s)\n", *addr, *interval)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
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
