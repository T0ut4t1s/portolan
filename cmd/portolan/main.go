// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

// Command portolan charts permitted passage for Cilium clusters.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/T0ut4t1s/portolan/pkg/graph"
	"github.com/T0ut4t1s/portolan/pkg/render"
	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

// version is stamped by goreleaser via -ldflags at release time.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "snapshot":
		err = cmdSnapshot(ctx, os.Args[2:])
	case "render":
		err = cmdRender(os.Args[2:])
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "whatif":
		err = cmdWhatif(os.Args[2:])
	case "serve":
		err = cmdServe(ctx, os.Args[2:])
	case "hashpw":
		err = cmdHashpw(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "portolan: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "portolan: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `portolan — charts of permitted passage for Cilium clusters

Commands:
  snapshot   capture cluster policy state to a snapshot file
  render     render a snapshot to a self-contained HTML map
  audit      report half-open passages, deny gaps, and dead selector refs
  diff       compare two snapshots (policies and derived edges)
  whatif     blast radius of a draft policy change (cilium engine verdicts)
  serve      in-cluster dashboard (collects on an interval, serves the map)
  hashpw     print a username:bcrypt line for the serve --auth-users-file
  version    print version

Run 'portolan <command> -h' for that command's flags.
`)
}

func readSnapshot(path string) (*snapshot.Snapshot, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	var snap snapshot.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parsing snapshot %s: %w", path, err)
	}
	if snap.SchemaVersion != snapshot.SchemaVersion {
		fmt.Fprintf(os.Stderr, "warning: %s has schema %q, this build expects %q — continuing anyway\n",
			path, snap.SchemaVersion, snapshot.SchemaVersion)
	}
	return &snap, nil
}

func cmdAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	in := fs.String("i", "snapshot.json", "input snapshot file (- for stdin)")
	failOn := fs.Bool("fail-on-findings", false, "exit 1 when half-open passages exist (CI gate)")
	brief := fs.String("brief", "", "also write a Markdown investigation brief for an LLM agent (- for stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	snap, err := readSnapshot(*in)
	if err != nil {
		return err
	}
	g := graph.Build(snap)
	a := graph.ComputeAudit(g)

	if *brief != "" {
		md := graph.Brief(g, a)
		if *brief == "-" {
			if _, err := os.Stdout.Write(md); err != nil {
				return err
			}
		} else if err := os.WriteFile(*brief, md, 0o644); err != nil {
			return err
		} else {
			fmt.Fprintf(os.Stderr, "wrote investigation brief: %s\n", *brief)
		}
	}

	fmt.Printf("Half-open passages (%d) — egress declared, default-deny receiver never accepts:\n", len(a.HalfOpen))
	for _, e := range a.HalfOpen {
		fmt.Printf("  %s -> %s %s  via %s\n", e.Src, e.Dst, strings.Join(e.Ports, ","), strings.Join(e.Policies, ", "))
	}
	fmt.Printf("\nNamespaces with workloads but no default-deny (%d):\n", len(a.NoDefaultDeny))
	for _, ns := range a.NoDefaultDeny {
		fmt.Printf("  %s\n", ns)
	}
	fmt.Printf("\nWorkloads with declared ingress from world/all (%d):\n", len(a.WorldReachable))
	for _, w := range a.WorldReachable {
		fmt.Printf("  %s\n", w)
	}
	fmt.Printf("\nSelector references matching no live workload (%d) — scaled-down, future, or dead:\n", len(a.DeadRefs))
	for _, r := range a.DeadRefs {
		fmt.Printf("  %s\n", r)
	}
	if *failOn && len(a.HalfOpen) > 0 {
		os.Exit(1)
	}
	return nil
}

func cmdDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	exitCode := fs.Bool("exit-code", false, "exit 1 when the snapshots differ (CI gate)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: portolan diff [--exit-code] <old.json> <new.json>")
	}
	oldSnap, err := readSnapshot(fs.Arg(0))
	if err != nil {
		return err
	}
	newSnap, err := readSnapshot(fs.Arg(1))
	if err != nil {
		return err
	}

	polKey := func(p snapshot.Policy) string {
		if p.Namespace == "" {
			return fmt.Sprintf("%s/%s", p.Kind, p.Name)
		}
		return fmt.Sprintf("%s/%s/%s", p.Kind, p.Namespace, p.Name)
	}
	polMap := func(s *snapshot.Snapshot) map[string]string {
		m := map[string]string{}
		for _, p := range s.Policies {
			var body strings.Builder
			for _, r := range p.Rules {
				body.Write(r)
			}
			m[polKey(p)] = body.String()
		}
		return m
	}
	edgeMap := func(s *snapshot.Snapshot) map[string]string {
		m := map[string]string{}
		for _, e := range graph.Build(s).Edges {
			m[e.Src+" -> "+e.Dst] = strings.Join(e.Ports, ",")
		}
		return m
	}

	changed := false
	report := func(title string, oldM, newM map[string]string) {
		var added, removed, modified []string
		for k := range newM {
			if _, ok := oldM[k]; !ok {
				added = append(added, k)
			} else if oldM[k] != newM[k] {
				modified = append(modified, k)
			}
		}
		for k := range oldM {
			if _, ok := newM[k]; !ok {
				removed = append(removed, k)
			}
		}
		sort.Strings(added)
		sort.Strings(removed)
		sort.Strings(modified)
		fmt.Printf("%s: +%d added, -%d removed, ~%d changed\n", title, len(added), len(removed), len(modified))
		for _, k := range added {
			fmt.Printf("  + %s\n", k)
		}
		for _, k := range removed {
			fmt.Printf("  - %s\n", k)
		}
		for _, k := range modified {
			fmt.Printf("  ~ %s\n", k)
		}
		changed = changed || len(added)+len(removed)+len(modified) > 0
	}

	report("Policies", polMap(oldSnap), polMap(newSnap))
	fmt.Println()
	report("Edges (derived)", edgeMap(oldSnap), edgeMap(newSnap))
	if *exitCode && changed {
		os.Exit(1)
	}
	return nil
}

func cmdRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	in := fs.String("i", "snapshot.json", "input snapshot file (- for stdin)")
	out := fs.String("o", "map.html", "output HTML file (- for stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	snap, err := readSnapshot(*in)
	if err != nil {
		return err
	}

	g := graph.Build(snap)
	// Standalone file: no server, so no session to sign out of.
	html, err := render.HTML(g, render.UI{})
	if err != nil {
		return err
	}

	if *out == "-" {
		_, err = os.Stdout.Write(html)
		return err
	}
	if err := os.WriteFile(*out, html, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s: %d edges (%d cross-namespace) from %d policies\n",
		*out, g.Stats.Edges, g.Stats.CrossEdges, g.Stats.Policies)
	for _, w := range g.Warnings {
		fmt.Fprintf(os.Stderr, "note: %s\n", w)
	}
	return nil
}

func cmdSnapshot(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	out := fs.String("o", "snapshot.json", "output file (- for stdout)")
	clusterName := fs.String("cluster-name", "", "optional cluster label recorded in the snapshot")
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig (default: standard loading rules, then in-cluster)")
	flowWindow := fs.Duration("flows", 0, "also capture Hubble flow observations over this look-back window, e.g. 15m (0: off)")
	hubbleServer := fs.String("hubble-server", defaultHubbleServer, "Hubble Relay address (plaintext gRPC)")
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
	snap, err := col.Collect(ctx, snapshot.FlowOptions{Server: *hubbleServer, Window: *flowWindow})
	if err != nil {
		return err
	}
	snap.Cluster = *clusterName
	snap.Tool = snapshot.ToolInfo{Name: snapshot.ToolName, Version: version}

	skipped := 0
	for _, src := range snap.Sources {
		if src.Status == "skipped" {
			skipped++
			fmt.Fprintf(os.Stderr, "warning: %s skipped: %s\n", src.Kind, src.Reason)
		}
	}
	if snap.Flows != nil && snap.Flows.Status != "ok" {
		fmt.Fprintf(os.Stderr, "warning: flow capture failed (snapshot still valid): %s\n", snap.Flows.Reason)
	}

	var w io.Writer = os.Stdout
	if *out != "-" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		return err
	}

	if *out != "-" {
		fmt.Fprintf(os.Stderr, "wrote %s: %d namespaces, %d workloads, %d policies (%d source(s) skipped)\n",
			*out, len(snap.Namespaces), len(snap.Workloads), len(snap.Policies), skipped)
		if snap.Flows != nil && snap.Flows.Status == "ok" {
			fmt.Fprintf(os.Stderr, "flows: %d edges from %d events over %s (%d skipped as noise, %d lost by hubble)\n",
				len(snap.Flows.Edges), snap.Flows.FlowsSeen, snap.Flows.Window, snap.Flows.Skipped, snap.Flows.LostEvents)
		}
	}
	return nil
}

// defaultHubbleServer is the address of the Hubble Relay service in a
// standard Cilium install, reachable from inside the cluster. Local runs
// typically override it with a port-forward (e.g. localhost:4245).
const defaultHubbleServer = "hubble-relay.kube-system.svc.cluster.local:80"

// restConfig follows kubectl's precedence via client-go's deferred loader:
// explicit --kubeconfig > $KUBECONFIG > ~/.kube/config, with the loader's
// own in-cluster fallback engaging only when no kubeconfig exists at all.
// An explicit path that fails to load is an error, never silently replaced.
func restConfig(explicitPath string) (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if explicitPath != "" {
		rules.ExplicitPath = explicitPath
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("loading kube config: %w", err)
	}
	return cfg, nil
}
