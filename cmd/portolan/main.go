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
	case "whatif":
		err = fmt.Errorf("whatif: not implemented yet (roadmap)")
	case "serve":
		err = fmt.Errorf("serve: not implemented yet (roadmap)")
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
  whatif     blast radius of a draft policy (roadmap)
  serve      in-cluster dashboard (roadmap)
  version    print version

Run 'portolan <command> -h' for that command's flags.
`)
}

func cmdRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	in := fs.String("i", "snapshot.json", "input snapshot file (- for stdin)")
	out := fs.String("o", "map.html", "output HTML file (- for stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var data []byte
	var err error
	if *in == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(*in)
	}
	if err != nil {
		return err
	}

	var snap snapshot.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("parsing snapshot: %w", err)
	}
	if snap.SchemaVersion != snapshot.SchemaVersion {
		fmt.Fprintf(os.Stderr, "warning: snapshot schema %q, this build expects %q — rendering anyway\n",
			snap.SchemaVersion, snapshot.SchemaVersion)
	}

	g := graph.Build(&snap)
	html, err := render.HTML(g)
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
	snap, err := col.Collect(ctx)
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
	}
	return nil
}

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
