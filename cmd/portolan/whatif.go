// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/T0ut4t1s/portolan/pkg/render"
	"github.com/T0ut4t1s/portolan/pkg/snapshot"
	"github.com/T0ut4t1s/portolan/pkg/whatif"
)

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func cmdWhatif(args []string) error {
	fs := flag.NewFlagSet("whatif", flag.ExitOnError)
	in := fs.String("i", "snapshot.json", "input snapshot file (- for stdin)")
	var drafts, deletes stringList
	fs.Var(&drafts, "f", "draft policy manifest (YAML/JSON, multi-doc; repeatable) — replaces or adds by kind/namespace/name")
	fs.Var(&deletes, "delete", "policy to remove, as Kind/namespace/name (repeatable)")
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	htmlOut := fs.String("o", "", "also write the result as a self-contained HTML delta map (e.g. whatif.html)")
	failOnBreak := fs.Bool("fail-on-break", false, "exit 1 when the draft would break observed live traffic (CI gate)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(drafts) == 0 && len(deletes) == 0 {
		return fmt.Errorf("usage: portolan whatif -i snapshot.json -f draft.yaml [-f more.yaml] [--delete Kind/ns/name]")
	}

	snap, err := readSnapshot(*in)
	if err != nil {
		return err
	}

	ch := whatif.Changes{Delete: deletes}
	for _, path := range drafts {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		pols, err := whatif.ParseDrafts(path, data)
		if err != nil {
			return err
		}
		ch.Apply = append(ch.Apply, pols...)
	}

	res, err := whatif.Compute(snap, ch)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return err
		}
	} else {
		printResult(snap, res)
	}
	if *htmlOut != "" {
		html, err := render.WhatifHTML(snap, res)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*htmlOut, html, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote delta map to %s\n", *htmlOut)
	}
	if *failOnBreak && len(res.BreaksFlows) > 0 {
		os.Exit(1)
	}
	return nil
}

func printResult(snap *snapshot.Snapshot, res *whatif.Result) {
	fmt.Printf("WHAT-IF against snapshot %s (%d workloads, %d policies)\n",
		snap.TakenAt.Format("2006-01-02 15:04 UTC"), len(snap.Workloads), len(snap.Policies))
	for _, c := range res.PolicyChanges {
		fmt.Printf("  %s\n", c)
	}

	fmt.Printf("\nNEW PASSAGES (%d):\n", len(res.Added))
	for _, d := range res.Added {
		badge := ""
		if d.HealsHalfOpen {
			badge = "  [heals half-open]"
		}
		fmt.Printf("  + %s -> %s  %s%s\n      via %s\n",
			d.Src, d.Dst, strings.Join(d.Ports, ", "), badge, strings.Join(d.Via, ", "))
	}
	if len(res.Added) == 0 {
		fmt.Println("  none")
	}

	fmt.Printf("\nREMOVED PASSAGES (%d):\n", len(res.Removed))
	for _, d := range res.Removed {
		fmt.Printf("  - %s -> %s  %s\n      was via %s\n",
			d.Src, d.Dst, strings.Join(d.Ports, ", "), strings.Join(d.Via, ", "))
	}
	if len(res.Removed) == 0 {
		fmt.Println("  none")
	}

	if len(res.HalfOpen) > 0 {
		fmt.Printf("\nHALF-OPEN INTRODUCED (%d) — one side changed, passage still blocked:\n", len(res.HalfOpen))
		for _, h := range res.HalfOpen {
			if h.Side == "egress" {
				fmt.Printf("  ! %s -> %s  %s — egress now declared but the receiver still denies (add the ingress allow)\n",
					h.Src, h.Dst, strings.Join(h.Ports, ", "))
			} else {
				fmt.Printf("  ! %s -> %s  %s — receiver would now accept but the sender still cannot send (add the egress allow)\n",
					h.Src, h.Dst, strings.Join(h.Ports, ", "))
			}
		}
	}

	if snap.Flows != nil && snap.Flows.Status == "ok" {
		fmt.Printf("\nOBSERVED TRAFFIC IMPACT (window %s, %d events):\n", snap.Flows.Window, snap.Flows.FlowsSeen)
		for _, f := range res.FixesDrops {
			fmt.Printf("  fixes drop: %s -> %s %s (%s x%d)\n", f.Src, f.Dst, f.Port, f.Reason, f.Count)
		}
		for _, f := range res.BreaksFlows {
			fmt.Printf("  BREAKS LIVE FLOW: %s -> %s %s (forwarded x%d in window)\n", f.Src, f.Dst, f.Port, f.Count)
		}
		if len(res.FixesDrops) == 0 && len(res.BreaksFlows) == 0 {
			fmt.Println("  none — no observed flow changes verdict")
		}
	}

	for _, w := range res.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	fmt.Printf("\n%d verdicts probed per repository — verdict-grade (cilium engine, in-process).\n", res.Probes)
}
