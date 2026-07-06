// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package render

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
	"github.com/T0ut4t1s/portolan/pkg/whatif"
)

//go:embed whatif.html
var whatifTemplate []byte

// wiWorkload / wiNamespace / wiExternal carry only what the delta map
// renders: the nodes touched by a delta, nothing else. The delta view is
// a diff, not a second full map.
type wiWorkload struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type wiNamespace struct {
	Name      string       `json:"name"`
	Workloads []wiWorkload `json:"workloads"`
}

type wiExternal struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type wiMeta struct {
	TakenAt    time.Time `json:"takenAt"`
	Cluster    string    `json:"cluster,omitempty"`
	Tool       string    `json:"tool"`
	Policies   int       `json:"policies"`
	Workloads  int       `json:"workloads"`
	FlowsOK    bool      `json:"flowsOK"`
	FlowWindow string    `json:"flowWindow,omitempty"`
	FlowsSeen  int       `json:"flowsSeen,omitempty"`
}

type wiView struct {
	Meta        wiMeta                 `json:"meta"`
	Changes     []string               `json:"changes"`
	Namespaces  []wiNamespace          `json:"namespaces"`
	Externals   []wiExternal           `json:"externals"`
	Added       []whatif.Delta         `json:"added"`
	Removed     []whatif.Delta         `json:"removed"`
	HalfOpen    []whatif.HalfOpenDelta `json:"halfOpen"`
	FixesDrops  []whatif.FlowImpact    `json:"fixesDrops"`
	BreaksFlows []whatif.FlowImpact    `json:"breaksFlows"`
	Warnings    []string               `json:"warnings,omitempty"`
	Probes      int                    `json:"probes"`
}

// WhatifHTML renders a what-if result as a self-contained delta map: only
// the pairs whose verdict changes, drawn in map.html's visual language.
func WhatifHTML(snap *snapshot.Snapshot, res *whatif.Result) ([]byte, error) {
	v := wiView{
		Changes:     res.PolicyChanges,
		Added:       res.Added,
		Removed:     res.Removed,
		HalfOpen:    res.HalfOpen,
		FixesDrops:  res.FixesDrops,
		BreaksFlows: res.BreaksFlows,
		Warnings:    res.Warnings,
		Probes:      res.Probes,
	}
	v.Meta = wiMeta{
		TakenAt:   snap.TakenAt,
		Cluster:   snap.Cluster,
		Tool:      snap.Tool.Name + " " + snap.Tool.Version,
		Policies:  len(snap.Policies),
		Workloads: len(snap.Workloads),
	}
	if snap.Flows != nil && snap.Flows.Status == "ok" {
		v.Meta.FlowsOK = true
		v.Meta.FlowWindow = snap.Flows.Window
		v.Meta.FlowsSeen = snap.Flows.FlowsSeen
	}

	// Collect every node a delta touches; group workloads by namespace.
	involved := map[string]bool{}
	touch := func(ids ...string) {
		for _, id := range ids {
			involved[id] = true
		}
	}
	for _, d := range res.Added {
		touch(d.Src, d.Dst)
	}
	for _, d := range res.Removed {
		touch(d.Src, d.Dst)
	}
	for _, h := range res.HalfOpen {
		touch(h.Src, h.Dst)
	}
	for _, f := range res.FixesDrops {
		touch(f.Src, f.Dst)
	}
	for _, f := range res.BreaksFlows {
		touch(f.Src, f.Dst)
	}

	wlByID := map[string]snapshot.Workload{}
	for _, wl := range snap.Workloads {
		wlByID[wl.Namespace+"/"+wl.Name] = wl
	}

	byNS := map[string][]wiWorkload{}
	for id := range involved {
		if ent, ok := strings.CutPrefix(id, "entity:"); ok {
			v.Externals = append(v.Externals, wiExternal{ID: id, Label: ent})
			continue
		}
		wl, ok := wlByID[id]
		if !ok {
			// A delta endpoint the snapshot no longer names — render it
			// anyway so no edge dangles.
			ns, name, _ := strings.Cut(id, "/")
			wl = snapshot.Workload{Namespace: ns, Name: name, Kind: "Pod"}
		}
		byNS[wl.Namespace] = append(byNS[wl.Namespace], wiWorkload{ID: id, Name: wl.Name, Kind: wl.Kind})
	}
	for ns, wls := range byNS {
		sort.Slice(wls, func(i, j int) bool { return wls[i].Name < wls[j].Name })
		v.Namespaces = append(v.Namespaces, wiNamespace{Name: ns, Workloads: wls})
	}
	sort.Slice(v.Namespaces, func(i, j int) bool { return v.Namespaces[i].Name < v.Namespaces[j].Name })
	sort.Slice(v.Externals, func(i, j int) bool { return v.Externals[i].Label < v.Externals[j].Label })

	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encoding what-if view: %w", err)
	}
	if !bytes.Contains(whatifTemplate, []byte(dataToken)) {
		return nil, fmt.Errorf("embedded what-if template is missing the %s token", dataToken)
	}
	return bytes.Replace(whatifTemplate, []byte(dataToken), data, 1), nil
}
