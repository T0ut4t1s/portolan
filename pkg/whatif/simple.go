// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package whatif

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	sigsyaml "sigs.k8s.io/yaml"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

// SimpleRule is the what-if panel's composer output: one allow between two
// endpoints on specific ports. It deliberately captures only the inputs
// that decide a verdict — everything else (selectors, namespaces, rule
// shape) is derived from the snapshot.
type SimpleRule struct {
	// From/To name a snapshot workload ("ns/name") or an entity
	// ("entity:world", "entity:host", "entity:remote-node",
	// "entity:kube-apiserver", "entity:cluster").
	From string `json:"from"`
	To   string `json:"to"`
	// Ports are "53/UDP"-form; a bare number means TCP. Empty allows all
	// ports between the pair.
	Ports []string `json:"ports,omitempty"`
	// Sides selects which half of the passage to declare: "both"
	// (default), "egress" (sender only), or "ingress" (receiver only).
	// One-sided rules are how half-opens happen — the panel lets you
	// build one on purpose and watch the finding appear.
	Sides string `json:"sides,omitempty"`
}

// Manifest is one generated CiliumNetworkPolicy, both as the policy the
// engine simulates and as the YAML the user takes to git. Simulation and
// generation share one builder, so the preview can never drift from the
// output.
type Manifest struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	YAML      string `json:"yaml"`
}

// generatableEntities are the entity peers a simple rule may name.
var generatableEntities = []string{"world", "host", "remote-node", "kube-apiserver", "cluster"}

// GenerateCNPs converts simple rules into CiliumNetworkPolicy objects:
// the snapshot.Policy form Compute simulates, plus the YAML manifests the
// generate button hands to the user. Rules for the same source or
// destination workload merge into one policy per (workload, direction) —
// mirroring how a human would author them.
func GenerateCNPs(snap *snapshot.Snapshot, rules []SimpleRule) ([]snapshot.Policy, []Manifest, error) {
	if len(rules) == 0 {
		return nil, nil, fmt.Errorf("no rules given")
	}
	wlByID := map[string]snapshot.Workload{}
	for _, wl := range snap.Workloads {
		wlByID[wl.Namespace+"/"+wl.Name] = wl
	}

	// One CNP per (workload, direction); rule sections append.
	type cnpDraft struct {
		ns, name string
		selector map[string]string
		egress   []map[string]any
		ingress  []map[string]any
	}
	drafts := map[string]*cnpDraft{}
	order := []string{}
	draftFor := func(wl snapshot.Workload, dir string) *cnpDraft {
		key := wl.Namespace + "/" + wl.Name + "/" + dir
		if d, ok := drafts[key]; ok {
			return d
		}
		d := &cnpDraft{
			ns:       wl.Namespace,
			name:     sanitizeName("whatif-" + wl.Name + "-" + dir),
			selector: pickSelector(wl.Labels),
		}
		drafts[key] = d
		order = append(order, key)
		return d
	}

	for i, r := range rules {
		sides := r.Sides
		if sides == "" {
			sides = "both"
		}
		if sides != "both" && sides != "egress" && sides != "ingress" {
			return nil, nil, fmt.Errorf("rule %d: sides must be both, egress, or ingress", i+1)
		}
		srcWL, srcEnt, err := resolveEndpoint(r.From, wlByID)
		if err != nil {
			return nil, nil, fmt.Errorf("rule %d from: %w", i+1, err)
		}
		dstWL, dstEnt, err := resolveEndpoint(r.To, wlByID)
		if err != nil {
			return nil, nil, fmt.Errorf("rule %d to: %w", i+1, err)
		}
		if srcEnt != "" && dstEnt != "" {
			return nil, nil, fmt.Errorf("rule %d: at least one side must be a workload", i+1)
		}
		ports, err := parsePorts(r.Ports)
		if err != nil {
			return nil, nil, fmt.Errorf("rule %d: %w", i+1, err)
		}

		// Egress side lives on the sender's CNP (workloads only — entities
		// have no policies).
		if (sides == "both" || sides == "egress") && srcEnt == "" {
			sec := map[string]any{}
			if dstEnt != "" {
				sec["toEntities"] = []string{dstEnt}
			} else {
				sec["toEndpoints"] = []any{peerSelector(dstWL)}
			}
			if ports != nil {
				sec["toPorts"] = ports
			}
			d := draftFor(srcWL, "egress")
			d.egress = append(d.egress, sec)
		}
		// Ingress side lives on the receiver's CNP.
		if (sides == "both" || sides == "ingress") && dstEnt == "" {
			sec := map[string]any{}
			if srcEnt != "" {
				sec["fromEntities"] = []string{srcEnt}
			} else {
				sec["fromEndpoints"] = []any{peerSelector(srcWL)}
			}
			if ports != nil {
				sec["toPorts"] = ports
			}
			d := draftFor(dstWL, "ingress")
			d.ingress = append(d.ingress, sec)
		}
	}

	var pols []snapshot.Policy
	var mans []Manifest
	for _, key := range order {
		d := drafts[key]
		spec := map[string]any{
			"endpointSelector": map[string]any{"matchLabels": d.selector},
		}
		if len(d.egress) > 0 {
			spec["egress"] = d.egress
		}
		if len(d.ingress) > 0 {
			spec["ingress"] = d.ingress
		}
		raw, err := json.Marshal(spec)
		if err != nil {
			return nil, nil, err
		}
		pols = append(pols, snapshot.Policy{
			Kind:       snapshot.KindCNP,
			Namespace:  d.ns,
			Name:       d.name,
			APIVersion: "cilium.io/v2",
			Rules:      []json.RawMessage{raw},
		})
		manifest := map[string]any{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata":   map[string]any{"name": d.name, "namespace": d.ns},
			"spec":       spec,
		}
		y, err := sigsyaml.Marshal(manifest)
		if err != nil {
			return nil, nil, err
		}
		mans = append(mans, Manifest{Namespace: d.ns, Name: d.name, YAML: string(y)})
	}
	return pols, mans, nil
}

// resolveEndpoint maps a composer endpoint string onto a snapshot workload
// or a generatable entity name.
func resolveEndpoint(s string, wlByID map[string]snapshot.Workload) (snapshot.Workload, string, error) {
	if ent, ok := strings.CutPrefix(s, "entity:"); ok {
		if !slices.Contains(generatableEntities, ent) {
			return snapshot.Workload{}, "", fmt.Errorf("unknown entity %q (valid: %s)",
				ent, strings.Join(generatableEntities, ", "))
		}
		return snapshot.Workload{}, ent, nil
	}
	wl, ok := wlByID[s]
	if !ok {
		return snapshot.Workload{}, "", fmt.Errorf("no workload %q in the snapshot", s)
	}
	return wl, "", nil
}

// pickSelector chooses the labels a generated CNP selects on: the stable
// app-identifying labels when present, the full label set otherwise.
// component is included when set — name+instance alone can span several
// workloads of one app (server vs worker), which would silently widen
// the policy beyond the drafted rule.
func pickSelector(lbls map[string]string) map[string]string {
	for _, keys := range [][]string{
		{"app.kubernetes.io/name", "app.kubernetes.io/instance", "app.kubernetes.io/component"},
		{"app", "app.kubernetes.io/component"},
	} {
		sel := map[string]string{}
		for _, k := range keys {
			if v, ok := lbls[k]; ok {
				sel[k] = v
			}
		}
		if len(sel) > 0 {
			return sel
		}
	}
	out := map[string]string{}
	for k, v := range lbls {
		out[k] = v
	}
	return out
}

// peerSelector builds the cross-namespace peer selector for a workload:
// its identifying labels plus the namespace label Cilium matches on.
func peerSelector(wl snapshot.Workload) map[string]any {
	ml := map[string]string{"k8s:io.kubernetes.pod.namespace": wl.Namespace}
	for k, v := range pickSelector(wl.Labels) {
		ml["k8s:"+k] = v
	}
	return map[string]any{"matchLabels": ml}
}

// parsePorts converts "53/UDP"-form ports into one toPorts section, or
// nil for "all ports".
func parsePorts(ports []string) ([]map[string]any, error) {
	if len(ports) == 0 {
		return nil, nil
	}
	var pp []map[string]any
	for _, p := range ports {
		num, protoStr, ok := strings.Cut(strings.TrimSpace(p), "/")
		if !ok {
			protoStr = "TCP"
		}
		proto := strings.ToUpper(strings.TrimSpace(protoStr))
		if parseProto(proto) == 0 {
			return nil, fmt.Errorf("port %q: unknown protocol %q", p, protoStr)
		}
		if _, _, ok := parsePort(num + "/" + proto); !ok {
			return nil, fmt.Errorf("port %q: want a number 1-65535, optionally /TCP, /UDP, or /SCTP", p)
		}
		pp = append(pp, map[string]any{"port": strings.TrimSpace(num), "protocol": proto})
	}
	return []map[string]any{{"ports": pp}}, nil
}

var nameRE = regexp.MustCompile(`[^a-z0-9-]+`)

// sanitizeName makes a valid RFC 1123 resource name from a label-ish string.
func sanitizeName(s string) string {
	s = nameRE.ReplaceAllString(strings.ToLower(s), "-")
	s = strings.Trim(s, "-")
	if len(s) > 63 {
		s = strings.Trim(s[:63], "-")
	}
	return s
}
