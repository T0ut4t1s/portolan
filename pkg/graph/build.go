// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package graph

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

// ---- loose rule structures ------------------------------------------------
// Parsed from the verbatim rule payloads. Unknown fields are ignored by
// encoding/json, which is exactly right for visualization-grade parsing.

type labelSel struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []selExpr         `json:"matchExpressions"`
}

type selExpr struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type ciliumRule struct {
	EndpointSelector  *labelSel         `json:"endpointSelector"`
	NodeSelector      *labelSel         `json:"nodeSelector"`
	Ingress           []ciliumIngress   `json:"ingress"`
	Egress            []ciliumEgress    `json:"egress"`
	IngressDeny       []json.RawMessage `json:"ingressDeny"`
	EgressDeny        []json.RawMessage `json:"egressDeny"`
	EnableDefaultDeny *struct {
		Ingress *bool `json:"ingress"`
		Egress  *bool `json:"egress"`
	} `json:"enableDefaultDeny"`
}

// sentinelDenyKey marks selectors that deliberately match nothing — the
// idiomatic "allow only this impossible label" arm of a default-deny policy.
const sentinelDenyKey = "io.cilium.policy/default-deny"

type ciliumIngress struct {
	FromEndpoints []labelSel `json:"fromEndpoints"`
	FromEntities  []string   `json:"fromEntities"`
	FromCIDR      []string   `json:"fromCIDR"`
	FromCIDRSet   []cidrRule `json:"fromCIDRSet"`
	FromRequires  []labelSel `json:"fromRequires"`
	ToPorts       []portRule `json:"toPorts"`
}

type ciliumEgress struct {
	ToEndpoints []labelSel        `json:"toEndpoints"`
	ToEntities  []string          `json:"toEntities"`
	ToCIDR      []string          `json:"toCIDR"`
	ToCIDRSet   []cidrRule        `json:"toCIDRSet"`
	ToFQDNs     []fqdnRule        `json:"toFQDNs"`
	ToServices  []json.RawMessage `json:"toServices"`
	ToRequires  []labelSel        `json:"toRequires"`
	ToPorts     []portRule        `json:"toPorts"`
}

type cidrRule struct {
	Cidr string `json:"cidr"`
}

type fqdnRule struct {
	MatchName    string `json:"matchName"`
	MatchPattern string `json:"matchPattern"`
}

type portRule struct {
	Ports []portProto     `json:"ports"`
	Rules json.RawMessage `json:"rules"` // L7 — flagged, not interpreted
}

type portProto struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

type netpolSpec struct {
	PodSelector labelSel        `json:"podSelector"`
	PolicyTypes []string        `json:"policyTypes"`
	Ingress     []netpolIngress `json:"ingress"`
	Egress      []netpolEgress  `json:"egress"`
}

type netpolIngress struct {
	From  []netpolPeer `json:"from"`
	Ports []netpolPort `json:"ports"`
}

type netpolEgress struct {
	To    []netpolPeer `json:"to"`
	Ports []netpolPort `json:"ports"`
}

type netpolPeer struct {
	PodSelector       *labelSel `json:"podSelector"`
	NamespaceSelector *labelSel `json:"namespaceSelector"`
	IPBlock           *struct {
		CIDR string `json:"cidr"`
	} `json:"ipBlock"`
}

type netpolPort struct {
	Protocol *string          `json:"protocol"`
	Port     *json.RawMessage `json:"port"` // int or named string
	EndPort  *int             `json:"endPort"`
}

// ---- builder ----------------------------------------------------------------

const (
	nsKey       = "io.kubernetes.pod.namespace"
	nsLabelsKey = "io.cilium.k8s.namespace.labels."
)

type builder struct {
	snap      *snapshot.Snapshot
	nsLabels  map[string]map[string]string // namespace -> labels
	nsNames   []string
	workloads map[string][]snapshot.Workload // namespace -> workloads
	edges     map[string]*Edge               // "src|dst" -> aggregated edge
	externals map[string]External
	dropped   map[string]int // unsupported-construct counters
	deadRefs  []string       // "policy → selector" refs matching no live workload
}

// Build derives the renderable topology from a snapshot.
func Build(snap *snapshot.Snapshot) *Graph {
	b := &builder{
		snap:      snap,
		nsLabels:  map[string]map[string]string{},
		workloads: map[string][]snapshot.Workload{},
		edges:     map[string]*Edge{},
		externals: map[string]External{},
		dropped:   map[string]int{},
	}
	for _, ns := range snap.Namespaces {
		b.nsLabels[ns.Name] = ns.Labels
		b.nsNames = append(b.nsNames, ns.Name)
	}
	for _, wl := range snap.Workloads {
		b.workloads[wl.Namespace] = append(b.workloads[wl.Namespace], wl)
	}

	defaultDeny := map[string]bool{}
	policyCount := map[string]int{}

	for _, pol := range snap.Policies {
		prov := fmt.Sprintf("%s/%s", pol.Kind, pol.Name)
		if pol.Namespace != "" {
			prov = fmt.Sprintf("%s/%s/%s", pol.Kind, pol.Namespace, pol.Name)
			policyCount[pol.Namespace]++
		}
		switch pol.Kind {
		case snapshot.KindCNP, snapshot.KindCCNP:
			for _, raw := range pol.Rules {
				b.ciliumRule(raw, pol, prov, defaultDeny)
			}
		case snapshot.KindNetPol:
			for _, raw := range pol.Rules {
				b.netpolRule(raw, pol, prov, defaultDeny)
			}
		default:
			b.dropped[fmt.Sprintf("unsupported policy kind %s", pol.Kind)]++
		}
	}

	return b.assemble(defaultDeny, policyCount)
}

// ciliumRule handles one CNP/CCNP rule payload.
func (b *builder) ciliumRule(raw json.RawMessage, pol snapshot.Policy, prov string, defaultDeny map[string]bool) {
	var rule ciliumRule
	if err := json.Unmarshal(raw, &rule); err != nil {
		b.dropped["unparseable Cilium rule"]++
		return
	}
	if rule.NodeSelector != nil {
		b.dropped["node (host) policies"]++
		return
	}
	if len(rule.IngressDeny) > 0 || len(rule.EgressDeny) > 0 {
		b.dropped["deny rules"]++
	}

	// Subject scope: CNP peers and subjects default to the policy's own
	// namespace; CCNP has no implicit namespace.
	defaultNS := pol.Namespace
	var sel labelSel
	if rule.EndpointSelector != nil {
		sel = *rule.EndpointSelector
	}
	subjects := b.match(sel, defaultNS, prov)

	// Default-deny detection: an all-endpoints selector combined with
	// either explicit enableDefaultDeny or a rule-free body. For CCNPs the
	// flag lands on every namespace with matched subjects.
	explicitDeny := rule.EnableDefaultDeny != nil &&
		((rule.EnableDefaultDeny.Ingress != nil && *rule.EnableDefaultDeny.Ingress) ||
			(rule.EnableDefaultDeny.Egress != nil && *rule.EnableDefaultDeny.Egress))
	if emptySel(sel) && (explicitDeny || (len(rule.Ingress) == 0 && len(rule.Egress) == 0)) {
		if pol.Namespace != "" {
			defaultDeny[pol.Namespace] = true
		} else {
			for _, s := range subjects {
				if ns, ok := nodeNS(s); ok {
					defaultDeny[ns] = true
				}
			}
		}
	}

	for _, ing := range rule.Ingress {
		ports := b.ports(ing.ToPorts)
		l7 := hasL7(ing.ToPorts)
		if len(ing.FromRequires) > 0 {
			b.dropped["fromRequires"]++
		}
		for _, peerSel := range ing.FromEndpoints {
			peers := b.match(peerSel, defaultNS, prov)
			for _, p := range peers {
				for _, s := range subjects {
					b.edge(p, s, ports, prov, false, true, l7)
				}
			}
		}
		for _, ent := range ing.FromEntities {
			id := b.external("entity", ent)
			for _, s := range subjects {
				b.edge(id, s, ports, prov, false, true, l7)
			}
		}
		for _, cidr := range append(ing.FromCIDR, cidrs(ing.FromCIDRSet)...) {
			id := b.external("cidr", cidr)
			for _, s := range subjects {
				b.edge(id, s, ports, prov, false, true, l7)
			}
		}
	}

	for _, eg := range rule.Egress {
		ports := b.ports(eg.ToPorts)
		l7 := hasL7(eg.ToPorts)
		if len(eg.ToServices) > 0 {
			b.dropped["toServices"]++
		}
		if len(eg.ToRequires) > 0 {
			b.dropped["toRequires"]++
		}
		for _, peerSel := range eg.ToEndpoints {
			peers := b.match(peerSel, defaultNS, prov)
			for _, p := range peers {
				for _, s := range subjects {
					b.edge(s, p, ports, prov, true, false, l7)
				}
			}
		}
		for _, ent := range eg.ToEntities {
			id := b.external("entity", ent)
			for _, s := range subjects {
				b.edge(s, id, ports, prov, true, false, l7)
			}
		}
		for _, cidr := range append(eg.ToCIDR, cidrs(eg.ToCIDRSet)...) {
			id := b.external("cidr", cidr)
			for _, s := range subjects {
				b.edge(s, id, ports, prov, true, false, l7)
			}
		}
		for _, f := range eg.ToFQDNs {
			name := f.MatchName
			if name == "" {
				name = f.MatchPattern
			}
			id := b.external("fqdn", name)
			for _, s := range subjects {
				b.edge(s, id, ports, prov, true, false, l7)
			}
		}
	}
}

// netpolRule handles one native NetworkPolicy spec.
func (b *builder) netpolRule(raw json.RawMessage, pol snapshot.Policy, prov string, defaultDeny map[string]bool) {
	var spec netpolSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		b.dropped["unparseable NetworkPolicy spec"]++
		return
	}
	subjects := b.match(spec.PodSelector, pol.Namespace, prov)

	hasType := func(t string) bool {
		if len(spec.PolicyTypes) == 0 {
			return t == "Ingress" // k8s default when types are unset
		}
		return slices.Contains(spec.PolicyTypes, t)
	}
	if emptySel(spec.PodSelector) && hasType("Ingress") && len(spec.Ingress) == 0 {
		defaultDeny[pol.Namespace] = true
	}

	for _, ing := range spec.Ingress {
		ports := b.netpolPorts(ing.Ports)
		for _, peer := range ing.From {
			for _, p := range b.netpolPeers(peer, pol.Namespace, prov) {
				for _, s := range subjects {
					b.edge(p, s, ports, prov, false, true, false)
				}
			}
		}
	}
	for _, eg := range spec.Egress {
		ports := b.netpolPorts(eg.Ports)
		for _, peer := range eg.To {
			for _, p := range b.netpolPeers(peer, pol.Namespace, prov) {
				for _, s := range subjects {
					b.edge(s, p, ports, prov, true, false, false)
				}
			}
		}
	}
}

// netpolPeers resolves one NetworkPolicy peer to node IDs.
func (b *builder) netpolPeers(peer netpolPeer, policyNS, prov string) []string {
	if peer.IPBlock != nil {
		return []string{b.external("cidr", peer.IPBlock.CIDR)}
	}
	var namespaces []string
	switch {
	case peer.NamespaceSelector == nil:
		namespaces = []string{policyNS}
	case emptySel(*peer.NamespaceSelector):
		namespaces = b.nsNames
	default:
		for _, ns := range b.nsNames {
			if matchLabels(*peer.NamespaceSelector, b.nsLabels[ns]) {
				namespaces = append(namespaces, ns)
			}
		}
	}
	podSel := labelSel{}
	if peer.PodSelector != nil {
		podSel = *peer.PodSelector
	}
	var out []string
	for _, ns := range namespaces {
		for _, wl := range b.workloads[ns] {
			if matchLabels(podSel, wl.Labels) {
				out = append(out, wl.Namespace+"/"+wl.Name)
			}
		}
	}
	if out == nil {
		b.deadRefs = append(b.deadRefs, prov+" → netpol peer "+selSummary(podSel))
	}
	return out
}

// match resolves a Cilium endpoint selector to workload node IDs. Keys may
// carry "k8s:" / "any:" source prefixes; the reserved namespace key (and
// namespace-label keys) scope the search, remaining keys match pod labels.
func (b *builder) match(sel labelSel, defaultNS, prov string) []string {
	// Sentinel selectors match nothing by design — not a policy smell.
	if _, ok := sel.MatchLabels[sentinelDenyKey]; ok {
		return nil
	}
	podSel, nsExact, nsLabels := splitSelector(sel)

	var namespaces []string
	switch {
	case len(nsExact) > 0:
		namespaces = nsExact
	case len(nsLabels.MatchLabels) > 0 || len(nsLabels.MatchExpressions) > 0:
		for _, ns := range b.nsNames {
			if matchLabels(nsLabels, b.nsLabels[ns]) {
				namespaces = append(namespaces, ns)
			}
		}
	case defaultNS != "":
		namespaces = []string{defaultNS}
	default:
		namespaces = b.nsNames
	}

	var out []string
	for _, ns := range namespaces {
		for _, wl := range b.workloads[ns] {
			if matchLabels(podSel, wl.Labels) {
				out = append(out, wl.Namespace+"/"+wl.Name)
			}
		}
	}
	if out == nil {
		b.deadRefs = append(b.deadRefs, prov+" → "+selSummary(sel))
	}
	return out
}

// selSummary renders a selector compactly for audit output.
func selSummary(sel labelSel) string {
	var parts []string
	keys := make([]string, 0, len(sel.MatchLabels))
	for k := range sel.MatchLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, k+"="+sel.MatchLabels[k])
	}
	for _, e := range sel.MatchExpressions {
		parts = append(parts, fmt.Sprintf("%s %s %v", e.Key, e.Operator, e.Values))
	}
	if len(parts) == 0 {
		return "(all endpoints in scope)"
	}
	return strings.Join(parts, ", ")
}

// splitSelector separates namespace scoping from pod-label matching.
func splitSelector(sel labelSel) (podSel labelSel, nsExact []string, nsLabels labelSel) {
	podSel.MatchLabels = map[string]string{}
	nsLabels.MatchLabels = map[string]string{}
	for k, v := range sel.MatchLabels {
		key := stripPrefix(k)
		switch {
		case key == nsKey:
			nsExact = append(nsExact, v)
		case strings.HasPrefix(key, nsLabelsKey):
			nsLabels.MatchLabels[strings.TrimPrefix(key, nsLabelsKey)] = v
		default:
			podSel.MatchLabels[key] = v
		}
	}
	for _, e := range sel.MatchExpressions {
		key := stripPrefix(e.Key)
		switch {
		case key == nsKey && e.Operator == "In":
			nsExact = append(nsExact, e.Values...)
		case strings.HasPrefix(key, nsLabelsKey):
			e.Key = strings.TrimPrefix(key, nsLabelsKey)
			nsLabels.MatchExpressions = append(nsLabels.MatchExpressions, e)
		default:
			e.Key = key
			podSel.MatchExpressions = append(podSel.MatchExpressions, e)
		}
	}
	sort.Strings(nsExact)
	return podSel, slices.Compact(nsExact), nsLabels
}

func stripPrefix(key string) string {
	for _, p := range []string{"k8s:", "any:"} {
		if strings.HasPrefix(key, p) {
			return strings.TrimPrefix(key, p)
		}
	}
	return key
}

// matchLabels evaluates matchLabels + the common matchExpressions operators.
func matchLabels(sel labelSel, labels map[string]string) bool {
	for k, v := range sel.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	for _, e := range sel.MatchExpressions {
		val, ok := labels[e.Key]
		switch e.Operator {
		case "In":
			if !ok || !slices.Contains(e.Values, val) {
				return false
			}
		case "NotIn":
			if ok && slices.Contains(e.Values, val) {
				return false
			}
		case "Exists":
			if !ok {
				return false
			}
		case "DoesNotExist":
			if ok {
				return false
			}
		default:
			return false // unknown operator: match nothing, stay honest
		}
	}
	return true
}

func emptySel(sel labelSel) bool {
	return len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0
}

// ---- edge/external aggregation ---------------------------------------------

func (b *builder) edge(src, dst string, ports []string, prov string, egress, ingress, l7 bool) {
	if src == dst {
		return // self-edges add noise, not information
	}
	key := src + "|" + dst
	e, ok := b.edges[key]
	if !ok {
		e = &Edge{Src: src, Dst: dst}
		b.edges[key] = e
	}
	e.Ports = append(e.Ports, ports...)
	e.DeclaredEgress = e.DeclaredEgress || egress
	e.DeclaredIngress = e.DeclaredIngress || ingress
	e.L7 = e.L7 || l7
	e.Policies = append(e.Policies, prov)
}

func (b *builder) external(kind, name string) string {
	id := kind + ":" + name
	b.externals[id] = External{ID: id, Kind: kind, Name: name}
	return id
}

func (b *builder) ports(rules []portRule) []string {
	var out []string
	for _, r := range rules {
		for _, p := range r.Ports {
			proto := p.Protocol
			if proto == "" {
				proto = "ANY"
			}
			out = append(out, p.Port+"/"+proto)
		}
	}
	if out == nil {
		out = []string{"any"}
	}
	return out
}

func (b *builder) netpolPorts(ports []netpolPort) []string {
	var out []string
	for _, p := range ports {
		proto := "TCP"
		if p.Protocol != nil {
			proto = *p.Protocol
		}
		port := "any"
		if p.Port != nil {
			port = strings.Trim(string(*p.Port), `"`)
		}
		if p.EndPort != nil {
			port = fmt.Sprintf("%s-%d", port, *p.EndPort)
		}
		out = append(out, port+"/"+proto)
	}
	if out == nil {
		out = []string{"any"}
	}
	return out
}

func hasL7(rules []portRule) bool {
	for _, r := range rules {
		if len(r.Rules) > 0 && string(r.Rules) != "null" {
			return true
		}
	}
	return false
}

func cidrs(set []cidrRule) []string {
	var out []string
	for _, c := range set {
		out = append(out, c.Cidr)
	}
	return out
}

// ---- assembly ----------------------------------------------------------------

func (b *builder) assemble(defaultDeny map[string]bool, policyCount map[string]int) *Graph {
	g := &Graph{
		Cluster:     b.snap.Cluster,
		TakenAt:     b.snap.TakenAt.Format("2006-01-02 15:04 UTC"),
		Tool:        fmt.Sprintf("%s %s", b.snap.Tool.Name, b.snap.Tool.Version),
		PolicyRules: make(map[string][]json.RawMessage, len(b.snap.Policies)),
	}
	for _, pol := range b.snap.Policies {
		key := fmt.Sprintf("%s/%s", pol.Kind, pol.Name)
		if pol.Namespace != "" {
			key = fmt.Sprintf("%s/%s/%s", pol.Kind, pol.Namespace, pol.Name)
		}
		g.PolicyRules[key] = pol.Rules
	}

	for _, ns := range b.snap.Namespaces {
		n := Namespace{
			Name:        ns.Name,
			DefaultDeny: defaultDeny[ns.Name],
			PolicyCount: policyCount[ns.Name],
			Workloads:   make([]Workload, 0, len(b.workloads[ns.Name])),
		}
		for _, wl := range b.workloads[ns.Name] {
			n.Workloads = append(n.Workloads, Workload{
				ID:       wl.Namespace + "/" + wl.Name,
				Name:     wl.Name,
				Kind:     wl.Kind,
				Replicas: wl.Replicas,
				Labels:   wl.Labels,
			})
		}
		g.Namespaces = append(g.Namespaces, n)
	}

	for _, ext := range b.externals {
		g.Externals = append(g.Externals, ext)
	}
	slices.SortFunc(g.Externals, func(a, b External) int { return cmp.Compare(a.ID, b.ID) })

	// Broad-allowance credit: a workload with egress to entity:cluster /
	// entity:all (or an all-CIDR) can reach any in-cluster peer without a
	// per-peer rule; same for ingress. A silent edge side backed by such an
	// allowance is covered, not half-open. This keeps the half-open signal
	// pointing at genuine gaps (visualization-grade; whatif gives verdicts).
	broadEgress, broadIngress := map[string]bool{}, map[string]bool{}
	for _, e := range b.edges {
		if !isBroad(e.Dst) && !isBroad(e.Src) {
			continue
		}
		if e.DeclaredEgress && isBroad(e.Dst) {
			broadEgress[e.Src] = true
		}
		if e.DeclaredIngress && isBroad(e.Src) {
			broadIngress[e.Dst] = true
		}
	}

	for _, e := range b.edges {
		slices.Sort(e.Ports)
		e.Ports = slices.Compact(e.Ports)
		slices.Sort(e.Policies)
		e.Policies = slices.Compact(e.Policies)
		e.Cross = crossNS(e.Src, e.Dst)
		if !e.DeclaredEgress && broadEgress[e.Src] {
			e.DeclaredEgress, e.BroadEgress = true, true
		}
		if !e.DeclaredIngress && broadIngress[e.Dst] {
			e.DeclaredIngress, e.BroadIngress = true, true
		}
		g.Edges = append(g.Edges, *e)
	}
	slices.SortFunc(g.Edges, func(a, b Edge) int {
		return cmp.Or(cmp.Compare(a.Src, b.Src), cmp.Compare(a.Dst, b.Dst))
	})

	for construct, n := range b.dropped {
		g.Warnings = append(g.Warnings, fmt.Sprintf("%d %s not rendered", n, construct))
	}
	if len(b.deadRefs) > 0 {
		g.Warnings = append(g.Warnings, fmt.Sprintf("%d selector reference(s) matched no live workload (see audit)", len(b.deadRefs)))
	}
	slices.Sort(g.Warnings)
	slices.Sort(b.deadRefs)
	g.DeadRefs = slices.Compact(b.deadRefs)

	g.Stats = Stats{
		Namespaces: len(g.Namespaces),
		Workloads:  len(b.snap.Workloads),
		Policies:   len(b.snap.Policies),
		Edges:      len(g.Edges),
	}
	for _, e := range g.Edges {
		if e.Cross {
			g.Stats.CrossEdges++
		}
	}
	return g
}

// crossNS reports whether an edge spans namespaces; edges touching an
// external pseudo-node are not namespace-crossings.
func crossNS(src, dst string) bool {
	sNS, sOK := nodeNS(src)
	dNS, dOK := nodeNS(dst)
	return sOK && dOK && sNS != dNS
}

func nodeNS(id string) (string, bool) {
	if strings.HasPrefix(id, "entity:") || strings.HasPrefix(id, "cidr:") || strings.HasPrefix(id, "fqdn:") {
		return "", false
	}
	ns, _, ok := strings.Cut(id, "/")
	return ns, ok
}

// isBroad reports whether a node ID represents an allowance wide enough to
// cover arbitrary in-cluster peers.
func isBroad(id string) bool {
	switch id {
	case "entity:cluster", "entity:all", "cidr:0.0.0.0/0", "cidr:::/0":
		return true
	}
	return false
}
