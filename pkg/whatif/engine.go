// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

// Package whatif computes the blast radius of draft policy changes:
// which passages a change adds, removes, half-opens, and what it does to
// traffic actually observed in the snapshot's Hubble window.
//
// Verdicts are VERDICT-GRADE: they come from Cilium's own policy engine
// (pkg/policy Repository → DistillPolicy → Lookup — the same pipeline the
// agent uses to program the datapath, and the same calls cilium's own
// policy.LookupFlow test helper makes). Portolan never reimplements
// evaluation; it only builds the engine's inputs from the snapshot.
package whatif

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"

	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	ciliumk8s "github.com/cilium/cilium/pkg/k8s"
	k8sutils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/spanstat"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/u8proto"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/T0ut4t1s/portolan/pkg/snapshot"
)

// clusterName is the Cilium cluster name assumed when building identities
// and parsing rules. It must match the cluster's `cluster-name` setting for
// entity:cluster and cross-cluster label matching to behave identically.
const clusterName = "default"

func init() {
	// EntitySelectorMapping[cluster] is empty until initialized — without
	// this, `toEntities: [cluster]` (the standard broad allowance) would
	// silently match nothing and every verdict involving it would be wrong.
	api.InitEntities(clusterName)
}

// node is one probe endpoint: a snapshot workload or a reserved entity,
// carrying the same node ID the graph/map uses plus its Cilium identity.
type node struct {
	ID string // "ns/name" or "entity:world"
	id *identity.Identity
}

// probeEntities are the reserved identities probed as peers alongside
// workloads. Health is deliberately absent (Cilium-internal noise).
var probeEntities = []struct {
	name string
	ni   identity.NumericIdentity
}{
	{"world", identity.ReservedIdentityWorld},
	{"host", identity.ReservedIdentityHost},
	{"remote-node", identity.ReservedIdentityRemoteNode},
	{"kube-apiserver", identity.ReservedIdentityKubeAPIServer},
}

// buildNodes constructs a Cilium identity per snapshot workload, labeled
// exactly the way the agent labels endpoints: pod labels plus the
// namespace, cluster, and namespace-object labels, all with the k8s
// source. Reserved entities come from Cilium's own reserved table.
func buildNodes(snap *snapshot.Snapshot) ([]node, identity.IdentityMap) {
	nsLabels := map[string]map[string]string{}
	for _, ns := range snap.Namespaces {
		nsLabels[ns.Name] = ns.Labels
	}

	var nodes []node
	idmap := identity.IdentityMap{}
	next := identity.NumericIdentity(1000)
	for _, wl := range snap.Workloads { // snapshot order is deterministic
		lbls := labels.LabelArray{
			labels.NewLabel("io.kubernetes.pod.namespace", wl.Namespace, labels.LabelSourceK8s),
			labels.NewLabel("io.cilium.k8s.policy.cluster", clusterName, labels.LabelSourceK8s),
		}
		for k, v := range nsLabels[wl.Namespace] {
			lbls = append(lbls, labels.NewLabel("io.cilium.k8s.namespace.labels."+k, v, labels.LabelSourceK8s))
		}
		for k, v := range wl.Labels {
			lbls = append(lbls, labels.NewLabel(k, v, labels.LabelSourceK8s))
		}
		id := identity.NewIdentityFromLabelArray(next, lbls.Sort())
		nodes = append(nodes, node{ID: wl.Namespace + "/" + wl.Name, id: id})
		idmap[next] = id.LabelArray
		next++
	}
	for _, e := range probeEntities {
		id := identity.LookupReservedIdentity(e.ni)
		nodes = append(nodes, node{ID: "entity:" + e.name, id: id})
	}
	// All reserved identities go into the selector cache (selectors like
	// entity:cluster expand to several reserved labels).
	for ni, la := range identity.ListReservedIdentities() {
		idmap[ni] = la
	}
	return nodes, idmap
}

// engine wraps one policy repository built from one policy set, with
// per-subject distilled policies cached for batch lookups.
type engine struct {
	logger   *slog.Logger
	repo     *policy.Repository
	idmgr    identitymanager.IDManager
	epps     map[identity.NumericIdentity]*policy.EndpointPolicy
	Warnings []string
}

// policyOwner is the minimal policy.PolicyOwner needed for distillation
// (mirrors the endpointInfo in cilium's pkg/policy/lookup.go). Named ports
// are not resolvable from a snapshot, so they look up as 0.
type policyOwner struct{ id uint64 }

func (o *policyOwner) GetID() uint64 { return o.id }
func (o *policyOwner) GetNamedPort(ingress bool, name string, proto u8proto.U8proto) uint16 {
	return 0
}
func (o *policyOwner) PolicyDebug(msg string, attrs ...any) {}
func (o *policyOwner) IsHost() bool                         { return false }
func (o *policyOwner) PreviousMapState() *policy.MapState   { return nil }
func (o *policyOwner) RegenerateIfAlive(_ *regeneration.ExternalRegenerationMetadata) <-chan bool {
	ch := make(chan bool)
	close(ch)
	return ch
}

type policyStats struct {
	wait spanstat.SpanStat
	calc spanstat.SpanStat
}

func (s *policyStats) WaitingForPolicyRepository() *spanstat.SpanStat { return &s.wait }
func (s *policyStats) SelectorPolicyCalculation() *spanstat.SpanStat  { return &s.calc }

// newEngine builds a repository from the given policy set and pre-loads
// every node identity, following the exact construction cilium's own
// LookupFlow tests use.
func newEngine(pols []snapshot.Policy, nodes []node, idmap identity.IdentityMap) (*engine, error) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	idmgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(logger, idmap, nil, nil, idmgr, testpolicy.NewPolicyMetricsNoop())
	repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())

	e := &engine{
		logger: logger,
		repo:   repo,
		idmgr:  idmgr,
		epps:   map[identity.NumericIdentity]*policy.EndpointPolicy{},
	}

	var rules api.Rules
	for _, pol := range pols {
		prov := provenance(pol)
		switch pol.Kind {
		case snapshot.KindCNP, snapshot.KindCCNP:
			for _, raw := range pol.Rules {
				var r api.Rule
				if err := json.Unmarshal(raw, &r); err != nil {
					e.Warnings = append(e.Warnings, fmt.Sprintf("%s: unparseable rule skipped: %v", prov, err))
					continue
				}
				// Same sequence as the agent's CiliumNetworkPolicy.Parse:
				// Sanitize FIRST (it converts `k8s:`-prefixed selector keys
				// to the internal form), THEN ParseToCiliumRule (it injects
				// the implicit same-namespace scoping and the provenance
				// labels verdicts are traced back through).
				if err := r.Sanitize(); err != nil {
					e.Warnings = append(e.Warnings, fmt.Sprintf("%s: rule rejected by cilium validation: %v", prov, err))
					continue
				}
				parsed := k8sutils.ParseToCiliumRule(logger, clusterName, pol.Namespace, pol.Name,
					k8stypes.UID("portolan-"+prov), &r)
				rules = append(rules, parsed)
			}
		case snapshot.KindNetPol:
			for _, raw := range pol.Rules {
				var spec slim_networkingv1.NetworkPolicySpec
				if err := json.Unmarshal(raw, &spec); err != nil {
					e.Warnings = append(e.Warnings, fmt.Sprintf("%s: unparseable spec skipped: %v", prov, err))
					continue
				}
				np := &slim_networkingv1.NetworkPolicy{
					ObjectMeta: slim_metav1.ObjectMeta{Name: pol.Name, Namespace: pol.Namespace},
					Spec:       spec,
				}
				entries, err := ciliumk8s.ParseNetworkPolicy(logger, clusterName, np)
				if err != nil {
					e.Warnings = append(e.Warnings, fmt.Sprintf("%s: rejected by cilium netpol parser: %v", prov, err))
					continue
				}
				repo.MustAddPolicyEntries(entries)
			}
		default:
			e.Warnings = append(e.Warnings, fmt.Sprintf("%s: unsupported policy kind for whatif", prov))
		}
	}
	if len(rules) > 0 {
		repo.MustAddList(rules)
	}
	for _, n := range nodes {
		idmgr.Add(n.id)
	}
	return e, nil
}

// epp returns the distilled endpoint policy for one subject, cached. This
// is the batched form of what policy.LookupFlow does per call: distill
// once, look up many peer/port keys against it.
func (e *engine) epp(n node) (*policy.EndpointPolicy, error) {
	if p, ok := e.epps[n.id.ID]; ok {
		return p, nil
	}
	selPol, _, err := e.repo.GetSelectorPolicy(n.id, 0, &policyStats{}, uint64(n.id.ID))
	if err != nil {
		return nil, fmt.Errorf("selector policy for %s: %w", n.ID, err)
	}
	owner := &policyOwner{id: uint64(n.id.ID)}
	p := selPol.DistillPolicy(e.logger, owner, nil)
	p.Ready()
	p.Detach(e.logger)
	e.epps[n.id.ID] = p
	return p, nil
}

// verdict is one directed pair+port decision, split by side.
type verdict struct {
	Egress  bool // allowed to leave src
	Ingress bool // allowed to enter dst
	// EgressVia/IngressVia carry the responsible rules' provenance.
	EgressVia  []string
	IngressVia []string
}

func (v verdict) Allowed() bool { return v.Egress && v.Ingress }

// lookup computes the verdict for src → dst on one port/proto — the same
// two key lookups policy.LookupFlow performs.
func (e *engine) lookup(src, dst node, proto u8proto.U8proto, port uint16) (verdict, error) {
	var v verdict
	sp, err := e.epp(src)
	if err != nil {
		return v, err
	}
	dp, err := e.epp(dst)
	if err != nil {
		return v, err
	}
	egKey := policy.EgressKey().WithIdentity(dst.id.ID).WithPortProto(proto, port)
	egEntry, egMeta, _ := sp.Lookup(egKey)
	v.Egress = !egEntry.IsDeny()
	v.EgressVia = provFromRuleMeta(egMeta)

	inKey := policy.IngressKey().WithIdentity(src.id.ID).WithPortProto(proto, port)
	inEntry, inMeta, _ := dp.Lookup(inKey)
	v.Ingress = !inEntry.IsDeny()
	v.IngressVia = provFromRuleMeta(inMeta)
	return v, nil
}

// provFromRuleMeta extracts "Kind/ns/name" provenance strings from the
// engine's rule-origin labels.
func provFromRuleMeta(meta policy.RuleMeta) []string {
	set := map[string]bool{}
	for _, la := range meta.LabelArray() {
		var kind, ns, name string
		for _, l := range la {
			switch l.Key {
			case "io.cilium.k8s.policy.derived-from":
				kind = l.Value
			case "io.cilium.k8s.policy.namespace":
				ns = l.Value
			case "io.cilium.k8s.policy.name":
				name = l.Value
			}
		}
		if name == "" {
			continue
		}
		p := name
		if ns != "" {
			p = ns + "/" + name
		}
		if kind != "" {
			p = kind + "/" + p
		}
		set[p] = true
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func provenance(pol snapshot.Policy) string {
	if pol.Namespace == "" {
		return fmt.Sprintf("%s/%s", pol.Kind, pol.Name)
	}
	return fmt.Sprintf("%s/%s/%s", pol.Kind, pol.Namespace, pol.Name)
}
