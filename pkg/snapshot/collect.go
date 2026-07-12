// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Portolan contributors

package snapshot

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
)

// pageSize bounds every List request so neither the API server nor this
// client has to materialize a whole large collection in one response.
const pageSize = 500

// GroupVersionResources Portolan reads. Nothing here is ever written.
var (
	gvrNamespaces  = schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	gvrPods        = schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	gvrReplicaSets = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}
	gvrJobs        = schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}
	gvrNetPol      = schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
	gvrCNP         = schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}
	gvrCCNP        = schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"}
)

// policySources is the single registry of policy kinds this collector
// captures. New kinds are added here (and in types.go's PolicyKind consts);
// nothing else needs to change on the collection side.
type policySource struct {
	GVR  schema.GroupVersionResource
	Kind PolicyKind
}

var policySources = []policySource{
	{gvrCNP, KindCNP},
	{gvrCCNP, KindCCNP},
	{gvrNetPol, KindNetPol},
}

// churn labels injected by controllers onto pods; no policy selects on them
// and they change on every rollout / schedule tick, so they are stripped
// from Workload.Labels to keep snapshots of identical topology identical.
var churnLabels = []string{
	"pod-template-hash",
	"controller-uid",
	"job-name",
	"batch.kubernetes.io/controller-uid",
	"batch.kubernetes.io/job-name",
}

// Collector gathers a Snapshot from one cluster. Policy objects come via the
// dynamic client (full specs, verbatim); namespaces, pods, ReplicaSets, and
// Jobs come via the metadata client (PartialObjectMetadata) since only
// ObjectMeta is needed — a large wire and heap saving on big clusters.
// Everything is read-only.
type Collector struct {
	dyn  dynamic.Interface
	meta metadata.Interface

	// podIdx is the live pod→controller index from the most recent Collect,
	// published so a long-lived flow stream can resolve peers as flows ARRIVE.
	// Timing is the whole point: a pod that has since died cannot be resolved
	// after the fact, so the streaming accumulator must ask the index that was
	// current when the flow was seen, not the one current at snapshot time.
	idxMu  sync.RWMutex
	podIdx map[nsName]workloadRef
}

// NewCollector builds a Collector from a rest.Config.
func NewCollector(cfg *rest.Config) (*Collector, error) {
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building dynamic client: %w", err)
	}
	md, err := metadata.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building metadata client: %w", err)
	}
	return &Collector{dyn: dyn, meta: md}, nil
}

// Collect captures a Snapshot. The independent list calls run concurrently.
// A policy kind whose resource is not served by the cluster (e.g. Cilium
// CRDs on a non-Cilium cluster) degrades gracefully and is recorded as
// skipped in Snapshot.Sources; any other failure aborts the snapshot.
//
// When flows.Window > 0, a bounded window of Hubble flow observations is
// captured afterwards (it needs the live-pod index the workload pass
// builds). Flow capture failure degrades — recorded in Snapshot.Flows with
// Status "error" — and never aborts the policy capture.
func (c *Collector) Collect(ctx context.Context, flows FlowOptions) (*Snapshot, error) {
	snap := &Snapshot{
		SchemaVersion: SchemaVersion,
		TakenAt:       time.Now().UTC(),
		Tool:          ToolInfo{Name: ToolName},
	}

	var (
		nss        []Namespace
		wls        []Workload
		podIdx     map[nsName]workloadRef
		polResults = make([][]Policy, len(policySources))
		statuses   = make([]SourceStatus, len(policySources))
	)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		nss, err = c.collectNamespaces(gctx)
		return err
	})
	g.Go(func() error {
		var err error
		wls, podIdx, err = c.collectWorkloads(gctx)
		return err
	})
	for i, src := range policySources {
		g.Go(func() error {
			pols, err := c.collectPolicies(gctx, src.GVR, src.Kind)
			if err != nil {
				// A missing CRD surfaces from the dynamic client as a plain
				// 404 StatusError (no RESTMapper is involved on this path).
				if apierrors.IsNotFound(err) {
					statuses[i] = SourceStatus{Kind: src.Kind, Status: "skipped", Reason: "resource not served by this cluster"}
					return nil
				}
				return fmt.Errorf("collecting %s: %w", src.Kind, err)
			}
			polResults[i] = pols
			statuses[i] = SourceStatus{Kind: src.Kind, Status: "ok", Count: len(pols)}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	c.idxMu.Lock()
	c.podIdx = podIdx
	c.idxMu.Unlock()

	snap.Namespaces = nss
	snap.Workloads = wls
	snap.Sources = statuses
	snap.Policies = make([]Policy, 0, totalLen(polResults))
	for _, pols := range polResults {
		snap.Policies = append(snap.Policies, pols...)
	}

	sortSnapshot(snap)

	if flows.Window > 0 {
		var (
			fc  *FlowCapture
			err error
		)
		if flows.Source != nil {
			// A long-lived listener already holds the window; ask it. This is
			// the only way the window can mean what it says — see FlowSource.
			fc, err = flows.Source.Capture(ctx, flows.Window)
		} else {
			fc, err = collectFlows(ctx, flows, c.Resolve)
		}
		if err != nil {
			fc = &FlowCapture{
				Status: "error",
				Reason: err.Error(),
				Server: flows.Server,
				Window: ShortDur(flows.Window),
				Edges:  []FlowEdge{},
			}
		}
		snap.Flows = fc
	}
	return snap, nil
}

// Resolve maps a pod to its controller identity using the index from the most
// recent Collect, and reports whether it was found. It is safe for concurrent
// use — the flow stream calls it from its own goroutine, continuously.
func (c *Collector) Resolve(namespace, pod string) (kind, name string, ok bool) {
	c.idxMu.RLock()
	defer c.idxMu.RUnlock()
	ref, ok := c.podIdx[nsName{namespace, pod}]
	return ref.kind, ref.name, ok
}

func totalLen(groups [][]Policy) int {
	n := 0
	for _, g := range groups {
		n += len(g)
	}
	return n
}

// eachMeta pages through a metadata-only List, invoking fn per item.
func (c *Collector) eachMeta(ctx context.Context, gvr schema.GroupVersionResource, opts metav1.ListOptions, fn func(*metav1.PartialObjectMetadata)) error {
	opts.Limit = pageSize
	for {
		list, err := c.meta.Resource(gvr).List(ctx, opts)
		if err != nil {
			return err
		}
		for i := range list.Items {
			fn(&list.Items[i])
		}
		if list.Continue == "" {
			return nil
		}
		opts.Continue = list.Continue
	}
}

func (c *Collector) collectNamespaces(ctx context.Context) ([]Namespace, error) {
	out := make([]Namespace, 0, 64)
	err := c.eachMeta(ctx, gvrNamespaces, metav1.ListOptions{}, func(item *metav1.PartialObjectMetadata) {
		out = append(out, Namespace{Name: item.Name, Labels: item.Labels})
	})
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}
	return out, nil
}

type nsName struct{ ns, name string }

// workloadRef is a resolved controller identity, used by the live-pod index
// that flow capture resolves peers against.
type workloadRef struct{ kind, name string }

// collectWorkloads lists live pods and resolves each to its topmost stable
// controller identity using real ownerReferences: ReplicaSet → owning
// Deployment, Job → owning CronJob. The owner maps come from metadata-only
// ReplicaSet/Job lists — exact lineage, no name-suffix heuristics, so bare
// ReplicaSets and Argo-Rollouts-style owners keep their true identity.
//
// The second return is the pod-level index (namespace/pod → resolved
// identity) that flow capture uses to land flow peers on the same nodes.
func (c *Collector) collectWorkloads(ctx context.Context) ([]Workload, map[nsName]workloadRef, error) {
	rsToDeploy := map[nsName]string{}
	err := c.eachMeta(ctx, gvrReplicaSets, metav1.ListOptions{}, func(item *metav1.PartialObjectMetadata) {
		if ref := metav1.GetControllerOfNoCopy(item); ref != nil && ref.Kind == "Deployment" {
			rsToDeploy[nsName{item.Namespace, item.Name}] = ref.Name
		}
	})
	if err != nil {
		return nil, nil, fmt.Errorf("listing replicasets: %w", err)
	}

	jobToCron := map[nsName]string{}
	err = c.eachMeta(ctx, gvrJobs, metav1.ListOptions{}, func(item *metav1.PartialObjectMetadata) {
		if ref := metav1.GetControllerOfNoCopy(item); ref != nil && ref.Kind == "CronJob" {
			jobToCron[nsName{item.Namespace, item.Name}] = ref.Name
		}
	})
	if err != nil {
		return nil, nil, fmt.Errorf("listing jobs: %w", err)
	}

	type gkey struct{ ns, kind, name string }
	type group struct {
		labels   map[string]string
		labelSrc string // pod name the labels came from; lexicographic-min pod wins for determinism
		replicas int
	}
	groups := map[gkey]*group{}
	podIdx := map[nsName]workloadRef{}

	// Terminal pods (Succeeded/Failed — completed Jobs, evicted pods) have
	// no network presence; the field selector excludes them server-side.
	podOpts := metav1.ListOptions{FieldSelector: "status.phase!=Succeeded,status.phase!=Failed"}
	err = c.eachMeta(ctx, gvrPods, podOpts, func(item *metav1.PartialObjectMetadata) {
		kind, name := resolveController(item, rsToDeploy, jobToCron)
		podIdx[nsName{item.Namespace, item.Name}] = workloadRef{kind, name}
		k := gkey{item.Namespace, kind, name}
		g, ok := groups[k]
		if !ok {
			g = &group{}
			groups[k] = g
		}
		g.replicas++
		if g.labelSrc == "" || item.Name < g.labelSrc {
			g.labelSrc = item.Name
			g.labels = cleanLabels(item.Labels)
		}
	})
	if err != nil {
		return nil, nil, fmt.Errorf("listing pods: %w", err)
	}

	out := make([]Workload, 0, len(groups))
	for k, g := range groups {
		out = append(out, Workload{
			Namespace: k.ns,
			Name:      k.name,
			Kind:      k.kind,
			Labels:    g.labels,
			Replicas:  g.replicas,
		})
	}
	return out, podIdx, nil
}

// resolveController maps a pod to its topmost stable controller identity.
func resolveController(pod *metav1.PartialObjectMetadata, rsToDeploy, jobToCron map[nsName]string) (kind, name string) {
	ref := metav1.GetControllerOfNoCopy(pod)
	if ref == nil {
		return "Pod", pod.Name
	}
	switch ref.Kind {
	case "ReplicaSet":
		if d, ok := rsToDeploy[nsName{pod.Namespace, ref.Name}]; ok {
			return "Deployment", d
		}
	case "Job":
		if cj, ok := jobToCron[nsName{pod.Namespace, ref.Name}]; ok {
			return "CronJob", cj
		}
	}
	return ref.Kind, ref.Name
}

// cleanLabels copies a pod's labels minus controller-injected churn labels.
func cleanLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[k] = v
	}
	for _, k := range churnLabels {
		delete(out, k)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// collectPolicies pages through one policy resource via the dynamic client,
// capturing rule payloads verbatim.
func (c *Collector) collectPolicies(ctx context.Context, gvr schema.GroupVersionResource, kind PolicyKind) ([]Policy, error) {
	var out []Policy
	opts := metav1.ListOptions{Limit: pageSize}
	for {
		list, err := c.dyn.Resource(gvr).List(ctx, opts)
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			item := &list.Items[i]
			rules, err := rawRules(item)
			if err != nil {
				return nil, fmt.Errorf("%s %s/%s: %w", kind, item.GetNamespace(), item.GetName(), err)
			}
			out = append(out, Policy{
				Kind:       kind,
				Namespace:  item.GetNamespace(), // "" for cluster-scoped kinds
				Name:       item.GetName(),
				APIVersion: item.GetAPIVersion(),
				Labels:     item.GetLabels(),
				Rules:      rules,
			})
		}
		if list.GetContinue() == "" {
			return out, nil
		}
		opts.Continue = list.GetContinue()
	}
}

// rawRules extracts every rule payload verbatim. Cilium policies may carry
// .spec, .specs, or both simultaneously — all forms are enforced by Cilium,
// so all are captured: .spec first, then each element of .specs, per the
// schema contract on Policy.Rules.
func rawRules(item *unstructured.Unstructured) ([]json.RawMessage, error) {
	var rules []json.RawMessage
	if spec, ok := item.Object["spec"]; ok && spec != nil {
		raw, err := json.Marshal(spec)
		if err != nil {
			return nil, err
		}
		rules = append(rules, raw)
	}
	if specs, ok := item.Object["specs"].([]any); ok {
		for _, s := range specs {
			raw, err := json.Marshal(s)
			if err != nil {
				return nil, err
			}
			rules = append(rules, raw)
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("object has neither .spec nor .specs")
	}
	return rules, nil
}

// sortSnapshot makes output deterministic so identical cluster state yields
// byte-identical snapshots (modulo takenAt) — a property history diffing
// depends on. Every comparator chain covers the full uniqueness key of its
// collection.
func sortSnapshot(s *Snapshot) {
	slices.SortFunc(s.Namespaces, func(a, b Namespace) int {
		return cmp.Compare(a.Name, b.Name)
	})
	slices.SortFunc(s.Workloads, func(a, b Workload) int {
		return cmp.Or(
			cmp.Compare(a.Namespace, b.Namespace),
			cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Name, b.Name),
		)
	})
	slices.SortFunc(s.Policies, func(a, b Policy) int {
		return cmp.Or(
			cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Namespace, b.Namespace),
			cmp.Compare(a.Name, b.Name),
		)
	})
	slices.SortFunc(s.Sources, func(a, b SourceStatus) int {
		return cmp.Compare(a.Kind, b.Kind)
	})
}
