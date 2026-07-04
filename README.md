# Portolan

**Charts of permitted passage for Cilium clusters** — visualize cross-namespace
network policy topology and simulate the blast radius of policy changes before
they ship.

## Why "Portolan"?

A *portolan* is a medieval nautical chart. Unlike maps that drew coastlines for
their own sake, portolan charts existed for one purpose: showing sailors the
**permitted passages between ports** — the routes you could actually take.

That is exactly what this tool draws for your cluster: every route traffic is
allowed to take, port numbers and all. Anything off the charted paths gets
dropped. In a cluster with hundreds of CiliumNetworkPolicies spread across
dozens of namespaces, nobody holds that chart in their head — Portolan draws it.

## What it does

- **Snapshot** — captures every declared policy (CiliumNetworkPolicy,
  CiliumClusterwideNetworkPolicy, and native NetworkPolicy), plus the
  namespaces and workloads they select, into one deterministic JSON artifact.
  Working today.
- **Map** *(in development)* — renders a snapshot as a directional,
  port-labeled graph, with namespace boundaries and default-deny coverage made
  visible. Hubble shows you the traffic that *happened*; Portolan shows you the
  traffic that is *permitted*.
- **What-if** *(roadmap)* — feed it a draft policy and get the blast radius:
  which flows it newly permits, which observed drops it would fix, what it
  removes. Powered by Cilium's own policy engine, not a reimplementation — so
  verdicts match what the CNI will actually do.
- **Observe** *(roadmap)* — overlay a bounded Hubble capture window on the map:
  observed-vs-declared edges, drop highlighting, and unused-rule detection.

## What it deliberately does not do

- **It never writes to your cluster.** Portolan is read-only by design
  (`get`/`list`/`watch` on policies, namespaces, and pods — nothing else).
  Authoring output is YAML for *you* to review and commit; your GitOps pipeline
  stays the single path to change.
- **It is not a flow-forensics platform.** Observation uses short capture
  windows, not streaming retention.
- **It is not a single-policy editor.** For that,
  [editor.networkpolicy.io](https://editor.networkpolicy.io) already exists.

## Architecture

Everything is a producer or consumer of one artifact — the snapshot:

```
portolan snapshot ──► snapshot.json ──► portolan render   (static HTML map)
 (CLI or in-cluster        │
  serve mode)              ├──────────► portolan whatif   (blast radius of a draft policy)
                           │
                           └──────────► portolan serve    (dashboard: collects on an
                                                           interval, serves the map)
```

`snapshot.json` is the stable contract: namespaces, workloads, raw policy
rules, and per-source collection status (so a degraded capture is
distinguishable from a healthy zero-policy cluster). History is just a
directory of timestamped snapshots; diffing two of them answers "what changed
in the mesh since Tuesday." No database — snapshots are immutable files.

## Quick start

```sh
# Point at any cluster you can read (uses your kubeconfig, kubectl-style):
portolan snapshot -o snapshot.json

# Keeping history? Timestamp the filenames — diffs between any two answer
# "what changed":
portolan snapshot -o "snapshots/$(date +%Y%m%dT%H%M%S).json"
```

`render`, `whatif`, and the in-cluster `serve` dashboard (with a Helm chart)
are in development — the CLI stubs exist but return "not implemented yet".

## Status

Early. The snapshot collector works today; rendering is the current focus.
The snapshot schema is versioned; breaking changes bump the version.

## License

[AGPL-3.0-or-later](LICENSE). Deploying and using Portolan carries no
obligations; if you modify it and offer it to others as a network service, you
must offer them your modified source too.
