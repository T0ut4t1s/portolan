<p align="center">
  <img src="assets/portolan.svg" alt="Portolan" width="104" height="104">
</p>

<h1 align="center">Portolan</h1>

<p align="center">
  <strong>A chart of every permitted passage in your Cilium cluster.</strong><br>
  See the allow-topology, catch half-open policy gaps, and simulate a change's
  blast radius — with verdicts from Cilium's own engine — before it ships.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: AGPL-3.0-or-later" src="https://img.shields.io/badge/license-AGPL--3.0--or--later-5b6cf0"></a>
  <img alt="Status: early but working" src="https://img.shields.io/badge/status-early%20but%20working-0f9c8c">
  <img alt="Cluster access: read-only" src="https://img.shields.io/badge/cluster%20access-read--only-63678a">
</p>

<p align="center">
  <img src="assets/overview.png" width="900"
       alt="The Portolan map: every namespace's workloads and the cross-namespace passages between them, aggregated at a glance.">
</p>

In a cluster with hundreds of CiliumNetworkPolicies across dozens of namespaces,
nobody holds the allow-topology in their head. Hubble shows you the traffic that
*happened*; Portolan shows you the traffic that is *permitted* — and the gaps
where the two disagree.

## Highlights

- 🗺️ **The whole chart, one file.** Every declared allow-edge — namespaces,
  workloads, ports, direction — rendered as a self-contained HTML map. No
  database, no backend required to view it.
- 🔎 **Catches half-open passages.** Traffic allowed *out* of one namespace but
  never *into* the default-deny namespace it targets — a one-sided-rule
  misconfiguration that's invisible in raw YAML. Portolan flags every one.
- 🧪 **Verdict-grade what-if.** Draft a policy change and see exactly what it
  opens, what it closes, which half-opens it heals or introduces, and which
  **live flows it would break** — computed by *Cilium's own policy engine*
  linked in-process, not a reimplementation. Millions of pair/port verdicts in
  seconds.
- 👁️ **Declared vs. observed, joined.** Overlay a bounded Hubble window: declared
  edges that carried real traffic animate; undeclared traffic draws as ghosts;
  denials draw red. Observed and declared join on the same workload identities.
- 🔒 **Read-only by design.** `get`/`list`/`watch` only — it never writes to your
  cluster. Authoring output is YAML for *you* to review and commit.

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
- **Map** — renders a snapshot as a directional, port-labeled graph in one
  self-contained HTML file: namespace boundaries, default-deny coverage,
  cross-namespace allows, and **half-open passages** (traffic allowed out of
  one namespace but not into the default-deny namespace it targets — a
  misconfiguration class that is invisible in raw YAML). Hubble shows you the
  traffic that *happened*; Portolan shows you the traffic that is *permitted*.
- **Passage query** — ask the map "can A reach B?" and get a verdict card:
  declared (with ports and the policies on each side), half-open (with the
  fix location named), or no passage (with what A may reach and what B
  accepts, so the missing rule's home is obvious).
- **Audit** — `portolan audit` (and the map's findings lens) reports half-open
  passages, namespaces without default-deny, workloads with declared ingress
  from the world, and selector references that match nothing.
  `--fail-on-findings` makes it a CI gate. Add `--brief findings.md` to emit
  a Markdown **investigation brief** — findings restructured as instructions
  for an LLM agent (or a human) with read access: evidence, ready-to-run
  verification commands, benign explanations to rule out, and orders to
  verify live state before concluding anything.

<p align="center">
  <img src="assets/findings.png" width="880"
       alt="The findings lens: the map contracts to every half-open passage while the inspector lists them with one-click passage checks.">
</p>

- **Diff** — `portolan diff old.json new.json` compares two snapshots:
  policies added/removed/changed and the derived allow-edges that appeared or
  vanished. `--exit-code` for pipelines.
- **Observe** — `--flows 15m` reads a bounded look-back window from Hubble
  Relay and records what the datapath actually did, aggregated to workload
  granularity: observed edges, verdicts, and drop reasons (`POLICY_DENIED`
  drops are misconfiguration leads). Flow peers resolve to the same
  controller identities the policy map draws, so observed and declared edges
  join cleanly. Honesty metadata included: if Hubble's ring buffer covered
  less than the requested window, `flows.oldestFlow` says so.

  On the map, observation becomes texture: declared edges that carried real
  traffic **animate**; traffic with no per-pair declared edge (riding a
  broad allowance or an unpolicied namespace) draws as a dotted **ghost**;
  denials draw **red** and always show. The Display menu's findings lenses
  act as filters — enable `half-open` or `dropped` and the map contracts to
  those findings in the context of everything the involved workloads may
  reach. An `unmatched selectors` lens renders selector references matching
  no live workload as phantom nodes docked where the missing workload would
  sit — dormant rules you can see, hover, and trace to their declaring policy.
- **What-if** — `portolan whatif -i snapshot.json -f draft.yaml` computes the
  blast radius of a draft change (add, replace, or `--delete`) before it
  ships: passages it opens (flagging which heal existing half-opens),
  passages it removes, and **half-opens it would introduce** — the
  one-sided-rule mistake caught at review time instead of in production.
  With flow data in the snapshot it also reports which observed drops the
  draft fixes and which observed live flows it would **break**
  (`--fail-on-break` gates CI on that). Verdicts come from Cilium's own
  policy engine linked in-process — the same distillation pipeline the
  agent uses to program the datapath, fed identities built exactly the way
  the agent labels endpoints — not a reimplementation. Millions of
  pair/port verdicts compute in seconds. Add `-o whatif.html` for the
  **delta map**: the diff rendered visually — green passages the draft
  opens, red ones it closes, half-open and broken-live-flow badges — in
  the map's visual language, as a single self-contained file.
- **What-if panel (dashboard)** — in serve mode the map gains an
  interactive what-if: draft simplified allow rules (from, to, ports,
  sides) against live autocomplete, and the server simulates them with
  the Cilium engine on the latest snapshot. Projected passages march
  green over the current view, one-sided rules flag the half-open they'd
  introduce, and per-rule **generate** hands you the exact
  CiliumNetworkPolicy YAML that was simulated — one builder feeds both,
  so the preview cannot drift from the output. Projections persist as an
  overlay while you explore.

<p align="center">
  <img src="assets/whatif.png" width="880"
       alt="What-if in the dashboard: one drafted allow rule, simulated by Cilium's engine — it heals a half-open but breaks five observed live flows and closes fourteen passages.">
</p>

> The screenshot above is the whole point: a naive "just add an allow rule"
> looks harmless, but simulating it against the real engine shows it would
> **break five live flows** and close fourteen passages — because adding any
> ingress rule flips the target out of its broad default. That's the blast
> radius you want to see at review time, not in an incident.

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

# Also capture what the datapath actually did (drops included) — needs
# Hubble Relay; from outside the cluster, port-forward it first:
#   kubectl -n kube-system port-forward svc/hubble-relay 4245:80
portolan snapshot --flows 15m --hubble-server localhost:4245 -o snapshot.json

# Keeping history? Timestamp the filenames — diffs between any two answer
# "what changed":
portolan snapshot -o "snapshots/$(date +%Y%m%dT%H%M%S).json"

# Render the map — a single HTML file, open it anywhere:
portolan render -i snapshot.json -o map.html

# Findings report (half-open passages, deny gaps, dead selector refs):
portolan audit -i snapshot.json

# What changed in the mesh between two captures?
portolan diff snapshots/monday.json snapshots/today.json

# Simulate a draft policy before it ships (text verdicts + visual delta map):
portolan whatif -i snapshot.json -f draft-cnp.yaml -o whatif.html
portolan whatif -i snapshot.json --delete CiliumNetworkPolicy/ns/name --fail-on-break

# Or run the dashboard in-cluster (or anywhere with a kubeconfig):
portolan serve --interval 15m --data /data
#   GET /              the map        GET /audit.json     findings
#   GET /brief.md      LLM handoff    GET /snapshots/     history archive
#   GET /healthz       liveness       GET /snapshot.json  latest capture
#   POST /api/whatif   simulate simplified allow rules (the map's panel)
```

A Helm chart for the in-cluster dashboard lives in [`charts/portolan`](charts/portolan).

## Status

Early but working: `snapshot`, `render`, `audit`, `diff`, `serve`, and
`whatif` function today. The snapshot schema is versioned; breaking changes
bump the version.

## License

[AGPL-3.0-or-later](LICENSE). Deploying and using Portolan carries no
obligations; if you modify it and offer it to others as a network service, you
must offer them your modified source too.
