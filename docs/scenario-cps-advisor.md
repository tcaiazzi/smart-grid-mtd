# The cps-advisor scenario: the SOC suggests, a person decides

## 1. What it is for

In the `cps` scenario the SOC decides and acts: a finding confirms a step of the
attack tree, the policy picks countermeasures, the Wazuh manager runs them. Here
the same SOC, on the same lab, **acts on nothing by itself**. Every
countermeasure it would run becomes a *suggestion* — what to do, on which host,
and why — and waits for an operator, who approves or rejects it. A suggestion
nobody answers expires and is not applied: no answer is not consent.

Only `notify` stays automatic, because it runs nothing.

Everything else — plant, attack chain, sensors, knowledge graph, attack tree,
policies, metrics — is the `cps` scenario's (`docs/scenario-cps.md`,
`docs/kg-and-attack-trees.md`).

## 2. How the operator and the SOC talk

```
   lab                                              host
 ┌──────────────── soc node ────────────────┐
 │ soc_analytics.py   policy → suggestion   │   GET  /approvals        ┌──────────┐
 │        │  ▲                              │ ◀──────────────────────  │ operator │
 │        ▼  │ verdict                      │   POST /approvals/<id>   │ console  │
 │ soc_operator.py  ApprovalDesk + HTTP API │ ◀──────────────────────  │ (browser)│
 │        │ approved                        │   bearer token, CORS     └──────────┘
 │        ▼                                 │
 │ Wazuh manager → active response on agent │
 └──────────────────────────────────────────┘
```

The interface is the SOC's own: `nodes/soc/soc_operator.py`, node software,
stdlib only. It is what would be deployed with the SOC outside the lab; the
cyber range's dashboard is just one console of it.

- `GET /approvals` → `{now, pending: [...], closed: [...]}`.
- `POST /approvals/<id>` with `{"verdict": "approve" | "reject", "operator": "<name>"}`.
  The first verdict wins (`409` afterwards); an unknown or expired id is `404`.
- Every request carries `Authorization: Bearer <token>`. The API refuses to
  start without a token.
- CORS is answered only for the configured console origins.
- A verdict is applied at the analytics' next step (`--respond-interval`, 0.5 s).

The platform's part is small and read-only: the `SocAnalytics` component
mirrors the SOC's `approval` records to the ledger, and the dashboard page
draws them. The page sends the verdict from the browser straight to the SOC;
the dashboard's server and the run never write into the lab.

**What differs from a real deployment**, and nothing else is meant to: the
token is a per-run shared secret that the run publishes on the ledger so the
page can use it (a deployment puts the operators' identity and TLS in front of
the API), and the port is published by the container runtime instead of a
management network's routing.

**Exposure in the lab.** The API's port is published on the host through the
SOC node's bridged interface, and an `iptables` rule on the SOC drops it on
MGMT: the HMI, the attacker's foothold, sits on that network and must not be
able to answer in the operator's place.

## 3. What a suggestion says

Built by `ResponseEngine.explain` from what the policy already knows:

| Field | Content |
|---|---|
| `trigger` | the finding that led to it: class, detector, confidence, source |
| `prevents` / `restores` | the attack-tree nodes the action stops or undoes, each with its label, ATT&CK technique and the SOC's current belief |
| `rationale` | the policy's own justification (the playbook line, or the solver's cost comparison) |
| `countermeasure` | label, D3FEND technique, the host it runs on, the exact commands, operational and energy cost, time to effect |
| `decided_with` | the other actions of the same decision |
| `cost_terms`, `alternatives` | solver only: the expected loss of the chosen set and the non-dominated alternatives it weighed |

After a verdict:

- **approved** → requested from the manager like any automatic response; its
  outcome is an `action` record as usual;
- **rejected** → never proposed again in this run. The policy decides again on
  the same belief without it, so with `solver` the operator is offered the
  next-best set (reject `block_flow` and `isolate_hmi` is proposed);
- **expired** → dropped; it may be proposed again if new evidence arrives.

## 4. Running it

```bash
make cps-image                       # once: the same images as cps
make cps-advisor-dashboard           # terminal 1 → http://127.0.0.1:8765
make cps-advisor PLAYGROUND=1        # terminal 2: attack, then the lab stays up
```

On the dashboard, the *Operator suggestions* card appears when the attack is
detected. Each suggestion shows its reasons and a countdown; **Approve** or
**Reject** it. `PLAYGROUND=1` keeps the lab up after the episode, until Ctrl-C,
so there is no rush; without it the run ends after `CPS_ADVISOR_POST` seconds.

| Variable | Default | |
|---|---|---|
| `CPS_ADVISOR_RESPOND` | `solver` | the advising policy (`rules` or `solver`) |
| `CPS_ADVISOR_TIMEOUT` | `120` | seconds a suggestion waits for its verdict |
| `CPS_ADVISOR_POST` | `180` | post-attack observation, the operator's window |
| `CPS_OPERATOR_PORT` | `8766` | host port of the SOC's operator API |
| `CPS_ADVISOR_OUT` | `output/cps-advisor/run-1` | run directory |

The `CPS_*` variables of the `cps` scenario for durations, detectors, the
attack and IT telemetry apply unchanged (`CPS_ATTACK_MODE`, `CPS_ATTACK_DRIVER`,
`CPS_IT`, …). The dashboard must be served on `CPS_DASH_PORT` (8765): that is
the console origin the API accepts.

Without the dashboard, the API can be driven by hand; the token is in the
`run_start` event of the run's `progress.jsonl`:

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8766/approvals
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"verdict": "approve", "operator": "me"}' http://127.0.0.1:8766/approvals/<id>
```

## 5. What is recorded and scored

`response.jsonl` gains, per suggestion, an `approval` record with
`state=requested` (with `request`, `due_t`, `explanation`) and one with its
outcome (`granted` / `rejected` with `operator` and `waited_s`, or `expired`).

`make cps-metrics CPS_OUT=output/cps-advisor/run-1` scores the run as a `cps`
run, and adds under `response.operator`: `suggestions`,
`suggestions_approved`, `suggestions_rejected`, `suggestions_expired`,
`operator_latency_median_s`.

Read the response metrics with the person in mind: `decision_latency_s` now
includes the operator's time, and `accurate` is false when the operator
rejected, or did not answer, what the run needed. There is no campaign for this
scenario — a run needs someone to answer it.
