"""mapping.py — sensor findings -> attack-tree nodes -> campaign state.

The DPI sensor sees only Modbus on the OT link, so it observes the *end* of the
chain (the plant manipulation) and never the IT steps. The mapping therefore:

1. turns each ``ot_finding`` into weighted evidence on attack-tree nodes,
   using the finding class, the register it touches and the role of its
   source (looked up in the knowledge graph);
2. separates **command-level** evidence (the write itself is wrong: out of
   range, policy violation, unknown writer) from **consequence** evidence
   (derived from the voltage leaving the band: unsafe_command,
   manual_mode_excursion, voltage-driven model anomalies);
3. *explains away* consequence evidence: once one impact leaf is confirmed by
   command-level evidence, voltage-derived evidence pointing at the other
   leaves is discounted — an open breaker also makes the operator's routine
   MANUAL dispatch "unsafe", which is not a hijack;
4. infers the unobservable prerequisites (AND-earlier steps) of an observed
   step: a manipulation through the HMI implies the HMI was used.

``CampaignState.snapshot()`` is the belief handed to the response policy (the
WP2 -> WP3 interface): per node a score in [0, 1] and a state.
"""

from defense_plane import ot_registers as reg
from defense_plane.soar import kg as kgmod
from defense_plane.soar import trees

CONFIRMED, SUSPECTED, INFERRED, UNKNOWN = "confirmed", "suspected", "inferred", "unknown"
CONFIRM_AT = 0.75
SUSPECT_AT = 0.30
MODEL_WEIGHT = 0.5        # the behavioural model alone never confirms a step
EXPLAINED_AWAY = 0.4      # discount on consequence evidence once another leaf is confirmed
COMMAND, CONSEQUENCE = "command", "consequence"
IMPACT_LEAVES = ("setpoint_oor", "breaker_open", "mode_hijack")

# IT-sensor finding class -> the attack-tree step it directly confirms.
_IT_KLASS_NODE = {"web_injection_pattern": "it_access", "web_child_process": "it_exec",
                  "unexpected_modbus_client": "pivot"}
_IT_NODES = set(_IT_KLASS_NODE.values())
# Early steps whose confirmation implies the pivot is likely next (forward belief).
FORWARD_STEPS = ("it_access", "it_exec")
FORWARD_WEIGHT = 0.5

# Model features -> leaves they hint at (evidence.top of behavioral_anomaly).
#  (feature names: defense_plane/agents/ot_model.py FEATURES)
_FEATURE_HINTS = {
    "max_dsetpoint": ("setpoint_oor", "mode_hijack"),
    "mode_writes": ("mode_hijack",),
    "manual_run_s": ("mode_hijack",),
    "plc_writes": ("mode_hijack",),       # the PLC going quiet = it handed off
    "v_min": ("breaker_open",),
    "v_max": ("setpoint_oor", "mode_hijack"),
}
_VOLTAGE_FEATURES = {"v_min", "v_max"}


def evidence_from_finding(f, g):
    """One finding -> [(node_id, weight, kind)]. ``g`` is the knowledge graph,
    used to resolve the source address to a host and its role."""
    klass = f.get("klass")
    det = f.get("detector") or "rules"
    ent = f.get("entities") or {}
    name = ent.get("name")
    src_host = kgmod.host_of_ip(g, ent.get("src")) if ent.get("src") else None
    role = g.nodes[f"host:{src_host}"]["role"] if src_host else None
    conf = float(f.get("confidence") or 0.0)

    if det == "it":
        # IT-side sensor: direct, observed evidence on the early steps the OT
        # sensor can only infer (the finding carries its own target node).
        node = f.get("maps_to") or _IT_KLASS_NODE.get(klass)
        return [(node, conf, COMMAND)] if node in _IT_NODES else []

    if det == "model":
        top_z = {t.get("feature"): float(t.get("z") or 0.0)
                 for t in (f.get("evidence") or {}).get("top") or []}
        top = list(top_z)
        # z is |deviation|: an overvoltage moves v_min too. Read v_min as an
        # undervoltage (open breaker) only when it clearly dominates v_max.
        if "v_min" in top_z and top_z.get("v_max", 0.0) * 4 > top_z["v_min"]:
            top.remove("v_min")
        out, seen = [], set()
        for feat in top:
            for leaf in _FEATURE_HINTS.get(feat, ()):
                if leaf not in seen:
                    seen.add(leaf)
                    kind = CONSEQUENCE if feat in _VOLTAGE_FEATURES else COMMAND
                    out.append((leaf, MODEL_WEIGHT * conf, kind))
        return out or [("ot_action", MODEL_WEIGHT * conf, CONSEQUENCE)]

    if klass in ("unauthorized_write_to_actuator", "unauthorized_write"):
        return [("ot_write_unknown", conf, COMMAND)]
    if klass == "unauthorized_read":
        return [("ot_write_unknown", 0.5 * conf, COMMAND)]
    if klass == "out_of_range_command":
        leaf = "breaker_open" if name == "switch_cmd" else "setpoint_oor"
        return [(leaf, conf, COMMAND)]
    if klass == "policy_violation":
        if name == "switch_cmd":
            return [("breaker_open", conf, COMMAND)]
        return [("ot_action", conf, COMMAND)]
    if klass == "unsafe_command":
        if role == "plc":
            # The regulator reacting to an excursion: a symptom, not a step.
            return []
        if name == "switch_cmd":
            return [("breaker_open", conf, CONSEQUENCE)]
        if name == "ctrl_mode":
            return [("mode_hijack", conf, CONSEQUENCE)]
        if name == "dg_setpoint":
            # An unsafe setpoint *inside* the envelope is the hijack's signature
            # (legal value, wrong moment); outside it is the out-of-range leaf.
            value = (f.get("evidence") or {}).get("value")
            lo, hi = reg.ACTUATOR_REGISTERS[reg.HR_DG_SETPOINT][2:4]
            if value is not None and lo <= float(value) <= hi:
                return [("mode_hijack", conf, CONSEQUENCE)]
            if value is not None:
                return [("setpoint_oor", conf, CONSEQUENCE)]
            return [("mode_hijack", conf, CONSEQUENCE), ("setpoint_oor", conf, CONSEQUENCE)]
        return [("ot_action", conf, CONSEQUENCE)]
    if klass == "manual_mode_excursion":
        return [("mode_hijack", conf, CONSEQUENCE)]
    return []


class CampaignState:
    """Belief over the attack tree, updated finding by finding."""

    def __init__(self, tree, g):
        self.tree, self.g = tree, g
        self.idx = trees.index(tree)
        self.parents = trees.parents(tree)
        # node -> {"command": best, "consequence": best}; first/last seen; classes
        self.ev = {n: {COMMAND: 0.0, CONSEQUENCE: 0.0} for n in self.idx}
        self.first_seen, self.last_seen = {}, {}
        self.classes = {n: [] for n in self.idx}
        self.sources = set()
        self.n_findings = 0

    # ── update ───────────────────────────────────────────────────────────────
    def update(self, finding):
        """Fold one ot_finding in; returns the nodes it touched."""
        if finding.get("kind", "ot_finding") != "ot_finding":
            return []
        self.n_findings += 1
        t = finding.get("t")
        src = (finding.get("entities") or {}).get("src")
        touched = []
        for node, w, kind in evidence_from_finding(finding, self.g):
            if node not in self.idx:
                continue
            e = self.ev[node]
            e[kind] = max(e[kind], min(1.0, w))
            self.first_seen.setdefault(node, t)
            self.last_seen[node] = t
            k = finding.get("klass")
            if k not in self.classes[node]:
                self.classes[node].append(k)
            touched.append(node)
        if touched and src:
            host = kgmod.host_of_ip(self.g, src)
            if host:
                self.sources.add(host)
        return touched

    # ── read ─────────────────────────────────────────────────────────────────
    def _command_confirmed(self):
        return {n for n in IMPACT_LEAVES if n in self.idx
                and self.ev[n][COMMAND] >= CONFIRM_AT}

    def observed_scores(self):
        """Direct score per node after explaining away."""
        cmd_conf = self._command_confirmed()
        scores = {}
        for n, e in self.ev.items():
            cons = e[CONSEQUENCE]
            if cmd_conf and n not in cmd_conf and n in IMPACT_LEAVES:
                cons *= EXPLAINED_AWAY
            scores[n] = max(e[COMMAND], cons)
        return scores

    def scores(self):
        """Observed scores plus inference: prerequisites of an observed node get
        its score (state ``inferred``); gates aggregate their children (OR: max,
        AND: max over the steps, since steps are only seen at the end)."""
        obs = self.observed_scores()
        s = dict(obs)
        inferred = {}
        for n, v in obs.items():
            if v < SUSPECT_AT:
                continue
            for p in trees.prerequisites(self.tree, n):
                if v > s.get(p, 0.0):
                    s[p] = v
                    inferred[p] = True
        # Forward belief: a confirmed early IT step means the chain is under way,
        # so the pivot (the gateway to the plant) is likely next — a discounted,
        # never-confirming score so the response can act before the manipulation.
        early = max((obs.get(n, 0.0) for n in FORWARD_STEPS if obs.get(n, 0.0) >= CONFIRM_AT),
                    default=0.0)
        if early and "pivot" in self.idx:
            fwd = min(FORWARD_WEIGHT * early, CONFIRM_AT - 0.01)
            if fwd > s.get("pivot", 0.0):
                s["pivot"] = fwd
                inferred["pivot"] = True
        for node in reversed(list(self.tree.walk())):   # children before parents
            if node.children:
                s[node.id] = max([s.get(node.id, 0.0)] + [s[c.id] for c in node.children])
        return s, inferred

    def node_state(self, score, inferred=False):
        if score >= CONFIRM_AT:
            return INFERRED if inferred else CONFIRMED
        if score >= SUSPECT_AT:
            return INFERRED if inferred else SUSPECTED
        return UNKNOWN

    def snapshot(self, t=None):
        s, inferred = self.scores()
        obs = self.observed_scores()
        nodes = {}
        for n in self.idx:
            if s[n] <= 0.0:
                continue
            nodes[n] = {"score": round(s[n], 3),
                        "state": self.node_state(s[n], inferred.get(n, False) and obs[n] < s[n]),
                        "classes": list(self.classes[n]),
                        "first_seen": self.first_seen.get(n),
                        "last_seen": self.last_seen.get(n)}
        active = [n for n in IMPACT_LEAVES if n in nodes and s[n] >= SUSPECT_AT]
        hosts = sorted(h for h in self.sources
                       if self.g.nodes[f"host:{h}"]["role"] not in ("plc", "plant"))
        if any(n in nodes for n in ("it_exec", "pivot")):
            hmi = trees.cps_context(self.g)["hmi"]
            if hmi not in hosts:
                hosts.append(hmi)
        return {"t": t, "findings": self.n_findings, "nodes": nodes,
                "active_impacts": active, "hosts_implicated": sorted(hosts),
                "next": self._next_steps(s, active)}

    def _next_steps(self, s, active):
        """Impact leaves not yet seen on an active branch: what may come next."""
        if not active:
            return []
        branch = self.parents[active[0]]
        return [c.id for c in branch.children if c.id not in active and s[c.id] < SUSPECT_AT]


def replay(findings, tree, g):
    """Fold a sequence of telemetry events; yields (event, snapshot) after each
    finding that touched the tree."""
    st = CampaignState(tree, g)
    for ev in findings:
        if ev.get("kind") != "ot_finding":
            continue
        if st.update(ev):
            yield ev, st.snapshot(ev.get("t"))
