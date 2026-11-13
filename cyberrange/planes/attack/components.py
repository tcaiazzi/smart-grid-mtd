"""components.py — attack plane building blocks (see cyberrange/core).

Every attack records what it really did in the run's ground truth (host-only):

    VulnApp              the deliberately vulnerable diagnostics web app (CPS foothold)
    ScriptedChain        fixed per-mode chain: RCE -> pivot -> unauthorized Modbus writes
    PlannedAttacker      reactive, tree-guided attacker, run in the lab (red_agent.py)
    RedConsole           the same steps, run by a person from a console on the attacker
    PassiveFingerprinter sniff -> CNN fingerprint of the nanogrid -> pick the IP to block
    DeliveryAttack       blackhole episodes + benign faults (cyberrange/detection_scenario)

Attack components that act during a phase expose ``attack(ctx)`` (blocking);
the scenario calls it inside its attack phase.
"""

import base64
import json
import logging
import os

from cyberrange.planes.attack import active_attack
from cyberrange.core.component import Artifact, Component, GuestAgent, TelemetryCursor, tail_reader

log = logging.getLogger("cyberrange.planes.attack.components")

PLANE = "attack"


# ── cyber-physical ────────────────────────────────────────────────────────────
class VulnApp(GuestAgent):
    """The diagnostics web app with a command injection; ``access_log`` makes
    its requests observable to the IT sensor."""

    SCRIPT = "vuln_app.py"  # names the process a shell got through it descends from

    def __init__(self, node, port, access_log=None):
        access = f" --access-log {access_log}" if access_log else ""
        arts = (
            [Artifact(node, access_log, f"{node}.{os.path.basename(access_log)}")]
            if access_log
            else []
        )
        super().__init__(
            node,
            f"python3 {self.SCRIPT} --host 0.0.0.0 --port {port}{access}",
            "vuln_app.log",
            plane=PLANE,
            name="vuln_app",
            artifacts=arts,
        )


def emit_attack_writes(ctx):
    """Put the attack's Modbus writes (from the ground truth) on the ledger."""
    try:
        with open(ctx.gt.path) as f:
            for line in f:
                ev = json.loads(line)
                if ev.get("kind") == "modbus_write":
                    ctx.emit(
                        "attack_write",
                        register=ev.get("register"),
                        register_name=ev.get("register_name"),
                        value=ev.get("value"),
                        ok=ev.get("ok"),
                        write_t=ev.get("t"),
                    )
    except Exception as e:
        log.debug("could not replay ground truth: %s", e)


class _ExploitDriver(Component):
    plane = PLANE
    node = "attacker"

    def __init__(self, target_url, engine_ip, engine_port, interval=0.5):
        self.target_url, self.engine_ip, self.engine_port = target_url, engine_ip, engine_port
        self.interval = interval

    def artifacts(self):
        return [Artifact(self.node, "/exploit.log", f"{self.node}.exploit.log")]


class ScriptedChain(_ExploitDriver):
    """The fixed chain of one attack mode (exploit_client.py --attack MODE)."""

    name = "scripted_chain"

    def __init__(self, mode, target_url, engine_ip, engine_port, repeat=None, interval=0.5):
        super().__init__(target_url, engine_ip, engine_port, interval)
        self.mode, self.repeat = mode, repeat

    @property
    def label(self):
        return self.mode

    def attack(self, ctx):
        rc = active_attack.drive_attack(
            ctx.manager,
            ctx.machine(self.node),
            ctx.gt,
            target_url=self.target_url,
            engine_ip=self.engine_ip,
            engine_port=self.engine_port,
            attack_mode=self.mode,
            repeat=self.repeat,
            interval=self.interval,
        )
        emit_attack_writes(ctx)
        return rc


class PlannedAttacker(_ExploitDriver):
    """A reactive attacker choosing each step on an attack tree of the lab, by
    profile (opportunistic | targeted | stealthy). The planner runs in the lab
    (nodes/redteam/red_agent.py): this component launches it with the tree as
    data and reconstructs the ground truth from the record it leaves, so the
    oracle stays off the lab and the DPI sensor never sees it."""

    name = "planned_attacker"
    RECORD = "/red_actions.jsonl"
    LOG = "/red_agent.log"

    def __init__(
        self,
        profile,
        target_url,
        engine_ip,
        engine_port,
        goal=None,
        dwell=0.0,
        max_steps=12,
        interval=0.5,
        tree=None,
    ):
        super().__init__(target_url, engine_ip, engine_port, interval)
        self.profile, self.goal, self.dwell, self.max_steps = profile, goal, dwell, max_steps
        # ctx -> the attack tree as a document (tree_doc). The scenario supplies
        # it: which tree describes a lab is the scenario's knowledge, and the
        # attacker reads a document, never the defender's code.
        self.tree = tree

    @property
    def label(self):
        return f"planner:{self.profile}"

    def artifacts(self):
        return [
            Artifact(self.node, self.LOG, f"{self.node}.red_agent.log"),
            Artifact(self.node, self.RECORD, f"{self.node}.red_actions.jsonl"),
        ]

    def attack(self, ctx):
        tree_b64 = base64.b64encode(json.dumps(self.tree(ctx)).encode()).decode()
        goal = f"--goal {self.goal} " if self.goal else ""
        seed = f"--seed {ctx.seed} " if ctx.seed is not None else ""
        cmd = (
            f'bash -c "set -o pipefail; PYTHONUNBUFFERED=1 python3 red_agent.py '
            f"--tree-b64 {tree_b64} --profile {self.profile} {goal}{seed}"
            f"--dwell {self.dwell} --max-steps {self.max_steps} "
            f"--target-url {self.target_url} --engine-ip {self.engine_ip} "
            f"--engine-port {self.engine_port} --interval {self.interval} "
            f'--record {self.RECORD} 2>&1 | tee {self.LOG}"'
        )
        log.info("[Attack] autonomous red agent (planner:%s) on %s", self.profile, self.node)
        # Blocks until the in-lab agent exits; then its record is the only source
        # of truth about what it did (the planner decided in the lab, not here).
        out, _err, rc = ctx.run(self.node, cmd, wait=True)
        return self._reconstruct(ctx, rc, (out or b"").decode(errors="replace"))

    def _reconstruct(self, ctx, rc, output):
        """Replay the agent's record into the ground truth and the ledger:
        attack_start, per-step plan_step, the Modbus writes, the foothold,
        attack_end. ``rc`` and ``output`` are the agent's own, to report a record
        that is missing or cut short."""
        summary = {"success": False, "stage_reached": "none", "writes_ok": 0}
        if ctx.gt is None:
            return summary
        seen = set()
        for line in ctx.exec_text(self.node, f"cat {self.RECORD}").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            seen.add(row.get("kind"))
            self._record_row(ctx, row, summary)
        tail = output[-500:].strip()
        if "attack_start" not in seen:
            # A run asked to attack whose ground truth holds no attack is scored
            # as a quiet one, every finding a false alarm: fail it instead.
            raise RuntimeError(f"the red agent left no record on {self.node} (rc={rc}): {tail}")
        if "attack_end" not in seen:
            # The agent died mid-attack. What it did is on record; the attack is
            # closed here, or the metrics would find no outcome for it.
            log.warning("red agent stopped before its attack_end (rc=%s): %s", rc, tail)
            ctx.gt.record("attack_end", mode=self.label, aborted=True, **summary)
        return summary

    def _record_row(self, ctx, row, summary):
        kind = row.get("kind")
        if kind == "attack_start":
            ctx.gt.record(
                "attack_start",
                t=row.get("t"),
                mode=row.get("mode"),
                target_url=row.get("target_url"),
                engine_ip=row.get("engine_ip"),
                engine_port=row.get("engine_port"),
                goal=row.get("goal"),
                dwell=row.get("dwell"),
            )
        elif kind == "plan_step":
            entry = {
                k: row.get(k)
                for k in ("node", "stage", "attck", "ok", "chosen_among", "target", "writes")
            }
            ctx.gt.record("plan_step", t=row.get("t"), mode=row.get("mode"), **entry)
            ctx.emit("plan_step", guest_t=row.get("t"), **entry)
            # Steps succeed in stage order, so the last one that did is how far
            # the attack got, should the agent never report its end.
            if row.get("ok"):
                summary["stage_reached"] = row.get("stage")
            summary["writes_ok"] += int(row.get("writes") or 0)
            for e in row.get("phases") or []:
                if e.get("phase") != "modbus_write":
                    continue
                write = dict(
                    register=e.get("register"),
                    register_name=active_attack.REGISTER_NAMES.get(e.get("register")),
                    value=e.get("value"),
                    ok=e.get("ok"),
                )
                ctx.gt.record(
                    "modbus_write",
                    t=e.get("t_send", e.get("t")),
                    mode=row.get("mode"),
                    attempt=e.get("attempt"),
                    source="pivot",
                    unauthorized=True,
                    **write,
                )
                ctx.emit("attack_write", write_t=e.get("t_send", e.get("t")), **write)
            foothold = active_attack.STAGE_TO_GT.get(row.get("node"))
            if foothold and row.get("ok"):
                ctx.gt.record(foothold, t=row.get("t"), mode=row.get("mode"))
        elif kind == "attack_end":
            ctx.gt.record(
                "attack_end",
                t=row.get("t"),
                mode=row.get("mode"),
                success=row.get("success"),
                stage_reached=row.get("stage_reached"),
                writes_ok=row.get("writes_ok"),
            )
            summary.update(
                success=bool(row.get("success")),
                stage_reached=row.get("stage_reached"),
                writes_ok=row.get("writes_ok", 0),
            )


class RedConsole(GuestAgent):
    """The red team's console on the attacker node (nodes/redteam/red_console.py):
    a person runs the attack's steps one at a time. The console is given the
    attack ``tree`` as data and builds its executable steps in the lab
    (red_steps.build_steps), the same registry the autonomous planner reads.

    What they run is the attack, so it is this component that writes the
    ground truth: it follows the console's record and turns every step into
    what a driven attack would have recorded — attack_start at the first one,
    the Modbus writes, the foothold — plus the step itself."""

    RECORD = "/red_actions.jsonl"
    MODE = "manual"

    def __init__(
        self,
        node,
        port,
        token,
        tree,
        target_url,
        engine_ip,
        engine_port,
        interval=0.5,
        terminal=None,
    ):
        packed = base64.b64encode(json.dumps(tree).encode()).decode()
        super().__init__(
            node,
            f"python3 red_console.py --port {port} --token {token} --tree-b64 {packed} "
            f"--target-url {target_url} --engine-ip {engine_ip} --engine-port {engine_port} "
            f"--interval {interval}" + (f" --terminal {terminal}" if terminal else ""),
            "red_console.log",
            plane=PLANE,
            name="red_console",
            artifacts=[Artifact(node, self.RECORD, f"{node}.red_actions.jsonl")],
        )
        self._cursor = None
        self._started = False

    def poll(self, ctx):
        if ctx.gt is None:
            return  # nothing may be lost: the steps are read once the truth is open
        if self._cursor is None:
            self._cursor = TelemetryCursor(tail_reader(ctx.exec_text, self.node, self.RECORD))
        for row in self._cursor.poll():
            if row.get("kind") != "red_step":
                continue
            if not self._started:
                self._started = True
                ctx.gt.record("attack_start", t=row.get("t"), mode=self.MODE)
            step = dict(step=row.get("step"), ok=row.get("ok"), operator=row.get("operator"))
            ctx.gt.record("red_step", t=row.get("t"), mode=self.MODE, **step)
            ctx.emit("red_step", guest_t=row.get("t"), **step)
            for e in row.get("phases") or []:
                if e.get("phase") != "modbus_write":
                    continue
                write = dict(
                    register=e.get("register"),
                    register_name=active_attack.REGISTER_NAMES.get(e.get("register")),
                    value=e.get("value"),
                    ok=e.get("ok"),
                )
                ctx.gt.record(
                    "modbus_write",
                    t=e.get("t_send", e.get("t")),
                    mode=self.MODE,
                    attempt=e.get("attempt"),
                    source="pivot",
                    unauthorized=True,
                    **write,
                )
                ctx.emit("attack_write", write_t=e.get("t_send", e.get("t")), **write)
            kind = active_attack.STAGE_TO_GT.get(row.get("step"))
            if kind and row.get("ok"):
                ctx.gt.record(kind, t=row.get("t"), mode=self.MODE)


# ── MQTT smart grid ───────────────────────────────────────────────────────────
BLOCK_POLICIES = ("top1", "threshold")


def detect_nanogrid_ip(pcap_path, model_path, scaler_path, block_policy="top1", threshold=None):
    """Score a capture with the trained CNN and rank source IPs by how
    nanogrid-like their traffic is, then pick the IP to block.

    top1       always block the top-ranked IP, whatever its score (the
               behaviour the workshop paper's results were produced with);
    threshold  block it only if its nanogrid_frac >= threshold.

    Returns (top_ip, ranking): ranking is rank_nanogrid_ips' per-IP DataFrame
    (indexed by src_ip, sorted by nanogrid_frac desc); top_ip is "" when nothing
    could be scored or the policy declines to block."""
    from cyberrange.planes.attack.classify import (
        extract_features,
        load_artifacts,
        predict_packets,
        rank_nanogrid_ips,
    )
    from cyberrange.planes.attack.thresholds import DETECT_THRESHOLD

    threshold = DETECT_THRESHOLD if threshold is None else threshold
    df = extract_features(pcap_path)  # unlabeled — the attacker has no ground truth
    model, scaler = load_artifacts(model_path, scaler_path)
    pkt_preds = predict_packets(df, model, scaler, window_size=model.window_size)
    ranking = rank_nanogrid_ips(pkt_preds)
    if ranking.empty:
        return "", ranking
    if block_policy == "threshold" and ranking.iloc[0]["nanogrid_frac"] < threshold:
        return "", ranking
    return str(ranking.index[0]), ranking


class PassiveFingerprinter(Component):
    """The passive attacker on the broker-side link: sniffs, then fingerprints
    the nanogrid's traffic with its CNN and picks the source IP to blackhole."""

    plane, name = PLANE, "passive_fingerprinter"
    CAPTURE = "attacker_capture.pcap"

    def __init__(self, node, iface, model, scaler, block_policy="top1", threshold=None):
        self.node, self.iface = node, iface
        self.model, self.scaler = model, scaler
        self.block_policy, self.threshold = block_policy, threshold
        self.detected_ip, self.ranking = "", None

    def sniff(self, ctx, seconds):
        from cyberrange.core.context import drain

        log.info("[Attack] Attacker sniffing for %ds", seconds)
        drain(ctx.exec(self.node, f"timeout {seconds} tcpdump -i {self.iface} -w {self.CAPTURE}"))
        log.info("[Attack] Downloading attacker capture")
        return ctx.download(self.node, self.CAPTURE, self.CAPTURE)

    def score(self, ctx, capture):
        log.info("[Attack] Scoring capture with the trained model")
        log.info("[Attack] Block policy: %s (threshold %s)", self.block_policy, self.threshold)
        self.detected_ip, self.ranking = detect_nanogrid_ip(
            capture,
            self.model,
            self.scaler,
            block_policy=self.block_policy,
            threshold=self.threshold,
        )
        log.info("[Attack] Per-IP nanogrid ranking:\n%s", self.ranking.to_string())
        with open(ctx.path("nanogrid_ranking.csv"), "w") as f:
            f.write(self.ranking.to_csv())
        if self.detected_ip:
            # plot_results.parse_block_event reads this exact line from run.log.
            log.info("[Attack] Blocking nanogrid IP: %s", self.detected_ip)
        else:
            log.warning("[Attack] No nanogrid IP detected — nothing blocked")
        return self.detected_ip


class DeliveryAttack(Component):
    """Blackhole episodes on the router (the CNN's pick or an oracle's) and
    benign faults, all in the ground truth (cyberrange/detection_scenario)."""

    plane, name = PLANE, "delivery_attack"

    def __init__(
        self,
        router,
        scmc,
        port_pool,
        relaunch,
        oracle=None,
        block_duration=None,
        block_episodes=1,
        impair=False,
        injector=None,
    ):
        self.router, self.scmc, self.port_pool, self.relaunch = router, scmc, port_pool, relaunch
        self.oracle, self.block_duration = oracle, block_duration
        self.block_episodes, self.impair = block_episodes, impair
        # The scenario owns what a fault looks like for it and passes the
        # injector class in; the component only drives its lifecycle.
        self.injector_cls, self.injector = injector, None

    @property
    def restarts(self):
        return self.injector.restarts if self.injector else 0

    def attack(self, ctx, cnn_ip):
        self.injector = self.injector_cls(
            ctx.manager,
            ctx.machine(self.router),
            ctx.machine(self.scmc),
            ctx.gt,
            self.port_pool,
            ctx.role_seed("attack"),
            self.relaunch,
        )
        self.injector.start(
            self.oracle, cnn_ip, self.block_duration, self.block_episodes, self.impair
        )

    def stop(self, ctx):
        if self.injector is not None:
            self.injector.finish()
            self.injector = None
