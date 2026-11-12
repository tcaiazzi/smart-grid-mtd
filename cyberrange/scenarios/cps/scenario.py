"""scenario.py — the cyber-physical scenario on the platform core.

Episode: services (sensor, plant, PLC, HMI, web app[, IT sensor]) → normal
operation (the sensor's model calibrates on the first --learn-seconds) →
[attack: scripted chain or tree-guided planner → post-attack observation].
An optional SOAR responder runs alongside as a host thread.

Composition (plane components):
    traffic   PhysicalProcess, PlcController, HmiClient
    attack    VulnApp, ScriptedChain | PlannedAttacker
    defense   OtSensor, [ItSensor], [SoarResponder]
    monitor   PlantMirror, TelemetryMirror
"""

import os
import logging
import time

from cyberrange.planes.attack import components as attack
from cyberrange.planes.defense import components as defense
from cyberrange.planes.monitor import components as monitor
from cyberrange.core.scenario import PhaseSpec, Scenario
from cyberrange.scenarios.cps import inventory
from cyberrange.scenarios.cps import topology as T
from cyberrange.planes.traffic import components as traffic

log = logging.getLogger("scenarios.cps")

ATTACK_MODES = ("setpoint-overvoltage", "breaker-open", "manual-hijack")
PROFILES = ("opportunistic", "targeted", "stealthy")
GOALS = ("setpoint_oor", "breaker_open", "mode_hijack")
RESPONSE_POLICIES = ("off", "rules", "solver")
LEARN_MARGIN_S = 5.0  # the model's calibration must end this long before the attack
ACCESS_LOG = "/vuln_app.access.jsonl"
# Untimed phases: first-guess durations for the ETA (the dashboard replaces them
# with the durations it observed in earlier runs of the same ledger).
OVERHEAD_S = {"deploy": 3.0, "services": 2.1, "attack": 4.0, "download": 0.5, "undeploy": 1.0}
SERVICE_SETTLE_S = 2.0  # engine up before its Modbus clients connect


def attack_label(args):
    if not getattr(args, "attack", False):
        return "normal"
    if getattr(args, "attack_driver", "scripted") == "planner":
        return f"planner:{args.attacker_profile}"
    return args.attack_mode


class CpsScenario(Scenario):
    name = "cps"
    lab_name = T.LAB_NAME
    overhead_s = OVERHEAD_S

    # ── options ──────────────────────────────────────────────────────────────
    def add_arguments(self, ap):
        g = ap.add_argument_group("cps scenario")
        g.add_argument("--out-dir", default="output/cps/run-1")
        g.add_argument("--step-interval", type=float, default=1.0)
        g.add_argument("--normal-duration", type=float, default=60.0)
        g.add_argument(
            "--learn-seconds",
            type=float,
            default=45.0,
            help="sensor model calibration period (inside the normal phase)",
        )
        g.add_argument(
            "--detectors",
            default="rules,model",
            help="sensor detectors to run (comma list of rules, model)",
        )
        g.add_argument(
            "--dashboard-port",
            type=int,
            default=0,
            help="host port of the sensor's live page (0 = off)",
        )
        g.add_argument(
            "--it-telemetry",
            action="store_true",
            help="run the IT-side sensor on the HMI (observe the attacker's early "
            "steps) + legitimate diagnostic traffic + the app access log",
        )
        a = ap.add_argument_group("cps attack")
        a.add_argument("--attack", action="store_true", help="run an active attack")
        a.add_argument(
            "--attack-driver",
            default="scripted",
            choices=("scripted", "planner"),
            help="scripted = fixed per-mode chain; planner = reactive tree-guided",
        )
        a.add_argument("--attack-mode", default="setpoint-overvoltage", choices=ATTACK_MODES)
        a.add_argument(
            "--attacker-profile",
            default="opportunistic",
            choices=PROFILES,
            help="planner driver: how the attacker chooses its next step",
        )
        a.add_argument(
            "--attack-goal",
            default=None,
            choices=GOALS,
            help="planner driver, targeted profile: the impact leaf to aim for",
        )
        a.add_argument(
            "--dwell",
            type=float,
            default=0.0,
            help="planner driver: seconds between steps (the defender's window)",
        )
        a.add_argument("--max-steps", type=int, default=12, help="planner driver: step budget")
        a.add_argument(
            "--attack-repeat",
            type=int,
            default=None,
            help="times the write sequence is issued (default: per attack mode)",
        )
        a.add_argument("--attack-interval", type=float, default=0.5)
        a.add_argument("--post-attack-duration", type=float, default=30.0)
        r = ap.add_argument_group("cps response")
        r.add_argument(
            "--respond",
            default="off",
            choices=RESPONSE_POLICIES,
            help="response policy driving countermeasures in the lab (SOAR)",
        )
        r.add_argument(
            "--respond-interval",
            type=float,
            default=0.5,
            help="seconds between the responder's telemetry pulls",
        )
        r.add_argument(
            "--approval",
            default="auto",
            help="operator approval for high-impact countermeasures: auto | deny | delay:<seconds>",
        )

    def validate(self, args):
        """Fail fast on a run whose model would calibrate on attack traffic."""
        if (
            getattr(args, "attack", False)
            and args.normal_duration < args.learn_seconds + LEARN_MARGIN_S
        ):
            raise SystemExit(
                f"--normal-duration ({args.normal_duration}s) must be >= --learn-seconds "
                f"({args.learn_seconds}s) + {LEARN_MARGIN_S}s: the sensor's model calibrates "
                f"on the first --learn-seconds and must not see the attack"
            )
        if (
            getattr(args, "attack", False)
            and getattr(args, "attack_driver", "scripted") == "planner"
            and getattr(args, "attacker_profile", None) == "targeted"
            and not getattr(args, "attack_goal", None)
        ):
            raise SystemExit(
                f"--attacker-profile targeted needs --attack-goal ({', '.join(GOALS)})"
            )
        spec = getattr(args, "approval", "auto") or "auto"
        if spec not in ("auto", "deny") and not (
            spec.startswith("delay:") and spec.split(":", 1)[1].replace(".", "", 1).isdigit()
        ):
            raise SystemExit(f"--approval must be auto, deny or delay:<seconds>, got {spec!r}")

    def topology(self, args):
        return T.topology(args)

    def episode_phases(self, args):
        ph = [
            PhaseSpec("services", OVERHEAD_S["services"]),
            PhaseSpec("normal", float(args.normal_duration), timed=True),
        ]
        if getattr(args, "attack", False):
            ph += [
                PhaseSpec("attack", OVERHEAD_S["attack"]),
                PhaseSpec("post_attack", float(args.post_attack_duration), timed=True),
            ]
        return ph

    def run_info(self, args):
        return dict(
            mode=attack_label(args),
            seed=args.seed,
            attack=bool(args.attack),
            learn_s=args.learn_seconds,
            respond=args.respond or "off",
            it=bool(args.it_telemetry),
        )

    def write_structure(self, ctx):
        """kg.json / tree.json for the dashboard and the attacker's planner. The
        SOC node builds these itself at run time; here, at deploy, the host runs
        the same tool (soc_tool) on the lab's inventory to lay them down first."""
        from cyberrange.scenarios.cps import soc_tool

        soc_tool.describe(ctx.out_dir, it=bool(ctx.args.it_telemetry), args=ctx.args)

    def metrics(self, run_dir):
        from cyberrange.scenarios.cps.metrics import compute_metrics

        return compute_metrics(run_dir)

    # ── dashboard ────────────────────────────────────────────────────────────
    def panel_js(self):
        """The plant / knowledge-graph / attack-tree drawing, served by the
        dashboard for runs of this scenario."""
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.js")

    def structure(self):
        """kg + attack tree rebuilt from the declared topology, for runs that
        predate kg.json. The host runs the SOC's own tool (soc_tool) on the
        lab's inventory, in a subprocess, rather than importing it."""
        from cyberrange.scenarios.cps import soc_tool

        return soc_tool.structure()

    # ── composition ──────────────────────────────────────────────────────────
    def _structure(self, ctx):
        """The structure the run recorded at deploy (soc_tool.describe)."""
        import json

        with open(os.path.join(ctx.out_dir, "tree.json")) as f:
            return json.load(f)

    def _attack_tree(self, ctx):
        """The attack tree as a document. The attacker reads it; it does not
        build the defender's graph."""
        return self._structure(ctx)["attack_tree"]

    def _countermeasures(self, ctx):
        """The countermeasures of the lab, with their commands and target host."""
        return self._structure(ctx)["countermeasures"]

    def attacker(self, args):
        target = f"http://{T.HMI_IP}:{T.APP_PORT}"
        if args.attack_driver == "planner":
            return attack.PlannedAttacker(
                args.attacker_profile,
                target,
                T.ENGINE_IP,
                T.MODBUS_PORT,
                goal=args.attack_goal,
                dwell=args.dwell,
                max_steps=args.max_steps,
                interval=args.attack_interval,
                tree=self._attack_tree,
            )
        return attack.ScriptedChain(
            args.attack_mode,
            target,
            T.ENGINE_IP,
            T.MODBUS_PORT,
            repeat=args.attack_repeat,
            interval=args.attack_interval,
        )

    def episode(self, ctx):
        a = ctx.args
        it = bool(a.it_telemetry)
        # The management plane (Wazuh + SOC analytics) runs in every episode, so
        # a detection-only run (respond=off) carries the same load and is
        # comparable. With respond=off the analytics watches but requests nothing.
        responding = (a.respond or "off") != "off"
        with ctx.phase("services"):
            # First, and in the background: the agents wait for it, and the
            # normal phase gives both the time to settle before any finding.
            keys = {name: defense.generate_shared_key() for name in T.WAZUH_AGENTS}
            ctx.start(
                defense.WazuhManager(
                    "soc", {n: (T.WAZUH_AGENTS[n], keys[n]) for n in T.WAZUH_AGENTS}
                )
            )
            # DPI sensor first, so the model's calibration window covers the
            # clients' session setup as well as steady state.
            ctx.start(
                defense.OtSensor(
                    "sensor",
                    "eth0",
                    T.ENGINE_IP,
                    T.MODBUS_PORT,
                    T.PLC_IP,
                    T.HMI_IP,
                    a.detectors,
                    a.learn_seconds,
                    dashboard_port=T.DASHBOARD_GUEST_PORT if a.dashboard_port else None,
                    # Only when a response runs: with none, a write from the
                    # firewall is nobody's and must be reported.
                    responder_ip=T.FW_OT_IP if responding else None,
                )
            )
            ctx.start(
                traffic.PhysicalProcess(
                    "engine", T.MODBUS_PORT, a.step_interval, seed=ctx.role_seed("engine")
                )
            )
            time.sleep(SERVICE_SETTLE_S)
            ctx.start(
                traffic.PlcController(
                    "plc", T.ENGINE_IP, T.MODBUS_PORT, a.step_interval, seed=ctx.role_seed("plc")
                )
            )
            ctx.start(
                traffic.HmiClient(
                    "hmi",
                    T.ENGINE_IP,
                    T.MODBUS_PORT,
                    seed=ctx.role_seed("hmi"),
                    diag_url=f"http://127.0.0.1:{T.APP_PORT}" if it else None,
                )
            )
            ctx.start(attack.VulnApp("hmi", T.APP_PORT, access_log=ACCESS_LOG if it else None))
            if it:
                ctx.start(
                    defense.ItSensor("hmi", T.ENGINE_IP, T.MODBUS_PORT, ACCESS_LOG, a.learn_seconds)
                )
            # What each agent may run, from the countermeasures the structure
            # recorded at deploy (tree.json): the host provisions the allowlist,
            # it does not decide. The SOC analytics asks for these by id.
            logs = {"sensor": [defense.OtSensor.TELEMETRY]}
            if it:
                logs["hmi"] = [defense.ItSensor.TELEMETRY]
            allowed = {name: {} for name in T.WAZUH_AGENTS}
            for cm in self._countermeasures(ctx):
                if cm["machine"] in allowed:
                    allowed[cm["machine"]][cm["id"]] = {
                        "apply": cm["apply"],
                        "revert": cm["revert"],
                    }
            for name, agent_id in T.WAZUH_AGENTS.items():
                ctx.start(
                    defense.WazuhAgent(
                        name,
                        T.SOC_IP,
                        agent_id,
                        keys[name],
                        responses=allowed[name],
                        logs=logs.get(name, ()),
                    )
                )
            # The decision runs on the SOC node: it reads the manager's alerts,
            # keeps the attack tree's belief and asks the manager for responses.
            ctx.start(
                defense.SocAnalytics(
                    "soc",
                    inventory.inventory(a),
                    policy=a.respond or "off",
                    approval=a.approval,
                    interval=a.respond_interval,
                    it=it,
                )
            )
        ctx.start(monitor.PlantMirror("engine"))
        ctx.start(monitor.TelemetryMirror())

        log.info(
            "Normal operation for %.0fs (model calibration: first %.0fs)",
            a.normal_duration,
            a.learn_seconds,
        )
        with ctx.phase("normal", learn_s=a.learn_seconds):
            ctx.observe(a.normal_duration)

        ctx.open_ground_truth(
            seed=a.seed,
            attack=bool(a.attack),
            attack_mode=a.attack_mode,
            attack_driver=a.attack_driver,
            engine_ip=T.ENGINE_IP,
            plc_ip=T.PLC_IP,
            hmi_ip=T.HMI_IP,
            authorized_writer=T.PLC_IP,
            learn_seconds=a.learn_seconds,
            detectors=a.detectors,
            respond=a.respond,
            approval=a.approval,
            it=it,
        )
        if not a.attack:
            return
        driver = ctx.start(self.attacker(a))
        # The attack blocks the main thread; ctx.live keeps the mirrors polling,
        # so the SOC's decisions and actions reach the ledger as they happen and
        # not only once the attack returns.
        with ctx.phase("attack", mode=driver.label), ctx.live():
            driver.attack(ctx)
        log.info("Post-attack observation for %.0fs", a.post_attack_duration)
        with ctx.phase("post_attack"):
            ctx.observe(a.post_attack_duration)
