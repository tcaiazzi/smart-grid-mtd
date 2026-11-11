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

import logging
import time

from attack_plane import components as attack
from defense_plane import components as defense
from monitor import components as monitor
from network_scenario.core.scenario import PhaseSpec, Scenario
from network_scenario.scenarios.cps import topology as T
from traffic_generator import components as traffic

log = logging.getLogger("scenarios.cps")

ATTACK_MODES = ("setpoint-overvoltage", "breaker-open", "manual-hijack")
PROFILES = ("opportunistic", "targeted", "stealthy")
GOALS = ("setpoint_oor", "breaker_open", "mode_hijack")
RESPONSE_POLICIES = ("off", "rules", "solver")
LEARN_MARGIN_S = 5.0     # the model's calibration must end this long before the attack
ACCESS_LOG = "/vuln_app.access.jsonl"
# Untimed phases: first-guess durations for the ETA (the dashboard replaces them
# with the durations it observed in earlier runs of the same ledger).
OVERHEAD_S = {"deploy": 3.0, "services": 2.1, "attack": 4.0, "download": 0.5,
              "undeploy": 1.0}
SERVICE_SETTLE_S = 2.0   # engine up before its Modbus clients connect


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
        g.add_argument("--learn-seconds", type=float, default=45.0,
                       help="sensor model calibration period (inside the normal phase)")
        g.add_argument("--detectors", default="rules,model",
                       help="sensor detectors to run (comma list of rules, model)")
        g.add_argument("--dashboard-port", type=int, default=0,
                       help="host port of the sensor's live page (0 = off)")
        g.add_argument("--it-telemetry", action="store_true",
                       help="run the IT-side sensor on the HMI (observe the attacker's early "
                            "steps) + legitimate diagnostic traffic + the app access log")
        a = ap.add_argument_group("cps attack")
        a.add_argument("--attack", action="store_true", help="run an active attack")
        a.add_argument("--attack-driver", default="scripted", choices=("scripted", "planner"),
                       help="scripted = fixed per-mode chain; planner = reactive tree-guided")
        a.add_argument("--attack-mode", default="setpoint-overvoltage", choices=ATTACK_MODES)
        a.add_argument("--attacker-profile", default="opportunistic", choices=PROFILES,
                       help="planner driver: how the attacker chooses its next step")
        a.add_argument("--attack-goal", default=None, choices=GOALS,
                       help="planner driver, targeted profile: the impact leaf to aim for")
        a.add_argument("--dwell", type=float, default=0.0,
                       help="planner driver: seconds between steps (the defender's window)")
        a.add_argument("--max-steps", type=int, default=12, help="planner driver: step budget")
        a.add_argument("--attack-repeat", type=int, default=None,
                       help="times the write sequence is issued (default: per attack mode)")
        a.add_argument("--attack-interval", type=float, default=0.5)
        a.add_argument("--post-attack-duration", type=float, default=30.0)
        r = ap.add_argument_group("cps response")
        r.add_argument("--respond", default="off", choices=RESPONSE_POLICIES,
                       help="response policy driving countermeasures in the lab (SOAR)")
        r.add_argument("--respond-interval", type=float, default=0.5,
                       help="seconds between the responder's telemetry pulls")
        r.add_argument("--approval", default="auto",
                       help="operator approval for high-impact countermeasures: "
                            "auto | deny | delay:<seconds>")

    def validate(self, args):
        """Fail fast on a run whose model would calibrate on attack traffic."""
        if getattr(args, "attack", False) and \
                args.normal_duration < args.learn_seconds + LEARN_MARGIN_S:
            raise SystemExit(
                f"--normal-duration ({args.normal_duration}s) must be >= --learn-seconds "
                f"({args.learn_seconds}s) + {LEARN_MARGIN_S}s: the sensor's model calibrates "
                f"on the first --learn-seconds and must not see the attack")
        if getattr(args, "attack", False) and getattr(args, "attack_driver", "scripted") == "planner" \
                and getattr(args, "attacker_profile", None) == "targeted" \
                and not getattr(args, "attack_goal", None):
            raise SystemExit("--attacker-profile targeted needs --attack-goal "
                             f"({', '.join(GOALS)})")
        from network_scenario.cps_responder import parse_approval
        try:
            parse_approval(getattr(args, "approval", "auto"))
        except ValueError as e:
            raise SystemExit(f"--approval: {e}")

    def topology(self, args):
        return T.topology(args)

    def episode_phases(self, args):
        ph = [PhaseSpec("services", OVERHEAD_S["services"]),
              PhaseSpec("normal", float(args.normal_duration), timed=True)]
        if getattr(args, "attack", False):
            ph += [PhaseSpec("attack", OVERHEAD_S["attack"]),
                   PhaseSpec("post_attack", float(args.post_attack_duration), timed=True)]
        return ph

    def run_info(self, args):
        return dict(mode=attack_label(args), seed=args.seed, attack=bool(args.attack),
                    learn_s=args.learn_seconds, respond=args.respond or "off",
                    it=bool(args.it_telemetry))

    def write_structure(self, ctx):
        """kg.json / tree.json for the dashboard, from the lab being deployed."""
        from defense_plane.soar import kg as soar_kg
        from network_scenario import cps_responder
        cps_responder.write_structure(ctx.out_dir, soar_kg.build_cps_kg(ctx.lab),
                                      it=bool(ctx.args.it_telemetry))

    def metrics(self, run_dir):
        from monitor.cps_metrics import compute_metrics
        return compute_metrics(run_dir)

    # ── composition ──────────────────────────────────────────────────────────
    def attacker(self, args):
        target = f"http://{T.HMI_IP}:{T.APP_PORT}"
        if args.attack_driver == "planner":
            return attack.PlannedAttacker(
                args.attacker_profile, target, T.ENGINE_IP, T.MODBUS_PORT,
                goal=args.attack_goal, dwell=args.dwell, max_steps=args.max_steps,
                interval=args.attack_interval)
        return attack.ScriptedChain(args.attack_mode, target, T.ENGINE_IP, T.MODBUS_PORT,
                                    repeat=args.attack_repeat, interval=args.attack_interval)

    def episode(self, ctx):
        a = ctx.args
        it = bool(a.it_telemetry)
        with ctx.phase("services"):
            # DPI sensor first, so the model's calibration window covers the
            # clients' session setup as well as steady state.
            ctx.start(defense.OtSensor(
                "sensor", "eth0", T.ENGINE_IP, T.MODBUS_PORT, T.PLC_IP, T.HMI_IP,
                a.detectors, a.learn_seconds,
                dashboard_port=T.DASHBOARD_GUEST_PORT if a.dashboard_port else None))
            ctx.start(traffic.PhysicalProcess("engine", T.MODBUS_PORT, a.step_interval,
                                              seed=ctx.role_seed("engine")))
            time.sleep(SERVICE_SETTLE_S)
            ctx.start(traffic.PlcController("plc", T.ENGINE_IP, T.MODBUS_PORT,
                                            a.step_interval, seed=ctx.role_seed("plc")))
            ctx.start(traffic.HmiClient(
                "hmi", T.ENGINE_IP, T.MODBUS_PORT, seed=ctx.role_seed("hmi"),
                diag_url=f"http://127.0.0.1:{T.APP_PORT}" if it else None))
            ctx.start(attack.VulnApp("hmi", T.APP_PORT, access_log=ACCESS_LOG if it else None))
            if it:
                ctx.start(defense.ItSensor("hmi", T.ENGINE_IP, T.MODBUS_PORT, ACCESS_LOG,
                                           a.learn_seconds))
        ctx.start(monitor.PlantMirror("engine"))
        ctx.start(monitor.TelemetryMirror())
        if (a.respond or "off") != "off":
            ctx.start(defense.SoarResponder(a.respond, approval=a.approval,
                                            interval=a.respond_interval, it=it))

        log.info("Normal operation for %.0fs (model calibration: first %.0fs)",
                 a.normal_duration, a.learn_seconds)
        with ctx.phase("normal", learn_s=a.learn_seconds):
            ctx.observe(a.normal_duration)

        ctx.open_ground_truth(
            seed=a.seed, attack=bool(a.attack), attack_mode=a.attack_mode,
            attack_driver=a.attack_driver, engine_ip=T.ENGINE_IP, plc_ip=T.PLC_IP,
            hmi_ip=T.HMI_IP, authorized_writer=T.PLC_IP, learn_seconds=a.learn_seconds,
            detectors=a.detectors, respond=a.respond, approval=a.approval, it=it)
        if not a.attack:
            return
        driver = ctx.start(self.attacker(a))
        with ctx.phase("attack", mode=driver.label):
            driver.attack(ctx)
        log.info("Post-attack observation for %.0fs", a.post_attack_duration)
        with ctx.phase("post_attack"):
            ctx.observe(a.post_attack_duration)
