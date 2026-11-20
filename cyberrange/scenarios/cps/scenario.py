"""scenario.py — the cyber-physical scenario on the platform core.

Episode: services (sensor, plant, PLC, HMI, web app[, IT sensor]) → normal
operation (the sensor's model calibrates on the first --learn-seconds) →
[attack: scripted chain or tree-guided planner → post-attack observation].
The response is decided in the lab, by the SOC's analytics on the soc node;
with --respond off it only watches.

Composition (plane components):
    traffic   PhysicalProcess, PlcController, HmiClient
    attack    VulnApp, EwsMaintenance, ScriptedChain | PlannedAttacker
    defense   OtSensor, [ItSensor], WazuhManager, WazuhAgent, SocAnalytics
    monitor   PlantMirror, TelemetryMirror

The lab is a LabSpec (lab.py): the episode finds its hosts by role and their
addresses in the spec. The scenarios built on this one add Features
(feature.py) to it rather than overriding it.
"""

import os
import logging
import random
import time
import types

from cyberrange.planes.attack import components as attack
from cyberrange.planes.defense import components as defense
from cyberrange.planes.defense import ot_registers as reg
from cyberrange.planes.monitor import components as monitor
from cyberrange.core.scenario import PhaseSpec, Scenario
from cyberrange.scenarios.cps import inventory
from cyberrange.scenarios.cps import topology as T
from cyberrange.planes.traffic import components as traffic

log = logging.getLogger("scenarios.cps")

ATTACK_MODES = (
    "setpoint-overvoltage",
    "breaker-open",
    "manual-hijack",
    "slow-ramp",
    "setpoint-oscillation",
    "breaker-chatter",
    "meas-fdi",
)
PROFILES = ("opportunistic", "targeted", "stealthy")
GOALS = (
    "setpoint_oor",
    "breaker_open",
    "mode_hijack",
    "setpoint_ramp",
    "setpoint_oscillation",
    "breaker_chatter",
    "meas_fdi",
)
RESPONSE_POLICIES = ("off", "rules", "solver")
LEARN_MARGIN_S = 5.0  # the model's calibration must end this long before the attack
ACCESS_LOG = "/vuln_app.access.jsonl"
WAY_IN_SERVICE = "diag-http"  # the application an HMI serves: what makes it a way in
# Untimed phases: first-guess durations for the ETA (the dashboard replaces them
# with the durations it observed in earlier runs of the same ledger).
OVERHEAD_S = {"deploy": 3.0, "services": 2.1, "attack": 4.0, "download": 0.5, "undeploy": 1.0}
SERVICE_SETTLE_S = 2.0  # engine up before its Modbus clients connect


def maint_token(seed):
    """The workstation's maintenance credential: the same in every run of a
    seed, so a seeded run replays; random in an unseeded one."""
    return random.Random(seed).getrandbits(128).to_bytes(16, "big").hex()


def attack_label(args):
    if not getattr(args, "attack", False):
        return "normal"
    if getattr(args, "attack_driver", "scripted") == "planner":
        return f"planner:{args.attacker_profile}"
    return args.attack_mode


def plant_of(spec):
    """The hosts and addresses the episode works with, found in ``spec`` by
    role: the names and numbers the components are started with."""
    soc, sensor = spec.one("soc").name, spec.one("sensor").name
    # The plant's first controller and HMI: the PLC whose writes the ground
    # truth calls authorized, the HMI an attack goes through unless told another.
    engine = spec.one("plant").name
    plc, hmi = spec.with_role("plc")[0].name, spec.with_role("hmi")[0].name
    ews = spec.with_role("engineering")
    plant_zone = spec.zone_of(engine)
    # The ways in: every HMI that serves the application, with its URL.
    ways = {
        h.name: f"http://{spec.ip(h.name)}:{svc.port}"
        for h in spec.with_role("hmi")
        for svc in h.services
        if svc.name == WAY_IN_SERVICE
    }
    return types.SimpleNamespace(
        ways=ways,
        soc=soc,
        soc_ip=spec.ip(soc),
        sensor=sensor,
        sensor_iface=spec.iface(sensor, plant_zone),  # its passive NIC on the plant's link
        engine=engine,
        engine_ip=spec.ip(engine),
        modbus_port=spec.service(engine, "modbus").port,
        plc=plc,
        plc_ip=spec.ip(plc),
        hmi=hmi,
        hmi_ip=spec.ip(hmi),
        app_port=spec.service(hmi, WAY_IN_SERVICE).port,
        # The boundary writes to the plant from its own foot on the plant's link.
        responder_ip=spec.ip(spec.boundary, plant_zone),
        ews=ews[0].name if ews else None,
    )


class CpsScenario(Scenario):
    name = "cps"
    lab_name = T.LAB_NAME
    overhead_s = OVERHEAD_S
    features = ()
    # Defaults a scenario built on this lab may set differently.
    DEFAULT_OUT_DIR = "output/cps/run-1"
    DEFAULT_RESPOND = "off"
    DEFAULT_APPROVAL = "auto"
    APPROVAL_HELP = (
        "operator approval for high-impact countermeasures: auto | deny | delay:<seconds>"
    )

    def lab_spec(self, args):
        """The lab of a run (lab.LabSpec)."""
        return T.DEFAULT

    def plant_spec(self, args):
        """The plant of a run (ot_registers.plant): its feeders, each a Modbus
        unit of the engine."""
        return reg.plant()

    # ── options ──────────────────────────────────────────────────────────────
    def add_arguments(self, ap):
        g = ap.add_argument_group("cps scenario")
        g.add_argument("--out-dir", default=self.DEFAULT_OUT_DIR)
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
            "--attack-via",
            default=None,
            metavar="HOST",
            help="the HMI the attack gets in through (scripted: default the lab's first; "
            "planner: default any, in the tree's order)",
        )
        a.add_argument(
            "--attack-unit",
            type=int,
            default=None,
            metavar="UNIT",
            help="the feeder the attack acts on, by its Modbus unit (scripted: default the "
            "plant's first; planner: default any)",
        )
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
            default=self.DEFAULT_RESPOND,
            choices=RESPONSE_POLICIES,
            help="response policy driving countermeasures in the lab (SOAR)",
        )
        r.add_argument(
            "--respond-interval",
            type=float,
            default=0.5,
            help="seconds between the responder's telemetry pulls",
        )
        r.add_argument("--approval", default=self.DEFAULT_APPROVAL, help=self.APPROVAL_HELP)
        for f in self.features:
            f.add_arguments(ap)

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
        if getattr(args, "attack", False):
            self.check_target(args)
        self.check_approval(getattr(args, "approval", "auto") or "auto")
        for f in self.features:
            f.validate(args)
        ports = [int(p or 0) for f in self.features for p in f.host_ports(args)]
        if getattr(args, "dashboard_port", 0):
            ports.append(int(args.dashboard_port))
        if len(set(ports)) != len(ports) or not all(0 < p < 65536 for p in ports):
            raise SystemExit(
                f"the host ports a run publishes must be distinct and valid, got {ports}"
            )

    def check_target(self, args):
        """An attack aimed at a way in or a feeder the run does not have would
        find nothing to do, and be scored as a plant well defended."""
        via, unit = getattr(args, "attack_via", None), getattr(args, "attack_unit", None)
        ways = plant_of(self.lab_spec(args)).ways
        if via is not None and via not in ways:
            raise SystemExit(f"--attack-via {via}: the lab's ways in are {', '.join(ways)}")
        units = reg.units(self.plant_spec(args))
        if unit is not None and unit not in units:
            raise SystemExit(f"--attack-unit {unit}: the plant's units are {units}")

    def check_approval(self, spec):
        """A person's verdict needs the SOC's operator API published and a
        console to answer from, which this scenario's lab does not set up: here
        approval is automatic, denied, or simulated by a delay — unless a
        feature puts a person in the loop and decides it."""
        if any(f.check_approval(spec) for f in self.features):
            return
        if spec not in ("auto", "deny") and not (
            spec.startswith("delay:") and spec.split(":", 1)[1].replace(".", "", 1).isdigit()
        ):
            raise SystemExit(f"--approval must be auto, deny or delay:<seconds>, got {spec!r}")

    def prepare(self, args):
        super().prepare(args)
        for f in self.features:
            f.prepare(args)

    def run_info(self, args):
        info = dict(
            mode=attack_label(args),
            seed=args.seed,
            attack=bool(args.attack),
            learn_s=args.learn_seconds,
            respond=args.respond or "off",
            it=bool(args.it_telemetry),
            # The plant's normal band, for the dashboard to draw the readings against.
            v_band=self.plant_spec(args)["limits"]["v_band"],
            # Its feeders, and where the attack was aimed (None: left to the attacker).
            units=reg.units(self.plant_spec(args)),
            attack_unit=getattr(args, "attack_unit", None),
            attack_via=getattr(args, "attack_via", None),
        )
        for f in self.features:
            info |= f.run_info(args)
        return info

    # ── the lab ──────────────────────────────────────────────────────────────
    def topology(self, args):
        spec = self.lab_spec(args)
        extras = {}
        for f in self.features:
            for host, extra in f.extras(spec, args).items():
                extras[host] = extras[host].merged(extra) if host in extras else extra
        topo = T.topology(args, name=self.lab_name, extras=extras, spec=spec)
        for f in self.features:
            topo.nodes += f.nodes(spec, args)
        return topo

    def links(self, args):
        """{team: {what: url}}: what the features hand to each team."""
        out = {}
        for f in self.features:
            for team, links in f.links(args).items():
                out.setdefault(team, {}).update(links)
        return out

    def operator_api(self, args):
        """SocAnalytics' operator arguments. With no feature setting them, the
        SOC decides alone."""
        out = {}
        for f in self.features:
            out |= f.operator_api(self, args)
        return out

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

    def write_structure(self, ctx):
        """kg.json / tree.json for the dashboard and the attacker's planner. The
        SOC node builds these itself at run time; here, at deploy, the host runs
        the same tool (soc_tool) on the lab's inventory to lay them down first."""
        from cyberrange.scenarios.cps import soc_tool

        a = ctx.args
        soc_tool.describe(
            ctx.out_dir, it=bool(a.it_telemetry), spec=self.lab_spec(a), plant=self.plant_spec(a)
        )

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
        for f in self.features:
            driver = f.attacker(self, args)
            if driver is not None:
                return driver
        spec, plant = self.lab_spec(args), self.plant_spec(args)
        p = plant_of(spec)
        node = spec.one("it-host").name
        via, unit = getattr(args, "attack_via", None), getattr(args, "attack_unit", None)
        target = p.ways[via] if via else f"http://{p.hmi_ip}:{p.app_port}"
        plant_b64 = reg.plant_b64(plant)
        if args.attack_driver == "planner":
            # Left free (None), the planner chooses its way and its feeder on
            # the tree, by its profile.
            return attack.PlannedAttacker(
                args.attacker_profile,
                target,
                p.engine_ip,
                p.modbus_port,
                goal=args.attack_goal,
                dwell=args.dwell,
                max_steps=args.max_steps,
                interval=args.attack_interval,
                tree=self._attack_tree,
                node=node,
                ways=p.ways,
                via=via,
                unit=unit,
                plant_b64=plant_b64,
            )
        return attack.ScriptedChain(
            args.attack_mode,
            target,
            p.engine_ip,
            p.modbus_port,
            repeat=args.attack_repeat,
            interval=args.attack_interval,
            node=node,
            via=via or p.hmi,
            unit=unit if unit is not None else reg.units(plant)[0],
            plant_b64=plant_b64,
        )

    def episode(self, ctx):
        a = ctx.args
        spec, plant = self.lab_spec(a), self.plant_spec(a)
        p = plant_of(spec)
        plant_b64 = reg.plant_b64(plant)
        first = reg.units(plant)[0]
        plcs = [(h.name, spec.ip(h.name), h.unit or first) for h in spec.with_role("plc")]
        hmis = [(h.name, spec.ip(h.name), h.unit or first) for h in spec.with_role("hmi")]
        it = bool(a.it_telemetry)
        # The management plane (Wazuh + SOC analytics) runs in every episode, so
        # a detection-only run (respond=off) carries the same load and is
        # comparable. With respond=off the analytics watches but requests nothing.
        responding = (a.respond or "off") != "off"
        agents = T.wazuh_agents(spec)
        with ctx.phase("services"):
            # First, and in the background: the agents wait for it, and the
            # normal phase gives both the time to settle before any finding.
            keys = {name: defense.generate_shared_key() for name in agents}
            ctx.start(defense.WazuhManager(p.soc, {n: (agents[n], keys[n]) for n in agents}))
            # DPI sensor first, so the model's calibration window covers the
            # clients' session setup as well as steady state.
            ctx.start(
                defense.OtSensor(
                    p.sensor,
                    p.sensor_iface,
                    p.engine_ip,
                    p.modbus_port,
                    ",".join(f"{ip}@{unit}" for _n, ip, unit in plcs),
                    ",".join(f"{ip}@{unit}" for _n, ip, unit in hmis),
                    a.detectors,
                    a.learn_seconds,
                    dashboard_port=T.DASHBOARD_GUEST_PORT if a.dashboard_port else None,
                    # Only when a response runs: with none, a write from the
                    # firewall is nobody's and must be reported.
                    responder_ip=p.responder_ip if responding else None,
                    plant_b64=plant_b64,
                )
            )
            ctx.start(
                traffic.PhysicalProcess(
                    p.engine,
                    p.modbus_port,
                    a.step_interval,
                    seed=ctx.role_seed("engine"),
                    plant_b64=plant_b64,
                )
            )
            time.sleep(SERVICE_SETTLE_S)
            # One controller per feeder, each on its own seed: the first keeps
            # the role's seed a single-feeder plant has always used.
            for i, (name, _ip, unit) in enumerate(plcs):
                ctx.start(
                    traffic.PlcController(
                        name,
                        p.engine_ip,
                        p.modbus_port,
                        a.step_interval,
                        seed=ctx.role_seed("plc" if i == 0 else f"plc:{unit}"),
                        unit=unit,
                        plant_b64=plant_b64,
                    )
                )
            for i, (name, _ip, unit) in enumerate(hmis):
                ctx.start(
                    traffic.HmiClient(
                        name,
                        p.engine_ip,
                        p.modbus_port,
                        seed=ctx.role_seed("hmi" if i == 0 else f"hmi:{unit}"),
                        # Legitimate use of the application, on every HMI serving it.
                        diag_url=(
                            f"http://127.0.0.1:{p.ways[name].rsplit(':', 1)[1]}"
                            if it and name in p.ways
                            else None
                        ),
                        diag_targets=(p.engine_ip, "localhost", p.plc_ip, "127.0.0.1"),
                        unit=unit,
                    )
                )
            # Every way in is a real one: the application runs on each HMI that
            # serves it, and each holds the workstation's credential.
            for name, url in p.ways.items():
                port = int(url.rsplit(":", 1)[1])
                ctx.start(attack.VulnApp(name, port, access_log=ACCESS_LOG if it else None))
            if p.ews:
                maint = spec.service(p.ews, "maint-http").port
                clients = [
                    (name, spec.ip(name), f"http://{spec.ip(p.ews, spec.zone_of(name))}:{maint}")
                    for name in p.ways
                ]
                ctx.start(
                    attack.EwsMaintenance(
                        p.ews, maint, clients, token=maint_token(ctx.role_seed("ews-maint"))
                    )
                )
            if it:
                for name in p.ways:
                    ctx.start(
                        defense.ItSensor(
                            name, p.engine_ip, p.modbus_port, ACCESS_LOG, a.learn_seconds
                        )
                    )
            # What each agent may run, from the countermeasures the structure
            # recorded at deploy (tree.json): the host provisions the allowlist,
            # it does not decide. The SOC analytics asks for these by id.
            logs = {p.sensor: [defense.OtSensor.TELEMETRY]}
            if it:
                logs.update({name: [defense.ItSensor.TELEMETRY] for name in p.ways})
            allowed = {name: {} for name in agents}
            for cm in self._countermeasures(ctx):
                if cm["machine"] in allowed:
                    allowed[cm["machine"]][cm["id"]] = {
                        "apply": cm["apply"],
                        "revert": cm["revert"],
                    }
            for name, agent_id in agents.items():
                ctx.start(
                    defense.WazuhAgent(
                        name,
                        p.soc_ip,
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
                    p.soc,
                    inventory.inventory(spec, plant=plant),
                    policy=a.respond or "off",
                    approval=a.approval,
                    interval=a.respond_interval,
                    it=it,
                    **self.operator_api(a),
                )
            )
            for f in self.features:
                f.services(ctx)
        ctx.start(monitor.PlantMirror(p.engine))
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
            attack_via=a.attack_via,
            attack_unit=a.attack_unit,
            ways=p.ways,
            units=reg.units(plant),
            engine_ip=p.engine_ip,
            plc_ip=p.plc_ip,
            hmi_ip=p.hmi_ip,
            authorized_writer=p.plc_ip,
            learn_seconds=a.learn_seconds,
            detectors=a.detectors,
            respond=a.respond,
            approval=a.approval,
            it=it,
        )
        for f in self.features:
            f.engage(ctx)
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
