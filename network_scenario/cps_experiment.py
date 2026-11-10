"""cps_experiment.py — Kathará lab builder and runner for the cyber-physical
(OT/Modbus) scenario (doc steps 3–4). Sibling to run_experiment.py: it reuses
that module's helpers (role_seed, with_console_log, download_file_from_container,
GroundTruth) rather than duplicating them, and leaves the MQTT pipeline untouched.

Three zones (see the plan): IT (attacker + the HMI/SCADA host, which also runs
a vulnerable diagnostics web app), OT (PLC + physical engine), defense (the
passive Modbus-DPI sensor), joined by an IT/OT boundary firewall that forwards
only the sanctioned flow: HMI -> engine Modbus. The attacker cannot reach the
engine directly; it must compromise the HMI and pivot from it, so its writes
come from an allowed host. The sensor has a
passive NIC on the OT link (it sees the Modbus traffic) and a management NIC on
the defense net (it reports findings, unreachable from OT).

Topology / addressing::

    IT 10.10.0.0/24            firewall             OT 10.20.0.0/24
      attacker 10.10.0.10   10.10.0.1 | 10.20.0.1   plc    10.20.0.10
      hmi      10.10.0.20       (FORWARD DROP,      engine 10.20.0.20
                                  HMI->engine Modbus  sensor eth0 (passive)
                                  allowed)
                                                    DEF 10.30.0.0/24
                                                      sensor eth1 10.30.0.10

Run:
    python -m network_scenario.cps_experiment --normal-duration 60 --attack \
        --attack-mode manual-hijack --out-dir output/cps/run-1 --seed 1
"""

import argparse
import contextlib
import json
import logging
import os
import time
import traceback

from Kathara.manager.Kathara import Kathara
from Kathara.setting.Setting import Setting
from Kathara.model.Lab import Lab

from network_scenario.guest_files import (
    ATTACKER_CPS_FILES,
    ENGINE_FILES,
    HMI_FILES,
    PLC_FILES,
    SENSOR_FILES,
)
from network_scenario.run_experiment import (
    role_seed, seed_arg, with_console_log, download_file_from_container,
)
from network_scenario.detection_scenario import GroundTruth
from attack_plane import active_attack
from monitor.progress import ProgressLog

log = logging.getLogger("cps_experiment")

IMAGE = "kathara/cps"
# Zones (collision domains)
IT, OT, DEF = "IT", "OT", "DEF"
# Addresses
ATTACKER_IP  = "10.10.0.10"
HMI_IP       = "10.10.0.20"
FW_IT_IP     = "10.10.0.1"
FW_OT_IP     = "10.20.0.1"
PLC_IP       = "10.20.0.10"
ENGINE_IP    = "10.20.0.20"
SENSOR_DEF_IP = "10.30.0.10"
IT_NET, OT_NET, DEF_NET = "10.10.0.0/24", "10.20.0.0/24", "10.30.0.0/24"
MODBUS_PORT  = 5020
APP_PORT     = 8080
DASHBOARD_GUEST_PORT = 8080
ATTACK_MODES = ("setpoint-overvoltage", "breaker-open", "manual-hijack")
LEARN_MARGIN_S = 5.0   # the model's calibration must end this long before the attack
# Untimed phases: first-guess durations for the ETA (the dashboard replaces them
# with the durations it has observed in earlier runs of the same ledger).
OVERHEAD_ESTIMATE_S = {"deploy": 3.0, "services": 2.1, "attack": 4.0,
                       "download": 0.5, "undeploy": 1.0}   # measured on the smoke campaign
DEFAULT_POLL_S = 2.0


def _stage(machine, manifest):
    for host_path, guest_path in manifest:
        machine.create_file_from_path(host_path, guest_path)


def firewall_rules():
    """Standing IT/OT boundary ruleset: default-drop forwarding, keep established
    flows, and allow ONLY the sanctioned HMI -> engine Modbus flow. The firewall
    cannot tell a legitimate operator command from a hijacked one — it only sees
    "HMI, TCP to 5020" — which is what the DPI sensor (and, later, the SOAR
    response) exist to compensate for."""
    return [
        "sysctl -w net.ipv4.ip_forward=1",
        "iptables -P FORWARD DROP",
        "iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT",
        f"iptables -A FORWARD -s {HMI_IP} -d {ENGINE_IP} -p tcp --dport {MODBUS_PORT} -j ACCEPT",
    ]


def build_lab(args):
    """Build (but do not deploy) the 3-zone lab. Returns (lab, machines) so the
    topology can be inspected/tested without Docker."""
    lab = Lab("cps")

    attacker  = lab.new_machine("attacker", image=IMAGE)
    hmi = lab.new_machine("hmi", image=IMAGE)
    firewall  = lab.new_machine("firewall", image=IMAGE)
    plc       = lab.new_machine("plc", image=IMAGE)
    engine    = lab.new_machine("engine", image=IMAGE)
    sensor    = lab.new_machine("sensor", image=IMAGE)

    # Interface order fixes eth0, eth1, ... — must match the startup files below.
    lab.connect_machine_obj_to_link(attacker, IT)     # eth0
    lab.connect_machine_obj_to_link(hmi, IT)    # eth0
    lab.connect_machine_obj_to_link(firewall, IT)     # eth0 (IT side)
    lab.connect_machine_obj_to_link(firewall, OT)     # eth1 (OT side)
    lab.connect_machine_obj_to_link(plc, OT)          # eth0
    lab.connect_machine_obj_to_link(engine, OT)       # eth0
    lab.connect_machine_obj_to_link(sensor, OT)       # eth0 (passive sniff)
    lab.connect_machine_obj_to_link(sensor, DEF)      # eth1 (management)

    dashboard = bool(getattr(args, "dashboard_port", 0))
    if dashboard:
        sensor.add_meta("bridged", True)
        sensor.add_meta("port", f"{args.dashboard_port}:{DASHBOARD_GUEST_PORT}/tcp")

    # Stage guest files.
    _stage(attacker, ATTACKER_CPS_FILES)
    _stage(hmi, HMI_FILES)
    _stage(plc, PLC_FILES)
    _stage(engine, ENGINE_FILES)
    _stage(sensor, SENSOR_FILES)

    # Startup (interface/route setup + the boundary ruleset). Kept in a dict so
    # the exact commands are inspectable/testable without materialising the fs.
    startups = {
        "attacker": [
            f"ip address add {ATTACKER_IP}/24 dev eth0",
            f"ip route add default via {FW_IT_IP} dev eth0",
        ],
        "hmi": [
            f"ip address add {HMI_IP}/24 dev eth0",
            f"ip route add default via {FW_IT_IP} dev eth0",
        ],
        "firewall": [
            f"ip address add {FW_IT_IP}/24 dev eth0",
            f"ip address add {FW_OT_IP}/24 dev eth1",
        ] + firewall_rules(),
        "plc": [
            f"ip address add {PLC_IP}/24 dev eth0",
            f"ip route add default via {FW_OT_IP} dev eth0",
        ],
        "engine": [
            f"ip address add {ENGINE_IP}/24 dev eth0",
            f"ip route add default via {FW_OT_IP} dev eth0",
        ],
        # Sensor: passive promiscuous NIC on OT (no IP -> unreachable from OT),
        # management IP on the defense net.
        "sensor": [
            "ip link set eth0 promisc on",
            "ip link set eth0 up",
            f"ip address add {SENSOR_DEF_IP}/24 dev eth1",
        ],
    }
    machines = {
        "attacker": attacker, "hmi": hmi, "firewall": firewall,
        "plc": plc, "engine": engine, "sensor": sensor,
    }
    for name, cmds in startups.items():
        lab.create_startup_file_from_list(machines[name], cmds)

    return lab, machines, startups


def validate_args(args):
    """Fail fast on a run whose model would calibrate on attack traffic."""
    if getattr(args, "attack", False) and \
            args.normal_duration < args.learn_seconds + LEARN_MARGIN_S:
        raise SystemExit(
            f"--normal-duration ({args.normal_duration}s) must be >= --learn-seconds "
            f"({args.learn_seconds}s) + {LEARN_MARGIN_S}s: the sensor's model calibrates "
            f"on the first --learn-seconds and must not see the attack")


def planned_phases(args):
    """The phases a run goes through, with their planned durations (s)."""
    ph = [("deploy", OVERHEAD_ESTIMATE_S["deploy"]),
          ("services", OVERHEAD_ESTIMATE_S["services"]),
          ("normal", float(args.normal_duration))]
    if getattr(args, "attack", False):
        ph += [("attack", OVERHEAD_ESTIMATE_S["attack"]),
               ("post_attack", float(args.post_attack_duration))]
    ph += [("download", OVERHEAD_ESTIMATE_S["download"]),
           ("undeploy", OVERHEAD_ESTIMATE_S["undeploy"])]
    return [{"name": n, "planned_s": d} for n, d in ph]


def planned_run_s(args):
    return sum(p["planned_s"] for p in planned_phases(args))


@contextlib.contextmanager
def phase(emit, name, **fields):
    """Emit phase start/end around a block (end carries the outcome)."""
    t0 = time.time()
    emit("phase", name=name, state="start", **fields)
    ok = False
    try:
        yield
        ok = True
    finally:
        emit("phase", name=name, state="end", ok=ok, duration_s=round(time.time() - t0, 3))


def run(args, progress=None):
    """Deploy the lab, run one episode, download the artifacts, undeploy.

    `progress` is a ledger emitter (monitor.progress); when None — a standalone
    `make cps-lab` / `cps-attack` — the run keeps its own ledger at
    <out_dir>/progress.jsonl (or --progress-file)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    validate_args(args)
    own = progress is None
    if own:
        ledger = ProgressLog(getattr(args, "progress_file", None)
                             or os.path.join(args.out_dir, "progress.jsonl"))
        run_id = getattr(args, "run_id", None) or os.path.basename(os.path.normpath(args.out_dir))
        emit = ledger.bind(run_id=run_id)
    else:
        emit = progress
    attack = bool(getattr(args, "attack", False))
    emit("run_start", mode=args.attack_mode if attack else "normal", seed=args.seed,
         attack=attack, out_dir=args.out_dir, learn_s=args.learn_seconds,
         poll_s=getattr(args, "poll_interval", DEFAULT_POLL_S),
         phases=planned_phases(args), planned_s=planned_run_s(args))

    t0 = time.time()
    status, error = "failed", None
    try:
        os.makedirs(args.out_dir, exist_ok=True)
        manager = Kathara.get_instance()
        Setting.get_instance().load_from_dict({"network_plugin": "kathara/katharanp_vde"})
        lab, m, _startups = build_lab(args)
        with phase(emit, "deploy"):
            log.info("Undeploying any existing lab")
            manager.undeploy_lab(lab=lab)
            log.info("Deploying cps lab")
            manager.deploy_lab(lab=lab)
        try:
            _run_episode(manager, m, args, emit)
            with phase(emit, "download"):
                _download_artifacts(manager, m, args.out_dir, attack=attack)
        finally:
            with phase(emit, "undeploy"):
                log.info("Undeploying cps lab")
                manager.undeploy_lab(lab=lab)
        status = "ok"
    except KeyboardInterrupt:
        status, error = "interrupted", "KeyboardInterrupt"
        raise
    except BaseException:
        error = traceback.format_exc()[-2000:]
        raise
    finally:
        emit("run_end", status=status, duration_s=round(time.time() - t0, 3), error=error)
        if own:
            ledger.close()


def _exec_text(manager, machine, cmd):
    out, _err, _rc = manager.exec_obj(machine, cmd, stream=False)
    return (out or b"").decode(errors="replace")


def _poll_plant(manager, m, emit, state):
    """Pull the live plant state and the sensor's new events out of the
    containers and put them on the ledger. Never raises: live monitoring must
    not break a run."""
    try:
        lines = [x for x in _exec_text(manager, m["engine"],
                                       "tail -n 1 /engine_frames.jsonl").splitlines() if x.strip()]
        if lines:
            fr = json.loads(lines[-1])
            if fr.get("step") != state.get("step"):
                state["step"] = fr.get("step")
                act = fr.get("actuators") or {}
                emit("plant", step=fr.get("step"), frame_t=fr.get("timestamp"),
                     v_load=fr.get("v_load"), v_dg=fr.get("v_dg"), abnormal=fr.get("abnormal"),
                     line_load=fr.get("line_load"), p_dg=fr.get("p_dg"),
                     energy_kwh=fr.get("energy_kwh"), dg_setpoint=act.get("dg_setpoint"),
                     ctrl_mode=act.get("ctrl_mode"), switch_cmd=act.get("switch_cmd"))
    except Exception as e:
        log.debug("plant poll failed: %s", e)
    try:
        start = state.get("tel_lines", 0) + 1
        raw = _exec_text(manager, m["sensor"], f"tail -n +{start} /telemetry.jsonl")
        consumed = 0
        for line in raw.splitlines():
            if not line.strip():
                consumed += 1
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                break            # partial last line: read it next time
            consumed += 1
            kind = ev.get("kind")
            ent = ev.get("entities") or {}
            if kind == "ot_finding":
                emit("finding", detector=ev.get("detector") or "rules", klass=ev.get("klass"),
                     src=ent.get("src"), register=ent.get("register"),
                     confidence=ev.get("confidence"), guest_t=ev.get("t"))
            elif kind == "ot_alert":
                emit("alert", state=ev.get("state"), detector=ev.get("detector") or "rules",
                     klass=ev.get("klass"), guest_t=ev.get("t"))
            elif kind in ("model_fitted", "model_error"):
                emit(kind, threshold=ev.get("threshold"), error=ev.get("error"),
                     guest_t=ev.get("t"))
        state["tel_lines"] = start - 1 + consumed
    except Exception as e:
        log.debug("sensor poll failed: %s", e)


def _observe(manager, m, seconds, emit, state, poll_s):
    """Wait `seconds` (deadline-based, so the phase keeps its length), pulling
    the live plant state every `poll_s` (0 = just wait)."""
    deadline = time.time() + seconds
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return
        if poll_s <= 0:
            time.sleep(remaining)
            return
        time.sleep(min(poll_s, remaining))
        _poll_plant(manager, m, emit, state)


def _emit_attack_writes(gt_path, emit):
    try:
        with open(gt_path) as f:
            for line in f:
                ev = json.loads(line)
                if ev.get("kind") == "modbus_write":
                    emit("attack_write", register=ev.get("register"),
                         register_name=ev.get("register_name"), value=ev.get("value"),
                         ok=ev.get("ok"), write_t=ev.get("t"))
    except Exception as e:
        log.debug("could not replay ground truth: %s", e)


def _run_episode(manager, m, args, emit):
    eng_seed = role_seed(args.seed, "engine")
    plc_seed = role_seed(args.seed, "plc")
    hmi_seed = role_seed(args.seed, "hmi")
    poll_s = float(getattr(args, "poll_interval", DEFAULT_POLL_S) or 0)
    live = {}

    with phase(emit, "services"):
        # DPI sensor first, so the model's calibration window covers the clients'
        # session setup as well as steady state.
        dash = f" --dashboard-port {DASHBOARD_GUEST_PORT}" if getattr(args, "dashboard_port", 0) else ""
        manager.exec_obj(m["sensor"], with_console_log(
            f"python3 ot_sensor.py --iface eth0 --engine-ip {ENGINE_IP} --engine-port {MODBUS_PORT} "
            f"--plc-ip {PLC_IP} --hmi-ip {HMI_IP} --detectors {args.detectors} "
            f"--learn-seconds {args.learn_seconds} --telemetry-file telemetry.jsonl{dash}",
            "sensor.log"), wait=False)
        # Physical engine (Modbus server + physics stepper).
        manager.exec_obj(m["engine"], with_console_log(
            f"python3 modbus_engine.py --host 0.0.0.0 --port {MODBUS_PORT} "
            f"--interval {args.step_interval} --frame-log engine_frames.jsonl{seed_arg(eng_seed)}",
            "engine.log"), wait=False)
        time.sleep(2)
        # PLC master / controller.
        manager.exec_obj(m["plc"], with_console_log(
            f"python3 plc_controller.py --engine-host {ENGINE_IP} --port {MODBUS_PORT} "
            f"--interval {args.step_interval}{seed_arg(plc_seed)}", "plc.log"), wait=False)
        # HMI: legitimate polling + operator dispatches, and the vulnerable web app.
        manager.exec_obj(m["hmi"], with_console_log(
            f"python3 hmi_client.py --engine-host {ENGINE_IP} --port {MODBUS_PORT}"
            f"{seed_arg(hmi_seed)}", "hmi.log"), wait=False)
        manager.exec_obj(m["hmi"], with_console_log(
            f"python3 vuln_app.py --host 0.0.0.0 --port {APP_PORT}", "vuln_app.log"), wait=False)

    log.info("Normal operation for %.0fs (model calibration: first %.0fs)",
             args.normal_duration, args.learn_seconds)
    with phase(emit, "normal", learn_s=args.learn_seconds):
        _observe(manager, m, args.normal_duration, emit, live, poll_s)

    gt_path = os.path.join(args.out_dir, "ground_truth.jsonl")
    gt = GroundTruth(gt_path)
    gt.record("run_meta", scenario="cps", seed=args.seed, attack=bool(args.attack),
              attack_mode=args.attack_mode, engine_ip=ENGINE_IP, plc_ip=PLC_IP,
              hmi_ip=HMI_IP, authorized_writer=PLC_IP, learn_seconds=args.learn_seconds,
              detectors=args.detectors)
    try:
        if args.attack:
            with phase(emit, "attack", mode=args.attack_mode):
                active_attack.drive_attack(
                    manager, m["attacker"], gt,
                    target_url=f"http://{HMI_IP}:{APP_PORT}",
                    engine_ip=ENGINE_IP, engine_port=MODBUS_PORT,
                    attack_mode=args.attack_mode, repeat=args.attack_repeat,
                    interval=args.attack_interval)
            _emit_attack_writes(gt_path, emit)
            log.info("Post-attack observation for %.0fs", args.post_attack_duration)
            with phase(emit, "post_attack"):
                _observe(manager, m, args.post_attack_duration, emit, live, poll_s)
    finally:
        gt.record("run_end")
        gt.close()


def _download_artifacts(manager, m, out_dir, attack=True):
    wanted = {
        "engine":    ["engine_frames.jsonl", "engine.log"],
        "plc":       ["plc.log"],
        "sensor":    ["telemetry.jsonl", "sensor.log"],
        "hmi":       ["hmi.log", "vuln_app.log"],
        "attacker":  ["exploit.log"],
    }
    if not attack:
        del wanted["attacker"]   # nothing ran there
    for name, files in wanted.items():
        container = m[name].api_object
        for f in files:
            try:
                download_file_from_container(container, f"/{f}", os.path.join(out_dir, f"{name}.{f}"))
            except Exception as e:
                log.warning("could not download %s:/%s (%s)", name, f, e)


def main():
    ap = argparse.ArgumentParser(description="Cyber-physical OT/Modbus Kathará scenario")
    ap.add_argument("--out-dir", default="output/cps/run-1")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--step-interval", type=float, default=1.0)
    ap.add_argument("--normal-duration", type=float, default=60.0)
    ap.add_argument("--learn-seconds", type=float, default=45.0,
                    help="sensor model calibration period (inside the normal phase)")
    ap.add_argument("--detectors", default="rules,model",
                    help="sensor detectors to run (comma list of rules, model)")
    ap.add_argument("--attack", action="store_true", help="run the active attack chain")
    ap.add_argument("--attack-mode", default="setpoint-overvoltage", choices=ATTACK_MODES)
    ap.add_argument("--attack-repeat", type=int, default=None,
                    help="times the write sequence is issued (default: per attack mode)")
    ap.add_argument("--attack-interval", type=float, default=0.5)
    ap.add_argument("--post-attack-duration", type=float, default=30.0)
    ap.add_argument("--dashboard-port", type=int, default=0, help="0 disables the live dashboard")
    ap.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_S,
                    help="seconds between live plant/sensor pulls for the progress ledger "
                         "(0 = no live view)")
    ap.add_argument("--progress-file", default=None,
                    help="progress ledger path (default <out-dir>/progress.jsonl)")
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
