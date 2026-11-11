"""components.py — defense plane building blocks (see network_scenario/core).

Detection and response, proactive and reactive:
    MtdCoordinator     moving-target defense on the SEMP (fixed timers or RL policy)
    QkdCertBootstrap   mutual-TLS bundle over the QKD-simulated channel
    OtSensor           passive Modbus DPI (rules + learned model) on the OT link
    ItSensor           host sensor on the HMI (web log, processes, connections)
    SoarResponder      host-side response loop: findings -> attack tree -> policy
                       -> countermeasures in the lab

Every guest sensor writes telemetry.jsonl-shaped events (mtd_telemetry.py) and
declares it as a TelemetrySource; ``mirror`` maps its events onto the
progress ledger.
"""

import logging
import os
import time

from network_scenario.core.component import (
    Artifact, Component, GuestAgent, TelemetrySource, tail_reader,
)
from network_scenario.core.context import seed_arg

log = logging.getLogger("defense_plane.components")

PLANE = "defense"


def _finding(ev):
    ent = ev.get("entities") or {}
    return "finding", dict(detector=ev.get("detector") or "rules", klass=ev.get("klass"),
                           src=ent.get("src"), register=ent.get("register"),
                           confidence=ev.get("confidence"), guest_t=ev.get("t"))


def _alert(ev):
    return "alert", dict(state=ev.get("state"), detector=ev.get("detector") or "rules",
                         klass=ev.get("klass"), guest_t=ev.get("t"))


# ── cyber-physical ────────────────────────────────────────────────────────────
class OtSensor(GuestAgent):
    """Passive Modbus DPI on the OT link; findings on its management NIC."""

    TELEMETRY = "/telemetry.jsonl"

    def __init__(self, node, iface, engine_ip, engine_port, plc_ip, hmi_ip, detectors,
                 learn_seconds, dashboard_port=None):
        dash = f" --dashboard-port {dashboard_port}" if dashboard_port else ""
        super().__init__(
            node,
            f"python3 ot_sensor.py --iface {iface} --engine-ip {engine_ip} "
            f"--engine-port {engine_port} --plc-ip {plc_ip} --hmi-ip {hmi_ip} "
            f"--detectors {detectors} --learn-seconds {learn_seconds} "
            f"--telemetry-file telemetry.jsonl{dash}",
            "sensor.log", plane=PLANE, name="ot_sensor",
            artifacts=[Artifact(node, self.TELEMETRY, f"{node}.telemetry.jsonl")])

    def telemetry(self):
        return [TelemetrySource(self.node, self.TELEMETRY, "ot")]

    def mirror(self, ev):
        kind = ev.get("kind")
        if kind == "ot_finding":
            return _finding(ev)
        if kind == "ot_alert":
            return _alert(ev)
        if kind in ("model_fitted", "model_error"):
            return kind, dict(threshold=ev.get("threshold"), error=ev.get("error"),
                              guest_t=ev.get("t"))
        return None


class ItSensor(GuestAgent):
    """Host sensor on the HMI: makes the attacker's early (IT) steps observable.
    Needs the web app's access log (attack_plane.components.VulnApp(access_log=))."""

    TELEMETRY = "/it_telemetry.jsonl"

    def __init__(self, node, engine_ip, engine_port, access_log, learn_seconds):
        super().__init__(
            node,
            f"python3 it_sensor.py --engine-ip {engine_ip} --engine-port {engine_port} "
            f"--access-log {access_log} --learn-seconds {learn_seconds} "
            f"--telemetry-file it_telemetry.jsonl",
            "it_sensor.log", plane=PLANE, name="it_sensor",
            artifacts=[Artifact(node, self.TELEMETRY, f"{node}.it_telemetry.jsonl")])

    def telemetry(self):
        return [TelemetrySource(self.node, self.TELEMETRY, "it")]

    def mirror(self, ev):
        kind = ev.get("kind")
        if kind == "ot_finding":
            return _finding(ev)
        if kind == "ot_alert":
            return _alert(ev)
        return None


class SoarResponder(Component):
    """The response loop (network_scenario/cps_responder.Responder) as a host
    thread reading every started sensor's telemetry. The knowledge graph is
    built from the deployed lab, so the policy reasons on what really runs."""

    plane, name = PLANE, "soar_responder"

    def __init__(self, policy, approval="auto", interval=0.5, it=False):
        self.policy, self.approval, self.interval, self.it = policy, approval, interval, it
        self.responder = None

    def start(self, ctx):
        from defense_plane.soar import kg as soar_kg
        from network_scenario import cps_responder
        sources = [tail_reader(ctx.exec_text, s.node, s.path)
                   for s in ctx.telemetry_sources() if s.name in ("ot", "it")]
        self.responder = cps_responder.Responder(
            ctx.manager, ctx.machines, self.policy, ctx.out_dir, emit=ctx.emit,
            interval=self.interval, approval=self.approval, it=self.it,
            sources=sources, g=soar_kg.build_cps_kg(ctx.lab))
        self.responder.start()
        log.info("Responder up: policy=%s approval=%s it=%s", self.policy, self.approval,
                 self.it)

    def stop(self, ctx):
        if self.responder is not None:
            self.responder.stop()


# ── MQTT smart grid ───────────────────────────────────────────────────────────
def generate_shared_key(n_bytes: int = 32) -> str:
    """The QKD-simulated shared key (hex): a host-generated random key stands in
    for the output of the QKD device."""
    return os.urandom(n_bytes).hex()


class QkdCertBootstrap(Component):
    """The SEMP's certificate authority, bootstrapped from the QKD-simulated
    shared key, and the SCMC fetching its mTLS bundle from it (with retries:
    right after deploy the SCMC may still be unconfigured)."""

    plane, name = PLANE, "qkd_cert_bootstrap"
    ATTEMPTS = 5

    def __init__(self, ca_node, client_node, shared_key, server_ips, client_ips,
                 ca_ip="10.1.0.2", ca_port=9999, server_cn="semp", client_cn="scmc1"):
        self.ca_node, self.client_node = ca_node, client_node
        self.shared_key, self.server_ips, self.client_ips = shared_key, server_ips, client_ips
        self.ca_ip, self.ca_port = ca_ip, ca_port
        self.server_cn, self.client_cn = server_cn, client_cn

    def start(self, ctx):
        ctx.exec(self.ca_node,
                 f"python3 cert_authority.py --shared-key {self.shared_key} --host 0.0.0.0 "
                 f"--port {self.ca_port} --out-dir /etc/mosquitto/certs/ "
                 f"--server-cn {self.server_cn} --server-ip {self.server_ips} "
                 f"--client-ip {self.client_ips}")
        cmd = (f"python3 cert_client.py --shared-key {self.shared_key} --ca-host {self.ca_ip} "
               f"--cn {self.client_cn} --out-dir certs/")
        for attempt in range(1, self.ATTEMPTS + 1):
            out, err, rc = ctx.run(self.client_node, cmd, wait=True)
            if rc == 0:
                return
            detail = (err or out or b"").decode(errors="replace").strip().splitlines()
            log.warning("cert client attempt %d/%d failed (rc=%s): %s", attempt,
                        self.ATTEMPTS, rc, detail[-1] if detail else "no output")
            time.sleep(2)
        raise RuntimeError("SCMC could not obtain its client certificate from the CA")


class MtdCoordinator(GuestAgent):
    """The MTD coordinator on the SEMP: fixed per-knob timers, or an RL policy
    (``rl_policy`` = guest path of the distilled .npz) deciding when to move."""

    TELEMETRY = "/telemetry.jsonl"

    def __init__(self, node, shared_key, ip_pool, port_pool, pad_buckets, scmc_ip_pool,
                 freq_pool, hop_timeout=10.0, hop_interval=2, pad_interval=3,
                 src_hop_interval=2, freq_interval=30, rl_policy=None, rl_tick=1.0,
                 seed=None, dashboard_port=None, detector_model=None, observe_data=True):
        common = (f" --control-port 9998 --ip-pool {ip_pool} --port-pool {port_pool}"
                  f" --real-port 18883 --hop-timeout {hop_timeout}"
                  f" --pad-buckets {pad_buckets} --scmc-ip-pool {scmc_ip_pool}"
                  f" --freq-pool {freq_pool}")
        if rl_policy:
            cmd = f"python3 mtd_rl_coordinator.py --policy {rl_policy} --tick {rl_tick}" + common
        else:
            cmd = ("python3 mtd_coordinator.py" + common
                   + f" --hop-interval {hop_interval} --pad-interval {pad_interval}"
                     f" --src-hop-interval {src_hop_interval}"
                     f" --freq-interval {freq_interval}")
        cmd += f" --shared-key {shared_key}" + seed_arg(seed)
        if observe_data:
            cmd += " --observe-data"
        if dashboard_port:
            cmd += f" --dashboard-port {dashboard_port}"
        if detector_model:
            cmd += f" --detector-model {detector_model}"
        super().__init__(node, cmd, "coordinator.log", plane=PLANE,
                         name="mtd_coordinator_rl" if rl_policy else "mtd_coordinator")
        self.kind = "rl" if rl_policy else "fixed"

    def artifacts(self):
        return []   # downloaded with the capture's prefix by the scenario

    def telemetry(self):
        return [TelemetrySource(self.node, self.TELEMETRY, "mtd")]

    def mirror(self, ev):
        kind = ev.get("kind")
        if kind == "action_outcome":
            return "mtd_action", {k: ev.get(k) for k in ("seq", "action", "status",
                                                       "rolled_back", "cost", "duration_s")} | {
                "guest_t": ev.get("t")}
        if kind == "data_gap":
            return "data_gap", dict(scmc_id=ev.get("scmc_id"), gap_s=ev.get("gap_s"),
                                    guest_t=ev.get("t"))
        if kind in ("detection", "detector_alert"):
            return kind, {k: v for k, v in ev.items() if k not in ("i", "t", "kind")} | {
                "guest_t": ev.get("t")}
        return None
