"""components.py — defense plane building blocks (see cyberrange/core).

Detection and response, proactive and reactive:
    MtdCoordinator     moving-target defense on the SEMP (fixed timers or RL policy)
    QkdCertBootstrap   mutual-TLS bundle over the QKD-simulated channel
    OtSensor           passive Modbus DPI (rules + learned model) on the OT link
    ItSensor           host sensor on the HMI (web log, processes, connections)
    SoarResponder      host-side response loop: findings -> attack tree -> policy
                       -> countermeasures in the lab
    WazuhManager       the SOC's manager on the management network
    WazuhAgent         a host reporting to it and running its active responses
    WazuhEnforcer      applies a countermeasure through the manager, not by exec

Every guest sensor writes telemetry.jsonl-shaped events (mtd_telemetry.py) and
declares it as a TelemetrySource; ``mirror`` maps its events onto the
progress ledger.
"""

import base64
import json
import logging
import os
import time

from cyberrange.core.component import Artifact, Component, GuestAgent, TelemetrySource
from cyberrange.core.context import seed_arg

log = logging.getLogger("cyberrange.planes.defense.components")

PLANE = "defense"


def _finding(ev):
    ent = ev.get("entities") or {}
    return "finding", dict(
        detector=ev.get("detector") or "rules",
        klass=ev.get("klass"),
        src=ent.get("src"),
        register=ent.get("register"),
        confidence=ev.get("confidence"),
        guest_t=ev.get("t"),
    )


def _alert(ev):
    return "alert", dict(
        state=ev.get("state"),
        detector=ev.get("detector") or "rules",
        klass=ev.get("klass"),
        guest_t=ev.get("t"),
    )


# ── cyber-physical ────────────────────────────────────────────────────────────
class OtSensor(GuestAgent):
    """Passive Modbus DPI on the OT link; findings on its management NIC."""

    TELEMETRY = "/telemetry.jsonl"

    def __init__(
        self,
        node,
        iface,
        engine_ip,
        engine_port,
        plc_ip,
        hmi_ip,
        detectors,
        learn_seconds,
        dashboard_port=None,
        responder_ip=None,
    ):
        """``responder_ip``: the address the automated response writes to the
        plant from; without it the sensor reports those writes as an attack."""
        dash = f" --dashboard-port {dashboard_port}" if dashboard_port else ""
        resp = f" --responder-ip {responder_ip}" if responder_ip else ""
        super().__init__(
            node,
            f"python3 ot_sensor.py --iface {iface} --engine-ip {engine_ip} "
            f"--engine-port {engine_port} --plc-ip {plc_ip} --hmi-ip {hmi_ip} "
            f"--detectors {detectors} --learn-seconds {learn_seconds} "
            f"--telemetry-file telemetry.jsonl{resp}{dash}",
            "sensor.log",
            plane=PLANE,
            name="ot_sensor",
            artifacts=[Artifact(node, self.TELEMETRY, f"{node}.telemetry.jsonl")],
        )

    def telemetry(self):
        return [TelemetrySource(self.node, self.TELEMETRY, "ot")]

    def mirror(self, ev):
        kind = ev.get("kind")
        if kind == "ot_finding":
            return _finding(ev)
        if kind == "ot_alert":
            return _alert(ev)
        if kind in ("model_fitted", "model_error"):
            return kind, dict(
                threshold=ev.get("threshold"), error=ev.get("error"), guest_t=ev.get("t")
            )
        if kind == "ot_response_write":
            return "response_write", dict(
                src=ev.get("src"),
                register=ev.get("register"),
                value=ev.get("value"),
                guest_t=ev.get("t"),
            )
        return None


class ItSensor(GuestAgent):
    """Host sensor on the HMI: makes the attacker's early (IT) steps observable.
    Needs the web app's access log (cyberrange.planes.attack.components.VulnApp(access_log=))."""

    TELEMETRY = "/it_telemetry.jsonl"

    def __init__(self, node, engine_ip, engine_port, access_log, learn_seconds):
        super().__init__(
            node,
            f"python3 it_sensor.py --engine-ip {engine_ip} --engine-port {engine_port} "
            f"--access-log {access_log} --learn-seconds {learn_seconds} "
            f"--telemetry-file it_telemetry.jsonl",
            "it_sensor.log",
            plane=PLANE,
            name="it_sensor",
            artifacts=[Artifact(node, self.TELEMETRY, f"{node}.it_telemetry.jsonl")],
        )

    def telemetry(self):
        return [TelemetrySource(self.node, self.TELEMETRY, "it")]

    def mirror(self, ev):
        kind = ev.get("kind")
        if kind == "ot_finding":
            return _finding(ev)
        if kind == "ot_alert":
            return _alert(ev)
        return None


# ── management network (Wazuh) ───────────────────────────────────────────────
# The tooling itself is node software (nodes/wazuh/, staged by the scenario's
# manifests): these components only launch it and name what it leaves behind.
class WazuhManager(GuestAgent):
    """The Wazuh manager on the SOC node. ``agents`` is {name: (id, key)}: each
    agent is registered with the key its WazuhAgent is started with."""

    ALERTS = "/var/ossec/logs/alerts/alerts.json"
    LOG = "/var/ossec/logs/ossec.log"

    def __init__(self, node, agents):
        registered = " ".join(f"{i}:{name}:{key}" for name, (i, key) in sorted(agents.items()))
        super().__init__(
            node,
            f"bash /wazuh-manager-setup.sh {registered}",
            "wazuh_manager.log",
            plane=PLANE,
            name="wazuh_manager",
            artifacts=[
                Artifact(node, self.ALERTS, f"{node}.alerts.json"),
                Artifact(node, self.LOG, f"{node}.ossec.log"),
            ],
        )


class WazuhAgent(GuestAgent):
    """A host of the management network: ships ``logs`` (guest JSONL files) to
    the manager and runs the countermeasures in ``responses``
    ({id: {"apply": [cmd], "revert": [cmd]}}) when the manager asks for one."""

    RECORD = "/var/ossec/logs/cps-response.jsonl"
    LOG = "/var/ossec/logs/ossec.log"

    def __init__(self, node, manager_ip, agent_id, key, responses=None, logs=()):
        allowlist = base64.b64encode(json.dumps(responses or {}).encode()).decode()
        super().__init__(
            node,
            f"bash /wazuh-agent-setup.sh {manager_ip} {agent_id} {node} {key} {allowlist} "
            + " ".join(logs),
            "wazuh_agent.log",
            plane=PLANE,
            name=f"wazuh_agent:{node}",
            artifacts=[
                Artifact(node, self.RECORD, f"{node}.cps-response.jsonl"),
                Artifact(node, self.LOG, f"{node}.ossec.log"),
            ],
        )


class SocAnalytics(GuestAgent):
    """The SOC's analytics on the manager's node (soc_analytics.py): it reads
    the manager's alerts, keeps the attack tree's belief and asks the manager
    for the responses. The decision runs here, in the lab, not on the host.

    ``policy`` is off | rules | solver; with ``off`` it watches and requests
    nothing. ``inventory`` is the lab as the SOC is told it (cps.inventory):
    the one thing a node cannot discover, passed base64 on the command line."""

    RESPONSE = "/response.jsonl"
    KG, TREE = "/kg.json", "/tree.json"

    def __init__(self, node, inventory, policy="off", approval="auto", interval=0.5, it=False):
        inv = base64.b64encode(json.dumps(inventory).encode()).decode()
        super().__init__(
            node,
            f"python3 soc_analytics.py --inventory-b64 {inv} --policy {policy} "
            f"--approval {approval} --interval {interval}" + (" --it" if it else ""),
            "soc_analytics.log",
            plane=PLANE,
            name="soc_analytics",
            artifacts=[
                Artifact(node, self.RESPONSE, "response.jsonl"),
                Artifact(node, self.KG, f"{node}.kg.json"),
                Artifact(node, self.TREE, f"{node}.tree.json"),
            ],
        )

    def telemetry(self):
        return [TelemetrySource(self.node, self.RESPONSE, "soar")]

    def mirror(self, ev):
        kind = ev.get("kind")
        if kind == "tree_state":
            nodes = ev.get("nodes") or {}
            return "tree_state", {
                "nodes": {n: [v.get("state"), v.get("score")] for n, v in nodes.items()},
                "active": ev.get("active_impacts"),
                "hosts": ev.get("hosts_implicated"),
                "next": ev.get("next"),
                "guest_t": ev.get("belief_t"),
            }
        if kind == "decision":
            return "decision", {
                k: ev.get(k) for k in ("policy", "actions", "rationale", "covers", "needs_approval")
            } | {"guest_t": ev.get("decided_t")}
        if kind == "action":
            return "action", dict(
                id=ev.get("id"),
                ok=ev.get("ok"),
                machine=ev.get("machine"),
                guest_t=ev.get("done_t"),
            )
        return None


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

    def __init__(
        self,
        ca_node,
        client_node,
        shared_key,
        server_ips,
        client_ips,
        ca_ip="10.1.0.2",
        ca_port=9999,
        server_cn="semp",
        client_cn="scmc1",
    ):
        self.ca_node, self.client_node = ca_node, client_node
        self.shared_key, self.server_ips, self.client_ips = shared_key, server_ips, client_ips
        self.ca_ip, self.ca_port = ca_ip, ca_port
        self.server_cn, self.client_cn = server_cn, client_cn

    def start(self, ctx):
        ctx.exec(
            self.ca_node,
            f"python3 cert_authority.py --shared-key {self.shared_key} --host 0.0.0.0 "
            f"--port {self.ca_port} --out-dir /etc/mosquitto/certs/ "
            f"--server-cn {self.server_cn} --server-ip {self.server_ips} "
            f"--client-ip {self.client_ips}",
        )
        cmd = (
            f"python3 cert_client.py --shared-key {self.shared_key} --ca-host {self.ca_ip} "
            f"--cn {self.client_cn} --out-dir certs/"
        )
        for attempt in range(1, self.ATTEMPTS + 1):
            out, err, rc = ctx.run(self.client_node, cmd, wait=True)
            if rc == 0:
                return
            detail = (err or out or b"").decode(errors="replace").strip().splitlines()
            log.warning(
                "cert client attempt %d/%d failed (rc=%s): %s",
                attempt,
                self.ATTEMPTS,
                rc,
                detail[-1] if detail else "no output",
            )
            time.sleep(2)
        raise RuntimeError("SCMC could not obtain its client certificate from the CA")


class MtdCoordinator(GuestAgent):
    """The MTD coordinator on the SEMP: fixed per-knob timers, or an RL policy
    (``rl_policy`` = guest path of the distilled .npz) deciding when to move."""

    TELEMETRY = "/telemetry.jsonl"

    def __init__(
        self,
        node,
        shared_key,
        ip_pool,
        port_pool,
        pad_buckets,
        scmc_ip_pool,
        freq_pool,
        hop_timeout=10.0,
        hop_interval=2,
        pad_interval=3,
        src_hop_interval=2,
        freq_interval=30,
        rl_policy=None,
        rl_tick=1.0,
        seed=None,
        dashboard_port=None,
        detector_model=None,
        observe_data=True,
    ):
        common = (
            f" --control-port 9998 --ip-pool {ip_pool} --port-pool {port_pool}"
            f" --real-port 18883 --hop-timeout {hop_timeout}"
            f" --pad-buckets {pad_buckets} --scmc-ip-pool {scmc_ip_pool}"
            f" --freq-pool {freq_pool}"
        )
        if rl_policy:
            cmd = f"python3 mtd_rl_coordinator.py --policy {rl_policy} --tick {rl_tick}" + common
        else:
            cmd = (
                "python3 mtd_coordinator.py"
                + common
                + f" --hop-interval {hop_interval} --pad-interval {pad_interval}"
                f" --src-hop-interval {src_hop_interval}"
                f" --freq-interval {freq_interval}"
            )
        cmd += f" --shared-key {shared_key}" + seed_arg(seed)
        if observe_data:
            cmd += " --observe-data"
        if dashboard_port:
            cmd += f" --dashboard-port {dashboard_port}"
        if detector_model:
            cmd += f" --detector-model {detector_model}"
        super().__init__(
            node,
            cmd,
            "coordinator.log",
            plane=PLANE,
            name="mtd_coordinator_rl" if rl_policy else "mtd_coordinator",
        )
        self.kind = "rl" if rl_policy else "fixed"

    def artifacts(self):
        return []  # downloaded with the capture's prefix by the scenario

    def telemetry(self):
        return [TelemetrySource(self.node, self.TELEMETRY, "mtd")]

    def mirror(self, ev):
        kind = ev.get("kind")
        if kind == "action_outcome":
            return "mtd_action", {
                k: ev.get(k)
                for k in ("seq", "action", "status", "rolled_back", "cost", "duration_s")
            } | {"guest_t": ev.get("t")}
        if kind == "data_gap":
            return "data_gap", dict(
                scmc_id=ev.get("scmc_id"), gap_s=ev.get("gap_s"), guest_t=ev.get("t")
            )
        if kind in ("detection", "detector_alert"):
            return kind, {k: v for k, v in ev.items() if k not in ("i", "t", "kind")} | {
                "guest_t": ev.get("t")
            }
        return None
