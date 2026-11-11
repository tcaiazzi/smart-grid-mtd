"""components.py — traffic plane building blocks: the legitimate system activity
a scenario's attacks and defenses play against (see cyberrange/core).

CPS:   PhysicalProcess (pandapower twin behind Modbus), PlcController, HmiClient
MQTT:  BackgroundReplay (tcpreplay of a real trace), ScmcPublisher (nanogrid
       telemetry, baseline publisher or MTD executor)
"""

from cyberrange.core.component import Artifact, GuestAgent
from cyberrange.core.context import seed_arg

PLANE = "traffic"


# ── cyber-physical ────────────────────────────────────────────────────────────
class PhysicalProcess(GuestAgent):
    """The plant: grid physics stepper + Modbus/TCP server exposing it."""

    def __init__(self, node, port, step_interval, seed=None, frame_log="engine_frames.jsonl"):
        super().__init__(
            node,
            f"python3 modbus_engine.py --host 0.0.0.0 --port {port} "
            f"--interval {step_interval} --frame-log {frame_log}{seed_arg(seed)}",
            "engine.log",
            plane=PLANE,
            name="physical_process",
            artifacts=[Artifact(node, f"/{frame_log}", f"{node}.{frame_log}")],
        )
        self.frame_log = frame_log


class PlcController(GuestAgent):
    """The PLC: Modbus master closing the control loop (legitimate OT traffic)."""

    def __init__(self, node, engine_ip, port, interval, seed=None):
        super().__init__(
            node,
            f"python3 plc_controller.py --engine-host {engine_ip} --port {port} "
            f"--interval {interval}{seed_arg(seed)}",
            "plc.log",
            plane=PLANE,
            name="plc",
        )


class HmiClient(GuestAgent):
    """The HMI: operator polling + dispatches; with ``diag_url`` also the
    operator's legitimate use of the diagnostics web app."""

    def __init__(self, node, engine_ip, port, seed=None, diag_url=None):
        diag = f" --diag-url {diag_url}" if diag_url else ""
        super().__init__(
            node,
            f"python3 hmi_client.py --engine-host {engine_ip} --port {port}{seed_arg(seed)}{diag}",
            "hmi.log",
            plane=PLANE,
            name="hmi",
        )


# ── MQTT smart grid ───────────────────────────────────────────────────────────
class BackgroundReplay(GuestAgent):
    """Replays the background PCAP trace onto ``iface`` at ``mbps``
    (``duration`` None = until the lab goes down)."""

    def __init__(self, node, iface, mbps, duration=None):
        prefix = f"timeout {duration} " if duration is not None else ""
        super().__init__(
            node,
            f"{prefix}bash ./replay_background.sh {iface} {mbps} 0",
            "replay.log",
            plane=PLANE,
            name="background_replay",
        )

    def start(self, ctx):
        ctx.exec(self.node, self.command)  # its output is not worth a console log

    def artifacts(self):
        return []


class ScmcPublisher(GuestAgent):
    """The nanogrid's SCMC publishing over MQTT/mTLS: the plain publisher
    (``mtd=False``) or the MTD executor, which follows the coordinator's moves.

    ``state`` (detection_scenario.executor_state) restarts the executor where the
    MTD has moved it instead of the initial endpoint (``command_for(state)``)."""

    BROKER_IP = "10.1.0.2"

    def __init__(
        self,
        node,
        mtd,
        scmc_ip_pool,
        shared_key=None,
        seed=None,
        console_log="client.console.log",
        state=None,
    ):
        self.mtd, self.scmc_ip_pool = mtd, scmc_ip_pool
        self.shared_key, self.seed = shared_key, seed
        super().__init__(
            node, self.command_for(state), console_log, plane=PLANE, name="scmc_publisher"
        )

    @property
    def log_file(self):
        return "mtd_executor.log" if self.mtd else "simple_client.log"

    def command_for(self, state=None):
        if not self.mtd:
            return (
                "python3 simple_client.py --broker 10.1.0.2 --port 8883 --ssl "
                "--cafile certs/ca.crt --certfile certs/client.crt "
                "--keyfile certs/client.key --log-file simple_client.log" + seed_arg(self.seed)
            )
        state = state or {}
        broker = state.get("broker_ip", self.BROKER_IP)
        pool = [x.strip() for x in self.scmc_ip_pool.split(",")]
        if state.get("src_ip") in pool:  # current source first = bound at start
            i = pool.index(state["src_ip"])
            pool = pool[i:] + pool[:i]
        resume = ""
        if "broker_port" in state:
            resume += f" --mqtt-port {state['broker_port']}"
        if "interval" in state:
            resume += f" --interval {state['interval']}"
        if state.get("pad_buckets"):
            resume += f" --pad-buckets {','.join(map(str, state['pad_buckets']))}"
        key = f" --shared-key {self.shared_key}" if self.shared_key else ""
        return (
            f"python3 mtd_executor.py --grid-id scmc1 --broker {broker} --ssl "
            "--cafile certs/ca.crt --certfile certs/client.crt --keyfile certs/client.key "
            f"--semp-control-ip {broker} --semp-control-port 9998 "
            f"--scmc-ip-pool {','.join(pool)} --log-file mtd_executor.log"
            f"{resume}{key}{seed_arg(self.seed)}"
        )

    def artifacts(self):
        # Names are set by the scenario (prefix per capture); see mqtt_mtd.scenario.
        return []
