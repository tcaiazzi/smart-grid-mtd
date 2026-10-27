"""Labelled attack and benign-fault episodes for the delivery-attack detector.

The detector (defense_plane/delivery_detector.py) flags a blackhole from the SEMP's
side: nanogrid data stops arriving. Training and scoring it needs runs where we know
exactly when an attack was in effect and when data stopped for benign reasons. During
an --attack run's post-attack phase this module drives, from the host:

  • blackhole episodes — the CNN attacker's block (as in the paper), or an "oracle"
    attacker that blocks the address the SCMC <-> SEMP path is using right now (read
    from the SCMC's established MQTT socket), optionally lifted after
    --block-duration and repeated --block-episodes times;
  • benign faults (--impair-profile random) — tc netem loss, delay and burst loss on
    the router, and executor restarts.

Every action is written to ground_truth.jsonl (one JSON object per line, host clock,
which the containers share) next to the run's captures. The ground truth stays on the
host: the SEMP never sees it. monitor/delivery_dataset.py turns it into labels.
"""

import json
import logging
import random
import re
import threading
import time

log = logging.getLogger(__name__)

_ADDR_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)")
ROUTER_DEVS = ("eth0", "eth1")       # eth0 → SCMC side (link A), eth1 → SEMP side (link B)


class GroundTruth:
    """Append-only ground_truth.jsonl writer (thread-safe)."""

    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._f = open(path, "w", buffering=1)

    def record(self, kind: str, **fields) -> None:
        line = json.dumps({"t": round(time.time(), 3), "kind": kind, **fields})
        with self._lock:
            self._f.write(line + "\n")

    def close(self) -> None:
        with self._lock:
            self._f.close()


def _run(manager, machine, cmd: str) -> str:
    out, err, _rc = manager.exec_obj(machine, cmd, stream=False)
    return (out or b"").decode(errors="replace")


def mqtt_path(manager, scmc, port_pool) -> dict:
    """The SCMC's live MQTT socket: {"src_ip", "broker_ip", "broker_port"}, or {}.

    Its peer port is one of the hopping pool ports (the coordinator NATs them onto
    the broker); the control channel (port 9998) is ignored.
    """
    for line in _run(manager, scmc, "ss -Htn state established").splitlines():
        addrs = _ADDR_RE.findall(line)
        if len(addrs) >= 2 and int(addrs[1][1]) in port_pool:
            return {"src_ip": addrs[0][0], "broker_ip": addrs[1][0],
                    "broker_port": int(addrs[1][1])}
    return {}


_LOG_PATTERNS = {
    "connect": re.compile(r"\] MQTT → ([\d.]+):(\d+) \(ok\)"),
    "hop": re.compile(r"\] hop seq=(\d+)\s+[\d.]+:\d+ → ([\d.]+):(\d+)"),
    "hop_failed": re.compile(r"\] hop seq=(\d+) failed"),
    "src": re.compile(r"\] src hop seq=\d+\s+[\d.]+ → ([\d.]+)"),
    "interval": re.compile(r"publish interval → ([\d.]+)s"),
    "pad": re.compile(r"padding policy → \[([\d, ]*)\]"),
}


def executor_log_state(text: str) -> dict:
    """Where mtd_executor.log says the executor is: broker endpoint, source IP,
    publish interval and padding — what it applied, in order (a hop counts unless
    its "failed — staying" line follows). Works mid-reconnect, when no MQTT socket
    is established."""
    state, hop_from = {}, {}
    for line in text.splitlines():
        p = _LOG_PATTERNS
        if m := p["connect"].search(line):
            state["broker_ip"], state["broker_port"] = m.group(1), int(m.group(2))
        elif m := p["hop"].search(line):
            hop_from[m.group(1)] = (state.get("broker_ip"), state.get("broker_port"))
            state["broker_ip"], state["broker_port"] = m.group(2), int(m.group(3))
        elif (m := p["hop_failed"].search(line)) and m.group(1) in hop_from:
            state["broker_ip"], state["broker_port"] = hop_from.pop(m.group(1))
        elif m := p["src"].search(line):
            state["src_ip"] = m.group(1)
        elif m := p["interval"].search(line):
            state["interval"] = float(m.group(1))
        elif m := p["pad"].search(line):
            state["pad_buckets"] = [int(x) for x in m.group(1).split(",") if x.strip()]
    return {k: v for k, v in state.items() if v is not None}


def executor_state(manager, scmc, port_pool) -> dict:
    """What a restarted executor must resume with: the state its log records,
    corrected by the live MQTT socket when one is established."""
    state = executor_log_state(_run(manager, scmc, "cat mtd_executor.log"))
    state.update(mqtt_path(manager, scmc, port_pool))
    return state


class Scenario:
    """Drives blackhole and benign-fault episodes during the post-attack phase."""

    def __init__(self, manager, router, scmc, gt: GroundTruth, port_pool, seed, relaunch):
        self.manager, self.router, self.scmc, self.gt = manager, router, scmc, gt
        self.port_pool = set(port_pool)
        self.relaunch = relaunch          # relaunch(state: dict, n: int) → restart executor
        self.stop = threading.Event()
        self._rng_block = random.Random(None if seed is None else f"{seed}:block")
        self._rng_impair = random.Random(None if seed is None else f"{seed}:impair")
        self._blocked: set = set()
        self._netem_devs: set = set()
        self._threads: list = []
        self.restarts = 0

    # ── blackhole ──

    def block(self, ip: str, target: str) -> None:
        _run(self.manager, self.router, f"iptables -A FORWARD -s {ip} -j DROP")
        self._blocked.add(ip)
        self.gt.record("block", ip=ip, target=target)
        log.info("[Scenario] Blackhole %s (%s)", ip, target)

    def unblock(self, ip: str) -> None:
        _run(self.manager, self.router, f"iptables -D FORWARD -s {ip} -j DROP")
        self._blocked.discard(ip)
        self.gt.record("unblock", ip=ip)
        log.info("[Scenario] Lifted blackhole on %s", ip)

    def _target(self, oracle: str, cnn_ip: str):
        if not oracle:
            return cnn_ip, "cnn"
        which = oracle if oracle != "random" else self._rng_block.choice(["src", "broker"])
        path = (mqtt_path(self.manager, self.scmc, self.port_pool)
                or executor_state(self.manager, self.scmc, self.port_pool))
        ip = path.get("src_ip" if which == "src" else "broker_ip")
        if ip is None:
            log.warning("[Scenario] SCMC path unknown — oracle block skipped")
        return ip, f"oracle-{which}"

    def _blocks(self, oracle: str, cnn_ip: str, duration: float, episodes: int) -> None:
        for ep in range(episodes):
            if self.stop.is_set():
                return
            ip, target = self._target(oracle, cnn_ip)
            if ip is None:
                if self.stop.wait(5.0):
                    return
                continue
            self.block(ip, target)
            if self.stop.wait(duration):
                return
            self.unblock(ip)
            if ep < episodes - 1 and self.stop.wait(self._rng_block.uniform(20.0, 40.0)):
                return

    # ── benign faults ──

    def _netem(self, devs, spec: str, kind: str, params: dict, duration: float) -> None:
        for dev in devs:
            _run(self.manager, self.router, f"tc qdisc replace dev {dev} root netem {spec}")
            self._netem_devs.add(dev)
        self.gt.record("impair_start", type=kind, devs=list(devs), params=params)
        log.info("[Scenario] netem %s on %s for %.0fs", spec, ",".join(devs), duration)
        self.stop.wait(duration)
        self._netem_clear()
        self.gt.record("impair_stop", type=kind)

    def _netem_clear(self) -> None:
        for dev in list(self._netem_devs):
            _run(self.manager, self.router, f"tc qdisc del dev {dev} root")
            self._netem_devs.discard(dev)

    def _restart(self) -> None:
        state = executor_state(self.manager, self.scmc, self.port_pool)
        self.restarts += 1
        self.gt.record("executor_restart", phase="kill", state=state)
        log.info("[Scenario] Restarting the SCMC executor (resume state %s)", state)
        _run(self.manager, self.scmc, "pkill -f mtd_executor.py")
        self.stop.wait(self._rng_impair.uniform(1.0, 5.0))
        self.relaunch(state, self.restarts)
        self.gt.record("executor_restart", phase="relaunch")

    def _impairments(self) -> None:
        rng = self._rng_impair
        while not self.stop.wait(rng.uniform(8.0, 25.0)):
            kind = rng.choices(["loss", "delay", "burst", "restart"], [0.3, 0.25, 0.25, 0.2])[0]
            duration = rng.uniform(10.0, 30.0)
            if kind == "loss":
                p = rng.uniform(1.0, 10.0)
                self._netem(ROUTER_DEVS, f"loss {p:.1f}%", kind, {"loss_pct": p}, duration)
            elif kind == "delay":
                d = rng.uniform(50.0, 300.0)
                self._netem(("eth1",), f"delay {d:.0f}ms {d * 0.2:.0f}ms distribution normal",
                            kind, {"delay_ms": d}, duration)
            elif kind == "burst":
                p, r, h = rng.uniform(1, 5), rng.uniform(10, 40), rng.uniform(50, 100)
                self._netem(ROUTER_DEVS, f"loss gemodel {p:.1f}% {r:.1f}% {h:.1f}%", kind,
                            {"p_pct": p, "r_pct": r, "bad_loss_pct": h}, duration)
            else:
                self._restart()

    # ── lifecycle ──

    def start(self, oracle: str, cnn_ip: str, duration: float, episodes: int,
              impair: bool) -> None:
        if oracle or (cnn_ip and duration):
            self._threads.append(threading.Thread(
                target=self._blocks, args=(oracle, cnn_ip, duration or 1e9, episodes),
                daemon=True))
        elif cnn_ip:
            self.block(cnn_ip, "cnn")             # the paper's single permanent block
        if impair:
            self._threads.append(threading.Thread(target=self._impairments, daemon=True))
        for t in self._threads:
            t.start()

    def finish(self) -> None:
        """Stop the episodes and leave the lab as the capture end found it: faults
        removed, blackholes kept (the post-attack window already ended)."""
        self.stop.set()
        for t in self._threads:
            t.join(timeout=30)
        self._netem_clear()
