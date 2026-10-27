"""Regression test for the MTD telemetry and the live dashboard.

Drives a real SEMPCoordinator (no iptables: no_nat=True) against a fake SCMC
executor speaking the control protocol over a socketpair, and checks what the
coordinator records: the actions it schedules, the executors' replies, how each
action ends (applied / failed + rolled back / timed out / client lost) and the
availability cost charged for it. Then checks the dashboard's HTTP API serves the
same events, and that the live cost agrees with the post-hoc cost
monitor/compare_coordinators.py bills from the executor's client.log.

Runs on the host without Docker (guest modules imported from their source dir,
as tests/test_seeding.py does). Run with
`.venv/bin/python -m unittest tests.test_telemetry`.
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "defense_plane" / "agents"))
sys.path.insert(0, str(REPO_ROOT / "defense_plane"))   # flat rl_policy, as on semp

from mtd_coordinator import SEMPCoordinator  # noqa: E402
from mtd_dashboard import DashboardServer  # noqa: E402
from mtd_wire import recv_msg, send_msg  # noqa: E402
from rl_policy import KNOB_COST, KNOBS  # noqa: E402

from monitor.compare_coordinators import load_availability_cost  # noqa: E402

COST = dict(zip(KNOBS, KNOB_COST))


def _start(target, *args):
    threading.Thread(target=target, args=args, daemon=True).start()


def _wait_for(cond, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.02)
    return False


class FakeExecutor:
    """The SCMC side of the control channel, on one end of a socketpair."""

    def __init__(self, coord: SEMPCoordinator, scmc_id: str = "scmc1"):
        coord_end, self.sock = socket.socketpair()
        _start(coord._handle_client, coord_end, None)
        send_msg(self.sock, {"type": "HELLO", "scmc_id": scmc_id})
        self.scmc_id = scmc_id

    def recv(self) -> dict:
        self.sock.settimeout(10)
        return recv_msg(self.sock)

    def send(self, mtype: str, seq: int) -> None:
        send_msg(self.sock, {"type": mtype, "seq": seq, "scmc_id": self.scmc_id})


def _coordinator(tmp, **kw):
    kw.setdefault("pad_buckets", [])
    return SEMPCoordinator(0, ["10.1.0.2", "10.1.0.4"], [8883, 8884], 0.05, no_nat=True,
                           telemetry_path=os.path.join(tmp, "telemetry.jsonl"), seed=1, **kw)


def _outcomes(coord) -> dict:
    return {e["seq"]: e for e in coord.telemetry.events() if e["kind"] == "action_outcome"}


class BrokerHopOutcomes(unittest.TestCase):
    """A hop that is applied, one every executor FAILs, one nobody answers."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        coord = cls.coord = _coordinator(cls.tmp, hop_timeout=60)
        coord._start_telemetry()
        ex = FakeExecutor(coord)
        _start(coord._hop_loop)
        _start(coord._action_watchdog_loop)

        cls.seqs = []
        msg = ex.recv()                       # 1: applied
        cls.seqs.append(msg["seq"])
        ex.send("HOP_ACK", msg["seq"])
        ex.send("HOP_DONE", msg["seq"])
        msg = ex.recv()                       # 2: failed → rolled back
        cls.seqs.append(msg["seq"])
        ex.send("HOP_ACK", msg["seq"])
        ex.send("HOP_FAILED", msg["seq"])
        msg = ex.recv()                       # 3: no answer → watchdog timeout
        cls.seqs.append(msg["seq"])
        with coord._lock:
            coord._hop_deadline[msg["seq"]] = 0.0
        assert _wait_for(lambda: cls.seqs[2] in _outcomes(coord)), "hop 3 never timed out"

    def test_outcomes_and_cost(self):
        out = _outcomes(self.coord)
        applied, failed, timed_out = (out[s] for s in self.seqs)
        both = COST["ip"] + COST["port"]     # 10.1.0.2:8883 → 10.1.0.4:8884
        self.assertEqual((applied["status"], applied["rolled_back"]), ("applied", False))
        self.assertAlmostEqual(applied["cost"], both)
        # The executor attempted the failed hop (it logs it), so it is charged too.
        self.assertEqual((failed["status"], failed["rolled_back"]), ("failed", True))
        self.assertAlmostEqual(failed["cost"], both)
        self.assertEqual((timed_out["status"], timed_out["timed_out"]), ("timed_out", ["scmc1"]))
        self.assertEqual(timed_out["cost"], 0.0)

    def test_scheduled_and_replies(self):
        events = self.coord.telemetry.events()
        sched = {e["seq"]: e for e in events if e["kind"] == "action_scheduled"}
        first = sched[self.seqs[0]]
        self.assertEqual((first["action"], first["knobs"], first["awaited"]),
                         ("hop", ["port", "ip"], ["scmc1"]))
        self.assertEqual(first["params"]["new_port"], 8884)
        replies = [(e["seq"], e["phase"]) for e in events if e["kind"] == "reply"]
        self.assertIn((self.seqs[0], "DONE"), replies)
        self.assertIn((self.seqs[1], "FAILED"), replies)
        self.assertTrue(all(e["latency_s"] >= 0 for e in events if e["kind"] == "reply"))
        # While hop 3 was pending the hop loop kept ticking and had to skip.
        self.assertTrue(any(e["kind"] == "action_skipped" and e["reason"] == "in_progress"
                            for e in events))
        self.assertEqual(events[0]["kind"], "run_info")
        self.assertEqual([e["i"] for e in events], list(range(len(events))))

    def test_jsonl_mirrors_memory(self):
        n = len(self.coord.telemetry)
        with open(os.path.join(self.tmp, "telemetry.jsonl")) as f:
            lines = [json.loads(line) for line in f][:n]
        self.assertEqual(lines, self.coord.telemetry.events()[:n])

    def test_dashboard_api(self):
        server = DashboardServer(self.coord.telemetry, 0, host="127.0.0.1")
        server.start()
        base = f"http://127.0.0.1:{server.port}"
        with urllib.request.urlopen(f"{base}/api/events?since=0") as r:
            body = json.load(r)
        self.assertEqual(body["next"], len(body["events"]))
        self.assertEqual(body["events"][0]["kind"], "run_info")
        with urllib.request.urlopen(f"{base}/api/events?since=3") as r:
            later = json.load(r)
        self.assertEqual(later["events"][0]["i"], 3)
        with urllib.request.urlopen(f"{base}/") as r:
            self.assertIn(b"MTD Defense Monitor", r.read())
        with urllib.request.urlopen(f"{base}/telemetry.jsonl") as r:
            self.assertGreaterEqual(len(r.read().splitlines()), body["next"])
        server.httpd.shutdown()


class SoftKnobOutcomes(unittest.TestCase):
    """A publish-interval change that is applied; a padding change whose only
    executor disconnects before DONE."""

    def test_freq_applied_and_pad_lost(self):
        tmp = tempfile.mkdtemp()
        coord = _coordinator(tmp, freq_pool=[0.5, 2.0], freq_interval=0.05,
                             pad_buckets=[128, 256], pad_interval=0.05)
        ex = FakeExecutor(coord)
        _start(coord._freq_loop)
        msg = ex.recv()
        self.assertEqual(msg["type"], "SET_INTERVAL")
        ex.send("INTERVAL_ACK", msg["seq"])
        ex.send("INTERVAL_DONE", msg["seq"])
        self.assertTrue(_wait_for(lambda: msg["seq"] in _outcomes(coord)))
        freq = _outcomes(coord)[msg["seq"]]
        self.assertEqual(freq["status"], "applied")
        self.assertAlmostEqual(freq["cost"], COST["freq"])
        # The data-plane observer now judges gaps against the new interval.
        self.assertEqual(coord.telemetry.publish_interval, msg["interval"])

        _start(coord._pad_loop)
        while True:                           # skip further SET_INTERVALs
            pad = ex.recv()
            if pad["type"] == "SET_PADDING":
                break
            ex.send("INTERVAL_DONE", pad["seq"])
        ex.sock.close()
        self.assertTrue(_wait_for(lambda: pad["seq"] in _outcomes(coord)))
        lost = _outcomes(coord)[pad["seq"]]
        self.assertEqual((lost["status"], lost["cost"]), ("client_lost", 0.0))
        self.assertTrue(any(e["kind"] == "client" and e["event"] == "disconnected"
                            for e in coord.telemetry.events()))


class BroadcastToDeadClient(unittest.TestCase):
    """A send that fails must release the actions awaiting that executor, or the
    knob's loop would skip ("still in progress") for the rest of the run."""

    def test_pending_released(self):
        coord = _coordinator(tempfile.mkdtemp(), pad_buckets=[128, 256], pad_interval=0.05)
        coord_end, scmc_end = socket.socketpair()
        coord._register("scmc1", coord_end)    # no reader thread: only the send sees it
        scmc_end.close()
        _start(coord._pad_loop)
        self.assertTrue(_wait_for(lambda: _outcomes(coord)))
        (lost,) = _outcomes(coord).values()
        self.assertEqual(lost["status"], "client_lost")
        with coord._lock:
            self.assertEqual((coord._pending_pad_done, coord._clients), ({}, {}))
        events = coord.telemetry.events()
        self.assertTrue(any(e["kind"] == "client" and e["event"] == "broadcast_failed"
                            for e in events))
        self.assertFalse(any(e["kind"] == "action_skipped" and e["reason"] == "in_progress"
                             for e in events))


class SoftActionWatchdog(unittest.TestCase):
    """A padding / source-hop / interval action whose DONE never arrives (e.g. lost
    to a blackhole) times out, and its loop resumes instead of skipping forever."""

    def test_interval_times_out_and_loop_resumes(self):
        coord = _coordinator(tempfile.mkdtemp(), freq_pool=[0.01, 0.02],
                             freq_interval=0.05, hop_timeout=0.1)
        ex = FakeExecutor(coord)
        _start(coord._freq_loop)
        _start(coord._action_watchdog_loop)
        first = ex.recv()
        ex.send("INTERVAL_ACK", first["seq"])          # ACK, but never DONE
        self.assertTrue(_wait_for(lambda: first["seq"] in _outcomes(coord)))
        out = _outcomes(coord)[first["seq"]]
        self.assertEqual((out["status"], out["timed_out"], out["cost"]),
                         ("timed_out", ["scmc1"], 0.0))
        nxt = ex.recv()
        self.assertEqual(nxt["type"], "SET_INTERVAL")
        self.assertGreater(nxt["seq"], first["seq"])
        with coord._lock:
            self.assertNotIn(first["seq"], coord._soft_deadline)


class LateConfirmation(unittest.TestCase):
    """A DONE that arrives after the action timed out is still charged: the
    executor fired it and client.log (hence the post-hoc cost) counts it."""

    def test_late_done_is_charged(self):
        from mtd_telemetry import Telemetry
        tel = Telemetry(knob_cost=COST)
        tel.scheduled(7, "src", ["src"], 10, ["scmc1"], new_src_ip="10.0.0.8")
        tel.finished(7, timed_out=["scmc1"])
        tel.reply(7, "scmc1", "DONE")
        out = [e for e in tel.events() if e["kind"] == "action_outcome"][0]
        late = [e for e in tel.events() if e["kind"] == "action_late"]
        self.assertEqual((out["status"], out["cost"]), ("timed_out", 0.0))
        self.assertEqual(len(late), 1)
        self.assertAlmostEqual(late[0]["cost"], COST["src"])
        tel.reply(7, "scmc1", "DONE")                    # a duplicate is not charged twice
        self.assertEqual(len([e for e in tel.events() if e["kind"] == "action_late"]), 1)


class LateHopDone(unittest.TestCase):
    """A HOP_DONE that arrives after its hop was rolled back (stuck behind a
    blackhole): the executor did migrate, so the coordinator must follow it —
    the bug found in the first detector lab run, where a later rollback took the
    coordinator (and the NAT) back to an endpoint the executor had left."""

    def setUp(self):
        import mtd_rl_coordinator
        original = mtd_rl_coordinator.NumpyMLPPolicy.load
        mtd_rl_coordinator.NumpyMLPPolicy.load = staticmethod(lambda _path: None)
        self.addCleanup(setattr, mtd_rl_coordinator.NumpyMLPPolicy, "load", original)
        self.coord = mtd_rl_coordinator.RLSEMPCoordinator(
            0, ["10.1.0.2", "10.1.0.4", "10.1.0.5"], [8883, 8884, 8885], 30.0,
            no_nat=True, pad_buckets=[], policy_path="unused", hop_timeout=60)
        self.ex = FakeExecutor(self.coord)
        self.assertTrue(_wait_for(lambda: self.coord._clients))

    def hop(self, port=True, ip=True) -> int:
        self.coord._emit_broker_hop(port, ip)
        return self.ex.recv()["seq"]

    def endpoint(self):
        with self.coord._lock:
            return self.coord.current_ip, self.coord.current_port

    def test_late_done_moves_coordinator(self):
        s1 = self.hop()                                    # → 10.1.0.4:8884
        self.coord._expire_actions(float("inf"))           # timed out → rolled back
        self.assertEqual(self.endpoint(), ("10.1.0.2", 8883))
        self.ex.send("HOP_DONE", s1)
        self.assertTrue(_wait_for(lambda: self.endpoint() == ("10.1.0.4", 8884)))
        kinds = [e["kind"] for e in self.coord.telemetry.events()]
        self.assertIn("action_late", kinds)

    def test_rollback_returns_to_confirmed_endpoint(self):
        s1 = self.hop()                                    # → 10.1.0.4:8884, rolled back
        self.coord._expire_actions(float("inf"))
        s2 = self.hop()                                    # → 10.1.0.4:8884 again
        self.ex.send("HOP_DONE", s1)                       # late: executor IS there
        self.assertTrue(_wait_for(lambda: self.coord._confirmed_seq == s1))
        self.coord._expire_actions(float("inf"))           # s2 times out
        self.assertEqual(self.endpoint(), ("10.1.0.4", 8884))
        self.assertGreater(s2, s1)

    def test_hop_is_priced_from_the_confirmed_endpoint(self):
        """The full campaign's fixed-cnn-s2 / rl-oracle-s2: s1's DONE arrives late, while
        s2 — scheduled from the rolled-back endpoint — targets where the executor
        already is. s2 must cost nothing, as client.log (no field changes) says."""
        s1 = self.hop()                                    # 10.1.0.2:8883 → 10.1.0.4:8884
        self.coord._expire_actions(float("inf"))           # rolled back
        s2 = self.hop()                                    # scheduled 2:8883 → 4:8884 (0.45)
        self.ex.send("HOP_DONE", s1)                       # late: executor moved with s1
        self.assertTrue(_wait_for(lambda: self.coord._confirmed_seq == s1))
        self.ex.send("HOP_DONE", s2)
        self.assertTrue(_wait_for(lambda: s2 in _outcomes(self.coord)))
        late = [e for e in self.coord.telemetry.events() if e["kind"] == "action_late"]
        self.assertEqual([(e["seq"], e["cost"]) for e in late],
                         [(s1, round(COST["ip"] + COST["port"], 4))])
        self.assertEqual(_outcomes(self.coord)[s2]["cost"], 0.0)

    def test_stale_late_done_is_ignored(self):
        s1 = self.hop()                                    # → 10.1.0.4:8884, rolled back
        self.coord._expire_actions(float("inf"))
        s2 = self.hop(ip=False)                            # → 10.1.0.2:8884, confirmed
        self.ex.send("HOP_DONE", s2)
        self.assertTrue(_wait_for(lambda: self.coord._confirmed_seq == s2))
        self.ex.send("HOP_DONE", s1)                       # older than s2: stale
        self.assertTrue(_wait_for(lambda: any(
            e["kind"] == "reply" and e["seq"] == s1 for e in self.coord.telemetry.events())))
        self.assertEqual(self.endpoint(), ("10.1.0.2", 8884))


class ReorderedHandover(unittest.TestCase):
    """The executor's make-before-break control reconnect sends the new HELLO before
    closing the old socket, but under netem delay/jitter the old socket's FIN can
    arrive first. That close must not release the executor's pending actions (it
    rolled back valid hops and closed their NAT port in the detector campaign) —
    unless it does not come back within the grace."""

    def setUp(self):
        self.coord = _coordinator(tempfile.mkdtemp(), pad_buckets=[128, 256], pad_interval=0.05)
        self.coord.RECONNECT_GRACE_S = 0.5
        self.old = FakeExecutor(self.coord)
        _start(self.coord._pad_loop)
        self.pad = self.old.recv()                        # SET_PADDING, now pending

    def events(self, kind):
        return [e for e in self.coord.telemetry.events() if e["kind"] == kind]

    def test_fin_before_hello_is_a_handover(self):
        self.old.sock.close()                             # FIN first...
        self.assertTrue(_wait_for(lambda: "scmc1" in self.coord._departing))
        new = FakeExecutor(self.coord)                    # ...then the new HELLO
        self.assertTrue(_wait_for(lambda: "scmc1" in self.coord._clients))
        time.sleep(0.8)                                   # past the grace
        with self.coord._lock:
            self.assertIn("scmc1", self.coord._pending_pad_done.get(self.pad["seq"], set()))
        new.send("PAD_DONE", self.pad["seq"])
        self.assertTrue(_wait_for(lambda: self.pad["seq"] in _outcomes(self.coord)))
        self.assertEqual(_outcomes(self.coord)[self.pad["seq"]]["status"], "applied")
        self.assertEqual([e["event"] for e in self.events("client")], ["connected", "handover"])

    def test_no_return_releases_after_grace(self):
        self.old.sock.close()
        self.assertTrue(_wait_for(lambda: self.pad["seq"] in _outcomes(self.coord)))
        self.assertEqual(_outcomes(self.coord)[self.pad["seq"]]["status"], "client_lost")
        self.assertEqual([e["event"] for e in self.events("client")], ["connected", "disconnected"])


class CostMatchesPostHoc(unittest.TestCase):
    """The cost charged live equals what compare_coordinators bills from the
    executor's client.log for the same actuations."""

    def test_same_total(self):
        tmp = tempfile.mkdtemp()
        coord = _coordinator(tmp, hop_timeout=60)
        ex = FakeExecutor(coord)
        _start(coord._hop_loop)
        log_lines = []
        for i in range(4):
            msg = ex.recv()
            sched = next(e for e in reversed(coord.telemetry.events())
                         if e["kind"] == "action_scheduled" and e["seq"] == msg["seq"])
            p = sched["params"]
            # The line mtd_executor.SCMCExecutor._do_hop logs for this hop.
            log_lines.append(f"2026-10-26T10:00:{i:02d}  [scmc1] hop seq={msg['seq']}  "
                             f"{p['old_ip']}:{p['old_port']} → {p['new_ip']}:{p['new_port']}")
            ex.send("HOP_DONE", msg["seq"])
        self.assertTrue(_wait_for(lambda: len(_outcomes(coord)) == 4))

        attack = Path(tmp, "exp", "attack", "model-mtd")
        attack.mkdir(parents=True)
        for name in ("scmc_capture.pcap", "router_capture.pcap"):
            (attack / name).touch()
        (attack / "client.log").write_text("\n".join(log_lines) + "\n")
        post_hoc = load_availability_cost(str(Path(tmp, "exp")))["total_cost"]
        live = sum(o["cost"] for o in _outcomes(coord).values())
        self.assertAlmostEqual(live, post_hoc)


if __name__ == "__main__":
    unittest.main()
