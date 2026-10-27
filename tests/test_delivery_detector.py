"""Regression tests for the delivery-attack detector pipeline.

  • Featurizer: what the SEMP sees in a blackhole (silence + unanswered actions),
    an executor restart (explicit disconnect), a hop (reconnect in flight) and a
    slow network (late ACKs) maps to distinguishable features.
  • NumpyDetector reproduces sklearn's MLP exactly (it is what runs on semp).
  • LiveDetector raises / clears alerts with its hysteresis.
  • monitor.delivery_dataset labels a blackhole by its impact on the real path,
    including the recovery tail after the unblock, from synthetic captures.
  • train_delivery_detector runs end to end on a synthetic dataset.

Host-only, no Docker. Run with `.venv/bin/python -m unittest tests.test_delivery_detector`.
"""

import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path

import dpkt
import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "defense_plane" / "agents"))

from defense_plane.delivery_detector import (  # noqa: E402
    FEATURE_SETS, FEATURES, Featurizer, History, LiveDetector, NumpyDetector, replay,
    rule_decision)
from monitor import delivery_dataset as ds  # noqa: E402
from mtd_telemetry import Telemetry  # noqa: E402

F = {name: i for i, name in enumerate(FEATURES)}


def data(t, n=1, silence=0.1, sid="scmc1", expected=1.0):
    return {"t": t, "kind": "data", "window_s": 1.0, "n": {sid: n},
            "silence_s": {sid: silence}, "expected_s": expected}


def sched(t, seq, action="pad"):
    return {"t": t, "kind": "action_scheduled", "seq": seq, "action": action,
            "awaited": ["scmc1"]}


def reply(t, seq, phase="ACK", latency=0.004):
    return {"t": t, "kind": "reply", "seq": seq, "scmc_id": "scmc1", "phase": phase,
            "latency_s": latency}


def normal_until(t_end):
    evs = [{"t": 0.0, "kind": "run_info", "initial": {"interval": 1.0}},
           {"t": 0.5, "kind": "client", "scmc_id": "scmc1", "event": "connected"}]
    for k in range(1, t_end):
        evs.append(data(float(k)))
        if k % 3 == 0:
            evs += [sched(k + 0.1, k), reply(k + 0.105, k)]
    return evs


def features_at(events, t):
    fz = Featurizer()
    for ev in sorted(events, key=lambda e: e["t"]):
        if ev["t"] <= t:
            fz.apply(ev)
    return fz.features("scmc1", t)


class FeaturizerScenarios(unittest.TestCase):
    def test_normal(self):
        x = features_at(normal_until(30), 29.5)
        self.assertLess(x[F["silence"]], 1.0)
        self.assertEqual(x[F["unacked"]], 0)
        self.assertEqual(x[F["ctrl_connected"]], 1.0)
        self.assertFalse(rule_decision(x))

    def test_blackhole_silence_and_unanswered_actions(self):
        evs = normal_until(30)
        evs.append(sched(30.1, 99))             # sent just before: never answered, still open
        for k in range(30, 45):                 # data stops, actions go unanswered
            evs.append(data(float(k), n=0, silence=k - 29.5))
            if k % 3 == 0:
                evs.append(sched(k + 0.1, 100 + k))
        x = features_at(evs, 44.5)
        self.assertGreater(x[F["silence"]], 10)
        self.assertGreater(x[F["unacked"]], 1)
        self.assertAlmostEqual(x[F["pending_age"]], 14.4, places=3)
        self.assertGreater(x[F["pending_n"]], 1)
        self.assertEqual(x[F["ctrl_connected"]], 1.0)    # no FIN: the blackhole is silent
        self.assertGreater(x[F["silence_vs_normal"]], 10)
        self.assertTrue(rule_decision(x))

    def test_pending_age_stops_at_the_outcome(self):
        """The watchdog closes an unanswered action: it no longer counts."""
        evs = normal_until(30) + [sched(30.1, 99),
                                  {"t": 40.0, "kind": "action_outcome", "seq": 99}]
        self.assertGreater(features_at(evs, 39.0)[F["pending_age"]], 8)
        self.assertEqual(features_at(evs, 41.0)[F["pending_age"]], 0.0)

    def test_control_alive_while_data_is_silent(self):
        evs = normal_until(30) + [data(float(k), n=0, silence=k - 29.5) for k in range(30, 40)]
        evs += [sched(38.5, 400), reply(38.6, 400)]        # control still answers
        x = features_at(evs, 39.5)
        self.assertGreater(x[F["ctrl_alive_silent"]], 5)
        self.assertLess(features_at(normal_until(40), 39.5)[F["ctrl_alive_silent"]], 1.0)

    def test_restart_is_an_explicit_disconnect(self):
        evs = normal_until(30) + [
            {"t": 30.2, "kind": "client", "scmc_id": "scmc1", "event": "disconnected"}]
        evs += [data(float(k), n=0, silence=k - 29.5) for k in range(31, 35)]
        x = features_at(evs, 34.5)
        self.assertEqual(x[F["ctrl_connected"]], 0.0)
        self.assertLess(x[F["since_disconnect"]], np.log1p(10))

    def test_confirmed_hop_explains_a_gap(self):
        evs = normal_until(30) + [sched(30.1, 200, "hop"), reply(33.0, 200, "DONE")]
        evs += [data(float(k), n=0, silence=k - 29.5) for k in range(31, 35)]
        x = features_at(evs, 34.5)
        self.assertEqual(x[F["reconnecting"]], 1.0)
        self.assertLess(x[F["since_reconnect"]], np.log1p(2))
        self.assertEqual(x[F["unconfirmed_age"]], 0.0)
        self.assertFalse(rule_decision(x))

    def test_unconfirmed_hop_age(self):
        evs = normal_until(30) + [sched(30.1, 200, "hop"), reply(30.11, 200, "ACK")]
        x = features_at(evs, 36.1)
        self.assertAlmostEqual(x[F["unconfirmed_age"]], 6.0, places=3)
        self.assertEqual(x[F["pending_age"]], 0.0)         # it was ACKed: not silent

    def test_normal_gap_size_scales_silence(self):
        """Gaps of ~3 s are what this MTD produces: a 3 s silence is then normal."""
        evs = [{"t": 0.0, "kind": "run_info", "initial": {"interval": 1.0}}]
        last = 0.0
        for k in range(1, 40):
            if k % 3 == 0:
                last = float(k)
            evs.append(data(float(k), n=1 if k % 3 == 0 else 0, silence=k - last))
        x = features_at(evs, 41.0)
        self.assertAlmostEqual(x[F["silence"]], 2.0, places=3)
        self.assertLess(x[F["silence_vs_normal"]], 1.0)

    def test_late_acks(self):
        evs = normal_until(30) + [sched(30.1, 300), reply(30.4, 300, latency=0.3)]
        x = features_at(evs, 31.0)
        self.assertGreater(x[F["ack_ms"]], np.log1p(250))

    def test_replay_ticks_from_first_data(self):
        rows = list(replay(normal_until(10)))
        self.assertEqual(rows[0][0], 1.0)
        self.assertEqual({sid for _, sid, _ in rows}, {"scmc1"})
        self.assertEqual(len(rows), 9)
        self.assertEqual(len(rows[0][2]), len(FEATURES))

    def test_history_lags(self):
        h = History()
        base = lambda v: np.full(len(FEATURES) - 6, v, dtype=np.float32)
        out = [h.full("scmc1", base(float(k))) for k in range(6)]
        self.assertEqual(out[5][F["silence_lag2"]], 3.0)
        self.assertEqual(out[5][F["silence_lag4"]], 1.0)
        self.assertEqual(out[1][F["silence_lag4"]], 0.0)    # oldest available early on


class LiveMatchesOffline(unittest.TestCase):
    """LiveDetector on the SEMP and replay() on a downloaded telemetry.jsonl must
    build the same vectors — the model is trained on one and runs on the other."""

    def test_same_vectors(self):
        evs = normal_until(25)
        evs += [sched(25.1, 500, "hop"), reply(25.12, 500)]
        evs += [data(float(k), n=0, silence=k - 24.5) for k in range(25, 35)]
        evs = [{**e, "i": i} for i, e in enumerate(sorted(evs, key=lambda e: e["t"]))]
        offline = {round(t, 3): x for t, _sid, x in replay(evs)}

        path = os.path.join(tempfile.mkdtemp(), "d.npz")
        _toy_detector().save(path)

        class Recorder:
            def __init__(self):
                self.out = []

            def emit(self, kind, **f):
                self.out.append({"kind": kind, **f})

        rec = Recorder()
        det = LiveDetector(rec, path)
        i, now = 0, 1.0
        while now <= evs[-1]["t"]:
            while i < len(evs) and evs[i]["t"] <= now:
                det._on_event(evs[i])
                i += 1
            det.step(now)
            now += 1.0
        live = [np.array(e["x"]) for e in rec.out if e["kind"] == "detection"]
        self.assertEqual(len(live), len(offline))
        for x_live, x_off in zip(live, offline.values()):
            np.testing.assert_allclose(x_live, x_off, atol=1e-3)


def _toy_detector(threshold=0.5):
    """p = sigmoid(silence − 3.5): above 0.5 once silent for more than 3.5 intervals."""
    return NumpyDetector(np.zeros(1), np.ones(1), [np.ones((1, 1))], [np.array([-3.5])],
                         threshold, ["silence"])


class NumpyMatchesSklearn(unittest.TestCase):
    def test_export_roundtrip(self):
        from defense_plane import train_delivery_detector as tr
        rng = np.random.default_rng(0)
        df = pd.DataFrame(rng.normal(size=(400, len(FEATURES))), columns=FEATURES)
        df["label"] = (df["silence"] + 0.3 * df["pending_age"] > 0.5).astype(int)
        model = tr.fit(df, tr.Config("v2h", smoothing=(2, 3)), seed=0)
        path = os.path.join(tempfile.mkdtemp(), "d.npz")
        tr.export(model, 0.42, path, df)          # asserts |Δp| < 1e-6 itself
        det = NumpyDetector.load(path)
        self.assertAlmostEqual(det.threshold, 0.42)
        self.assertEqual(det.features, FEATURE_SETS["v2h"])
        self.assertEqual(det.smoothing, (2, 3))
        x_full = df[FEATURES].to_numpy(np.float64)[:5]
        np.testing.assert_allclose(det.proba(det.select(x_full)), tr.proba(model, df.iloc[:5]),
                                   atol=1e-6)

    def test_tree_export_roundtrip(self):
        """Gradient-boosted trees replayed in numpy give sklearn's probabilities."""
        from defense_plane import train_delivery_detector as tr
        from defense_plane.delivery_detector import NumpyTreeDetector, load_detector
        rng = np.random.default_rng(1)
        df = pd.DataFrame(rng.normal(size=(600, len(FEATURES))), columns=FEATURES)
        df["label"] = ((df["silence"] > 0.3) & (df["ctrl_connected"] > -0.5)).astype(int)
        model = tr.fit(df, tr.Config("v2h", kind="hgb"), seed=0)
        path = os.path.join(tempfile.mkdtemp(), "trees.npz")
        tr.export(model, 0.37, path, df)                   # asserts |Δp| < 1e-6 itself
        det = load_detector(path)
        self.assertIsInstance(det, NumpyTreeDetector)
        self.assertEqual(det.features, FEATURE_SETS["v2h"])
        x_full = df[FEATURES].to_numpy(np.float64)[:50]
        np.testing.assert_allclose(det.proba(det.select(x_full)),
                                   tr.proba(model, df.iloc[:50]), atol=1e-9)
        self.assertEqual(len(det.top_features(det.select(x_full[0])[0])), 3)

    def test_old_schema_is_refused(self):
        path = os.path.join(tempfile.mkdtemp(), "old.npz")
        np.savez(path, mean=np.zeros(1), std=np.ones(1), threshold=0.5, n_layers=1,
                 W0=np.ones((1, 1)), b0=np.zeros(1), features=np.array(["silence"]))
        with self.assertRaises(ValueError):
            NumpyDetector.load(path)


class LiveDetectorWithTrees(unittest.TestCase):
    def test_live_detector_runs_an_exported_tree_model(self):
        from defense_plane import train_delivery_detector as tr
        rng = np.random.default_rng(2)
        df = pd.DataFrame(rng.normal(size=(400, len(FEATURES))), columns=FEATURES)
        df["label"] = (df["silence"] > 0).astype(int)
        path = os.path.join(tempfile.mkdtemp(), "trees.npz")
        tr.export(tr.fit(df, tr.Config("v2", kind="hgb"), seed=0), 0.5, path, df)
        tel = Telemetry()
        det = LiveDetector(tel, path)
        det.start()
        tel.emit("client", scmc_id="scmc1", event="connected")
        tel.emit("data", window_s=1.0, n={"scmc1": 1}, silence_s={"scmc1": 0.0}, expected_s=1.0)
        det.step(tel.events()[-1]["t"] + 1)
        d = [e for e in tel.events() if e["kind"] == "detection"]
        self.assertEqual(len(d), 1)
        self.assertTrue(0.0 <= d[0]["p"] <= 1.0)


class LiveDetectorHysteresis(unittest.TestCase):
    def test_raise_and_clear(self):
        path = os.path.join(tempfile.mkdtemp(), "d.npz")
        _toy_detector().save(path)
        tel = Telemetry()
        det = LiveDetector(tel, path)
        det.start()
        tel.emit("client", scmc_id="scmc1", event="connected")
        t0 = tel.events()[-1]["t"]
        tel.emit("data", window_s=1.0, n={"scmc1": 1}, silence_s={"scmc1": 0.0}, expected_s=1.0)
        states = []
        for k in range(1, 9):                     # silent for 8 s
            det.step(t0 + k)
            states.append(tel.events()[-1]["alert"] if tel.events()[-1]["kind"] == "detection"
                          else tel.events()[-2]["alert"])
        tel.emit("data", window_s=1.0, n={"scmc1": 1}, silence_s={"scmc1": 0.0}, expected_s=1.0)
        t1 = tel.events()[-1]["t"]
        for k in range(1, 5):
            det.step(t1 + 0.1 * k)
        alerts = [e for e in tel.events() if e["kind"] == "detector_alert"]
        self.assertEqual([a["state"] for a in alerts], ["raised", "cleared"])
        # Silent 4 s is the first hit (p > 0.5); the alert needs a second one (5 s).
        self.assertEqual(states.index(True), 4)


# ── labels from synthetic captures ───────────────────────────────────────────

def _write_pcap(path, packets):
    """packets: (ts, src, dst, sport, dport, seq, payload_len)."""
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, src, dst, sport, dport, seq, n in packets:
            tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, flags=dpkt.tcp.TH_ACK,
                               data=b"x" * n)
            ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                            p=dpkt.ip.IP_PROTO_TCP, data=tcp)
            ip.len = len(ip)
            eth = dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x00" * 6,
                                         type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
            w.writepkt(bytes(eth), ts=ts)


class ImpactLabels(unittest.TestCase):
    def test_intervals(self):
        path_t = [float(t) for t in range(0, 60)]
        path = [("10.0.0.2", "10.1.0.2")] * 20 + [("10.0.0.4", "10.1.0.2")] * 10 + \
               [("10.0.0.2", "10.1.0.2")] * 30
        deliveries = [5.0, 9.0, 21.0, 52.0]
        # src blocked 10→40: path leaves it at 20 (release, delivery 21), comes back at
        # 30 while still blocked, unblock at 40, data again only at 52 (recovery tail).
        blocks = [("10.0.0.2", 10.0, 40.0, "oracle-src"),
                  ("10.1.0.9", 12.0, 30.0, "cnn")]           # not on the path
        out = ds.impact_intervals(blocks, path_t, path, deliveries, 60.0)
        self.assertEqual([(a, b) for a, b, *_ in out], [(10.0, 21.0), (30.0, 52.0)])

    def test_build_run_end_to_end(self):
        run = Path(tempfile.mkdtemp(), "fixed-oracle-s1")
        run.mkdir()
        t0 = 1000.0
        tel = [{"i": 0, "t": t0, "kind": "run_info", "initial": {"interval": 1.0}},
               {"i": 1, "t": t0 + 0.5, "kind": "client", "scmc_id": "scmc1", "event": "connected"}]
        for k in range(1, 61):
            silent = 20 <= k < 45
            tel.append({"i": len(tel), **data(t0 + k, n=0 if silent else 1,
                                                silence=(k - 19.5) if silent else 0.1)})
        with open(run / "telemetry.jsonl", "w") as f:
            f.write("\n".join(json.dumps(e) for e in tel) + "\n")
        gt = [{"t": t0, "kind": "run_meta", "rl_policy": None, "oracle_block": "src", "seed": 1,
               "scmc_ip_pool": "10.0.0.2,10.0.0.4", "port_pool": "8883,8884"},
              {"t": t0 + 19.0, "kind": "post_attack_start"},
              {"t": t0 + 20.0, "kind": "block", "ip": "10.0.0.2", "target": "oracle-src"},
              {"t": t0 + 40.0, "kind": "unblock", "ip": "10.0.0.2"},
              {"t": t0 + 60.5, "kind": "post_attack_end"}]
        with open(run / "ground_truth.jsonl", "w") as f:
            f.write("\n".join(json.dumps(e) for e in gt) + "\n")
        sent = [(t0 + k + 0.2, "10.0.0.2", "10.1.0.2", 40000, 8883, 1 + 100 * k, 100)
                for k in range(1, 61)]
        _write_pcap(run / "scmc_capture.pcap", sent)
        # Router (link B): nothing crosses 20–40; after the unblock the first packets are
        # retransmissions of already-delivered data, new data only from 45 on.
        crossed = [p for p in sent if not 20 <= p[0] - t0 < 45]
        retrans = [(t0 + 41.2, "10.0.0.2", "10.1.0.2", 40000, 8883, 1 + 100 * 19, 100)]
        _write_pcap(run / "router_capture.pcap", sorted(crossed + retrans))

        df = ds.build_run(str(run))
        lab = dict(zip((df["t"] - t0).round(1), df["label"]))
        self.assertEqual(lab[19.0], 0)
        self.assertTrue(all(lab[float(k)] == 1 for k in range(20, 45)))   # incl. recovery tail
        self.assertEqual(lab[46.0], 0)
        self.assertEqual(set(df["attack"]), {"oracle"})
        self.assertEqual(set(df["variant"]), {"fixed"})


class RestartResumeState(unittest.TestCase):
    """The restarted executor resumes where its log says it is, even mid-reconnect
    (no established MQTT socket to read) — a regression from the first lab run."""

    def test_log_state(self):
        from network_scenario.detection_scenario import executor_log_state
        log = "\n".join([
            "2026-10-26T16:27:32  [scmc1] MQTT → 10.1.0.2:8883 (ok)",
            "2026-10-26T16:27:45  [scmc1] src hop seq=2  10.0.0.2 → 10.0.0.4",
            "2026-10-26T16:27:47  [scmc1] hop seq=3  10.1.0.2:8883 → 10.1.0.4:8884",
            "2026-10-26T16:27:52  [scmc1] publish interval → 0.8s",
            "2026-10-26T16:27:56  [scmc1] padding policy → [128, 640]",
            "2026-10-26T16:28:01  [scmc1] hop seq=9  10.1.0.4:8884 → 10.1.0.5:8885",
            "2026-10-26T16:28:04  [scmc1] hop seq=9 failed — staying on 10.1.0.4:8884",
            "2026-10-26T16:28:17  [scmc1] src hop seq=19  10.0.0.4 → 10.0.0.8",
            "2026-10-26T16:28:17  [scmc1] MQTT connect failed ([Errno 111] Connection refused), retry in 3s",
        ])
        self.assertEqual(executor_log_state(log), {
            "broker_ip": "10.1.0.4", "broker_port": 8884, "src_ip": "10.0.0.8",
            "interval": 0.8, "pad_buckets": [128, 640]})


class SourceHopIntoBlackhole(unittest.TestCase):
    """A source hop onto an already blocked address: the executor only retries its
    connect (SYNs, no data). The outage is the attack's — found in the campaign's
    fixed-cnn-s2 run, where data-only path tracking labelled it benign."""

    def test_syn_attempts_count_as_path(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "scmc.pcap")
        with open(p, "wb") as f:
            w = dpkt.pcap.Writer(f)
            def pkt(ts, src, flags, n):
                tcp = dpkt.tcp.TCP(sport=40000, dport=8883, seq=1, flags=flags, data=b"x" * n)
                ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton("10.1.0.2"),
                                p=dpkt.ip.IP_PROTO_TCP, data=tcp)
                ip.len = len(ip)
                w.writepkt(bytes(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip)), ts=ts)
            pkt(1.0, "10.0.0.8", dpkt.tcp.TH_ACK, 100)          # data from the old source
            pkt(2.0, "10.0.0.2", dpkt.tcp.TH_SYN, 0)            # hop onto the blocked one
            pkt(3.0, "10.0.0.2", dpkt.tcp.TH_SYN, 0)
            pkt(4.0, "10.0.0.8", dpkt.tcp.TH_ACK, 0)            # pure ACK: not path evidence
        path_t, path = ds.scmc_path(p, {"10.0.0.2", "10.0.0.8"}, {8883})
        self.assertEqual([s for s, _ in path], ["10.0.0.8", "10.0.0.2", "10.0.0.2"])
        out = ds.impact_intervals([("10.0.0.2", 0.5, 10.0, "cnn")], path_t, path, [12.0], 20.0)
        self.assertEqual([(a, b) for a, b, *_ in out], [(2.0, 12.0)])

    def test_retransmissions_of_an_abandoned_flow_are_ignored(self):
        """After a hop away from a blocked broker, the old connection keeps
        retransmitting unacknowledged data to it — that is not the path in use
        (found in the full campaign's fixed-oracle-s7: 1-window phantom episodes)."""
        d = tempfile.mkdtemp()
        p = os.path.join(d, "scmc.pcap")
        rows = [(1.0, 40000, "10.1.0.7", 1, 100),          # old flow, new data
                (2.0, 40001, "10.1.0.8", 1, 100),          # hop: new flow
                (2.5, 40000, "10.1.0.7", 1, 100),          # old flow retransmission
                (3.0, 40001, "10.1.0.8", 101, 100)]
        with open(p, "wb") as f:
            w = dpkt.pcap.Writer(f)
            for ts, sport, dst, seq, n in rows:
                tcp = dpkt.tcp.TCP(sport=sport, dport=8883, seq=seq, flags=dpkt.tcp.TH_ACK,
                                   data=b"x" * n)
                ip = dpkt.ip.IP(src=socket.inet_aton("10.0.0.8"), dst=socket.inet_aton(dst),
                                p=dpkt.ip.IP_PROTO_TCP, data=tcp)
                ip.len = len(ip)
                w.writepkt(bytes(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip)), ts=ts)
        path_t, path = ds.scmc_path(p, {"10.0.0.8"}, {8883})
        self.assertEqual(path_t, [1.0, 2.0, 3.0])
        # Blocked after the hop: the retransmission at 2.5 must not make it an outage.
        out = ds.impact_intervals([("10.1.0.7", 2.2, 10.0, "oracle-broker")], path_t, path,
                                  [2.0, 3.0], 20.0)
        self.assertEqual(out, [])

    def test_syn_with_data_still_flowing_is_ignored(self):
        """A make-before-break hop attempt: SYNs to a (blocked) new endpoint while the
        old connection keeps carrying data — no outage, not path evidence."""
        d = tempfile.mkdtemp()
        p = os.path.join(d, "scmc.pcap")
        rows = [(1.0, "10.0.0.8", "10.1.0.2", dpkt.tcp.TH_ACK, 100, 1),
                (1.5, "10.0.0.8", "10.1.0.9", dpkt.tcp.TH_SYN, 0, 1),     # hop attempt
                (2.0, "10.0.0.8", "10.1.0.2", dpkt.tcp.TH_ACK, 100, 101),  # data continues
                (3.0, "10.0.0.8", "10.1.0.2", dpkt.tcp.TH_ACK, 100, 201)]
        with open(p, "wb") as f:
            w = dpkt.pcap.Writer(f)
            for ts, src, dst, flags, n, seq in rows:
                tcp = dpkt.tcp.TCP(sport=40000, dport=8883, seq=seq, flags=flags, data=b"x" * n)
                ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                                p=dpkt.ip.IP_PROTO_TCP, data=tcp)
                ip.len = len(ip)
                w.writepkt(bytes(dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip)), ts=ts)
        _t, path = ds.scmc_path(p, {"10.0.0.8"}, {8883})
        self.assertNotIn(("10.0.0.8", "10.1.0.9"), path)


def _synthetic_windows(n_runs=6, seed=1):
    rng = np.random.default_rng(seed)
    frames = []
    for r in range(n_runs):
        n = 120
        df = pd.DataFrame(rng.normal(size=(n, len(FEATURES))), columns=FEATURES)
        df["label"] = 0
        df.loc[40:70, "label"] = 1
        df.loc[df["label"] == 1, "silence"] += 6
        df["run"], df["scmc_id"], df["t"] = f"run{r}", "scmc1", np.arange(n, dtype=float)
        df["variant"], df["attack"], df["fault"] = ("rl" if r % 2 else "fixed"), "oracle", ""
        df["seed"] = r + 1
        df["rule"] = (df["silence"] > 3).astype(int)
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


class TrainingSmoke(unittest.TestCase):
    def test_cross_validated_report(self):
        from defense_plane import train_delivery_detector as tr
        data = _synthetic_windows()
        cfg = tr.Config("v2h", smoothing=(2, 3))
        scored, ths = tr.cross_validate(data, cfg, folds=3, seed=0)
        self.assertEqual(len(scored), len(data))
        self.assertEqual(len(ths), 3)
        kpi = tr.evaluate(scored, seed=0)
        allm = kpi[(kpi.scope == "all") & (kpi.model == "mlp")].iloc[0]
        self.assertGreater(allm["f1"], 0.9)
        self.assertEqual(allm["episodes"], 6)
        sec = kpi[kpi.scope.str.startswith("secondary") & (kpi.model == "mlp")].iloc[0]
        self.assertEqual(sec["positives"], allm["positives"] - 6 * 2)   # 2 s dropped per episode
        out = tempfile.mkdtemp()
        tr.write_report(kpi, tr.run_ci(scored, "pred", 0), os.path.join(out, "kpi.md"),
                        "synthetic", cfg, float(np.median(ths)))
        text = open(os.path.join(out, "kpi.md")).read()
        self.assertIn("| F1 | > 85%", text)
        self.assertIn("Secondary (declared)", text)

    def test_smoothing_two_of_three(self):
        from defense_plane import train_delivery_detector as tr
        df = pd.DataFrame({"run": "r", "scmc_id": "s", "t": np.arange(6.0)})
        p = np.array([0.9, 0.1, 0.9, 0.9, 0.1, 0.1])
        out = tr.decide(df, p, 0.5, tr.Config(smoothing=(2, 3)))
        self.assertEqual(out.tolist(), [0, 0, 1, 1, 1, 0])

    def test_seed_split(self):
        from defense_plane import train_delivery_detector as tr
        self.assertEqual(tr.seeds_arg("1-3"), {1, 2, 3})
        self.assertEqual(tr.seeds_arg("4-6,9"), {4, 5, 6, 9})


class BrokerLogEndsImpact(unittest.TestCase):
    """The impact ends when the broker receives nanogrid data again (mosquitto.log),
    not at the first packet crossing the router (a reconnection's TLS handshake)."""

    def test_broker_publishes(self):
        path = os.path.join(tempfile.mkdtemp(), "mosquitto.log")
        with open(path, "w") as f:
            f.write("1000: New client connected from 10.0.0.2:5000 as scmc1 (p5, c1, k60).\n"
                    "1001: Received PUBLISH from scmc1 (d0, q0, r0, m0, 'grid/scmc1/power_kw', ... (58 bytes))\n"
                    "1003: Received PUBLISH from scmc1 (d0, q0, r0, m0, 'grid/scmc1/snapshot', ... (300 bytes))\n")
        self.assertEqual(ds.broker_publishes(path), [1001.0, 1003.0])
        self.assertEqual(ds.broker_publishes(path + ".missing"), [])

    def test_end_rounded_up_to_the_logged_second(self):
        path_t, path = [0.0], [("10.0.0.2", "10.1.0.2")]
        blocks = [("10.0.0.2", 10.0, 20.0, "oracle-src")]
        # Logged at 20 (true time in [20, 21)): may be after the 20.4 release → ends at 21.
        out = ds.impact_intervals(blocks, path_t, path, [5.0, 20.0, 24.0], 60.0, resolution=1.0)
        self.assertEqual([(a, b) for a, b, *_ in out], [(10.0, 21.0)])
        out = ds.impact_intervals([("10.0.0.2", 10.0, 20.4, "x")], path_t, path,
                                  [5.0, 19.0, 24.0], 60.0, resolution=1.0)
        self.assertEqual([(a, b) for a, b, *_ in out], [(10.0, 25.0)])


if __name__ == "__main__":
    unittest.main()
