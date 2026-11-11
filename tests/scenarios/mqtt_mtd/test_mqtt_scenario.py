"""The MQTT smart-grid scenario on the platform core, with a FAKE Kathará
manager (no Docker): topology, the commands each mode issues, the artifacts
downloaded under the names downstream tools read, ground truth, ledger
events and the exit code of a run whose SCMC never published.

Run: `.venv/bin/python -m unittest tests.test_mqtt_scenario`.
"""

import logging
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path


from cyberrange.planes.attack import components as attack_components  # noqa: E402
from cyberrange.core.progress import read_events  # noqa: E402
from cyberrange.scenarios.mqtt_mtd import cli  # noqa: E402
from cyberrange.core.cli import default_args  # noqa: E402
from cyberrange.core.streams import read_jsonl  # noqa: E402
from cyberrange.core.topology import build_lab, export_lab_conf  # noqa: E402
from cyberrange.scenarios.mqtt_mtd import topology as T  # noqa: E402
from cyberrange.scenarios.mqtt_mtd.scenario import (  # noqa: E402
    EXIT_NO_PUBLISH,
    MqttMtdScenario,
)
from tests.helpers.kathara import FakeManager, fake_downloads  # noqa: E402

# One publish line in the executor's format ("#<n> → ip:port") and one that is not.
PUBLISHED = (
    b"2026-10-08T11:26:39  [scmc1] MQTT \xe2\x86\x92 10.1.0.2:8883 (ok)\n"
    b"2026-10-08T11:26:40  [scmc1] #1 \xe2\x86\x92 10.1.0.2:8883  power=1 kW\n"
)


_TRACE = os.path.join(tempfile.mkdtemp(prefix="mqtt-trace-"), "trace.pcap")
open(_TRACE, "wb").close()


def _args(**kw):
    kw.setdefault("trace", _TRACE)  # staged on the router: must exist on the host
    return default_args(MqttMtdScenario(), **kw)


class Topology(unittest.TestCase):
    def test_mtd_pools_are_bound_and_dashboard_is_bridged(self):
        a = _args(dashboard_port=8090)
        lab, m, st = build_lab(T.topology(a))
        self.assertEqual(set(lab.machines), {"scmc", "router", "semp", "attacker"})
        self.assertIn("ip address add 10.0.0.4/24 dev eth0", st["scmc"])
        self.assertIn("ip address add 10.1.0.5/24 dev eth0", st["semp"])
        self.assertIn("ip route replace default via 10.1.0.1 dev eth0", st["semp"])
        self.assertEqual(m["semp"].meta["ports"], {(8090, "tcp"): T.DASHBOARD_GUEST_PORT})
        self.assertEqual(m["semp"].meta["addresses"], {"eth0": "10.1.0.2/24"})
        self.assertEqual(
            m["router"].meta["addresses"], {"eth0": "10.0.0.1/24", "eth1": "10.1.0.1/24"}
        )

    def test_baseline_has_no_pools_no_dashboard_and_its_own_broker_config(self):
        topo = T.topology(_args(no_mtd=True))
        _lab, m, st = build_lab(topo)
        self.assertEqual([c for c in st["scmc"] if "10.0.0.4" in c], [])
        self.assertIsNone(m["semp"].meta.get("bridged"))
        semp_files = dict((g, h) for h, g in topo.node("semp").files)
        self.assertEqual(
            semp_files["/etc/mosquitto/mosquitto.conf"], "assets/mosquitto/mosquitto_nomtd.conf"
        )

    def test_rl_policy_is_staged_with_its_coordinator(self):
        topo = T.topology(_args(rl_policy="output/rl/policy.npz"))
        guest = [g for _h, g in topo.node("semp").files]
        self.assertIn("/mtd_rl_coordinator.py", guest)
        self.assertIn(T.POLICY_GUEST, guest)

    def test_lab_conf_export(self):
        out = tempfile.mkdtemp(prefix="mqtt-labconf-")
        export_lab_conf(T.topology(_args()), out)
        conf = Path(out, "lab.conf").read_text()
        self.assertIn('scmc[0]="A"', conf)
        self.assertIn('router[1]="B"', conf)
        self.assertIn('semp[image]="kathara/mqtt"', conf)
        self.assertNotIn("attacker[image]", conf)  # Kathará's default image
        self.assertIn(
            "ip route add default via 10.0.0.1 dev eth0", Path(out, "scmc.startup").read_text()
        )


class _Run(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="mqtt-run-")
        self._stdout = sys.stdout
        self._handlers = list(logging.getLogger().handlers)

    def tearDown(self):
        sys.stdout = self._stdout  # the run tees stdout into run.log
        root = logging.getLogger()
        for h in list(root.handlers):
            if h not in self._handlers:
                root.removeHandler(h)


class DatasetMode(_Run):
    def _run(self, files, **kw):
        a = _args(
            generate_dataset=1, name="train", datasets_dir=self.out, seed=7, poll_interval=0, **kw
        )
        mgr = FakeManager()
        with fake_downloads(files):
            rc = cli.run(a, manager=mgr)
        return rc, mgr

    def test_mtd_capture_layout_commands_and_ledger(self):
        files = {
            ("router", "/train.pcap"): b"pcap",
            ("scmc", "/mtd_executor.log"): PUBLISHED,
            ("semp", "/var/log/mosquitto/mosquitto.log"): b"log",
            ("semp", "/telemetry.jsonl"): b"",
        }
        rc, mgr = self._run(files)
        self.assertEqual(rc, 0)
        for name in (
            "train.pcap",
            "train.client.log",
            "train.mosquitto.log",
            "train.telemetry.jsonl",
            "train.run.log",
            "scmc_ips.txt",
            "progress.jsonl",
            "topology.json",
        ):
            self.assertTrue(os.path.exists(os.path.join(self.out, name)), name)
        self.assertEqual(
            Path(self.out, "scmc_ips.txt").read_text().strip(), "10.0.0.2,10.0.0.4,10.0.0.5"
        )
        semp = mgr.commands("semp")
        self.assertTrue(any(c.startswith("python3 cert_authority.py") for c in semp))
        coord = [c for c in semp if "mtd_coordinator.py" in c]
        self.assertEqual(len(coord), 1)
        self.assertIn("--observe-data", coord[0])
        self.assertIn("--dashboard-port 8080", coord[0])
        self.assertIn("--seed", coord[0])
        self.assertTrue(any("cert_client.py" in c for c in mgr.commands("scmc")))
        self.assertTrue(any("mtd_executor.py" in c for c in mgr.commands("scmc")))
        router = mgr.commands("router")
        self.assertTrue(
            any(c.startswith("timeout 1 bash ./replay_background.sh eth1 2") for c in router)
        )
        self.assertIn("timeout 1 tcpdump -i eth1 -w train.pcap", router)
        evs = read_events(os.path.join(self.out, "progress.jsonl"))
        self.assertEqual(evs[0]["kind"], "run_start")
        self.assertEqual(evs[0]["scenario"], "mqtt-mtd")
        self.assertEqual(evs[0]["run_id"], "train")
        phases = [e["name"] for e in evs if e["kind"] == "phase" and e["state"] == "start"]
        self.assertEqual(phases, ["deploy", "services", "capture", "download", "undeploy"])
        self.assertEqual(evs[-1]["status"], "ok")
        self.assertEqual(mgr.undeployed, ["test", "test"])

    def test_no_publish_discards_the_capture_and_exits_3(self):
        files = {
            ("router", "/train.pcap"): b"pcap",
            ("scmc", "/mtd_executor.log"): b"",
            ("semp", "/var/log/mosquitto/mosquitto.log"): b"log",
        }
        rc, _mgr = self._run(files)
        self.assertEqual(rc, EXIT_NO_PUBLISH)
        self.assertFalse(os.path.exists(os.path.join(self.out, "train.pcap")))
        evs = read_events(os.path.join(self.out, "progress.jsonl"))
        self.assertEqual((evs[-1]["status"], evs[-1]["rc"]), ("invalid", EXIT_NO_PUBLISH))

    def test_baseline_runs_the_plain_publisher_and_no_coordinator(self):
        files = {
            ("router", "/train.pcap"): b"pcap",
            ("scmc", "/simple_client.log"): PUBLISHED,
            ("semp", "/var/log/mosquitto/mosquitto.log"): b"log",
        }
        rc, mgr = self._run(files, no_mtd=True)
        self.assertEqual(rc, 0)
        self.assertFalse(any("coordinator" in c for c in mgr.commands("semp")))
        self.assertTrue(any("simple_client.py" in c for c in mgr.commands("scmc")))
        self.assertEqual(Path(self.out, "scmc_ips.txt").read_text().strip(), "10.0.0.2")

    def test_rl_coordinator_replaces_the_fixed_one(self):
        files = {
            ("router", "/train.pcap"): b"pcap",
            ("scmc", "/mtd_executor.log"): PUBLISHED,
            ("semp", "/var/log/mosquitto/mosquitto.log"): b"log",
        }
        policy = os.path.join(self.out, "policy.npz")
        open(policy, "wb").close()
        rc, mgr = self._run(files, rl_policy=policy, rl_tick=0.5)
        self.assertEqual(rc, 0)
        coord = [c for c in mgr.commands("semp") if "coordinator.py" in c]
        self.assertEqual(len(coord), 1)
        self.assertIn("mtd_rl_coordinator.py --policy policy.npz --tick 0.5", coord[0])


class AttackMode(_Run):
    def setUp(self):
        super().setUp()
        self._detect = attack_components.detect_nanogrid_ip
        ranking = types.SimpleNamespace(
            to_string=lambda: "src_ip nanogrid_frac\n10.0.0.2 0.9",
            to_csv=lambda: (
                "src_ip,nanogrid_frac,n_packets,positive_count\n"
                "10.0.0.2,0.9,100,90\n192.168.1.5,0.1,100,10\n"
            ),
        )
        attack_components.detect_nanogrid_ip = lambda *a, **k: ("10.0.0.2", ranking)

    def tearDown(self):
        attack_components.detect_nanogrid_ip = self._detect
        super().tearDown()

    def test_attack_artifacts_ground_truth_and_metrics(self):
        a = _args(
            attack=1, post_attack=0, results_dir=self.out, seed=3, poll_interval=0, dashboard_port=0
        )
        files = {
            (n, f"/{p}"): b"pcap"
            for n, p in (
                ("attacker", "attacker_capture.pcap"),
                ("attacker", "post_attack_capture.pcap"),
                ("router", "router_capture.pcap"),
                ("scmc", "scmc_capture.pcap"),
            )
        }
        files.update(
            {
                ("scmc", "/mtd_executor.log"): PUBLISHED,
                ("semp", "/var/log/mosquitto/mosquitto.log"): b"log",
            }
        )
        mgr = FakeManager()
        with fake_downloads(files):
            rc = cli.run(a, manager=mgr)
        self.assertEqual(rc, 0)
        for name in (
            "attacker_capture.pcap",
            "router_capture.pcap",
            "scmc_capture.pcap",
            "post_attack_capture.pcap",
            "nanogrid_ranking.csv",
            "client.log",
            "mosquitto.log",
            "run.log",
            "ground_truth.jsonl",
            "scmc_ips.txt",
        ):
            self.assertTrue(os.path.exists(os.path.join(self.out, name)), name)
        # plot_results.parse_block_event reads this line from run.log
        self.assertIn("Blocking nanogrid IP: 10.0.0.2", Path(self.out, "run.log").read_text())
        gt = read_jsonl(os.path.join(self.out, "ground_truth.jsonl"))
        kinds = [e["kind"] for e in gt]
        self.assertEqual(kinds[0], "run_meta")
        meta = gt[0]
        for key in ("scmc_ip_pool", "port_pool", "rl_policy", "oracle_block", "seed", "cnn_ip"):
            self.assertIn(key, meta)
        self.assertEqual(meta["cnn_ip"], "10.0.0.2")
        self.assertIn("block", kinds)
        self.assertLess(kinds.index("post_attack_start"), kinds.index("block"))
        self.assertLess(kinds.index("block"), kinds.index("post_attack_end"))
        self.assertIn("iptables -A FORWARD -s 10.0.0.2 -j DROP", mgr.commands("router"))
        self.assertIn("pkill -INT tcpdump", mgr.commands("router"))
        phases = [
            e["name"]
            for e in read_events(os.path.join(self.out, "progress.jsonl"))
            if e["kind"] == "phase" and e["state"] == "start"
        ]
        self.assertEqual(
            phases, ["deploy", "services", "sniff", "score", "post_attack", "download", "undeploy"]
        )
        m = MqttMtdScenario().metrics(self.out)
        self.assertAlmostEqual(m["nanogrid_detect"], 0.9)
        self.assertEqual(m["blocked_ip"], "10.0.0.2")
        self.assertTrue(m["blocked_is_scmc"])
        self.assertEqual(m["publishes"], 1)

    def test_dataset_and_attack_are_exclusive(self):
        with self.assertRaises(SystemExit):
            from cyberrange.core.cli import build_parser

            with open(os.devnull, "w") as devnull:
                err, sys.stderr = sys.stderr, devnull
                try:
                    build_parser(MqttMtdScenario()).parse_args(
                        ["--attack", "1", "--generate-dataset", "1"]
                    )
                finally:
                    sys.stderr = err


if __name__ == "__main__":
    unittest.main()
