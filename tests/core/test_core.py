"""The platform core on its own (no scenario, no Docker): campaign units and
steps (order, reuse, retries, dependencies, command steps), the 95%-CI
aggregate, the declarative topology and its lab.conf export, the scenario
registry.

Run: `.venv/bin/python -m unittest tests.test_core`.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path


from cyberrange.core.progress import read_events  # noqa: E402
from cyberrange.core import aggregate, registry  # noqa: E402
from cyberrange.core.campaign import Campaign, Step, Unit  # noqa: E402
from cyberrange.core.component import TelemetryCursor  # noqa: E402
from cyberrange.core.topology import (  # noqa: E402
    Iface,
    Node,
    Route,
    Topology,
    build_lab,
    export_lab_conf,
    to_dict,
)


class CampaignRunner(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="core-campaign-")
        self.done = []

    def step(self, sid, fail=0, **kw):
        state = {"n": 0}

        def run(emit):
            state["n"] += 1
            self.done.append(sid)
            if state["n"] <= fail:
                raise RuntimeError(f"{sid} failed")

        return Step(sid, run=run, **kw)

    def kinds(self):
        return [e["kind"] for e in read_events(os.path.join(self.root, "progress.jsonl"))]

    def test_failed_unit_blocks_its_dependents_only(self):
        units = [
            Unit("base", [self.step("a", fail=9)]),
            Unit("dep", [self.step("b")], needs=["base"]),
            Unit("free", [self.step("c")]),
        ]
        res = Campaign("t", self.root, units).run()
        self.assertEqual(self.done, ["a", "c"])
        self.assertEqual(res["status"], "done_with_failures")
        self.assertEqual(res["failed_units"], ["base", "dep"])
        k = self.kinds()
        self.assertIn("unit_blocked", k)
        self.assertEqual(k.count("step_failed"), 1)

    def test_a_failed_step_stops_its_unit(self):
        units = [Unit("u", [self.step("a"), self.step("b", fail=9), self.step("c")])]
        Campaign("t", self.root, units).run()
        self.assertEqual(self.done, ["a", "b"])

    def test_retries_then_success(self):
        units = [Unit("u", [self.step("a", fail=1, retries=1)])]
        res = Campaign("t", self.root, units).run()
        self.assertEqual((res["status"], self.done), ("done", ["a", "a"]))
        self.assertEqual(self.kinds().count("step_retry"), 1)

    def test_reuse_skips(self):
        units = [Unit("u", [self.step("a", skip_if=lambda: True), self.step("b")])]
        res = Campaign("t", self.root, units).run()
        self.assertEqual((self.done, res["skipped"]), (["b"], 1))
        self.assertIn("step_skipped", self.kinds())

    def test_command_steps_and_dry_run(self):
        lines = []
        units = [
            Unit(
                "u",
                [
                    Step("ok", cmd=[sys.executable, "-c", "pass"]),
                    Step("bad", cmd=[sys.executable, "-c", "raise SystemExit(4)"]),
                ],
                header="== unit u ==",
            )
        ]
        c = Campaign("t", self.root, units, out=lines.append)
        c.dry_run()
        self.assertEqual(lines[0], "== unit u ==")
        self.assertTrue(lines[1].startswith("  DRY: ") and lines[1].endswith("-c pass"))
        res = c.run()
        self.assertEqual(res["failed_units"], ["u"])
        ends = [
            e
            for e in read_events(os.path.join(self.root, "progress.jsonl"))
            if e["kind"] == "step_end"
        ]
        self.assertEqual([e["ok"] for e in ends], [True, False])
        self.assertIn("exit 4", ends[-1]["error"])

    def test_scored_step_metrics_aggregate_and_resume(self):
        rdir = os.path.join(self.root, "runs", "r1")
        agg_calls = []

        def agg(root, rows):
            agg_calls.append(len(rows))
            return {"n": len(rows)}

        def mk():
            return [
                Unit(
                    "u",
                    [
                        self.step(
                            "r1",
                            run_dir=rdir,
                            metrics=lambda d: {"x": 1.0},
                            label={"run_id": "r1", "group": "g"},
                        )
                    ],
                )
            ]

        Campaign("t", self.root, mk(), aggregate=agg).run()
        self.assertTrue(os.path.exists(os.path.join(rdir, "metrics.json")))
        Campaign("t", self.root, mk(), aggregate=agg).run()  # resumed: not rerun
        self.assertEqual(self.done, ["r1"])
        self.assertEqual(agg_calls, [1, 1])
        k = self.kinds()
        self.assertEqual((k.count("run_metrics"), k.count("run_skipped")), (1, 1))


class Aggregate(unittest.TestCase):
    def test_ci_and_flattening(self):
        rows = [
            {"group": "a", "metrics": {"x": v, "d": {"ok": b}, "skip": None}}
            for v, b in ((1.0, True), (2.0, False), (3.0, True))
        ]
        t = {r["metric"]: r for r in aggregate.summarize(rows)}
        self.assertEqual(set(t), {"x", "d.ok"})
        x = t["x"]
        self.assertEqual((x["n"], x["mean"], x["median"]), (3, 2.0, 2.0))
        self.assertAlmostEqual(x["std"], 1.0)
        self.assertAlmostEqual(x["ci95_high"] - x["mean"], 4.303 / 3**0.5, places=3)
        self.assertAlmostEqual(t["d.ok"]["mean"], 2 / 3, places=5)
        md = aggregate.format_markdown(aggregate.summarize(rows), metrics=["x"])
        self.assertIn("| a | 2 [", md)


class Topo(unittest.TestCase):
    def topo(self):
        return Topology(
            "demo",
            default_image="img/a",
            nodes=[
                Node(
                    "h1",
                    [Iface("L", "10.0.0.1/24", aliases=["10.0.0.9/24"])],
                    routes=[Route("default", "10.0.0.254", "eth0")],
                    role="target",
                ),
                Node("tap", [Iface("L", promisc=True), Iface("M", "10.9.0.1/24")], image=""),
            ],
        )

    def test_build_and_startup_order(self):
        lab, m, st = build_lab(self.topo())
        self.assertEqual(
            st["h1"],
            [
                "ip address add 10.0.0.1/24 dev eth0",
                "ip route add default via 10.0.0.254 dev eth0",
                "ip address add 10.0.0.9/24 dev eth0",
            ],
        )
        self.assertEqual(st["tap"][:2], ["ip link set eth0 promisc on", "ip link set eth0 up"])
        self.assertEqual(m["tap"].meta["addresses"], {"eth1": "10.9.0.1/24"})
        self.assertEqual(m["h1"].get_image(), "img/a")
        self.assertEqual(to_dict(self.topo())["nodes"][1]["image"], "")

    def test_lab_conf(self):
        out = tempfile.mkdtemp(prefix="core-labconf-")
        export_lab_conf(self.topo(), out)
        conf = Path(out, "lab.conf").read_text()
        self.assertIn('h1[0]="L"', conf)
        self.assertIn('tap[1]="M"', conf)
        self.assertIn('h1[image]="img/a"', conf)
        self.assertNotIn("tap[image]", conf)


class Misc(unittest.TestCase):
    def test_cursor_keeps_partial_lines(self):
        data = ['{"a": 1}\n{"b"']

        cur = TelemetryCursor(
            lambda start: "".join(data)[
                sum(len(x) + 1 for x in "".join(data).split("\n")[: start - 1]) :
            ]
        )
        self.assertEqual(cur.poll(), [{"a": 1}])
        data[0] = '{"a": 1}\n{"b": 2}\nnot json\n'
        self.assertEqual(cur.poll(), [{"b": 2}])
        self.assertEqual(cur.lines, 3)

    def test_registry(self):
        self.assertEqual(registry.names(), ["cps", "cps-advisor", "mqtt-mtd"])
        self.assertEqual(registry.get("cps").lab_name, "cps")
        self.assertEqual(registry.get("cps-advisor").lab_name, "cps-advisor")
        self.assertEqual(registry.get("mqtt-mtd").lab_name, "test")


if __name__ == "__main__":
    unittest.main()
