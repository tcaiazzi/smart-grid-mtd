"""The MTD ablation grid and the manifest it writes.

The figures in analysis/plot_sweep.py are drawn against the manifest columns, so
a configuration whose row does not match the parameters it actually ran with
produces a plausible, wrong figure. Nothing else checks that correspondence.

Run: `.venv/bin/python -m pytest tests/scenarios/mqtt_mtd/test_ablation.py`
"""

import csv
import tempfile
import unittest
from pathlib import Path

from cyberrange.scenarios.mqtt_mtd import ablation
from cyberrange.scenarios.mqtt_mtd.campaign import MtdParams, slug


class Grid(unittest.TestCase):
    def test_every_group_is_present_and_sized(self):
        g = ablation.groups()
        self.assertEqual({"e0", "e1", "e2", "e3", "e4"}, set(g))
        sizes = {name: len(configs) for name, configs in g.items()}
        self.assertEqual(
            {"e0": 1, "e1": 4, "e2": 4, "e3": 3, "e4": 3},
            sizes,
            "the ablation grid changed size; the figures expect one series per "
            "configuration, so check analysis/plot_sweep.py still matches.",
        )

    def test_e1_isolates_one_mechanism_at_a_time(self):
        """E1 is only meaningful if the other pools really are collapsed: a pool
        of one is a mechanism with nowhere to move to."""
        by_name = dict(ablation.groups()["e1"])
        for name, expected in [
            ("E1-no-hop", (1, 1, 1)),
            ("E1-port-only", (1, 5, 1)),
            ("E1-ip-only", (4, 1, 1)),
            ("E1-src-only", (1, 1, 4)),
        ]:
            with self.subTest(config=name):
                c = by_name[name].counts()
                self.assertEqual(
                    expected,
                    (c["n_ips"], c["n_ports"], c["n_src"]),
                    f"{name} no longer isolates what its name claims",
                )

    def test_each_axis_varies_only_its_own_parameter(self):
        d = ablation.DEFAULTS
        for name, params in ablation.groups()["e2"]:
            with self.subTest(config=name):
                self.assertEqual(params.counts(), d.counts(), "E2 must vary timing, not pools")
        for name, params in ablation.groups()["e4"]:
            with self.subTest(config=name):
                self.assertEqual(params.hop, d.hop, "E4 must vary frequency, not the address hop")


class Manifest(unittest.TestCase):
    def test_rows_describe_the_configuration_that_ran(self):
        configs = [c for g in ("e0", "e1", "e2", "e3", "e4") for c in ablation.groups()[g]]
        with tempfile.TemporaryDirectory() as root:
            ablation.write_manifest(configs, root=root)
            rows = list(csv.DictReader(open(Path(root, "sweep_manifest.csv"))))

        self.assertEqual(len(configs), len(rows), "one manifest row per configuration")
        by_experiment = {r["experiment"]: r for r in rows}
        for experiment, params in configs:
            with self.subTest(config=experiment):
                row, counts = by_experiment[experiment], params.counts()
                self.assertEqual(str(params.hop), row["hop"])
                self.assertEqual(str(params.mbps), row["bg_mbps"])
                self.assertEqual(str(params.freq_interval), row["freq_interval"])
                for key in ("n_ips", "n_ports", "n_src", "n_pads", "n_freqs"):
                    self.assertEqual(str(counts[key]), row[key])
                self.assertEqual(
                    slug(no_mtd=False, mbps=params.mbps, params=params),
                    row["slug"],
                    "the row points at a directory this configuration will not write",
                )

    def test_the_rows_actually_differ(self):
        """A manifest whose rows are all the same is the defect this replaces:
        the figures would plot one point many times."""
        configs = [c for g in ("e1", "e2") for c in ablation.groups()[g]]
        with tempfile.TemporaryDirectory() as root:
            ablation.write_manifest(configs, root=root)
            rows = list(csv.DictReader(open(Path(root, "sweep_manifest.csv"))))
        axes = {(r["hop"], r["n_ips"], r["n_ports"], r["n_src"]) for r in rows}
        self.assertEqual(len(rows), len(axes), "two configurations share the same axes")


class CampaignShape(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="ablation-")
        self.campaign, self.configs = ablation.build_campaign(["e2"], root=self.root)

    def test_the_figures_are_a_step_of_the_campaign(self):
        last = self.campaign.units[-1]
        self.assertEqual(
            ["figures"],
            [s.id for s in last.steps],
            "the ablation ends without drawing its figures: `make sweep` leaves no sweep/*.pdf",
        )
        self.assertIn("cyberrange.scenarios.mqtt_mtd.analysis.plot_sweep", last.steps[0].cmd)
        self.assertEqual([], last.needs, "one failed configuration must not cancel the figures")

    def test_it_is_listed_under_its_own_scenario_and_summarised(self):
        self.assertEqual("mqtt-mtd", self.campaign.scenario)
        self.assertIsNotNone(self.campaign.aggregate_fn, "summary.md and ci.csv are never written")

    def test_the_manifest_step_records_the_configuration_that_ran(self):
        for unit in self.campaign.units:
            for step in unit.steps:
                if step.id == "manifest":
                    step.run(None)
        rows = list(csv.DictReader(open(Path(self.root, "sweep_manifest.csv"))))
        self.assertEqual(
            sorted(str(p.hop) for _exp, p in self.configs),
            sorted(r["hop"] for r in rows),
            "the manifest step wrote the paper's hop interval for every configuration, "
            "so the E2 figure plots four points at one x",
        )

    def test_a_stale_row_is_replaced_not_kept(self):
        experiment, params = self.configs[0]
        exp = slug(no_mtd=False, mbps=params.mbps, params=params)
        ablation.append_manifest(experiment, params.mbps, exp, root=self.root)  # paper params
        ablation.append_manifest(experiment, params.mbps, exp, root=self.root, params=params)
        rows = list(csv.DictReader(open(Path(self.root, "sweep_manifest.csv"))))
        self.assertEqual([str(params.hop)], [r["hop"] for r in rows])

    def test_every_unit_writes_under_the_chosen_root(self):
        for unit in self.campaign.units:
            self.assertTrue(
                unit.id == "figures" or unit.id.endswith(f"@{self.root}"),
                f"unit {unit.id} ignores --output-root: its results land under output/",
            )


class PaperDefaultsUnchanged(unittest.TestCase):
    def test_parameterising_did_not_move_the_paper_configuration(self):
        p = MtdParams()
        self.assertEqual(4, p.hop)
        self.assertEqual(5, p.freq_interval)
        self.assertEqual(
            {"n_ips": 6, "n_ports": 7, "n_pads": 7, "n_src": 6, "n_freqs": 6},
            p.counts(),
            "the paper campaign's parameters changed; main.py would no longer "
            "reproduce the published numbers.",
        )


if __name__ == "__main__":
    unittest.main()
