"""Harnesses at the teams' seats (cyberrange/scenarios/cps_advisor/feature.py):
the options that put one there, the nodes it plays from and what they can
reach, and the episode two of them play with nobody watching — run with the
fake Kathará manager, so no Docker and no model.

Run: `.venv/bin/python -m pytest tests/scenarios/cps_advisor/test_agent_players.py`.
"""

import json
import os
import tempfile
import time
import unittest
from unittest import mock

from cyberrange.core.cli import default_args
from cyberrange.core.component import SeatPlayer
from cyberrange.core.harness import Harness
from cyberrange.core.topology import build_lab
from cyberrange.scenarios.cps import scenario as cps_scenario
from cyberrange.scenarios.cps.metrics import compute_metrics
from cyberrange.scenarios.cps_advisor import cli as advisor
from cyberrange.scenarios.cps_advisor import harnesses
from cyberrange.scenarios.cps_advisor.briefing import briefing
from cyberrange.scenarios.cps_advisor.feature import managed
from cyberrange.scenarios.cps_advisor.scenario import CpsAdvisorScenario
from tests.helpers.kathara import FakeManager, fake_downloads, fake_uploads

BOTH = dict(teams=True, red_harness="scripted", blue_harness="scripted")
TRANSCRIPT = SeatPlayer.TRANSCRIPT


class Collector:
    def __init__(self):
        self.events = []

    def __call__(self, kind, **fields):
        self.events.append({"kind": kind, **fields})


class Options(unittest.TestCase):
    def setUp(self):
        self.s = CpsAdvisorScenario()

    def refused(self, **over):
        with self.assertRaises(SystemExit) as why:
            self.s.validate(default_args(self.s, **over))
        return str(why.exception)

    def test_a_harness_plays_a_team_so_there_must_be_teams(self):
        self.assertIn("--teams", self.refused(red_harness="scripted"))

    def test_with_a_harness_at_both_seats_nobody_has_to_stay(self):
        self.s.validate(default_args(self.s, **BOTH))

    def test_with_a_person_at_one_seat_the_lab_must_stay_up(self):
        self.assertIn("--playground", self.refused(teams=True, red_harness="scripted"))
        self.s.validate(default_args(self.s, teams=True, red_harness="scripted", playground=True))

    def test_a_harness_whose_secret_the_host_lacks_is_refused_before_the_lab_starts(self):
        with mock.patch.dict(os.environ, clear=False) as env:
            env.pop("ANTHROPIC_API_KEY", None)
            env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
            why = self.refused(teams=True, red_harness="claude-code", blue_harness="scripted")
            self.assertIn("ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN", why)
            # Either one is enough: an API key, or a subscription's token.
            env["CLAUDE_CODE_OAUTH_TOKEN"] = "a-subscription-token"
            self.s.validate(
                default_args(self.s, teams=True, red_harness="claude-code", blue_harness="scripted")
            )

    def test_the_run_says_who_plays_each_seat(self):
        args = default_args(self.s, **BOTH, red_model="m1")
        self.assertEqual(
            self.s.run_info(args)["players"],
            {
                "blue": {"kind": "agent", "harness": "scripted", "model": None},
                "red": {"kind": "agent", "harness": "scripted", "model": "m1"},
            },
            "a comparison of harnesses is grouped by this",
        )
        mixed = default_args(self.s, teams=True, playground=True, blue_harness="scripted")
        self.assertEqual(self.s.run_info(mixed)["players"]["red"], {"kind": "human"})
        self.assertNotIn("players", self.s.run_info(default_args(self.s)))

    def test_the_engagement_is_a_declared_phase_only_when_harnesses_play_both_seats(self):
        def names(**over):
            return [p.name for p in self.s.episode_phases(default_args(self.s, **over))]

        self.assertEqual(names(**BOTH)[-1], "engagement")
        self.assertNotIn("engagement", names(teams=True, playground=True))
        self.assertNotIn("engagement", names(teams=True, playground=True, red_harness="scripted"))


class Tokens(unittest.TestCase):
    def test_a_token_never_reads_as_an_option(self):
        from cyberrange.scenarios.cps_advisor import feature

        real = feature.secrets.token_urlsafe
        self.addCleanup(setattr, feature.secrets, "token_urlsafe", real)
        drawn = iter(["-dashFirst", "_underscoreFirst", "aGoodOne"])
        feature.secrets.token_urlsafe = lambda _n: next(drawn)
        self.assertEqual(
            feature.fresh_token(),
            "aGoodOne",
            "a token starting with a dash is taken for an option by the console it is passed "
            "to: the console does not start",
        )


class TheRegistry(unittest.TestCase):
    """Adding a harness must be an entry and its files: a launcher that is not
    staged, or an image nobody builds, fails hours into a campaign."""

    def test_every_harness_has_its_launcher_staged_and_its_image_buildable(self):
        from cyberrange.scenarios.cps_advisor.guest_files import PLAYER_FILES
        from tests.helpers import REPO_ROOT

        for name, h in harnesses.HARNESSES.items():
            with self.subTest(harness=name):
                self.assertEqual(h.name, name)
                staged = {guest for _host, guest in PLAYER_FILES + list(h.files)}
                self.assertIn(
                    h.launcher.split()[-1],
                    staged,
                    f"{name}'s launcher is not copied onto its node: the player would not start",
                )
                dockerfile = REPO_ROOT / "docker" / h.image.split("/")[-1] / "Dockerfile"
                self.assertTrue(
                    dockerfile.is_file(), f"nothing builds {h.image}, the node {name} plays from"
                )


class TheLab(unittest.TestCase):
    def build(self, **over):
        s = CpsAdvisorScenario()
        args = default_args(s, **over)
        s.prepare(args)
        topo = s.topology(args)
        _lab, machines, startups = build_lab(topo)
        return topo, machines, startups

    def test_a_player_has_its_seat_a_way_out_and_nothing_of_the_lab(self):
        topo, machines, _startups = self.build(**BOTH)
        lab_links = {f.link for n in topo.nodes if n.role != "player" for f in n.ifaces}
        for team, address in (("blue", "198.18.0.2/30"), ("red", "198.18.0.6/30")):
            with self.subTest(team=team):
                node = topo.node(f"{team}player")
                self.assertEqual(
                    [(f.link, f.cidr) for f in node.ifaces],
                    [(f"seat{team}", address)],
                    "a player's node has a foot on a network of the lab: it could reach the "
                    "hosts without going through its seat",
                )
                self.assertTrue(machines[node.name].meta.get("bridged"), "no way out to a model")
                self.assertFalse(machines[node.name].meta.get("ports"), "a player is never dialled")
                self.assertEqual(topo.image_of(node), "kathara/player")
                guest = [g for _h, g in node.files]
                for needed in ("/seat_mcp.py", "/player-run.sh", "/player-firewall.sh"):
                    self.assertIn(needed, guest)
        self.assertEqual(
            sum(1 for n in topo.nodes for f in n.ifaces if f.link == "seatred"),
            2,
            "the link to a seat is between the console's node and its player's, and no other",
        )
        self.assertIn("seatred", lab_links)

    def test_the_consoles_node_opens_the_link_to_its_player_only(self):
        topo, _machines, startups = self.build(**BOTH)
        for host, player in (("attacker", "198.18.0.6"), ("soc", "198.18.0.2")):
            with self.subTest(host=host):
                iface = f"eth{len(topo.node(host).ifaces) - 1}"
                rules = [c for c in startups[host] if f" {iface} " in c and "iptables" in c]
                self.assertEqual(
                    rules,
                    [
                        f"iptables -A INPUT -i {iface} -p tcp -s {player} --dport 8090 -j ACCEPT",
                        f"iptables -A INPUT -i {iface} -j DROP",
                        f"iptables -A FORWARD -i {iface} -j DROP",
                        f"iptables -A FORWARD -o {iface} -j DROP",
                    ],
                    "the player's node could reach the team's terminal, or be routed on into "
                    "the lab through its console's node",
                )
                self.assertIn("/seat.py", [g for _h, g in topo.node(host).files])

    def test_a_seat_a_person_plays_gains_nothing(self):
        topo, _machines, _startups = self.build(teams=True, playground=True, red_harness="scripted")
        self.assertEqual([n.name for n in topo.nodes if n.role == "player"], ["redplayer"])
        self.assertNotIn("seatblue", [f.link for f in topo.node("soc").ifaces])


class TheBriefing(unittest.TestCase):
    def setUp(self):
        self.s = CpsAdvisorScenario()
        self.args = default_args(self.s, **BOTH, engagement_s=300, max_calls=40)
        self.spec = self.s.lab_spec(self.args)

    def test_each_side_is_told_its_own(self):
        red = briefing("red", self.spec, self.args, engaged=True)
        blue = briefing("blue", self.spec, self.args, managed=managed(self.spec), engaged=True)
        self.assertIn(self.spec.ip("attacker"), red)
        for url in cps_scenario.plant_of(self.spec).ways.values():
            self.assertIn(url, red, "the red team is not told the way in")
        for name in ("soc", "sensor"):
            self.assertNotIn(f"`{name}`", red, f"the red team is told of the defence's {name}")
        self.assertIn("`firewall`", blue)
        self.assertIn("120 seconds", blue, "the blue team is not told how long a suggestion waits")
        self.assertNotIn("web application", blue, "the blue team is told the attack's way in")

    def test_both_sides_are_told_the_game_is_the_whole_engagement(self):
        for team in ("red", "blue"):
            text = briefing(team, self.spec, self.args, managed=managed(self.spec), engaged=True)
            self.assertIn(
                "whole engagement",
                text,
                f"the {team} team is not told to keep playing: a harness stops at its first "
                "success and the rest of the engagement is played against nobody",
            )

    def test_the_terms_are_the_runs(self):
        red = briefing("red", self.spec, self.args, engaged=True)
        self.assertIn("300 seconds", red)
        self.assertIn("40 tool calls", red)
        with_people = briefing("red", self.spec, self.args, engaged=False)
        self.assertIn("until the referee closes it", with_people)
        self.assertNotIn("tool calls", with_people)


class TheSeatPlayer(unittest.TestCase):
    def setUp(self):
        self.harness = Harness("h1", image="img", launcher="python3 /h1.py", secret_env=("KEY",))
        self.player = SeatPlayer(
            "redplayer",
            "red",
            self.harness,
            ("198.18.0.5", 8090, "eth0"),
            "t0ken",
            terms={"CR_OPERATOR": "agent:h1:m 1", "CR_MODEL": None, "CR_DEADLINE": 1700.5},
            secrets={"KEY": "s3cr3t'quote"},
            resolvers=["9.9.9.9", "1.1.1.1"],
        )

    def test_secrets_reach_the_node_as_files_and_never_on_a_command_line(self):
        class Ctx:
            def __init__(self):
                self.uploaded, self.ran = {}, []

            def upload(self, node, path, text, mode=0o600):
                self.uploaded[path] = text

            def exec(self, node, cmd, **_kw):
                self.ran.append(cmd)

        ctx = Ctx()
        self.player.start(ctx)
        self.assertEqual(ctx.ran, ["bash /player-run.sh"])
        self.assertEqual(ctx.uploaded[SeatPlayer.TOKEN], "t0ken")
        self.assertEqual(ctx.uploaded[SeatPlayer.SECRETS], "KEY='s3cr3t'\"'\"'quote'\n")
        terms = dict(line.split("=", 1) for line in ctx.uploaded[SeatPlayer.TERMS].splitlines())
        self.assertEqual(terms["CR_SEAT_URL"], "http://198.18.0.5:8090")
        self.assertEqual(terms["CR_OPERATOR"], "'agent:h1:m 1'", "a space would split the value")
        self.assertEqual(terms["LAUNCHER"], "'python3 /h1.py'")
        self.assertEqual((terms["SEAT_IP"], terms["SEAT_IFACE"]), ("198.18.0.5", "eth0"))
        self.assertEqual(terms["RESOLVERS"], "'9.9.9.9 1.1.1.1'")
        self.assertNotIn("CR_MODEL", terms, "a term nobody set was passed as the string None")
        self.assertNotIn("s3cr3t", ctx.uploaded[SeatPlayer.TERMS])

    def test_the_transcript_is_mirrored_and_its_last_row_ends_the_player(self):
        call = {"t": 5.0, "kind": "player_call", "tool": "run_step", "outcome": "ok", "team": "red"}
        self.assertEqual(
            self.player.mirror(call),
            ("player_call", {"tool": "run_step", "outcome": "ok", "team": "red", "guest_t": 5.0}),
        )
        self.assertIsNone(self.player.mirror({"kind": "something_else"}))
        self.assertFalse(self.player.exited)
        self.player.mirror({"t": 9.0, "kind": "player_exit", "rc": 0})
        self.assertTrue(self.player.exited)


def transcript(team):
    rows = [
        {"t": 100.0, "kind": "player_start", "harness": "scripted", "harness_version": "1"},
        {
            "t": 101.0,
            "kind": "player_call",
            "tool": "list_steps",
            "outcome": "ok",
            "duration_s": 0.1,
        },
        {"t": 102.0, "kind": "player_call", "tool": "run_step", "outcome": "ok", "duration_s": 2.0},
        {
            "t": 103.0,
            "kind": "player_call",
            "tool": "run_step",
            "outcome": "seat_error",
            "duration_s": 4.0,
        },
        {"t": 104.0, "kind": "player_usage", "turns": None, "stop_reason": "done"},
        {"t": 105.0, "kind": "player_exit", "rc": 0},
    ]
    return [json.dumps({**r, "team": team}) + "\n" for r in rows]


class Episode(unittest.TestCase):
    def setUp(self):
        self._settle = cps_scenario.SERVICE_SETTLE_S
        cps_scenario.SERVICE_SETTLE_S = 0.0
        self.addCleanup(setattr, cps_scenario, "SERVICE_SETTLE_S", self._settle)
        self.out = tempfile.mkdtemp(prefix="cps-agents-")

    def play(self, files, **over):
        s = CpsAdvisorScenario()
        args = default_args(
            s,
            out_dir=self.out,
            seed=1,
            normal_duration=0.2,
            learn_seconds=0.1,
            poll_interval=0.05,
            **BOTH,
            **over,
        )
        self.mgr, col = FakeManager(files=files), Collector()
        left = {
            (f"{team}player", TRANSCRIPT): "".join(transcript(team)).encode()
            for team in ("red", "blue")
        }
        with fake_downloads(left), fake_uploads() as self.uploaded:
            self.assertEqual(advisor.run(args, progress=col, manager=self.mgr), 0)
        return args, col

    def steps(self):
        rows = [
            {"step": "it_access", "stage": "it_access", "stage_rank": 0, "ok": True},
            {
                "step": "pivot",
                "stage": "pivot",
                "stage_rank": 2,
                "ok": True,
                "note": "through the HMI",
            },
            {"step": "meas_fdi", "stage": "impact", "stage_rank": 5, "ok": False},
        ]
        rows[2]["phases"] = [{"phase": "fdi", "t": 52.5, "ok": False, "sent": 0}]
        return [
            json.dumps({"t": 50.0 + i, "kind": "red_step", "operator": "agent:scripted", **r})
            + "\n"
            for i, r in enumerate(rows)
        ]

    def test_two_harnesses_play_and_the_run_ends_by_itself(self):
        began = time.time()
        args, col = self.play(
            {"/red_actions.jsonl": self.steps(), TRANSCRIPT: transcript("red")}, engagement_s=60
        )
        self.assertLess(
            time.time() - began, 30, "the engagement outlasted two players that had both stopped"
        )
        phases = [e["name"] for e in col.events if e["kind"] == "phase" and e["state"] == "start"]
        self.assertEqual(
            phases,
            ["deploy", "services", "normal", "engagement", "download", "undeploy"],
            "a run nobody watches must not wait for a Ctrl-C",
        )
        for team in ("red", "blue"):
            node = f"{team}player"
            self.assertEqual(
                [c for c in self.mgr.commands(node) if "player-run" in c],
                ['bash -c "PYTHONUNBUFFERED=1 bash /player-run.sh > player.log 2>&1"'],
            )
            token = getattr(args, f"{team}_token")
            self.assertEqual(self.uploaded[(node, SeatPlayer.TOKEN)], token.encode())
            terms = self.uploaded[(node, SeatPlayer.TERMS)].decode()
            self.assertIn("CR_OPERATOR=agent:scripted\n", terms)
            self.assertIn("CR_DEADLINE=", terms)
            for _node, cmd, _w, _s in self.mgr.calls:
                if _node == node:
                    self.assertNotIn(token, cmd, "a team's token is on a command line")
        kinds = [e["kind"] for e in col.events]
        for kind in ("player_start", "player_call", "player_usage", "player_exit"):
            self.assertIn(kind, kinds, "the ledger does not show what the players did")
        start = next(e for e in col.events if e["kind"] == "run_start")
        self.assertEqual(start["players"]["red"]["harness"], "scripted")

    def test_what_the_red_harness_did_is_scored_as_an_attack(self):
        self.play({"/red_actions.jsonl": self.steps(), TRANSCRIPT: transcript("red")})
        with open(os.path.join(self.out, "ground_truth.jsonl")) as f:
            gt = [json.loads(line) for line in f]
        end = next(e for e in gt if e["kind"] == "attack_end")
        self.assertEqual(
            (end["stage_reached"], end["success"], end["mode"]),
            ("pivot", False, "manual"),
            "an attack played at the console has no end on record: it cannot be scored",
        )
        steps = [e for e in gt if e["kind"] == "red_step"]
        self.assertEqual([s["stage"] for s in steps], ["it_access", "pivot", "impact"])
        self.assertEqual(steps[1]["note"], "through the HMI")
        self.assertIn("fdi", [e["kind"] for e in gt], "falsified readings are not on the record")
        m = compute_metrics(self.out)
        self.assertEqual(
            (m["stage_reached"], m["attack_succeeded"], m["prevented"]), ("pivot", False, True)
        )

    def test_each_harness_gets_its_scorecard(self):
        self.play({"/red_actions.jsonl": self.steps(), TRANSCRIPT: transcript("red")})
        card = compute_metrics(self.out)["players"]["red"]
        self.assertEqual((card["harness"], card["harness_version"]), ("scripted", "1"))
        self.assertEqual((card["calls"], card["actions"]), (3, 2))
        self.assertEqual(card["failed_calls"], {"seat_error": 1})
        self.assertEqual(card["action_latency_median_s"], 3.0)
        self.assertEqual(
            (card["stop_reason"], card["exit_code"], card["played_s"]), ("done", 0, 5.0)
        )
        self.assertIsNone(
            card["cost_usd"], "a figure the harness did not report was filled in with something"
        )

    def test_a_run_nobody_played_has_no_scorecard(self):
        self.assertIsNone(compute_metrics(tempfile.mkdtemp())["players"])


if __name__ == "__main__":
    unittest.main()
