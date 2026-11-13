"""The cps-advisor scenario (cyberrange/scenarios/cps_advisor): the cps lab under
its own name, with the SOC's operator API published, and an episode whose SOC
advises — run with the fake Kathará manager, so no Docker.

Run: `.venv/bin/python -m pytest tests/scenarios/cps_advisor`.
"""

import base64
import json
import os
import tempfile
import unittest

from cyberrange.core import registry
from cyberrange.core.cli import default_args
from cyberrange.core.context import RunContext
from cyberrange.core.topology import build_lab
from cyberrange.planes.defense.components import SocAnalytics
from cyberrange.scenarios.cps import scenario as cps_scenario
from cyberrange.scenarios.cps_advisor import cli as advisor
from cyberrange.scenarios.cps_advisor.scenario import CpsAdvisorScenario
from tests.helpers.kathara import FakeManager, fake_downloads


class Collector:
    def __init__(self):
        self.events = []

    def __call__(self, kind, **fields):
        self.events.append({"kind": kind, **fields})


def args_of(scenario, **over):
    args = default_args(scenario, **over)
    scenario.prepare(args)
    return args


class Options(unittest.TestCase):
    def setUp(self):
        self.s = CpsAdvisorScenario()
        self.args = default_args(self.s)

    def test_it_advises_by_default(self):
        self.assertEqual(registry.get("cps-advisor").name, "cps-advisor")
        self.assertEqual((self.args.respond, self.args.approval), ("solver", "operator:120"))
        self.assertEqual(self.args.out_dir, "output/cps-advisor/run-1")
        self.s.validate(self.args)

    def test_the_cps_defaults_are_untouched(self):
        cps = default_args(cps_scenario.CpsScenario())
        self.assertEqual((cps.respond, cps.approval), ("off", "auto"))
        self.assertEqual(cps.out_dir, "output/cps/run-1")

    def test_only_an_operator_may_decide_here(self):
        for approval in ("auto", "deny", "delay:5", "operator:0", "operator:x"):
            self.args.approval = approval
            with self.assertRaises(SystemExit, msg=approval):
                self.s.validate(self.args)

    def test_an_advisor_needs_a_policy_and_its_ports(self):
        self.args.respond = "off"
        with self.assertRaises(SystemExit):
            self.s.validate(self.args)
        self.args.respond, self.args.blue_shell_port = "rules", self.args.blue_port
        with self.assertRaises(SystemExit):
            self.s.validate(self.args)

    def test_teams_need_a_lab_that_stays_up_and_an_attack_nobody_drives(self):
        self.args.teams = True
        with self.assertRaises(SystemExit):
            self.s.validate(self.args)  # no --playground
        self.args.playground = True
        self.s.validate(self.args)
        self.args.attack = True
        with self.assertRaises(SystemExit):
            self.s.validate(self.args)

    def test_each_team_gets_its_own_secret_and_the_ledger_gets_none(self):
        args = args_of(self.s, teams=True, playground=True)
        self.assertGreaterEqual(len(args.blue_token), 24)
        self.assertNotEqual(args.blue_token, args.red_token, "one token opens both consoles")
        self.assertNotEqual(args.blue_token, args_of(self.s).blue_token)
        told = json.dumps(self.s.run_info(args))
        for secret in (args.blue_token, args.red_token):
            self.assertNotIn(
                secret, told, "a team's token is on the ledger, which the other team may read"
            )
        links = self.s.links(args)
        self.assertEqual(
            links["blue"]["console"], f"http://127.0.0.1:8766/#token={args.blue_token}"
        )
        self.assertEqual(links["red"]["terminal"], f"http://red:{args.red_token}@127.0.0.1:8769/")
        self.assertNotIn("red", self.s.links(args_of(self.s)))


class Lab(unittest.TestCase):
    def build(self, **over):
        s = CpsAdvisorScenario()
        topo = s.topology(args_of(s, **over))
        return topo, *build_lab(topo)[1:]

    def test_same_lab_other_name_with_the_blue_team_let_in(self):
        topo, machines, startups = self.build()
        self.assertEqual(topo.name, "cps-advisor", "it would undeploy a running cps lab")
        cps = cps_scenario.CpsScenario()
        self.assertEqual(
            [n.name for n in topo.nodes], [n.name for n in cps.topology(default_args(cps)).nodes]
        )
        self.assertEqual(machines["soc"].meta["ports"], {(8766, "tcp"): 8090, (8767, "tcp"): 8091})
        for port in (8090, 8091):
            self.assertIn(
                f"iptables -A INPUT -i eth0 -p tcp --dport {port} -j DROP", startups["soc"]
            )
        files = {n.name: [g for _h, g in n.files] for n in topo.nodes}
        self.assertIn("/soc_console.html", files["soc"])
        for name in ("soc", "firewall", "sensor", "hmi"):
            self.assertIn("/team-access.sh", files[name], name)
            self.assertIn("/command_audit.sh", files[name], name)
        self.assertIsNone(machines["attacker"].meta.get("bridged"), "no red team, no way in")
        self.assertNotIn("/red_console.py", files["attacker"])

    def test_the_red_team_is_let_in_only_with_teams(self):
        topo, machines, startups = self.build(teams=True, playground=True)
        self.assertEqual(
            machines["attacker"].meta["ports"], {(8768, "tcp"): 8090, (8769, "tcp"): 8091}
        )
        self.assertIn(
            "iptables -A INPUT -i eth0 -p tcp --dport 8090 -j DROP",
            startups["attacker"],
            "the red console would answer on the IT network, to the hosts under attack",
        )
        files = {n.name: [g for _h, g in n.files] for n in topo.nodes}
        self.assertIn("/red_console.py", files["attacker"])
        self.assertIn("/team-access.sh", files["attacker"])


class Episode(unittest.TestCase):
    def setUp(self):
        self._settle = cps_scenario.SERVICE_SETTLE_S
        cps_scenario.SERVICE_SETTLE_S = 0.0
        self.addCleanup(setattr, cps_scenario, "SERVICE_SETTLE_S", self._settle)
        self.out = tempfile.mkdtemp(prefix="cps-advisor-")

    def run_it(self, mgr, **over):
        s = CpsAdvisorScenario()
        args = default_args(
            s,
            out_dir=self.out,
            seed=1,
            normal_duration=0.2,
            learn_seconds=0.1,
            poll_interval=0.05,
            **over,
        )
        col = Collector()
        with fake_downloads():
            self.assertEqual(advisor.run(args, progress=col, manager=mgr), 0)
        return args, col

    def started(self, mgr, node, needle):
        return next((c for n, c, _w, _s in mgr.calls if n == node and needle in c), None)

    def test_the_soc_is_started_as_an_advisor_with_its_console(self):
        mgr = FakeManager(responses={"team-access.sh jump": (b"ssh-ed25519 AAAAkey soc\n", b"", 0)})
        args, col = self.run_it(mgr)
        self.assertEqual(mgr.deployed, ["cps-advisor"])
        start = col.events[0]
        self.assertEqual((start["scenario"], start["approval"]), ("cps-advisor", "operator:120"))
        self.assertFalse(start["teams"])
        soc = self.started(mgr, "soc", "soc_analytics.py")
        self.assertIn("--policy solver --approval operator:120", soc)
        self.assertIn(f"--operator-port 8090 --operator-token {args.blue_token}", soc)
        self.assertIn(f"--operator-terminal http://blue:{args.blue_token}@127.0.0.1:8767/", soc)
        self.assertIn(
            f"terminal 8091 blue {args.blue_token}",
            self.started(mgr, "soc", "team-access.sh terminal"),
        )
        # The blue team reaches the hosts it manages from the SOC, with the SOC's key.
        for name, ip in (
            ("firewall", "10.30.0.1"),
            ("sensor", "10.30.0.10"),
            ("hmi", "10.30.0.30"),
        ):
            self.assertIn(
                f"sshd {ip} 'ssh-ed25519 AAAAkey soc'", self.started(mgr, name, " sshd "), name
            )
        self.assertIsNone(self.started(mgr, "attacker", "red_console.py"))
        with open(os.path.join(self.out, "teams.json")) as f:
            self.assertEqual(sorted(json.load(f)), ["blue"])

    def test_no_key_no_listener(self):
        mgr = FakeManager()  # the jump host printed no key
        self.run_it(mgr)
        self.assertIsNone(
            self.started(mgr, "firewall", " sshd "),
            "sshd was started with an empty authorized_keys",
        )

    def test_with_teams_nobody_drives_the_attack_and_the_red_team_is_let_in(self):
        real_hold = RunContext.hold
        self.addCleanup(setattr, RunContext, "hold", real_hold)

        def hold(ctx, *a, **k):
            ctx.poll()  # one look at the lab, then the referee closes it

        RunContext.hold = hold
        step = {
            "t": 50.0,
            "kind": "red_step",
            "step": "breaker_open",
            "ok": True,
            "operator": "eve",
        }
        step["phases"] = [
            {"phase": "modbus_write", "t_send": 50.1, "register": 1, "value": 1.0, "ok": True}
        ]
        # One record stands for every node's: typed in a web terminal on the
        # teams' own nodes, and reached through the vulnerable app on the HMI.
        typed = {"t": 51.0, "kind": "command", "cmd": "nmap 10.10.0.20", "cwd": "/", "from": ""}
        typed["ancestry"] = ["sh -c", "python3 vuln_app.py", "ttyd -p"]
        mgr = FakeManager(
            files={
                "/red_actions.jsonl": [json.dumps(step) + "\n"],
                "/var/log/commands.jsonl": [json.dumps(typed) + "\n"],
            }
        )
        args, col = self.run_it(mgr, teams=True, playground=True)
        phases = [e["name"] for e in col.events if e["kind"] == "phase" and e["state"] == "start"]
        self.assertEqual(phases, ["deploy", "services", "normal", "open", "download", "undeploy"])
        red = self.started(mgr, "attacker", "red_console.py")
        self.assertIn(f"--port 8090 --token {args.red_token}", red)
        # The console is handed the attack tree as data and the target to reach;
        # it builds its executable steps in the lab (red_steps, tested in
        # tests/planes/test_attack_planner.py).
        self.assertIn("--target-url http://", red)
        self.assertIn("--engine-ip ", red)
        self.assertIn("--engine-port ", red)
        tree = json.loads(base64.b64decode(red.split("--tree-b64 ")[1].split()[0]))
        ids = set()

        def _walk(n):
            ids.add(n["id"])
            for c in n.get("children") or []:
                _walk(c)

        _walk(tree)
        self.assertLessEqual({"it_access", "it_exec", "pivot", "breaker_open"}, ids)
        teams = os.path.join(self.out, "teams.json")
        with open(teams) as f:
            self.assertEqual(sorted(json.load(f)), ["blue", "red"])
        self.assertEqual(os.stat(teams).st_mode & 0o777, 0o600, "the links are readable by others")
        # The links are the teams' secrets: nothing else the run leaves may hold them.
        for name in sorted(os.listdir(self.out)):
            path = os.path.join(self.out, name)
            if name == "teams.json" or not os.path.isfile(path):
                continue
            with open(path, errors="replace") as f:
                left = f.read()
            for secret in (args.blue_token, args.red_token):
                self.assertNotIn(
                    secret, left, f"{name} holds a team's token: whoever reads the run has it"
                )
        # What the red team did is the attack: the ground truth and the ledger have it.
        with open(os.path.join(self.out, "ground_truth.jsonl")) as f:
            gt = [json.loads(line) for line in f]
        kinds = [e["kind"] for e in gt]
        for kind in ("attack_start", "red_step", "modbus_write", "command"):
            self.assertIn(kind, kinds)
        write = next(e for e in gt if e["kind"] == "modbus_write")
        self.assertEqual((write["register_name"], write["t"]), ("switch_cmd", 50.1))
        ledger = {e["kind"]: e for e in col.events}
        self.assertEqual(ledger["red_step"]["step"], "breaker_open")
        self.assertEqual(ledger["attack_write"]["register_name"], "switch_cmd")
        typed_by = {(e["node"], e["team"]) for e in col.events if e["kind"] == "team_command"}
        self.assertIn(("attacker", "red"), typed_by)
        self.assertIn(("soc", "blue"), typed_by)
        self.assertIn(
            ("hmi", "red"),
            typed_by,
            "a shell got through the HMI's vulnerable app was not taken for the attacker's",
        )


class Mirror(unittest.TestCase):
    def test_suggestions_and_answers_reach_the_ledger(self):
        soc = SocAnalytics("soc", {}, policy="rules", approval="operator:60")
        asked = {
            "t": 10.0,
            "kind": "approval",
            "request": "r1",
            "action": "block_flow",
            "state": "requested",
            "due_t": 70.0,
            "requested_t": 10.0,
            "explanation": {"rationale": "because"},
        }
        kind, fields = soc.mirror(asked)
        self.assertEqual(kind, "approval")
        self.assertEqual(fields["explanation"], {"rationale": "because"})
        self.assertEqual(
            (fields["request"], fields["due_t"], fields["guest_t"]), ("r1", 70.0, 10.0)
        )
        answered = {"t": 14.0, "kind": "approval", "request": "r1", "action": "block_flow"}
        answered |= {"state": "granted", "operator": "ada", "waited_s": 4.0}
        _kind, fields = soc.mirror(answered)
        self.assertEqual(
            (fields["state"], fields["operator"], fields["waited_s"]), ("granted", "ada", 4.0)
        )

    def test_what_the_operator_did_by_hand_is_told_apart(self):
        soc = SocAnalytics("soc", {}, policy="rules")
        row = {"kind": "action", "id": "isolate_hmi", "ok": True, "machine": "hmi", "done_t": 5.0}
        self.assertEqual(soc.mirror(row)[1]["by"], "soc")
        _kind, fields = soc.mirror(row | {"op": "revert", "by": "ada"})
        self.assertEqual((fields["op"], fields["by"]), ("revert", "ada"))
        self.assertEqual(
            soc.mirror({"kind": "mode", "mode": "auto", "operator": "ada"})[0], "soc_mode"
        )

    def test_a_soc_that_decides_alone_serves_no_console(self):
        self.assertNotIn("--operator", SocAnalytics("soc", {}, policy="rules").command)


if __name__ == "__main__":
    unittest.main()
