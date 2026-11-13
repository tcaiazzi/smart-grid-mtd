"""scenario.py — the cps-advisor scenario with a real SOC's tools.

The same lab, episode and people as cyberrange/scenarios/cps_advisor: a SOC that
advises, an operator who decides, and with --teams a red team against a blue
team. What changes is what the blue team works on. Instead of the SOC's own
console it gets the open-source tools of a real SOC, each deployed as its
project deploys it, one service per node:

    SIEM             Wazuh indexer + dashboard; the manager's alerts shipped to
                     the indexer by Filebeat, as in a Wazuh server; the alerts
                     worth triage forwarded to IRIS by a Wazuh integration
    case management  DFIR-IRIS (web, app, worker, Postgres, RabbitMQ); the SOC
                     files each countermeasure it proposes as a task of the
                     run's case, which an analyst closes (approve) or cancels;
                     the SOC's own module adds IRIS menu entries to apply or
                     revert a countermeasure, and to switch the SOC's mode

The SOC's analytics, its policy and the lab it protects are unchanged: the new
nodes are the defence's tooling, not part of the inventory the SOC reasons
about. Every secret (the indexer's users, IRIS's keys and passwords) is drawn
per run and reaches the team only through teams.json.

Why a scenario of its own: its lab adds seven nodes and some 3 GB of memory,
which no cps or cps-advisor run should pay for.
"""

import logging
import os
import secrets

from cyberrange.core.topology import Iface, Node
from cyberrange.planes.defense import components as defense
from cyberrange.scenarios.cps import topology as T
from cyberrange.scenarios.cps_advisor.guest_files import RED_FILES, TEAM_FILES
from cyberrange.scenarios.cps_advisor.scenario import BLUE, MANAGED, CpsAdvisorScenario
from cyberrange.scenarios.cps_soc.guest_files import (
    DASHBOARD_FILES,
    INDEXER_FILES,
    IRIS_FILES,
    IRIS_MODULE_FILES,
    SOC_SIEM_FILES,
)

log = logging.getLogger("scenarios.cps_soc")

LAB_NAME = "cps-soc"
SOC_IMAGE = "kathara/soc-siem"
# The SOC's tooling network: IRIS's services talk to each other here, as on the
# backend network of IRIS's compose file; only its web front is also on MGMT.
SOAR = "SOAR"
SOAR_NET = "10.40.0.0/24"
INDEXER_IP, DASHBOARD_IP, IRIS_MGMT_IP = "10.30.0.21", "10.30.0.22", "10.30.0.40"
IRIS_WEB_IP, IRIS_APP_IP, IRIS_WORKER_IP = "10.40.0.1", "10.40.0.10", "10.40.0.11"
IRIS_DB_IP, IRIS_MQ_IP = "10.40.0.20", "10.40.0.30"
# Images: the services' own, pinned, with a thin layer where a lab node needs one
# (docker/wazuh-*, docker/iris-*); IRIS's database and broker run unmodified.
IMAGES = {
    "indexer": "kathara/wazuh-indexer",
    "wazuhui": "kathara/wazuh-dashboard",
    "irisweb": "kathara/iris-web",
    "irisapp": "kathara/iris-app",
    "irisworker": "kathara/iris-app",
    "irisdb": "ghcr.io/dfir-iris/iriswebapp_db:v2.4.29",
    "irismq": "rabbitmq:3.13.7-management-alpine",
}
# A service image's own entrypoint would start it as the container comes up,
# before the lab has addressed and configured it: the node idles on a shell and
# its component starts the service.
IDLE = "/bin/sh"
DASHBOARD_PORT, IRIS_PORT = 5601, 443
# The attack tree in the SIEM: the SOC's analytics feeds its belief to the
# manager and keeps what it delivered in this file; the dashboard with this id
# (nodes/wazuh/dashboard/dashboard_objects.py) draws the tree from the alerts.
BELIEF_FEED = "/soc_belief.jsonl"
ATTACK_TREE_VIEW = "app/dashboards#/view/cps-attack-tree"
TEAM_LOGIN = BLUE  # the blue team's account on the indexer and on IRIS


def only_from(iface, *sources):
    """Inbound on ``iface`` from ``sources`` only (and the replies to what the
    node itself opened). The HMI, the attacker's foothold, is on MGMT: without
    these rules it could reach the SIEM and the case management directly."""
    rules = [f"iptables -A INPUT -i {iface} -m state --state ESTABLISHED,RELATED -j ACCEPT"]
    rules += [f"iptables -A INPUT -i {iface} -s {s} -j ACCEPT" for s in sources]
    return rules + [f"iptables -A INPUT -i {iface} -j DROP"]


def password():
    """A fresh password that every service here accepts: IRIS asks for 12
    characters with upper and lower case and a digit, and the platform passes
    it on a command line, so it holds nothing the shell would read."""
    return secrets.token_urlsafe(18) + "Aa1"


class CpsSocScenario(CpsAdvisorScenario):
    name = "cps-soc"
    lab_name = LAB_NAME
    DEFAULT_OUT_DIR = "output/cps-soc/run-1"

    def add_arguments(self, ap):
        super().add_arguments(ap)
        g = ap.add_argument_group("cps-soc tools")
        g.add_argument("--siem-port", type=int, default=8770, help="host port of Wazuh's dashboard")
        g.add_argument("--cases-port", type=int, default=8771, help="host port of DFIR-IRIS")

    def validate(self, args):
        super().validate(args)
        ports = [args.siem_port, args.cases_port, args.blue_shell_port]
        if args.teams:
            ports += [args.red_port, args.red_shell_port]
        if len(set(ports)) != len(ports):
            raise SystemExit(f"the tools' host ports must differ from the teams', got {ports}")

    def prepare(self, args):
        super().prepare(args)
        # Drawn per run, like the teams' tokens; never on the ledger.
        args.soc_secrets = {
            "indexer_admin": password(),
            "indexer_shipper": password(),
            "indexer_dashboard": password(),
            "blue": password(),
            "postgres": password(),
            "postgres_admin": password(),
            "iris_secret": secrets.token_hex(32),
            "iris_salt": secrets.token_hex(16),
            "iris_admin": password(),
            "iris_key": secrets.token_hex(32),
        }

    # ── the lab: the cps one, the people's access, and the SOC's tools ───────
    def topology(self, args):
        def published(*pairs):
            return [f"{host}:{guest}/tcp" for host, guest in pairs]

        served = (T.TERMINAL_GUEST_PORT,)
        extras = {name: T.Extra(files=TEAM_FILES) for name in MANAGED}
        # The SOC keeps its shell for the blue team; its console gives way to
        # the tools below.
        extras["soc"] = T.Extra(
            files=SOC_SIEM_FILES + TEAM_FILES,
            ports=published((args.blue_shell_port, T.TERMINAL_GUEST_PORT)),
            startup=T.closed_on("eth0", *served),  # MGMT, where the HMI is
            image=SOC_IMAGE,
        )
        if getattr(args, "teams", False):
            extras["attacker"] = T.Extra(
                files=RED_FILES + TEAM_FILES,
                ports=published(
                    (args.red_port, T.CONSOLE_GUEST_PORT),
                    (args.red_shell_port, T.TERMINAL_GUEST_PORT),
                ),
                startup=T.closed_on("eth0", T.CONSOLE_GUEST_PORT, T.TERMINAL_GUEST_PORT),
            )
        topo = T.topology(args, name=self.lab_name, extras=extras)
        topo.nodes += self._tool_nodes(args)
        return topo

    def _tool_nodes(self, args):
        def node(name, ifaces, role, files, startup=(), port=None):
            return Node(
                name,
                ifaces,
                image=IMAGES[name],
                role=role,
                files=files,
                startup=list(startup),
                mgmt_port=port,
                entrypoint=IDLE,
            )

        mgmt = T.MGMT
        return [
            node(
                "indexer",
                [Iface(mgmt, f"{INDEXER_IP}/24")],
                "siem",
                INDEXER_FILES,
                only_from("eth0", T.SOC_IP, DASHBOARD_IP),
            ),
            node(
                "wazuhui",
                [Iface(mgmt, f"{DASHBOARD_IP}/24")],
                "siem",
                DASHBOARD_FILES,
                only_from("eth0"),  # reached by the team on its published port only
                port=f"{args.siem_port}:{DASHBOARD_PORT}/tcp",
            ),
            node(
                "irisweb",
                [Iface(SOAR, f"{IRIS_WEB_IP}/24"), Iface(mgmt, f"{IRIS_MGMT_IP}/24")],
                "case-management",
                IRIS_FILES,
                only_from("eth1", T.SOC_IP),  # MGMT: the SOC's desk files its tasks here
                port=f"{args.cases_port}:{IRIS_PORT}/tcp",
            ),
            # The app and the worker load IRIS's modules, the SOC's among them.
            node(
                "irisapp",
                [Iface(SOAR, f"{IRIS_APP_IP}/24")],
                "case-management",
                IRIS_FILES + IRIS_MODULE_FILES,
            ),
            node(
                "irisworker",
                [Iface(SOAR, f"{IRIS_WORKER_IP}/24")],
                "case-management",
                IRIS_FILES + IRIS_MODULE_FILES,
            ),
            node("irisdb", [Iface(SOAR, f"{IRIS_DB_IP}/24")], "case-management", IRIS_FILES),
            node("irismq", [Iface(SOAR, f"{IRIS_MQ_IP}/24")], "case-management", IRIS_FILES),
        ]

    # ── where the blue team goes ─────────────────────────────────────────────
    def links(self, args):
        out = super().links(args)
        blue = dict(out[BLUE])
        blue.pop("console", None)  # the suggestions are in IRIS
        s = getattr(args, "soc_secrets", None) or {}
        blue["siem"] = (
            f"https://127.0.0.1:{args.siem_port}/  (login {TEAM_LOGIN} / {s.get('blue')})"
        )
        blue["attack tree"] = f"https://127.0.0.1:{args.siem_port}/{ATTACK_TREE_VIEW}"
        blue["cases"] = (
            f"https://127.0.0.1:{args.cases_port}/  (login {TEAM_LOGIN} / {s.get('blue')})"
        )
        out[BLUE] = blue
        return out

    def operator_api(self, args):
        """The SOC files its suggestions in IRIS, as the team's account, and
        feeds its belief on the attack tree to the SIEM."""
        s = args.soc_secrets
        return dict(
            iris=dict(
                url=f"https://{IRIS_MGMT_IP}",
                key=s["iris_key"],
                ca="/pki/root-ca.pem",
                case=self.run_id(args),
                analyst=TEAM_LOGIN,
                analyst_password=s["blue"],
            ),
            belief_feed=BELIEF_FEED,
        )

    # ── the episode: the advisor's, with the SOC's tools started first ──────
    def extra_services(self, ctx):
        s = ctx.args.soc_secrets
        ctx.start(
            defense.WazuhIndexer(
                "indexer",
                {
                    "admin": s["indexer_admin"],
                    "shipper": s["indexer_shipper"],
                    "kibanaserver": s["indexer_dashboard"],
                    "blue": s["blue"],
                },
            )
        )
        ctx.start(defense.AlertShipper("soc", s["indexer_shipper"]))
        # The alerts worth triage go to IRIS's Alerts page, for the analyst to
        # merge into the run's case, escalate or close.
        ctx.start(defense.IrisAlertForwarder("soc", f"https://{IRIS_MGMT_IP}", s["iris_key"]))
        ctx.start(defense.WazuhDashboard("wazuhui", s["indexer_dashboard"]))
        db = {
            "POSTGRES_USER": "postgres",
            "POSTGRES_PASSWORD": s["postgres"],
            "POSTGRES_ADMIN_USER": "raptor",
            "POSTGRES_ADMIN_PASSWORD": s["postgres_admin"],
            "POSTGRES_DB": "iris_db",
        }
        app = db | {
            "POSTGRES_SERVER": IRIS_DB_IP,
            "POSTGRES_PORT": "5432",
            "DOCKERIZED": "1",
            "IRIS_SECRET_KEY": s["iris_secret"],
            "IRIS_SECURITY_PASSWORD_SALT": s["iris_salt"],
            "CELERY_BROKER": f"amqp://{IRIS_MQ_IP}",
            "IRIS_AUTHENTICATION_TYPE": "local",
            "IRIS_ADM_USERNAME": "administrator",
            "IRIS_ADM_PASSWORD": s["iris_admin"],
            "IRIS_ADM_API_KEY": s["iris_key"],
            # Where IRIS finds the SOC response module (IRIS_MODULE_FILES).
            "PYTHONPATH": "/iris_modules",
        }
        web = {
            "IRIS_UPSTREAM_SERVER": IRIS_APP_IP,
            "IRIS_UPSTREAM_PORT": "8000",
            "INTERFACE_HTTPS_PORT": str(IRIS_PORT),
            "SERVER_NAME": "iris.lab",
            "CERT_FILENAME": "iris_lab_cert.pem",
            "KEY_FILENAME": "iris_lab_key.pem",
            "IRIS_AUTHENTICATION_TYPE": "local",
        }
        services = [
            ("irisdb", "db", db),
            ("irismq", "mq", {}),
            ("irisapp", "app", app),
            ("irisworker", "worker", app | {"IRIS_WORKER": "1"} | web),
            ("irisweb", "web", web),
        ]
        for node, role, env in services:
            ctx.start(defense.IrisService(node, role, env))
        super().extra_services(ctx)

    def panel_js(self):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.js")
