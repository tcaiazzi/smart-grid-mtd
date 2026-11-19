"""feature.py — the tools of a real SOC, for the blue team of a CPS scenario.

Instead of the SOC's own console the blue team gets the open-source tools of a
real SOC, each deployed as its project deploys it, one service per node:

    SIEM             Wazuh indexer + dashboard; the manager's alerts shipped to
                     the indexer by Filebeat, as in a Wazuh server; the alerts
                     worth triage forwarded to IRIS by a Wazuh integration
    case management  DFIR-IRIS (web, app, worker, Postgres, RabbitMQ); the SOC
                     files each countermeasure it proposes as a task of the
                     run's case, which an analyst closes (approve) or cancels;
                     the SOC's own module adds IRIS menu entries to apply or
                     revert a countermeasure, and to switch the SOC's mode

The SOC's analytics, its policy and the lab it protects are unchanged: the new
nodes are the defence's tooling, not part of the lab's spec, so not of the
inventory the SOC reasons about. Every secret (the indexer's users, IRIS's keys
and passwords) is drawn per run and reaches the team only through teams.json.
"""

import ipaddress
import secrets

from cyberrange.core.topology import Iface, Node
from cyberrange.planes.defense import components as defense
from cyberrange.scenarios.cps import topology as T
from cyberrange.scenarios.cps.feature import Feature
from cyberrange.scenarios.cps_soc.guest_files import (
    DASHBOARD_FILES,
    INDEXER_FILES,
    IRIS_FILES,
    IRIS_MODULE_FILES,
    SOC_SIEM_FILES,
)

SOC_IMAGE = "kathara/soc-siem"
# The SOC's tooling network: IRIS's services talk to each other here, as on the
# backend network of IRIS's compose file; only its web front is also on the
# SOC's network.
SOAR = "SOAR"
SOAR_NET = "10.40.0.0/24"
# The tools' addresses on the SOC's network, by host number; a lab that puts a
# host of its own there fails when the tools are added.
INDEXER_HOST, DASHBOARD_HOST, IRIS_MGMT_HOST = 21, 22, 40
# The names the services are dialled by: the ones the lab's certificates carry
# (docker/wazuh-pki), so TLS checks the name and no address is baked into an
# image. Each node that dials one resolves it from its own /etc/hosts.
INDEXER_NAME, DASHBOARD_NAME = "wazuh.indexer", "wazuh.dashboard"
MANAGER_NAME, IRIS_NAME = "wazuh.manager", "iris.lab"
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
TEAM_LOGIN = "blue"  # the blue team's account on the indexer and on IRIS


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
    it on a command line, so it holds nothing the shell would read — and it
    starts with a letter, because one that starts with '-' is taken for an
    option by the argparse of the agent it is handed to."""
    return "Aa1" + secrets.token_urlsafe(18)


def names(spec):
    """Startup commands that let a node dial the SOC's services by name."""
    _zone, indexer, dashboard, iris = addresses(spec)
    known = {
        INDEXER_NAME: indexer,
        DASHBOARD_NAME: dashboard,
        MANAGER_NAME: spec.ip(spec.one("soc").name),
        IRIS_NAME: iris,
    }
    return [f"echo '{ip} {name}' >> /etc/hosts" for name, ip in known.items()]


def addresses(spec):
    """(zone, indexer, dashboard, IRIS's web front) on the SOC's network of
    ``spec``; fails on an address a host of the lab already has."""
    zone = spec.zone_of(spec.one("soc").name)
    net = ipaddress.ip_network(spec.zone(zone).cidr)
    tools = [str(net.network_address + n) for n in (INDEXER_HOST, DASHBOARD_HOST, IRIS_MGMT_HOST)]
    taken = {
        spec.address(n) for h in spec.hosts for n in h.nics if n.zone == zone and not n.passive
    }
    clash = sorted(set(tools) & taken)
    if clash:
        raise ValueError(f"the SOC's tools need {clash} on {zone}, which the lab already uses")
    return (zone, *tools)


class SocTools(Feature):
    """Wazuh's indexer and dashboard, and DFIR-IRIS, for the blue team."""

    # ── options ──────────────────────────────────────────────────────────────
    def add_arguments(self, ap):
        g = ap.add_argument_group("SOC tools")
        g.add_argument("--siem-port", type=int, default=8770, help="host port of Wazuh's dashboard")
        g.add_argument("--cases-port", type=int, default=8771, help="host port of DFIR-IRIS")

    def host_ports(self, args):
        return [args.siem_port, args.cases_port]

    def prepare(self, args):
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

    # ── the lab ──────────────────────────────────────────────────────────────
    def extras(self, spec, args):
        # The SOC's console gives way to the tools; the SOC carries Filebeat, and
        # dials the indexer and IRIS.
        return {
            spec.one("soc").name: T.Extra(
                files=SOC_SIEM_FILES, startup=names(spec), image=SOC_IMAGE
            )
        }

    def nodes(self, spec, args):
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

        zone, indexer, dashboard, iris = addresses(spec)
        prefix = ipaddress.ip_network(spec.zone(zone).cidr).prefixlen
        soc_ip = spec.ip(spec.one("soc").name)
        return [
            node(
                "indexer",
                [Iface(zone, f"{indexer}/{prefix}")],
                "siem",
                INDEXER_FILES,
                only_from("eth0", soc_ip, dashboard),
            ),
            node(
                "wazuhui",
                [Iface(zone, f"{dashboard}/{prefix}")],
                "siem",
                DASHBOARD_FILES,
                # Reached by the team on its published port only; it dials the
                # indexer, the manager's API and itself.
                only_from("eth0") + names(spec),
                port=f"{args.siem_port}:{DASHBOARD_PORT}/tcp",
            ),
            node(
                "irisweb",
                [Iface(SOAR, f"{IRIS_WEB_IP}/24"), Iface(zone, f"{iris}/{prefix}")],
                "case-management",
                IRIS_FILES,
                only_from("eth1", soc_ip),  # the SOC's desk files its tasks here
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
        s = getattr(args, "soc_secrets", None) or {}
        login = f"(login {TEAM_LOGIN} / {s.get('blue')})"
        return {
            "blue": {
                "siem": f"https://127.0.0.1:{args.siem_port}/  {login}",
                "attack tree": f"https://127.0.0.1:{args.siem_port}/{ATTACK_TREE_VIEW}",
                "cases": f"https://127.0.0.1:{args.cases_port}/  {login}",
            }
        }

    def operator_api(self, scenario, args):
        """The SOC files its suggestions in IRIS, as the team's account, and
        feeds its belief on the attack tree to the SIEM."""
        s = args.soc_secrets
        return dict(
            iris=dict(
                url=f"https://{IRIS_NAME}",
                key=s["iris_key"],
                ca="/pki/root-ca.pem",
                case=scenario.run_id(args),
                analyst=TEAM_LOGIN,
                analyst_password=s["blue"],
            ),
            belief_feed=BELIEF_FEED,
        )

    # ── the episode ──────────────────────────────────────────────────────────
    def services(self, ctx):
        s = ctx.args.soc_secrets
        soc = ctx.scenario.lab_spec(ctx.args).one("soc").name
        iris_url = f"https://{IRIS_NAME}"
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
        ctx.start(defense.AlertShipper(soc, s["indexer_shipper"]))
        # The alerts worth triage go to IRIS's Alerts page, for the analyst to
        # merge into the run's case, escalate or close.
        ctx.start(defense.IrisAlertForwarder(soc, iris_url, s["iris_key"]))
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
            "SERVER_NAME": IRIS_NAME,
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
