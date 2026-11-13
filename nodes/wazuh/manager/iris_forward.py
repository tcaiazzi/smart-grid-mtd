#!/usr/bin/env python3
"""iris_forward.py — the Wazuh manager's integration with DFIR-IRIS: the alerts
worth an analyst's look become IRIS alerts, for the blue team to triage.

Installed as /var/ossec/integrations/custom-iris.py (wazuh-iris-integration.sh)
and run by the manager's integrator once per matching alert, as Wazuh's own
integrations are (Shuffle, Slack): ``custom-iris.py <alert file> <api key>
<IRIS URL>``, with Wazuh's embedded Python.

What is forwarded is what a tuned SOC would put in front of a person, not every
finding:

- the OT sensor's alerts as they open (rule 100101, state "raised"): one per
  episode, where the findings behind it are one per packet;
- every finding of the IT sensor on the HMI (rule 100100, detector "it"): rare,
  and each one a step of an intrusion.

The findings themselves stay searchable in Wazuh's dashboard. Each IRIS alert
carries the host that reported it (an asset) and the source address seen (an
IOC); the analyst merges it into the run's case, escalates it or closes it.

Repeats are aggregated, as a SIEM does: the same host, rule, class and source
within AGGREGATE_S do not open another alert, they update the open one's note
("seen N times"). An attacker's eight Modbus connections are one alert to
triage, not eight. Not done in Wazuh's rules: the SOC's analytics reads every
finding, and must keep doing so.

Copied flat onto the SOC node of the cps-soc lab. Stdlib only.
"""

import fcntl
import json
import ssl
import sys
import time
import urllib.error
import urllib.request

LOG = "/var/ossec/logs/integrations.log"
STATE = "/var/ossec/logs/custom-iris.state"  # open IRIS alerts, for aggregation
AGGREGATE_S = 120.0
CAFILE = "/pki/root-ca.pem"  # the lab's authority (docker/wazuh-pki)
FINDING, SENSOR_ALERT = "100100", "100101"
TAGS = ["wazuh", "cps-soc"]


def should_forward(alert):
    """Whether this Wazuh alert is one an analyst should triage in IRIS."""
    rule = str((alert.get("rule") or {}).get("id"))
    data = alert.get("data") or {}
    if rule == SENSOR_ALERT:
        return data.get("state") == "raised"
    if rule == FINDING:
        return data.get("detector") == "it"
    return False


def key_of(alert):
    """What makes two alerts the same thing to triage."""
    data = alert.get("data") or {}
    entities = data.get("entities") or {}
    return "|".join(
        str(x)
        for x in (
            (alert.get("agent") or {}).get("name"),
            (alert.get("rule") or {}).get("id"),
            data.get("klass"),
            entities.get("src"),
        )
    )


def aggregate(state, key, now, window=AGGREGATE_S):
    """The open IRIS alert ``key`` repeats, as (alert id, times seen), or None
    when it opens a new one. ``state`` is {key: {"alert_id", "n", "t"}}; entries
    older than ``window`` are forgotten."""
    for k in [k for k, v in state.items() if now - v["t"] > window]:
        del state[k]
    seen = state.get(key)
    if seen is None:
        return None
    seen["n"] += 1
    seen["t"] = now
    return seen["alert_id"], seen["n"]


def severity_of(alert):
    """IRIS severity, by name: an intrusion step on IT is High, an OT alert
    that opens Medium, unless the sensor itself is certain."""
    data = alert.get("data") or {}
    if data.get("detector") == "it":
        return "High"
    try:
        confidence = float(data.get("confidence") or 0)
    except ValueError:
        confidence = 0.0
    return "High" if confidence >= 0.9 else "Medium"


def to_iris(alert, ids):
    """The IRIS alert for a Wazuh ``alert``. ``ids`` maps the names of IRIS's
    reference values to their ids: {"severity": {...}, "status": {...},
    "ioc_type": {...}, "asset_type": {...}, "tlp": {...}}."""
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    entities = data.get("entities") or {}
    klass = data.get("klass") or "unknown"
    detector = data.get("detector") or "rules"
    src = entities.get("src")
    host = agent.get("name") or "manager"
    what = rule.get("description", "Wazuh alert")
    lines = [
        f"{what} (rule {rule.get('id')}, level {rule.get('level')})",
        f"Reported by: {host}" + (f" ({agent['ip']})" if agent.get("ip") else ""),
        f"Detector: {detector}; class: {klass}",
    ]
    if src:
        lines.append(f"Source seen: {src}")
    if entities.get("name") or entities.get("register") is not None:
        lines.append(f"Register: {entities.get('name') or entities.get('register')}")
    if data.get("maps_to"):
        lines.append(f"Attack step it points to: {data['maps_to']}")
    lines += ["", "Triage: merge it into the run's case, escalate it, or close it."]
    out = {
        "alert_title": f"[{host}] {rule.get('description') or klass}",
        "alert_description": "\n".join(lines),
        "alert_source": "Wazuh",
        "alert_source_ref": str(alert.get("id") or ""),
        "alert_source_content": alert,
        "alert_severity_id": ids["severity"][severity_of(alert)],
        "alert_status_id": ids["status"]["New"],
        "alert_customer_id": 1,  # the customer IRIS creates at its first start
        "alert_tags": ",".join(TAGS + [detector, klass]),
        "alert_assets": [],
        "alert_iocs": [],
    }
    if alert.get("timestamp"):
        # Wazuh's "2026-11-13T20:10:20.268+0000"; IRIS wants it without the offset.
        out["alert_source_event_time"] = alert["timestamp"][:23]
    if agent.get("ip") and "Linux - Server" in ids["asset_type"]:
        out["alert_assets"].append(
            {
                "asset_name": host,
                "asset_ip": agent["ip"],
                "asset_type_id": ids["asset_type"]["Linux - Server"],
                "asset_description": "Wazuh agent that reported the alert",
            }
        )
    if src and "ip-src" in ids["ioc_type"]:
        out["alert_iocs"].append(
            {
                "ioc_value": src,
                "ioc_type_id": ids["ioc_type"]["ip-src"],
                "ioc_tlp_id": ids["tlp"].get("amber", 2),
                "ioc_description": f"Source of the {klass} the {detector} detector saw",
                "ioc_tags": ",".join(TAGS),
            }
        )
    return out


class Iris:
    def __init__(self, url, key, cafile=CAFILE, timeout=20.0):
        self.url, self.key, self.timeout = url.rstrip("/"), key, timeout
        self.context = ssl.create_default_context(cafile=cafile)
        self.context.check_hostname = False  # the lab's certificates name addresses

    def call(self, method, path, body=None):
        req = urllib.request.Request(
            self.url + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"},
            method=method,
        )
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.context) as r:
            doc = json.load(r)
        if doc.get("status") != "success":
            raise RuntimeError(f"{method} {path}: {doc.get('message')}")
        return doc.get("data")

    def ids(self):
        """IRIS's reference values, by name."""

        def by(path, name, key):
            return {row[name]: row[key] for row in self.call("GET", path)}

        return {
            "severity": by("/manage/severities/list", "severity_name", "severity_id"),
            "status": by("/manage/alert-status/list", "status_name", "status_id"),
            "ioc_type": by("/manage/ioc-types/list", "type_name", "type_id"),
            "asset_type": by("/manage/asset-type/list", "asset_name", "asset_id"),
            "tlp": by("/manage/tlp/list", "tlp_name", "tlp_id"),
        }


def log(msg):
    try:
        with open(LOG, "a") as f:
            f.write(f"custom-iris: {msg}\n")
    except OSError:
        pass


def main(argv, state_path=STATE, clock=time.time):
    if len(argv) < 4:
        log(f"bad arguments: {argv[1:]}")
        return 2
    alert_file, key, url = argv[1], argv[2], argv[3]
    with open(alert_file) as f:
        alert = json.load(f)
    if not should_forward(alert):
        return 0
    rule = (alert.get("rule") or {}).get("id")
    try:
        iris = Iris(url, key)
        # The integrator may run several of these at once: one at a time here,
        # or two repeats would both open an alert.
        with open(state_path, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            try:
                state = json.loads(f.read() or "{}")
            except ValueError:
                state = {}
            k, now = key_of(alert), clock()
            repeat = aggregate(state, k, now)
            if repeat:
                alert_id, n = repeat
                note = f"Seen {n} times; last at {alert.get('timestamp', '?')}."
                iris.call("POST", f"/alerts/update/{alert_id}", {"alert_note": note})
                log(f"rule {rule} -> IRIS alert {alert_id} (seen {n} times)")
            else:
                created = iris.call("POST", "/alerts/add", to_iris(alert, iris.ids()))
                state[k] = {"alert_id": created.get("alert_id"), "n": 1, "t": now}
                log(f"rule {rule} -> IRIS alert {created.get('alert_id')}")
            f.seek(0)
            f.truncate()
            f.write(json.dumps(state))
    except (OSError, RuntimeError, KeyError, ValueError, urllib.error.URLError) as e:
        log(f"rule {rule} not forwarded: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
