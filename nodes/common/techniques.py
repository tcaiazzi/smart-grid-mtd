#!/usr/bin/env python3
"""techniques.py — the steps an attack on a CPS lab is made of, as data.

The attack tree is not written per lab: attack_graph.py instantiates these
steps on the knowledge graph, once per way in and per feeder, and the steps say
what each one is (label, ATT&CK technique, impact weight, whether the OT sensor
can see it) and, for an action on the plant, which registers it writes. A new
kind of impact is one entry here, not a new branch in code.

Copied flat onto the SOC node and onto the attacker (see the scenarios'
guest_files.py); stdlib only.
"""

# ── the ways in ──────────────────────────────────────────────────────────────
# Through a host whose role may command the plant and that serves an
# application: access to it, execution on it, then its own sanctioned flow.
ACCESS_STEPS = (
    dict(
        kind="it_access",
        label="Initial access to the {who}'s web application",
        attck="T1190",
        attck_name="Exploit Public-Facing Application",
        observable=False,
    ),
    dict(
        kind="it_exec",
        label="Command execution on the {who} host",
        attck="T1059",
        attck_name="Command and Scripting Interpreter",
        observable=False,
    ),
    dict(
        kind="pivot",
        label="Use the sanctioned {who} -> plant Modbus flow",
        observable=False,
        review="ATT&CK id to be chosen (lateral movement over a trusted flow)",
    ),
)
VIA = dict(kind="via", label="Through the {who} (the only host allowed across the boundary)")
OT_ACTION = dict(kind="ot_action", label="Manipulate the plant over Modbus")

# From a host without a Modbus role that stands on the plant's link.
DIRECT = dict(kind="direct_ot", label="From a host without a Modbus role")
FOOTHOLD = dict(
    kind="ot_foothold",
    label="Foothold on a host that reaches the plant",
    attck="T0886",
    attck_name="Remote Services",
    observable=False,
    review="T0859 (Valid Accounts) also plausible: the way in is a credential",
)
DIRECT_ACTION = dict(kind="ot_direct_action", label="Act on the plant from that host")
WRITE_UNKNOWN = dict(
    kind="ot_write_unknown",
    label="Unauthorized Modbus access from that host",
    attck="T0855",
    attck_name="Unauthorized Command Message",
    impact=0.6,
)
VIA_AITM = dict(kind="via_aitm", label="Between the PLC and the plant")
AITM = dict(
    kind="ot_aitm",
    label="Adversary in the middle of the PLC's Modbus session",
    attck="T0830",
    attck_name="Adversary-in-the-Middle",
)
FDI = dict(
    kind="meas_fdi",
    label="Measurements falsified on their way to the PLC",
    attck="T0856",
    attck_name="Spoof Reporting Message",
    impact=0.9,
    reads=("v_load", "v_dg"),  # the input registers whose readings are forged
)
ROOT = dict(kind="impact", label="Physical impact on the feeder")

# ── what an attacker who talks Modbus to the plant can do ────────────────────
# ``writes``: the holding registers (by name) the action writes; it exists for a
# feeder whose registers include them.
IMPACTS = (
    dict(
        kind="setpoint_oor",
        label="DG setpoint written outside its envelope",
        attck="T0855",
        attck_name="Unauthorized Command Message",
        writes=("dg_setpoint",),
        impact=0.6,
    ),
    dict(
        kind="breaker_open",
        label="Feeder breaker opened remotely",
        attck="T0855",
        attck_name="Unauthorized Command Message",
        writes=("switch_cmd",),
        impact=1.0,
        review="T0813 (Denial of Control) / T0831 also plausible",
    ),
    dict(
        kind="mode_hijack",
        label="MANUAL authority taken, in-range unsafe dispatch",
        attck="T0831",
        attck_name="Manipulation of Control",
        writes=("ctrl_mode", "dg_setpoint"),
        impact=0.9,
    ),
    dict(
        kind="setpoint_ramp",
        label="MANUAL authority taken, DG setpoint ramped up in small steps",
        attck="T0831",
        attck_name="Manipulation of Control",
        writes=("ctrl_mode", "dg_setpoint"),
        impact=0.8,
    ),
    dict(
        kind="setpoint_oscillation",
        label="MANUAL authority taken, DG setpoint swung between levels",
        attck="T0831",
        attck_name="Manipulation of Control",
        writes=("ctrl_mode", "dg_setpoint"),
        impact=0.7,
    ),
    dict(
        kind="breaker_chatter",
        label="Feeder breaker opened and re-closed repeatedly",
        attck="T0855",
        attck_name="Unauthorized Command Message",
        writes=("switch_cmd",),
        impact=0.85,
    ),
)
IMPACT_KINDS = tuple(t["kind"] for t in IMPACTS)

# ── how the people of the lab call a host, by role ───────────────────────────
ROLE_LABEL = {"hmi": "HMI", "engineering": "engineering workstation", "plc": "PLC"}

# ── what the responses put back ──────────────────────────────────────────────
# The impact kinds each restoring response undoes (in this order).
RESTORES = {
    "force_auto": ("mode_hijack", "setpoint_oor", "setpoint_ramp", "setpoint_oscillation"),
    "restore_breaker": ("breaker_open", "breaker_chatter"),
    "repair_arp": ("ot_aitm", "meas_fdi"),
}
# The process an access service runs as on its host: what killing the foothold
# means. The knowledge graph knows services, not their processes.
ACCESS_PROCESS = "vuln_app.py"
# Hosts whose isolation takes a person's console away: it needs their approval.
OPERATOR_ROLES = ("hmi",)
