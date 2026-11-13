#!/usr/bin/env python3
"""belief_tree.py — turn what recon found into an attack tree the planner reads.

The attacker does not receive the defender's tree; it builds its own *belief*
from reconnaissance, in the same document shape the planner consumes
(``tree_doc``: id, gate, children, impact, feasible, attck). The structure is the
attacker's knowledge of the generic CPS pattern — exploit the web app, pivot
through the HMI, write the plant's registers — and recon only sets which parts
are ``feasible`` on this target and which impacts the discovered registers allow.

Copied flat onto the attacker node with recon.py and red_recon_agent.py (see the
scenario's guest_files.py). Stdlib only; reads the attacker's own vocabulary
(steps.py) and the plant contract (ot_registers.py), never the defender's code.
"""

import ot_registers as reg
import steps as S

AND, OR, LEAF = "AND", "OR", "LEAF"

# The attacker's prior knowledge of the prerequisite steps (ATT&CK ids it would
# attribute to each). Order follows steps.PREREQ_ORDER.
PREREQ_META = {
    "it_access": (
        "Initial access to the HMI web app",
        "T1190",
        "Exploit Public-Facing Application",
    ),
    "it_exec": ("Command execution on the HMI host", "T1059", "Command and Scripting Interpreter"),
    "pivot": ("Use the sanctioned HMI -> plant Modbus flow", None, None),
}

# The attacker's own catalogue of impacts: its *estimate* of each one's loss
# weight and the register that realises it (names/scales from the plant contract).
IMPACT_META = {
    "setpoint_oor": ("DG setpoint written outside its envelope", "T0855",
                     "Unauthorized Command Message", 0.6, reg.HR_DG_SETPOINT),
    "breaker_open": ("Feeder breaker opened remotely", "T0855",
                     "Unauthorized Command Message", 1.0, reg.HR_SWITCH_CMD),
    "mode_hijack": ("MANUAL authority taken, in-range unsafe dispatch", "T0831",
                    "Manipulation of Control", 0.9, reg.HR_CTRL_MODE),
}  # fmt: skip


def _node(node_id, label, gate=LEAF, children=None, attck=None, attck_name=None, impact=0.0,
          feasible=True, targets=None):  # fmt: skip
    return {
        "id": node_id,
        "label": label,
        "gate": gate,
        "attck": attck,
        "attck_name": attck_name,
        "targets": targets or [],
        "impact": impact,
        "feasible": feasible,
        "children": children or [],
    }


def build(findings):
    """Assemble the belief attack tree from recon ``findings``:

        {"foothold": {"ip","port"} | None,   # an HTTP host found on the IT scan
         "ot": {"engine_ip","modbus_ok","registers": {addr: raw}} | {}}

    Returns the ``attack_tree`` document (root ``via_hmi``). Feasibility is set by
    what recon confirmed; an impact is included only for a register the attacker
    has reason to believe exists (discovered, or — the engine answering Modbus —
    assumed from the known plant contract)."""
    foothold = bool(findings.get("foothold"))
    ot = findings.get("ot") or {}
    pivot_ok = bool(ot.get("engine_ip"))
    discovered = set((ot.get("registers") or {}).keys())
    # The engine answered Modbus but the read did not enumerate: fall back to the
    # known plant contract (the attacker has ot_registers), so impacts aren't lost.
    if ot.get("modbus_ok") and not discovered:
        discovered = set(reg.ACTUATOR_REGISTERS)

    prereqs = []
    for node_id in S.PREREQ_ORDER:
        label, attck, attck_name = PREREQ_META[node_id]
        feasible = foothold if node_id in ("it_access", "it_exec") else pivot_ok
        prereqs.append(_node(node_id, label, attck=attck, attck_name=attck_name, feasible=feasible))

    impacts = []
    for node_id in S.IMPACT_MODE:
        label, attck, attck_name, impact, register = IMPACT_META[node_id]
        impacts.append(
            _node(
                node_id,
                label,
                attck=attck,
                attck_name=attck_name,
                impact=impact,
                feasible=pivot_ok and register in discovered,
                targets=[f"reg:hr:{register}"],
            )
        )

    ot_action = _node("ot_action", "Manipulate the plant over Modbus", OR, children=impacts)
    return _node(
        "via_hmi",
        "Through the HMI (the only host allowed across the boundary)",
        AND,
        children=prereqs + [ot_action],
    )
