"""guest_files.py — what the cps-advisor scenario stages on top of the cps lab.

The lab itself is the cps scenario's and so are its manifests
(cyberrange/scenarios/cps/guest_files.py), which already carry the SOC's
analytics and its console's server. Listed here is only what putting people in
the lab adds: the console pages, the red team's console, and the scripts that
give a team its shells and keep what is typed in them.
"""

# Every host a team gets a shell on: the web terminal or SSH, and the record of
# the commands typed there.
TEAM_FILES = [
    ("nodes/common/team-access.sh", "/team-access.sh"),
    ("nodes/common/command_audit.sh", "/command_audit.sh"),
]

# SOC node: the page of the operator console that soc_operator.py serves.
SOC_CONSOLE_FILES = [("nodes/soc/soc_console.html", "/soc_console.html")]

# Attacker node, when a red team plays: its console.
RED_FILES = [
    ("nodes/redteam/red_console.py", "/red_console.py"),
    ("nodes/redteam/red_console.html", "/red_console.html"),
]
