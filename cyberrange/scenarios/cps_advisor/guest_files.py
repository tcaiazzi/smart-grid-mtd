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

# Every node a team has a console on, when teams play: what the console serves
# a player that is not a browser — the seat's description, the briefing, a
# shell. red_console.py imports it; the SOC's console only when a team sits there.
SEAT_FILES = [("nodes/common/seat.py", "/seat.py")]

# Attacker node, when a red team plays: its console. The console builds the
# attack tree's steps in the lab (red_steps), the same registry (steps.py,
# tree_doc.py — staged on the attacker by the cps lab) the autonomous planner
# reads.
RED_FILES = [
    ("nodes/redteam/red_console.py", "/red_console.py"),
    ("nodes/redteam/red_console.html", "/red_console.html"),
    ("nodes/redteam/red_steps.py", "/red_steps.py"),
]

# A player's node, when a harness sits at a team's seat: the seat's MCP adapter,
# what every launcher shares, the scripted player, and the two scripts that
# close the node's firewall and start the harness as an unprivileged user.
PLAYER_FILES = [
    ("nodes/players/seat_mcp.py", "/seat_mcp.py"),
    ("nodes/players/harness_kit.py", "/harness_kit.py"),
    ("nodes/players/scripted_player.py", "/scripted_player.py"),
    ("nodes/players/player-run.sh", "/player-run.sh"),
    ("nodes/players/player-firewall.sh", "/player-firewall.sh"),
]

# The same node, for the claude-code harness: its launcher.
CLAUDE_PLAYER_FILES = [("nodes/players/claude_player.py", "/claude_player.py")]
