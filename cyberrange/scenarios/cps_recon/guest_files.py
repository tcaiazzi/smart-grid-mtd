"""guest_files.py — what the cps-recon scenario stages on top of the cps lab.

The lab itself is the cps scenario's and so are its manifests
(cyberrange/scenarios/cps/guest_files.py), which already stage the exploit chain,
the planner and the register map on the attacker node. Listed here is only what
the recon-driven attacker adds: the scanner, the belief-tree builder, the tree
generator it builds on, and the agent that orchestrates them. They ride on the
kathara/redteam image (nmap, networkx).
"""

# Attacker node (kathara/redteam): reconnaissance + the agent that derives the
# attack tree from it. exploit_client/ot_registers/planner/steps/tree_doc/red_agent
# come from the cps lab's ATTACKER_CPS_FILES, reused here.
RECON_FILES = [
    ("nodes/redteam/recon.py", "/recon.py"),
    ("nodes/redteam/belief_tree.py", "/belief_tree.py"),
    ("nodes/redteam/red_recon_agent.py", "/red_recon_agent.py"),
    # The SOC's own tree generator, on what recon found: one way of deriving
    # an attack tree, two views of the lab.
    ("nodes/common/soar_kg.py", "/soar_kg.py"),
    ("nodes/common/soar_trees.py", "/soar_trees.py"),
    ("nodes/common/techniques.py", "/techniques.py"),
    ("nodes/common/attack_graph.py", "/attack_graph.py"),
]
