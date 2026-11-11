"""Tree-guided attacker for validating the CPS defences (host-side).

Instead of a scripted sequence, an AttackPlanner (planner.py) walks the attack
tree (cyberrange/planes/defense/soar/trees.py) and picks the next step from the current
state, composing the SAME lab primitives the scripted driver uses (steps.py maps
each tree node to an exploit_client.py step). It learns by outcome: when a step
fails — e.g. the responder blocked the pivot flow — it tries an alternative or
gives up, so it exercises the defence like a reactive adversary would.

This is a decision layer over existing, lab-only primitives for purple-team
evaluation; it adds no new offensive capability. It is also the baseline
adversary of the WP3 stochastic game.
"""
