"""SOAR prototype for the cyber-physical (OT/Modbus) scenario — host-side only.

The data -> detection -> response chain on one small, fully observable case:

    kg.py       knowledge graph of the lab (hosts, zones, addresses, services,
                registers, boundary rules), built from the Kathará Lab model
    trees.py    attack tree of the CPS chain + countermeasures (defense tree)
    mapping.py  sensor findings -> attack-tree nodes -> campaign state (belief)
    policy.py   response policies: fixed rules (baseline) and a small solver

Nothing here runs on a guest, so networkx is allowed (it is not on the flat
guest import contract). The runtime loop lives in network_scenario.cps_responder.
"""
