"""The four planes: reusable building blocks a scenario composes.

Each plane exposes its components in ``components.py`` (the contract the core
runs), its guest code under ``agents/`` (flat modules copied into containers),
and its host-side domain logic beside them. A plane never imports a scenario:
that is what keeps it reusable.
"""
