"""Monitoring plane: the components that observe a running lab.

Capture, TelemetryMirror and PlantMirror only ever read — they never write
into a container, and a failed pull never breaks a run. The progress ledger
and the dashboard that reads it are platform core (cyberrange/core), not this
plane: every scenario gets them for free.
"""
