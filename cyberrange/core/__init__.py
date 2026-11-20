"""cyberrange.core — the platform core every scenario runs on.

A scenario is a composition of plane components (the attack, defense,
cyberrange.planes.traffic, monitor) on a declared topology. The core owns everything
that is not specific to one scenario:

    topology.py   declarative lab description -> Kathará Lab (+ lab.conf export)
    context.py    RunContext: the handle a scenario's episode drives the lab with
    component.py  Component / TelemetrySource / TelemetryCursor
    streams.py    the three event streams (ground truth, telemetry, progress)
    scenario.py   the Scenario contract + PhaseSpec
    lifecycle.py  run(scenario, args): deploy -> episode -> download -> undeploy
    campaign.py   units x steps, resume, retries, ledger, aggregate
    aggregate.py  mean / std / 95% CI per metric and group
    registry.py   name -> Scenario
    cli.py        the common command line of a scenario's single run

Host-side only: nothing here is copied into a container.
"""
