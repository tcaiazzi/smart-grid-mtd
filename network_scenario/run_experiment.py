"""run_experiment.py — command line of one MQTT smart-grid scenario run.

The scenario itself lives in network_scenario/scenarios/mqtt_mtd (topology +
episode); the run lifecycle in network_scenario/core. The Makefile drives the
three modes (dataset capture, attack, idle) through this entry point.

Run:
    python -m network_scenario.run_experiment --generate-dataset 300 --name train \
        --datasets-dir output/<slug>/datasets [--no-mtd] [--seed 1]
    python -m network_scenario.run_experiment --attack 120 --post-attack 15 \
        --results-dir output/<slug>/attack/model-baseline --model ... --scaler ...
"""

from network_scenario.core import cli, lifecycle
from network_scenario.scenarios.mqtt_mtd.scenario import MqttMtdScenario


def run(args, progress=None, manager=None):
    """One MQTT run (see core.lifecycle.run); returns the exit code."""
    return lifecycle.run(MqttMtdScenario(), args, progress=progress, manager=manager)


def main(argv=None):
    cli.main(MqttMtdScenario(), argv, description="Smart-grid MTD experiment (MQTT scenario)")


if __name__ == "__main__":
    main()
