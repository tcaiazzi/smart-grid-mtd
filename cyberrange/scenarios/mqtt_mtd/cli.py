"""cli.py — command line of one MQTT smart-grid scenario run.

The scenario itself lives in cyberrange/scenarios/mqtt_mtd (topology +
episode); the run lifecycle in cyberrange/core. The Makefile drives the
three modes (dataset capture, attack, idle) through this entry point.

Run:
    python -m cyberrange.scenarios.mqtt_mtd.cli --generate-dataset 300 --name train \
        --datasets-dir output/<slug>/datasets [--no-mtd] [--seed 1]
    python -m cyberrange.scenarios.mqtt_mtd.cli --attack 120 --post-attack 15 \
        --results-dir output/<slug>/attack/model-baseline --model ... --scaler ...
"""

from cyberrange.core import cli, lifecycle
from cyberrange.scenarios.mqtt_mtd.scenario import MqttMtdScenario


def run(args, progress=None, manager=None):
    """One MQTT run (see core.lifecycle.run); returns the exit code."""
    return lifecycle.run(MqttMtdScenario(), args, progress=progress, manager=manager)


def main(argv=None):
    cli.main(MqttMtdScenario(), argv, description="Smart-grid MTD experiment (MQTT scenario)")


if __name__ == "__main__":
    main()
