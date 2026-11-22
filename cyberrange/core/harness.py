"""harness.py — a harness, as the platform knows it: the program that runs a
model as a player (Claude Code, a script with no model at all).

The harness is an axis of an experiment of its own, apart from the model it
runs: the same model can be tried under two harnesses, and one harness with two
models. For that to be a matter of choosing a name, everything the platform
needs to put a harness in a seat is data — the image of its node, the command
that starts it, the secrets it wants from the host — and nothing in the
platform is written for one harness in particular. The harnesses themselves
are node software (nodes/players/), and a scenario lists the ones it offers.
"""

import os
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class Harness:
    name: str  # as chosen on the command line and written in every record
    image: str  # the image of the player's node
    launcher: str  # the command that starts it there, as the unprivileged player
    files: Tuple[Tuple[str, str], ...] = ()  # (host path, guest path) of its own launcher
    # Host environment variables that authenticate it to its model, any one of
    # which is enough (an API key, or a subscription's token): the only things
    # of the host that enter the player's node.
    secret_env: Tuple[str, ...] = ()
    default_model: Optional[str] = None  # when the run names none; None: the harness's own
    # The teams it can play; empty: any. A fixed policy is one side's.
    seats: Tuple[str, ...] = ()

    def missing(self, env=None) -> list:
        """The secrets one of which this harness needs, when the host holds
        none of them; empty when it can authenticate."""
        env = os.environ if env is None else env
        return [] if not self.secret_env or self.secrets(env) else list(self.secret_env)

    def secrets(self, env=None) -> dict:
        env = os.environ if env is None else env
        return {name: env[name] for name in self.secret_env if env.get(name)}
