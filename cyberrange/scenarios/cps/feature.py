"""feature.py — what a scenario built on the CPS lab adds to it, as a unit.

The CPS scenarios share one lab and one episode and differ by additions:
people in the loop (cps-advisor), the tools of a real SOC (cps-soc), an attacker
that finds its own way (cps-recon). Each addition is a Feature, and a scenario
is the cps one with a tuple of them. Written as subclasses, the additions could
only stack along one line — a SOC with tools *and* a recon attacker would have
been a sixth class; as features it is another tuple.

Every hook has a neutral default, so a feature implements only what it adds.
The scenario calls the features in the order it lists them: what one feature
puts on a node comes before what the next one puts there (guest files, startup
commands), and its services start first.
"""


class Feature:
    """One addition to the CPS scenario. ``scenario`` and ``spec`` (the run's
    LabSpec) are passed in; a feature keeps no state of its own between runs."""

    # ── options ──────────────────────────────────────────────────────────────
    def add_arguments(self, ap):
        pass

    def validate(self, args):
        pass

    def check_approval(self, spec) -> bool:
        """True when this feature decides what --approval may be (and has
        checked ``spec``); the cps rule applies when no feature does."""
        return False

    def host_ports(self, args):
        """The host ports this feature publishes: they must differ from every
        other one the run publishes."""
        return []

    def prepare(self, args):
        pass

    def run_info(self, args):
        return {}

    # ── the lab ──────────────────────────────────────────────────────────────
    def extras(self, spec, args):
        """{host: Extra}: what this feature adds to the lab's hosts."""
        return {}

    def nodes(self, spec, args):
        """Nodes of this feature's own, next to the lab's."""
        return []

    # ── people and the SOC ───────────────────────────────────────────────────
    def links(self, args):
        """{team: {what: url}}: what this feature hands to each team."""
        return {}

    def operator_api(self, scenario, args):
        """SocAnalytics keyword arguments this feature sets."""
        return {}

    # ── the episode ──────────────────────────────────────────────────────────
    def services(self, ctx):
        """Components started with the lab's services, before normal operation."""

    def engage(self, ctx):
        """Called once the ground truth is open, when an attack may begin."""

    def attacker(self, scenario, args):
        """The attack driver, when this feature brings its own; None otherwise."""
        return None
