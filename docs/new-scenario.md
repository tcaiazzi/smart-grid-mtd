# Creating a scenario

**[Open the interactive guide →](scenario-guide.html)**

The guide takes you step by step through adding a scenario. In its second step
you choose which kind:

- **a lab of its own**, as `mqtt-mtd` has: its own nodes, networks and episode;
- **a variant of the cps lab**, as `cps-recon` and `cps-advisor` are: the cps lab
  and episode, with a `Feature` that adds options, software on a host or
  services.

You describe the scenario as you go. At each step the guide shows you the file
that step writes, built from your answers, and checks for the mistakes the
repository's guardrails would otherwise catch only later. It flags:

- a name or lab name already in use;
- a `-` in a node name;
- an address used twice on one link;
- a published port on a node whose default route is not replaced;
- a guest module name that is already taken;
- for a variant, a host the cps lab does not have, or an option cps already has;
- a component left without a required argument, or placed on a node whose image
  lacks a package its guest code imports.

While you declare the lab, the guide also shows what Kathará will be given:
`lab.conf` and each node's startup file, as `make lab-conf` renders them.

**Export answers** saves what you entered as `<name>.scenario.json`, and
**Import** loads such a file back. Use it to hand a scenario's design to someone
else, or to keep it next to the work. Your answers and ticks are also saved in
your browser, so you can close the page and pick up where you left off.

At the end you download every new file as one zip and unpack it at the
repository root. The zip also carries `scenario-edits.json`, the edits the
scenario needs in files that already exist: the registry, the make include,
`.PHONY` and help, the guardrail tables and the docs nav. A tool applies them:

```bash
.venv/bin/python tools/apply_scenario_edits.py            # show the diff
.venv/bin/python tools/apply_scenario_edits.py --write    # apply it
```

It writes every edit or none, and skips an edit already made, so you can run it
again. Two things stay yours, because they are deliberate acts: the snapshot
update and `MIN_TESTS`. The tool ends by recalling both, with the commands.

What you get is a skeleton that runs as soon as it is unpacked. For a lab of
its own:

- a `Topology` and a `Scenario` with a best-effort phase and a timed one;
- a placeholder guest agent and its manifest;
- the plane components you chose, started in their phase, with the guest files
  they launch staged on their nodes;
- `SOURCES`, `cli.py`, `metrics.py` and a `make/<name>.mk`;
- if you ask for them, a `campaign.py` (one scored run per seed, resumable)
  and a `panel.js` (a dashboard card with the run's metrics);
- a test that runs the whole lifecycle on the fake lab;
- this site's page for the scenario.

For a variant of the cps lab:

- a `Feature` with the options you declared, a placeholder agent staged on
  the cps host you chose, and the plane components you chose, all started
  with the lab's services;
- a `Scenario` that is `CpsScenario` with that feature;
- a `panel.js` that shows the cps panel, `SOURCES`, `cli.py` and a
  `make/<name>.mk` that reuses the `CPS_*` variables;
- a test of what the variant adds;
- this site's page for the scenario.

`tests/core/test_scenario_guide.py` generates that same skeleton, formats and
lints it, runs its tests and applies its edits to copies of the files they
touch. It renders every step of the page, and compares the page's `lab.conf`
preview with what the platform renders for the same lab. It also checks every name the guide cites against the code, so the guide
stays in step with the repository.

## When the repository changes

The guide carries a copy of some facts of the repository: the scenario and lab
names in use, the make targets, the guest modules, and what each node image
installs. Adding a scenario, a target, a guest module or a package to an image
makes that copy stale, and the test above goes red until the guide is brought
along:

```bash
UPDATE_GUIDE_CONTRACT=1 .venv/bin/python -m pytest tests/core/test_scenario_guide.py -q
```

The same holds for the plane components, whose constructors and guest files
the guide also copies. That rewrites one block of the page, `#guide-contract-derived`, from the
repository; read the page's diff before committing, as it should show only what
you changed. The switch updates facts and nothing else: if the test is red
because the skeleton no longer runs, the guide's templates need fixing.

## Opening it locally

The guide is a single page, `docs/scenario-guide.html`. You can open it in
either of two ways:

- **from the documentation site:** run `make docs-serve`, then open
  <http://127.0.0.1:8000/scenario-guide.html>;
- **from the file:** open `docs/scenario-guide.html` in a browser.

It loads its libraries (code highlighting, the topology graph, the zip) from a
CDN. Without an internet connection it still works, without highlighting or the
graph, and you save the files one by one instead of as a zip.

## Choosing components

The step that writes the episode (for a variant, the step that says what it
adds) offers every component of `cyberrange/planes/*/components.py`, with its
constructor as it is in the code. You fill in its arguments as Python
expressions, and the guide writes the call, stages the guest files the component
launches together with the modules they import, and checks the packages they
need against the node's image. [Components](components.md) says what each one
does. System tools and configuration a component relies on (tcpdump, ttyd, a
Wazuh agent) are the image's, and the guide does not check them.

## Not covered here

The guide writes a variant's `Feature` with three hooks: options, files on a
host, and services. A variant that brings its own attacker, adds nodes to the
lab, or changes the lab or the plant uses the other hooks, which the guide
explains and points to but does not generate. A variant gets no campaign or
panel stub: it has the cps ones.
[Extending the platform](extending.md) covers the CPS family, and
[Architecture](platform.md) gives the full scenario contract.
