---
name: kathara-lab-creation
description: "Create and configure Kathara labs with consistent folder structure, lab.conf, and startup files. Use when designing new teaching labs, exercises, or exam scenarios in Kathara repositories."
argument-hint: "Topic/category, lab name, devices, links, addressing, and validation goal"
user-invocable: true
---

# Kathara Lab Creation

Create a new Kathara lab configuration with consistent naming, topology declaration, and runnable startup scripts.

## Authoritative References
- Base command reference: https://www.kathara.org/man-pages/kathara.1.html
- Lab configuration reference (`lab.conf`): https://www.kathara.org/man-pages/kathara-lab.conf.5.html

- Scenario lifecycle commands:
  - `kathara lstart`: https://www.kathara.org/man-pages/kathara-lstart.1.html
  - `kathara linfo`: https://www.kathara.org/man-pages/kathara-linfo.1.html
  - `kathara lrestart`: https://www.kathara.org/man-pages/kathara-lrestart.1.html
  - `kathara lclean`: https://www.kathara.org/man-pages/kathara-lclean.1.html
- Device interaction commands:
  - `kathara connect`: https://www.kathara.org/man-pages/kathara-connect.1.html
  - `kathara exec`: https://www.kathara.org/man-pages/kathara-exec.1.html
- Environment validation: https://www.kathara.org/man-pages/kathara-check.1.html

You can add `--help` to any command for more details.
Verify correctness of the command before using it.

When in doubt, prefer the behavior described in these man pages over assumptions.

## Basic concepts
- A lab is a folder centered on `lab.conf` plus per-device `.startup` files.
- Optional per-device folders are mounted as each device root filesystem; use them when files must persist in the lab definition.
- Collision-domain names in `lab.conf` (for example `A`, `netA`) are labels only and do not set IP/routing by themselves.
- Interactive changes made after `kathara lstart` are ephemeral; persist all intended configuration in lab files.

## When to Use
- You need to create a new Kathara lab from scratch.
- You need a repeatable configuration process for main labs, exercises, or exam labs.
- You want an opinionated checklist that avoids missing required files.

## Expected Inputs
The user may start with an incomplete natural-language description. Extract or infer these inputs while keeping assumptions explicit:
1. Target location (path and category)
2. Lab name (final folder name)
3. Device list (hosts/routers/switches) and interface count
4. Link mapping (collision domains or direct links)
5. Addressing plan (IPv4/IPv6, static routes)
6. Runtime images per device (for example `kathara/core`)
7. Validation goal (ping matrix, traceroute, protocol checks)
8. Whether the current step is only prompt generation or actual scenario creation

If any missing detail would materially affect topology, addressing, routing, selected images, or validation, ask the user before proceeding.

## Available Images

Source repository (develop branch): https://github.com/KatharaFramework/Docker-Images/tree/develop

All images are based on Debian 12 and compiled for `amd64` and `arm64`.

| Image | Description | Notable tags |
|---|---|---|
| `kathara/core` | Base image with common network tools; foundation for all others. | `latest` |
| `kathara/base` | Extends core with BIND9, Apache, and dnsmasq. | `latest` |
| `kathara/apache` | Extends core with the [Apache](https://httpd.apache.org/) web server. | `latest` |
| `kathara/bind` | Extends core with the [BIND9](https://bind9.net/) DNS daemon. | `9.11.5`, `latest` |
| `kathara/dnsmasq` | Extends core with [dnsmasq](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html). | `latest` |
| `kathara/bird` | Extends core with [BIRD](https://bird.network.cz/) v1. | `latest` (v1.6.8) |
| `kathara/bird2` | Extends core with [BIRD 2](https://bird.network.cz/). | `2.0.8`, `latest` |
| `kathara/bird3` | Extends core with [BIRD 3](https://bird.network.cz/). | `latest` |
| `kathara/frr` | Extends core with [FRRouting](https://frrouting.org/). | `9`, `10`, `latest` |
| `kathara/quagga` | Extends core with [Quagga](https://www.nongnu.org/quagga/). | `latest` |
| `kathara/openbgpd` | Extends core with the [OpenBGPD](https://www.openbgpd.org/) daemon. | `latest` |
| `kathara/openvswitch` | Extends core with [Open vSwitch](https://www.openvswitch.org/) (also tagged as `kathara/sdn`). | `latest` |
| `kathara/pox` | Extends core with [POX](https://github.com/noxrepo/pox) Python SDN controller and `python3-networkx`. | `latest` |
| `kathara/bmv2` | Extends core with [BMv2](https://github.com/p4lang/behavioral-model) P4 programmable switch (also tagged as `kathara/p4`). | `latest` |
| `kathara/krill` | Extends core with [Krill](https://www.nlnetlabs.nl/projects/rpki/krill/) RPKI CA. | `latest` |
| `kathara/routinator` | Extends core with [Routinator](https://www.nlnetlabs.nl/projects/rpki/routinator/) RPKI relying party. | `latest` |
| `kathara/rpki-client` | Extends core with [rpki-client](https://www.rpki-client.org/). | `latest` |
| `kathara/rift-python` | Extends core with the [RIFT-Python](https://github.com/brunorijsman/rift-python) implementation. | `latest` |
| `kathara/scion` | Extends core with [SCION](https://scion-architecture.net/). | `0.12.0`, `latest` |


## Commands for device configuration
- Use `ip` for interface and route configuration.
- Must use `systemctl` for service management.
- Use `ping` for connectivity checks.
- Use `curl` for application-level checks when relevant.
- Use `tcpdump` for packet-level diagnosis when relevant.
- Use  `traceroute` for path checks when relevant.


## General rules
- Kathará interfaces are already up at boot; do not use `ip link set up` on them.
- You can derive configuration examples from the official Kathara labs: https://github.com/KatharaFramework/Kathara-Labs

## Procedure

### 1) Collect the lab request in natural language
- Start from the user's natural-language description rather than requiring a fully structured specification.
- Extract the intended topology, devices, protocols, services, and validation goal.
- Ask clarifying questions only for details that materially affect the lab design or validation outcome.
- If details are omitted but can be safely standardized, plan to fill them with explicit defaults in the generated prompt.

### 2) Generate a structured prompt from the request
- Write a prompt that restates the requested lab in a precise, implementation-ready form.
- Fill in unspecified details with reasonable defaults and mark them as assumptions.
- Include at least:
  - target path and lab name
  - device list and roles
  - link mapping / collision domains
  - addressing and routing plan
  - selected images
  - required files to generate
  - validation checks to perform
- Present this prompt to the user as the working specification for the scenario.

### 3) Refine the prompt if needed
- Ask follow-up questions about the generated prompt only if some assumptions remain too risky or ambiguous.
- Update the prompt until it is detailed enough to implement without hidden decisions.
- Do not generate the lab yet unless the user explicitly asks to create the scenario from the prompt.

### 4) Wait for explicit creation request
- Treat prompt generation and lab creation as separate stages.
- Only start creating files after the user asks to create the scenario starting from the generated prompt.

### 5) Select canonical layout
- Create one folder containing:
  - `lab.conf`
  - `<device>.startup` for each device
  - optional `<device>/` folder for device root filesystem files
  - optional `shared/`
  - optional `images/`
  - optional `README.md`

### 6) Build topology in `lab.conf`
- Add optional metadata when relevant:
  - `LAB_DESCRIPTION`, `LAB_VERSION`, `LAB_AUTHOR`, `LAB_EMAIL`, `LAB_WEB`
- Declare each device interfaces with collision domains and optional MACs.
- Set image and feature flags (for example `ipv6=false`) explicitly when needed.
- Keep interface numbering contiguous from `0`.

### 7) Create startup scripts
- For each host/router, add interface addressing and routes.
- Keep commands idempotent where possible.
- Use deterministic addressing and route conventions across devices.

### 8) Add minimal documentation
- Add a short `README.md` when the lab is intended for learners.
- Include:
  - one-paragraph objective
  - topology image reference if available
  - execution command: `kathara lstart`
  - one quick validation procedure

### 9) Validate the generated lab
After generating the scenario, await user request to validate it before considering the task complete. Execute validation as **separate steps**, with each command run independently for refined debugging:
1. Run `kathara check` to verify the local environment.
2. Run `kathara lstart` from the lab directory and wait for completion.
3. Run `kathara linfo` to verify all devices are running.
4. For each device, run `kathara exec <device> -- ip addr show` to verify interface addressing.
5. For each device, run `kathara exec <device> -- ip route show` to verify routing configuration.
6. Run connectivity checks: for each link, run `kathara exec <source> -- ping -c 2 <destination_ip>` separately.
7. Run protocol-specific validation: run `kathara exec <device> -- <command>` for each check (e.g., `systemctl status <service>`).
8. If any step fails, inspect output, fix the lab files, then re-run that specific step and subsequent steps.
- Persist all fixes in lab files; do not rely on manual interactive changes.

### 10) Validate configuration completeness
Run this checklist before considering the configuration done:
- `lab.conf` exists and every device in it has a matching startup file when needed.
- All referenced interfaces exist in startup scripts.
- IP/MAC plan has no duplicates unless intentional.
- Collision-domain labels are used consistently and are not treated as implicit IP configuration.
- Lab starts without immediate boot errors.

Run each validation command separately:
1. Run `kathara check` to verify the local environment.
2. Run `kathara lstart` from the generated lab directory.
3. Run `kathara linfo` to verify devices and links are up.
4. Run `kathara lclean` to shut down the lab cleanly.
5. Run `kathara lstart` again to verify the lab can be restarted reliably.
6. Run `kathara linfo` again to confirm all devices restart correctly.

If any step fails, inspect the output, fix files, and re-run that step before proceeding.

### 11) Troubleshoot with documented commands
When validation fails, use single commands to isolate and diagnose issues:
- **Check lab status**: Run `kathara linfo` to inspect running devices and their interfaces.
- **Restart lab**: Run `kathara lrestart` if devices are not responding.
- **Interactive access**: Run `kathara connect <device>` for interactive shell inside a single device for manual testing.
- **Non-interactive checks**: Run `kathara exec <device> -- <command>` for one-off commands (e.g., `kathara exec h1 -- ip addr show`).
- **Inspect startup logs**: Run `kathara exec <device> -- cat /var/log/syslog` to review device boot logs.
- **Reset lab state**: Run `kathara lclean` to shut down all devices, then `kathara lstart` to restart fresh.
- **Deep environment reset**: Run `kathara wipe --all --force` as a last-resort reset if devices remain stuck across multiple cleanup attempts.

Always run one command, examine output, then proceed to the next command.

## Decision Branches
- If the audience is students, include `README.md` with explicit test goals.
- If this is an exam/training scenario, keep configuration minimal and move guidance to external docs.

## Completion Criteria
A configuration is complete when:
1. A natural-language request has been converted into a structured prompt with explicit assumptions.
2. The lab is generated only after the user explicitly asks to create the scenario from that prompt.
3. The folder structure is present and internally consistent.
4. The scenario starts with `kathara lstart` and is visible in `kathara linfo`.
5. At least one validation check can be executed end-to-end.
6. Naming and structure match repository conventions for the selected category.
