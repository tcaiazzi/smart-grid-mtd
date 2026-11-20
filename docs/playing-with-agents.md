# Harnesses as players

A team's seat in the red-vs-blue playground need not be a person's. Given a
**harness** — the program that runs a model as an agent, such as Claude Code —
a team is played by a program, at the same console and under the same rules as
a person. With a harness at both seats nobody has to be there: the run plays an
engagement of fixed length, ends by itself and is scored like any other.

The point is to **evaluate harnesses**. The harness is an axis of the
experiment of its own, apart from the model: the same model can be tried under
two harnesses, and one harness with two models.

This page is for whoever runs such a game or adds a harness. For the game
itself — the lab, the attack, the countermeasures — see
[the playground](playground-red-vs-blue.md).

- [1. Run it](#1-run-it)
- [2. How a harness sits at a seat](#2-how-a-harness-sits-at-a-seat)
- [3. The sandbox](#3-the-sandbox)
- [4. What is the same for every harness](#4-what-is-the-same-for-every-harness)
- [5. What is measured](#5-what-is-measured)
- [6. Adding a harness](#6-adding-a-harness)

---

## 1. Run it

```sh
make cps-image cps-players-image          # once: the lab's images and the players'

# No model, no API key: a scripted player at each seat.
make cps-agents RED_HARNESS=scripted BLUE_HARNESS=scripted ENGAGEMENT_S=300

# Claude Code against the scripted defender, on an API key or on a subscription.
export ANTHROPIC_API_KEY=...            # or: export CLAUDE_CODE_OAUTH_TOKEN=...
make cps-agents RED_HARNESS=claude-code BLUE_HARNESS=scripted RED_MODEL=<model>

# A person at the blue console, a harness attacking.
make cps-teams RED_HARNESS=claude-code
```

| Variable | Meaning | Default |
|---|---|---|
| `RED_HARNESS`, `BLUE_HARNESS` | the harness at that seat | `claude-code` for `cps-agents`; a person for `cps-teams` |
| `RED_MODEL`, `BLUE_MODEL` | the model that harness runs | the harness's own default |
| `ENGAGEMENT_S` | how long two harnesses play, at most | `900` |
| `MAX_CALLS` | each harness's budget of tool calls | none |
| `PLAYER_DNS` | name servers of the players' nodes, comma-separated | `1.1.1.1,8.8.8.8` |
| `CPS_ADVISOR_TIMEOUT` | how long a SOC suggestion waits for the blue team's verdict | `120` |

The harnesses available today:

| Name | What it is | Needs from the host |
|---|---|---|
| `claude-code` | Claude Code, headless (`claude --print`) | `ANTHROPIC_API_KEY`, or `CLAUDE_CODE_OAUTH_TOKEN` |
| `scripted` | no model: red runs the attack's steps in order, blue approves every suggestion | nothing |

To play Claude Code on a **Claude subscription** instead of an API key, run
`claude setup-token` once on your machine: it opens the browser, and prints a
long-lived token. Export it as `CLAUDE_CODE_OAUTH_TOKEN` and leave
`ANTHROPIC_API_KEY` unset — with both, the key is the one used and billed. On a
subscription the run draws on your plan's usage limits, and the `cost_usd` a
harness reports is what the same tokens would have cost on the API, not a
charge.

`scripted` is the yardstick, and the opponent to keep fixed while the other
seat's harness changes: two runs are comparable only if what they played
against was the same.

The engagement ends when its time is up or when both players have stopped,
whichever comes first. Follow it on `make dashboard`: the **Teams** card says
who plays each seat, lists every step, countermeasure and command with the
reason the player gave for it, and counts each harness's calls.

## 2. How a harness sits at a seat

```
 model's API          lab
 (HTTPS) ◀── bridged ─┬─ redplayer ──── link seatred ───▶ attacker: red_console.py
                      │   harness                          /seat /briefing /state
                      │    └ stdio ─ seat_mcp.py           /steps/<id> /shell
                      │
                      └─ blueplayer ─── link seatblue ──▶ soc: soc_analytics.py
                          (the same)                       /seat /briefing /state /approvals/<id>
                                                           /countermeasures/<id> /mode /shell
```

**The seat** is the team's console (`nodes/soc/soc_operator.py`,
`nodes/redteam/red_console.py`). Next to the routes its page uses, it serves
what a player that is not a browser needs (`nodes/common/seat.py`):

| Route | What it gives |
|---|---|
| `GET /seat` | the team, the actions the console takes, the node's clock, the version of this contract |
| `GET /briefing` | the team's briefing, written from the run's own lab and options |
| `POST /shell` | one command as root on the team's node, recorded where the team's typed commands are |

Every action also takes a `note`: the reason for it, in the player's words. It
is kept with the action on record, and shown to the referees.

**The adapter** (`nodes/players/seat_mcp.py`) is an MCP server on stdio that
turns each tool call into the request a browser would have made. It is the only
thing the harness is given: a team is shown its own levers and no other.

**The launcher** is the only code written for one harness. It points the
harness at the adapter, takes its built-in tools away, and reports which
harness played and what it spent.

A harness is a player like any other: the same console, the same token, the
same records. In those records it names itself `agent:<harness>[:<model>]`, so
an agent's actions can be told from a person's without being treated
differently.

## 3. The sandbox

A harness is a program the range did not write, and it needs a way out to the
Internet. It runs on a node of its own, built to hold only that:

- **No volumes.** The node has nothing of the host: not the run's directory
  (which holds the ground truth and the other team's token), not the
  repository, not your credentials.
- **One link into the lab**, to its team's console, on a network of two
  addresses. The console's node accepts the console's port from the player's
  address on that link, drops everything else, and forwards nothing.
- **A closed firewall** (`nodes/players/player-firewall.sh`), set before the
  harness starts: out to the console, to the node's resolvers, and to HTTPS on
  public addresses. The host — the gateway of the bridged interface, where the
  other team's console is published — and every private network are refused.
- **An unprivileged user.** The harness runs as `player` and cannot lift the
  firewall.
- **One thing of the host comes in**: the environment variables the harness
  declares it needs (its API key). They reach the node as a file, never on a
  command line, and are in no record of the run.

If the firewall cannot be set, the harness is not started.

A lab node has no name server of its own, so a player's node is given some
(`PLAYER_DNS`): set them to your network's if it does not let public resolvers
through. A model served on the local network is refused by this firewall as any
private address is.

## 4. What is the same for every harness

A comparison holds only if the harnesses played the same game. So everything
that must be equal is done by the adapter, and none of it by the harness:

- the briefing, the tools and their wording;
- the budget of calls and the deadline — past either, a call is refused and
  nothing reaches the seat;
- the record of every call: when, which tool, how long, how it ended.

What is left to the harness is what is being evaluated: its own system prompt,
its own loop, how it reads a failure and what it tries next. A launcher must
not touch those.

## 5. What is measured

The outcome of the game is in the run's usual metrics (`metrics.json`), which
now hold for an attack played at the console as well as for a driven one:

| Metric | Meaning |
|---|---|
| `stage_reached` | the furthest stage of the attack a step succeeded at |
| `attack_succeeded` | whether the plant took a write or falsified readings |
| `prevented` | the opposite, as the defence sees it |
| `response.*` | what the blue team applied, whether it was called for, how fast |
| `response.operator.by_kind` | suggestions answered and median latency, apart for people and harnesses |

Next to it, `players.<team>` is each harness's scorecard, read from the
transcript the adapter kept (`player-<team>.jsonl`):

| Field | Meaning |
|---|---|
| `harness`, `harness_version`, `model` | who played; the version is read from the harness itself |
| `calls`, `actions` | tool calls made, and those that act on the lab |
| `call_latency_median_s`, `action_latency_median_s` | how long a call took |
| `failed_calls`, `failed_call_rate` | calls the seat did not carry out, by why: `bad_arguments`, `seat_error`, `over_budget`, `past_deadline`, `unknown_tool` |
| `turns`, `input_tokens`, `output_tokens`, `cost_usd` | what the harness reports of its own run; `null` where it reports nothing |
| `stop_reason`, `exit_code`, `played_s` | how and when it stopped; `null` for a harness still playing when the engagement ended |

A figure a harness does not give is `null`, never a guess: it would be compared
with real ones.

## 6. Adding a harness

Three things, and nothing in the platform, the consoles, the adapter or the
metrics changes:

1. **A launcher** under `nodes/players/`, staged by a manifest in
   `cyberrange/scenarios/cps_advisor/guest_files.py`. Stdlib and what its image
   installs only.
2. **An image** under `docker/player-<name>/`, built on `kathara/player`, with
   the harness at a pinned version.
3. **An entry** in `cyberrange/scenarios/cps_advisor/harnesses.py`: its name,
   image, launcher, the host variables it needs.

The launcher's contract (`nodes/players/harness_kit.py` does the common part):

1. **In**: the terms in the environment (`CR_SEAT_URL`, `CR_OPERATOR`,
   `CR_MODEL`, `CR_PROMPT`, `CR_DEADLINE`, `CR_MAX_CALLS`, `CR_TRANSCRIPT`…).
   Nothing else.
2. **The seat is the only tool.** Register `Terms.mcp_server()` as the
   harness's one MCP server and switch its built-in tools off — shell, files,
   web. The sandbox would hold without that; the comparison would not.
3. **Leave the harness as it ships**: no system prompt of ours, no change to
   its loop.
4. **Run without a person**, and exit when the harness is done.
5. **Out**: `Terms.started(harness, version)` before the harness starts, with
   the version the harness reports of itself; `Terms.used(...)` when it ends,
   translated from its own log, with `None` for what it does not say.

`nodes/players/claude_player.py` is the example to copy;
`nodes/players/scripted_player.py` shows a player with no MCP client at all.
Read the harness's options from the `--help` of the version the image installs,
not from memory, and raise the two together.
