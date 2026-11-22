#!/usr/bin/env python3
"""claude_player.py — the launcher of the claude-code harness: Claude Code,
headless, with a team's seat as its only tools.

What is evaluated is the harness as it ships: its own system prompt and its own
loop are left alone. What the launcher takes away is everything a person at the
console does not have — the built-in tools (shell, files, web), the settings
and memory of whoever built the image, any MCP server but the seat — so that
the harness plays the same game as the other players. The node's sandbox would
hold without that; the comparison would not.

It runs on whichever credential the range passed: an API key
(ANTHROPIC_API_KEY), or the token of a Claude subscription
(CLAUDE_CODE_OAUTH_TOKEN, from `claude setup-token`). With a key it is started
in the CLI's bare mode, which reads no settings at all — and no subscription
token either, so with a token that mode is left out: the node is built with
nothing in the player's home for the CLI to pick up, which is what bare mode
would have skipped.

Its stream of events goes to stdout (the range keeps it as the player's log);
the last one, the result, is what the transcript's usage row is read from.

Copied flat onto a player's node of the kathara/player-claude image, which
installs the claude CLI. Stdlib only.
"""

import json
import os
import subprocess
import sys
import tempfile

import harness_kit

HARNESS = "claude-code"
SERVER = "seat"  # the MCP server's name: its tools are mcp__seat__<tool>
API_KEY = "ANTHROPIC_API_KEY"  # with it the CLI bills the key, whatever else is set


def version():
    try:
        out = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=30)
        return out.stdout.split()[0] if out.stdout.split() else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def command(terms, config_path, env=None):
    env = os.environ if env is None else env
    cmd = ["claude", "--print", terms.prompt]
    if env.get(API_KEY):
        # No settings, hooks, memory or CLAUDE.md of the image's: only the key.
        # Bare mode reads nothing else, a subscription's token included.
        cmd.append("--bare")
    cmd += [
        "--tools",
        "",  # none of the built-in tools
        "--mcp-config",
        config_path,
        "--strict-mcp-config",
        "--allowedTools",
        f"mcp__{SERVER}__*",
        "--output-format",
        "stream-json",
        "--verbose",  # stream-json is refused without it in print mode
        "--no-session-persistence",
    ]
    if terms.model:
        cmd += ["--model", terms.model]
    return cmd


def usage_of(result):
    """The transcript's usage figures, from the harness's closing ``result``
    event; None for whatever it does not say."""
    result = result or {}
    spent = result.get("usage") or {}
    read = [spent.get(k) for k in ("input_tokens", "cache_creation_input_tokens")]
    read.append(spent.get("cache_read_input_tokens"))
    return {
        "turns": result.get("num_turns"),
        "input_tokens": sum(n for n in read if n) if any(n is not None for n in read) else None,
        "output_tokens": spent.get("output_tokens"),
        "cost_usd": result.get("total_cost_usd"),
        "stop_reason": result.get("subtype"),
    }


class Running:
    """What the harness has spent so far, from the events it prints as it goes.

    Its closing event carries the totals, and its cost — but a harness that
    plays to the deadline is cut off with the lab and never prints one. Without
    a running count such a player would leave no figure at all, and it is the
    usual case: both sides are told to play until the time is up."""

    READ = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")

    def __init__(self):
        self.spent = {}  # message id -> (tokens read, tokens written)

    def add(self, ev):
        """Count one ``assistant`` event; True if it changed the count. A
        message is printed once per block it holds, each time with what it has
        used so far: the largest figure seen for it is the one kept."""
        msg = ev.get("message") or {}
        used = msg.get("usage") or {}
        if not msg.get("id"):
            return False
        now = (sum(used.get(k) or 0 for k in self.READ), used.get("output_tokens") or 0)
        was = self.spent.get(msg["id"], (0, 0))
        self.spent[msg["id"]] = (max(was[0], now[0]), max(was[1], now[1]))
        return self.spent[msg["id"]] != was

    def usage(self):
        return {
            "turns": len(self.spent),
            "input_tokens": sum(r for r, _w in self.spent.values()),
            "output_tokens": sum(w for _r, w in self.spent.values()),
            "cost_usd": None,  # only the closing event says it
            "stop_reason": "cut_off",
        }


def main():
    terms = harness_kit.Terms()
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"mcpServers": {SERVER: terms.mcp_server()}}, f)
    release = version()
    terms.started(HARNESS, release)
    result, running = None, Running()
    try:
        p = subprocess.Popen(
            command(terms, f.name), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True
        )
    except OSError as e:
        terms.used(stop_reason="not_started")
        raise SystemExit(f"claude_player: {e}") from e
    for line in p.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        if ev.get("type") == "result":
            result = ev
        elif ev.get("type") == "assistant" and running.add(ev):
            # Said again at every turn: the last one stands if the harness is
            # cut off, and the closing event's replaces it if it is not.
            terms.used(**running.usage())
        elif ev.get("type") == "system" and ev.get("subtype") == "init" and ev.get("model"):
            # The model it actually runs, which a run that named none left to it.
            terms.started(HARNESS, release, model=ev["model"])
    rc = p.wait()
    os.unlink(f.name)
    terms.used(**usage_of(result))
    sys.exit(rc)


if __name__ == "__main__":
    main()
