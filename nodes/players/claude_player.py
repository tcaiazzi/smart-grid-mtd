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
the last one, the result, is what the transcript's usage row is read from. On
the way each answer of the model is put on the transcript as a turn, and so is
what the harness did on its own — a refused answer, a change of model: the
transcript then tells the whole game in the same words for every harness.

Copied flat onto a player's node of the kathara/player-claude image, which
installs the claude CLI. Stdlib only.
"""

import json
import os
import subprocess
import sys
import tempfile
import time

import harness_kit

HARNESS = "claude-code"
SERVER = "seat"  # the MCP server's name: its tools are mcp__seat__<tool>
REFUSED = "refusal"  # how the harness names an answer its model's safeguards stopped
SYNTHETIC = "<synthetic>"  # the "model" of a message the harness wrote itself
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
        # The model's API events as they arrive: the one that closes an answer
        # is the only place the harness says what the answer cost to write.
        "--include-partial-messages",
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
        "turns_uncounted": 0 if spent else None,  # the closing totals leave none out
        # A run its model refused closes as a "success" of the harness's loop:
        # what stopped it is said apart, and is what the card must show.
        "stop_reason": REFUSED if result.get("stop_reason") == REFUSED else result.get("subtype"),
    }


class Running:
    """What the harness has spent so far, from the events it prints as it goes.

    Its closing event carries the totals, and its cost — but a harness that
    plays to the deadline is cut off with the lab and never prints one. Without
    a running count such a player would leave no figure at all, and it is the
    usual case: both sides are told to play until the time is up.

    An answer is printed with what it had read and next to nothing of what it
    wrote: its tokens written are final only in the API event that closes it
    (``closed``). An answer never closed — the one the lab was cut off under —
    is counted in ``turns_uncounted`` and adds nothing: a part of a figure
    would be summed with whole ones."""

    READ = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")

    def __init__(self):
        self.read = {}  # message id -> tokens read
        self.written = {}  # message id -> tokens written, once its answer closed

    def add(self, ev):
        """Count one ``assistant`` event; True if it changed the count. A
        message is printed once per block it holds, each time with what it has
        read so far: the largest figure seen for it is the one kept."""
        msg = ev.get("message") or {}
        used = msg.get("usage") or {}
        if not msg.get("id") or msg.get("model") == SYNTHETIC:
            return False
        now = sum(used.get(k) or 0 for k in self.READ)
        was = self.read.get(msg["id"])
        self.read[msg["id"]] = max(was or 0, now)
        return self.read[msg["id"]] != was

    def closed(self, message_id, written):
        """The answer ``message_id`` is whole and took ``written`` tokens."""
        if message_id is None or not isinstance(written, int) or isinstance(written, bool):
            return False
        self.read.setdefault(message_id, 0)
        self.written[message_id] = written
        return True

    def usage(self):
        return {
            "turns": len(self.read),
            "input_tokens": sum(self.read.values()),
            # None while no answer has closed: a harness that does not print
            # the closing events has no count, not a count of zero.
            "output_tokens": sum(self.written.values()) if self.written else None,
            "cost_usd": None,  # only the closing event says it
            "stop_reason": "cut_off",
            "turns_uncounted": len(self.read) - len(self.written),
        }


class Api:
    """The model's API events the harness passes on (``stream_event``), read
    for the one thing nothing else says: what a whole answer took to write.
    The event that opens a message names it; the one that closes it does not,
    and is the last message opened's."""

    KEPT = ("message_start", "message_delta")  # the rest is the text, a piece at a time

    def __init__(self):
        self.current = None

    def read(self, ev):
        """-> (message id, tokens written) when ``ev`` closes an answer, else None."""
        inner = ev.get("event") or {}
        if inner.get("type") == "message_start":
            self.current = (inner.get("message") or {}).get("id")
        elif inner.get("type") == "message_delta":
            return self.current, (inner.get("usage") or {}).get("output_tokens")
        return None

    @classmethod
    def worth_keeping(cls, ev):
        """Whether the event belongs in the player's log: an answer's text
        arrives in hundreds of pieces, and the whole answer is printed anyway."""
        return (ev.get("event") or {}).get("type") in cls.KEPT


class Turns:
    """The model's answers, one per message, from the events that print them.

    A message comes block by block — its text, then each call, the results of
    the earlier calls in between — so an answer is whole only when the next
    one begins, or the stream ends."""

    def __init__(self, say):
        self.say, self.open = say, None
        self.written = {}  # message id -> tokens written, from the event that closed it

    def closed(self, message_id, written):
        self.written[message_id] = written

    def add(self, ev, now):
        msg = ev.get("message") or {}
        # A message the harness wrote in the model's place (an API error put
        # into words) is not an answer of the model: it would be scored as one.
        if not msg.get("id") or msg.get("model") == SYNTHETIC:
            return
        if self.open is None or self.open["id"] != msg["id"]:
            self.close()
            self.open = {"id": msg["id"], "t": now, "model": msg.get("model")}
            self.open |= {"text": [], "calls": [], "thinking": 0, "usage": {}}
        turn = self.open
        for block in msg.get("content") or []:
            kind = block.get("type") if isinstance(block, dict) else None
            if kind == "text":
                turn["text"].append(block.get("text") or "")
            elif kind == "thinking":
                turn["thinking"] += 1
            elif kind == "tool_use" and block.get("id") not in {c["id"] for c in turn["calls"]}:
                name = (block.get("name") or "").removeprefix(f"mcp__{SERVER}__")
                turn["calls"].append({"id": block.get("id"), "name": name, "args": block["input"]})
        for k, n in (msg.get("usage") or {}).items():
            if isinstance(n, int) and not isinstance(n, bool):
                turn["usage"][k] = max(n, turn["usage"].get(k, 0))

    def close(self):
        turn, self.open = self.open, None
        if turn is None:
            return
        # What the answer wrote is the closing event's count or nothing: the
        # figure printed with its blocks is where the count stood as it began.
        turn["usage"].pop("output_tokens", None)
        if turn["id"] in self.written:
            turn["usage"]["output_tokens"] = self.written.pop(turn["id"])
        self.say(
            "\n".join(turn["text"]),
            model=turn["model"],
            usage=turn["usage"],
            tool_calls=turn["calls"],
            t=turn["t"],
            message_id=turn["id"],
            # The harness passes on that the model reasoned, not what: the
            # count is all a reader can be told of it.
            thinking_blocks=turn["thinking"],
        )


def on_its_own(ev, terms):
    """Put on the transcript what the harness did that no call shows."""
    # With a fallback the game goes on, on another model; with none it ends
    # there — and a player that never moved must not read as one that chose to.
    kind = str(ev.get("subtype") or "")
    if not kind.startswith("model_refusal"):
        return
    was, now = ev.get("original_model"), ev.get("fallback_model")
    terms.event(REFUSED, category=ev.get("api_refusal_category"), model=was, fell_back=bool(now))
    if now and now != was:
        terms.event("model_change", was=was, now=now, scope=ev.get("scope"))


def main():
    terms = harness_kit.Terms()
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"mcpServers": {SERVER: terms.mcp_server()}}, f)
    release = version()
    terms.started(HARNESS, release)
    result, running, turns, api = None, Running(), Turns(terms.turn), Api()
    try:
        p = subprocess.Popen(
            command(terms, f.name), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True
        )
    except OSError as e:
        terms.used(stop_reason="not_started")
        raise SystemExit(f"claude_player: {e}") from e
    for line in p.stdout:
        try:
            ev = json.loads(line)
        except ValueError:
            ev = None
        partial = isinstance(ev, dict) and ev.get("type") == "stream_event"
        if not partial or Api.worth_keeping(ev):
            sys.stdout.write(line)
            sys.stdout.flush()
        if not isinstance(ev, dict):
            continue
        if partial:
            closed = api.read(ev)
            if closed and running.closed(*closed):
                turns.closed(*closed)
                terms.used(**running.usage())
        elif ev.get("type") == "result":
            result = ev
        elif ev.get("type") == "assistant":
            turns.add(ev, time.time())
            if running.add(ev):
                # Said again at every turn: the last one stands if the harness
                # is cut off, and the closing event's replaces it if it is not.
                terms.used(**running.usage())
        elif ev.get("type") == "system" and ev.get("subtype") == "init" and ev.get("model"):
            # The model it actually runs, which a run that named none left to it.
            terms.started(HARNESS, release, model=ev["model"])
        elif ev.get("type") == "system":
            on_its_own(ev, terms)
    turns.close()
    rc = p.wait()
    os.unlink(f.name)
    terms.used(**usage_of(result))
    sys.exit(rc)


if __name__ == "__main__":
    main()
