"""trajectory.py — what each player did, step by step, as one ATIF document.

The scorecard says how a harness played in figures. A trajectory is the game
itself — what the agent was told, what its model answered at each turn, the
calls it made and all that each gave back — in a form other benchmarks' tools
read: the Agent Trajectory Interchange Format (ATIF-v1.8, Harbor's;
rfcs/0001-trajectory-format.md in harbor-framework/harbor). With it two agents
are compared move by move, by tools that know nothing of this range.

It is built from the transcript the seat's adapter and the harness's launcher
kept on the player's node (player-<team>.jsonl), and from nothing else: the
same builder for every harness, and for a scripted player, which has calls and
no model. What the format has no field for — a call's outcome at the seat, the
note the player gave, a refused answer, a change of model — goes in ``extra``,
where the format puts what is the producer's own.

    python -m cyberrange.scenarios.cps.trajectory RUN_DIR [--harness-log red=FILE]

``--harness-log`` rebuilds the trajectory of a run whose transcript has no
turns and no outputs, from the Claude Code stream the range kept as the
player's log.
"""

import argparse
import datetime
import glob
import json
import os

from cyberrange.scenarios.cps.scorecard import _read_jsonl

SCHEMA = "ATIF-v1.8"
FILE = "trajectory-{team}.json"
SYNTHETIC = "<synthetic>"  # the "model" of a message Claude Code wrote itself
SEAT_PREFIX = "mcp__seat__"  # how Claude Code names the seat's tools
NOTES = (
    "Built from the transcript kept by the seat's adapter (tool calls and all each "
    "returned) and by the harness's launcher (the model's turns). Not recorded: the "
    "model's reasoning, which the harness does not pass on (extra.thinking_blocks "
    "counts its blocks), and the harness's own system prompt. A turn has "
    "completion_tokens only when the harness said what the whole answer took; "
    "final_metrics leave out the answers it did not (extra.turns_uncounted). "
    "tool_calls[].extra holds what the seat says of "
    "a call (outcome, result_ok, duration_s, note); steps of source system are things "
    "the harness did on its own (a refused answer, a change of model)."
)
# The fields the format declares, object by object: it refuses any other, so
# what is the range's own must sit in an ``extra``.
ROOT = ("schema_version", "session_id", "trajectory_id", "agent", "steps", "notes")
ROOT += ("final_metrics", "extra")
AGENT = ("name", "version", "model_name", "tool_definitions", "extra")
EVERY_STEP = ("step_id", "timestamp", "source", "message", "observation", "extra")
EVERY_STEP += ("llm_call_count",)
AGENT_STEP = ("model_name", "reasoning_effort", "reasoning_content", "tool_calls", "metrics")
TOOL_CALL = ("tool_call_id", "function_name", "arguments", "extra")
RESULT = ("source_call_id", "content", "extra")
METRICS = ("prompt_tokens", "completion_tokens", "cached_tokens", "cost_usd", "extra")
FINAL = ("total_prompt_tokens", "total_completion_tokens", "total_cached_tokens")
FINAL += ("total_cost_usd", "total_steps", "extra")
SOURCES = ("system", "user", "agent")
# What the seat says of a call, kept beside it.
OF_THE_SEAT = ("outcome", "result_ok", "duration_s", "note", "n", "woken_by")


def _iso(t):
    if t is None:
        return None
    stamp = datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
    return stamp.isoformat(timespec="milliseconds")


def _given(d):
    """``d`` without what nobody measured: the format's optional fields are
    left out, not set to null."""
    return {k: v for k, v in d.items() if v is not None}


def _arguments(row):
    try:
        args = json.loads(row.get("input") or "{}")
    except ValueError:
        args = {}
    return args if isinstance(args, dict) else {}


def _tool_name(row):
    tool = row.get("tool")
    return tool.get("name") if isinstance(tool, dict) else tool


def _call(call_id, name, args, row):
    """One tool call with the result its row holds: (ToolCall, ObservationResult
    or None). A call with no row was made and never answered — the lab went
    down under it — and has no observation rather than an empty one."""
    extra = {k: row[k] for k in OF_THE_SEAT if k in row} if row else {"answered": False}
    if row and row.get("t") is not None:
        # When the seat was asked. The calls of one turn share their step's
        # timestamp, which is the model's answer: without this a reader cannot
        # tell when each of them began.
        extra["timestamp"] = _iso(row["t"])
    call = {"tool_call_id": call_id, "function_name": name, "arguments": args, "extra": extra}
    if not row or row.get("output") is None:
        return call, None
    return call, {"source_call_id": call_id, "content": row["output"]}


def _metrics(usage):
    """A turn's token counts in the format's terms: its prompt tokens include
    the cached ones, which the model's API counts apart."""
    if not usage:
        return None
    read = [usage.get(k) or 0 for k in ("input_tokens", "cache_creation_input_tokens")]
    cached = usage.get("cache_read_input_tokens")
    made = usage.get("cache_creation_input_tokens")
    return _given(
        {
            "prompt_tokens": sum(read) + (cached or 0),
            "completion_tokens": usage.get("output_tokens"),
            "cached_tokens": cached,
            "extra": {"cache_creation_input_tokens": made} if made is not None else None,
        }
    )


def _turn_step(turn, ended, by_id, outputs):
    """The step of one answer of the model. Its calls are found on the seat's
    rows by the id both carry; failing that — a harness that does not pass its
    id on — by the order they were made in, and only between calls of the same
    tool: a call matched to another's result would put words in the seat's
    mouth, so one that finds no row is left without."""
    calls, results, unmatched = [], [], 0
    for c in turn.get("tool_calls") or []:
        row = by_id.pop(c.get("id"), None)
        if row is None:
            row = next((r for r in ended if _tool_name(r) == c.get("name")), None)
            unmatched += row is None
        if row is not None and row in ended:
            ended.remove(row)
        if row is not None and row.get("output") is None and c.get("id") in outputs:
            row = row | {"output": outputs[c["id"]]}
        call, result = _call(c.get("id"), c.get("name"), c.get("args") or {}, row)
        calls.append(call)
        results += [result] if result else []
    step = {
        "timestamp": _iso(turn.get("t")),
        "source": "agent",
        "model_name": turn.get("model"),
        "message": turn.get("text") or "",
        "tool_calls": calls or None,
        "observation": {"results": results} if results else None,
        "metrics": _metrics(turn.get("usage_metadata")),
        "extra": _given(
            {"message_id": turn.get("message_id"), "thinking_blocks": turn.get("thinking_blocks")}
        ),
    }
    return _given(step), unmatched


def _call_step(row, started=None):
    """The step of a call no model's turn made: a scripted player's move."""
    row = row or {}
    asked = started or row
    call_id = asked.get("tool_call_id") or f"call-{row.get('n')}"
    call, result = _call(call_id, _tool_name(asked), _arguments(asked), row or None)
    step = {
        "timestamp": _iso(asked.get("t")),
        "source": "agent",
        "message": "",
        "tool_calls": [call],
        "observation": {"results": [result]} if result else None,
        "llm_call_count": 0,  # a dispatch nobody inferred: not a model's step
    }
    return _given(step)


EVENT_TEXT = {
    "refusal": "The harness's model refused to answer ({category}).",
    "model_change": "The harness changed the model it runs, from {was} to {now}.",
}


def _event_step(row):
    known = {k: row.get(k) for k in ("category", "was", "now")}
    text = EVENT_TEXT.get(row.get("what"), "The harness reported: {what}.")
    extra = {k: v for k, v in row.items() if k not in ("t", "kind", "team", "timestamp", "phase")}
    return {
        "timestamp": _iso(row.get("t")),
        "source": "system",
        "message": text.format(what=row.get("what"), **known),
        "extra": extra,
    }


def _tools(rows):
    listed = next((r for r in reversed(rows) if r.get("kind") == "player_tools"), {})
    return [
        {
            "type": "function",
            "function": {
                "name": t.get("name"),
                "description": t.get("description"),
                "parameters": t.get("inputSchema") or {"type": "object", "properties": {}},
            },
        }
        for t in listed.get("tools") or []
    ]


def build(rows, run_id=None, team=None, card=None, outputs=None):
    """The ATIF document of one player from its transcript's ``rows``.
    ``card`` is the team's scorecard, kept with the trajectory so that it reads
    on its own; ``outputs`` are results by call id from somewhere else, for a
    transcript that did not keep them."""

    def of(kind):
        return [r for r in rows if r.get("kind") == kind]

    def last(kind):
        return (of(kind) or [{}])[-1]

    start, usage = last("player_start"), last("player_usage")
    turns, ended = of("player_turn"), of("player_call")
    by_id = {r["tool_call_id"]: r for r in ended if r.get("tool_call_id")}
    left = list(ended)
    timed, unmatched = [], 0
    for prompt in of("player_prompt")[:1]:
        said = {"timestamp": _iso(prompt.get("t")), "source": "user", "message": prompt["text"]}
        timed.append((prompt.get("t") or 0.0, said))
    for turn in turns:
        step, missed = _turn_step(turn, left, by_id, outputs or {})
        unmatched += missed
        timed.append((turn.get("t") or 0.0, step))
    # What is left was called and is on no turn: every call of a player with no
    # model, and with one, a call its harness made outside an answer.
    begun = {r.get("tool_call_id"): r for r in of("player_call_start")}
    for row in left:
        timed.append(
            (row.get("t") or 0.0, _call_step(row, begun.pop(row.get("tool_call_id"), None)))
        )
    answered = {r.get("tool_call_id") for r in ended}
    made = {c.get("id") for t in turns for c in t.get("tool_calls") or []}
    for call_id, row in begun.items():
        if call_id not in answered and call_id not in made:
            timed.append((row.get("t") or 0.0, _call_step(None, row)))
    timed += [(r.get("t") or 0.0, _event_step(r)) for r in of("player_event")]
    steps = [step for _t, step in sorted(timed, key=lambda item: item[0])]
    for n, step in enumerate(steps, 1):
        step["step_id"] = n
    models = [start.get("model")] + [r.get("now") for r in of("player_event") if r.get("now")]
    doc = {
        "schema_version": SCHEMA,
        "session_id": run_id,
        "trajectory_id": f"{run_id}-{team}" if run_id and team else None,
        "agent": _given(
            {
                "name": start.get("harness") or "unknown",
                "version": str(start.get("harness_version") or "unknown"),
                "model_name": start.get("model"),
                "tool_definitions": _tools(rows) or None,
                "extra": _given({"team": team}),
            }
        ),
        "steps": steps,
        "notes": NOTES,
        "final_metrics": _given(
            {
                "total_prompt_tokens": usage.get("input_tokens"),
                "total_completion_tokens": usage.get("output_tokens"),
                "total_cost_usd": usage.get("cost_usd"),
                "total_steps": len(steps),
            }
        ),
        "extra": _given(
            {
                "team": team,
                "models": [m for m in models if m],
                "stop_reason": usage.get("stop_reason"),
                "turns_uncounted": usage.get("turns_uncounted"),
                "exit_code": last("player_exit").get("rc"),
                # Calls of a turn that no row of the seat could be told to be
                # theirs: their results are not in the trajectory.
                "unmatched_calls": unmatched,
                "scorecard": card,
            }
        ),
    }
    return _given(doc)


# ── the format's rules ───────────────────────────────────────────────────────
def _undeclared(obj, declared, where):
    return [f"{where}: {k} is not a field of the format" for k in obj if k not in declared]


def check(doc):
    """What in ``doc`` the format refuses, as sentences; [] for a document its
    readers take. The rules are the ones this builder could break: fields the
    format does not declare, steps out of sequence, a field of the model's on a
    step that is not the agent's, a result that answers no call."""
    wrong = _undeclared(doc, ROOT, "trajectory")
    if doc.get("schema_version") != SCHEMA:
        wrong.append(f"trajectory: schema_version is not {SCHEMA}")
    agent = doc.get("agent") or {}
    wrong += _undeclared(agent, AGENT, "agent")
    wrong += [f"agent: {k} is required" for k in ("name", "version") if not agent.get(k)]
    wrong += _undeclared(doc.get("final_metrics") or {}, FINAL, "final_metrics")
    for n, step in enumerate(doc.get("steps") or [], 1):
        at = f"step {n}"
        if step.get("step_id") != n:
            wrong.append(f"{at}: step_id is {step.get('step_id')!r}, not {n}")
        if step.get("source") not in SOURCES:
            wrong.append(f"{at}: source {step.get('source')!r} is not one of {SOURCES}")
        if not isinstance(step.get("message"), str):
            wrong.append(f"{at}: message is required (it may be empty)")
        is_agent = step.get("source") == "agent"
        wrong += _undeclared(step, EVERY_STEP + (AGENT_STEP if is_agent else ()), at)
        if step.get("llm_call_count") == 0 and ("metrics" in step or "reasoning_content" in step):
            wrong.append(f"{at}: a step no model inferred carries a model's metrics")
        calls = step.get("tool_calls") or []
        for c in calls:
            wrong += _undeclared(c, TOOL_CALL, f"{at} tool call")
            if not c.get("tool_call_id") or not c.get("function_name"):
                wrong.append(f"{at}: a tool call needs tool_call_id and function_name")
            if not isinstance(c.get("arguments"), dict):
                wrong.append(f"{at}: a tool call's arguments must be an object")
        wrong += _undeclared(step.get("metrics") or {}, METRICS, f"{at} metrics")
        observation = step.get("observation")
        if observation is not None:
            wrong += _undeclared(observation, ("results",), f"{at} observation")
            ids = {c.get("tool_call_id") for c in calls}
            for r in observation.get("results") or []:
                wrong += _undeclared(r, RESULT, f"{at} result")
                if r.get("source_call_id") is not None and r["source_call_id"] not in ids:
                    wrong.append(
                        f"{at}: a result answers {r['source_call_id']!r}, not a call of it"
                    )
    return wrong


# ── a harness's own log, for a transcript without turns ──────────────────────
def from_claude_stream(path):
    """(turn rows, {call id: output}) from a Claude Code stream-json log: what
    its launcher now puts on the transcript as it reads the stream, for a run
    played before it did."""
    turns, outputs, events, at = {}, {}, [], None
    for ev in _read_jsonl(path):
        if not isinstance(ev, dict):
            continue
        stamp = ev.get("timestamp")
        if isinstance(stamp, str):
            at = datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
        msg = ev.get("message") or {}
        blocks = [b for b in msg.get("content") or [] if isinstance(b, dict)]
        if ev.get("type") == "assistant" and msg.get("id") and msg.get("model") != SYNTHETIC:
            fresh = {"kind": "player_turn", "t": at, "model": msg.get("model"), "text": ""}
            fresh |= {"message_id": msg["id"], "tool_calls": [], "usage_metadata": {}}
            turn = turns.setdefault(msg["id"], fresh | {"thinking_blocks": 0})
            for b in blocks:
                if b.get("type") == "text":
                    turn["text"] = "\n".join(filter(None, [turn["text"], b.get("text") or ""]))
                elif b.get("type") == "thinking":
                    turn["thinking_blocks"] += 1
                elif b.get("type") == "tool_use":
                    name = (b.get("name") or "").removeprefix(SEAT_PREFIX)
                    turn["tool_calls"].append({"id": b.get("id"), "name": name, "args": b["input"]})
            for k, n in (msg.get("usage") or {}).items():
                if isinstance(n, int) and not isinstance(n, bool):
                    turn["usage_metadata"][k] = max(n, turn["usage_metadata"].get(k, 0))
        elif ev.get("type") == "user":
            for b in blocks:
                if b.get("type") == "tool_result":
                    content = b.get("content")
                    if isinstance(content, list):
                        content = "\n".join(p.get("text") or "" for p in content if "text" in p)
                    outputs[b.get("tool_use_id")] = content
        elif str(ev.get("subtype") or "").startswith("model_refusal"):
            event = {"kind": "player_event", "t": at}
            events.append(event | {"what": "refusal", "category": ev.get("api_refusal_category")})
            was, now = ev.get("original_model"), ev.get("fallback_model")
            if now and now != was:
                events.append(event | {"what": "model_change", "was": was, "now": now})
    return list(turns.values()) + events, outputs


# ── a run ────────────────────────────────────────────────────────────────────
def _run_id(out_dir):
    try:
        with open(os.path.join(out_dir, "run.json")) as f:
            return json.load(f).get("run_id")
    except (OSError, ValueError):
        return os.path.basename(os.path.normpath(out_dir))


def write(out_dir, cards=None, harness_logs=None):
    """Write trajectory-<team>.json for every player of the run in ``out_dir``;
    -> {team: path}. A document the format would refuse is not written: a file
    that another tool rejects is worse than none, and the error says why."""
    written = {}
    for path in sorted(glob.glob(os.path.join(out_dir, "player-*.jsonl"))):
        team = os.path.basename(path)[len("player-") : -len(".jsonl")]
        rows, outputs = _read_jsonl(path), {}
        log = (harness_logs or {}).get(team)
        if log and not any(r.get("kind") == "player_turn" for r in rows):
            more, outputs = from_claude_stream(log)
            rows = rows + more
        doc = build(rows, _run_id(out_dir), team, (cards or {}).get(team), outputs)
        wrong = check(doc)
        if wrong:
            raise ValueError(f"the trajectory of {team} is not valid ATIF: " + "; ".join(wrong[:5]))
        written[team] = os.path.join(out_dir, FILE.format(team=team))
        with open(written[team], "w") as f:
            json.dump(doc, f, indent=1)
    return written


def main():
    ap = argparse.ArgumentParser(description="Write each player's ATIF trajectory of a run")
    ap.add_argument("out_dir", help="one run's directory")
    ap.add_argument(
        "--harness-log",
        action="append",
        default=[],
        metavar="TEAM=FILE",
        help="a Claude Code stream to take turns and outputs from, for an older transcript",
    )
    args = ap.parse_args()
    cards = {}
    try:
        with open(os.path.join(args.out_dir, "metrics.json")) as f:
            cards = json.load(f).get("players") or {}
    except (OSError, ValueError):
        pass
    logs = dict(item.split("=", 1) for item in args.harness_log)
    for team, path in write(args.out_dir, cards, logs).items():
        print(f"{team}: {path}")


if __name__ == "__main__":
    main()
