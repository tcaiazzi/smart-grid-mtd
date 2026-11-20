"""orders.py — what a menu entry of the module orders, decided from the entry's
name and the object it was chosen on. No IRIS import: the decision is tested
where IRIS does not run.

The SOC files one task per countermeasure in the case (its catalogue), tagged
``catalog`` and the countermeasure's id; an order is a task tagged ``order``,
which the SOC reads and closes.
"""

TAG = "cps-soc"
APPLY, REVERT = "SOC: apply this countermeasure", "SOC: revert this countermeasure"
AUTO, ADVISE = "SOC: act alone (automatic)", "SOC: advise (wait for approval)"
# (IRIS hook, menu entry): the entries on a task, and on the case.
ENTRIES = [
    ("on_manual_trigger_task", APPLY),
    ("on_manual_trigger_task", REVERT),
    ("on_manual_trigger_case", AUTO),
    ("on_manual_trigger_case", ADVISE),
]


def tags_of(text):
    return [t.strip() for t in (text or "").split(",") if t.strip()]


def countermeasure_of(tags):
    """The countermeasure a catalogue or suggestion task stands for: the tag
    after the scenario's own, or None for a task the SOC did not file."""
    tags = tags_of(tags) if isinstance(tags, str) else list(tags)
    if TAG not in tags or "order" in tags:
        return None
    rest = [t for t in tags if t not in (TAG, "catalog")]
    return rest[0] if rest else None


def order_of(entry, task_tags=None):
    """(title, tags) of the order task a menu ``entry`` files, chosen on a task
    tagged ``task_tags`` (or on the case, for the mode entries); None when the
    entry does not apply there."""
    if entry in (APPLY, REVERT):
        cm = countermeasure_of(task_tags or "")
        if cm is None:
            return None
        op = "apply" if entry == APPLY else "revert"
        return f"Order: {op} {cm}", [TAG, "order", op, cm]
    if entry in (AUTO, ADVISE):
        mode = "auto" if entry == AUTO else "advise"
        return f"Order: SOC to {'automatic' if mode == 'auto' else 'advise'}", [
            TAG,
            "order",
            "mode",
            mode,
        ]
    return None


def parse_order(tags):
    """The order a task tagged ``tags`` carries, as the SOC's desk takes orders
    ({"kind": "countermeasure", "id", "op"} or {"kind": "mode", "mode"}, with the
    IRIS login that filed it as "operator"), or None if it is not one."""
    tags = tags_of(tags) if isinstance(tags, str) else list(tags)
    if TAG not in tags or "order" not in tags:
        return None
    who = next((t[3:] for t in tags if t.startswith("by:")), None)
    rest = [t for t in tags if t not in (TAG, "order") and not t.startswith("by:")]
    if len(rest) >= 2 and rest[0] in ("apply", "revert"):
        return {"kind": "countermeasure", "op": rest[0], "id": rest[1], "operator": who}
    if len(rest) >= 2 and rest[0] == "mode" and rest[1] in ("auto", "advise"):
        return {"kind": "mode", "mode": rest[1], "operator": who}
    return None
