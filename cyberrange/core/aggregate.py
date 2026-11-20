"""aggregate.py — campaign statistics common to every scenario.

``summarize(rows, by)`` groups per-run metric dicts (``rows`` = [{"metrics": {...},
<label fields>}]) and reports, for every numeric leaf metric (nested dicts are
flattened as ``a.b.c``; booleans count as 0/1, i.e. a rate), n / mean / std /
95% confidence interval (Student t) / median / min / max. Missing values (None,
NaN) are left out of that metric's n, so a latency is averaged over the runs
that detected.
"""

import csv
import math
import os

# Two-sided 95% Student t critical values, df = 1..30 (then the normal 1.96).
_T95 = [
    12.706,
    4.303,
    3.182,
    2.776,
    2.571,
    2.447,
    2.365,
    2.306,
    2.262,
    2.228,
    2.201,
    2.179,
    2.160,
    2.145,
    2.131,
    2.120,
    2.110,
    2.101,
    2.093,
    2.086,
    2.080,
    2.074,
    2.069,
    2.064,
    2.060,
    2.056,
    2.052,
    2.048,
    2.045,
    2.042,
]


def t95(df):
    return _T95[df - 1] if 1 <= df <= len(_T95) else 1.96


def flatten(d, prefix=""):
    """{"a": {"b": 1}, "c": True} -> {"a.b": 1.0, "c": 1.0} (numeric leaves only)."""
    out = {}
    for k, v in (d or {}).items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, key + "."))
        elif isinstance(v, bool):
            out[key] = 1.0 if v else 0.0
        elif isinstance(v, (int, float)):
            if not (isinstance(v, float) and math.isnan(v)):
                out[key] = float(v)
    return out


def stats(xs):
    n = len(xs)
    if n == 0:
        return {
            "n": 0,
            "mean": None,
            "std": None,
            "ci95_low": None,
            "ci95_high": None,
            "median": None,
            "min": None,
            "max": None,
        }
    mean = sum(xs) / n
    std = math.sqrt(sum((x - mean) ** 2 for x in xs) / (n - 1)) if n > 1 else 0.0
    half = t95(n - 1) * std / math.sqrt(n) if n > 1 else 0.0
    s = sorted(xs)
    med = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2

    def r(x):
        return round(x, 6)

    return {
        "n": n,
        "mean": r(mean),
        "std": r(std),
        "ci95_low": r(mean - half),
        "ci95_high": r(mean + half),
        "median": r(med),
        "min": r(s[0]),
        "max": r(s[-1]),
    }


def summarize(rows, by=("group",), include=None, exclude=("run.",)):
    """[{**group fields, "metric", n, mean, std, ci95_low, ci95_high, median, min, max}]
    per group (``by`` label fields) x metric. ``include`` (prefixes) narrows the
    metrics; ``exclude`` (prefixes) drops bookkeeping ones."""
    groups = {}
    for row in rows:
        key = tuple(row.get(b) for b in by)
        groups.setdefault(key, []).append(flatten(row.get("metrics")))
    out = []
    for key in sorted(groups, key=lambda k: tuple(str(x) for x in k)):
        flat = groups[key]
        names = sorted({m for f in flat for m in f})
        for name in names:
            if include and not name.startswith(tuple(include)):
                continue
            if exclude and name.startswith(tuple(exclude)):
                continue
            xs = [f[name] for f in flat if name in f]
            out.append({**dict(zip(by, key)), "metric": name, **stats(xs)})
    return out


def write_csv(path, table):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    cols = []
    for r in table:
        cols += [c for c in r if c not in cols]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(table)
    return path


def format_markdown(table, by=("group",), metrics=None):
    """Mean [95% CI] (n) per group x metric, one row per group."""
    if not table:
        return "_no scored runs yet_\n"
    names = metrics or sorted({r["metric"] for r in table})
    groups = []
    for r in table:
        g = tuple(r.get(b) for b in by)
        if g not in groups:
            groups.append(g)
    cell = {(tuple(r.get(b) for b in by), r["metric"]): r for r in table}
    lines = ["| " + " | ".join(list(by) + names) + " |", "|" + "---|" * (len(by) + len(names))]
    for g in groups:
        vals = []
        for n in names:
            r = cell.get((g, n))
            if not r or r["n"] == 0:
                vals.append("—")
            elif r["n"] == 1:
                vals.append(f"{r['mean']:.3g} (1)")
            else:
                vals.append(
                    f"{r['mean']:.3g} [{r['ci95_low']:.3g}, {r['ci95_high']:.3g}] ({r['n']})"
                )
        lines.append("| " + " | ".join([str(x) for x in g] + vals) + " |")
    return "\n".join(lines) + "\n"
