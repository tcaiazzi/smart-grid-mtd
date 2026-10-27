"""Train the delivery-attack detector and report its KPIs.

Input: output/detector/windows.csv (monitor/delivery_dataset.py) — one row per 1 s
window per SCMC with every delivery_detector.FEATURES column, the threshold-rule
decision and the ground-truth label (blackhole in effect).

Runs are split by seed into a DEVELOPMENT set and a held-out TEST set. Everything that
is tuned — feature set, network size, smoothing, threshold — is chosen on the dev set
only; the test set is scored once, by `--mode final`, so its numbers are honest.

  --mode dev     cross-validates on the dev runs, BY RUN (windows of one run are never
                 split between training and test: adjacent windows are near-duplicates).
                 With --ablation it compares feature sets, sizes, smoothing and a
                 gradient-boosting reference -> ablation.md.
  --mode final   fits the chosen configuration on all dev runs, with the threshold set
                 to the median of the per-fold thresholds of a dev cross-validation,
                 scores the test runs -> kpi.md / kpi.csv / predictions.csv, and exports
                 detector.npz for LiveDetector (checked to match sklearn exactly).

Within each fit, the threshold is chosen on validation runs held out from the fitted
ones: highest F1 with Precision >= 0.9 when reachable.

Reported, for the MLP and the threshold rule:
  • window-level Accuracy, Precision, Recall, F1 — the headline KPIs — pooled and as a
    mean with 95% bootstrap CI over runs;
  • a SECONDARY, declared variant excluding the first 2 s of each attack episode (a
    blackhole can't be told from a normal gap before a few silent publish intervals);
  • episode-level: share of episodes raised as an alert (LiveDetector's hysteresis),
    detection delay, false alerts per hour;
  • breakdowns by coordinator, attacker and benign fault.

Usage:
  python -m defense_plane.train_delivery_detector --mode dev --ablation
  python -m defense_plane.train_delivery_detector --mode final --features v2h --hidden 16,16 --smoothing 2of3
"""

import argparse
import os

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

from defense_plane.delivery_detector import (FEATURE_SETS, LiveDetector, NumpyDetector,
                                             NumpyTreeDetector, load_detector, smooth)

KPI_TARGET = {"accuracy": 0.90, "precision": 0.90, "recall": 0.85, "f1": 0.85}
MIN_PRECISION = 0.90
EARLY_S = 2.0            # secondary metric: drop the first EARLY_S of each episode


class Config:
    """What is being trained: feature set, MLP size, k-of-n smoothing, model kind."""

    def __init__(self, features="v2h", hidden=(16, 16), smoothing=(1, 1), kind="mlp"):
        self.features, self.hidden = features, tuple(hidden)
        self.smoothing, self.kind = tuple(smoothing), kind

    @property
    def columns(self) -> list:
        return FEATURE_SETS[self.features]

    def __str__(self):
        size = "x".join(map(str, self.hidden)) if self.kind == "mlp" else "hgb"
        k, n = self.smoothing
        return f"{self.features} {size} {'raw' if n == 1 else f'{k}of{n}'}"


def fit(df: pd.DataFrame, cfg: Config, seed: int):
    """StandardScaler + model on df, positives oversampled to balance the classes."""
    X, y = df[cfg.columns].to_numpy(np.float64), df["label"].to_numpy()
    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)
    pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    rng = np.random.default_rng(seed)
    if 0 < len(pos) < len(neg):
        pos = rng.choice(pos, size=len(neg), replace=True)
    idx = rng.permutation(np.concatenate([pos, neg]))
    if cfg.kind == "hgb":
        clf = HistGradientBoostingClassifier(random_state=seed)
    else:
        clf = MLPClassifier(hidden_layer_sizes=cfg.hidden, activation="relu", max_iter=400,
                            random_state=seed)
    return scaler, clf.fit(Xs[idx], y[idx]), cfg


def proba(model, df: pd.DataFrame) -> np.ndarray:
    scaler, clf, cfg = model
    return clf.predict_proba(scaler.transform(df[cfg.columns].to_numpy(np.float64)))[:, 1]


def decide(df: pd.DataFrame, p: np.ndarray, threshold: float, cfg: Config) -> np.ndarray:
    """Per-window decisions: threshold, then the config's k-of-n smoothing along each
    (run, SCMC) time series — exactly what LiveDetector does."""
    k, n = cfg.smoothing
    if n <= 1:
        return (p >= threshold).astype(int)
    out = np.zeros(len(df), dtype=int)
    hits = pd.Series(p >= threshold, index=df.index)
    for _, idx in df.groupby(["run", "scmc_id"]).groups.items():
        order = df.loc[idx, "t"].sort_values().index
        out[df.index.get_indexer(order)] = smooth(hits.loc[order].to_numpy(), k, n)
    return out


def pick_threshold(df: pd.DataFrame, p: np.ndarray, cfg: Config) -> float:
    """Highest-F1 threshold among those keeping Precision >= MIN_PRECISION (highest
    F1 overall if none does), on decisions after smoothing."""
    y = df["label"].to_numpy()
    best, best_ok = (0.0, 0.5), (0.0, None)
    for th in np.linspace(0.05, 0.95, 91):
        pred = decide(df, p, th, cfg)
        f1 = f1_score(y, pred, zero_division=0)
        if f1 > best[0]:
            best = (f1, th)
        if precision_score(y, pred, zero_division=0) >= MIN_PRECISION and f1 > best_ok[0]:
            best_ok = (f1, th)
    return float(best_ok[1] if best_ok[1] is not None else best[1])


def fit_with_threshold(df: pd.DataFrame, cfg: Config, seed: int):
    """Fit on ~80% of df's runs, choose the threshold on the other ~20%."""
    runs = list(np.random.default_rng(seed).permutation(sorted(df["run"].unique())))
    n_val = max(1, int(round(len(runs) * 0.2)))
    val_runs, fit_runs = runs[:n_val], runs[n_val:] or runs[:n_val]
    model = fit(df[df["run"].isin(fit_runs)], cfg, seed)
    val = df[df["run"].isin(val_runs)]
    return model, pick_threshold(val, proba(model, val), cfg)


def cross_validate(df: pd.DataFrame, cfg: Config, folds: int, seed: int, quiet=False):
    """Out-of-fold scores for every window (columns p, threshold, pred) and the
    per-fold thresholds."""
    runs = np.random.default_rng(seed).permutation(sorted(df["run"].unique()))
    folds = max(2, min(folds, len(runs)))
    parts, thresholds = [], []
    for k in range(folds):
        test_runs = set(runs[k::folds])
        train, test = df[~df["run"].isin(test_runs)], df[df["run"].isin(test_runs)].copy()
        model, th = fit_with_threshold(train, cfg, seed + k)
        test["p"] = proba(model, test)
        test["threshold"] = th
        test["pred"] = decide(test, test["p"].to_numpy(), th, cfg)
        parts.append(test)
        thresholds.append(th)
        if not quiet:
            print(f"[detector] {cfg} fold {k + 1}/{folds}: {len(test_runs)} test runs, "
                  f"threshold {th:.2f}")
    return pd.concat(parts).sort_values(["run", "scmc_id", "t"]), thresholds


# ── metrics ───────────────────────────────────────────────────────────────────

def window_metrics(y, pred) -> dict:
    return {"accuracy": accuracy_score(y, pred),
            "precision": precision_score(y, pred, zero_division=0),
            "recall": recall_score(y, pred, zero_division=0),
            "f1": f1_score(y, pred, zero_division=0),
            "windows": len(y), "positives": int(np.sum(y))}


def run_ci(df: pd.DataFrame, col: str, seed: int, n_boot: int = 2000) -> dict:
    """Mean and 95% bootstrap CI over runs of each window metric. Precision, Recall
    and F1 only over runs that had an attack in effect (undefined otherwise)."""
    per_run = [window_metrics(g["label"].to_numpy(), g[col].to_numpy())
               for _, g in df.groupby("run")]
    out = {}
    rng = np.random.default_rng(seed)
    for m in KPI_TARGET:
        vals = np.array([r[m] for r in per_run if m == "accuracy" or r["positives"]])
        if not len(vals):
            continue
        boots = [rng.choice(vals, len(vals)).mean() for _ in range(n_boot)]
        out[m] = (vals.mean(), np.percentile(boots, 2.5), np.percentile(boots, 97.5))
    return out


def episode_start_offset(df: pd.DataFrame) -> pd.Series:
    """Seconds since the start of the attack episode a positive window belongs to
    (NaN for negative windows)."""
    out = pd.Series(np.nan, index=df.index)
    for _, g in df.groupby(["run", "scmc_id"]):
        g = g.sort_values("t")
        start = None
        for i, (t, y) in zip(g.index, zip(g["t"], g["label"])):
            if y == 1:
                start = t if start is None else start
                out[i] = t - start
            else:
                start = None
    return out


def alerts(pred: np.ndarray) -> np.ndarray:
    """LiveDetector's alert state from per-window hits (raise after 2, clear after 3)."""
    state, above, below, out = False, 0, 0, []
    for h in pred:
        above, below = (above + 1, 0) if h else (0, below + 1)
        if not state and above >= LiveDetector.RAISE:
            state = True
        elif state and below >= LiveDetector.CLEAR:
            state = False
        out.append(state)
    return np.array(out, dtype=bool)


def episode_metrics(df: pd.DataFrame, col: str) -> dict:
    """Attack episodes (runs of label=1) caught by an alert, the delay to it, and
    alerts raised outside any episode per hour of attack-free time."""
    found, delays, false_alerts, clean_s = 0, [], 0, 0.0
    n_episodes = 0
    for _, g in df.groupby(["run", "scmc_id"]):
        g = g.sort_values("t")
        t, y = g["t"].to_numpy(), g["label"].to_numpy()
        a = alerts(g[col].to_numpy())
        raised = np.flatnonzero(a & ~np.r_[False, a[:-1]])
        clean_s += float(np.sum(y == 0))
        false_alerts += sum(1 for i in raised if y[i] == 0)
        starts = np.flatnonzero((y == 1) & ~np.r_[False, y[:-1] == 1])
        for s in starts:
            e = s
            while e + 1 < len(y) and y[e + 1] == 1:
                e += 1
            n_episodes += 1
            hit = np.flatnonzero(a[s:e + 1])
            if len(hit):
                found += 1
                delays.append(t[s + hit[0]] - t[s])
    return {"episodes": n_episodes,
            "episode_recall": found / n_episodes if n_episodes else float("nan"),
            "delay_median_s": float(np.median(delays)) if delays else float("nan"),
            "delay_p95_s": float(np.percentile(delays, 95)) if delays else float("nan"),
            "false_alerts_per_h": false_alerts / (clean_s / 3600) if clean_s else float("nan")}


def evaluate(df: pd.DataFrame, seed: int) -> pd.DataFrame:
    """KPI rows per scope (all / breakdowns / secondary) and model (mlp / rule)."""
    rows = []
    offset = episode_start_offset(df)
    scopes = [("all", df), (f"secondary: without first {EARLY_S:.0f} s of episodes",
                            df[~(offset < EARLY_S)])]
    for col in ("variant", "attack", "fault"):
        for v, g in df.groupby(col):
            scopes.append((f"{col}={v or 'none'}", g))
    for name, g in scopes:
        # Fault scopes are scattered windows, not whole runs: no episodes there.
        whole_runs = name == "all" or name.startswith(("variant", "attack"))
        for model, col in (("mlp", "pred"), ("rule", "rule")):
            rows.append({"scope": name, "model": model, "runs": g["run"].nunique(),
                         **window_metrics(g["label"].to_numpy(), g[col].to_numpy()),
                         **(episode_metrics(g, col) if whole_runs else {})})
    return pd.DataFrame(rows)


def pct(x):
    return "—" if pd.isna(x) else f"{100 * x:.1f}%"


def write_report(kpi: pd.DataFrame, ci: dict, path: str, provenance: str, cfg: Config,
                 threshold: float) -> None:
    allm = kpi[(kpi.scope == "all") & (kpi.model == "mlp")].iloc[0]
    allr = kpi[(kpi.scope == "all") & (kpi.model == "rule")].iloc[0]
    sec = kpi[kpi.scope.str.startswith("secondary") & (kpi.model == "mlp")].iloc[0]
    lines = ["# Delivery-attack detector — KPI report", "", provenance, "",
             f"Model: `{cfg}` (threshold {threshold:.2f}).", "",
             "## KPI (all test windows, 1 s per SCMC)", "",
             "| Metric | Target | Model | Model mean over runs [95% CI] | Threshold rule |",
             "|---|---|---|---|---|"]
    for m, target in KPI_TARGET.items():
        ok = "✅" if allm[m] > target else "❌"
        c = ci.get(m)
        cis = f"{pct(c[0])} [{pct(c[1])}, {pct(c[2])}]" if c else "—"
        lines.append(f"| {m.capitalize()} | > {target:.0%} | {pct(allm[m])} {ok} | {cis} | {pct(allr[m])} |")
    lines += ["", f"Secondary (declared): the same windows without the first {EARLY_S:.0f} s of each "
              "attack episode — a blackhole can't be told from a normal gap before a few silent "
              f"publish intervals. Accuracy {pct(sec.accuracy)}, Precision {pct(sec.precision)}, "
              f"Recall {pct(sec.recall)}, F1 {pct(sec.f1)}.",
              "", "## Episodes", "",
              "| | Model | Threshold rule |", "|---|---|---|",
              f"| Attack episodes | {int(allm['episodes'])} | {int(allr['episodes'])} |",
              f"| Raised as an alert | {pct(allm['episode_recall'])} | {pct(allr['episode_recall'])} |",
              f"| Detection delay, median / p95 | {allm['delay_median_s']:.1f} s / {allm['delay_p95_s']:.1f} s"
              f" | {allr['delay_median_s']:.1f} s / {allr['delay_p95_s']:.1f} s |",
              f"| False alerts per hour | {allm['false_alerts_per_h']:.2f} | {allr['false_alerts_per_h']:.2f} |",
              "", "## Breakdown (model)", "",
              "| Scope | Runs | Windows | Positives | Accuracy | Precision | Recall | F1 |",
              "|---|---|---|---|---|---|---|---|"]
    for _, r in kpi[(kpi.model == "mlp") & (kpi.scope != "all")
                    & ~kpi.scope.str.startswith("secondary")].iterrows():
        lines.append(f"| {r.scope} | {r.runs} | {r.windows} | {r.positives} | {pct(r.accuracy)} | "
                     f"{pct(r.precision) if r.positives else '—'} | "
                     f"{pct(r.recall) if r.positives else '—'} | {pct(r.f1) if r.positives else '—'} |")
    lines += ["", "Windows during benign faults (`fault=...`) carry attack windows too when a "
              "blackhole overlaps them; a scope without positives only measures false positives "
              "(Accuracy = 1 − false-positive rate).", ""]
    with open(path, "w") as f:
        f.write("\n".join(lines))


def tree_arrays(clf) -> dict:
    """Flatten a binary HistGradientBoostingClassifier into NumpyTreeDetector's
    arrays (global node indices, one root per tree)."""
    nodes = [pred.nodes for (pred,) in clf._predictors]
    if any(n["is_categorical"].any() for n in nodes):
        raise ValueError("categorical splits are not supported by NumpyTreeDetector")
    roots, offset, parts = [], 0, []
    for n in nodes:
        roots.append(offset)
        parts.append((n["feature_idx"], n["num_threshold"], n["left"] + offset,
                      n["right"] + offset, n["is_leaf"], n["value"]))
        offset += len(n)
    cat = [np.concatenate([p[i] for p in parts]) for i in range(6)]
    return {"baseline": float(np.ravel(clf._baseline_prediction)[0]), "roots": np.array(roots),
            "feature": cat[0].astype(int), "thr": cat[1], "left": cat[2].astype(int),
            "right": cat[3].astype(int), "leaf": cat[4].astype(bool), "value": cat[5]}


def export(model, threshold: float, path: str, check: pd.DataFrame) -> None:
    scaler, clf, cfg = model
    if cfg.kind == "hgb":
        det = NumpyTreeDetector(scaler.mean_, scaler.scale_, threshold=threshold,
                                features=cfg.columns, smoothing=cfg.smoothing,
                                **tree_arrays(clf))
    else:
        det = NumpyDetector(scaler.mean_, scaler.scale_, list(clf.coefs_),
                            list(clf.intercepts_), threshold, cfg.columns, cfg.smoothing)
    det.save(path)
    loaded = load_detector(path)
    diff = np.max(np.abs(loaded.proba(check[cfg.columns].to_numpy(np.float64)) - proba(model, check)))
    assert diff < 1e-6, f"numpy detector disagrees with sklearn (max |Δp| = {diff})"
    print(f"[detector] exported {path} ({cfg}, threshold {threshold:.2f}, numpy == sklearn, "
          f"max |Δp| {diff:.1e})")


# ── modes ─────────────────────────────────────────────────────────────────────

ABLATION = [Config("v1"), Config("v2"), Config("v2h"), Config("v2h", (32, 32)),
            Config("v2h", smoothing=(2, 3)),
            Config("v1", kind="hgb"), Config("v2", kind="hgb"), Config("v2h", kind="hgb"),
            Config("v2h", smoothing=(2, 3), kind="hgb")]


def ablation(dev: pd.DataFrame, folds: int, seed: int, out_dir: str) -> None:
    lines = ["# Detector ablation (dev runs only, cross-validated by run)", "",
             f"{dev['run'].nunique()} dev runs, {len(dev)} windows. Choose here; score the test "
             "set once with `--mode final`. hgb = gradient-boosted trees (sklearn defaults), "
             "exported to numpy like the MLP.", "",
             "| Config | Accuracy | Precision | Recall | F1 | F1 w/o first 2 s | Episodes alerted "
             "| Delay median | False alerts/h | Fold thresholds |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for cfg in ABLATION:
        scored, ths = cross_validate(dev, cfg, folds, seed, quiet=True)
        kpi = evaluate(scored, seed)
        m = kpi[(kpi.scope == "all") & (kpi.model == "mlp")].iloc[0]
        sec = kpi[kpi.scope.str.startswith("secondary") & (kpi.model == "mlp")].iloc[0]
        row = (f"| {cfg} | {pct(m.accuracy)} | {pct(m.precision)} | {pct(m.recall)} | {pct(m.f1)} "
               f"| {pct(sec.f1)} | {pct(m.episode_recall)} | {m.delay_median_s:.1f} s "
               f"| {m.false_alerts_per_h:.1f} | {', '.join(f'{t:.2f}' for t in ths)} |")
        print(row)
        lines.append(row)
    rule = kpi[(kpi.scope == "all") & (kpi.model == "rule")].iloc[0]
    lines += [f"| threshold rule | {pct(rule.accuracy)} | {pct(rule.precision)} | "
              f"{pct(rule.recall)} | {pct(rule.f1)} | — | {pct(rule.episode_recall)} | "
              f"{rule.delay_median_s:.1f} s | {rule.false_alerts_per_h:.1f} | — |", ""]
    with open(os.path.join(out_dir, "ablation.md"), "w") as f:
        f.write("\n".join(lines))
    print(f"[detector] -> {os.path.join(out_dir, 'ablation.md')}")


def seeds_arg(text: str) -> set:
    """'1,2,3' or '4-10' or a mix."""
    out = set()
    for part in filter(None, (p.strip() for p in text.split(","))):
        a, _, b = part.partition("-")
        out.update(range(int(a), int(b or a) + 1))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data", default="output/detector/windows.csv")
    ap.add_argument("--out-dir", default="output/detector")
    ap.add_argument("--mode", choices=("dev", "final"), default="dev")
    ap.add_argument("--dev-seeds", default="1-3")
    ap.add_argument("--test-seeds", default="4-10")
    ap.add_argument("--ablation", action="store_true", help="dev mode: compare configurations")
    ap.add_argument("--model", choices=("mlp", "hgb"), default="mlp")
    ap.add_argument("--features", choices=sorted(FEATURE_SETS), default="v2h")
    ap.add_argument("--hidden", default="16,16", help="MLP hidden layer sizes")
    ap.add_argument("--smoothing", default="1of1", help="k-of-n decision smoothing, e.g. 2of3")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    k, _, n = args.smoothing.partition("of")
    cfg = Config(args.features, tuple(int(h) for h in args.hidden.split(",")), (int(k), int(n)),
                 args.model)
    df = pd.read_csv(args.data, keep_default_na=False, na_values=[""])
    df["fault"] = df["fault"].fillna("")
    dev_seeds, test_seeds = seeds_arg(args.dev_seeds), seeds_arg(args.test_seeds)
    if dev_seeds & test_seeds:
        raise SystemExit("dev and test seeds overlap")
    dev, test = df[df["seed"].isin(dev_seeds)], df[df["seed"].isin(test_seeds)]
    print(f"[detector] dev: {dev['run'].nunique()} runs (seeds {sorted(dev_seeds)}), "
          f"test: {test['run'].nunique()} runs (seeds {sorted(test_seeds)})")
    if dev["run"].nunique() < 2:
        raise SystemExit("need at least 2 dev runs to cross-validate by run")
    os.makedirs(args.out_dir, exist_ok=True)

    if args.mode == "dev":
        if args.ablation:
            ablation(dev, args.folds, args.seed, args.out_dir)
            return
        scored, ths = cross_validate(dev, cfg, args.folds, args.seed)
        kpi = evaluate(scored, args.seed)
        provenance = (f"DEV cross-validation: {dev['run'].nunique()} runs (seeds "
                      f"{sorted(dev_seeds)}), {len(dev)} windows, by run. Not the test set.")
        write_report(kpi, run_ci(scored, "pred", args.seed),
                     os.path.join(args.out_dir, "kpi_dev.md"), provenance, cfg, float(np.median(ths)))
        print(open(os.path.join(args.out_dir, "kpi_dev.md")).read())
        return

    if test.empty:
        raise SystemExit("no test runs: run the campaign for the test seeds first")
    _, ths = cross_validate(dev, cfg, args.folds, args.seed)
    threshold = float(np.median(ths))
    model = fit(dev, cfg, args.seed)
    scored = test.copy()
    scored["p"] = proba(model, scored)
    scored["threshold"] = threshold
    scored["pred"] = decide(scored, scored["p"].to_numpy(), threshold, cfg)
    kpi = evaluate(scored, args.seed)
    provenance = (f"Trained on {dev['run'].nunique()} DEV runs (seeds {sorted(dev_seeds)}); "
                  f"threshold = median of {len(ths)} dev-fold thresholds; scored ONCE on "
                  f"{test['run'].nunique()} held-out TEST runs (seeds {sorted(test_seeds)}), "
                  f"{len(test)} windows.")
    scored.to_csv(os.path.join(args.out_dir, "predictions.csv"), index=False)
    kpi.to_csv(os.path.join(args.out_dir, "kpi.csv"), index=False)
    write_report(kpi, run_ci(scored, "pred", args.seed), os.path.join(args.out_dir, "kpi.md"),
                 provenance, cfg, threshold)
    export(model, threshold, os.path.join(args.out_dir, "detector.npz"),
           dev.sample(min(len(dev), 2000), random_state=0))
    print(open(os.path.join(args.out_dir, "kpi.md")).read())


if __name__ == "__main__":
    main()
