"""cps_metrics.py — scores one cyber-physical scenario run from its downloaded
artifacts (doc "Cosa si misura"): detection on the cyber side, impact on the
physical side. Reads three host-clock logs produced by cps_experiment:

  - engine frames   (<out>/engine.engine_frames.jsonl): per-step physics (+ ctrl_mode)
  - sensor telemetry(<out>/sensor.telemetry.jsonl):     findings/alerts (per detector)
  - ground truth    (<out>/ground_truth.jsonl):         attack window + real write times

Detection, per detector ("rules", "model") and "combined":
  - detected / detection_latency_s : first finding at/after the attack start
  - latency_from_write_s           : … measured from the first malicious write
  - before_impact                  : flagged before the physics went abnormal
  - false_alarms                   : findings during the normal phase, and how many
                                     of them fell inside a legitimate operator
                                     (MANUAL) window
Impact, measured on the plant (independent of the attacker's knobs):
  - time_to_impact_s       : first malicious write -> first abnormal frame
  - impact_duration_s      : first -> last abnormal frame (+ one step)
  - impact_ongoing_at_end  : the plant is still abnormal at the end of the run
  - recovered / recovery_s : came back in band, and how long after the impact began
  - manual_mode_s          : time control authority spent in MANUAL after the attack
  - mitigated_s (MTM)      : first malicious write -> the plant is back in band for
                             good (None while the impact persists)
  - max_abs_deviation_pu / v range / energy
Response (only when <out>/response.jsonl exists — the SOAR prototype):
  - policy, decisions, explained_decisions (coverage of the justification)
  - decision_latency_s     : first finding of the attack -> first countermeasure done
  - actions / failed_actions, expected_actions, accurate (expected ⊆ applied),
    over_response (applied − expected)
  - attacker_writes_after_block : malicious writes that still succeeded after
                             the boundary block took effect
  - false_responses        : countermeasures before the attack (or in a normal run)
  - hmi_unavailable_s      : operator HMI cut off by the response

Run: `python -m monitor.cps_metrics --out-dir output/cps/run-1`.
"""

import argparse
import glob
import json
import os

V_BAND_LOW, V_BAND_HIGH = 0.95, 1.05
V_NOMINAL = 1.0


def _read_jsonl(path):
    if not path or not os.path.exists(path):
        return []
    out = []
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def _find(out_dir, *names):
    for n in names:
        p = os.path.join(out_dir, n)
        if os.path.exists(p):
            return p
    # last resort: glob
    for n in names:
        hits = glob.glob(os.path.join(out_dir, "*" + n))
        if hits:
            return hits[0]
    return None


DETECTORS = ("rules", "model")
SLACK_S = 1.0   # clock slack between guest and host timestamps


def _detector(e):
    return e.get("detector") or "rules"   # pre-v2 runs only had rules


def _manual_windows(frames, dt):
    """[(t_start, t_end)] spans where the frames report ctrl_mode == MANUAL."""
    spans, cur = [], None
    for fr in frames:
        manual = int((fr.get("actuators") or {}).get("ctrl_mode", fr.get("ctrl_mode", 0)) or 0) == 1
        t = fr.get("timestamp", 0)
        if manual and cur is None:
            cur = [t, t]
        elif manual:
            cur[1] = t
        elif cur is not None:
            spans.append((cur[0], cur[1] + dt))
            cur = None
    if cur is not None:
        spans.append((cur[0], cur[1] + dt))
    return spans


def _detection(findings, attack_start, first_write, first_abnormal, manual_spans):
    if attack_start is None:
        fa = findings
        hits = []
    else:
        fa = [e for e in findings if e["t"] < attack_start - SLACK_S]
        hits = [e["t"] for e in findings if e["t"] >= attack_start - SLACK_S]
    first = min(hits) if hits else None
    in_op = sum(1 for e in fa if any(a - SLACK_S <= e["t"] <= b + SLACK_S for a, b in manual_spans))
    return {
        "detected": bool(hits),
        "findings": len(findings),
        "detection_latency_s": round(first - attack_start, 3) if first is not None else None,
        "latency_from_write_s": (round(first - first_write, 3)
                                 if first is not None and first_write is not None else None),
        "before_impact": (first < first_abnormal) if first is not None and first_abnormal else
                         (first is not None),
        "false_alarms": len(fa),
        "false_alarms_in_operator_windows": in_op,
        "classes": sorted({e.get("klass") for e in findings if e["t"] >= (attack_start or 0) - SLACK_S}),
    }


HMI_CUTTING = ("block_flow", "isolate_hmi")


def expected_response(gt):
    """Countermeasures the run needs, derived from the registers the attacker
    wrote — robust to both the scripted (per-mode) and planner drivers. Always
    block the flow; restore the breaker if it was opened; force AUTO if control
    mode was taken. A lone out-of-range setpoint needs only the block (the PLC
    rejects the value and recovers)."""
    # register name, or the number as a fallback (HR_SWITCH_CMD=1, HR_CTRL_MODE=2).
    REG_NAME = {0: "dg_setpoint", 1: "switch_cmd", 2: "ctrl_mode"}
    names = set()
    for e in gt:
        if e.get("kind") != "modbus_write":
            continue
        names.add(e.get("register_name") or REG_NAME.get(e.get("register")))
    if not names:
        return set()
    want = {"block_flow"}
    if "switch_cmd" in names:
        want.add("restore_breaker")
    if "ctrl_mode" in names:
        want.add("force_auto")
    return want


def _explained(decision):
    acts = [a for a in decision.get("actions") or [] if a != "notify"]
    covers = decision.get("covers") or {}
    return bool(decision.get("rationale")) and all(
        (covers.get(a) or {}).get("prevents") or (covers.get(a) or {}).get("restores")
        for a in acts)


def _response(resp, gt, findings, attack_start, mode, end_t):
    up = next((r for r in resp if r.get("kind") == "response_up"), {})
    decisions = [r for r in resp if r.get("kind") == "decision"]
    actions = [r for r in resp if r.get("kind") == "action"]
    applied = [a for a in actions if a.get("ok")]
    applied_ids = {a["id"] for a in applied}
    expected = expected_response(gt)
    hits = [e["t"] for e in findings
            if attack_start is not None and e["t"] >= attack_start - SLACK_S]
    real = [a for a in applied if a["id"] != "notify"]
    first_action = min((a["done_t"] for a in real), default=None)
    block_t = min((a["done_t"] for a in applied if a["id"] in HMI_CUTTING), default=None)
    ok_writes = [e for e in gt if e.get("kind") == "modbus_write" and e.get("ok")]
    pre = [a for a in real if attack_start is None or a["done_t"] < attack_start - SLACK_S]
    # The attack reached the plant iff a write landed; otherwise, with an attack
    # present, a response that applied is what prevented it (not over-response).
    prevented = attack_start is not None and not ok_writes
    if attack_start is None:
        accurate, over = (not pre), sorted(applied_ids - {"notify"})
    elif prevented:
        accurate = bool(real)                   # a countermeasure stopped it early
        over = []                               # preventing before the plant is good
    else:
        accurate = expected <= applied_ids
        over = sorted(applied_ids - expected - {"notify"})
    return {
        "policy": up.get("policy"),
        "approval": up.get("approval"),
        "decisions": len(decisions),
        "explained_decisions": sum(1 for d in decisions if _explained(d)),
        "explained_coverage": _rate(sum(1 for d in decisions if _explained(d)), len(decisions)),
        "decision_latency_s": (round(first_action - min(hits), 3)
                               if first_action is not None and hits else None),
        "actions": sorted(applied_ids - {"notify"}),
        "failed_actions": sorted({a["id"] for a in actions if not a.get("ok")}),
        "expected_actions": sorted(expected),
        "prevented_before_impact": prevented,
        "accurate": accurate,
        "over_response": over,
        "attacker_writes_after_block": (sum(1 for e in ok_writes if e["t"] > block_t)
                                        if block_t is not None else None),
        "false_responses": len(pre),
        "hmi_unavailable_s": (round(max(0.0, end_t - block_t), 3)
                              if block_t is not None and end_t is not None else 0.0),
    }


def compute_metrics(out_dir: str) -> dict:
    frames = _read_jsonl(_find(out_dir, "engine.engine_frames.jsonl", "engine_frames.jsonl"))
    events = _read_jsonl(_find(out_dir, "sensor.telemetry.jsonl", "telemetry.jsonl"))
    # IT-side sensor findings (when --it-telemetry ran): same ot_finding shape,
    # detector="it". Folded in so detection and response latency see them too.
    it_events = _read_jsonl(_find(out_dir, "hmi.it_telemetry.jsonl", "it_telemetry.jsonl"))
    gt = _read_jsonl(_find(out_dir, "ground_truth.jsonl"))
    resp_path = os.path.join(out_dir, "response.jsonl")
    resp = _read_jsonl(resp_path) if os.path.exists(resp_path) else None
    frames.sort(key=lambda fr: fr.get("timestamp", 0))

    attack_start = next((e["t"] for e in gt if e.get("kind") == "attack_start"), None)
    attack_end = next((e["t"] for e in gt if e.get("kind") == "attack_end"), None)
    writes = [e["t"] for e in gt if e.get("kind") == "modbus_write"]
    first_write = min(writes) if writes else attack_start
    mode = next((e.get("mode") for e in gt if e.get("kind") == "attack_start"), None)
    attack_end_ev = next((e for e in gt if e.get("kind") == "attack_end"), {})
    planner = bool(mode) and str(mode).startswith("planner:")
    plan_steps = [e for e in gt if e.get("kind") == "plan_step"]

    ts = [fr.get("timestamp", 0) for fr in frames]
    dt = (ts[-1] - ts[0]) / (len(ts) - 1) if len(ts) > 1 else 1.0

    # ── impact ───────────────────────────────────────────────────────────────
    after = [fr for fr in frames if attack_start is None or fr.get("timestamp", 0) >= attack_start - SLACK_S]
    win = after or frames
    abn = [fr for fr in win if fr.get("abnormal")]
    first_abn = abn[0]["timestamp"] if abn else None
    last_abn = abn[-1]["timestamp"] if abn else None
    ongoing = bool(frames) and bool(frames[-1].get("abnormal")) and bool(abn)
    vs = [v for fr in win for v in (fr.get("v_load", V_NOMINAL), fr.get("v_dg", V_NOMINAL))
          if v is not None]
    manual_spans = _manual_windows(frames, dt)
    manual_after = sum(min(b, ts[-1] + dt) - max(a, attack_start) for a, b in manual_spans
                       if attack_start is not None and b > attack_start) if frames else 0.0

    energies = [fr.get("energy_kwh") for fr in frames if fr.get("energy_kwh") is not None]
    energy_attack = None
    if attack_start is not None and energies:
        pre = [fr.get("energy_kwh") for fr in frames
               if fr.get("timestamp", 0) < attack_start and fr.get("energy_kwh") is not None]
        if pre:
            energy_attack = round(energies[-1] - pre[-1], 5)

    # ── detection ────────────────────────────────────────────────────────────
    ot_findings = [e for e in events if e.get("kind") == "ot_finding"]
    it_findings = [e for e in it_events if e.get("kind") == "ot_finding"]
    findings = ot_findings + it_findings       # combined / response see both sides
    normal_spans = [(a, b) for a, b in manual_spans if attack_start is None or a < attack_start]
    per = {d: _detection([e for e in ot_findings if _detector(e) == d], attack_start,
                         first_write, first_abn, normal_spans) for d in DETECTORS}
    if it_findings:
        per["it"] = _detection(it_findings, attack_start, first_write, first_abn, normal_spans)
    per["combined"] = _detection(findings, attack_start, first_write, first_abn, normal_spans)
    fitted = next((e for e in events if e.get("kind") == "model_fitted"), None)

    comb = per["combined"]
    # MTM: back in band for good = the first normal frame after the last abnormal one.
    mitigated_t = None
    if abn and not ongoing:
        mitigated_t = next((fr["timestamp"] for fr in win
                            if fr.get("timestamp", 0) > last_abn and not fr.get("abnormal")), None)
    response = (_response(resp, gt, findings, attack_start, mode,
                          ts[-1] + dt if ts else None) if resp is not None else None)
    return {
        "attack": attack_start is not None,
        "attack_mode": mode,
        # combined detection (kept flat for backwards compatibility)
        "detected": comb["detected"],
        "detection_latency_s": comb["detection_latency_s"],
        "false_alarms": comb["false_alarms"],
        "findings": comb["findings"],
        "first_finding_t": min((e["t"] for e in findings), default=None),
        "detectors": per,
        "model_threshold": fitted.get("threshold") if fitted else None,
        # impact
        "time_to_impact_s": (round(first_abn - first_write, 3)
                             if first_abn is not None and first_write is not None else None),
        "abnormal_frames": len(abn),
        "abnormal_duration_s": round(last_abn - first_abn, 3) if abn else 0.0,
        "impact_duration_s": round(last_abn - first_abn + dt, 3) if abn else 0.0,
        "impact_ongoing_at_end": ongoing,
        "impact_persists_after_attack": bool(abn) and attack_end is not None and
                                        last_abn is not None and last_abn > attack_end + 2 * dt,
        "recovered": bool(abn) and not ongoing,
        "recovery_s": round(last_abn + dt - first_abn, 3) if abn and not ongoing else None,
        "manual_mode_s": round(manual_after, 3),
        "mitigated_s": (round(mitigated_t - first_write, 3)
                        if mitigated_t is not None and first_write is not None else None),
        "response": response,
        # Tree-guided attacker (planner driver)
        "planner": planner,
        "attacker_profile": (mode.split(":", 1)[1] if planner else None),
        "stage_reached": attack_end_ev.get("stage_reached") if planner else None,
        "attack_succeeded": (bool(attack_end_ev.get("success")) if planner else None),
        "prevented": (not any(e.get("kind") == "modbus_write" and e.get("ok") for e in gt)
                      if planner else None),
        "plan_steps": [{"node": e.get("node"), "stage": e.get("stage"), "ok": e.get("ok")}
                       for e in plan_steps] if planner else None,
        "max_abs_deviation_pu": round(max((abs(v - V_NOMINAL) for v in vs), default=0.0), 4),
        "v_min": round(min(vs), 4) if vs else None,
        "v_max": round(max(vs), 4) if vs else None,
        "energy_kwh_total": round(energies[-1], 5) if energies else None,
        "energy_kwh_during_attack": energy_attack,
        "n_frames": len(frames),
    }


def format_report(m: dict) -> str:
    lines = ["# Cyber-physical run metrics", ""]
    det = "yes" if m["detected"] else "NO"
    lines.append(f"- attack present: {m['attack']}"
                 + (f" (mode: {m['attack_mode']})" if m.get("attack_mode") else ""))
    lines.append(f"- detected: {det}  (findings={m['findings']}, "
                 f"latency={m['detection_latency_s']}s)")
    lines.append(f"- false alarms (normal phase): {m['false_alarms']}")
    lines.append("")
    lines.append("| detector | detected | latency (s) | from write (s) | before impact "
                 "| false alarms | …in operator windows | classes |")
    lines.append("|---|---|---|---|---|---|---|---|")
    det_rows = (*DETECTORS, *(["it"] if "it" in m["detectors"] else []), "combined")
    for d in det_rows:
        x = m["detectors"][d]
        lines.append(f"| {d} | {'yes' if x['detected'] else 'no'} | {x['detection_latency_s']} "
                     f"| {x['latency_from_write_s']} | {'yes' if x['before_impact'] and x['detected'] else 'no'} "
                     f"| {x['false_alarms']} | {x['false_alarms_in_operator_windows']} "
                     f"| {', '.join(c for c in x['classes'] if c) or '—'} |")
    lines.append("")
    lines.append(f"- physical deviation: max |ΔV|={m['max_abs_deviation_pu']} pu "
                 f"(V∈[{m['v_min']},{m['v_max']}]), abnormal {m['abnormal_frames']} frames "
                 f"/ {m['abnormal_duration_s']}s")
    lines.append(f"- impact: time-to-impact={m['time_to_impact_s']}s, "
                 f"duration={m['impact_duration_s']}s, "
                 f"persists after attack={m['impact_persists_after_attack']}, "
                 f"ongoing at end={m['impact_ongoing_at_end']}, "
                 f"recovered={m['recovered']} (recovery {m['recovery_s']}s)")
    lines.append(f"- control authority in MANUAL after the attack: {m['manual_mode_s']}s")
    lines.append(f"- mitigated (MTM, from first write): {m.get('mitigated_s')}s")
    lines.append(f"- energy: total={m['energy_kwh_total']} kWh, "
                 f"during attack={m['energy_kwh_during_attack']} kWh")
    if m.get("planner"):
        lines.append(f"- tree-guided attacker ({m['attacker_profile']}): reached "
                     f"{m['stage_reached']}, succeeded={m['attack_succeeded']}, "
                     f"prevented={m['prevented']}")
    r = m.get("response")
    if r:
        lines += ["", f"## Response (policy: {r['policy']}, approval: {r['approval']})", ""]
        lines.append(f"- countermeasures applied: {', '.join(r['actions']) or '—'} "
                     f"(expected: {', '.join(r['expected_actions']) or '—'}; "
                     f"accurate: {r['accurate']}; over-response: "
                     f"{', '.join(r['over_response']) or '—'}; failed: "
                     f"{', '.join(r['failed_actions']) or '—'})")
        if r.get("prevented_before_impact"):
            lines.append("- attack prevented before the plant was touched")
        lines.append(f"- decision latency (first finding -> first countermeasure done): "
                     f"{r['decision_latency_s']}s")
        lines.append(f"- decisions: {r['decisions']}, explained: {r['explained_decisions']} "
                     f"(coverage {r['explained_coverage']})")
        lines.append(f"- attacker writes that succeeded after the block: "
                     f"{r['attacker_writes_after_block']}")
        lines.append(f"- false responses: {r['false_responses']}; "
                     f"HMI unavailable: {r['hmi_unavailable_s']}s")
    return "\n".join(lines) + "\n"


# ── campaign aggregation ────────────────────────────────────────────────────
def _median(xs):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    n = len(xs)
    return round(xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2.0, 3)


def _rate(k, n):
    return round(k / n, 3) if n else None


def aggregate(rows):
    """Aggregate many runs. `rows`: [{"mode", "seed", "metrics"}].

    Returns {"detection": [...], "impact": [...]}:
      detection — one row per (mode, detector): runs, detection rate, latency
                  from the first malicious write (median/min/max over detected
                  runs), share flagged before the physical impact, false alarms
                  (normal phase; for normal-only runs every finding) and how many
                  fell inside legitimate operator windows;
      impact    — one row per mode: persistence / recovery shares and medians of
                  time-to-impact, impact duration, max deviation, time in MANUAL.
    """
    modes = []
    for r in rows:
        if r["mode"] not in modes:
            modes.append(r["mode"])
    detection, impact = [], []
    for mode in modes:
        runs = [r["metrics"] for r in rows if r["mode"] == mode]
        n = len(runs)
        attack = any(m.get("attack") for m in runs)
        for det in (*DETECTORS, "combined"):
            ds = [m["detectors"][det] for m in runs if det in (m.get("detectors") or {})]
            hit = [d for d in ds if d["detected"]]
            lat = [d.get("latency_from_write_s") for d in hit]
            detection.append({
                "mode": mode, "detector": det, "runs": n,
                "detected": len(hit) if attack else None,
                "detection_rate": _rate(len(hit), n) if attack else None,
                "latency_median_s": _median(lat) if attack else None,
                "latency_min_s": min((x for x in lat if x is not None), default=None) if attack else None,
                "latency_max_s": max((x for x in lat if x is not None), default=None) if attack else None,
                "before_impact_rate": (_rate(sum(1 for d in hit if d.get("before_impact")), n)
                                       if attack else None),
                "false_alarms": sum(d.get("false_alarms", 0) for d in ds),
                "runs_with_false_alarms": sum(1 for d in ds if d.get("false_alarms")),
                "false_alarms_in_operator_windows":
                    sum(d.get("false_alarms_in_operator_windows", 0) for d in ds),
            })
        impact.append({
            "mode": mode, "runs": n,
            "impact_rate": _rate(sum(1 for m in runs if m.get("abnormal_frames")), n),
            "persists_rate": _rate(sum(1 for m in runs if m.get("impact_persists_after_attack")), n),
            "recovered_rate": _rate(sum(1 for m in runs if m.get("recovered")), n),
            "time_to_impact_median_s": _median(m.get("time_to_impact_s") for m in runs),
            "impact_duration_median_s": _median(m.get("impact_duration_s") for m in runs),
            "max_dev_median_pu": _median(m.get("max_abs_deviation_pu") for m in runs),
            "manual_mode_median_s": _median(m.get("manual_mode_s") for m in runs),
            "mitigated_median_s": _median(m.get("mitigated_s") for m in runs),
        })
    response = []
    for mode in modes:
        rs = [r["metrics"]["response"] for r in rows
              if r["mode"] == mode and (r["metrics"].get("response") or None)]
        if not rs:
            continue
        n = len(rs)
        dec = sum(r.get("decisions", 0) for r in rs)
        response.append({
            "mode": mode, "policy": ",".join(sorted({str(r.get("policy")) for r in rs})),
            "runs": n,
            "accuracy": _rate(sum(1 for r in rs if r.get("accurate")), n),
            "over_response_runs": sum(1 for r in rs if r.get("over_response")),
            "decision_latency_median_s": _median(r.get("decision_latency_s") for r in rs),
            "explained_coverage": _rate(sum(r.get("explained_decisions", 0) for r in rs), dec),
            "attacker_writes_after_block_median":
                _median(r.get("attacker_writes_after_block") for r in rs),
            "false_responses": sum(r.get("false_responses", 0) for r in rs),
            "failed_action_runs": sum(1 for r in rs if r.get("failed_actions")),
            "hmi_unavailable_median_s": _median(r.get("hmi_unavailable_s") for r in rs),
        })
    return {"detection": detection, "impact": impact, "response": response}


def _fmt(v):
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:g}"
    return str(v)


def format_aggregate(agg) -> str:
    lines = ["# CPS campaign summary", "", "## Detection", "",
             "| mode | detector | runs | detection rate | latency from write (median, min–max s) "
             "| before impact | false alarms (runs) | …in operator windows |",
             "|---|---|---|---|---|---|---|---|"]
    for r in agg["detection"]:
        lat = (f"{_fmt(r['latency_median_s'])} ({_fmt(r['latency_min_s'])}–{_fmt(r['latency_max_s'])})"
               if r["detected"] else "—")
        lines.append(f"| {r['mode']} | {r['detector']} | {r['runs']} | {_fmt(r['detection_rate'])} "
                     f"| {lat} | {_fmt(r['before_impact_rate'])} "
                     f"| {r['false_alarms']} ({r['runs_with_false_alarms']}) "
                     f"| {r['false_alarms_in_operator_windows']} |")
    lines += ["", "## Physical impact", "",
              "| mode | runs | impacted | persists | recovered | time-to-impact (s) "
              "| impact duration (s) | max ΔV (pu) | MANUAL (s) |",
              "|---|---|---|---|---|---|---|---|---|"]
    for r in agg["impact"]:
        lines.append(f"| {r['mode']} | {r['runs']} | {_fmt(r['impact_rate'])} "
                     f"| {_fmt(r['persists_rate'])} | {_fmt(r['recovered_rate'])} "
                     f"| {_fmt(r['time_to_impact_median_s'])} | {_fmt(r['impact_duration_median_s'])} "
                     f"| {_fmt(r['max_dev_median_pu'])} | {_fmt(r['manual_mode_median_s'])} |")
    if agg.get("response"):
        lines += ["", "## Response", "",
                  "| mode | policy | runs | accuracy | over-response (runs) "
                  "| decision latency (median s) | explained | writes after block (median) "
                  "| false responses | failed (runs) | HMI unavailable (median s) |",
                  "|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in agg["response"]:
            lines.append(f"| {r['mode']} | {r['policy']} | {r['runs']} | {_fmt(r['accuracy'])} "
                         f"| {r['over_response_runs']} | {_fmt(r['decision_latency_median_s'])} "
                         f"| {_fmt(r['explained_coverage'])} "
                         f"| {_fmt(r['attacker_writes_after_block_median'])} "
                         f"| {r['false_responses']} | {r['failed_action_runs']} "
                         f"| {_fmt(r['hmi_unavailable_median_s'])} |")
    return "\n".join(lines) + "\n"


def load_campaign_rows(campaign_dir):
    """[{"mode","seed","metrics"}] from <campaign>/runs/*/metrics.json."""
    rows = []
    for p in sorted(glob.glob(os.path.join(campaign_dir, "runs", "*", "metrics.json"))):
        try:
            with open(p) as f:
                m = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        run = m.get("run") or {}
        rows.append({"mode": run.get("mode") or m.get("attack_mode") or "normal",
                     "seed": run.get("seed"), "metrics": m})
    return rows


CI_HEADLINE = ("detectors.combined.detected", "detectors.combined.latency_from_write_s",
               "impact_duration_s", "max_abs_deviation_pu", "false_alarms",
               "response.accurate", "mitigated_s")


def write_aggregate(campaign_dir, rows=None):
    """Write summary.md / summary.csv / impact.csv; return the aggregate."""
    import csv
    from network_scenario.core import aggregate as core_agg
    rows = rows if rows is not None else load_campaign_rows(campaign_dir)
    agg = aggregate(rows)
    # Every numeric metric with its 95% CI, per mode (core statistics).
    ci = core_agg.summarize(rows, by=("mode",))
    core_agg.write_csv(os.path.join(campaign_dir, "ci.csv"), ci)
    with open(os.path.join(campaign_dir, "summary.md"), "w") as f:
        f.write(format_aggregate(agg))
        f.write("\n## Headline metrics, mean [95% CI] (runs)\n\n")
        f.write(core_agg.format_markdown(ci, by=("mode",), metrics=[
            m for m in CI_HEADLINE if any(r["metric"] == m for r in ci)]))
    for name, key in (("summary.csv", "detection"), ("impact.csv", "impact"),
                      ("response.csv", "response")):
        table = agg.get(key) or []
        if key == "response" and not table:
            continue
        with open(os.path.join(campaign_dir, name), "w", newline="") as f:
            if table:
                w = csv.DictWriter(f, fieldnames=list(table[0]))
                w.writeheader()
                w.writerows(table)
    return {**agg, "ci": [r for r in ci if r["metric"] in CI_HEADLINE]}


def main():
    ap = argparse.ArgumentParser(description="Score a cyber-physical scenario run or campaign")
    ap.add_argument("--out-dir", default=None, help="one run's directory")
    ap.add_argument("--report", default=None, help="write the markdown report here too")
    ap.add_argument("--json", default=None, help="write the metrics as JSON here too")
    ap.add_argument("--aggregate", default=None, metavar="CAMPAIGN_DIR",
                    help="aggregate <dir>/runs/*/metrics.json into summary.{md,csv}")
    args = ap.parse_args()
    if args.aggregate:
        agg = write_aggregate(args.aggregate)
        print(format_aggregate(agg))
        return
    if not args.out_dir:
        ap.error("--out-dir or --aggregate is required")
    m = compute_metrics(args.out_dir)
    report = format_report(m)
    print(report)
    print(json.dumps(m, indent=2))
    if args.report:
        with open(args.report, "w") as f:
            f.write(report)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(m, f, indent=2)


if __name__ == "__main__":
    main()
