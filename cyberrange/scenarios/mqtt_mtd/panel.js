// panel.js — the MQTT scenario's own dashboard views.
//
// The core page (cyberrange/core/dashboard.html) draws what every scenario has:
// the ledger, the phases, the run queue, the aggregate. What only this scenario
// can read — the attacker's confidence in its nanogrid guess, the MTD actions
// and what each one cost, the delivery gaps — is drawn here and served to the
// page at /graph.js, which concatenates the panel of every registered scenario.
//
// The factory below is invoked by the page once its own helpers exist, so this
// code can use them (h, $, num, dur, now, statusBadge, S) directly.
"use strict";
(function () {
function renderQueueMqtt(ui) {
  ui.queueTable({
    note: "attacker confidence: its nanogrid_frac over the nanogrid's own IPs "
        + "(lower = the MTD hides it better); MTD cost: availability cost of the knob changes.",
    columns: [
      { label: "step" },
      { label: "attacker confidence", num: true },
      { label: "blocked" },
      { label: "MTD cost", num: true },
    ],
    cells: r => {
      const m = r.metrics;
      const blocked = !m ? "—" : !m.blocked_ip ? "nothing"
        : `${m.blocked_ip}${m.blocked_is_scmc ? " (SCMC)"
            : m.blocked_is_nanogrid ? " (broker side)" : " (background)"}`;
      return [
        ui.stepCell(r),
        h("td", { class: "num" }, m ? String(num(m.nanogrid_detect)) : "—"),
        h("td", {}, blocked),
        h("td", { class: "num" }, m ? String(num(m.availability_cost, 2)) : "—"),
      ];
    },
  });
}

function renderDetailMqtt(r) {
  const chip = (k, v, dot) => h("div", { class: "chip" }, h("div", { class: "k" }, k),
    h("div", { class: "v" }, dot ? h("span", { class: "dot", style: `background:${dot}` }) : null, v));
  const by = st => r.mtd.filter(a => a.status === st).length;
  const m = r.metrics, maxGap = r.gaps.reduce((a, g) => Math.max(a, g.gap || 0), 0);
  $("d-chips").replaceChildren(
    chip("MTD actions", String(r.mtd.length || (m ? Object.values(m.mtd_outcomes || {}).reduce((a, b) => a + b, 0) : 0))),
    chip("applied", String(by("applied")), "var(--good)"),
    chip("failed / timed out", String(by("failed") + by("timed_out")), by("failed") + by("timed_out") ? "var(--warning)" : null),
    chip("delivery gaps", String(r.gaps.length || (m?.data_gaps ?? 0)), r.gaps.length ? "var(--critical)" : null),
    chip("longest gap", maxGap ? `${num(maxGap, 1)} s` : (m?.max_data_gap_s ? `${num(m.max_data_gap_s, 1)} s` : "—")),
    chip("detector alerts", String(r.alerts2.filter(a => a.kind === "detector_alert").length)),
  );
  if (r.step) $("d-sub").textContent += ` · step: ${r.step}`;
  $("d-err").textContent = r.error && r.status !== "ok" ? `error: ${r.error}` : "";
  drawMtd(r);
  $("f-title").textContent = "MTD actions";
  $("f-sub").textContent = "Moving-target actions of the coordinator by knob and outcome, and the delivery gaps the SEMP observed (live during the run).";
  const agg = {};
  for (const a of r.mtd) { const k = `${a.action}|${a.status}`; (agg[k] = agg[k] || { a: a.action, s: a.status, n: 0, cost: 0, first: a.t }).n++; agg[k].cost += a.cost || 0; }
  if (r.gaps.length) agg["gap"] = { a: "data gap", s: `max ${num(maxGap, 1)} s`, n: r.gaps.length, cost: null, first: r.gaps[0].t };
  const rows = Object.values(agg).sort((x, y) => x.first - y.first).map(x =>
    h("tr", {}, h("td", {}, x.a), h("td", {}, x.s), h("td", { class: "num" }, String(x.n)),
      h("td", { class: "num" }, x.cost == null ? "—" : String(num(x.cost, 2))),
      h("td", { class: "num" }, r.start_t ? `+${dur(x.first - r.start_t)}` : "—")));
  $("d-findings").replaceChildren(h("thead", {}, h("tr", {}, h("th", {}, "action"), h("th", {}, "outcome"), h("th", { class: "num" }, "count"), h("th", { class: "num" }, "cost"), h("th", { class: "num" }, "first at"))),
    h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: 5, class: "empty" },
      S.kind === "campaign" ? "Live MTD events are in the run's own ledger (select it in the list)" : "No MTD events (baseline run, or not started yet)"))));
}

// MQTT: MTD actions over time (one lane per knob, colour = outcome) and the
// delivery gaps the SEMP saw, on the run's phase timeline.
function drawMtd(r) {
  const box = $("d-chart"), legend = $("d-legend");
  const key = ["mtd", r.id, r.start_t, r.mtd.length, r.gaps.length, box.clientWidth, document.documentElement.dataset.theme || ""].join("|");
  if (key === chartKey) return;
  chartKey = key;
  box.querySelector("svg")?.remove(); box.querySelector(".empty")?.remove(); legend.replaceChildren();
  if (!r.start_t || (!r.mtd.length && !r.gaps.length)) {
    box.append(h("div", { class: "empty" }, r.start_t ? "No MTD actions or delivery gaps yet." : "No live trace for this run."));
    return;
  }
  const lanes = [...new Set(r.mtd.map(a => a.action))].sort();
  if (r.gaps.length) lanes.push("delivery gap");
  const COL = { applied: "var(--good)", failed: "var(--critical)", timed_out: "var(--warning)", client_lost: "var(--serious)" };
  legend.append(...Object.entries(COL).map(([k, c]) => h("span", {}, h("span", { class: "lk", style: `background:${c}` }), k.replace("_", " "))));
  const W = Math.max(320, box.clientWidth || 600), LH = 22, m = { l: 96, r: 12, t: 8, b: 24 };
  const H = m.t + m.b + LH * Math.max(lanes.length, 1);
  const t0 = r.start_t, tEnd = Math.max(...r.mtd.map(a => a.t), ...r.gaps.map(g => g.t), ...r.phases.map(p => p.end_t || 0), t0 + 10);
  const plannedEnd = t0 + r.phases.reduce((a, p) => a + (p.planned_s || 0), 0);
  const xMax = (r.status === "running" ? Math.max(tEnd, plannedEnd) : tEnd) - t0;
  const X = v => m.l + (W - m.l - m.r) * Math.min(1, Math.max(0, v - t0) / Math.max(xMax, 1));
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `MTD actions for ${r.id}` });
  lanes.forEach((ln, i) => {
    const y = m.t + LH * i + LH / 2;
    svg.append(s("line", { x1: m.l, x2: W - m.r, y1: y, y2: y, stroke: "var(--grid)" }));
    svg.append(s("text", { x: m.l - 6, y: y + 4, "text-anchor": "end", "font-size": 11, fill: "var(--muted)" }, ln));
  });
  for (const a of r.mtd) {
    const y = m.t + LH * lanes.indexOf(a.action) + LH / 2;
    svg.append(s("rect", { x: X(a.t) - 1.5, y: y - 6, width: 3, height: 12, fill: COL[a.status] || "var(--axis)" }));
  }
  if (r.gaps.length) {
    const y = m.t + LH * (lanes.length - 1) + LH / 2;
    for (const g of r.gaps) svg.append(s("rect", { x: X(g.t - (g.gap || 0)), y: y - 5, width: Math.max(2, X(g.t) - X(g.t - (g.gap || 0))), height: 10, fill: "var(--critical)" }));
  }
  const step = xMax > 240 ? 60 : xMax > 90 ? 30 : 10;
  for (let x = 0; x <= xMax; x += step)
    svg.append(s("text", { x: X(t0 + x), y: H - 6, "text-anchor": "middle", "font-size": 11, fill: "var(--muted)" }, `${x}s`));
  box.insertBefore(svg, $("tip"));
}

  (window.CyberRangePanels ||= {})["mqtt-mtd"] = ui => ({
    queue: () => renderQueueMqtt(ui),
    detail: renderDetailMqtt,
    // This scenario's aggregate is the 95%-CI table, which the page shows from
    // the data itself; it adds no tab of its own.
    tabs: [],
  });
})();
