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
// This panel's own redraw key and the page's SVG helper (set by the factory):
// every panel is concatenated into one script, so nothing here may lean on
// another panel's private names.
let chartKey = null, s = null;

// This scenario's words, for the page (ui.metric, ui.term) and the views here:
// every metric of the campaign's mean [95% CI] table (campaign.HEADLINE), the
// moving-target knobs by what each one moves, and the outcomes of an action.
const COST_HELP = "Each change the moving-target defence makes interrupts the clients a little, and is charged a fixed weight: "
  + "0.30 for a broker or source address, 0.15 for a broker port, 0.01 for a padding or timing change. No unit; 0 with no defence.";
const LABELS = {
  metrics: {
    nanogrid_detect: { label: "attacker's confidence in the nanogrid", unit: "share 0–1",
      help: "Of the packets from the nanogrid's real addresses, the share the attacker's classifier flagged as nanogrid. Lower: the defence hides it better" },
    availability_cost: { label: "availability cost of the defence", unit: "weighted changes", help: COST_HELP },
    blocked_is_nanogrid: { label: "attacker blocked a nanogrid address", unit: "share of runs",
      help: "Runs in which the address the attacker chose to block really belonged to the nanogrid" },
    data_gaps: { label: "delivery gaps", unit: "count", help: "Times the nanogrid's data stopped reaching the broker for longer than expected" },
    publishes: { label: "messages published", unit: "count", help: "MQTT publishes the nanogrid client sent during the run" },
  },
  terms: {
    hop: "broker address and port", src: "client source address", pad: "message padding", freq: "publish timing",
    applied: "applied", failed: "failed", timed_out: "timed out", client_lost: "client lost",
  },
};
const KNOB_HELP = {
  hop: "The broker moves to another address and/or port, and the clients follow", src: "The client changes the address it publishes from",
  pad: "Messages are padded to another size, to blur their length", freq: "The publishing interval changes, to blur its rhythm",
};

function renderQueueMqtt(ui) {
  const M = LABELS.metrics;
  ui.queueTable({
    note: "attacker's confidence: how surely the attacker picked out the nanogrid's addresses, 0 to 1 "
        + "(lower = the defence hides it better). Hover a column for what it measures.",
    columns: [
      { label: "step", attrs: { title: "The step of the experiment the run is on" } },
      { label: "attacker's confidence (0–1)", attrs: { class: "num", title: M.nanogrid_detect.help } },
      { label: "address the attacker blocked", attrs: { title: "The address its classifier ranked most likely to be the nanogrid, and what that address really was" } },
      { label: "defence cost", attrs: { class: "num", title: COST_HELP } },
    ],
    cells: r => {
      const m = r.metrics;
      const blocked = !m ? "—" : !m.blocked_ip ? "nothing"
        : `${m.blocked_ip}${m.blocked_is_scmc ? " (the nanogrid client: a hit)"
            : m.blocked_is_nanogrid ? " (the nanogrid's broker side: a hit)" : " (background traffic: a miss)"}`;
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
  const chip = (k, v, dot, help) => h("div", { class: "chip", title: help || null }, h("div", { class: "k" }, k),
    h("div", { class: "v" }, dot ? h("span", { class: "dot", style: `background:${dot}` }) : null, v));
  const by = st => r.mtd.filter(a => a.status === st).length;
  const m = r.metrics, maxGap = r.gaps.reduce((a, g) => Math.max(a, g.gap || 0), 0);
  $("d-chips").replaceChildren(
    chip("defence actions", String(r.mtd.length || (m ? Object.values(m.mtd_outcomes || {}).reduce((a, b) => a + b, 0) : 0)), null,
      "Changes the moving-target defence asked for: a broker hop, a source hop, a padding or timing change"),
    chip("applied", String(by("applied")), "var(--good)", "Changes every client carried out"),
    chip("failed / timed out", String(by("failed") + by("timed_out")), by("failed") + by("timed_out") ? "var(--warning)" : null,
      "Changes a client refused, or did not confirm in time"),
    chip("delivery gaps", String(r.gaps.length || (m?.data_gaps ?? 0)), r.gaps.length ? "var(--critical)" : null, LABELS.metrics.data_gaps.help),
    chip("longest gap", maxGap ? `${num(maxGap, 1)} s` : (m?.max_data_gap_s ? `${num(m.max_data_gap_s, 1)} s` : "none"), null,
      "The longest time the nanogrid's data did not reach the broker"),
    // An alert is one raise: its clearing is the same alert ending, not another one.
    chip("attack-detector alerts", String(r.detections.filter(a => a.kind === "detector_alert" && a.state !== "cleared").length), null,
      "Times the detector judged that the attacker was blocking the nanogrid's traffic, rather than a gap the defence's own changes explain"),
  );
  if (r.step) $("d-sub").textContent += ` · step: ${r.step}`;
  drawMtd(r);
  $("f-title").textContent = "Defence actions";
  $("f-sub").textContent = "What the moving-target defence changed, by what it moves and how each change ended, and the gaps in the nanogrid's data (live during the run).";
  const agg = {};
  for (const a of r.mtd) { const k = `${a.action}|${a.status}`; (agg[k] = agg[k] || { a: a.action, s: a.status, n: 0, cost: 0, first: a.t }).n++; agg[k].cost += a.cost || 0; }
  const rows = Object.values(agg).sort((x, y) => x.first - y.first).map(x =>
    h("tr", {}, h("td", {}, term(x.a, null, KNOB_HELP[x.a])), h("td", {}, term(x.s)), h("td", { class: "num" }, String(x.n)),
      h("td", { class: "num" }, String(num(x.cost, 2))),
      h("td", { class: "num" }, r.start_t ? rel(x.first, r.start_t) : "—")));
  if (r.gaps.length) rows.push(h("tr", {}, h("td", {}, "delivery gap"), h("td", {}, `longest ${num(maxGap, 1)} s`), h("td", { class: "num" }, String(r.gaps.length)),
    h("td", { class: "num muted", title: "A gap is an effect, not a change: it has no cost of its own" }, "—"),
    h("td", { class: "num" }, r.start_t ? rel(r.gaps[0].t, r.start_t) : "—")));
  const heads = [["what moved", "What the defence changed; hover a row for what that does, and for the name it is recorded under"],
    ["outcome", "applied · failed · timed out (not confirmed in time) · client lost (a client did not follow)"],
    ["count", "How many times", "num"], ["cost", COST_HELP, "num"], ["first, since run start", "When the first one happened, counted from the start of the run", "num"]];
  $("d-findings").replaceChildren(h("thead", {}, h("tr", {}, heads.map(([label, help, kind]) => h("th", { class: kind || null, title: help }, label)))),
    h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: 5, class: "empty" },
      S.kind === "campaign" ? "A campaign's ledger holds each run's score, not its live events: pick the run's own entry in the Experiment list to see them"
        : r.start_t ? "No defence action: this run has no moving-target defence (a baseline), or it has not acted yet" : "No live trace for this run"))));
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

  (window.CyberRangePanels ||= {})["mqtt-mtd"] = ui => {
    s = ui.svg;
    return {
      queue: () => renderQueueMqtt(ui),
      detail: renderDetailMqtt,
      labels: LABELS,
      // This scenario's aggregate is the 95%-CI table, which the page shows from
      // the data itself; it adds no results tab of its own.
    };
  };
})();
