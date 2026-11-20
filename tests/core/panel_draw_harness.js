// panel_draw_harness.js — a page reduced to what the dashboard's panels touch,
// for tests/core/test_panels.py: elements that record their children, the page's
// helpers as globals, and a run with one of every event kind of the cps family.
// The test puts the panels' sources where the PANELS marker is and reads the
// failures each panel's hooks raised from the JSON printed at the end.
globalThis.window = globalThis;
window.CyberRangePanels = {};
class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.style = {};
    this.dataset = {}; this.textContent = ""; this.clientWidth = 800; this.offsetWidth = 120; }
  // As the DOM does: a null handed to append() becomes the text "null".
  append(...k) { for (const c of k) this.children.push(c == null ? String(c) : c); }
  appendChild(c) { this.append(c); return c; }
  replaceChildren(...k) { this.children = []; this.append(...k); }
  insertBefore(c) { this.append(c); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  addEventListener() {}
  remove() {}
  querySelector() { return null; }
  querySelectorAll() { return []; }
  closest() { return null; }
  getBoundingClientRect() { return { left: 0, top: 0, width: 800, height: 300 }; }
}
globalThis.Node = El;
globalThis.document = { createElementNS: (ns, t) => new El(t), createElement: t => new El(t),
  documentElement: { dataset: {} } };
const els = {};
globalThis.$ = id => els[id] || (els[id] = new El("div"));
globalThis.h = (tag, attrs, ...kids) => {
  const e = new El(tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v != null) e.setAttribute(k, v);
  for (const c of kids.flat()) if (c != null) e.append(c instanceof El ? c : String(c));
  return e;
};
globalThis.svg = (tag, attrs, text) => { const e = h(tag, attrs); if (text != null) e.textContent = text; return e; };
globalThis.num = (v, d = 3) => v == null ? "—" : (typeof v === "number" ? +v.toFixed(d) : v);
globalThis.dur = s => s == null ? "—" : `${Math.round(s)}s`;
globalThis.clock = t => String(t);
globalThis.S = { kind: "run", scenario: null, runs: {}, order: [] };
let VIEW = null, TIME = null;
const api = { S, $, h, svg, num, dur, clock, now: () => 200, statusBadge: () => h("span"),
  shownRunId: () => "r1", select() {}, render() {}, stepCell: () => h("td"), queueTable() {},
  time: () => TIME, setTime(t) { TIME = t; }, view: () => VIEW };
// A panel may defer drawing to a microtask (once its box is on the page): run it
// now, so that what it throws is caught and named like the rest.
globalThis.queueMicrotask = fn => fn();

function emptyRun() {
  return { id: "r1", mode: "planner:opportunistic", seed: 1, status: "running", start_t: 100,
    phases: [{ name: "normal", planned_s: 30, start_t: 100, end_t: 130, ok: true },
             { name: "attack", planned_s: 20, start_t: 130 }],
    plant: [], findings: [], writes: [], alerts: [], threshold: null, metrics: null, learn_s: 10,
    states: [], decisions: [], actions: [], respond: "off", approvals: {}, teams: [],
    mtd: [], gaps: [], alerts2: [], x: {} };
}
function fullRun() {
  return Object.assign(emptyRun(), {
    respond: "rules", threshold: 7.5,
    plant: [{ t: 101, v_load: 1, v_dg: 1.01, abnormal: false, ctrl_mode: 0, dg_setpoint: 20, switch_cmd: 0 },
            { t: 140, v_load: 1.1, v_dg: 1.15, abnormal: true, ctrl_mode: 1, dg_setpoint: 200, switch_cmd: 0 }],
    findings: [{ t: 133, detector: "it", klass: "web_injection_pattern", src: "10.0.0.9", maps_to: "it_access" },
               { t: 139, detector: "rules", klass: "unsafe_command", name: "dg_setpoint" }],
    writes: [{ t: 138, register: "dg_setpoint", value: 200, ok: true }],
    states: [{ t: 134, nodes: { it_access: ["confirmed", 0.9], pivot: ["suspected", 0.5] },
               active: [], hosts: ["hmi"], next: ["pivot"] }],
    decisions: [{ t: 135, policy: "rules", actions: ["block_web_src"], rationale: "seen",
                  covers: { block_web_src: { prevents: ["it_access"] } }, needs_approval: [] }],
    actions: [{ t: 136, id: "block_web_src", ok: true, machine: "hmi" }],
    approvals: { q1: { request: "q1", asked_t: 135, action: "isolate_hmi", state: "requested" } },
    mtd: [{ t: 131, action: "hop", status: "applied", cost: 1 }], gaps: [{ t: 140, gap: 2 }],
    metrics: { attack: true, abnormal_frames: 3, recovered: true, recovery_s: 4,
      detectors: { combined: { detected: true, latency_from_write_s: 0.5, before_impact: true, false_alarms: 0 },
                   rules: { detected: true, latency_from_write_s: 1.2, before_impact: true } },
      stage_reached: "it_exec", attack_succeeded: false,
      response: { policy: "rules", accurate: true, over_response: false },
      tree_fidelity: { precision: 1, recall: 0.5, discovered: ["it_access"], extra: ["ghost"] } },
  });
}
// The same run on a plant of two feeders, attacked on the second: every sample
// carries each feeder's readings, every write, finding and alert its unit.
function twoFeederRun() {
  const feeder = (v, abnormal, mode, kw) => ({ v_load: v, v_dg: v + 0.01, abnormal, ctrl_mode: mode, dg_setpoint: kw, switch_cmd: 0 });
  return Object.assign(fullRun(), {
    info: { units: [1, 2], attack_unit: 2, v_band: [0.95, 1.05] },
    plant: [{ t: 101, ...feeder(1, false, 0, 20), units: { 1: feeder(1, false, 0, 20), 2: feeder(1, false, 0, 30) } },
            { t: 140, ...feeder(1, false, 0, 20), units: { 1: feeder(1, false, 0, 20), 2: feeder(1.1, true, 1, 80) } },
            { t: 145, ...feeder(1, false, 0, 20), units: { 1: feeder(1, false, 0, 20), 2: feeder(1.1, true, 1, 80) } }],
    findings: [{ t: 133, detector: "it", klass: "web_injection_pattern", src: "10.0.0.9" },
               { t: 139, detector: "model", klass: "behavioral_anomaly", unit: 2 },
               { t: 139.5, detector: "model", klass: "behavioral_anomaly", unit: 1 },
               { t: 141, detector: "rules", klass: "unsafe_command", unit: 2 }],
    writes: [{ t: 138, unit: 2, register: "ctrl_mode", value: 1, ok: true },
             { t: 138, unit: 2, register: "dg_setpoint", value: 80, ok: true }],
  });
}
const TWO_FEEDER_EVENTS = [
  { kind: "alert", guest_t: 139, state: "raised", detector: "model", klass: "behavioral_anomaly", unit: 2 },
  { kind: "alert", guest_t: 139.5, state: "raised", detector: "model", klass: "behavioral_anomaly", unit: 1 },
];
// Everything a drawn element says, in order: its own text and its children's.
const textOf = e => typeof e === "string" ? e : [e.textContent, ...(e.children || []).map(textOf)].join(" ");
const all = (e, pred, out = []) => { if (typeof e !== "string") { if (pred(e)) out.push(e); for (const c of e.children) all(c, pred, out); } return out; };
// What a plant of several feeders must show, on the panels of the cps family.
function checkFeeders(panel, run, fail) {
  panel.detail(run);
  const tabs = all($("d-chips"), e => e.tag === "button");
  const pressed = tabs.filter(b => b.attrs["aria-pressed"] === "true").map(textOf).join();
  if (tabs.length !== 2) fail(`feeder selector: ${tabs.length} buttons for two feeders`);
  if (!/unit 2/.test(pressed)) fail(`feeder selector: the attacked feeder is not the one shown (${pressed})`);
  const chips = textOf($("d-chips"));
  if (!/MANUAL/.test(chips) || !/80 kW/.test(chips)) fail(`chips show another feeder's state: ${chips}`);
  const rows = all($("d-findings"), e => e.tag === "tr").map(textOf);
  if (rows.filter(t => /behavioral_anomaly/.test(t)).length !== 2)
    fail(`findings table merges the two feeders' model findings: ${rows.join(" / ")}`);
  if (!/feeder/.test(rows[0])) fail("findings table has no feeder column");
  run.x.unit = "1";
  panel.detail(run);
  if (/MANUAL/.test(textOf($("d-chips")))) fail("feeder 1 selected, feeder 2's MANUAL still shown");
  const single = fullRun();
  panel.detail(single);
  if (all($("d-chips"), e => e.tag === "button").length) fail("a plant of one feeder got a feeder selector");
  if (/feeder/.test(textOf($("d-findings")))) fail("a plant of one feeder got a feeder column");
  if (/null|undefined|feeder/.test(textOf($("d-legend")))) fail(`a plant of one feeder: the legend reads "${textOf($("d-legend"))}"`);
}
const EVENTS = [
  { kind: "attack_start", guest_t: 131, mode: "planner:opportunistic", profile: "opportunistic" },
  { kind: "attack_plan", guest_t: 131, target: "mode_hijack", sequence: ["it_access", "it_exec", "pivot", "mode_hijack"],
    candidates: [{ node: "mode_hijack", impact: 3, detectability: 0.4 }], blocked: [], reason: "initial" },
  { kind: "plan_step", guest_t: 132, node: "it_access", stage: "it_access", ok: true, target: "mode_hijack",
    observed: { whoami: "www-data" } },
  { kind: "plan_step", guest_t: 137, node: "pivot", stage: "pivot", ok: false, target: "mode_hijack",
    observed: { detail: "refused" } },
  { kind: "red_step", guest_t: 138, step: "it_exec", stage: "it_exec", ok: true, operator: "alice", observed: {} },
  { kind: "recon", guest_t: 131, stage: "it", hosts: [{ ip: "10.0.0.2", ports: [{ port: 80, service: "http" }] }],
    foothold: { ip: "10.0.0.2", port: 80 } },
  { kind: "recon", guest_t: 133, stage: "ot", engine_ip: "10.1.0.2", modbus_port: 5020, modbus_ok: true,
    registers: { "0": 20, "2": 0 } },
  { kind: "attacker_belief", guest_t: 133, tree: { id: "via_hmi", children: [{ id: "it_access" }, { id: "ghost" }] } },
  { kind: "alert", guest_t: 139, state: "raised", detector: "rules", klass: "unsafe_command" },
  { kind: "response_write", guest_t: 141, register: "ctrl_mode", value: 0 },
  { kind: "attack_end", guest_t: 150, success: false, stage_reached: "it_exec", writes_ok: 1 },
];
const STRUCT = { kg: { nodes: [], links: [] }, tree: {
  attack_tree: { id: "impact", label: "impact", gate: "OR", children: [{ id: "via_hmi", label: "via hmi", gate: "AND",
    children: [{ id: "it_access", label: "access" }, { id: "it_exec", label: "exec" }, { id: "pivot", label: "pivot" },
               { id: "mode_hijack", label: "hijack", impact: 3 }] }] },
  defense: { it_access: { prevented_by: ["block_web_src"] } },
  countermeasures: [{ id: "block_web_src", machine: "hmi" }] } };
/* PANELS */
const out = {};
for (const [name, make] of Object.entries(window.CyberRangePanels)) {
  const failures = [];
  const step = (what, fn) => { try { fn(); } catch (e) { failures.push(`${what}: ${e.stack || e}`); } };
  const panel = make(api);
  for (const [label, run] of [["empty run", emptyRun()], ["full run", fullRun()], ["two feeders", twoFeederRun()]]) {
    if (label !== "empty run") for (const ev of EVENTS) step(`reduce ${ev.kind}`, () => panel.reduce?.(run, ev));
    if (label === "two feeders") for (const ev of TWO_FEEDER_EVENTS) step(`reduce ${ev.kind}`, () => panel.reduce?.(run, ev));
    step(`${label}: detail`, () => panel.detail?.(run));
    step(`${label}: chart`, () => panel.chart?.(run));
    for (const view of [null, ...(panel.views || []).map(v => v.id)]) {
      VIEW = view;
      for (const card of panel.cards || []) for (const t of [null, 135])
        step(`${label}: card ${card.id} in view ${view} at ${t}`, () => card.render(new El("div"), run, t));
    }
    const perspectives = (panel.graph?.options || []).find(o => o.id === "perspective")?.choices?.map(c => c.id) || [null];
    if (panel.graph) for (const t of [null, 135]) for (const perspective of perspectives)
      step(`${label}: attack tree (${perspective}) at ${t}`, () => {
        panel.graph.marks(run);
        panel.graph.drawTree(new El("div"), STRUCT, panel.graph.overlayAt(run, t), { width: 800, perspective });
      });
  }
  if (name === "cps") step("two feeders shown apart", () => {
    const run = twoFeederRun();
    for (const ev of [...EVENTS, ...TWO_FEEDER_EVENTS]) panel.reduce?.(run, ev);
    checkFeeders(panel, run, what => failures.push(what));
  });
  step("chart with no run", () => panel.chart?.(null));
  out[name] = failures;
}
console.log(JSON.stringify(out));
