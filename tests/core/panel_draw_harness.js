// panel_draw_harness.js — the dashboard page reduced to what its panels touch,
// for tests/core/test_panels.py: elements that record their children, the page's
// own model script (its reducer and helpers, taken from dashboard.html) and its
// own libraries, and runs built the way the page builds them — by folding ledger
// events of the shape the platform writes through the page's apply().
// A run built by hand would hold whatever its author thought the reducer keeps;
// built by the reducer, it holds what the page really shows.
// The test puts the panels' sources where the PANELS marker is and reads the
// failures each panel's hooks raised from the JSON printed at the end.
const fs = require("fs");
globalThis.window = globalThis;
window.CyberRangePanels = {};
// The page's libraries, the very files it serves: each is handed no module
// system, so it defines its global (d3, Plot) as it does under a script tag.
for (const file of JSON.parse(process.env.DASHBOARD_VENDOR_FILES))
  new Function("exports", "module", "define", fs.readFileSync(file, "utf8")).call(globalThis);
// An element with what the panels, d3 and Plot ask of one. Plot draws on it for
// real, so a chart given a wrong option or a missing channel throws here too.
class El {
  constructor(tag, ns) { this.tag = this.tagName = tag; this.namespaceURI = ns; this.children = []; this.attrs = {};
    this.dataset = {}; this.textContent = ""; this.clientWidth = 800; this.offsetWidth = 120;
    this.parentNode = null; this.ownerDocument = globalThis.document;
    this.style = { setProperty(k, v) { this[k] = v; }, removeProperty(k) { delete this[k]; } };
    this.classList = { add() {}, remove() {}, toggle() {}, contains: () => false }; }
  get childNodes() { return this.children; }
  get firstChild() { return this.children[0] || null; }
  get nextSibling() { return null; }
  // As the DOM does: a null handed to append() becomes the text "null".
  append(...k) { for (const c of k) { this.children.push(c == null ? String(c) : c); if (c instanceof El) c.parentNode = this; } }
  appendChild(c) { this.append(c); return c; }
  replaceChildren(...k) { this.children = []; this.append(...k); }
  insertBefore(c, ref) {
    const i = ref ? this.children.indexOf(ref) : -1;
    if (i < 0) this.children.push(c); else this.children.splice(i, 0, c);
    if (c instanceof El) c.parentNode = this;
    return c;
  }
  removeChild(c) { this.children = this.children.filter(x => x !== c); return c; }
  remove() { this.parentNode?.removeChild(this); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  setAttributeNS(ns, k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return this.attrs[k] ?? null; }
  hasAttribute(k) { return k in this.attrs; }
  removeAttribute(k) { delete this.attrs[k]; }
  removeAttributeNS(ns, k) { delete this.attrs[k]; }
  addEventListener() {}
  removeEventListener() {}
  dispatchEvent() { return true; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  matches() { return false; }
  closest() { return null; }
  cloneNode() { return new El(this.tag, this.namespaceURI); }
  getBoundingClientRect() { return { left: 0, top: 0, width: 800, height: 300 }; }
}
globalThis.Node = El;
const XHTML = "http://www.w3.org/1999/xhtml";
const els = {};
globalThis.document = { createElementNS: (ns, t) => new El(t, ns), createElement: t => new El(t, XHTML),
  createTextNode: t => String(t), createDocumentFragment: () => new El("#fragment"),
  getElementById: id => els[id] || (els[id] = new El("div")),
  documentElement: { dataset: {}, namespaceURI: XHTML }, defaultView: globalThis };
document.documentElement.ownerDocument = document;
// Tabulator lays its rows out in a real window, so it is not loaded here: this
// stand-in keeps a list's data the way Tabulator's calls do (rows known by
// `index`, added on top, updated in place, replaced), writes each row through
// the column formatters so a check can read the list as text, and records the
// calls, so a check can tell a list that was added to from one built again.
globalThis.Tabulator = class {
  constructor(box, options) {
    this.box = box; this.options = options; this.rows = [...(options.data || [])]; this.calls = [];
    Tabulator.last = this; this.draw();
  }
  draw() {
    this.shown = this.rows.map(d => {
      const row = new El("div"), component = { getData: () => d, getElement: () => row };
      for (const c of this.options.columns) row.append(c.formatter ? c.formatter({ getData: () => d, getValue: () => d[c.field] }) : String(d[c.field]), " ");
      this.options.rowFormatter?.(component);
      return component;
    });
    this.box.replaceChildren(...this.shown.map(component => component.getElement()));
    if (!this.rows.length && this.options.placeholder) this.box.append(this.options.placeholder);
  }
  on(name, fn) { if (name === "tableBuilt") fn(); }
  addData(rows, top) { this.calls.push("addData"); this.rows = top ? [...rows, ...this.rows] : [...this.rows, ...rows]; this.draw(); return Promise.resolve(); }
  updateData(rows) {
    this.calls.push("updateData");
    const key = this.options.index;
    for (const u of rows) {
      const i = this.rows.findIndex(d => d[key] === u[key]);
      if (i < 0) throw new Error(`updateData: no row ${u[key]}`);
      this.rows[i] = { ...this.rows[i], ...u };
    }
    this.draw(); return Promise.resolve();
  }
  replaceData(rows) { this.calls.push("replaceData"); this.rows = [...rows]; this.draw(); return Promise.resolve(); }
  getRows() { return this.shown; }
  scrollToRow() { return Promise.resolve(); }
  destroy() { this.calls.push("destroy"); }
};
// A panel may defer drawing to a microtask (once its box is on the page): run it
// now, so that what it throws is caught and named like the rest.
globalThis.queueMicrotask = fn => fn();

// The page's model, run as the browser runs it: a script of its own, whose
// top-level names (S, apply, h, $, num, …) the panels then find by name.
const page = fs.readFileSync(process.env.DASHBOARD_PAGE, "utf8");
const model = /<script data-part="model">([\s\S]*?)<\/script>/.exec(page);
if (!model) throw new Error("dashboard.html has no <script data-part=\"model\">: the reducer cannot be tested");
// The reducer hands each event to the panel of the run's scenario: here, the one under test.
let PANEL = null;
globalThis.panel = () => PANEL;
require("vm").runInThisContext(model[1], { filename: "dashboard.html (model)" });

let VIEW = null, TIME = null;
// The run's structure as the page hands it to a panel; null while it loads.
let STRUCTURE = null;
const api = { get S() { return S; }, $, h, svg, num, dur, clock, rel, pretty, metric, metricHead, term, termText, empty, table, grid,
  plot, plotTip, timeAxis, now: () => 200, statusBadge, structure: () => STRUCTURE,
  shownRunId: () => "r1", select() {}, render() {}, stepCell: () => h("td"), queueTable() {},
  time: () => TIME, setTime(t) { TIME = t; }, view: () => VIEW };

// ── ledger events, as the platform writes them ──────────────────────────────
// The ledger stamps `t` when the host hears of a fact; the fact's own time is
// guest_t, frame_t or write_t. They differ here, as they do in a lab.
const heard = ev => ({ run_id: "r1", t: (ev.guest_t ?? ev.frame_t ?? ev.write_t ?? 100) + 0.5, ...ev });
function runFrom(events) {
  S = fresh();
  for (const ev of events) apply(heard(ev));
  return S.runs.r1;
}
const START = { kind: "run_start", t: 100, mode: "planner:opportunistic", seed: 1, respond: "rules", learn_s: 10,
  phases: [{ name: "normal", planned_s: 30 }, { name: "attack", planned_s: 20 }] };
const PHASES = [{ kind: "phase", name: "normal", state: "start", t: 100 },
  { kind: "phase", name: "normal", state: "end", ok: true, duration_s: 30, t: 130 },
  { kind: "phase", name: "attack", state: "start", t: 130 }];
const SCORE = { kind: "run_metrics", t: 160, metrics: { attack: true, abnormal_frames: 3, recovered: true, recovery_s: 4,
  detectors: { combined: { detected: true, latency_from_write_s: 0.5, before_impact: true, false_alarms: 0 },
               rules: { detected: true, latency_from_write_s: 1.2, before_impact: true } },
  stage_reached: "it_exec", attack_succeeded: false,
  response: { policy: "rules", accurate: true, over_response: false },
  tree_fidelity: { precision: 1, recall: 0.5, discovered: ["it_access"], extra: ["ghost"] } } };
// One of every event kind of the cps family, with every field the platform
// records on it (planes/*/components.py): the views are checked against these.
const ATTACK = [
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
  { kind: "attack_end", guest_t: 150, success: false, stage_reached: "it_exec", writes_ok: 1 },
];
const DEFENCE = [
  { kind: "model_fitted", guest_t: 111, threshold: 7.5 },
  { kind: "finding", guest_t: 133, detector: "it", klass: "web_injection_pattern", src: "10.0.0.9", register: null, name: null,
    confidence: 0.8, maps_to: "it_access" },
  { kind: "tree_state", guest_t: 134, nodes: { it_access: ["confirmed", 0.9], pivot: ["suspected", 0.5] },
    active: [], hosts: ["hmi"], next: ["pivot"] },
  { kind: "decision", guest_t: 135, policy: "rules", actions: ["block_web_src"], rationale: "seen",
    covers: { block_web_src: { prevents: ["it_access"], restores: [] } }, needs_approval: [],
    cost_terms: { residual: 0.2, op: 0.1, total: 0.3 }, trigger_klass: "web_injection_pattern", trigger_t: 133 },
  { kind: "action", guest_t: 136, id: "block_web_src", ok: true, machine: "hmi", op: "apply", by: "soc" },
  { kind: "approval", guest_t: 135, request: "q1", action: "isolate_hmi", state: "requested" },
  { kind: "finding", guest_t: 139, detector: "rules", klass: "unsafe_command", src: null, register: 2, name: "dg_setpoint",
    confidence: 1, maps_to: null },
  { kind: "alert", guest_t: 139, state: "raised", detector: "rules", klass: "unsafe_command" },
  { kind: "response_write", guest_t: 141, register: "ctrl_mode", value: 0 },
];
const PLANT = [
  { kind: "plant", frame_t: 101, step: 1, v_load: 1, v_dg: 1.01, line_load: 40, p_dg: 20, abnormal: false, ctrl_mode: 0, dg_setpoint: 20, switch_cmd: 0 },
  { kind: "attack_write", write_t: 138, register: 2, register_name: "dg_setpoint", value: 200, ok: true },
  { kind: "plant", frame_t: 140, step: 40, v_load: 1.1, v_dg: 1.15, line_load: 90, p_dg: 200, abnormal: true, ctrl_mode: 1, dg_setpoint: 200, switch_cmd: 0 },
];
// The other scenarios' kinds: the MTD coordinator's telemetry.
const MTD = [{ kind: "mtd_action", guest_t: 131, action: "hop", status: "applied", cost: 1 },
  { kind: "data_gap", guest_t: 140, gap_s: 2 }];
const emptyRun = () => runFrom([START, ...PHASES]);
const fullEvents = () => [START, ...PHASES, ...DEFENCE, ...PLANT, ...MTD, ...ATTACK, SCORE];
const fullRun = () => runFrom(fullEvents());
// The same run on a plant of two feeders, attacked on the second: every sample
// carries each feeder's readings, every write, finding and alert its unit.
function twoFeederEvents() {
  const feeder = (v, abnormal, mode, kw) => ({ v_load: v, v_dg: v + 0.01, abnormal, ctrl_mode: mode, dg_setpoint: kw, switch_cmd: 0 });
  const sample = (t, second) => ({ kind: "plant", frame_t: t, ...feeder(1, false, 0, 20), units: { 1: feeder(1, false, 0, 20), 2: second } });
  return [{ ...START, units: [1, 2], attack_unit: 2, v_band: [0.95, 1.05] }, ...PHASES, ...MTD, ...ATTACK,
    { kind: "model_fitted", guest_t: 111, threshold: 7.5, unit: 1 }, { kind: "model_fitted", guest_t: 111, threshold: 6.1, unit: 2 },
    sample(101, feeder(1, false, 0, 30)), sample(140, feeder(1.1, true, 1, 80)), sample(145, feeder(1.1, true, 1, 80)),
    { kind: "finding", guest_t: 133, detector: "it", klass: "web_injection_pattern", src: "10.0.0.9" },
    { kind: "attack_write", write_t: 138, unit: 2, register: 0, register_name: "ctrl_mode", value: 1, ok: true },
    { kind: "attack_write", write_t: 138, unit: 2, register: 2, register_name: "dg_setpoint", value: 80, ok: true },
    { kind: "finding", guest_t: 139, detector: "model", klass: "behavioral_anomaly", unit: 2 },
    { kind: "finding", guest_t: 139.5, detector: "model", klass: "behavioral_anomaly", unit: 1 },
    { kind: "finding", guest_t: 141, detector: "rules", klass: "unsafe_command", unit: 2 },
    { kind: "alert", guest_t: 139, state: "raised", detector: "model", klass: "behavioral_anomaly", unit: 2 },
    { kind: "alert", guest_t: 139.5, state: "raised", detector: "model", klass: "behavioral_anomaly", unit: 1 },
    ...DEFENCE.filter(e => e.kind !== "finding" && e.kind !== "model_fitted"), SCORE];
}
// A run recorded before actions said whether they applied or reverted, decisions
// what they covered, and writes whether the plant took them: it must still draw.
const olderEvents = () => [{ ...START, respond: undefined }, ...PHASES,
  { kind: "plant", frame_t: 101, v_load: 1, v_dg: 1.01, abnormal: false, ctrl_mode: 0, dg_setpoint: 20, switch_cmd: 0 },
  { kind: "attack_write", write_t: 138, register: "dg_setpoint", value: 200 },
  { kind: "finding", guest_t: 139, detector: "rules", klass: "unsafe_command" },
  { kind: "decision", guest_t: 140, policy: "rules", actions: ["block_flow"], rationale: "seen" },
  { kind: "action", guest_t: 141, id: "block_flow", ok: true, machine: "firewall" }];

// Everything a drawn element says, in order: its own text and its children's.
const textOf = e => typeof e === "string" ? e : [e.textContent, ...(e.children || []).map(textOf)].join(" ");
const all = (e, pred, out = []) => { if (typeof e !== "string") { if (pred(e)) out.push(e); for (const c of e.children) all(c, pred, out); } return out; };
const drawn = (card, run, t = null, view = null) => { VIEW = view; const box = new El("div"); card.render(box, run, t); return textOf(box); };
const cardOf = (p, id) => (p.cards || []).find(c => c.id === id);

// ── the page's reducer, whatever the panel ──────────────────────────────────
function checkPage(fail) {
  PANEL = null;
  // A fact is the event whole: a field the ledger carries reaches the views
  // without the reducer having to know its name.
  for (const [kind, spec] of Object.entries(FACTS)) {
    const run = runFrom([START, { kind, guest_t: 120, frame_t: 121, write_t: 122, __probe: 1 }]);
    const kept = run[spec.list][run[spec.list].length - 1];
    if (!kept || kept.__probe !== 1) fail(`${kind}: the reducer drops fields of the event, so a view reading one shows nothing`);
    const own = { frame_t: 121, write_t: 122 }[spec.t] ?? 120;
    if (kept && kept.t !== own) fail(`${kind}: its time is ${kept.t}, not the ${spec.t || "guest_t"} it happened at (${own})`);
  }
  // A run's results are read under the keys a campaign aggregates them under,
  // and a yes/no is said as one: on a single run "1" reads as a count.
  const flat = flatMetrics(SCORE.metrics);
  if (flat["detectors.combined.latency_from_write_s"] !== 0.5 || flat["response.accurate"] !== true || !Array.isArray(flat["tree_fidelity.extra"]))
    fail(`a run's metrics are not flattened as the campaign's are: ${JSON.stringify(flat)}`);
  const said = [metricValue(true, metric("response.accurate")), metricValue(null, metric("mitigated_s")), metricValue(4, metric("recovery_s")), metricValue([], metric("x"))];
  if (said.join("|") !== "yes|—|4 s|none") fail(`a run's results read "${said.join("|")}"`);
  // The rows of a run's results: the scenario's own first, each beside the
  // campaign's mean for runs of its mode; with no panel, every metric is "other".
  const scored = runFrom([START, ...PHASES, SCORE]);
  const rows = scoreRows(scored, [{ mode: "planner:opportunistic", metric: "recovery_s", n: 3, mean: 5, ci95_low: 4, ci95_high: 6 },
    { mode: "another", metric: "abnormal_frames", n: 3, mean: 9 }]);
  const row = key => rows.find(d => d.key === key) || {};
  if (row("recovery_s").meanText !== "5 [4 – 6]" || row("abnormal_frames").n != null) fail(`a run's results are compared with a campaign's runs of another mode: ${JSON.stringify([row("recovery_s"), row("abnormal_frames")])}`);
  if (row("response.accurate").sort !== 1 || row("stage_reached").sort !== null || rows.some(d => d.kind !== "other")) fail("a run's results cannot be ordered or have a kind with no panel to give one");
  const aggregate = { kind: "aggregate", t: 300, detection: [], impact: [], response: [{ mode: "m" }], countermeasures: [], ci: [] };
  runFrom([START, { run_id: undefined, ...aggregate }]);
  if (!S.aggregate || !S.aggregate.response) fail("aggregate: a table the campaign reported is dropped before any panel sees it");
  runFrom([START, { run_id: undefined, kind: "aggregate_failed", t: 300, error: "boom" }]);
  if (S.aggregateError !== "boom") fail("aggregate_failed: a campaign that could not aggregate shows nothing of it");
  runFrom([START, { kind: "made_up_kind", guest_t: 120 }, { kind: "made_up_kind", guest_t: 121 }, { kind: "finding", guest_t: 122 }]);
  if (S.unshown.made_up_kind !== 2) fail(`an event kind the page has no view for is not counted as unshown: ${JSON.stringify(S.unshown)}`);
  if (Object.keys(S.unshown).length !== 1) fail(`kinds the page does show are listed as unshown: ${JSON.stringify(S.unshown)}`);
  // A campaign of command steps: a unit is scored mid-way, runs more steps, and
  // has no end event of its own. It must not stay "running" once the next unit
  // starts, nor the last one once the campaign ends.
  S = fresh();
  const unit = (u, t) => [{ kind: "unit_start", unit: u, t }, { kind: "step_start", unit: u, step: "datasets", t: t + 1 },
    { kind: "step_end", unit: u, step: "datasets", ok: true, t: t + 5 }, { kind: "run_metrics", run_id: u, metrics: { x: 1 }, t: t + 6 },
    { kind: "step_start", unit: u, step: "plot", t: t + 7 }, { kind: "step_end", unit: u, step: "plot", ok: true, t: t + 9 }];
  for (const ev of [{ kind: "campaign_start", name: "c", t: 100, grid: [{ run_id: "a", group: "a", seed: 1 }, { run_id: "b", group: "b", seed: 1 }] },
      ...unit("a", 100), ...unit("b", 110)]) apply(ev);
  if (S.runs.a.status !== "ok") fail(`a campaign unit is still "${S.runs.a.status}" after the next unit started`);
  if (S.runs.b.status !== "running") fail(`the unit under way reads "${S.runs.b.status}"`);
  apply({ kind: "campaign_end", status: "done", t: 120 });
  if (S.runs.b.status !== "ok" || S.runs.b.duration !== 10) fail(`the last unit of a finished campaign reads "${S.runs.b.status}" after ${S.runs.b.duration} s: it would run for ever`);
  if (S.current != null) fail("a finished campaign still names a unit as the one under way");
  if (num(NaN) !== "—" || num(null) !== "—") fail(`num() prints ${num(NaN)} for a value that is not a number`);
}

// What a plant of several feeders must show, on the panels of the cps family.
function checkFeeders(panel, fail) {
  PANEL = panel;
  const run = runFrom(twoFeederEvents());
  panel.detail(run);
  const tabs = all($("d-chips"), e => e.tag === "button");
  const pressed = tabs.filter(b => b.attrs["aria-pressed"] === "true").map(textOf).join();
  if (tabs.length !== 2) fail(`feeder selector: ${tabs.length} buttons for two feeders`);
  if (!/unit 2/.test(pressed)) fail(`feeder selector: the attacked feeder is not the one shown (${pressed})`);
  const chips = textOf($("d-chips"));
  if (!/MANUAL/.test(chips) || !/80 kW/.test(chips)) fail(`chips show another feeder's state: ${chips}`);
  const rows = all($("d-findings"), e => e.tag === "tr").map(textOf);
  if (rows.filter(t => /behavioral anomaly/.test(t)).length !== 2)
    fail(`findings table merges the two feeders' model findings: ${rows.join(" / ")}`);
  if (!/feeder/.test(rows[0])) fail("findings table has no feeder column");
  run.x.unit = "1";
  panel.detail(run);
  if (/MANUAL/.test(textOf($("d-chips")))) fail("feeder 1 selected, feeder 2's MANUAL still shown");
  const single = runFrom(fullEvents());
  panel.detail(single);
  if (all($("d-chips"), e => e.tag === "button").length) fail("a plant of one feeder got a feeder selector");
  if (/feeder/.test(textOf($("d-findings")))) fail("a plant of one feeder got a feeder column");
  if (/null|undefined|feeder/.test(textOf($("d-legend")))) fail(`a plant of one feeder: the legend reads "${textOf($("d-legend"))}"`);
}

// What the ledger records and the cps views must therefore show. Each of these
// was once a column of dashes or a wrong picture, with every test green.
function checkFacts(panel, fail) {
  PANEL = panel;
  STRUCTURE = STRUCT;
  const has = (text, what, why) => { if (!what.test(text)) fail(`${why}: got "${text.replace(/\s+/g, " ").slice(0, 400)}"`); };
  let run = runFrom(fullEvents());
  const defender = drawn(cardOf(panel, "defender"), run, null, "defender");
  has(defender, /web injection pattern \(decided 2 s later\)/, "the decisions table does not say which finding triggered a decision, or how long after");
  has(defender, /operational cost 0\.1/, "the decisions table does not show what the policy weighed (cost_terms)");
  const chain = drawn(cardOf(panel, "killchain"), run);
  has(chain, /Block the attacking source\s+at \+/, "the kill chain does not name the countermeasure that covered a step");
  // A step and a countermeasure go by the names the run's structure gives them.
  if (/it_access|block_web_src/.test(chain)) fail(`the kill chain shows recorded identifiers where the structure has names: ${chain.replace(/\s+/g, " ").slice(0, 300)}`);
  STRUCTURE = null;
  has(drawn(cardOf(panel, "killchain"), run), /it access/, "until the structure loads, a step should read as words, not as an identifier");
  STRUCTURE = STRUCT;
  has(drawn(cardOf(panel, "journal"), run), /web injection pattern from 10\.0\.0\.9, pointing to the step "access"/, "the journal does not say which attack step a finding points to");
  // A write the plant refused is not a write that changed it.
  run = runFrom([...fullEvents(), { kind: "attack_write", write_t: 142, register: 2, register_name: "dg_setpoint", value: 300, ok: false }]);
  has(drawn(cardOf(panel, "sides"), run), /1 refused/, "the attacker's writes do not say how many the plant refused");
  // A countermeasure reverted is no longer in force: not on the tree, not on the topology.
  const revert = { kind: "action", guest_t: 145, id: "block_web_src", ok: true, machine: "hmi", op: "revert", by: "blue" };
  run = runFrom([...fullEvents(), revert]);
  if (!("block_web_src" in panel.graph.overlayAt(run, 140).applied)) fail("a countermeasure applied at 136 is not in force at 140");
  if ("block_web_src" in panel.graph.overlayAt(run, null).applied) fail("a reverted countermeasure is still drawn as applied");
  has(drawn(cardOf(panel, "journal"), run), /reverts "Block the attacking source"/, "the journal shows a revert as another application");
  if (!panel.graph.marks(run).some(m => /block web src reverted/.test(m.kind))) fail("the time bar names a revert as an application");
  // The journal reads newest first, and a new fact is a row added on top of
  // the list that is there: the rows already in it stay. A list replaced at
  // every event throws the reader back to its top and takes a row from under a click.
  run = runFrom(fullEvents());
  VIEW = null;
  const journal = new El("div");
  cardOf(panel, "journal").render(journal, run, null);
  const list = Tabulator.last, was = list.rows.map(d => d.key);
  if (!/attack ends/.test(list.rows[0].text) || !/attack starts|reconnaissance/.test(list.rows[was.length - 1].text))
    fail(`the journal is not newest first: it opens with "${list.rows[0].text}"`);
  apply(heard({ kind: "finding", guest_t: 155, detector: "rules", klass: "policy_violation", src: null, maps_to: null }));
  cardOf(panel, "journal").render(journal, run, null);
  if (list.rows.length !== was.length + 1 || !/policy violation/.test(list.rows[0].text)) fail(`a new fact did not go to the top of the journal: ${list.rows.length} rows after ${was.length}`);
  if (Tabulator.last !== list || list.calls.includes("replaceData") || was.some((key, i) => list.rows[i + 1].key !== key))
    fail("the journal rebuilt its list for one new fact: the reader loses their place at every event");
  // A burst that grows by one is the same row with its text updated, not a row more.
  apply(heard({ kind: "finding", guest_t: 156, detector: "rules", klass: "policy_violation", src: null, maps_to: null }));
  cardOf(panel, "journal").render(journal, run, null);
  if (list.rows.length !== was.length + 1 || !/policy violation ×2/.test(list.rows[0].text) || list.calls.includes("replaceData"))
    fail(`a finding repeated within the burst is not folded into its row: the journal opens with "${list.rows[0].text}"`);
  // A fact after the time shown is greyed, and a click on a fact shows the run then.
  cardOf(panel, "journal").render(journal, run, 135);
  const greyed = all(journal, e => e.style && e.style.opacity === ".4").length;
  if (!greyed || greyed === list.rows.length) fail(`the journal greys ${greyed} of ${list.rows.length} facts at a time in the middle of the run`);
  // A card that throws is drawn again at the next frame: drawn once and kept,
  // its error would be shown for a second and a blank card for ever after.
  const grid = api.grid, broken = new El("div");
  let tries = 0;
  api.grid = () => { tries++; throw new Error("no list library"); };
  for (let i = 0; i < 2; i++) try { cardOf(panel, "journal").render(broken, run, null); } catch (e) { /* the page shows it */ }
  api.grid = grid;
  if (tries !== 2) fail(`a journal that failed to draw was tried ${tries} time(s) in two frames: its error would not stay in sight`);
  // A run's results are filtered by kind: every metric this scenario records
  // has one, and the ones it reports as results open the list.
  const results = scoreRows(runFrom([START, ...PHASES, SCORE]), []);
  const unplaced = results.filter(d => d.kind === "other").map(d => d.key);
  if (unplaced.length) fail(`these metrics have no kind, so no filter of the run's results finds them but "Other": ${unplaced.join(", ")}`);
  const kindOf = key => results.find(d => d.key === key)?.kind;
  if (kindOf("detectors.rules.latency_from_write_s") !== "detection" || kindOf("response.policy") !== "response" || kindOf("stage_reached") !== "attack" || kindOf("recovery_s") !== "plant")
    fail(`a metric is filed under the wrong kind: ${JSON.stringify(results.map(d => [d.key, d.kind]))}`);
  if (!results[0].main || results[0].key !== "detectors.combined.detected") fail(`a run's results do not open on the ones the scenario reports: ${results[0].key}`);
  // The journal is beside every view, so it is in none of them.
  if (cardOf(panel, "journal").dock !== "side") fail("the journal is not docked beside the views");
  // A model that could not be fitted is said, not left to look like a quiet run.
  run = runFrom([...fullEvents(), { kind: "model_error", guest_t: 112, error: "too few samples" }]);
  if (S.unshown.model_error) fail("model_error is recorded and shown nowhere");
  has(drawn(cardOf(panel, "journal"), run), /could not be fitted: too few samples/, "the journal does not report a model that failed to fit");
  // The campaign tables the scenario reports and the page used to drop.
  const table = new El("table");
  panel.results.render("response", { response: [{ mode: "manual-hijack", policy: "rules", runs: 3, accuracy: 0.67 }] }, table);
  has(textOf(table), /manual-hijack[\s\S]*0\.67/, "the Response tab does not draw the campaign's response table");
  panel.results.render("countermeasures", { countermeasures: [{ countermeasure: "block_flow", runs: 2, dispatch_median_s: 0.4 }] }, table);
  has(textOf(table), /block_flow[\s\S]*0\.4/, "the Countermeasures tab does not draw the campaign's table");
  // A run recorded before these fields existed draws, and its one action stands applied.
  run = runFrom(olderEvents());
  if (!("block_flow" in panel.graph.overlayAt(run, null).applied)) fail("an action recorded without `op` is not taken as applied");
  for (const card of panel.cards) drawn(card, run);
}

function checkMtd(panel, fail) {
  PANEL = panel;
  const alert = (t, state) => ({ kind: "detector_alert", guest_t: t, scmc_id: "s1", state, p: 0.9 });
  const run = runFrom([START, ...MTD, alert(120, "raised"), alert(125, "cleared"), alert(130, "raised"),
    { kind: "detection", guest_t: 120, scmc_id: "s1", p: 0.9, alert: true }]);
  panel.detail(run);
  const chips = all($("d-chips"), e => e.className === "chip").map(textOf).map(t => t.replace(/\s+/g, " ").trim());
  const alerts = chips.find(t => /^attack-detector alerts/.test(t));
  if (!/ 2$/.test(alerts || "")) fail(`two alerts were raised (one of them cleared); the chip reads "${alerts}"`);
}

const STRUCT = { kg: { nodes: [], links: [] }, tree: {
  attack_tree: { id: "impact", label: "impact", gate: "OR", children: [{ id: "via_hmi", label: "via hmi", gate: "AND",
    children: [{ id: "it_access", label: "access" }, { id: "it_exec", label: "exec" }, { id: "pivot", label: "pivot" },
               { id: "mode_hijack", label: "hijack", impact: 3 }] }] },
  defense: { it_access: { prevented_by: ["block_web_src"] } },
  countermeasures: [{ id: "block_web_src", label: "Block the attacking source", machine: "hmi" }] } };
/* PANELS */
const out = { page: [] };
try { checkPage(what => out.page.push(what)); } catch (e) { out.page.push(`the reducer threw: ${e.stack || e}`); }
for (const [name, make] of Object.entries(window.CyberRangePanels)) {
  const failures = [];
  const step = (what, fn) => { try { fn(); } catch (e) { failures.push(`${what}: ${e.stack || e}`); } };
  const panel = PANEL = make(api);
  for (const [label, events] of [["empty run", [START, ...PHASES]], ["full run", fullEvents()],
      ["two feeders", twoFeederEvents()], ["older ledger", olderEvents()]]) {
    let run = null;
    step(`${label}: reduce`, () => { run = runFrom(events); });
    if (!run) continue;
    step(`${label}: detail`, () => panel.detail?.(run));
    step(`${label}: chart`, () => panel.chart?.(run));
    // Each card before the run's structure has loaded, and once it has.
    for (const structure of [null, STRUCT]) for (const view of [null, ...(panel.views || []).map(v => v.id)]) {
      VIEW = view; STRUCTURE = structure;
      for (const card of panel.cards || []) for (const t of [null, 135])
        step(`${label}: card ${card.id} in view ${view} at ${t}${structure ? "" : ", structure not loaded"}`, () => card.render(new El("div"), run, t));
    }
    const perspectives = (panel.graph?.options || []).find(o => o.id === "perspective")?.choices?.map(c => c.id) || [null];
    if (panel.graph) for (const t of [null, 135]) for (const perspective of perspectives)
      step(`${label}: attack tree (${perspective}) at ${t}`, () => {
        panel.graph.marks(run);
        panel.graph.drawTree(new El("div"), STRUCT, panel.graph.overlayAt(run, t), { width: 800, perspective });
      });
  }
  if (name === "cps") {
    step("two feeders shown apart", () => checkFeeders(panel, what => failures.push(what)));
    step("what the ledger records is shown", () => checkFacts(panel, what => failures.push(what)));
  }
  if (name === "mqtt-mtd") step("detector alerts counted once", () => checkMtd(panel, what => failures.push(what)));
  step("chart with no run", () => panel.chart?.(null));
  out[name] = failures;
}
console.log(JSON.stringify(out));
