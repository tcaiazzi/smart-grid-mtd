// panel.js — the cps scenario's views on the platform dashboard
// (cyberrange/core/dashboard.html, which serves every scenario's panel at /graph.js).
//
// The run's two sides at once: what the attacker does and knows, what the
// defender does and believes (the "Attacker · Defender" card), on top of the
// plant chart, the findings, and the topology / knowledge-graph / attack-tree
// views. Self-contained (no libraries, no CDN); every structure view is a pure
// function of (structure, overlay) drawing an SVG with a deterministic layout, so
// a redraw never moves anything that did not change.
//
//   structure = /api/structure → {source, kg: networkx node-link, tree: {attack_tree, defense, countermeasures}}
//   overlay   = overlayAt(run, t) → the defender's response state and the attacker's progress at time t
"use strict";
(function () {
  const NS = "http://www.w3.org/2000/svg";
  function el(tag, attrs, text) {
    const e = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v != null) e.setAttribute(k, v);
    if (text != null) e.textContent = text;
    return e;
  }
  function clip(s, n) { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; }
  function wrap2(s, n) {             // two lines of at most n chars, word-wrapped
    const words = String(s ?? "").split(/\s+/), lines = [""];
    for (const w of words) {
      const cur = lines[lines.length - 1];
      if (!cur || (cur + " " + w).length <= n) lines[lines.length - 1] = cur ? `${cur} ${w}` : w;
      else if (lines.length < 2) lines.push(w);
      else { lines[1] = clip(`${lines[1]} ${w}`, n); break; }
    }
    return lines.map(l => clip(l, n));
  }
  const ZONE_ORDER = ["IT", "OT", "MGMT"];
  const STATE_STYLE = {
    confirmed: { stroke: "var(--critical)", fill: "var(--critical)", dash: null, label: "confirmed" },
    inferred: { stroke: "var(--serious)", fill: "var(--serious)", dash: "5 3", label: "inferred" },
    suspected: { stroke: "var(--warning)", fill: "var(--warning)", dash: null, label: "suspected" },
    unknown: { stroke: "var(--axis)", fill: null, dash: null, label: "not seen" },
  };
  const ATTACKER_STYLE = {
    done: { stroke: "var(--critical)", fill: "var(--critical)", dash: null, label: "done" },
    failed: { stroke: "var(--critical)", fill: null, dash: "4 3", label: "failed" },
    target: { stroke: "var(--serious)", fill: null, dash: "2 2", label: "its target" },
  };
  // How an applied countermeasure shows on the topology, by its kind (others: a
  // generic tag). A run recorded before kinds were has its ids for kinds.
  const CM_STYLE = {
    block_flow: { kind: "block", tag: "flow blocked" },
    isolate_way: { kind: "isolate", tag: "isolated" },
    isolate_ot_host: { kind: "isolate", tag: "isolated" },
    isolate_hmi: { kind: "isolate", tag: "isolated" },
    force_auto: { kind: "restore", tag: "AUTO + setpoint restored" },
    restore_breaker: { kind: "restore", tag: "breaker re-closed" },
  };

  // ── graph index ────────────────────────────────────────────────────────────
  function index(kg) {
    const nodes = {}, out = {}, inn = {};
    for (const n of kg.nodes || []) { nodes[n.id] = n; out[n.id] = []; inn[n.id] = []; }
    for (const l of kg.links || kg.edges || []) {
      const e = { s: l.source, t: l.target, rel: l.rel || l.key, attrs: l };
      if (out[e.s]) out[e.s].push(e);
      if (inn[e.t]) inn[e.t].push(e);
    }
    const rel = (id, r) => (out[id] || []).filter(e => e.rel === r).map(e => e.t);
    const relIn = (id, r) => (inn[id] || []).filter(e => e.rel === r).map(e => e.s);
    const ofType = t => Object.values(nodes).filter(n => n.type === t);
    return { nodes, out, inn, rel, relIn, ofType };
  }
  function zoneOrder(zones) {
    return zones.map(z => z.name || z.id.slice(5)).sort((a, b) => {
      const ia = ZONE_ORDER.indexOf(a), ib = ZONE_ORDER.indexOf(b);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b);
    });
  }
  function treeIndex(tree) {
    const nodes = {}, parent = {};
    (function walk(n, p) { nodes[n.id] = n; if (p) parent[n.id] = p.id; (n.children || []).forEach(c => walk(c, n)); })(tree.attack_tree, null);
    const cms = {}; for (const c of tree.countermeasures || []) cms[c.id] = c;
    return { nodes, parent, cms };
  }

  // ── response state at time t ──────────────────────────────────────────────
  // Every fact of either side is a stop of the run's time bar.
  function marks(run) {
    const m = [];
    for (const s of run.states || []) m.push({ t: s.t, kind: "belief update" });
    for (const d of run.decisions || []) m.push({ t: d.t, kind: "decision" });
    for (const a of run.actions || []) m.push({ t: a.t, kind: `${a.id} ${a.ok ? "applied" : "failed"}` });
    for (const w of run.writes || []) m.push({ t: w.t, kind: "attacker write" });
    const red = run.x && run.x.red;
    if (red) {
      for (const st of red.steps) m.push({ t: st.t, kind: `attacker ${st.node} ${st.ok ? "done" : "failed"}` });
      for (const c of red.recon) m.push({ t: c.t, kind: `attacker recon (${c.stage})` });
    }
    // One stop per detector and class: a burst of identical findings is one fact.
    const seen = new Set();
    for (const f of run.findings || []) {
      const k = `${f.detector}|${f.klass}`;
      if (!seen.has(k)) { seen.add(k); m.push({ t: f.t, kind: `${f.detector}: ${f.klass}` }); }
    }
    return m.filter(x => x.t != null).sort((a, b) => a.t - b.t);
  }
  const uptoT = t => x => t == null || (x && x.t != null && x.t <= t + 1e-6);
  function overlayAt(run, t) {
    const upto = uptoT(t);
    const states = (run.states || []).filter(upto);
    const st = states[states.length - 1] || null;
    const applied = {};
    for (const a of run.actions || []) if (upto(a) && a.ok && a.id !== "notify" && !(a.id in applied)) applied[a.id] = a.t;
    // What the attacker really did by t, drawn over the defender's belief.
    const red = run.x && run.x.red, done = {}, failed = {};
    const steps = red ? red.steps.filter(upto) : [], plans = red ? red.plans.filter(upto) : [];
    for (const s of steps) (s.ok ? done : failed)[s.node] = s.t;
    const target = plans.length ? plans[plans.length - 1].target : (steps.length ? steps[steps.length - 1].target : null);
    return {
      t, nodes: st ? st.nodes || {} : {}, active: st ? st.active || [] : [], hosts: st ? st.hosts || [] : [],
      next: st ? st.next || [] : [], applied, writes: (run.writes || []).filter(upto).length,
      decisions: (run.decisions || []).filter(upto),
      red: { done, failed, target },
    };
  }
  function stateOf(ov, id) { const s = ov.nodes[id]; return s ? { state: s[0], score: s[1] } : { state: "unknown", score: 0 }; }

  // What the overlay implies on the knowledge graph: blocked rules, isolated /
  // restored hosts, hosts carrying an active impact, highlighted kg nodes.
  function implications(G, T, ov) {
    const blocked = new Set(), isolated = new Set(), tags = {}, hot = new Set(ov.hosts.map(h => `host:${h}`));
    const tag = (host, text, color) => (tags[host] = tags[host] || []).push({ text, color });
    for (const id of Object.keys(ov.applied)) {
      const cm = T.cms[id]; if (!cm) continue;
      const style = CM_STYLE[cm.kind || id] || { kind: "tag", tag: id };
      if (style.kind === "block") {
        for (const nid of cm.prevents || []) for (const tgt of (T.nodes[nid]?.targets || []))
          if (G.nodes[tgt]?.type === "flow_rule") blocked.add(tgt);
      } else if (style.kind === "isolate" && cm.machine) isolated.add(`host:${cm.machine}`);
      if (cm.machine && style.kind !== "block") tag(`host:${cm.machine}`, style.tag, "var(--good)");
    }
    for (const h of ov.hosts) tag(`host:${h}`, "compromised (inferred)", "var(--critical)");
    for (const leaf of ov.active) {
      const st = stateOf(ov, leaf).state;
      for (const tgt of T.nodes[leaf]?.targets || []) {
        hot.add(tgt);
        if (G.nodes[tgt]?.type === "register") {
          for (const svc of G.relIn(tgt, "exposes")) for (const h of G.relIn(svc, "runs")) {
            const txt = `${st === "confirmed" ? "impact" : "possible impact"}: ${leaf}`;
            if (!(tags[h] || []).some(x => x.text === txt)) tag(h, txt, st === "confirmed" ? "var(--critical)" : "var(--warning)");
          }
        }
      }
    }
    for (const [nid, s] of Object.entries(ov.nodes))
      if (s[0] === "confirmed" || s[0] === "inferred") for (const tgt of T.nodes[nid]?.targets || []) hot.add(tgt);
    return { blocked, isolated, tags, hot };
  }

  // ── topology ──────────────────────────────────────────────────────────────
  function drawTopology(box, S, ov, opts) {
    const G = index(S.kg), T = treeIndex(S.tree), I = implications(G, T, ov);
    const W = Math.max(720, (opts && opts.width) || box.clientWidth || 960);
    const zones = zoneOrder(G.ofType("zone"));
    const zi = Object.fromEntries(zones.map((z, i) => [z, i]));
    const hosts = G.ofType("host").sort((a, b) => a.name.localeCompare(b.name));
    const hostZones = h => G.rel(h.id, "in_zone").map(z => G.nodes[z].name).filter(z => z in zi).sort((a, b) => zi[a] - zi[b]);
    const ips = h => G.rel(h.id, "has_ip").map(i => G.nodes[i]);
    const addrZone = ip => { const z = G.rel(ip.id, "in_zone")[0]; return z ? G.nodes[z].name : null; };
    const svcs = h => G.rel(h.id, "runs").map(s => G.nodes[s]);
    const BW = 184, GAP = BW + 76, M = 12, HEAD = 30;
    const colW = Math.max(BW + 24, (W - 2 * M - GAP * (zones.length - 1)) / zones.length);
    const colX = i => M + i * (colW + GAP);
    // host box size: name + role + one line per address + services + tags
    const lines = h => 2 + ips(h).length + (I.tags[h.id] || []).length;
    const boxH = h => 10 + lines(h) * 15 + svcs(h).length * 20 + 6;
    const place = {}, stackY = {};
    const slot = (key, h) => { const y = stackY[key] ?? (HEAD + 18); stackY[key] = y + boxH(h) + 18; return y; };
    for (const h of hosts) {
      const zs = hostZones(h);
      let x;
      // A host on two neighbouring zones sits on the edge between them. Zones
      // further away (the management network, for a host of IT) are not drawn
      // as a link: the line would cross the columns in between, and the host's
      // address list already says it is there.
      const k = zs.findIndex((z, n) => n + 1 < zs.length && zi[zs[n + 1]] - zi[z] === 1);
      if (k >= 0) {
        const a = zi[zs[k]];
        x = colX(a) + colW + (GAP - BW) / 2;
        place[h.id] = { x, y: slot(`gap${a}-${a + 1}`, h), zs: [zs[k], zs[k + 1]] };
      } else {
        const i = zi[zs[0]] ?? 0;
        x = colX(i) + (colW - BW) / 2;
        place[h.id] = { x, y: slot(`col${i}`, h), zs: zs.slice(0, 1) };
      }
    }
    const H = Math.max(...Object.values(stackY), HEAD + 120) + 30;
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Lab topology", class: "graph" });
    const defs = el("defs");
    for (const [id, col] of [["arr", "var(--ink-2)"], ["arr-bad", "var(--critical)"]]) {
      const mk = el("marker", { id: `${id}-${box.id}`, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" });
      mk.append(el("path", { d: "M0,0 L10,5 L0,10 z", fill: col })); defs.append(mk);
    }
    svg.append(defs);
    // zones
    zones.forEach((z, i) => {
      svg.append(el("rect", { x: colX(i), y: 4, width: colW, height: H - 8, rx: 10, fill: "var(--wash)", stroke: "var(--grid)" }));
      const nets = [...new Set(G.ofType("ip").filter(ip => addrZone(ip) === z).map(ip => ip.network))].join(", ");
      svg.append(el("text", { x: colX(i) + 12, y: 22, "font-size": 13, "font-weight": 600, fill: "var(--ink)" }, `${z} zone`));
      if (nets) svg.append(el("text", { x: colX(i) + colW - 10, y: 22, "font-size": 11, fill: "var(--muted)", "text-anchor": "end" }, nets));
    });
    // interface links of boundary devices (dashed = no address: passive tap)
    for (const h of hosts) {
      const p = place[h.id]; if (p.zs.length < 2) continue;
      const addrBy = {}; for (const ip of ips(h)) addrBy[addrZone(ip)] = ip;
      const ifBy = {}; for (const e of G.out[h.id].filter(e => e.rel === "in_zone")) ifBy[G.nodes[e.t].name] = e.attrs.iface;
      for (const z of p.zs) {
        const i = zi[z], left = colX(i) + colW < p.x;
        const x1 = left ? p.x : p.x + BW, x2 = left ? colX(i) + colW : colX(i), y = p.y + 22;
        const tap = !addrBy[z];
        svg.append(el("line", { x1, y1: y, x2, y2: y, stroke: tap ? "var(--muted)" : "var(--ink-2)", "stroke-width": 1.5, "stroke-dasharray": tap ? "4 3" : null }));
        svg.append(el("text", { x: (x1 + x2) / 2, y: y - 4, "font-size": 10, fill: "var(--muted)", "text-anchor": "middle" }, ifBy[z] || ""));
        if (tap) svg.append(el("text", { x: (x1 + x2) / 2, y: y + 12, "font-size": 10, fill: "var(--muted)", "text-anchor": "middle" }, "tap"));
      }
    }
    // flow rules: src host -> boundary -> dst service
    const svcPos = {};
    const ruleLayer = el("g");
    // hosts
    for (const h of hosts) {
      const p = place[h.id], hh = boxH(h), hot = I.tags[h.id]?.some(t => t.color === "var(--critical)") && ov.hosts.includes(h.name);
      const g = el("g", { opacity: I.isolated.has(h.id) ? 0.45 : 1 });
      g.append(el("rect", { x: p.x, y: p.y, width: BW, height: hh, rx: 8, fill: "var(--surface)",
        stroke: hot ? "var(--critical)" : "var(--ring)", "stroke-width": hot ? 2.5 : 1 }));
      let y = p.y + 18;
      g.append(el("text", { x: p.x + 10, y, "font-size": 13, "font-weight": 600, fill: "var(--ink)" }, h.name));
      g.append(el("text", { x: p.x + BW - 10, y, "font-size": 11, fill: "var(--muted)", "text-anchor": "end" }, h.role));
      for (const ip of ips(h)) { y += 15; g.append(el("text", { x: p.x + 10, y, "font-size": 11, fill: "var(--ink-2)", "font-family": "ui-monospace, monospace" }, `${ip.iface} ${ip.addr}/${ip.prefix}`)); }
      if (h.forward_default) { y += 15; g.append(el("text", { x: p.x + 10, y, "font-size": 11, fill: "var(--ink-2)" }, `FORWARD default ${h.forward_default}`)); }
      for (const s of svcs(h)) {
        y += 8;
        g.append(el("rect", { x: p.x + 10, y, width: BW - 20, height: 16, rx: 8, fill: I.hot.has(s.id) ? "var(--wash)" : "none", stroke: I.hot.has(s.id) ? "var(--critical)" : "var(--axis)" }));
        g.append(el("text", { x: p.x + 18, y: y + 12, "font-size": 11, fill: "var(--ink-2)" }, `${s.name} · ${s.proto}/${s.port}`));
        svcPos[s.id] = { x: p.x + 10, y: y + 8, w: BW - 20 };
        y += 12;
      }
      for (const t of I.tags[h.id] || []) {
        y += 15;
        g.append(el("circle", { cx: p.x + 14, cy: y - 4, r: 3.5, fill: t.color }));
        g.append(el("text", { x: p.x + 22, y, "font-size": 11, fill: "var(--ink)" }, clip(t.text, 27)));
      }
      g.append(el("title", {}, [h.name, h.role, ...ips(h).map(i => i.addr)].join(" · ")));
      svg.append(g);
    }
    for (const rule of G.ofType("flow_rule")) {
      const src = G.rel(rule.id, "src")[0], dst = G.rel(rule.id, "dst")[0];
      const fw = G.relIn(rule.id, "enforces")[0];
      if (!src || !dst || !place[src] || !svcPos[dst] || !place[fw]) continue;
      const bad = I.blocked.has(rule.id), ps = place[src], pf = place[fw], pd = svcPos[dst];
      const sx = ps.x + BW, sy = ps.y + 24, fx = pf.x + BW / 2, fy = pf.y + boxH(G.nodes[fw]) + 2;
      const dx = pd.x, dy = pd.y;
      const midY = Math.max(fy + 26, sy, dy);
      const d = `M${sx},${sy} C${sx + 40},${sy} ${fx - 60},${midY} ${fx},${midY} S${dx - 40},${dy} ${dx},${dy}`;
      ruleLayer.append(el("path", { d, fill: "none", stroke: bad ? "var(--critical)" : "var(--ink-2)", "stroke-width": 2,
        "stroke-dasharray": bad ? "6 4" : null, "marker-end": `url(#${bad ? "arr-bad" : "arr"}-${box.id})` }));
      const label = `${rule.proto || "any"}/${rule.dport ?? "any"} ${rule.action}${bad ? " → BLOCKED" : ""}`;
      ruleLayer.append(el("text", { x: fx, y: midY + 15, "font-size": 11, "text-anchor": "middle", fill: bad ? "var(--critical)" : "var(--ink-2)",
        "font-weight": bad ? 600 : 400, stroke: "var(--surface)", "stroke-width": 3, "paint-order": "stroke" }, label));
      if (ov.writes) ruleLayer.append(el("text", { x: fx, y: midY - 6, "font-size": 11, "text-anchor": "middle", fill: "var(--critical)",
        stroke: "var(--surface)", "stroke-width": 3, "paint-order": "stroke" }, `${ov.writes} attacker write${ov.writes === 1 ? "" : "s"}`));
      if (bad) ruleLayer.append(el("path", { d: `M${fx - 6},${midY - 6} L${fx + 6},${midY + 6} M${fx + 6},${midY - 6} L${fx - 6},${midY + 6}`, stroke: "var(--critical)", "stroke-width": 2.5 }));
    }
    svg.append(ruleLayer);
    box.replaceChildren(svg);
    return [
      ["var(--critical)", "compromised (inferred) / blocked / impact"], ["var(--good)", "countermeasure applied"],
      ["var(--warning)", "possible impact"], ["var(--muted)", "dashed link: passive tap (no address)"],
    ];
  }

  // ── knowledge graph ───────────────────────────────────────────────────────
  const LAYERS = ["zone", "host", "ip", "service", "flow_rule", "register"];
  const REL_COLOR = {
    in_zone: "var(--muted)", has_ip: "var(--s1)", runs: "var(--s2)", exposes: "var(--ink-2)",
    may_write: "var(--warning)", enforces: "var(--axis)", src: "var(--good)", dst: "var(--good)",
  };
  function drawKG(box, S, ov, opts) {
    const G = index(S.kg), T = treeIndex(S.tree), I = implications(G, T, ov);
    const hideInputs = !!(opts && opts.hideInputs);
    const W = Math.max(860, (opts && opts.width) || box.clientWidth || 960);
    const hostOrder = G.ofType("host").map(h => h.name).sort();
    const ownerRank = n => { const hidx = hostOrder.indexOf(n.host); return hidx < 0 ? 99 : hidx; };
    const keep = n => !(hideInputs && n.type === "register" && n.kind === "input");
    const layers = LAYERS.map(t => G.ofType(t).filter(keep));
    const extra = Object.values(G.nodes).filter(n => !LAYERS.includes(n.type));
    if (extra.length) layers.push(extra);
    layers[0].sort((a, b) => zoneOrder([a, b])[0] === (a.name || a.id) ? -1 : 1);
    layers[1].sort((a, b) => a.name.localeCompare(b.name));
    layers[2].sort((a, b) => ownerRank(a) - ownerRank(b) || a.addr.localeCompare(b.addr));
    layers[3].sort((a, b) => ownerRank(a) - ownerRank(b));
    layers[4].sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
    layers[5].sort((a, b) => (a.kind === b.kind ? a.addr - b.addr : a.kind === "holding" ? -1 : 1));
    const NW = 150, NH = 24, VG = 10, M = 16, TOP = 26;
    const lw = (W - 2 * M - NW) / Math.max(1, layers.length - 1);
    const maxN = Math.max(...layers.map(l => l.length));
    const H = TOP + maxN * (NH + VG) + 20;
    const pos = {};
    layers.forEach((layer, li) => {
      const span = layer.length * (NH + VG) - VG, y0 = TOP + (H - TOP - 20 - span) / 2;
      layer.forEach((n, i) => { pos[n.id] = { x: M + li * lw, y: y0 + i * (NH + VG) }; });
    });
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Knowledge graph", class: "graph" });
    LAYERS.concat(extra.length ? ["other"] : []).forEach((t, li) => svg.append(el("text", { x: M + li * lw + NW / 2, y: 14, "font-size": 11,
      fill: "var(--muted)", "text-anchor": "middle" }, t.replace("_", " ") + (t === "register" && hideInputs ? " (holding)" : ""))));
    const edgeLayer = el("g"), nodeLayer = el("g"), edges = [];
    for (const [sid, list] of Object.entries(G.out)) for (const e of list) {
      const a = pos[sid], b = pos[e.t]; if (!a || !b) continue;
      const fwd = a.x <= b.x, x1 = fwd ? a.x + NW : a.x, x2 = fwd ? b.x : b.x + NW;
      const y1 = a.y + NH / 2, y2 = b.y + NH / 2, c = Math.max(30, Math.abs(x2 - x1) / 2);
      const d = a.x === b.x
        ? `M${a.x + NW},${y1} C${a.x + NW + 40},${y1} ${b.x + NW + 40},${y2} ${b.x + NW},${y2}`
        : `M${x1},${y1} C${x1 + (fwd ? c : -c)},${y1} ${x2 - (fwd ? c : -c)},${y2} ${x2},${y2}`;
      const bad = I.blocked.has(sid) || I.blocked.has(e.t);
      const p = el("path", { d, fill: "none", stroke: bad ? "var(--critical)" : (REL_COLOR[e.rel] || "var(--axis)"),
        "stroke-width": 1.4, opacity: 0.75, "stroke-dasharray": bad ? "5 3" : null });
      p.append(el("title", {}, `${sid} —${e.rel}→ ${e.t}`));
      edges.push({ p, s: sid, t: e.t }); edgeLayer.append(p);
    }
    const tip = opts && opts.tip;
    for (const layer of layers) for (const n of layer) {
      const p = pos[n.id], hot = I.hot.has(n.id), bad = I.blocked.has(n.id);
      const g = el("g", { tabindex: 0, style: "cursor:default" });
      g.append(el("rect", { x: p.x, y: p.y, width: NW, height: NH, rx: 6, fill: "var(--surface)",
        stroke: bad || hot ? "var(--critical)" : "var(--ring)", "stroke-width": bad || hot ? 2 : 1, "stroke-dasharray": bad ? "4 2" : null }));
      const label = n.type === "host" ? n.name : n.type === "ip" ? n.addr : n.type === "service" ? `${n.host}/${n.name}`
        : n.type === "register" ? `${n.kind === "holding" ? "HR" : "IR"}${n.addr} ${n.name}` : n.type === "flow_rule" ? `${n.action} ${n.proto || ""}/${n.dport ?? "*"}`
        : n.name || n.id;
      g.append(el("text", { x: p.x + 8, y: p.y + 16, "font-size": 11, fill: "var(--ink)" }, clip(label, 21)));
      if (n.sensitive) g.append(el("circle", { cx: p.x + NW - 9, cy: p.y + NH / 2, r: 3.5, fill: "var(--warning)" }));
      const enter = ev => {
        for (const e of edges) e.p.setAttribute("opacity", e.s === n.id || e.t === n.id ? 1 : 0.08);
        if (tip) {
          const rows = Object.entries(n).filter(([k]) => !["id"].includes(k)).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`);
          tip.show(ev, n.id, rows);
        }
      };
      const leave = () => { for (const e of edges) e.p.setAttribute("opacity", 0.75); if (tip) tip.hide(); };
      g.addEventListener("mouseenter", enter); g.addEventListener("mouseleave", leave);
      g.addEventListener("focus", enter); g.addEventListener("blur", leave);
      nodeLayer.append(g);
    }
    svg.append(edgeLayer, nodeLayer);
    box.replaceChildren(svg);
    const used = new Set(); for (const list of Object.values(G.out)) for (const e of list) used.add(e.rel);
    return [...used].map(r => [REL_COLOR[r] || "var(--axis)", r]).concat([["var(--warning)", "● sensitive register"], ["var(--critical)", "involved / blocked"]]);
  }

  // ── attack tree ───────────────────────────────────────────────────────────
  // perspective "both": the defender's belief (fill), the attacker's progress
  // (badges) and, when it built its own tree, the real nodes it does not know
  // (red dashed frame). "defender": the belief alone. "attacker": the tree as
  // the attacker knows it (its own belief tree when it built one), with its
  // progress and nothing of the defence.
  function drawTree(box, S, ov, opts) {
    const persp = (opts && opts.perspective) || "both";
    let tree = S.tree;
    if (persp === "defender") ov = { ...ov, red: {}, redKnows: null };
    if (persp === "attacker") {
      ov = { ...ov, nodes: {}, applied: {}, redKnows: null };
      tree = { attack_tree: ov.redTree || S.tree.attack_tree, defense: {}, countermeasures: [] };
    }
    const T = treeIndex(tree), root = tree.attack_tree, def = tree.defense || {};
    const NW = 160, NH = 62, CHIP = 13, XG = 10, LV = 40;
    // tidy layout: leaves left to right, parents centred over their children
    let leafX = 0; const pos = {}; let depthMax = 0;
    const chipLines = n => (def[n.id]?.prevented_by?.length ? 1 : 0) + (def[n.id]?.restored_by?.length ? 1 : 0);
    const rowH = d => NH + 3 * CHIP + LV;
    (function lay(n, d) {
      depthMax = Math.max(depthMax, d);
      if (!(n.children || []).length) { pos[n.id] = { x: leafX, d }; leafX += NW + XG; return; }
      n.children.forEach(c => lay(c, d + 1));
      const xs = n.children.map(c => pos[c.id].x);
      pos[n.id] = { x: (Math.min(...xs) + Math.max(...xs)) / 2, d };
    })(root, 0);
    // The top margin leaves room for the attacker's badge above a root node.
    const M = 12, W = leafX - XG + 2 * M, H = (depthMax + 1) * rowH() + 20;
    const Y = d => 18 + d * rowH();
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Attack tree", class: "graph",
      style: `max-width:${Math.max(W, 600)}px` });
    const edges = el("g"), nodes = el("g");
    (function draw(n) {
      const p = pos[n.id], x = M + p.x, y = Y(p.d);
      const s = stateOf(ov, n.id);
      const rd = ov.red || {};
      // Seen from the attacker, a node is styled by what it did there.
      const st = persp === "attacker"
        ? (n.id in (rd.done || {}) ? ATTACKER_STYLE.done : n.id in (rd.failed || {}) ? ATTACKER_STYLE.failed
          : rd.target === n.id ? ATTACKER_STYLE.target : STATE_STYLE.unknown)
        : (STATE_STYLE[s.state] || STATE_STYLE.unknown);
      for (const c of n.children || []) {
        const q = pos[c.id], cx = M + q.x + NW / 2, cy = Y(q.d);
        edges.append(el("path", { d: `M${x + NW / 2},${y + NH + 2 * CHIP + 4} C${x + NW / 2},${cy - LV / 2} ${cx},${y + NH + 2 * CHIP + LV / 2} ${cx},${cy}`,
          fill: "none", stroke: "var(--axis)", "stroke-width": 1.3 }));
        draw(c);
      }
      const g = el("g");
      if (st.fill) g.append(el("rect", { x, y, width: NW, height: NH, rx: 8, fill: st.fill, opacity: 0.13 }));
      g.append(el("rect", { x, y, width: NW, height: NH, rx: 8, fill: st.fill ? "none" : "var(--surface)", stroke: st.stroke,
        "stroke-width": st === STATE_STYLE.unknown ? 1 : 2, "stroke-dasharray": st.dash }));
      wrap2(n.label || n.id, 25).forEach((line, i) =>
        g.append(el("text", { x: x + 8, y: y + 15 + i * 13, "font-size": 11.5, "font-weight": 600, fill: "var(--ink)" }, line)));
      const sub = [n.attck, n.gate !== "LEAF" ? n.gate : null, n.observable === false ? "not observable" : null].filter(Boolean).join(" · ");
      g.append(el("text", { x: x + 8, y: y + 43, "font-size": 10.5, fill: "var(--ink-2)" }, clip(sub, 29)));
      const line3 = persp === "attacker" ? (st === STATE_STYLE.unknown ? (n.feasible === false ? "believed infeasible" : "not tried") : st.label)
        : s.state === "unknown" ? st.label : `${st.label} ${(+s.score).toFixed(2)}`;
      g.append(el("text", { x: x + 8, y: y + 56, "font-size": 10.5, fill: st === STATE_STYLE.unknown ? "var(--muted)" : st.stroke, "font-weight": 600 }, line3));
      if (n.impact) g.append(el("text", { x: x + NW - 8, y: y + 56, "font-size": 10, fill: "var(--muted)", "text-anchor": "end" }, `impact ${n.impact}`));
      g.append(el("title", {}, [n.label, n.attck_name, n.review ? `review: ${n.review}` : null, (n.targets || []).join(", ")].filter(Boolean).join("\n")));
      // countermeasure chips: filled = applied by t
      let cy = y + NH + CHIP - 1;
      for (const [kind, list] of [["⊘", def[n.id]?.prevented_by], ["↺", def[n.id]?.restored_by]]) {
        if (!list || !list.length) continue;
        const t = el("text", { x: x + 4, y: cy, "font-size": 10 });
        t.append(el("tspan", { fill: "var(--muted)" }, `${kind} `));
        list.forEach((id, i) => {
          const on = id in ov.applied;
          t.append(el("tspan", { fill: on ? "var(--good)" : "var(--muted)", "font-weight": on ? 700 : 400 }, (on ? "✓" : "") + id + (i < list.length - 1 ? " " : "")));
        });
        g.append(t); cy += CHIP;
      }
      // The attacker's side of the same node: what it did, what it aims at,
      // and (when it built its own tree) whether it knows the node at all.
      const mark = persp === "attacker" ? null : n.id in (rd.done || {}) ? "✓ attacker" : n.id in (rd.failed || {}) ? "✗ attacker"
        : rd.target === n.id ? "◎ target" : null;
      if (mark) {
        g.append(el("rect", { x: x + NW - 72, y: y - 9, width: 68, height: 16, rx: 8, fill: "var(--surface)", stroke: "var(--critical)" }));
        g.append(el("text", { x: x + NW - 38, y: y + 3, "font-size": 10, "font-weight": 600, "text-anchor": "middle", fill: "var(--critical)" }, mark));
      }
      if (ov.redKnows && !ov.redKnows.has(n.id) && !(ov.redLeavesOnly && (n.children || []).length))
        g.append(el("rect", { x: x - 4, y: y - 4, width: NW + 8, height: NH + 8, rx: 11, fill: "none",
          stroke: "var(--critical)", "stroke-dasharray": "3 3", opacity: 0.8 }));
      nodes.append(g);
    })(root);
    svg.append(edges, nodes);
    box.replaceChildren(svg);
    // The legend in groups, a heading (no colour) before each.
    const legend = [];
    if (persp !== "attacker") legend.push([null, "Defender believes:"],
      ...Object.values(STATE_STYLE).map(v => [v.stroke, v.label]),
      [null, "Countermeasures:"], ["var(--muted)", "⊘ would prevent · ↺ would restore"], ["var(--good)", "✓ applied by the time shown"]);
    if (persp !== "defender") {
      legend.push([null, "Attacker:"]);
      if (persp === "attacker") {
        legend.push(...Object.values(ATTACKER_STYLE).map(v => [v.stroke, v.label]), [STATE_STYLE.unknown.stroke, "not tried"]);
        legend.push([null, ov.redTree ? "the tree it built by its own reconnaissance" : "the tree it was handed (or the red console's steps)"]);
      } else legend.push(["var(--critical)", "✓ done · ✗ failed · ◎ its target"]);
      if (ov.redKnows) {
        legend.push(["var(--critical)", "dashed frame: real, but unknown to it"]);
        const extra = [...ov.redKnows].filter(id => !T.nodes[id]);
        if (extra.length) legend.push(["var(--warning)", `it believes in nodes that are not real: ${extra.join(", ")}`]);
      }
    }
    return legend;
  }


  // ── views the core page cannot draw ───────────────────────────────────
  // Only this scenario knows what a detection latency or a bus voltage means.
  // The page's helpers (h, $, num, dur, now, statusBadge) are globals by the
  // time this factory runs; its SVG helper comes in as ui.svg.
  let s = null;
  const LATENCY_HINT = "latency from the first malicious write; * = after the physical impact";

  function det(m, d) { return m?.detectors?.[d]; }
  function detCell(m, d) {
    const x = det(m, d);
    if (!m || !m.attack || !x) return h("td", { class: "muted" }, "—");
    return h("td", { class: "num" }, x.detected ? `${num(x.latency_from_write_s, 2)} s${x.before_impact ? "" : " *"}` : "missed");
  }
  function impactText(m) {
    return !m ? "—" : !m.abnormal_frames ? "none"
      : m.impact_persists_after_attack ? "persists"
      : m.recovered ? `recovered ${num(m.recovery_s, 1)} s` : "yes";
  }

  function queue(ui) {
    ui.queueTable({
      note: { html: "rules / model: detection latency from the first malicious write; "
                  + "<b>*</b> = fired only after the physical impact." },
      columns: [
        { label: "rules", attrs: { class: "num", title: LATENCY_HINT } },
        { label: "model", attrs: { class: "num", title: LATENCY_HINT } },
        { label: "impact" },
        { label: "false alarms", num: true },
      ],
      cells: r => {
        const m = r.metrics;
        const fa = m ? (m.detectors?.combined?.false_alarms ?? m.false_alarms) : null;
        return [detCell(m, "rules"), detCell(m, "model"), h("td", {}, impactText(m)),
          h("td", { class: "num" }, fa == null ? "—" : String(fa))];
      },
    });
  }

  function chip(k, v, dot) {
    return h("div", { class: "chip", title: HELP[k] || null }, h("div", { class: "k" }, k),
      h("div", { class: "v" }, dot ? h("span", { class: "dot", style: `background:${dot}` }) : null, v));
  }

  // The run's score, once it has one (a campaign scores each run; a standalone
  // run is scored when it ends). Only what the run measured is shown.
  function scoreChips(m) {
    if (!m) return [];
    const out = [], c = det(m, "combined");
    if (m.attack && c) out.push(chip("score · detection", c.detected ? `${num(c.latency_from_write_s, 2)} s` : "missed",
      c.detected ? (c.before_impact ? "var(--good)" : "var(--warning)") : "var(--critical)"));
    else if (c) out.push(chip("score · false alarms", String(c.false_alarms ?? 0), c.false_alarms ? "var(--warning)" : "var(--good)"));
    if (m.stage_reached) out.push(chip("score · attack reached", m.stage_reached, m.attack_succeeded ? "var(--critical)" : "var(--good)"));
    if (m.attack) out.push(chip("score · impact", impactText(m), m.abnormal_frames ? "var(--critical)" : "var(--good)"));
    const resp = m.response;
    if (resp && resp.policy && resp.policy !== "off")
      out.push(chip("score · response", `${resp.accurate ? "accurate" : "inaccurate"}${resp.over_response ? " · over-response" : ""}`,
        resp.accurate ? "var(--good)" : "var(--warning)"));
    const fid = m.tree_fidelity;
    if (fid) out.push(chip("score · tree fidelity", `P ${num(fid.precision, 2)} · R ${num(fid.recall, 2)}`));
    return out;
  }

  // ── the plant's feeders ───────────────────────────────────────────────────
  // A plant of several feeders is shown one at a time: each is a Modbus unit,
  // every reading, write, finding and alert names its own, and a run with one
  // feeder reads as it always did (no selector, no unit named anywhere).
  const unitsOf = r => r.info?.units?.length ? r.info.units.map(String)
    : Object.keys((r.plant.find(p => p.units) || {}).units || {});
  const several = r => unitsOf(r).length > 1;
  // The feeder the attack acted on: where it wrote, or where it was aimed.
  const attackedUnit = r => { const u = r.writes.find(w => w.unit != null)?.unit ?? r.info?.attack_unit; return u == null ? null : String(u); };
  // The feeder on show: the one chosen, else the attacked one, else the first.
  const shownUnit = r => several(r) ? String(r.x.unit ?? attackedUnit(r) ?? unitsOf(r)[0]) : null;
  // One feeder's readings in a plant sample; the sample's own are the first feeder's.
  const feederOf = (p, unit) => (unit != null && p.units && p.units[unit]) || p;
  const plantOf = (r, unit) => unit == null ? r.plant : r.plant.map(p => ({ t: p.t, ...feederOf(p, unit) }));
  // What concerns a feeder: its own, and what names none (an IT finding, a spoofed address).
  const onUnit = unit => e => unit == null || e.unit == null || String(e.unit) === unit;
  const where = (r, e) => several(r) && e.unit != null ? ` on unit ${e.unit}` : "";
  // [unit, its plant samples, how to name it] for every feeder; one nameless entry for a plant of one.
  const feeders = r => several(r) ? unitsOf(r).map(u => [u, plantOf(r, u), ` (unit ${u})`]) : [[null, r.plant, ""]];

  function unitTabs(r) {
    if (!several(r)) return null;
    const shown = shownUnit(r), hit = attackedUnit(r);
    return h("div", { class: "tabs", role: "group", "aria-label": "Feeder shown", style: "margin-bottom:0;align-items:center" },
      ...unitsOf(r).map(u => {
        const last = r.plant.length ? feederOf(r.plant[r.plant.length - 1], u) : null;
        const dot = last?.abnormal ? "var(--critical)" : last?.ctrl_mode === 1 ? "var(--warning)" : null;
        return h("button", { type: "button", "aria-pressed": String(u === shown),
          title: `Show feeder ${u}: its voltages, control and findings${u === hit ? " — the feeder the attack acted on" : ""}`,
          onclick: () => { r.x.unit = u; chartKey = null; UI.render(); } },
          dot ? h("span", { class: "dot", style: `background:${dot};margin-right:5px` }) : null,
          `unit ${u}${u === hit ? " · attacked" : ""}`);
      }));
  }

  // The selected run: live plant state and score as chips, the voltage chart,
  // and the sensor findings by detector and class. The page has drawn the phases.
  function detail(r) {
    if (r.threshold != null) $("d-sub").textContent += ` · model threshold ${r.threshold}`;
    $("f-title").textContent = "Findings";
    $("f-sub").textContent = "Sensor findings so far, by detector and class (live during the run).";
    const unit = shownUnit(r), mine = onUnit(unit);
    const last = r.plant.length ? feederOf(r.plant[r.plant.length - 1], unit) : undefined;
    const writes = r.writes.filter(mine);
    const byDet = d => r.findings.filter(f => f.detector === d && mine(f));
    const firstAfter = d => { const w0 = writes[0]?.t; const f = byDet(d).find(f => w0 == null || f.t >= w0 - 1); return f && w0 != null ? `${num(f.t - w0, 2)} s` : (byDet(d).length ? "yes" : "—"); };
    $("d-chips").replaceChildren(
      ...(several(r) ? [unitTabs(r)] : []),
      chip("control", last ? (last.ctrl_mode === 1 ? "MANUAL" : "auto") : "—", last?.ctrl_mode === 1 ? "var(--warning)" : null),
      chip("DG setpoint", last?.dg_setpoint != null ? `${num(last.dg_setpoint, 1)} kW` : "—"),
      chip("breaker", last ? (last.switch_cmd ? "OPEN" : "closed") : "—", last?.switch_cmd ? "var(--critical)" : null),
      chip("plant", last ? (last.abnormal ? "abnormal" : "in band") : "—", last ? (last.abnormal ? "var(--critical)" : "var(--good)") : null),
      chip("rules fired", writes.length ? firstAfter("rules") : String(byDet("rules").length)),
      chip("model fired", writes.length ? firstAfter("model") : String(byDet("model").length)),
      ...scoreChips(r.metrics),
    );
    drawChart(r);
    const agg = {};
    // Every feeder's findings, each feeder on its own rows: the table is the whole run's.
    const many = several(r);
    for (const f of r.findings) { const k = `${f.detector}|${f.klass}|${many ? f.unit ?? "" : ""}`; (agg[k] = agg[k] || { d: f.detector, k: f.klass, u: f.unit, n: 0, first: f.t }).n++; }
    const rows = Object.values(agg).sort((a, b) => a.first - b.first).map(a =>
      h("tr", {}, h("td", {}, a.d), h("td", {}, a.k), many ? h("td", {}, a.u != null ? `unit ${a.u}` : "—") : null,
        h("td", { class: "num" }, String(a.n)),
        h("td", { class: "num" }, r.start_t ? `+${dur(a.first - r.start_t)}` : "—")));
    $("d-findings").replaceChildren(h("thead", {}, h("tr", {}, h("th", {}, "detector"), h("th", {}, "class"), many ? h("th", {}, "feeder") : null, h("th", { class: "num" }, "count"), h("th", { class: "num" }, "first at"))),
      h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: many ? 5 : 4, class: "empty" }, "No findings"))));
  }

  // The campaign aggregate (metrics.write_aggregate): detection per mode and
  // detector, physical impact per mode.
  const RESULT_TABS = [{ id: "detection", label: "Detection" }, { id: "impact", label: "Physical impact" }];
  function results(tab, a, tb) {
    const n = c => h("td", { class: "num" }, c == null ? "—" : String(num(c)));
    const data = a[tab];
    if (!data) { tb.replaceChildren(h("tbody", {}, h("tr", {}, h("td", { class: "empty" }, "No scored runs yet")))); return; }
    if (tab === "detection") {
      const head = h("tr", {}, ...["mode", "detector", "runs"].map(x => h("th", {}, x)),
        ...["detection rate", "latency median (s)", "min–max (s)", "before impact", "false alarms (runs)", "…in operator windows"].map(x => h("th", { class: "num" }, x)));
      const rows = data.map(r => h("tr", {}, h("td", {}, r.mode), h("td", {}, r.detector), n(r.runs),
        n(r.detection_rate), n(r.latency_median_s), h("td", { class: "num" }, r.latency_min_s == null ? "—" : `${num(r.latency_min_s)}–${num(r.latency_max_s)}`),
        n(r.before_impact_rate), h("td", { class: "num" }, `${r.false_alarms} (${r.runs_with_false_alarms})`), n(r.false_alarms_in_operator_windows)));
      tb.replaceChildren(h("thead", {}, head), h("tbody", {}, rows));
    } else {
      const head = h("tr", {}, h("th", {}, "mode"), ...["runs", "impacted", "persists", "recovered", "time-to-impact (s)", "impact duration (s)", "max ΔV (pu)", "MANUAL (s)"].map(x => h("th", { class: "num" }, x)));
      const rows = data.map(r => h("tr", {}, h("td", {}, r.mode), n(r.runs), n(r.impact_rate), n(r.persists_rate), n(r.recovered_rate),
        n(r.time_to_impact_median_s), n(r.impact_duration_median_s), n(r.max_dev_median_pu), n(r.manual_mode_median_s)));
      tb.replaceChildren(h("thead", {}, head), h("tbody", {}, rows));
    }
  }

  // ── voltage chart ─────────────────────────────────────────────────────────
  // Time-axis ticks: a round step giving about eight labels, so an hour-long
  // playground run does not print a label every minute on top of each other.
  const TICKS = [10, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200];
  const tickStep = span => TICKS.find(t => span / t <= 8) || Math.ceil(span / 8 / 3600) * 3600;
  const tickLabel = v => v < 60 || v % 60 ? `${v}s` : v % 3600 ? `${v / 60}m` : `${v / 3600}h`;
  const Y_LO = 0.80, Y_HI = 1.20;
  let chartKey = null;
  function drawChart(r) {
    const box = $("d-chart"), tip = $("tip");
    const unit = r ? shownUnit(r) : null;
    const key = r ? [r.id, r.start_t, r.plant.length, r.findings.length, r.writes.length, box.clientWidth,
      document.documentElement.dataset.theme || "", unit ?? ""].join("|") : "none";
    if (key === chartKey) return;            // unchanged: keep the frame (and a live tooltip)
    chartKey = key;
    box.querySelector("svg")?.remove();
    const legend = $("d-legend"); legend.replaceChildren();
    if (!r || !r.plant.length) {
      box.querySelector(".empty")?.remove();
      box.append(h("div", { class: "empty" }, r && r.start_t ? "Waiting for the first plant sample…" : "No plant trace for this run."));
      return;
    }
    box.querySelector(".empty")?.remove();
    // The plant's normal band, from the run; a run recorded without one had the default plant's.
    const band = r.info?.v_band || [0.95, 1.05];
    legend.append(
      ...(unit != null ? [h("span", {}, h("b", {}, `feeder unit ${unit}`))] : []),
      h("span", {}, h("span", { class: "lk", style: "background:var(--s1)" }), "load-bus voltage"),
      h("span", {}, h("span", { class: "lk", style: "background:var(--s2)" }), "DG-bus voltage"),
      h("span", {}, h("span", { class: "lk", style: "background:var(--wash);height:8px;border:1px solid var(--grid)" }), `normal band ${band[0]}–${band[1]} pu`));
    const W = Math.max(320, box.clientWidth || 600), H = 230, m = { l: 44, r: 12, t: 14, b: 26 };
    // The feeder on show: its samples, and the writes and findings that concern it.
    const t0 = r.start_t, pts = plantOf(r, unit);
    const writes = r.writes.filter(onUnit(unit)), findings = r.findings.filter(onUnit(unit));
    const tEnd = Math.max(pts[pts.length - 1].t, ...(r.phases.map(p => p.end_t || 0)), t0 + 10);
    const plannedEnd = t0 + r.phases.reduce((a, p) => a + (p.planned_s || 0), 0);
    // A live run is drawn on its whole planned timeline (stable axis, fills up);
    // a finished one on what actually happened.
    const xMax = (r.status === "running" ? Math.max(tEnd, plannedEnd) : tEnd) - t0;
    const X = v => m.l + (W - m.l - m.r) * Math.min(1, Math.max(0, v - t0) / Math.max(xMax, 1));
    const clampV = v => Math.min(Y_HI, Math.max(Y_LO, v));
    const Y = v => m.t + (H - m.t - m.b) * (1 - (clampV(v) - Y_LO) / (Y_HI - Y_LO));
    const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Bus voltages for ${r.id}${unit != null ? `, feeder unit ${unit}` : ""}` });
    // calibration window
    const np = r.phases.find(p => p.name === "normal");
    if (np?.start_t && r.learn_s) {
      const x1 = X(np.start_t), x2 = Math.min(X(np.start_t + r.learn_s), W - m.r);
      svg.append(s("rect", { x: x1, y: m.t, width: Math.max(0, x2 - x1), height: H - m.t - m.b, fill: "var(--wash)" }));
      svg.append(s("text", { x: x1 + 4, y: H - m.b - 6, "font-size": 11, fill: "var(--muted)" }, "model calibration"));
    }
    // band + grid
    svg.append(s("rect", { x: m.l, y: Y(band[1]), width: W - m.l - m.r, height: Y(band[0]) - Y(band[1]), fill: "var(--wash)", stroke: "var(--grid)" }));
    for (const v of [0.8, 0.9, 1.0, 1.1, 1.2]) {
      svg.append(s("line", { x1: m.l, x2: W - m.r, y1: Y(v), y2: Y(v), stroke: "var(--grid)", "stroke-width": 1 }));
      svg.append(s("text", { x: m.l - 6, y: Y(v) + 4, "text-anchor": "end", "font-size": 11, fill: "var(--muted)" }, v.toFixed(2)));
    }
    const step = tickStep(xMax);
    for (let x = 0; x <= xMax; x += step)
      svg.append(s("text", { x: X(t0 + x), y: H - 6, "text-anchor": "middle", "font-size": 11, fill: "var(--muted)" }, tickLabel(x)));
    svg.append(s("line", { x1: m.l, x2: W - m.r, y1: H - m.b, y2: H - m.b, stroke: "var(--axis)" }));
    // events: attack + first finding per detector
    const marks = [];
    if (writes.length) marks.push({ t: writes[0].t, label: "attack", dash: "4 3", shape: null });
    for (const [d, shape] of [["rules", "tri"], ["model", "dia"]]) {
      const w0 = writes[0]?.t;
      const f = findings.find(f => f.detector === d && (w0 == null || f.t >= w0 - 1));
      if (f) marks.push({ t: f.t, label: d, dash: null, shape });
    }
    let lastX = -1e9, row = 0;
    for (const mk of marks.sort((a, b) => a.t - b.t)) {
      const x = X(mk.t);
      row = x - lastX < 46 ? row + 1 : 0; lastX = x;
      svg.append(s("line", { x1: x, x2: x, y1: m.t, y2: H - m.b, stroke: "var(--ink-2)", "stroke-width": 1, "stroke-dasharray": mk.dash || "none" }));
      const ty = m.t + 12 + row * 13;          // inside the plot, stacked downward
      if (mk.shape === "tri") svg.append(s("path", { d: `M${x - 4},${ty - 8} L${x + 4},${ty - 8} L${x},${ty - 1}`, fill: "var(--ink-2)" }));
      if (mk.shape === "dia") svg.append(s("path", { d: `M${x},${ty - 9} L${x + 4},${ty - 5} L${x},${ty - 1} L${x - 4},${ty - 5}Z`, fill: "var(--ink-2)" }));
      svg.append(s("text", { x: x + 6, y: ty, "font-size": 11, fill: "var(--ink-2)", stroke: "var(--surface)", "stroke-width": 3, "paint-order": "stroke" }, mk.label));
    }
    // series
    for (const [key, col] of [["v_load", "var(--s1)"], ["v_dg", "var(--s2)"]]) {
      const d = pts.filter(p => p[key] != null).map((p, i) => `${i ? "L" : "M"}${X(p.t).toFixed(1)},${Y(p[key]).toFixed(1)}`).join("");
      svg.append(s("path", { d, fill: "none", stroke: col, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }));
    }
    // direct labels at the line ends
    const lp = pts[pts.length - 1];
    const ly = [[Y(lp.v_load), "load"], [Y(lp.v_dg), "DG"]].sort((a, b) => a[0] - b[0]);
    if (ly[1][0] - ly[0][0] < 12) ly[1][0] = ly[0][0] + 12;
    for (const [y, txt] of ly) svg.append(s("text", { x: Math.min(X(lp.t) + 4, W - 2), y: y + 4, "font-size": 11, fill: "var(--ink-2)", "text-anchor": X(lp.t) + 30 > W ? "end" : "start" }, txt));
    if (pts.some(p => p.v_load < Y_LO || p.v_dg < Y_LO || p.v_load > Y_HI || p.v_dg > Y_HI))
      svg.append(s("text", { x: W - m.r, y: H - m.b - 6, "text-anchor": "end", "font-size": 11, fill: "var(--muted)" }, "values outside 0.80–1.20 pu clipped"));
    // crosshair + tooltip
    const hair = s("line", { y1: m.t, y2: H - m.b, stroke: "var(--ink)", "stroke-width": 1, visibility: "hidden" });
    const dots = [s("circle", { r: 4, fill: "var(--s1)", stroke: "var(--surface)", "stroke-width": 2, visibility: "hidden" }),
                  s("circle", { r: 4, fill: "var(--s2)", stroke: "var(--surface)", "stroke-width": 2, visibility: "hidden" })];
    svg.append(hair, ...dots);
    const hit = s("rect", { x: m.l, y: 0, width: W - m.l - m.r, height: H, fill: "transparent" });
    svg.append(hit);
    const hide = () => { hair.setAttribute("visibility", "hidden"); dots.forEach(d => d.setAttribute("visibility", "hidden")); tip.style.display = "none"; };
    hit.addEventListener("pointerleave", hide);
    hit.addEventListener("pointermove", ev => {
      const rect = svg.getBoundingClientRect(), px = (ev.clientX - rect.left) * W / rect.width;
      let best = pts[0], bd = 1e9;
      for (const p of pts) { const d = Math.abs(X(p.t) - px); if (d < bd) { bd = d; best = p; } }
      const x = X(best.t);
      hair.setAttribute("x1", x); hair.setAttribute("x2", x); hair.setAttribute("visibility", "visible");
      [["v_load", 0], ["v_dg", 1]].forEach(([k, i]) => { dots[i].setAttribute("cx", x); dots[i].setAttribute("cy", Y(best[k])); dots[i].setAttribute("visibility", "visible"); });
      const row = (col, val, name) => h("div", { class: "row" }, h("span", { class: "lk", style: `background:${col}` }), h("b", {}, val), h("span", { class: "muted" }, name));
      tip.replaceChildren(h("div", { class: "muted" }, `+${dur(best.t - t0)} into the run`),
        row("var(--s1)", `${num(best.v_load)} pu`, "load bus"), row("var(--s2)", `${num(best.v_dg)} pu`, "DG bus"),
        h("div", { class: "muted" }, `${best.ctrl_mode === 1 ? "MANUAL" : "auto"} · ${num(best.dg_setpoint, 1)} kW · ${best.abnormal ? "abnormal" : "in band"}`));
      tip.style.display = "block";
      const left = x * rect.width / W;
      tip.style.left = `${Math.min(left + 12, rect.width - tip.offsetWidth - 4)}px`;
      tip.style.top = "8px";
    });
    box.insertBefore(svg, tip);
  }

  // ── the two sides of the run ──────────────────────────────────────────────
  // Folded from the ledger into run.x by reduce(): what the attacker recorded
  // (its agent, its recon, or the people at the red console) and the defender
  // events the page does not keep itself.
  function sides(r) {
    if (!r.x.red) Object.assign(r.x, {
      red: { start: null, plans: [], steps: [], recon: [], belief: null, end: null },
      blue: { alerts: [], respWrites: [] },
    });
    return r.x;
  }
  function reduce(r, ev) {
    const x = sides(r), t = ev.guest_t || ev.t;
    switch (ev.kind) {
      case "attack_start": x.red.start = { t, mode: ev.mode, profile: ev.profile, goal: ev.goal }; break;
      case "attack_plan": x.red.plans.push({ t, target: ev.target, sequence: ev.sequence || [],
        candidates: ev.candidates || [], blocked: ev.blocked || [], reason: ev.reason }); break;
      case "plan_step": x.red.steps.push({ t, node: ev.node, stage: ev.stage, attck: ev.attck, ok: !!ev.ok,
        target: ev.target, observed: ev.observed || {}, by: "agent" }); break;
      case "red_step": x.red.steps.push({ t, node: ev.step, stage: ev.stage || ev.step, ok: !!ev.ok,
        observed: ev.observed || {}, by: ev.operator || "red team" }); break;
      case "recon": x.red.recon.push({ t, stage: ev.stage, hosts: ev.hosts || [], foothold: ev.foothold,
        engine_ip: ev.engine_ip, modbus_port: ev.modbus_port, modbus_ok: ev.modbus_ok, registers: ev.registers || null }); break;
      case "attacker_belief": x.red.belief = { t, tree: ev.tree }; break;
      case "attack_end": x.red.end = { t, success: !!ev.success, stage_reached: ev.stage_reached, writes_ok: ev.writes_ok }; break;
      case "alert": x.blue.alerts.push({ t, state: ev.state, detector: ev.detector, klass: ev.klass, unit: ev.unit }); break;
      case "response_write": x.blue.respWrites.push({ t, register: ev.register, value: ev.value }); break;
    }
  }

  const STATE_RANK = { confirmed: 0, inferred: 1, suspected: 2 };
  const STAGES = ["it_access", "it_exec", "pivot"];
  const last = a => a[a.length - 1] || null;

  // Each side as it stood at t (null = now): what it is doing, what it can see.
  function sidesAt(r, t) {
    const x = sides(r), red = x.red, u = uptoT(t);
    const steps = red.steps.filter(u), plans = red.plans.filter(u), recon = red.recon.filter(u);
    const writes = r.writes.filter(u), plan = last(plans), done = new Set(steps.filter(s => s.ok).map(s => s.node));
    const end = u(red.end) ? red.end : null, start = u(red.start) ? red.start : null;
    const belief = u(red.belief) ? red.belief : null;
    const humans = steps.some(s => s.by !== "agent");
    const mode = start?.mode || "";
    // A recon attacker plans with the same agent, so its mode says planner too:
    // what tells it apart is that it went looking first.
    const source = mode.startsWith("recon:") || red.recon.length || red.belief ? "a tree it built by its own reconnaissance"
      : mode.startsWith("planner:") ? `the attack tree, handed to it (planner, ${start.profile || mode.slice(8)})`
      : humans ? "people at the red console, step by step"
      : writes.length ? `a fixed script (${r.mode || "scripted"}): no plan, no feedback` : null;
    const states = r.states.filter(u), st = last(states);
    const open = {};
    for (const a of x.blue.alerts.filter(u)) { const k = `${a.detector}: ${a.klass}${where(r, a)}`; if (a.state === "cleared") delete open[k]; else open[k] = a; }
    const approvals = Object.values(r.approvals).filter(a => u({ t: a.asked_t }))
      .map(a => ({ ...a, state: a.t != null && u({ t: a.t }) ? a.state : "requested" }));
    return {
      red: { steps, plan, plans, done, writes, end, start, recon, belief, source,
        target: plan?.target || last(steps)?.target || null,
        remaining: plan ? plan.sequence.filter(n => !done.has(n)) : [] },
      blue: { findings: r.findings.filter(u), st, decisions: r.decisions.filter(u), actions: r.actions.filter(u),
        open: Object.keys(open), approvals, respWrites: x.blue.respWrites.filter(u) },
    };
  }

  // What each line, column and mark means: shown on hover.
  const HELP = {
    // attacker
    status: "Where the attacker is: planning, at a step (done or failed), finished, or stopped by the defence",
    "aims at": "The impact it is going for, and the steps it still needs to get there",
    steps: "Every step it ran: ✓ worked · ✗ failed (a countermeasure closed the path, or the step itself failed). Hover a step for its ATT&CK technique",
    writes: "Modbus writes it sent to the plant, by register: how many, the last value, how many the plant refused",
    knowledge: "Where its picture of the target comes from",
    "hosts found": "Hosts and open ports its network scan found",
    foothold: "The user it runs as on the host it broke into, as its own commands reported",
    "plant reached": "Whether it reached the plant's Modbus server, as it found out",
    "registers read": "Plant registers it read through its foothold (address = value)",
    "its belief": "The attack tree it built from what it found",
    options: "The impacts still open to it when it last planned (impact weight in brackets)",
    "paths closed": "Steps that failed: it treats every path through them as blocked",
    // defender
    response: "How the defender acts: its policy, on its own or by suggesting to an operator; or watching only",
    "last decision": "The latest response decision, with the policy's justification",
    countermeasures: "Countermeasures run so far: ✓ applied · ✗ failed, and on which host",
    "awaiting operator": "Suggestions put to the operator and not answered yet",
    "plant writes": "Writes the response made to the plant to put it back (control mode, setpoint)",
    findings: "Sensor findings so far, by detector: rules (Modbus policy), model (learned traffic behaviour), it (host sensor on the HMI)",
    latest: "The latest finding: its class, where it came from, and the attack step it points to",
    "alerts open": "Alerts raised and not cleared yet",
    "attack tree": "What the defender believes of each step: confirmed · inferred (implied by a confirmed later step) · suspected, with its belief 0–1",
    "expects next": "The steps the defender's analytics expects the attacker to take next",
    "hosts implicated": "Hosts the defender believes the attacker controls",
    "model threshold": "Anomaly score above which the learned model reports (fitted on the normal phase)",
    // run detail chips
    control: "Who drives the plant's distributed generator: auto (the PLC) or MANUAL (whoever writes the setpoint)",
    "DG setpoint": "Power the distributed generator is told to produce",
    breaker: "The feeder breaker: OPEN cuts the load off",
    plant: "Whether the bus voltages are inside the plant's normal band",
    "rules fired": "First rules finding after the first attacker write (or how many, with no attack)",
    "model fired": "First learned-model finding after the first attacker write (or how many, with no attack)",
    "score · detection": "Detection latency from the first malicious write (green: before the physical impact)",
    "score · false alarms": "Findings with no attack to explain them",
    "score · attack reached": "The furthest stage of the attack that succeeded",
    "score · impact": "Whether the plant left its band, and whether and when it recovered",
    "score · response": "Whether the response did what this attack called for, and nothing it did not",
    "score · tree fidelity": "How close the attacker's own tree is to the real one: precision and recall of its feasible leaves",
    // kill chain
    "time to detect": "From the attacker's first step to the defender's first finding",
    "time to respond": "From the first finding to the first countermeasure that worked",
    "time to impact": "From the attacker's first step to the plant leaving its band",
    "who is ahead": "The furthest stage the attacker reached, against the furthest the defender has confirmed",
  };

  const kv = rows => h("dl", { class: "kv" }, ...rows.filter(([, v]) => v != null && v !== "" && !(Array.isArray(v) && !v.length))
    .flatMap(([k, v]) => [h("dt", { title: HELP[k] || null }, k), h("dd", {}, v)]));
  const mark = (ok, text, title) => h("span", { title: title || null, style: `margin-right:10px;white-space:nowrap;color:${ok == null ? "var(--ink-2)" : ok ? "var(--ink)" : "var(--critical)"}` },
    ok == null ? "◎ " : ok ? "✓ " : "✗ ", text);
  const none = text => h("span", { class: "muted" }, text);
  const th = (label, help, num) => h("th", { class: num ? "num" : null, title: help || null }, label);
  const table = (heads, rows, empty) => h("div", { class: "scroll" }, h("table", {},
    h("thead", {}, h("tr", {}, heads)),
    h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: heads.length, class: "empty" }, empty)))));
  // A time relative to the start of the attack (or of the run).
  const t0Of = (r, R) => R.start?.t ?? R.steps[0]?.t ?? r.writes[0]?.t ?? r.start_t;
  const rel = (t, t0) => t == null || t0 == null ? "—" : `${t - t0 >= 0 ? "+" : ""}${num(t - t0, 1)} s`;
  // A row that moves the run's time to its fact when clicked.
  const jump = t => ({ class: "click", tabindex: "0", title: "Show the run at this time",
    onclick: () => UI.setTime(t), onkeydown: e => { if (e.key === "Enter") UI.setTime(t); } });

  function redDoing(v) {
    const R = v.red, lastStep = last(R.steps);
    const status = R.end ? (R.end.success ? "finished: it reached its impact" : `stopped: defended (reached ${R.end.stage_reached || "nothing"})`)
      : lastStep ? `at ${lastStep.node} — ${lastStep.ok ? "done" : "failed, re-planning"}`
      : R.start ? "planning its first step" : R.writes.length ? "writing to the plant" : null;
    const byReg = {};
    for (const w of R.writes) { const k = w.register || "?"; (byReg[k] = byReg[k] || { n: 0, v: w.value, ok: 0 }).n++; byReg[k].v = w.value; if (w.ok !== false) byReg[k].ok++; }
    const writes = Object.entries(byReg).map(([k, w]) => `${k} ×${w.n} (last ${w.v}${w.ok < w.n ? `, ${w.n - w.ok} refused` : ""})`).join(" · ");
    return status || R.steps.length ? kv([
      ["status", status],
      ["aims at", R.target ? `${R.target}${R.remaining.length ? ` — next: ${R.remaining.join(" → ")}` : ""}` : null],
      ["steps", R.steps.length ? h("span", {}, ...R.steps.map(s => mark(s.ok, s.node, [s.attck, s.by !== "agent" ? `by ${s.by}` : null].filter(Boolean).join(" · ")))) : null],
      ["writes", writes || null],
    ]) : none("No attack activity yet.");
  }
  function redKnows(v) {
    const R = v.red;
    const who = R.steps.map(s => s.observed?.whoami).find(Boolean);
    const it = last(R.recon.filter(c => c.stage === "it")), ot = last(R.recon.filter(c => c.stage === "ot"));
    const pivot = R.steps.find(s => s.node === "pivot");
    const regs = ot && ot.registers ? Object.entries(ot.registers) : [];
    const countNodes = n => n ? 1 + (n.children || []).reduce((a, c) => a + countNodes(c), 0) : 0;
    const P = R.plan;
    return R.source || R.recon.length ? kv([
      ["knowledge", R.source],
      ["hosts found", it ? it.hosts.map(x => `${x.ip} (${(x.ports || []).map(p => p.port ?? p).join(", ")})`).join(" · ") : null],
      ["foothold", who ? `runs as ${who}${it?.foothold ? ` on ${it.foothold.ip ?? it.foothold}` : ""}` : (it?.foothold ? `${it.foothold.ip ?? it.foothold}` : null)],
      ["plant reached", ot ? `${ot.engine_ip}:${ot.modbus_port} — Modbus ${ot.modbus_ok ? "answers" : "silent"}`
        : pivot ? `${pivot.ok ? "reachable" : "unreachable"}${pivot.observed?.detail ? ` (${pivot.observed.detail})` : ""}` : null],
      ["registers read", regs.length ? regs.slice(0, 6).map(([a, x]) => `${a}=${x}`).join(" · ") + (regs.length > 6 ? ` … (${regs.length})` : "") : null],
      ["its belief", R.belief ? `a tree of ${countNodes(R.belief.tree)} nodes` : null],
      ["options", P && P.candidates.length ? P.candidates.map(c => `${c.node}${c.impact != null ? ` (impact ${c.impact})` : ""}`).join(" · ") : null],
      ["paths closed", P && P.blocked.length ? P.blocked.join(" · ") : null],
    ]) : none("Nothing yet.");
  }
  function blueDoing(v, r) {
    const B = v.blue, policy = r.respond && r.respond !== "off" ? r.respond : (B.decisions[0]?.policy || null);
    const advise = Object.keys(r.approvals).length > 0, d = last(B.decisions), cms = {};
    for (const a of B.actions) if (a.id !== "notify") cms[a.id] = a;
    const pending = B.approvals.filter(a => a.state === "requested");
    return kv([
      ["response", policy ? `${policy}${advise ? ", advising an operator" : ", automatic"}` : "watching only: no response policy"],
      ["last decision", d ? `${d.actions.join(", ") || "no action"}${d.rationale ? ` — ${d.rationale}` : ""}` : (policy ? "none yet" : null)],
      ["countermeasures", Object.keys(cms).length ? h("span", {}, ...Object.values(cms).map(a =>
        mark(a.ok, `${a.id}${a.machine ? ` @${a.machine}` : ""}`))) : null],
      ["awaiting operator", pending.length ? pending.map(a => `⏳ ${a.action}`).join(" · ") : null],
      ["plant writes", B.respWrites.length ? `${B.respWrites.length} restoring write${B.respWrites.length === 1 ? "" : "s"}` : null],
    ]);
  }
  function blueSees(v, r) {
    const B = v.blue, byDet = {};
    for (const f of B.findings) byDet[f.detector] = (byDet[f.detector] || 0) + 1;
    const lf = last(B.findings);
    const nodes = Object.entries(B.st?.nodes || {}).filter(([, s]) => s[0] in STATE_RANK)
      .sort((a, b) => STATE_RANK[a[1][0]] - STATE_RANK[b[1][0]] || b[1][1] - a[1][1]);
    return B.findings.length || nodes.length ? kv([
      ["findings", Object.entries(byDet).map(([k, n]) => `${k} ×${n}`).join(" · ")],
      ["latest", lf ? `${lf.klass}${lf.src ? ` from ${lf.src}` : ""}${lf.unit != null ? ` on unit ${lf.unit}` : ""}${lf.maps_to ? ` → ${lf.maps_to}` : ""}` : null],
      ["alerts open", B.open.length ? B.open.join(" · ") : null],
      ["attack tree", nodes.length ? h("span", {}, ...nodes.map(([id, s]) => h("span", {
        style: `margin-right:10px;white-space:nowrap;color:${STATE_STYLE[s[0]].stroke}` }, `${id} ${s[0]} ${num(s[1], 2)}`))) : null],
      ["expects next", B.st?.next?.length ? B.st.next.join(" · ") : null],
      ["hosts implicated", B.st?.hosts?.length ? B.st.hosts.join(" · ") : null],
      ["model threshold", r.threshold != null ? String(r.threshold) : null],
    ]) : none("Nothing observed yet.");
  }
  const side = (who, label, parts) => h("div", { class: `side ${who}` },
    h("b", { style: `color:${who === "red" ? "var(--critical)" : "var(--s1)"}` }, label),
    ...parts.flatMap(([title, body]) => [h("h3", {}, title), body]));

  // One lane per side and one for the plant, on the run's timeline; the
  // vertical line is the time shown. A mark is a fact: click it to go there.
  const LANE_HELP = {
    attacker: "Attacker: ● step done · ✗ step failed · thin tick a Modbus write",
    defender: "Defender: ▲ finding · ◇ decision · ■ countermeasure (green applied, red failed)",
    plant: "Plant: red band = voltages out of the normal band · dashed amber = control in MANUAL",
  };
  function drawLanes(box, r, t, lanes) {
    box.replaceChildren();
    if (!r.start_t) return;
    const x = sides(r), red = x.red;
    const W = Math.max(320, box.clientWidth || 600), LH = 26, m = { l: 70, r: 12, t: 4, b: 22 };
    const H = m.t + m.b + lanes.length * LH, t0 = r.start_t;
    const times = [...red.steps, ...r.writes, ...r.findings, ...r.decisions, ...r.actions, ...r.plant].map(e => e.t).filter(v => v != null);
    const tEnd = Math.max(t0 + 10, ...times, ...r.phases.map(p => p.end_t || 0));
    const plannedEnd = t0 + r.phases.reduce((a, p) => a + (p.planned_s || 0), 0);
    const xMax = (r.status === "running" ? Math.max(tEnd, plannedEnd) : tEnd) - t0;
    const X = v => m.l + (W - m.l - m.r) * Math.min(1, Math.max(0, v - t0) / Math.max(xMax, 1));
    const row = name => lanes.indexOf(name), Yc = i => m.t + LH * i + LH / 2;
    const g = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Timeline of ${lanes.join(", ")} for ${r.id}` });
    lanes.forEach((ln, i) => {
      g.append(s("line", { x1: m.l, x2: W - m.r, y1: Yc(i), y2: Yc(i), stroke: "var(--grid)" }));
      const lab = s("text", { x: m.l - 8, y: Yc(i) + 4, "text-anchor": "end", "font-size": 11, fill: "var(--ink-2)" }, ln);
      lab.append(s("title", {}, LANE_HELP[ln])); g.append(lab);
    });
    const put = (el, at, text) => {
      el.append(s("title", {}, `${text} — click to show the run at this time`));
      el.setAttribute("style", "cursor:pointer");
      el.addEventListener("click", () => UI.setTime(at));
      g.append(el);
    };
    if (row("attacker") >= 0) {
      const y = Yc(row("attacker"));
      for (const w of r.writes) put(s("line", { x1: X(w.t), x2: X(w.t), y1: y - 9, y2: y + 9, stroke: "var(--critical)", opacity: 0.5, "stroke-width": 2 }), w.t, `write ${w.register} = ${w.value}${where(r, w)}`);
      for (const st of red.steps) {
        const cx = X(st.t);
        put(st.ok ? s("circle", { cx, cy: y, r: 5, fill: "var(--critical)" })
          : s("path", { d: `M${cx - 5},${y - 5} L${cx + 5},${y + 5} M${cx + 5},${y - 5} L${cx - 5},${y + 5}`, stroke: "var(--critical)", "stroke-width": 2.5 }),
          st.t, `${st.node} ${st.ok ? "done" : "failed"}`);
      }
    }
    if (row("defender") >= 0) {
      const y = Yc(row("defender"));
      for (const f of r.findings) { const cx = X(f.t), cy = y - 3;
        put(s("path", { d: `M${cx - 4},${cy + 6} L${cx + 4},${cy + 6} L${cx},${cy - 2}Z`, fill: "var(--s1)", opacity: 0.6 }), f.t, `${f.detector}: ${f.klass}${where(r, f)}`); }
      for (const d of r.decisions) { const cx = X(d.t);
        put(s("path", { d: `M${cx},${y - 6} L${cx + 6},${y} L${cx},${y + 6} L${cx - 6},${y}Z`, fill: "var(--surface)", stroke: "var(--s1)", "stroke-width": 2 }), d.t, `decision: ${d.actions.join(", ") || "no action"}`); }
      for (const a of r.actions) if (a.id !== "notify")
        put(s("rect", { x: X(a.t) - 4, y: y - 4, width: 8, height: 8, fill: a.ok ? "var(--good)" : "var(--critical)" }), a.t, `${a.id} ${a.ok ? "applied" : "failed"}`);
    }
    if (row("plant") >= 0) {
      const y = Yc(row("plant"));
      // Every feeder's spans on the one lane: each says which feeder it is.
      for (const [, plant, name] of feeders(r)) {
        for (const [a, b] of spans(plant, p => p.abnormal)) put(s("rect", { x: X(a), y: y - 6, width: Math.max(2, X(b) - X(a)), height: 12, fill: "var(--critical)", opacity: 0.45 }), a, `plant out of its band${name}`);
        for (const [a, b] of spans(plant, p => p.ctrl_mode === 1)) put(s("line", { x1: X(a), x2: X(b), y1: y - 10, y2: y - 10, stroke: "var(--warning)", "stroke-width": 2, "stroke-dasharray": "4 3" }), a, `control in MANUAL${name}`);
      }
    }
    const step = tickStep(xMax);
    for (let v = 0; v <= xMax; v += step) g.append(s("text", { x: X(t0 + v), y: H - 6, "text-anchor": "middle", "font-size": 11, fill: "var(--muted)" }, tickLabel(v)));
    if (t != null) g.append(s("line", { x1: X(t), x2: X(t), y1: m.t, y2: H - m.b, stroke: "var(--ink)", "stroke-width": 1.5 }));
    box.append(g);
  }
  // The intervals over which a plant condition held.
  function spans(plant, pred) {
    const out = []; let a = null;
    for (const p of plant) { if (pred(p)) a = a ?? p.t; else if (a != null) { out.push([a, p.t]); a = null; } }
    if (a != null && plant.length) out.push([a, plant[plant.length - 1].t]);
    return out;
  }
  const lanesBox = (r, t, lanes) => { const b = h("div", { class: "lanes" }); queueMicrotask(() => drawLanes(b, r, t, lanes)); return b; };

  // ── kill chain ────────────────────────────────────────────────────────────
  // Per step of the attack: when the attacker did it, when the defender first
  // suspected and confirmed it, and the countermeasure that covered it.
  function chainRows(r, v) {
    const R = v.red, B = v.blue;
    const ids = STAGES.filter(n => R.steps.some(s => s.node === n) || B.st?.nodes?.[n]);
    for (const s of R.steps) if (!ids.includes(s.node)) ids.push(s.node);
    const states = r.states.filter(uptoT(v.t));
    const first = (n, pred) => states.find(x => x.nodes?.[n] && pred(x.nodes[n][0]))?.t ?? null;
    const counter = n => {
      for (const d of B.decisions) for (const [a, c] of Object.entries(d.covers || {}))
        if ([...(c.prevents || []), ...(c.restores || [])].includes(n)) {
          const act = B.actions.find(x => x.id === a && x.ok && x.t >= d.t - 1e-3);
          if (act) return { id: a, t: act.t };
        }
      return null;
    };
    return ids.map(n => {
      const did = R.steps.find(s => s.node === n && s.ok), tried = R.steps.find(s => s.node === n);
      return { n, did: did?.t ?? null, failed: !did && tried ? tried.t : null, sus: first(n, st => st in STATE_RANK),
        conf: first(n, st => st === "confirmed"), c: counter(n) };
    });
  }
  const stageIndex = n => STAGES.includes(n) ? STAGES.indexOf(n) : STAGES.length;
  function renderKillchain(box, r, t) {
    if (!keep(box, r, t)) return;
    const v = sidesAt(r, t), R = v.red, B = v.blue, rows = chainRows(r, v), t0 = t0Of(r, R);
    const a0 = R.steps[0]?.t ?? r.writes[0]?.t ?? null;
    const f0 = B.findings.find(f => a0 == null || f.t >= a0 - 1)?.t ?? null;
    const c0 = f0 == null ? null : B.actions.find(a => a.ok && a.id !== "notify" && a.t >= f0)?.t ?? null;
    const p0 = a0 == null ? null : r.plant.filter(uptoT(t)).find(p => p.abnormal && p.t >= a0)?.t ?? null;
    const reached = Math.max(-1, ...R.steps.filter(s => s.ok).map(s => stageIndex(s.node)));
    const seen = Math.max(-1, ...Object.entries(B.st?.nodes || {}).filter(([, s]) => s[0] === "confirmed").map(([n]) => stageIndex(n)));
    const nameOf = i => i < 0 ? "nothing" : i < STAGES.length ? STAGES[i] : "impact";
    const ahead = a0 == null ? "no attack yet" : reached > seen ? `attacker: ${nameOf(reached)} vs ${nameOf(seen)} confirmed`
      : `defender has confirmed ${nameOf(seen)}`;
    const kpi = (k, val, dot) => chip(k, val, dot);
    const span = x => x == null ? "—" : `${num(x, 2)} s`;
    const kpis = h("div", { class: "chips" },
      kpi("time to detect", a0 == null ? "—" : span(f0 == null ? null : f0 - a0), f0 == null ? null : "var(--s1)"),
      kpi("time to respond", span(c0 == null || f0 == null ? null : c0 - f0), c0 == null ? null : "var(--good)"),
      kpi("time to impact", a0 == null ? "—" : (p0 == null ? "not reached" : span(p0 - a0)), p0 == null ? "var(--good)" : "var(--critical)"),
      kpi("who is ahead", ahead, a0 == null ? null : reached > seen ? "var(--critical)" : "var(--s1)"));
    if (!rows.length) { box.replaceChildren(kpis, none("No attack step yet: each row will compare when the attacker did a step with when the defender saw it.")); return; }
    // One bar per step on a shared axis, from the attack's start to its last fact.
    const times = rows.flatMap(x => [x.did, x.failed, x.sus, x.conf, x.c?.t]).filter(v => v != null);
    const lo = Math.min(t0, ...times), hi = Math.max(lo + 1, ...times, t ?? -Infinity);
    const W = 360, X = v => 6 + (W - 12) * (v - lo) / (hi - lo);
    const bar = x => {
      const g = s("svg", { viewBox: `0 0 ${W} 18`, width: W, height: 18, role: "img", "aria-label": `timeline of ${x.n}` });
      g.append(s("line", { x1: 6, x2: W - 6, y1: 9, y2: 9, stroke: "var(--grid)" }));
      const at = (v, el, text) => { if (v == null) return; el.append(s("title", {}, text)); g.append(el); };
      if (x.did != null) at(x.did, s("circle", { cx: X(x.did), cy: 9, r: 5, fill: "var(--critical)" }), `attacker did it ${rel(x.did, t0)}`);
      if (x.failed != null) at(x.failed, s("path", { d: `M${X(x.failed) - 4},5 L${X(x.failed) + 4},13 M${X(x.failed) + 4},5 L${X(x.failed) - 4},13`, stroke: "var(--critical)", "stroke-width": 2 }), `attacker failed it ${rel(x.failed, t0)}`);
      if (x.sus != null) at(x.sus, s("path", { d: `M${X(x.sus) - 5},15 L${X(x.sus) + 5},15 L${X(x.sus)},5Z`, fill: "var(--s1)", opacity: 0.8 }), `defender suspected it ${rel(x.sus, t0)}`);
      if (x.conf != null) at(x.conf, s("path", { d: `M${X(x.conf)},3 L${X(x.conf) + 6},9 L${X(x.conf)},15 L${X(x.conf) - 6},9Z`, fill: "var(--s1)" }), `defender confirmed it ${rel(x.conf, t0)}`);
      if (x.c) at(x.c.t, s("rect", { x: X(x.c.t) - 4, y: 5, width: 8, height: 8, fill: "var(--good)" }), `${x.c.id} applied ${rel(x.c.t, t0)}`);
      if (t != null) g.append(s("line", { x1: X(t), x2: X(t), y1: 0, y2: 18, stroke: "var(--ink)" }));
      return g;
    };
    const lag = x => { const a = x.did ?? x.failed; return a == null || x.sus == null ? "—" : `${x.sus - a >= 0 ? "+" : ""}${num(x.sus - a, 2)} s`; };
    box.replaceChildren(kpis,
      h("div", { class: "legend" }, h("span", {}, h("span", { class: "dot", style: "background:var(--critical)" }), "attacker did it (✗ failed)"),
        h("span", {}, "▲ defender suspected"), h("span", {}, "◆ confirmed"), h("span", {}, h("span", { class: "dot", style: "background:var(--good);border-radius:1px" }), "countermeasure applied")),
      table([th("attack step", "A step of the attack tree the attacker ran, or the defender has an opinion on"),
        th("timeline", "The step's facts on one axis, from the start of the attack; the black line is the time shown"),
        th("attacker", "When the attacker did the step (from the start of the attack); ✗ when it tried and failed", true),
        th("suspected", "When the defender first believed it possible", true), th("confirmed", "When the defender was first sure of it", true),
        th("seen after", "How long after the attacker's step the defender first suspected it", true),
        th("countered by", "The first countermeasure that covered the step and was applied")],
        rows.map(x => h("tr", jump(x.did ?? x.failed ?? x.sus ?? t0), h("td", {}, x.n), h("td", {}, bar(x)),
          h("td", { class: "num" }, x.did != null ? rel(x.did, t0) : x.failed != null ? h("span", { style: "color:var(--critical)" }, `✗ ${rel(x.failed, t0)}`) : "—"),
          h("td", { class: "num" }, rel(x.sus, t0)), h("td", { class: "num" }, rel(x.conf, t0)),
          h("td", { class: "num" }, lag(x)), h("td", {}, x.c ? `${x.c.id} at ${rel(x.c.t, t0)}` : "—"))), ""));
  }

  // A card redraws only when what it shows changed: same run, time, data, width.
  function keep(box, r, t, extra) {
    const x = sides(r);
    const sig = JSON.stringify([r.id, r.status, t, x.red.steps.length, x.red.plans.length, x.red.recon.length, !!x.red.belief, !!x.red.end,
      r.writes.length, r.findings.length, r.states.length, r.decisions.length, r.actions.length, x.blue.alerts.length,
      Object.values(r.approvals).map(a => a.state).join(), r.plant.length, Math.round(box.clientWidth / 40),
      document.documentElement.dataset.theme || "", extra ?? null]);
    if (box.dataset.sig === sig) return false;
    box.dataset.sig = sig;
    return true;
  }

  // ── the cards of the three views ──────────────────────────────────────────
  function renderSides(box, r, t) {
    if (!keep(box, r, t)) return;
    const v = sidesAt(r, t);
    box.replaceChildren(h("div", { class: "cols2" },
      side("red", "Attacker", [["doing", redDoing(v)], ["knows", redKnows(v)]]),
      side("blue", "Defender", [["doing", blueDoing(v, r)], ["sees / believes", blueSees(v, r)]])),
      lanesBox(r, t, ["attacker", "defender", "plant"]));
  }

  function renderAttacker(box, r, t) {
    if (!keep(box, r, t)) return;
    const v = sidesAt(r, t), R = v.red, t0 = t0Of(r, R);
    const seen = o => [o.whoami ? `as ${o.whoami}` : null, o.detail || null,
      o.writes?.length ? `${o.writes.filter(w => w.ok).length}/${o.writes.length} writes accepted (${[...new Set(o.writes.map(w => w.register_name))].join(", ")})` : null]
      .filter(Boolean).join(" · ") || "—";
    const steps = table([th("at", "From the start of the attack", true), th("step", "The attack-tree step it ran"),
      th("ATT&CK", "The technique the step is an instance of"), th("outcome", "✓ worked · ✗ failed"),
      th("what it observed", "What the step's own output told the attacker: the user it ran as, what it found, which writes the plant accepted"),
      th("by", "The autonomous agent, or the person at the red console")],
      R.steps.map(s => h("tr", jump(s.t), h("td", { class: "num" }, rel(s.t, t0)), h("td", {}, s.node), h("td", {}, s.attck || "—"),
        h("td", {}, mark(s.ok, s.ok ? "done" : "failed")), h("td", { class: "wrap" }, seen(s.observed || {})), h("td", {}, s.by))),
      "No step yet");
    const plans = R.plans.length ? [h("h3", { class: "sub", style: "margin:14px 0 4px" }, "Its plans"),
      table([th("at", "From the start of the attack", true), th("why", "initial: its first choice · replan: a step failed and it chose again"),
        th("target", "The impact it chose"), th("route", "The steps to get there, in order"),
        th("options", "The impacts open to it then (impact weight · how detectable, 0–1)"), th("closed", "Steps that had failed: paths it gave up")],
        R.plans.map(p => h("tr", jump(p.t), h("td", { class: "num" }, rel(p.t, t0)), h("td", {}, p.reason || "—"), h("td", {}, p.target),
          h("td", {}, p.sequence.join(" → ")),
          h("td", { class: "wrap" }, p.candidates.map(c => `${c.node} (${c.impact ?? "?"} · ${c.detectability ?? "?"})`).join(", ") || "—"),
          h("td", {}, p.blocked.join(", ") || "—"))), "")] : [];
    const recon = R.recon.length ? [h("h3", { class: "sub", style: "margin:14px 0 4px" }, "Its reconnaissance"),
      table([th("at", "From the start of the attack", true), th("stage", "it: the network scan · ot: the plant, through the foothold"), th("found", "What it learnt")],
        R.recon.map(c => h("tr", jump(c.t), h("td", { class: "num" }, rel(c.t, t0)), h("td", {}, c.stage),
          h("td", { class: "wrap" }, c.stage === "it"
            ? `${(c.hosts || []).map(x => `${x.ip} (${(x.ports || []).map(p => p.port ?? p).join(", ")})`).join(" · ") || "no host"}${c.foothold ? ` — foothold ${c.foothold.ip ?? c.foothold}:${c.foothold.port ?? ""}` : ""}`
            : `${c.engine_ip || "?"}:${c.modbus_port || "?"} Modbus ${c.modbus_ok ? "answers" : "silent"}${c.registers ? ` — ${Object.entries(c.registers).map(([a, x]) => `${a}=${x}`).join(" · ")}` : ""}`))), "")] : [];
    box.replaceChildren(h("div", { class: "cols2" },
      side("red", "Doing", [["now", redDoing(v)]]), side("red", "Knows", [["of the target", redKnows(v)]])),
      lanesBox(r, t, ["attacker", "plant"]),
      h("h3", { class: "sub", style: "margin:14px 0 4px" }, "Its steps"), steps, ...plans, ...recon);
  }

  function renderDefender(box, r, t) {
    if (!keep(box, r, t)) return;
    const v = sidesAt(r, t), B = v.blue, t0 = r.start_t;
    const cost = c => c ? Object.entries(c).filter(([, x]) => typeof x === "number").map(([k, x]) => `${k} ${num(x, 2)}`).join(" · ") : "—";
    const decisions = table([th("at", "From the start of the run", true),
      th("trigger", "The finding that led to it, and how long after it the decision came"),
      th("actions", "What it decided to run"), th("cost", "The terms the policy weighed (residual risk, future risk, operational cost, …)"),
      th("justification", "The policy's own reason")],
      B.decisions.map(d => h("tr", jump(d.t), h("td", { class: "num" }, rel(d.t, t0)),
        h("td", {}, d.trigger_klass ? `${d.trigger_klass}${d.trigger_t != null ? ` (+${num(d.t - d.trigger_t, 2)} s)` : ""}` : "—"),
        h("td", {}, d.actions.join(", ") || "no action"), h("td", { class: "wrap" }, cost(d.cost_terms)),
        h("td", { class: "wrap" }, d.rationale || "—"))),
      r.respond && r.respond !== "off" ? "No decision yet" : "No response policy in this run: the defender only watches");
    // Alerts as intervals: raised, then cleared.
    const open = {}, alerts = [];
    for (const a of sides(r).blue.alerts.filter(uptoT(t))) {
      const k = `${a.detector}: ${a.klass}${where(r, a)}`;
      if (a.state === "cleared") { if (open[k]) { open[k].cleared = a.t; delete open[k]; } }
      else if (!open[k]) { open[k] = { k, raised: a.t, cleared: null }; alerts.push(open[k]); }
    }
    const alertTable = table([th("alert", "Detector and class"), th("raised", "From the start of the run", true),
      th("cleared", "When the condition ended", true), th("lasted", "", true)],
      alerts.map(a => h("tr", jump(a.raised), h("td", {}, a.k), h("td", { class: "num" }, rel(a.raised, t0)),
        h("td", { class: "num" }, a.cleared == null ? "open" : rel(a.cleared, t0)),
        h("td", { class: "num" }, a.cleared == null ? "—" : `${num(a.cleared - a.raised, 1)} s`))), "No alert yet");
    // When each node of the tree first reached each belief.
    const firstAt = {};
    for (const st of r.states.filter(uptoT(t))) for (const [n, [state]] of Object.entries(st.nodes || {}))
      if (state in STATE_RANK) (firstAt[n] = firstAt[n] || {})[state] = firstAt[n][state] ?? st.t;
    const belief = table([th("step", "A node of the attack tree"),
      ...["suspected", "inferred", "confirmed"].map(k => th(k, HELP["attack tree"], true))],
      Object.entries(firstAt).sort((a, b) => Math.min(...Object.values(a[1])) - Math.min(...Object.values(b[1])))
        .map(([n, f]) => h("tr", jump(Math.min(...Object.values(f))), h("td", {}, n),
          ...["suspected", "inferred", "confirmed"].map(k => h("td", { class: "num", style: f[k] != null ? `color:${STATE_STYLE[k].stroke}` : null }, rel(f[k], t0))))),
      "No belief yet");
    box.replaceChildren(h("div", { class: "cols2" },
      side("blue", "Doing", [["now", blueDoing(v, r)]]), side("blue", "Sees / believes", [["so far", blueSees(v, r)]])),
      lanesBox(r, t, ["defender", "plant"]),
      h("h3", { class: "sub", style: "margin:14px 0 4px" }, "Its decisions"), decisions,
      h("div", { class: "cols2", style: "margin-top:14px" },
        h("div", {}, h("h3", { class: "sub", style: "margin:0 0 4px" }, "Alerts"), alertTable),
        h("div", {}, h("h3", { class: "sub", style: "margin:0 0 4px" }, "Its belief, step by step"), belief)));
  }

  // ── journal ───────────────────────────────────────────────────────────────
  // Every fact of the run in order, by side; a click shows the run at its time.
  const SIDES = { attacker: "var(--critical)", defender: "var(--s1)", plant: "var(--axis)" };
  const journalShow = {}, journalAll = {};
  function journalDefaults(view) {
    return view === "attacker" ? { attacker: true, defender: false, plant: true }
      : view === "defender" ? { attacker: false, defender: true, plant: true } : { attacker: true, defender: true, plant: true };
  }
  function journalOf(r) {
    const x = sides(r), red = x.red, out = [];
    const add = (t, side, text) => { if (t != null) out.push({ t, side, text }); };
    if (red.start) add(red.start.t, "attacker", `attack starts (${red.start.mode || "?"})`);
    for (const c of red.recon) add(c.t, "attacker", c.stage === "it" ? `recon: ${(c.hosts || []).length} host(s) found${c.foothold ? `, foothold ${c.foothold.ip ?? c.foothold}` : ""}`
      : `recon: plant at ${c.engine_ip}:${c.modbus_port}, Modbus ${c.modbus_ok ? "answers" : "silent"}`);
    if (red.belief) add(red.belief.t, "attacker", "builds its own attack tree");
    for (const p of red.plans) add(p.t, "attacker", `${p.reason === "replan" ? "re-plans" : "plans"}: ${p.target} via ${p.sequence.join(" → ")}`);
    for (const s of red.steps) add(s.t, "attacker", `${s.node} ${s.ok ? "done" : "failed"}${s.by !== "agent" ? ` (by ${s.by})` : ""}${s.observed?.whoami ? ` — runs as ${s.observed.whoami}` : ""}`);
    let w = null;
    for (const x2 of r.writes) {
      const reg = `${x2.register}${where(r, x2)}`;   // the same register of another feeder is another write
      if (w && w.reg === reg && x2.t - w.last < 5) { w.n++; w.last = x2.t; w.item.text = `writes ${x2.register} = ${x2.value}${where(r, x2)} ×${w.n}`; continue; }
      w = { reg, n: 1, last: x2.t, item: { t: x2.t, side: "attacker", text: `writes ${x2.register} = ${x2.value}${where(r, x2)}` } };
      out.push(w.item);
    }
    if (red.end) add(red.end.t, "attacker", red.end.success ? "attack ends: impact reached" : `attack ends: stopped at ${red.end.stage_reached || "nothing"}`);
    let f = null;
    for (const x2 of r.findings) {
      const k = `${x2.detector}: ${x2.klass}${where(r, x2)}`;
      if (f && f.k === k && x2.t - f.last < 5) { f.n++; f.last = x2.t; f.item.text = `finding ${k} ×${f.n}`; continue; }
      f = { k, n: 1, last: x2.t, item: { t: x2.t, side: "defender", text: `finding ${k}${x2.src ? ` from ${x2.src}` : ""}${x2.maps_to ? ` → ${x2.maps_to}` : ""}` } };
      out.push(f.item);
    }
    for (const a of x.blue.alerts) add(a.t, "defender", `alert ${a.state}: ${a.detector}: ${a.klass}${where(r, a)}`);
    let prev = {};
    for (const st of r.states) {
      const changes = Object.entries(st.nodes || {}).filter(([n, s2]) => s2[0] in STATE_RANK && prev[n] !== s2[0]).map(([n, s2]) => `${n} ${s2[0]}`);
      prev = Object.fromEntries(Object.entries(st.nodes || {}).map(([n, s2]) => [n, s2[0]]));
      if (changes.length) add(st.t, "defender", `believes: ${changes.join(", ")}`);
    }
    for (const d of r.decisions) add(d.t, "defender", `decides: ${d.actions.join(", ") || "no action"}`);
    for (const a of r.actions) if (a.id !== "notify") add(a.t, "defender", `${a.op === "revert" ? "reverts" : "applies"} ${a.id}${a.machine ? ` on ${a.machine}` : ""}: ${a.ok ? "done" : "failed"}`);
    for (const a of Object.values(r.approvals)) {
      add(a.asked_t, "defender", `asks the operator: ${a.action}`);
      if (a.state && a.state !== "requested" && a.t !== a.asked_t) add(a.t, "defender", `operator: ${a.action} ${a.state}${a.operator ? ` by ${a.operator}` : ""}`);
    }
    for (const [, plant, name] of feeders(r)) {
      for (const [a, b] of spans(plant, p => p.abnormal)) { add(a, "plant", `voltages leave the normal band${name}`); add(b, "plant", `voltages back in band${name}`); }
      for (const [a, b] of spans(plant, p => p.ctrl_mode === 1)) { add(a, "plant", `control switches to MANUAL${name}`); add(b, "plant", `control back to auto${name}`); }
      for (const [a, b] of spans(plant, p => !!p.switch_cmd)) { add(a, "plant", `feeder breaker opens${name}`); add(b, "plant", `feeder breaker closes${name}`); }
    }
    return out.sort((a, b) => a.t - b.t);
  }
  function renderJournal(box, r, t) {
    const view = UI.view() || "overview";
    const show = journalShow[view] || (journalShow[view] = journalDefaults(view));
    if (!keep(box, r, t, [view, show, !!journalAll[view]])) return;
    const items = journalOf(r).filter(e => show[e.side]);
    const all = !!journalAll[view], shown = all ? items : items.slice(-300);
    const filters = h("div", { class: "tabs", role: "group", "aria-label": "Sides shown" },
      ...Object.keys(SIDES).map(k => h("button", { type: "button", "aria-pressed": String(!!show[k]), title: `Show the ${k}'s facts`,
        onclick: () => { show[k] = !show[k]; box.dataset.sig = ""; UI.render(); } },
        h("span", { class: "dot", style: `background:${SIDES[k]};margin-right:5px` }), k)));
    const t0 = r.start_t;
    const rows = shown.map(e => h("tr", { ...jump(e.t), style: t != null && e.t > t + 1e-6 ? "opacity:.4" : null },
      h("td", { class: "num" }, t0 ? `+${dur(e.t - t0)}` : clock(e.t)),
      h("td", {}, h("span", { class: "dot", style: `background:${SIDES[e.side]}` }), ` ${e.side}`),
      h("td", { class: "wrap" }, e.text)));
    // replaceChildren would print a null as the text "null": the note is spread in or not at all.
    box.replaceChildren(filters,
      ...(items.length > shown.length ? [h("p", { class: "sub" }, `The last ${shown.length} of ${items.length} facts. `,
        h("button", { type: "button", onclick: () => { journalAll[view] = true; box.dataset.sig = ""; UI.render(); } }, "show all"))] : []),
      h("div", { class: "scroll", style: "max-height:420px;overflow-y:auto" }, h("table", {},
        h("thead", {}, h("tr", {}, th("at", "From the start of the run", true), th("side", "Whose fact it is"), th("what", "Facts after the time shown are greyed"))),
        h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: 3, class: "empty" }, "Nothing yet"))))));
  }

  const GRAPH_OPTIONS = [
    { id: "hideInputs", label: "hide input registers", view: "kg", default: true,
      help: "Input registers are the plant's measurements: read-only, never a target" },
    { id: "perspective", label: "show", view: "tree", default: "both",
      help: "Whose view of the attack tree to draw",
      choices: [
        { id: "both", label: "Both", help: "The defender's belief (fill) and what the attacker did (red badges)" },
        { id: "attacker", label: "Attacker's", help: "The tree as the attacker knows it, with what it did; nothing of the defence" },
        { id: "defender", label: "Defender's", help: "Only what the defender believes, and its countermeasures" },
      ] },
  ];
  const origin = r => r.writes.length ? { t: r.writes[0].t, label: "from the first malicious write" } : null;

  // The page's sections and this panel's cards, composed into three views.
  const VIEWS = [
    { id: "overview", label: "Overview", help: "Both sides, side by side: the kill chain, what each is doing and seeing, the plant",
      sections: ["card-killchain", "card-sides", "queue-card", "detail", "card-journal", "graph-card", "op-card", "teams-card", "results-card"],
      options: { perspective: "both" } },
    { id: "attacker", label: "Attacker", help: "Only the attacker: what it did, what it knew and planned, the tree as it knew it",
      sections: ["card-attacker", "card-journal", "graph-card", "detail"], options: { perspective: "attacker" } },
    { id: "defender", label: "Defender", help: "Only the defender: what it saw and believed, what it decided and ran",
      sections: ["card-defender", "card-journal", "detail", "graph-card", "op-card"], options: { perspective: "defender" } },
  ];
  const CARDS = [
    { id: "killchain", title: "Kill chain", render: renderKillchain,
      sub: "Each step of the attack against the defender's view of it, at the time shown.",
      help: "One row per step of the attack.\n● red: the attacker did it (✗: tried and failed) · ▲ the defender first suspected it · ◆ confirmed it · green ■: a countermeasure covering it was applied.\nseen after: how long the defender took to suspect a step after the attacker did it.\nThe four figures above: time to detect, to respond, to impact, and who is ahead (hover each)." },
    { id: "sides", title: "Attacker · Defender", render: renderSides,
      sub: "What each side is doing and what it can see, at the time shown. Attacker: from its own record; defender: from its telemetry and decisions.",
      help: "Left, the attacker: what it is doing and what it knows of the target, from the record its agent (or the red console) keeps. Right, the defender: what it is doing and what it sees and believes, from its sensors and analytics.\nHover a line's name for its meaning. The lanes below put both sides and the plant on one timeline: click a mark to show the run at that time." },
    { id: "attacker", title: "Attacker", render: renderAttacker,
      sub: "Only the attacker: its steps and what each told it, its plans and its reconnaissance.",
      help: "Everything here comes from the attacker's own record: nothing of what the defender saw.\nIts steps: what it ran and what each step's output told it. Its plans: each time it chose an impact to aim at, the options it had and the paths it had lost. Its reconnaissance: what its scans found (recon attacker only).\nClick a row to show the run at that time." },
    { id: "defender", title: "Defender", render: renderDefender,
      sub: "Only the defender: what it saw, what it believed and when, what it decided and ran.",
      help: "Everything here comes from the defender's sensors and analytics: nothing of what the attacker really did.\nIts decisions: each response with the finding that triggered it and what the policy weighed. Alerts: raised and cleared. Its belief: when each step of the attack tree was first suspected, inferred, confirmed.\nClick a row to show the run at that time." },
    { id: "journal", title: "Journal", render: renderJournal,
      sub: "Every fact of the run in order. Click a row to show the run at that time.",
      help: "The run as a log: the attacker's steps, plans and writes; the defender's findings, beliefs, decisions and actions; the plant's changes of state. Repeated findings and writes within 5 s are grouped. Facts after the time shown are greyed. The buttons choose whose facts to list." },
  ];

  let UI = null;
  // The page invokes this once, with its own handles.
  (window.CyberRangePanels ||= {})["cps"] = ui => {
    s = ui.svg;
    UI = ui;
    return {
      queue: () => queue(ui),
      detail,
      chart: drawChart,
      reduce,
      views: VIEWS,
      cards: CARDS,
      graph: { index, overlayAt, marks, drawTopology, drawKG, drawTree, options: GRAPH_OPTIONS, origin },
      // The results tabs this scenario fills, shown before any run is scored.
      results: { tabs: RESULT_TABS, render: results },
    };
  };
})();
