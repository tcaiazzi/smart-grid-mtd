// cps_graph.js — topology, knowledge-graph and attack-tree views for the CPS
// progress dashboard (monitor/cps_dashboard.html). Served at /graph.js by
// monitor/cps_dashboard.py. Self-contained (no libraries, no CDN); every view
// is a pure function of (structure, overlay) that draws an SVG with a
// deterministic layout, so a redraw never moves anything that did not change.
//
//   structure = /api/structure → {source, kg: networkx node-link, tree: {attack_tree, defense, countermeasures}}
//   overlay   = CPSGraph.overlayAt(run, t) → response state at time t
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
  const ZONE_ORDER = ["IT", "OT", "DEF"];
  const STATE_STYLE = {
    confirmed: { stroke: "var(--critical)", fill: "var(--critical)", dash: null, label: "confirmed" },
    inferred: { stroke: "var(--serious)", fill: "var(--serious)", dash: "5 3", label: "inferred" },
    suspected: { stroke: "var(--warning)", fill: "var(--warning)", dash: null, label: "suspected" },
    unknown: { stroke: "var(--axis)", fill: null, dash: null, label: "not seen" },
  };
  // How an applied countermeasure shows on the topology (others: a generic tag).
  const CM_STYLE = {
    block_flow: { kind: "block", tag: "flow blocked" },
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
  function marks(run) {
    const m = [];
    for (const s of run.states || []) m.push({ t: s.t, kind: "state" });
    for (const d of run.decisions || []) m.push({ t: d.t, kind: "decision" });
    for (const a of run.actions || []) m.push({ t: a.t, kind: "action" });
    for (const w of run.writes || []) m.push({ t: w.t, kind: "write" });
    return m.sort((a, b) => a.t - b.t);
  }
  function overlayAt(run, t) {
    const upto = x => t == null || x.t <= t + 1e-6;
    const states = (run.states || []).filter(upto);
    const st = states[states.length - 1] || null;
    const applied = {};
    for (const a of run.actions || []) if (upto(a) && a.ok && a.id !== "notify" && !(a.id in applied)) applied[a.id] = a.t;
    return {
      t, nodes: st ? st.nodes || {} : {}, active: st ? st.active || [] : [], hosts: st ? st.hosts || [] : [],
      next: st ? st.next || [] : [], applied, writes: (run.writes || []).filter(upto).length,
      decisions: (run.decisions || []).filter(upto),
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
      const style = CM_STYLE[id] || { kind: "tag", tag: id };
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
      if (zs.length >= 2) {           // boundary device: on the edge between its outermost zones
        const a = zi[zs[0]], b = zi[zs[zs.length - 1]];
        // adjacent zones: centred in the gap; otherwise centred over the span
        x = b - a === 1 ? colX(a) + colW + (GAP - BW) / 2 : (colX(a) + colW + colX(b)) / 2 - BW / 2;
        place[h.id] = { x, y: slot(`gap${a}-${b}`, h), zs };
      } else {
        const i = zi[zs[0]] ?? 0;
        x = colX(i) + (colW - BW) / 2;
        place[h.id] = { x, y: slot(`col${i}`, h), zs };
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
  function drawTree(box, S, ov, opts) {
    const T = treeIndex(S.tree), root = S.tree.attack_tree, def = S.tree.defense || {};
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
    const M = 12, W = leafX - XG + 2 * M, H = (depthMax + 1) * rowH() + 10;
    const Y = d => 8 + d * rowH();
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Attack tree", class: "graph",
      style: `max-width:${Math.max(W, 600)}px` });
    const edges = el("g"), nodes = el("g");
    (function draw(n) {
      const p = pos[n.id], x = M + p.x, y = Y(p.d);
      const s = stateOf(ov, n.id), st = STATE_STYLE[s.state] || STATE_STYLE.unknown;
      for (const c of n.children || []) {
        const q = pos[c.id], cx = M + q.x + NW / 2, cy = Y(q.d);
        edges.append(el("path", { d: `M${x + NW / 2},${y + NH + 2 * CHIP + 4} C${x + NW / 2},${cy - LV / 2} ${cx},${y + NH + 2 * CHIP + LV / 2} ${cx},${cy}`,
          fill: "none", stroke: "var(--axis)", "stroke-width": 1.3 }));
        draw(c);
      }
      const g = el("g");
      if (st.fill) g.append(el("rect", { x, y, width: NW, height: NH, rx: 8, fill: st.fill, opacity: 0.13 }));
      g.append(el("rect", { x, y, width: NW, height: NH, rx: 8, fill: st.fill ? "none" : "var(--surface)", stroke: st.stroke,
        "stroke-width": s.state === "unknown" ? 1 : 2, "stroke-dasharray": st.dash }));
      wrap2(n.label, 25).forEach((line, i) =>
        g.append(el("text", { x: x + 8, y: y + 15 + i * 13, "font-size": 11.5, "font-weight": 600, fill: "var(--ink)" }, line)));
      const sub = [n.attck, n.gate !== "LEAF" ? n.gate : null, n.observable === false ? "not observable" : null].filter(Boolean).join(" · ");
      g.append(el("text", { x: x + 8, y: y + 43, "font-size": 10.5, fill: "var(--ink-2)" }, clip(sub, 29)));
      g.append(el("text", { x: x + 8, y: y + 56, "font-size": 10.5, fill: s.state === "unknown" ? "var(--muted)" : st.stroke, "font-weight": 600 },
        s.state === "unknown" ? st.label : `${st.label} ${(+s.score).toFixed(2)}`));
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
      nodes.append(g);
    })(root);
    svg.append(edges, nodes);
    box.replaceChildren(svg);
    return Object.entries(STATE_STYLE).map(([k, v]) => [v.stroke, v.label]).concat([
      ["var(--muted)", "⊘ prevented by · ↺ restored by"], ["var(--good)", "✓ countermeasure applied by the selected time"]]);
  }


  // ── views the core page cannot draw ───────────────────────────────────
  // Moved out of dashboard.html: only this scenario knows what a detection
  // latency or a bus voltage means. The page's helpers (h, $, num, dur, now,
  // statusBadge) are globals by the time this factory runs.
function det(m, d) { return m?.detectors?.[d]; }
function detCell(m, d) {
  const x = det(m, d);
  if (!m || !m.attack || !x) return h("td", { class: "muted" }, "—");
  return h("td", { class: "num" }, x.detected ? `${num(x.latency_from_write_s, 2)} s${x.before_impact ? "" : " *"}` : "missed");
}

// The queue every scenario gets: what a run is, not what it measured. Numeric
// metrics are shown in the order the scenario reported them, with no opinion
// about which matter — a scenario that wants an opinion ships a panel.
  const LATENCY_HINT = "latency from the first malicious write; * = after the physical impact";

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
        const impact = !m ? "—" : !m.abnormal_frames ? "none"
          : m.impact_persists_after_attack ? "persists"
          : m.recovered ? `recovered ${num(m.recovery_s, 1)} s` : "yes";
        const fa = m ? (m.detectors?.combined?.false_alarms ?? m.false_alarms) : null;
        return [detCell(m, "rules"), detCell(m, "model"), h("td", {}, impact),
          h("td", { class: "num" }, fa == null ? "—" : String(fa))];
      },
    });
  }

// The selected run: live plant state as chips, the voltage chart, and the
// sensor findings by detector and class. The page has drawn the phases above.
function detail(r) {
  if (r.threshold != null) $("d-sub").textContent += ` · model threshold ${r.threshold}`;
  $("f-title").textContent = "Findings";
  $("f-sub").textContent = "Sensor findings so far, by detector and class (live during the run).";
  const last = r.plant[r.plant.length - 1];
  const chip = (k, v, dot) => h("div", { class: "chip" }, h("div", { class: "k" }, k),
    h("div", { class: "v" }, dot ? h("span", { class: "dot", style: `background:${dot}` }) : null, v));
  const byDet = d => r.findings.filter(f => f.detector === d);
  const firstAfter = d => { const w0 = r.writes[0]?.t; const f = byDet(d).find(f => w0 == null || f.t >= w0 - 1); return f && w0 != null ? `${num(f.t - w0, 2)} s` : (byDet(d).length ? "yes" : "—"); };
  $("d-chips").replaceChildren(
    chip("control", last ? (last.ctrl_mode === 1 ? "MANUAL" : "auto") : "—", last?.ctrl_mode === 1 ? "var(--warning)" : null),
    chip("DG setpoint", last?.dg_setpoint != null ? `${num(last.dg_setpoint, 1)} kW` : "—"),
    chip("breaker", last ? (last.switch_cmd ? "OPEN" : "closed") : "—", last?.switch_cmd ? "var(--critical)" : null),
    chip("plant", last ? (last.abnormal ? "abnormal" : "in band") : "—", last ? (last.abnormal ? "var(--critical)" : "var(--good)") : null),
    chip("rules fired", r.writes.length ? firstAfter("rules") : String(byDet("rules").length)),
    chip("model fired", r.writes.length ? firstAfter("model") : String(byDet("model").length)),
  );
  drawChart(r);
  const agg = {};
  for (const f of r.findings) { const k = `${f.detector}|${f.klass}`; (agg[k] = agg[k] || { d: f.detector, k: f.klass, n: 0, first: f.t }).n++; }
  const rows = Object.values(agg).sort((a, b) => a.first - b.first).map(a =>
    h("tr", {}, h("td", {}, a.d), h("td", {}, a.k), h("td", { class: "num" }, String(a.n)),
      h("td", { class: "num" }, r.start_t ? `+${dur(a.first - r.start_t)}` : "—")));
  $("d-findings").replaceChildren(h("thead", {}, h("tr", {}, h("th", {}, "detector"), h("th", {}, "class"), h("th", { class: "num" }, "count"), h("th", { class: "num" }, "first at"))),
    h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: 4, class: "empty" }, "No findings"))));
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

// ── voltage chart ───────────────────────────────────────────────────────────
const SVGNS = "http://www.w3.org/2000/svg";
function s(tag, attrs, text) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  if (text != null) e.textContent = text;
  return e;
}
const Y_LO = 0.80, Y_HI = 1.20;
let chartKey = null;
function drawChart(r) {
  const box = $("d-chart"), tip = $("tip");
  const key = r ? [r.id, r.start_t, r.plant.length, r.findings.length, r.writes.length, box.clientWidth,
    document.documentElement.dataset.theme || ""].join("|") : "none";
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
  legend.append(
    h("span", {}, h("span", { class: "lk", style: "background:var(--s1)" }), "load-bus voltage"),
    h("span", {}, h("span", { class: "lk", style: "background:var(--s2)" }), "DG-bus voltage"),
    h("span", {}, h("span", { class: "lk", style: "background:var(--wash);height:8px;border:1px solid var(--grid)" }), "normal band 0.95–1.05 pu"));
  const W = Math.max(320, box.clientWidth || 600), H = 230, m = { l: 44, r: 12, t: 14, b: 26 };
  const t0 = r.start_t, pts = r.plant;
  const tEnd = Math.max(pts[pts.length - 1].t, ...(r.phases.map(p => p.end_t || 0)), t0 + 10);
  const plannedEnd = t0 + r.phases.reduce((a, p) => a + (p.planned_s || 0), 0);
  // A live run is drawn on its whole planned timeline (stable axis, fills up);
  // a finished one on what actually happened.
  const xMax = (r.status === "running" ? Math.max(tEnd, plannedEnd) : tEnd) - t0;
  const X = v => m.l + (W - m.l - m.r) * Math.min(1, Math.max(0, v - t0) / Math.max(xMax, 1));
  const clampV = v => Math.min(Y_HI, Math.max(Y_LO, v));
  const Y = v => m.t + (H - m.t - m.b) * (1 - (clampV(v) - Y_LO) / (Y_HI - Y_LO));
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Bus voltages for ${r.id}` });
  // calibration window
  const np = r.phases.find(p => p.name === "normal");
  if (np?.start_t && r.learn_s) {
    const x1 = X(np.start_t), x2 = Math.min(X(np.start_t + r.learn_s), W - m.r);
    svg.append(s("rect", { x: x1, y: m.t, width: Math.max(0, x2 - x1), height: H - m.t - m.b, fill: "var(--wash)" }));
    svg.append(s("text", { x: x1 + 4, y: H - m.b - 6, "font-size": 11, fill: "var(--muted)" }, "model calibration"));
  }
  // band + grid
  svg.append(s("rect", { x: m.l, y: Y(1.05), width: W - m.l - m.r, height: Y(0.95) - Y(1.05), fill: "var(--wash)", stroke: "var(--grid)" }));
  for (const v of [0.8, 0.9, 1.0, 1.1, 1.2]) {
    svg.append(s("line", { x1: m.l, x2: W - m.r, y1: Y(v), y2: Y(v), stroke: "var(--grid)", "stroke-width": 1 }));
    svg.append(s("text", { x: m.l - 6, y: Y(v) + 4, "text-anchor": "end", "font-size": 11, fill: "var(--muted)" }, v.toFixed(2)));
  }
  const step = xMax > 240 ? 60 : xMax > 90 ? 30 : 10;
  for (let x = 0; x <= xMax; x += step)
    svg.append(s("text", { x: X(t0 + x), y: H - 6, "text-anchor": "middle", "font-size": 11, fill: "var(--muted)" }, `${x}s`));
  svg.append(s("line", { x1: m.l, x2: W - m.r, y1: H - m.b, y2: H - m.b, stroke: "var(--axis)" }));
  // events: attack + first finding per detector
  const marks = [];
  if (r.writes.length) marks.push({ t: r.writes[0].t, label: "attack", dash: "4 3", shape: null });
  for (const [d, shape] of [["rules", "tri"], ["model", "dia"]]) {
    const w0 = r.writes[0]?.t;
    const f = r.findings.find(f => f.detector === d && (w0 == null || f.t >= w0 - 1));
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

  // The page invokes this once, with its own handles.
  (window.CyberRangePanels ||= {})["cps"] = ui => ({
    queue: () => queue(ui),
    detail,
    chart: drawChart,
    graph: { index, overlayAt, marks, drawTopology, drawKG, drawTree },
    // The results tabs this scenario fills, shown before any run is scored.
    results: { tabs: RESULT_TABS, render: results },
  });
})();
