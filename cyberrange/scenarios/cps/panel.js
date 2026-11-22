// panel.js — the cps scenario's views on the platform dashboard
// (cyberrange/core/dashboard.html, which serves every scenario's panel at /graph.js).
//
// The run's two sides at once: what the attacker does and knows, what the
// defender does and believes (the "Attacker · Defender" card), on top of the
// plant chart, the findings, and the topology / knowledge-graph / attack-tree
// views. The charts are drawn by Observable Plot (through ui.plot) and the
// attack tree is laid out by D3, both served by the page from its own files.
// Every structure view is a pure function of (structure, overlay) drawing an SVG
// with a deterministic layout, so a redraw never moves anything that did not
// change. The topology and the knowledge graph place their nodes themselves:
// their columns mean something (a zone, a type of node), which no general
// layout would keep.
//
//   structure = /api/structure → {source, kg: networkx node-link, tree: {attack_tree, defense, countermeasures}}
//   overlay   = overlayAt(run, t) → the defender's response state and the attacker's progress at time t
"use strict";
(function () {
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
    for (const s of run.states || []) m.push({ t: s.t, kind: "defender's belief changes" });
    for (const d of run.decisions || []) m.push({ t: d.t, kind: "defender decides" });
    for (const a of run.actions || []) m.push({ t: a.t, kind: `countermeasure ${pretty(a.id)} ${didWhat(a)}` });
    for (const w of run.writes || []) m.push({ t: w.t, kind: "attacker writes to the plant" });
    const red = run.x && run.x.red;
    if (red) {
      for (const st of red.steps) m.push({ t: st.t, kind: `attacker step ${pretty(st.node)} ${st.ok ? "done" : "failed"}` });
      for (const c of red.recon) m.push({ t: c.t, kind: `attacker reconnaissance (${c.stage === "it" ? "IT network" : "plant"})` });
    }
    // One stop per detector and class: a burst of identical findings is one fact.
    const seen = new Set();
    for (const f of run.findings || []) {
      const k = `${f.detector}|${f.klass}`;
      if (!seen.has(k)) { seen.add(k); m.push({ t: f.t, kind: `finding: ${pretty(f.klass)}` }); }
    }
    return m.filter(x => x.t != null).sort((a, b) => a.t - b.t);
  }
  const uptoT = t => x => t == null || (x && x.t != null && x.t <= t + 1e-6);
  function overlayAt(run, t) {
    const upto = uptoT(t);
    const states = (run.states || []).filter(upto);
    const st = states[states.length - 1] || null;
    const applied = inForce((run.actions || []).filter(upto));
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
    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Lab topology", class: "graph" });
    const defs = svg("defs");
    for (const [id, col] of [["arr", "var(--ink-2)"], ["arr-bad", "var(--critical)"]]) {
      const mk = svg("marker", { id: `${id}-${box.id}`, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" });
      mk.append(svg("path", { d: "M0,0 L10,5 L0,10 z", fill: col })); defs.append(mk);
    }
    root.append(defs);
    // zones
    zones.forEach((z, i) => {
      root.append(svg("rect", { x: colX(i), y: 4, width: colW, height: H - 8, rx: 10, fill: "var(--wash)", stroke: "var(--grid)" }));
      const nets = [...new Set(G.ofType("ip").filter(ip => addrZone(ip) === z).map(ip => ip.network))].join(", ");
      root.append(svg("text", { x: colX(i) + 12, y: 22, "font-size": 13, "font-weight": 600, fill: "var(--ink)" }, `${z} zone`));
      if (nets) root.append(svg("text", { x: colX(i) + colW - 10, y: 22, "font-size": 11, fill: "var(--muted)", "text-anchor": "end" }, nets));
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
        root.append(svg("line", { x1, y1: y, x2, y2: y, stroke: tap ? "var(--muted)" : "var(--ink-2)", "stroke-width": 1.5, "stroke-dasharray": tap ? "4 3" : null }));
        root.append(svg("text", { x: (x1 + x2) / 2, y: y - 4, "font-size": 10, fill: "var(--muted)", "text-anchor": "middle" }, ifBy[z] || ""));
        if (tap) root.append(svg("text", { x: (x1 + x2) / 2, y: y + 12, "font-size": 10, fill: "var(--muted)", "text-anchor": "middle" }, "tap"));
      }
    }
    // flow rules: src host -> boundary -> dst service
    const svcPos = {};
    const ruleLayer = svg("g");
    // hosts
    for (const h of hosts) {
      const p = place[h.id], hh = boxH(h), hot = I.tags[h.id]?.some(t => t.color === "var(--critical)") && ov.hosts.includes(h.name);
      const g = svg("g", { opacity: I.isolated.has(h.id) ? 0.45 : 1 });
      g.append(svg("rect", { x: p.x, y: p.y, width: BW, height: hh, rx: 8, fill: "var(--surface)",
        stroke: hot ? "var(--critical)" : "var(--ring)", "stroke-width": hot ? 2.5 : 1 }));
      let y = p.y + 18;
      g.append(svg("text", { x: p.x + 10, y, "font-size": 13, "font-weight": 600, fill: "var(--ink)" }, h.name));
      g.append(svg("text", { x: p.x + BW - 10, y, "font-size": 11, fill: "var(--muted)", "text-anchor": "end" }, h.role));
      for (const ip of ips(h)) { y += 15; g.append(svg("text", { x: p.x + 10, y, "font-size": 11, fill: "var(--ink-2)", "font-family": "ui-monospace, monospace" }, `${ip.iface} ${ip.addr}/${ip.prefix}`)); }
      if (h.forward_default) { y += 15; g.append(svg("text", { x: p.x + 10, y, "font-size": 11, fill: "var(--ink-2)" }, `FORWARD default ${h.forward_default}`)); }
      for (const s of svcs(h)) {
        y += 8;
        g.append(svg("rect", { x: p.x + 10, y, width: BW - 20, height: 16, rx: 8, fill: I.hot.has(s.id) ? "var(--wash)" : "none", stroke: I.hot.has(s.id) ? "var(--critical)" : "var(--axis)" }));
        g.append(svg("text", { x: p.x + 18, y: y + 12, "font-size": 11, fill: "var(--ink-2)" }, `${s.name} · ${s.proto}/${s.port}`));
        svcPos[s.id] = { x: p.x + 10, y: y + 8, w: BW - 20 };
        y += 12;
      }
      for (const t of I.tags[h.id] || []) {
        y += 15;
        g.append(svg("circle", { cx: p.x + 14, cy: y - 4, r: 3.5, fill: t.color }));
        g.append(svg("text", { x: p.x + 22, y, "font-size": 11, fill: "var(--ink)" }, clip(t.text, 27)));
      }
      g.append(svg("title", {}, [h.name, h.role, ...ips(h).map(i => i.addr)].join(" · ")));
      root.append(g);
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
      ruleLayer.append(svg("path", { d, fill: "none", stroke: bad ? "var(--critical)" : "var(--ink-2)", "stroke-width": 2,
        "stroke-dasharray": bad ? "6 4" : null, "marker-end": `url(#${bad ? "arr-bad" : "arr"}-${box.id})` }));
      const label = `${rule.proto || "any"}/${rule.dport ?? "any"} ${rule.action}${bad ? " → BLOCKED" : ""}`;
      ruleLayer.append(svg("text", { x: fx, y: midY + 15, "font-size": 11, "text-anchor": "middle", fill: bad ? "var(--critical)" : "var(--ink-2)",
        "font-weight": bad ? 600 : 400, stroke: "var(--surface)", "stroke-width": 3, "paint-order": "stroke" }, label));
      if (ov.writes) ruleLayer.append(svg("text", { x: fx, y: midY - 6, "font-size": 11, "text-anchor": "middle", fill: "var(--critical)",
        stroke: "var(--surface)", "stroke-width": 3, "paint-order": "stroke" }, `${ov.writes} attacker write${ov.writes === 1 ? "" : "s"}`));
      if (bad) ruleLayer.append(svg("path", { d: `M${fx - 6},${midY - 6} L${fx + 6},${midY + 6} M${fx + 6},${midY - 6} L${fx - 6},${midY + 6}`, stroke: "var(--critical)", "stroke-width": 2.5 }));
    }
    root.append(ruleLayer);
    box.replaceChildren(root);
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
  // What each relation of the graph says, from its source node to its target.
  const REL_WORDS = {
    in_zone: "is in the zone", has_ip: "has the address", runs: "runs the service", exposes: "exposes the register",
    may_write: "may write the register", enforces: "enforces the flow rule", src: "flow allowed from", dst: "flow allowed to",
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
    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Knowledge graph", class: "graph" });
    LAYERS.concat(extra.length ? ["other"] : []).forEach((t, li) => root.append(svg("text", { x: M + li * lw + NW / 2, y: 14, "font-size": 11,
      fill: "var(--muted)", "text-anchor": "middle" }, t.replace("_", " ") + (t === "register" && hideInputs ? " (holding)" : ""))));
    const edgeLayer = svg("g"), nodeLayer = svg("g"), edges = [], across = d3.linkHorizontal();
    for (const [sid, list] of Object.entries(G.out)) for (const e of list) {
      const a = pos[sid], b = pos[e.t]; if (!a || !b) continue;
      const fwd = a.x <= b.x, x1 = fwd ? a.x + NW : a.x, x2 = fwd ? b.x : b.x + NW;
      const y1 = a.y + NH / 2, y2 = b.y + NH / 2;
      // Between layers, a smooth link; within one, a loop out to the right.
      const d = a.x === b.x
        ? `M${a.x + NW},${y1} C${a.x + NW + 40},${y1} ${b.x + NW + 40},${y2} ${b.x + NW},${y2}`
        : across({ source: [x1, y1], target: [x2, y2] });
      const bad = I.blocked.has(sid) || I.blocked.has(e.t);
      const p = svg("path", { d, fill: "none", stroke: bad ? "var(--critical)" : (REL_COLOR[e.rel] || "var(--axis)"),
        "stroke-width": 1.4, opacity: 0.75, "stroke-dasharray": bad ? "5 3" : null });
      p.append(svg("title", {}, `${sid} ${REL_WORDS[e.rel] || pretty(e.rel)} ${e.t}`));
      edges.push({ p, s: sid, t: e.t }); edgeLayer.append(p);
    }
    const tip = opts && opts.tip;
    for (const layer of layers) for (const n of layer) {
      const p = pos[n.id], hot = I.hot.has(n.id), bad = I.blocked.has(n.id);
      const g = svg("g", { tabindex: 0, style: "cursor:default" });
      g.append(svg("rect", { x: p.x, y: p.y, width: NW, height: NH, rx: 6, fill: "var(--surface)",
        stroke: bad || hot ? "var(--critical)" : "var(--ring)", "stroke-width": bad || hot ? 2 : 1, "stroke-dasharray": bad ? "4 2" : null }));
      const label = n.type === "host" ? n.name : n.type === "ip" ? n.addr : n.type === "service" ? `${n.host}/${n.name}`
        : n.type === "register" ? `${n.name} (${n.kind === "holding" ? "holding" : "input"} ${n.addr})` : n.type === "flow_rule" ? `${n.action} ${n.proto || ""}/${n.dport ?? "*"}`
        : n.name || n.id;
      g.append(svg("text", { x: p.x + 8, y: p.y + 16, "font-size": 11, fill: "var(--ink)" }, clip(label, 24)));
      if (n.sensitive) g.append(svg("circle", { cx: p.x + NW - 9, cy: p.y + NH / 2, r: 3.5, fill: "var(--warning)" }));
      const enter = ev => {
        for (const e of edges) e.p.setAttribute("opacity", e.s === n.id || e.t === n.id ? 1 : 0.08);
        if (tip) {
          // What the graph records of the node, one property a line, then how it relates to others.
          const say = v => v == null ? "—" : Array.isArray(v) ? (v.join(", ") || "none") : typeof v === "object"
            ? Object.entries(v).map(([k, x]) => `${pretty(k)} ${x}`).join(", ") : typeof v === "boolean" ? (v ? "yes" : "no") : String(v);
          const rows = Object.entries(n).filter(([k]) => k !== "id" && k !== "type").map(([k, v]) => `${pretty(k)}: ${say(v)}`);
          const links = [...(G.out[n.id] || []).map(e => `${REL_WORDS[e.rel] || pretty(e.rel)} ${e.t}`), ...(G.inn[n.id] || []).map(e => `${e.s} ${REL_WORDS[e.rel] || pretty(e.rel)} it`)];
          tip.show(ev, `${pretty(n.type)}: ${label}`, [...rows, ...(links.length ? [`relations: ${links.slice(0, 8).join(" · ")}${links.length > 8 ? ` … (${links.length})` : ""}`] : [])]);
        }
      };
      const leave = () => { for (const e of edges) e.p.setAttribute("opacity", 0.75); if (tip) tip.hide(); };
      g.addEventListener("mouseenter", enter); g.addEventListener("mouseleave", leave);
      g.addEventListener("focus", enter); g.addEventListener("blur", leave);
      nodeLayer.append(g);
    }
    root.append(edgeLayer, nodeLayer);
    box.replaceChildren(root);
    const used = new Set(); for (const list of Object.values(G.out)) for (const e of list) used.add(e.rel);
    return [[null, "Relations:"], ...[...used].map(r => [REL_COLOR[r] || "var(--axis)", REL_WORDS[r] || pretty(r)]),
      [null, "Marks:"], ["var(--warning)", "● sensitive register: one that actuates the plant"], ["var(--critical)", "involved in the attack, or blocked"]];
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
    const NW = 190, NH = 62, CHIP = 13, XG = 12, LV = 48, CHIP_CHARS = 33, STRIP = 16;
    // The countermeasures under a node, as lines that fit its width: each list
    // (⊘ would prevent, ↺ would restore) wraps instead of running into the next node.
    const chipLines = id => [["⊘", def[id]?.prevented_by], ["↺", def[id]?.restored_by]].flatMap(([kind, list]) => {
      const lines = [];
      for (const cm of list || []) {
        const line = lines[lines.length - 1];
        if (line && line.len + cm.length + 2 <= CHIP_CHARS) { line.ids.push(cm); line.len += cm.length + 2; }
        else lines.push({ kind: lines.length ? " " : kind, ids: [cm], len: cm.length + 3 });
      }
      return lines;
    });
    let maxChips = 0;
    (function count(n) { maxChips = Math.max(maxChips, chipLines(n.id).length); (n.children || []).forEach(count); })(root);
    // A tidy tree (d3.tree): every node one slot wide, a parent centred over its
    // children. The layout depends on the tree alone, so a redraw moves nothing.
    const rowH = () => NH + maxChips * CHIP + LV;
    const laid = d3.tree().nodeSize([NW + XG, rowH()]).separation(() => 1)(d3.hierarchy(root, n => n.children));
    const left = d3.min(laid.descendants(), n => n.x), right = d3.max(laid.descendants(), n => n.x);
    const pos = Object.fromEntries(laid.descendants().map(n => [n.data.id, { x: n.x - left, d: n.depth }]));
    const depthMax = laid.height;
    // The top margin leaves room for the attacker's badge above a root node.
    const M = 12, W = right - left + NW + 2 * M, H = (depthMax + 1) * rowH() + 20;
    const link = d3.linkVertical();
    const Y = d => 22 + d * rowH();
    // A wide tree is not shrunk until its text cannot be read: below four fifths
    // of its size the card scrolls sideways instead (and it can be zoomed).
    const drawing = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Attack tree", class: "graph",
      style: `max-width:${Math.max(W, 600)}px;min-width:${Math.round(W * 0.8)}px` });
    // What really happened at a node, beside what the defender believes of it:
    // the attacker did the step, tried and failed, or aims at it; and whether a
    // countermeasure against the step is in force at the time shown.
    const rd0 = ov.red || {};
    const happened = id => persp === "attacker" ? null : id in (rd0.done || {}) ? "done" : id in (rd0.failed || {}) ? "failed" : rd0.target === id ? "target" : null;
    const countered = id => [...(def[id]?.prevented_by || []), ...(def[id]?.restored_by || [])].filter(cm => cm in ov.applied);
    const edges = svg("g"), nodes = svg("g");
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
        // The links down to the steps the attacker did are the path the attack took.
        const taken = happened(c.id) === "done";
        edges.append(svg("path", { d: link({ source: [x + NW / 2, y + NH + chipLines(n.id).length * CHIP + 4], target: [cx, cy - (happened(c.id) ? STRIP : 0)] }),
          fill: "none", stroke: taken ? "var(--critical)" : "var(--axis)", "stroke-width": taken ? 3 : 1.3 }));
        draw(c);
      }
      const g = svg("g");
      // A strip on top of the node says what happened there in words, solid when the
      // step was done; drawn first, so that the node's body covers its lower edge.
      const what = happened(n.id);
      if (what) {
        const solid = what === "done";
        g.append(svg("rect", { x, y: y - STRIP, width: NW, height: STRIP + 8, rx: 8, fill: solid ? "var(--critical)" : "var(--surface)",
          stroke: "var(--critical)", "stroke-width": 2, "stroke-dasharray": solid ? null : "4 3" }));
        g.append(svg("text", { x: x + 8, y: y - STRIP + 12, "font-size": 10.5, "font-weight": 700, fill: solid ? "var(--surface)" : "var(--critical)" },
          { done: "✓ the attacker did this", failed: "✗ the attacker tried and failed", target: "◎ the attacker aims at this" }[what]));
      }
      g.append(svg("rect", { x, y, width: NW, height: NH, rx: 8, fill: "var(--surface)" }));
      if (st.fill) g.append(svg("rect", { x, y, width: NW, height: NH, rx: 8, fill: st.fill, opacity: 0.13 }));
      g.append(svg("rect", { x, y, width: NW, height: NH, rx: 8, fill: "none", stroke: st.stroke,
        "stroke-width": st === STATE_STYLE.unknown ? 1 : 2, "stroke-dasharray": st.dash }));
      wrap2(n.label || n.id, 27).forEach((line, i) =>
        g.append(svg("text", { x: x + 8, y: y + 15 + i * 13, "font-size": 11.5, "font-weight": 600, fill: "var(--ink)" }, line)));
      const sub = [n.attck, n.gate !== "LEAF" ? n.gate : null, n.observable === false ? "not observable" : null].filter(Boolean).join(" · ");
      g.append(svg("text", { x: x + 8, y: y + 43, "font-size": 10.5, fill: "var(--ink-2)" }, clip(sub, n.impact ? 25 : 34)));
      const line3 = persp === "attacker" ? (st === STATE_STYLE.unknown ? (n.feasible === false ? "believed infeasible" : "not tried") : st.label)
        : s.state === "unknown" ? st.label : `${st.label} ${(+s.score).toFixed(2)}`;
      g.append(svg("text", { x: x + 8, y: y + 56, "font-size": 10.5, fill: st === STATE_STYLE.unknown ? "var(--muted)" : st.stroke, "font-weight": 600 }, line3));
      if (n.impact) g.append(svg("text", { x: x + NW - 8, y: y + 43, "font-size": 10, fill: "var(--muted)", "text-anchor": "end" }, `impact ${n.impact}`));
      g.append(svg("title", {}, [n.label, n.attck_name, n.review ? `review: ${n.review}` : null, (n.targets || []).join(", ")].filter(Boolean).join("\n")));
      // countermeasure chips: filled = applied by t
      let cy = y + NH + CHIP - 1;
      for (const line of chipLines(n.id)) {
        const t = svg("text", { x: x + 4, y: cy, "font-size": 10 });
        t.append(svg("tspan", { fill: "var(--muted)" }, `${line.kind} `));
        line.ids.forEach((id, i) => {
          const on = id in ov.applied, chip = svg("tspan", { fill: on ? "var(--good)" : "var(--muted)", "font-weight": on ? 700 : 400 },
            (on ? "✓" : "") + id + (i < line.ids.length - 1 ? "  " : ""));
          // The countermeasure's own name, on hover.
          if (T.cms[id]?.label) chip.append(svg("title", {}, `${T.cms[id].label}${on ? " — applied" : ""}`));
          t.append(chip);
        });
        g.append(t); cy += CHIP;
      }
      // The attacker's side of the same node: what it did, what it aims at,
      // and (when it built its own tree) whether it knows the node at all.
      const cms = countered(n.id);
      if (cms.length) {
        const tag = svg("g");
        tag.append(svg("rect", { x: x + NW - 78, y: y + NH - 20, width: 72, height: 15, rx: 7.5, fill: "var(--good)" }));
        tag.append(svg("text", { x: x + NW - 42, y: y + NH - 9, "font-size": 10, "font-weight": 700, "text-anchor": "middle", fill: "var(--surface)" }, "countered"));
        tag.append(svg("title", {}, `In force against this step: ${cms.map(cm => T.cms[cm]?.label || cm).join("; ")}`));
        g.append(tag);
      }
      if (ov.redKnows && !ov.redKnows.has(n.id) && !(ov.redLeavesOnly && (n.children || []).length))
        g.append(svg("rect", { x: x - 4, y: y - 4, width: NW + 8, height: NH + 8, rx: 11, fill: "none",
          stroke: "var(--critical)", "stroke-dasharray": "3 3", opacity: 0.8 }));
      nodes.append(g);
    })(root);
    drawing.append(edges, nodes);
    box.replaceChildren(drawing);
    // The legend in groups, a heading (no colour) before each.
    const legend = [];
    if (persp !== "attacker") legend.push([null, "Defender believes:"],
      ...Object.values(STATE_STYLE).map(v => [v.stroke, v.label]),
      [null, "Countermeasures:"], ["var(--muted)", "⊘ would prevent · ↺ would restore"], ["var(--good)", "✓ applied by the time shown · green tag: the step is countered"]);
    if (persp !== "defender") {
      legend.push([null, "Attacker:"]);
      if (persp === "attacker") {
        legend.push(...Object.values(ATTACKER_STYLE).map(v => [v.stroke, v.label]), [STATE_STYLE.unknown.stroke, "not tried"]);
        legend.push([null, ov.redTree ? "the tree it built by its own reconnaissance" : "the tree it was handed (or the red console's steps)"]);
      } else legend.push(["var(--critical)", "red strip on a step: the attacker did it (dashed: tried and failed, or aims at it)"],
        ["var(--critical)", "red link: the path the attack took"]);
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
  // The page's helpers (h, svg, $, num, dur, rel, pretty) are globals by the time
  // this factory runs; the ones that need the page's state come in as ui.
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
      note: { html: "detected by rules / by model: how long after the first malicious write each detector reported; "
                  + "<b>*</b> = only after the plant had already left its normal band; <b>missed</b> = never." },
      columns: [
        { label: "detected by rules", attrs: { class: "num", title: `The Modbus policy rules: ${LATENCY_HINT}` } },
        { label: "detected by model", attrs: { class: "num", title: `The learned traffic model: ${LATENCY_HINT}` } },
        { label: "impact on the plant", attrs: { title: "none: the voltages stayed in band · recovered: they left it and came back, after that long · persists: still out of band when the attack ended" } },
        { label: "false alarms", attrs: { class: "num", title: "Findings during normal operation, with no attack to explain them" } },
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
    if (fid) out.push(chip("score · tree fidelity", `precision ${num(fid.precision, 2)} · recall ${num(fid.recall, 2)}`));
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
    if (r.threshold != null) $("d-sub").textContent += ` · learned model reports above an anomaly score of ${r.threshold}`;
    $("f-title").textContent = "Findings";
    $("f-sub").textContent = "What the sensors reported so far, by detector and by class of what they saw (live during the run).";
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
      // A model that could not be fitted detects nothing: "0 findings" would read as "nothing to find".
      ...(sides(r).blue.modelErrors.filter(mine).length ? [chip("model", "not fitted", "var(--critical)")] : []),
      ...scoreChips(r.metrics),
    );
    drawChart(r);
    const agg = {};
    // Every feeder's findings, each feeder on its own rows: the table is the whole run's.
    const many = several(r);
    for (const f of r.findings) { const k = `${f.detector}|${f.klass}|${many ? f.unit ?? "" : ""}`; (agg[k] = agg[k] || { d: f.detector, k: f.klass, u: f.unit, n: 0, first: f.t }).n++; }
    const rows = Object.values(agg).sort((a, b) => a.first - b.first).map(a =>
      h("tr", {}, h("td", {}, UI.term(a.d)), h("td", {}, UI.term(a.k)), many ? h("td", {}, a.u != null ? `unit ${a.u}` : "—") : null,
        h("td", { class: "num" }, String(a.n)),
        h("td", { class: "num" }, r.start_t ? rel(a.first, r.start_t) : "—")));
    $("d-findings").replaceChildren(h("thead", {}, h("tr", {},
        th("detector", "Which sensor reported: the Modbus policy rules, the learned traffic model, or the host sensor on the IT side"),
        th("class", "What kind of thing it saw; hover for the name it is recorded under"),
        many ? th("feeder", "The feeder (Modbus unit) the finding concerns") : null,
        th("count", "How many findings of this detector and class", true), th("first, since run start", "When the first of them came, counted from the start of the run", true))),
      h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: many ? 5 : 4, class: "empty" },
        reused(r) || (r.start_t ? "No findings: the sensors have reported nothing in this run" : "No findings: this run has not started")))));
  }

  // The campaign aggregate (metrics.write_aggregate): detection per mode and
  // detector, physical impact per mode.
  const RESULT_TABS = [{ id: "detection", label: "Detection" }, { id: "impact", label: "Physical impact" },
    { id: "response", label: "Response" }, { id: "countermeasures", label: "Countermeasures" }];
  const RESULT_EMPTY = {
    response: "No run of this campaign had a response policy: the defender only watched.",
    countermeasures: "No countermeasure was timed in this campaign: none was applied, or the runs had no response policy.",
  };
  function results(tab, a, tb) {
    const n = c => h("td", { class: "num" }, c == null ? "—" : String(num(c)));
    const data = a[tab];
    if (!data || !data.length) { tb.replaceChildren(h("tbody", {}, h("tr", {}, h("td", { class: "empty" }, RESULT_EMPTY[tab] || "No scored runs yet")))); return; }
    const cols = (heads, cells) => tb.replaceChildren(
      h("thead", {}, h("tr", {}, heads.map(([label, help, text]) => h("th", { class: text ? null : "num", title: help || null }, label)))),
      h("tbody", {}, data.map(r => h("tr", {}, cells(r)))));
    if (tab === "response") {
      cols([["mode", "The attack (or normal operation) the runs were under", true], ["policy", "The response policy that decided", true],
        ["runs", "Scored runs with a response policy"],
        ["accurate (share of runs)", "Runs where the response did what the attack called for"],
        ["over-response (runs)", "Runs where it also did something the attack did not call for"],
        ["decision latency, median (s)", "From the first finding to the first countermeasure done"],
        ["explained (share of decisions)", "Decisions that came with the policy's own justification"],
        ["attacker writes after the block, median", "Malicious writes the plant still accepted once a blocking countermeasure was in force"],
        ["false responses", "Countermeasures run before the attack, or in a run with no attack"],
        ["runs with a failed action", "Runs where a countermeasure could not be carried out"],
        ["HMI unavailable, median (s)", "How long the response kept the operator's HMI cut off"]],
        r => [h("td", {}, r.mode), h("td", {}, r.policy), n(r.runs), n(r.accuracy), n(r.over_response_runs), n(r.decision_latency_median_s),
          n(r.explained_coverage), n(r.attacker_writes_after_block_median), n(r.false_responses), n(r.failed_action_runs), n(r.hmi_unavailable_median_s)]);
    } else if (tab === "countermeasures") {
      cols([["countermeasure", "The countermeasure, by its id in the attack tree", true], ["runs", "Runs in which it was applied"],
        ["dispatch, median (s)", "From the request for the countermeasure to its outcome on the host that runs it"],
        ["runs that settled", "Runs in which it was the last restoring countermeasure and the plant came back into its band"],
        ["settle, median (s)", "In those runs, from the countermeasure done to the plant back in its band"]],
        r => [h("td", {}, r.countermeasure), n(r.runs), n(r.dispatch_median_s), n(r.settle_runs), n(r.settle_median_s)]);
    } else if (tab === "detection") {
      const head = h("tr", {}, ...["mode", "detector", "runs"].map(x => h("th", {}, x)),
        ...["detection rate", "latency median (s)", "min–max (s)", "before impact", "false alarms (runs)", "…in operator windows"].map(x => h("th", { class: "num" }, x)));
      const rows = data.map(r => h("tr", {}, h("td", {}, r.mode), h("td", {}, UI.term(r.detector)), n(r.runs),
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
  let chartKey = null;
  // Why a run has nothing live to show, when the reason is that it was not run again.
  const reused = r => r.status === "skipped"
    ? "This run was not run again: its score was reused from an earlier attempt of the campaign, so this ledger has its result but not its events." : null;
  // The run's time axis, shared by its charts: seconds since run start. A live
  // run is laid on its whole planned length (a stable axis that fills up), a
  // finished one on what happened.
  function runSpan(r, times) {
    const t0 = r.start_t, tEnd = Math.max(t0 + 10, ...times, ...r.phases.map(p => p.end_t || 0));
    const plannedEnd = t0 + r.phases.reduce((a, p) => a + (p.planned_s || 0), 0);
    return (r.status === "running" ? Math.max(tEnd, plannedEnd) : tEnd) - t0;
  }
  function drawChart(r) {
    const box = $("d-chart");
    const unit = r ? shownUnit(r) : null;
    const key = r ? [r.id, r.start_t, r.status, r.plant.length, r.findings.length, r.writes.length, box.clientWidth, unit ?? ""].join("|") : "none";
    if (key === chartKey) return;            // unchanged: keep the frame (and a live tooltip)
    chartKey = key;
    box.querySelector("svg")?.remove();
    box.querySelector(".empty")?.remove();
    const legend = $("d-legend"); legend.replaceChildren();
    if (!r || !r.plant.length) {
      box.append(h("div", { class: "empty" }, !r ? "Select a run to see its plant." : reused(r) || (r.status === "running"
        ? "Waiting for the first plant sample: the plant is polled once the lab is up." : "This run recorded no plant sample.")));
      return;
    }
    // The plant's normal band, from the run; a run recorded without one had the default plant's.
    const band = r.info?.v_band || [0.95, 1.05];
    // The feeder on show: its samples, and the writes and findings that concern it.
    const t0 = r.start_t, pts = plantOf(r, unit).map(p => ({ ...p, x: p.t - t0 }));
    const writes = r.writes.filter(onUnit(unit)), findings = r.findings.filter(onUnit(unit));
    const xMax = runSpan(r, [pts[pts.length - 1].t]);
    // The axis holds every sample and the whole band: nothing is clipped, and
    // the band is in sight even when the voltages never leave it.
    const vs = pts.flatMap(p => [p.v_load, p.v_dg]).filter(v => v != null && isFinite(v));
    const lo = Math.min(band[0] - 0.02, ...vs), hi = Math.max(band[1] + 0.02, ...vs);
    legend.append(
      ...(unit != null ? [h("span", {}, h("b", {}, `feeder unit ${unit}`))] : []),
      h("span", { title: "Voltage at the bus feeding the load, as a fraction of its nominal value" }, h("span", { class: "lk", style: "background:var(--s1)" }), "load-bus voltage"),
      h("span", { title: "Voltage at the bus of the distributed generator (DG), as a fraction of its nominal value" }, h("span", { class: "lk", style: "background:var(--s2)" }), "DG-bus voltage"),
      h("span", { title: "Inside this band the plant is normal; outside it, the run counts a physical impact" },
        h("span", { class: "lk", style: "background:var(--wash);height:8px;border:1px solid var(--axis)" }), `normal band ${band[0]}–${band[1]} pu`),
      h("span", { class: "muted", title: "pu (per unit): a voltage as a fraction of its nominal value; 1.05 pu is 5 % above nominal" }, "pu = fraction of nominal"));
    // The run's turning points: the attack, and each detector's first finding after it.
    const w0 = writes[0]?.t, events = [];
    if (w0 != null) events.push({ x: w0 - t0, label: "attack: first malicious write", dash: "4 3" });
    for (const d of ["rules", "model"]) {
      const f = findings.find(f => f.detector === d && (w0 == null || f.t >= w0 - 1));
      if (f) events.push({ x: f.t - t0, label: `first finding: ${UI.termText(d)}`, dash: null });
    }
    events.sort((a, b) => a.x - b.x).forEach((e, i) => { e.row = i; });
    const np = r.phases.find(p => p.name === "normal");
    const learn = np?.start_t && r.learn_s ? [{ x1: np.start_t - t0, x2: Math.min(np.start_t - t0 + r.learn_s, xMax) }] : [];
    const last = pts[pts.length - 1];
    const state = p => `${p.ctrl_mode === 1 ? "MANUAL control" : "automatic control"} · ${p.abnormal ? "out of the normal band" : "in the normal band"}`;
    const told = p => [`${UI.rel(p.t, t0)} since run start`,
      `load bus ${num(p.v_load)} pu · DG bus ${num(p.v_dg)} pu`,
      `DG setpoint ${num(p.dg_setpoint, 1)} kW${p.p_dg != null ? ` · DG output ${num(p.p_dg, 1)} kW` : ""}`,
      ...(p.line_load != null ? [`line loading ${num(p.line_load, 1)} %`] : []), state(p)].join("\n");
    const chart = UI.plot({
      width: Math.max(320, box.clientWidth || 600), height: 250, marginLeft: 48, marginRight: 64, marginBottom: 38,
      ariaLabel: `Bus voltages for ${r.id}${unit != null ? `, feeder unit ${unit}` : ""}`,
      x: { domain: [0, xMax], ...UI.timeAxis(xMax, "run start") },
      y: { domain: [lo, hi], nice: true, grid: true, label: "voltage (pu)", labelArrow: "none", tickFormat: v => v.toFixed(2) },
      marks: [
        Plot.rect(learn, { x1: "x1", x2: "x2", y1: () => lo, y2: () => hi, fill: "var(--wash)" }),
        Plot.text(learn, { x: "x1", text: () => "learned model is being fitted", frameAnchor: "bottom-left", dx: 4, dy: -4, fill: "var(--muted)", textAnchor: "start" }),
        Plot.rect([band], { x1: () => 0, x2: () => xMax, y1: d => d[0], y2: d => d[1], fill: "var(--wash)", stroke: "var(--axis)", strokeOpacity: 0.6 }),
        // One rule per turning point, its label stacked under the one before it.
        ...events.flatMap(e => [Plot.ruleX([e.x], { stroke: "var(--ink-2)", strokeDasharray: e.dash }),
          Plot.text([e], { x: "x", text: "label", frameAnchor: "top", dx: 5, dy: 4 + e.row * 13, textAnchor: "start",
            fill: "var(--ink-2)", stroke: "var(--surface)", strokeWidth: 3 })]),
        Plot.lineY(pts, { x: "x", y: "v_load", stroke: "var(--s1)", strokeWidth: 2 }),
        Plot.lineY(pts, { x: "x", y: "v_dg", stroke: "var(--s2)", strokeWidth: 2 }),
        // Each line named at its end, so that it is not told apart by colour alone.
        Plot.text([last], { x: "x", y: "v_load", text: () => "load", dx: 6, dy: last.v_load >= last.v_dg ? -5 : 5, textAnchor: "start", fill: "var(--ink-2)" }),
        Plot.text([last], { x: "x", y: "v_dg", text: () => "DG", dx: 6, dy: last.v_dg > last.v_load ? -5 : 5, textAnchor: "start", fill: "var(--ink-2)" }),
        // The sample under the pointer: a hairline, both readings, and what the plant recorded then.
        Plot.ruleX(pts, Plot.pointerX({ x: "x", stroke: "var(--ink)", strokeWidth: 1 })),
        Plot.dot(pts, Plot.pointerX({ x: "x", y: "v_load", r: 4, fill: "var(--s1)", stroke: "var(--surface)", strokeWidth: 2 })),
        Plot.dot(pts, Plot.pointerX({ x: "x", y: "v_dg", r: 4, fill: "var(--s2)", stroke: "var(--surface)", strokeWidth: 2 })),
        UI.plotTip(pts, { x: "x", y: "v_load", title: told }),
      ],
    });
    box.append(chart);
  }
  // ── the two sides of the run ──────────────────────────────────────────────
  // Folded from the ledger into run.x by reduce(): what the attacker recorded
  // (its agent, its recon, or the people at the red console) and the defender
  // events the page does not keep itself.
  function sides(r) {
    if (!r.x.red) Object.assign(r.x, {
      red: { start: null, plans: [], steps: [], recon: [], belief: null, end: null },
      blue: { alerts: [], respWrites: [], modelErrors: [] },
    });
    return r.x;
  }
  // Like the page's own reducer, each fact is the event whole with `t` the time
  // it happened: a view reads whatever the ledger recorded, and only the fields
  // the views name differently, or default, are spelled out. Answers true for a
  // kind it folds, so the page knows the event is shown somewhere.
  function reduce(r, ev) {
    const x = sides(r), f = { ...ev, t: ev.guest_t || ev.t };
    switch (ev.kind) {
      case "attack_start": x.red.start = f; break;
      case "attack_plan": x.red.plans.push({ ...f, sequence: ev.sequence || [], candidates: ev.candidates || [], blocked: ev.blocked || [] }); break;
      case "plan_step": x.red.steps.push({ ...f, ok: !!ev.ok, observed: ev.observed || {}, by: "agent" }); break;
      case "red_step": x.red.steps.push({ ...f, node: ev.step, stage: ev.stage || ev.step, ok: !!ev.ok,
        observed: ev.observed || {}, by: ev.operator || "red team" }); break;
      case "recon": x.red.recon.push({ ...f, hosts: ev.hosts || [], registers: ev.registers || null }); break;
      case "attacker_belief": x.red.belief = f; break;
      case "attack_end": x.red.end = { ...f, success: !!ev.success }; break;
      case "alert": x.blue.alerts.push(f); break;
      case "response_write": x.blue.respWrites.push(f); break;
      case "model_error": x.blue.modelErrors.push(f); break;
      default: return false;
    }
    return true;
  }
  // The countermeasures in force at a time: applied and not reverted since. An
  // action that failed changes nothing. Ledgers without `op` only ever applied.
  function inForce(actions) {
    const on = {};
    for (const a of [...actions].sort((p, q) => p.t - q.t)) {
      if (!a.ok || a.id === "notify") continue;
      if (a.op === "revert") delete on[a.id]; else if (!(a.id in on)) on[a.id] = a.t;
    }
    return on;
  }
  const didWhat = a => a.op === "revert" ? (a.ok ? "reverted" : "revert failed") : (a.ok ? "applied" : "failed");

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
    for (const a of x.blue.alerts.filter(u)) { const k = `${UI.termText(a.detector)}: ${pretty(a.klass)}${where(r, a)}`; if (a.state === "cleared") delete open[k]; else open[k] = a; }
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
    steps: "Each step it ran, with how its last try went: ✓ worked · ✗ failed (a countermeasure closed the path, or the step itself failed). Times are counted from the start of the attack. Click a step to show the run at its last try; hover it for its ATT&CK technique",
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
    believes: "What the defender believes of each step of the attack tree, by how sure it is: confirmed · inferred (implied by a later step it confirmed) · suspected. Belief runs from 0 to 1. Click a line to open or close its list",
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
    model: "The learned model could not be fitted on this run's normal phase, so it reports nothing (the journal has the reason)",
    "score · detection": "Detection latency from the first malicious write (green: before the physical impact)",
    "score · false alarms": "Findings with no attack to explain them",
    "score · attack reached": "The furthest stage of the attack that succeeded",
    "score · impact": "Whether the plant left its band, and whether and when it recovered",
    "score · response": "Whether the response did what this attack called for, and nothing it did not",
    "score · tree fidelity": "How close the attacker's own tree is to the real one, from 0 to 1. Precision: the share of the leaves it believes in that are real. Recall: the share of the real leaves it found",
    // kill chain
    "time to detect": "From the attacker's first step to the defender's first finding",
    "time to respond": "From the first finding to the first countermeasure that worked",
    "time to impact": "From the attacker's first step to the plant leaving its band",
    "who is ahead": "The furthest stage the attacker reached, against the furthest the defender has confirmed",
  };

  // This scenario's words, for the page (ui.metric, ui.term) and for the views
  // here: every metric of the campaign's mean [95% CI] table (metrics.CI_HEADLINE),
  // the detectors by what they are, and a run's mode as a sentence.
  const LABELS = {
    metrics: {
      "detectors.combined.detected": { label: "attack detected, by any detector", unit: "share of runs",
        help: "Runs in which at least one detector reported after the attack began" },
      "detectors.combined.latency_from_write_s": { label: "detection latency", unit: "s",
        help: "From the first malicious write to the first finding of any detector" },
      impact_duration_s: { label: "plant out of its normal band", unit: "s", help: "From the first abnormal plant sample to the last" },
      max_abs_deviation_pu: { label: "largest voltage deviation from nominal", unit: "pu",
        help: "pu (per unit): a voltage as a fraction of its nominal value; 0.05 pu is 5 %" },
      false_alarms: { label: "false alarms", unit: "findings", help: "Findings during normal operation, with no attack to explain them" },
      "response.accurate": { label: "response accurate", unit: "share of runs",
        help: "Runs in which every countermeasure the attack called for was applied" },
      mitigated_s: { label: "time to mitigation", unit: "s",
        help: "From the first malicious write to the plant back in its band for good; no value while the impact persists" },
    },
    terms: {
      rules: "rules (Modbus policy)", model: "learned model", it: "IT host sensor", combined: "any detector",
      notify: "Alert the operator, no automatic action",
    },
    mode: mode => mode === "normal" ? "normal operation, no attack"
      : mode.startsWith("planner:") ? `attack by the planning agent (${mode.slice(8)} profile)`
      : mode.startsWith("recon:") ? `attack by the reconnaissance agent (${mode.slice(6)} profile)`
      : `scripted attack: ${mode}`,
  };
  // The names a run's own structure gives the nodes of its attack tree and its
  // countermeasures. `text` is the name alone; `el` shows it with the recorded
  // id on hover; `id` keeps the id (where space is short) with the name on hover.
  // Until the structure has loaded, an id is spelled out as words.
  function namer(r) {
    const st = UI.structure ? UI.structure(r) : null, T = st ? treeIndex(st.tree) : null;
    const label = id => (T && (T.nodes[id]?.label || T.cms[id]?.label)) || null;
    return {
      loaded: !!T, text: id => UI.termText(id, label(id)), el: (id, help) => UI.term(id, label(id), help),
      id: id => h("span", { class: "term", title: label(id) || LABELS.terms[id] || null }, id),
      list: (ids, sep = ", ") => ids.flatMap((id, i) => [i ? sep : null, UI.term(id, label(id))]),
    };
  }

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
  // A row that moves the run's time to its fact when clicked.
  const jump = t => ({ class: "click", tabindex: "0", title: "Show the run at this time",
    onclick: () => UI.setTime(t), onkeydown: e => { if (e.key === "Enter") UI.setTime(t); } });

  // One thing a line: a list of names set side by side cannot wrap between two
  // of them and runs out of its column, over the one beside it.
  const lines = items => h("div", { class: "lines" }, ...items.map(x => h("div", {}, x)));
  const tick = ok => h("span", { class: "tick", style: `color:${ok == null ? "var(--ink-2)" : ok ? "var(--good)" : "var(--critical)"}` }, ok == null ? "◎" : ok ? "✓" : "✗");
  const note = text => h("span", { class: "muted" }, text);
  // A list that folds under a line saying how many it holds. It stays open or
  // shut as the reader left it, across the redraws a live run causes.
  const folds = {};
  function fold(key, summary, body, open) {
    const d = h("details", { class: "fold", open: (folds[key] ?? open) ? "" : null }, h("summary", {}, summary), body);
    d.addEventListener("toggle", () => { folds[key] = d.open; });
    return d;
  }
  // A write to the plant in words, by the register it changes.
  const WRITE_WORDS = {
    ctrl_mode: v => `control switched to ${+v === 1 ? "MANUAL" : "automatic"}`,
    dg_setpoint: v => `DG setpoint set to ${num(+v, 1)} kW`,
    switch_cmd: v => `feeder breaker ${+v ? "opened" : "closed"}`,
  };
  const writeWords = (reg, v) => WRITE_WORDS[reg] ? WRITE_WORDS[reg](v) : `${pretty(reg)} set to ${v}`;

  function redDoing(v, N, r) {
    const R = v.red, lastStep = last(R.steps), t0 = t0Of(r, R);
    const status = R.end ? (R.end.success ? "Finished: it reached its impact on the plant" : `Stopped short of its impact: it got as far as ${R.end.stage_reached ? `"${N.text(R.end.stage_reached)}"` : "nothing"}`)
      : lastStep ? `${lastStep.ok ? "Just did" : "Just failed"}: ${N.text(lastStep.node)}`
      : R.start ? "Planning its first step" : R.writes.length ? "Writing to the plant" : null;
    // Each step once, with how its attempts went: a player tries a step many times.
    const byStep = new Map();
    for (const s of R.steps) {
      const e = byStep.get(s.node) || { node: s.node, tries: 0, worked: 0, attck: s.attck };
      byStep.set(s.node, Object.assign(e, { tries: e.tries + 1, worked: e.worked + (s.ok ? 1 : 0), ok: s.ok, t: s.t, by: s.by }));
    }
    const steps = [...byStep.values()].map(s => h("div", { ...jump(s.t), title: [`Show the run at this step's last attempt`, `recorded as: ${s.node}`,
        s.attck ? `ATT&CK ${s.attck}` : null, s.by !== "agent" ? `by ${s.by}` : null].filter(Boolean).join("\n") },
      tick(s.ok), N.text(s.node),
      note(s.tries === 1 ? ` — ${rel(s.t, t0)}`
        : s.worked === s.tries ? ` — done ${s.tries} times, last at ${rel(s.t, t0)}`
        : s.worked === 0 ? ` — failed ${s.tries} times, last at ${rel(s.t, t0)}`
        : ` — worked ${s.worked} of ${s.tries} times; the last try ${s.ok ? "worked" : "failed"}, at ${rel(s.t, t0)}`)));
    const byReg = {};
    for (const w of R.writes) { const k = w.register || "?"; (byReg[k] = byReg[k] || { n: 0, v: w.value, ok: 0 }).n++; byReg[k].v = w.value; if (w.ok !== false) byReg[k].ok++; }
    const writes = Object.entries(byReg).map(([k, w]) => h("div", { title: `register ${k}, last value ${w.v}` }, writeWords(k, w.v),
      note(` — ${w.n} write${w.n === 1 ? "" : "s"}${w.ok < w.n ? `, ${w.n - w.ok} refused by the plant` : ""}`)));
    return status || R.steps.length ? h("div", {}, status ? h("p", { class: "now" }, status) : null, kv([
      ["aims at", R.target ? h("span", {}, N.el(R.target), ...(R.remaining.length ? [note(" — still to do: "), ...N.list(R.remaining, " → ")] : [])) : null],
      ["steps", steps.length ? h("div", { class: "lines" }, ...steps) : null],
      ["writes", writes.length ? h("div", { class: "lines" }, ...writes) : null],
    ])) : none("No attack activity yet.");
  }
  function redKnows(v, N) {
    const R = v.red;
    const who = R.steps.map(s => s.observed?.whoami).find(Boolean);
    // `id` prints uid=0(root) gid=…: the user's name is what matters, the rest is on hover.
    const user = who ? (/uid=\d+\(([^)]+)\)/.exec(who) || [])[1] || who : null;
    const it = last(R.recon.filter(c => c.stage === "it")), ot = last(R.recon.filter(c => c.stage === "ot"));
    const pivot = last(R.steps.filter(s => s.node === "pivot"));
    const regs = ot && ot.registers ? Object.entries(ot.registers) : [];
    const countNodes = n => n ? 1 + (n.children || []).reduce((a, c) => a + countNodes(c), 0) : 0;
    const P = R.plan;
    return R.source || R.recon.length ? kv([
      ["knowledge", R.source],
      ["hosts found", it ? lines(it.hosts.map(x => `${x.ip}, open ports ${(x.ports || []).map(p => p.port ?? p).join(", ") || "none"}`)) : null],
      ["foothold", user ? h("span", { class: "term", title: `as its own command reported: ${who}` }, `runs as ${user}${it?.foothold ? ` on ${it.foothold.ip ?? it.foothold}` : ""}`)
        : (it?.foothold ? `${it.foothold.ip ?? it.foothold}` : null)],
      ["plant reached", ot ? `${ot.engine_ip}:${ot.modbus_port} — its Modbus server ${ot.modbus_ok ? "answers" : "does not answer"}`
        : pivot ? h("span", { class: pivot.observed?.detail ? "term" : null, title: pivot.observed?.detail ? `what its last try printed: ${pivot.observed.detail}` : null },
          pivot.ok ? "yes, through the HMI" : "no: its last try through the HMI failed") : null],
      ["registers read", regs.length ? regs.slice(0, 6).map(([a, x]) => `${a}=${x}`).join(" · ") + (regs.length > 6 ? ` … (${regs.length})` : "") : null],
      ["its belief", R.belief ? `a tree of ${countNodes(R.belief.tree)} nodes` : null],
      ["options", P && P.candidates.length ? lines(P.candidates.map(c => [N.el(c.node), note(c.impact != null ? ` — impact weight ${c.impact}` : "")])) : null],
      ["paths closed", P && P.blocked.length ? lines(P.blocked.map(id => N.el(id))) : null],
    ]) : none("Nothing yet.");
  }
  function blueDoing(v, r, N) {
    const B = v.blue, policy = r.respond && r.respond !== "off" ? r.respond : (B.decisions[0]?.policy || null);
    const advise = Object.keys(r.approvals).length > 0, d = last(B.decisions), cms = {};
    for (const a of B.actions) if (a.id !== "notify") cms[a.id] = a;
    const pending = B.approvals.filter(a => a.state === "requested");
    const inForce = Object.values(cms).filter(a => a.ok && a.op !== "revert").length;
    const status = !policy ? "Watching only: this run has no response policy"
      : pending.length ? `Waiting for its operator on ${pending.length} suggestion${pending.length === 1 ? "" : "s"}`
      : inForce ? `${inForce} countermeasure${inForce === 1 ? "" : "s"} in force`
      : d ? "Has decided, nothing in force yet" : "Nothing to respond to yet";
    return h("div", {}, h("p", { class: "now" }, status), kv([
      ["response", policy ? `${policy} policy${advise ? ", suggesting to an operator" : ", acting on its own"}` : null],
      ["last decision", d ? h("div", { class: "lines" },
        ...(d.actions.length ? d.actions.map(id => h("div", {}, N.el(id))) : [h("div", {}, "no action")]),
        d.trigger_klass ? h("div", {}, note(`after the finding "${pretty(d.trigger_klass)}", ${rel(d.t, r.start_t)} since run start`)) : null,
        d.rationale ? fold("why", "why (the policy's own words)", h("div", { class: "muted" }, d.rationale), false) : null) : (policy ? "none yet" : null)],
      // Each countermeasure by its latest action: in force, reverted since, or failed.
      ["countermeasures", Object.keys(cms).length ? lines(Object.values(cms).map(a => [
        a.op === "revert" && a.ok ? h("span", { class: "tick muted" }, "↩") : tick(a.ok),
        N.el(a.id), note(`${a.machine ? ` — on ${a.machine}` : ""}${a.op === "revert" ? `, ${didWhat(a)}: no longer in force` : a.ok ? "" : ", failed"}`)])) : null],
      ["awaiting operator", pending.length ? lines(pending.map(a => [h("span", { class: "tick" }, "⏳"), N.el(a.action)])) : null],
      ["plant writes", B.respWrites.length ? `${B.respWrites.length} write${B.respWrites.length === 1 ? "" : "s"} to put the plant back` : null],
    ]));
  }
  function blueSees(v, r, N) {
    const B = v.blue, byDet = {};
    for (const f of B.findings) byDet[f.detector] = (byDet[f.detector] || 0) + 1;
    const lf = last(B.findings);
    const nodes = Object.entries(B.st?.nodes || {}).filter(([, s]) => s[0] in STATE_RANK)
      .sort((a, b) => STATE_RANK[a[1][0]] - STATE_RANK[b[1][0]] || b[1][1] - a[1][1]);
    // What it believes of the attack tree, by how sure it is: the steps it has
    // confirmed in sight, the rest one click away.
    const believed = Object.keys(STATE_RANK).map(state => [state, nodes.filter(([, s]) => s[0] === state)]).filter(([, list]) => list.length)
      .map(([state, list]) => fold(`belief-${state}`, [h("span", { class: "dot", style: `background:${STATE_STYLE[state].stroke};margin-right:6px` }),
        `${state}: ${list.length} step${list.length === 1 ? "" : "s"}`],
        lines(list.map(([id, s]) => [N.el(id), note(` — belief ${num(s[1], 2)}`)])), state === "confirmed"));
    const next = B.st?.next || [];
    return B.findings.length || nodes.length ? kv([
      ["findings", lines(Object.entries(byDet).map(([k, n]) => [UI.termText(k), note(` — ${n}`)]))],
      ["latest", lf ? `${pretty(lf.klass)}${lf.src ? ` from ${lf.src}` : ""}${lf.unit != null ? ` on unit ${lf.unit}` : ""}${lf.maps_to ? ` — points to the step "${N.text(lf.maps_to)}"` : ""}` : null],
      ["alerts open", B.open.length ? lines(B.open) : null],
      ["believes", believed.length ? h("div", {}, ...believed) : null],
      ["expects next", next.length ? fold("next", `${next.length} step${next.length === 1 ? "" : "s"} the attacker could take next`, lines(next.map(id => N.el(id))), false) : null],
      ["hosts implicated", B.st?.hosts?.length ? B.st.hosts.join(" · ") : null],
      ["model threshold", r.threshold != null ? `${r.threshold} (anomaly score, no unit)` : null],
    ]) : none("Nothing observed yet.");
  }

  const side = (who, label, parts) => h("div", { class: `side ${who}` },
    h("b", { style: `color:${who === "red" ? "var(--critical)" : "var(--s1)"}` }, label),
    ...parts.flatMap(([title, body]) => [h("h3", {}, title), body]));

  // One lane per side and one for the plant, on the run's timeline; the
  // vertical line is the time shown. A mark is a fact: click it to go there.
  const LANE_KEY = {
    attacker: [["●", "var(--critical)", "attack step done", "done"], ["✕", "var(--critical)", "attack step failed", "failed"], ["|", "var(--critical)", "write to the plant", "write"]],
    defender: [["▲", "var(--s1)", "finding", "finding"], ["◇", "var(--s1)", "decision", "decision"], ["■", "var(--good)", "countermeasure applied", "action var(--good)"],
      ["□", "var(--good)", "countermeasure reverted", "revert var(--good)"], ["■", "var(--critical)", "countermeasure failed", "action var(--critical)"]],
    plant: [["▬", "var(--critical)", "voltages out of the normal band", "band"], ["┅", "var(--warning)", "control in MANUAL", "manual"]],
  };
  function drawLanes(box, r, t, lanes) {
    box.replaceChildren();
    if (!r.start_t) { box.append(UI.empty(reused(r) || "This run has not started: there is no timeline yet.")); return; }
    const x = sides(r), red = x.red, t0 = r.start_t, N = namer(r);
    // Every fact as a point of its lane, with the sentence its tooltip says.
    const fact = (lane, e, shape, colour, text) => ({ lane, x: e.t - t0, t: e.t, shape, colour, text });
    const facts = [];
    if (lanes.includes("attacker")) {
      for (const w of r.writes) facts.push(fact("attacker", w, "write", "var(--critical)", `write to the plant: ${w.register} = ${w.value}${where(r, w)}${w.ok === false ? " (refused)" : ""}`));
      for (const st of red.steps) facts.push(fact("attacker", st, st.ok ? "done" : "failed", "var(--critical)", `attack step ${st.ok ? "done" : "failed"}: ${N.text(st.node)}`));
    }
    if (lanes.includes("defender")) {
      for (const f of r.findings) facts.push(fact("defender", f, "finding", "var(--s1)", `finding by ${UI.termText(f.detector)}: ${pretty(f.klass)}${where(r, f)}`));
      for (const d of r.decisions) facts.push(fact("defender", d, "decision", "var(--s1)", `decision: ${d.actions.map(N.text).join(", ") || "no action"}`));
      for (const a of r.actions) if (a.id !== "notify")
        facts.push(fact("defender", a, a.op === "revert" ? "revert" : "action", a.ok ? "var(--good)" : "var(--critical)", `countermeasure ${didWhat(a)}: ${N.text(a.id)}`));
    }
    // Every feeder's spans on the one lane: each says which feeder it is.
    const bands = [], manual = [];
    if (lanes.includes("plant")) for (const [, plant, name] of feeders(r)) {
      for (const [a, b] of spans(plant, p => p.abnormal)) bands.push({ lane: "plant", x1: a - t0, x2: Math.max(b - t0, a - t0 + 0.5), x: a - t0, t: a, text: `voltages out of the normal band${name}, for ${num(b - a, 1)} s` });
      for (const [a, b] of spans(plant, p => p.ctrl_mode === 1)) manual.push({ lane: "plant", x1: a - t0, x2: b - t0, x: a - t0, t: a, text: `control in MANUAL${name}, for ${num(b - a, 1)} s` });
    }
    const xMax = runSpan(r, [...facts, ...bands, ...manual].map(e => e.t).concat(r.plant.map(p => p.t)));
    const of = shape => facts.filter(f => f.shape === shape);
    const point = [...facts, ...bands, ...manual];
    const chart = UI.plot({
      width: Math.max(320, box.clientWidth || 600), height: 44 + lanes.length * 28, marginLeft: 70, marginRight: 14, marginBottom: 36, marginTop: 6,
      ariaLabel: `Timeline of ${lanes.join(", ")} for ${r.id}`,
      x: { domain: [0, xMax], ...UI.timeAxis(xMax, "run start") },
      y: { domain: lanes, label: null, tickSize: 0, padding: 0.3 },
      marks: [
        Plot.ruleY(lanes, { stroke: "var(--grid)" }),
        Plot.barX(bands, { x1: "x1", x2: "x2", y: "lane", fill: "var(--critical)", fillOpacity: 0.45, insetTop: 2, insetBottom: 2 }),
        Plot.ruleY(manual, { x1: "x1", x2: "x2", y: "lane", stroke: "var(--warning)", strokeWidth: 2, strokeDasharray: "4 3", dy: -9 }),
        Plot.tickX(of("write"), { x: "x", y: "lane", stroke: "var(--critical)", strokeOpacity: 0.5, strokeWidth: 2 }),
        Plot.dot(of("finding"), { x: "x", y: "lane", symbol: "triangle", r: 4, fill: "var(--s1)", fillOpacity: 0.6 }),
        Plot.dot(of("done"), { x: "x", y: "lane", r: 5, fill: "var(--critical)", stroke: "var(--surface)", strokeWidth: 1 }),
        Plot.dot(of("failed"), { x: "x", y: "lane", symbol: "times", r: 5, stroke: "var(--critical)", strokeWidth: 2.5 }),
        Plot.dot(of("decision"), { x: "x", y: "lane", symbol: "diamond", r: 6, fill: "var(--surface)", stroke: "var(--s1)", strokeWidth: 2 }),
        // A countermeasure, by how it went; a revert is the same square, hollow: no longer in force.
        ...["var(--good)", "var(--critical)"].flatMap(colour => [
          Plot.dot(of("action").filter(f => f.colour === colour), { x: "x", y: "lane", symbol: "square", r: 5, fill: colour, stroke: "var(--surface)", strokeWidth: 1 }),
          Plot.dot(of("revert").filter(f => f.colour === colour), { x: "x", y: "lane", symbol: "square", r: 5, fill: "var(--surface)", stroke: colour, strokeWidth: 2 })]),
        ...(t != null ? [Plot.ruleX([t - t0], { stroke: "var(--ink)", strokeWidth: 1.5 })] : []),
        // The fact nearest the pointer: ringed, and said in words.
        Plot.dot(point, Plot.pointer({ x: "x", y: "lane", r: 9, stroke: "var(--ink)", strokeWidth: 1.5 })),
        UI.plotTip(point, { near: true, x: "x", y: "lane", title: e => `${e.text}\n${UI.rel(e.t, t0)} since run start — click to show the run at this time` }),
      ],
    });
    // Plot keeps the fact under the pointer as the chart's value.
    chart.style.cursor = "pointer";
    chart.addEventListener("click", () => { if (chart.value) UI.setTime(chart.value.t); });
    // The legend names the marks this timeline has, not every mark there could be.
    const drawn = new Set([...facts.map(f => f.shape), ...facts.map(f => `${f.shape} ${f.colour}`), ...(bands.length ? ["band"] : []), ...(manual.length ? ["manual"] : [])]);
    box.append(chart, h("div", { class: "legend" }, ...lanes.flatMap(lane => LANE_KEY[lane].filter(([, , , kind]) => drawn.has(kind)).map(([mark, colour, label]) =>
      h("span", {}, h("span", { style: `color:${colour};font-weight:700` }, mark), label))),
      ...(point.length ? [h("span", { class: "muted" }, "click a mark to show the run at that time")] : [h("span", { class: "muted" }, "nothing has happened yet on these lanes")])));
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
          const act = B.actions.find(x => x.id === a && x.ok && x.op !== "revert" && x.t >= d.t - 1e-3);
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
    const c0 = f0 == null ? null : B.actions.find(a => a.ok && a.op !== "revert" && a.id !== "notify" && a.t >= f0)?.t ?? null;
    const p0 = a0 == null ? null : r.plant.filter(uptoT(t)).find(p => p.abnormal && p.t >= a0)?.t ?? null;
    const reached = Math.max(-1, ...R.steps.filter(s => s.ok).map(s => stageIndex(s.node)));
    const seen = Math.max(-1, ...Object.entries(B.st?.nodes || {}).filter(([, s]) => s[0] === "confirmed").map(([n]) => stageIndex(n)));
    const N = namer(r);
    const nameOf = i => i < 0 ? "nothing" : i < STAGES.length ? `"${N.text(STAGES[i])}"` : "the impact on the plant";
    const ahead = a0 == null ? "no attack yet" : reached > seen ? `attacker: it reached ${nameOf(reached)}, the defender has confirmed ${nameOf(seen)}`
      : `defender: it has confirmed ${nameOf(seen)}`;
    const kpi = (k, val, dot) => chip(k, val, dot);
    const span = x => x == null ? "—" : `${num(x, 2)} s`;
    const kpis = h("div", { class: "chips" },
      kpi("time to detect", a0 == null ? "no attack yet" : f0 == null ? "not detected" : span(f0 - a0), a0 == null ? null : f0 == null ? "var(--critical)" : "var(--s1)"),
      kpi("time to respond", f0 == null ? "nothing found yet" : c0 == null ? "no countermeasure yet" : span(c0 - f0), c0 == null ? null : "var(--good)"),
      kpi("time to impact", a0 == null ? "no attack yet" : (p0 == null ? "plant not affected" : span(p0 - a0)), a0 == null ? null : p0 == null ? "var(--good)" : "var(--critical)"),
      kpi("who is ahead", ahead, a0 == null ? null : reached > seen ? "var(--critical)" : "var(--s1)"));
    if (reused(r)) { box.replaceChildren(none(reused(r))); return; }
    if (!rows.length) { box.replaceChildren(kpis, none("No attack step yet: each row will compare when the attacker did a step with when the defender saw it.")); return; }
    // Every step on one axis, counted from the start of the attack: when the
    // attacker did it, when the defender suspected and confirmed it, and when
    // a countermeasure covering it was applied.
    const short = n => clip(N.text(n), 38);
    const at = (x, n, v, kind, text) => v == null ? [] : [{ step: short(x.n), x: v - t0, t: v, kind, text: `${N.text(x.n)}\n${text} ${rel(v, t0)} since attack start` }];
    const facts = rows.flatMap(x => [...at(x, x.n, x.did, "did", "the attacker did it"), ...at(x, x.n, x.failed, "failed", "the attacker tried and failed"),
      ...at(x, x.n, x.sus, "suspected", "the defender first suspected it"), ...at(x, x.n, x.conf, "confirmed", "the defender confirmed it"),
      ...(x.c ? at(x, x.n, x.c.t, "countered", `countered by "${N.text(x.c.id)}", applied`) : [])]);
    const lo = Math.min(0, ...facts.map(f => f.x)), hi = Math.max(lo + 1, ...facts.map(f => f.x), t == null ? -Infinity : t - t0);
    const kind = k => facts.filter(f => f.kind === k);
    const timeline = h("div", { class: "lanes" });
    queueMicrotask(() => {
      const chart = UI.plot({
        width: Math.max(360, box.clientWidth || 700), height: 46 + rows.length * 26, marginLeft: 250, marginRight: 16, marginBottom: 36, marginTop: 6,
        ariaLabel: `Kill chain of ${r.id}: each attack step against the defender's view of it`,
        x: { domain: [lo, hi], ...UI.timeAxis(hi - lo, "attack start") },
        y: { domain: rows.map(x => short(x.n)), label: null, tickSize: 0, padding: 0.3 },
        marks: [
          Plot.ruleY(rows.map(x => short(x.n)), { stroke: "var(--grid)" }),
          Plot.dot(kind("suspected"), { x: "x", y: "step", symbol: "triangle", r: 5, fill: "var(--s1)", fillOpacity: 0.7 }),
          Plot.dot(kind("confirmed"), { x: "x", y: "step", symbol: "diamond", r: 6, fill: "var(--s1)", stroke: "var(--surface)", strokeWidth: 1 }),
          Plot.dot(kind("countered"), { x: "x", y: "step", symbol: "square", r: 5, fill: "var(--good)", stroke: "var(--surface)", strokeWidth: 1 }),
          Plot.dot(kind("did"), { x: "x", y: "step", r: 5, fill: "var(--critical)", stroke: "var(--surface)", strokeWidth: 1 }),
          Plot.dot(kind("failed"), { x: "x", y: "step", symbol: "times", r: 5, stroke: "var(--critical)", strokeWidth: 2.5 }),
          ...(t != null ? [Plot.ruleX([t - t0], { stroke: "var(--ink)", strokeWidth: 1.5 })] : []),
          Plot.dot(facts, Plot.pointer({ x: "x", y: "step", r: 9, stroke: "var(--ink)", strokeWidth: 1.5 })),
          UI.plotTip(facts, { near: true, x: "x", y: "step", title: "text" }),
        ],
      });
      chart.style.cursor = "pointer";
      chart.addEventListener("click", () => { if (chart.value) UI.setTime(chart.value.t); });
      timeline.replaceChildren(chart);
    });
    const lag = x => { const a = x.did ?? x.failed; return a == null || x.sus == null ? "—" : rel(x.sus, a); };
    const SINCE = "counted from the start of the attack";
    const key = (mark, colour, label) => h("span", {}, h("span", { style: `color:${colour};font-weight:700` }, mark), label);
    box.replaceChildren(kpis,
      h("p", { class: "sub", style: "margin:6px 0" }, "Times are counted from the start of the attack: the attacker's first step, or its first write to the plant."),
      timeline,
      h("div", { class: "legend" }, key("●", "var(--critical)", "the attacker did the step"), key("✕", "var(--critical)", "tried and failed"),
        key("▲", "var(--s1)", "the defender suspected it"), key("◆", "var(--s1)", "confirmed it"), key("■", "var(--good)", "a countermeasure covering it was applied")),
      table([th("attack step", "A step of the attack tree the attacker ran, or the defender has an opinion on; hover for the name it is recorded under"),
        th("attacker did it", `When the attacker did the step, ${SINCE}; ✗ when it tried and failed`, true),
        th("defender suspected", `When the defender first believed the step possible, ${SINCE}`, true),
        th("defender confirmed", `When the defender was first sure of it, ${SINCE}`, true),
        th("suspected after", "How long after the attacker's step the defender first suspected it. Negative: the defender expected the step before the attacker got to it", true),
        th("countered by", `The first countermeasure that covered the step and was applied, and when (${SINCE})`)],
        rows.map(x => h("tr", jump(x.did ?? x.failed ?? x.sus ?? t0), h("td", { class: "wrap" }, N.el(x.n)),
          h("td", { class: "num" }, x.did != null ? rel(x.did, t0) : x.failed != null ? h("span", { style: "color:var(--critical)" }, `✗ ${rel(x.failed, t0)}`) : "—"),
          h("td", { class: "num" }, rel(x.sus, t0)), h("td", { class: "num" }, rel(x.conf, t0)),
          h("td", { class: "num" }, lag(x)),
          h("td", { class: "wrap" }, x.c ? [N.el(x.c.id), h("span", { class: "muted" }, ` at ${rel(x.c.t, t0)}`)] : h("span", { class: "muted", title: "No applied countermeasure covers this step" }, "nothing")))), ""));
  }

  // A card redraws only when what it shows changed: same run, time, data, width.
  function keep(box, r, t, extra) {
    const x = sides(r);
    const sig = JSON.stringify([r.id, r.status, t, x.red.steps.length, x.red.plans.length, x.red.recon.length, !!x.red.belief, !!x.red.end,
      r.writes.length, r.findings.length, r.states.length, r.decisions.length, r.actions.length, x.blue.alerts.length, x.blue.modelErrors.length,
      Object.values(r.approvals).map(a => a.state).join(), r.plant.length, Math.round(box.clientWidth / 40),
      !!(UI.structure && UI.structure(r)),  // the names of the tree's nodes arrive with the structure
      document.documentElement.dataset.theme || "", extra ?? null]);
    if (box.dataset.sig === sig) return false;
    box.dataset.sig = sig;
    return true;
  }

  // ── the cards of the three views ──────────────────────────────────────────
  function renderSides(box, r, t) {
    if (!keep(box, r, t)) return;
    const v = sidesAt(r, t), N = namer(r);
    box.replaceChildren(h("div", { class: "cols2" },
      side("red", "Attacker", [["doing", redDoing(v, N, r)], ["knows", redKnows(v, N)]]),
      side("blue", "Defender", [["doing", blueDoing(v, r, N)], ["sees / believes", blueSees(v, r, N)]])),
      lanesBox(r, t, ["attacker", "defender", "plant"]));
  }

  function renderAttacker(box, r, t) {
    if (!keep(box, r, t)) return;
    const v = sidesAt(r, t), R = v.red, t0 = t0Of(r, R), N = namer(r);
    const seen = o => [o.whoami ? `as ${o.whoami}` : null, o.detail || null,
      o.writes?.length ? `${o.writes.filter(w => w.ok).length}/${o.writes.length} writes accepted (${[...new Set(o.writes.map(w => w.register_name))].join(", ")})` : null]
      .filter(Boolean).join(" · ") || "—";
    const since = th("since attack start", "Counted from the start of the attack: the attacker's first step, or its first write to the plant", true);
    const steps = table([since, th("step", "The attack-tree step it ran; hover for the name it is recorded under"),
      th("ATT&CK technique", "The MITRE ATT&CK technique the step is an instance of"), th("outcome", "✓ worked · ✗ failed"),
      th("what it observed", "What the step's own output told the attacker: the user it ran as, what it found, which writes the plant accepted"),
      th("by", "agent: the autonomous attacker · a name: the person at the red console")],
      R.steps.map(s => h("tr", jump(s.t), h("td", { class: "num" }, rel(s.t, t0)), h("td", { class: "wrap" }, N.el(s.node)), h("td", {}, s.attck || "—"),
        h("td", {}, mark(s.ok, s.ok ? "done" : "failed")), h("td", { class: "wrap" }, seen(s.observed || {})), h("td", {}, s.by))),
      R.start || r.writes.length ? "This attacker ran no step of the attack tree: it only wrote to the plant (see its writes above)"
        : "No attack step yet: the attack has not started, or this run has none");
    const WHY = { initial: "first plan", replan: "re-plan after a failed step" };
    const plans = R.plans.length ? [h("h3", { class: "sub", style: "margin:14px 0 4px" }, "Its plans"),
      table([since, th("why", "first plan: its first choice · re-plan: a step failed and it chose again"),
        th("target", "The impact on the plant it chose to go for"), th("route", "The steps to get there, in order"),
        th("options", "The impacts open to it then, with the weight it gives each and how likely it thinks each is to be detected (0–1)"),
        th("closed", "Steps that had failed: it gave up every path through them")],
        R.plans.map(p => h("tr", jump(p.t), h("td", { class: "num" }, rel(p.t, t0)), h("td", {}, WHY[p.reason] || p.reason || "—"), h("td", { class: "wrap" }, N.el(p.target)),
          h("td", { class: "wrap" }, N.list(p.sequence, " → ")),
          h("td", { class: "wrap" }, p.candidates.map(c => `${N.text(c.node)} (weight ${c.impact ?? "?"}, detectability ${c.detectability ?? "?"})`).join("; ") || "—"),
          h("td", { class: "wrap" }, p.blocked.length ? N.list(p.blocked) : "none"))), "")] : [];
    const STAGE = { it: "IT network scan", ot: "plant, through the foothold" };
    const recon = R.recon.length ? [h("h3", { class: "sub", style: "margin:14px 0 4px" }, "Its reconnaissance"),
      table([since, th("stage", "IT network scan: what hosts and ports it found · plant: what it learnt of the plant's Modbus server through its foothold"), th("found", "What it learnt; registers are listed as address=value")],
        R.recon.map(c => h("tr", jump(c.t), h("td", { class: "num" }, rel(c.t, t0)), h("td", {}, STAGE[c.stage] || c.stage),
          h("td", { class: "wrap" }, c.stage === "it"
            ? `${(c.hosts || []).map(x => `${x.ip} (${(x.ports || []).map(p => p.port ?? p).join(", ")})`).join(" · ") || "no host"}${c.foothold ? ` — foothold ${c.foothold.ip ?? c.foothold}:${c.foothold.port ?? ""}` : ""}`
            : `${c.engine_ip || "?"}:${c.modbus_port || "?"} Modbus ${c.modbus_ok ? "answers" : "silent"}${c.registers ? ` — ${Object.entries(c.registers).map(([a, x]) => `${a}=${x}`).join(" · ")}` : ""}`))), "")] : [];
    box.replaceChildren(h("div", { class: "cols2" },
      side("red", "Doing", [["now", redDoing(v, N, r)]]), side("red", "Knows", [["of the target", redKnows(v, N)]])),
      lanesBox(r, t, ["attacker", "plant"]),
      h("h3", { class: "sub", style: "margin:14px 0 4px" }, "Its steps"), steps, ...plans, ...recon);
  }

  function renderDefender(box, r, t) {
    if (!keep(box, r, t)) return;
    const v = sidesAt(r, t), B = v.blue, t0 = r.start_t, N = namer(r);
    // What the policy weighed, in its own terms, spelled out.
    const COST = { residual: "risk left", future: "risk ahead", op: "operational cost", time: "time to take effect", energy: "energy cost", total: "total" };
    const cost = c => c && Object.values(c).some(x => typeof x === "number")
      ? Object.entries(c).filter(([, x]) => typeof x === "number").map(([k, x]) => `${COST[k] || pretty(k)} ${num(x, 2)}`).join(" · ")
      : h("span", { class: "muted", title: "This policy records no cost for its decisions, or the run predates the record" }, "not recorded");
    const since = th("since run start", "Counted from the start of the run", true);
    const decisions = table([since,
      th("triggered by", "The finding that led to the decision, and how long after that finding the decision came"),
      th("decided", "The countermeasures it chose to run; hover for the name each is recorded under"),
      th("what it weighed", "The terms of the policy's cost function for this choice, unitless, lower is better: risk left once it is applied, risk still ahead, operational cost, time to take effect, energy cost, and their total"),
      th("its justification", "The policy's own reason, as it recorded it")],
      B.decisions.map(d => h("tr", jump(d.t), h("td", { class: "num" }, rel(d.t, t0)),
        h("td", {}, d.trigger_klass ? `${pretty(d.trigger_klass)}${d.trigger_t != null ? ` (decided ${num(d.t - d.trigger_t, 2)} s later)` : ""}`
          : h("span", { class: "muted", title: "The decision does not record which finding led to it" }, "not recorded")),
        h("td", { class: "wrap" }, d.actions.length ? N.list(d.actions) : "no action"), h("td", { class: "wrap" }, cost(d.cost_terms)),
        h("td", { class: "wrap" }, d.rationale || "—"))),
      r.respond && r.respond !== "off" ? "No decision yet: nothing the policy answers to has been found" : "No response policy in this run: the defender only watches");
    // Alerts as intervals: raised, then cleared.
    const open = {}, alerts = [];
    for (const a of sides(r).blue.alerts.filter(uptoT(t))) {
      const k = `${UI.termText(a.detector)}: ${pretty(a.klass)}${where(r, a)}`;
      if (a.state === "cleared") { if (open[k]) { open[k].cleared = a.t; delete open[k]; } }
      else if (!open[k]) { open[k] = { k, raised: a.t, cleared: null }; alerts.push(open[k]); }
    }
    const alertTable = table([th("alert", "The detector that raised it and the class of what it saw"), th("raised", "When, since run start", true),
      th("cleared", "When the condition ended, since run start; \"still open\" if it has not", true), th("lasted", "From raised to cleared", true)],
      alerts.map(a => h("tr", jump(a.raised), h("td", {}, a.k), h("td", { class: "num" }, rel(a.raised, t0)),
        h("td", { class: "num" }, a.cleared == null ? "still open" : rel(a.cleared, t0)),
        h("td", { class: "num" }, a.cleared == null ? "—" : `${num(a.cleared - a.raised, 1)} s`))), "No alert raised yet");
    // When each node of the tree first reached each belief.
    const firstAt = {};
    for (const st of r.states.filter(uptoT(t))) for (const [n, [state]] of Object.entries(st.nodes || {}))
      if (state in STATE_RANK) (firstAt[n] = firstAt[n] || {})[state] = firstAt[n][state] ?? st.t;
    const BELIEF = { suspected: "first suspected", inferred: "first inferred", confirmed: "first confirmed" };
    const BELIEF_HELP = { suspected: "When the defender first thought the step possible", inferred: "When it first took the step as implied by a later step it had confirmed",
      confirmed: "When it was first sure the step had happened" };
    const belief = table([th("attack step", "A node of the attack tree; hover for the name it is recorded under"),
      ...["suspected", "inferred", "confirmed"].map(k => th(BELIEF[k], `${BELIEF_HELP[k]}, since run start`, true))],
      Object.entries(firstAt).sort((a, b) => Math.min(...Object.values(a[1])) - Math.min(...Object.values(b[1])))
        .map(([n, f]) => h("tr", jump(Math.min(...Object.values(f))), h("td", { class: "wrap" }, N.el(n)),
          ...["suspected", "inferred", "confirmed"].map(k => h("td", { class: "num", style: f[k] != null ? `color:${STATE_STYLE[k].stroke}` : null }, rel(f[k], t0))))),
      r.respond && r.respond !== "off" ? "No belief yet: no finding has pointed to a step of the attack tree"
        : "This run's defender keeps no belief on the attack tree: it has no response policy");
    box.replaceChildren(h("div", { class: "cols2" },
      side("blue", "Doing", [["now", blueDoing(v, r, N)]]), side("blue", "Sees / believes", [["so far", blueSees(v, r, N)]])),
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
    // Steps and countermeasures by the names the run's structure gives them.
    const N = namer(r), q = id => `"${N.text(id)}"`;
    if (red.start) add(red.start.t, "attacker", `attack starts${red.start.mode ? `: ${LABELS.mode(red.start.mode)}` : ""}`);
    for (const c of red.recon) add(c.t, "attacker", c.stage === "it" ? `reconnaissance: ${(c.hosts || []).length} host(s) found${c.foothold ? `, foothold on ${c.foothold.ip ?? c.foothold}` : ""}`
      : `reconnaissance: plant at ${c.engine_ip}:${c.modbus_port}, its Modbus server ${c.modbus_ok ? "answers" : "does not answer"}`);
    if (red.belief) add(red.belief.t, "attacker", "builds its own attack tree from what it found");
    for (const p of red.plans) add(p.t, "attacker", `${p.reason === "replan" ? "re-plans" : "plans"}: goes for ${q(p.target)}, by way of ${p.sequence.map(q).join(" → ")}`);
    for (const s of red.steps) add(s.t, "attacker", `step ${s.ok ? "done" : "failed"}: ${q(s.node)}${s.by !== "agent" ? ` (by ${s.by})` : ""}${s.observed?.whoami ? ` — runs as ${s.observed.whoami}` : ""}`);
    let w = null;
    for (const x2 of r.writes) {
      const reg = `${x2.register}${where(r, x2)}`;   // the same register of another feeder is another write
      const refused = x2.ok === false ? " — refused by the plant" : "";
      if (w && w.reg === reg + refused && x2.t - w.last < 5) { w.n++; w.last = x2.t; w.item.text = `writes ${x2.register} = ${x2.value}${where(r, x2)} ×${w.n}${refused}`; continue; }
      w = { reg: reg + refused, n: 1, last: x2.t, item: { t: x2.t, side: "attacker", text: `writes ${x2.register} = ${x2.value}${where(r, x2)}${refused}` } };
      out.push(w.item);
    }
    if (red.end) add(red.end.t, "attacker", red.end.success ? "attack ends: it reached its impact on the plant"
      : `attack ends short of its impact: it got as far as ${red.end.stage_reached ? q(red.end.stage_reached) : "nothing"}`);
    let f = null;
    for (const x2 of r.findings) {
      const k = `${UI.termText(x2.detector)}: ${pretty(x2.klass)}${where(r, x2)}`;
      if (f && f.k === k && x2.t - f.last < 5) { f.n++; f.last = x2.t; f.item.text = `finding by ${k} ×${f.n}`; continue; }
      f = { k, n: 1, last: x2.t, item: { t: x2.t, side: "defender", text: `finding by ${k}${x2.src ? ` from ${x2.src}` : ""}${x2.maps_to ? `, pointing to the step ${q(x2.maps_to)}` : ""}` } };
      out.push(f.item);
    }
    for (const a of x.blue.alerts) add(a.t, "defender", `alert ${a.state}: ${UI.termText(a.detector)}: ${pretty(a.klass)}${where(r, a)}`);
    for (const e of x.blue.modelErrors) add(e.t, "defender", `the learned model could not be fitted${where(r, e)}: ${e.error || "no reason recorded"}`);
    let prev = {};
    for (const st of r.states) {
      const changes = Object.entries(st.nodes || {}).filter(([n, s2]) => s2[0] in STATE_RANK && prev[n] !== s2[0]).map(([n, s2]) => `${q(n)} ${s2[0]}`);
      prev = Object.fromEntries(Object.entries(st.nodes || {}).map(([n, s2]) => [n, s2[0]]));
      if (changes.length) add(st.t, "defender", `now believes: ${changes.join(", ")}`);
    }
    for (const d of r.decisions) add(d.t, "defender", `decides: ${d.actions.map(q).join(", ") || "no action"}`);
    for (const a of r.actions) if (a.id !== "notify") add(a.t, "defender", `${a.op === "revert" ? "reverts" : "applies"} ${q(a.id)}${a.machine ? ` on ${a.machine}` : ""}: ${a.ok ? "done" : "failed"}`);
    const ANSWER = { granted: "approved", rejected: "rejected", expired: "left unanswered until it expired" };
    for (const a of Object.values(r.approvals)) {
      add(a.asked_t, "defender", `asks the operator whether to apply ${q(a.action)}`);
      if (a.state && a.state !== "requested" && a.t !== a.asked_t) add(a.t, "defender", `operator: ${q(a.action)} ${ANSWER[a.state] || a.state}${a.operator ? ` by ${a.operator}` : ""}`);
    }
    for (const [, plant, name] of feeders(r)) {
      for (const [a, b] of spans(plant, p => p.abnormal)) { add(a, "plant", `voltages leave the normal band${name}`); add(b, "plant", `voltages back in band${name}`); }
      for (const [a, b] of spans(plant, p => p.ctrl_mode === 1)) { add(a, "plant", `control switches to MANUAL${name}`); add(b, "plant", `control back to auto${name}`); }
      for (const [a, b] of spans(plant, p => !!p.switch_cmd)) { add(a, "plant", `feeder breaker opens${name}`); add(b, "plant", `feeder breaker closes${name}`); }
    }
    return out.sort((a, b) => a.t - b.t);
  }
  // The journal lists the newest fact first, and is kept, not redrawn: a new
  // fact is a row put in at the top, a fact that changed (a burst grown by one)
  // has its text updated, and every other row stays the element it was. So a
  // reader scrolled down the list, or about to click a row, keeps their place
  // while a live run goes on adding facts above.
  const journals = new WeakMap();
  function renderJournal(box, r, t) {
    const view = UI.view() || "overview";
    const show = journalShow[view] || (journalShow[view] = journalDefaults(view));
    if (!keep(box, r, t, [view, show, !!journalAll[view]])) return;
    const items = journalOf(r).filter(e => show[e.side]);
    const all = !!journalAll[view], shown = (all ? items : items.slice(-300)).reverse();
    // The frame (filters, note, table) is built when what frames the list changes.
    const frame = JSON.stringify([r.id, view, show, all, items.length > shown.length]);
    let J = journals.get(box);
    if (!J || J.frame !== frame) {
      const redraw = () => { box.dataset.sig = ""; UI.render(); };
      const filters = h("div", { class: "tabs", role: "group", "aria-label": "Sides shown" },
        ...Object.keys(SIDES).map(k => h("button", { type: "button", "aria-pressed": String(!!show[k]), title: `Show the ${k}'s facts`,
          onclick: () => { show[k] = !show[k]; redraw(); } },
          h("span", { class: "dot", style: `background:${SIDES[k]};margin-right:5px` }), k)));
      J = { frame, rows: new Map(), tbody: h("tbody", {}), note: h("span", {}) };
      // The list keeps its own place when rows are added above (set below), so the browser must not also try to.
      J.scroll = h("div", { class: "scroll", style: "max-height:420px;overflow-y:auto;overflow-anchor:none" }, h("table", {},
        h("thead", {}, h("tr", {}, th("since run start", "When the fact happened, counted from the start of the run", true),
          th("side", "Whose fact it is: the attacker's, the defender's, or the plant's own state"),
          th("what happened", "The newest fact is at the top. Facts after the time shown on the time bar are greyed"))),
        J.tbody));
      // replaceChildren would print a null as the text "null": the button is spread in or not at all.
      box.replaceChildren(filters, h("p", { class: "sub", style: "margin:6px 0" }, "Newest first. ", J.note,
        ...(items.length > shown.length ? [" ", h("button", { type: "button", onclick: () => { journalAll[view] = true; redraw(); } }, "show all")] : [])),
        J.scroll);
      journals.set(box, J);
    }
    J.note.textContent = items.length > shown.length ? `The latest ${shown.length} of ${items.length} facts.`
      : `${items.length} fact${items.length === 1 ? "" : "s"}.`;
    // A fact is known by when it happened and whose it is; two at one instant by their order.
    const seen = {}, wanted = [], t0 = r.start_t;
    for (const e of [...shown].reverse()) {
      const base = `${e.t}|${e.side}`, key = `${base}|${seen[base] = (seen[base] || 0) + 1}`;
      let row = J.rows.get(key);
      if (!row) {
        row = { what: h("td", { class: "wrap" }), text: null, dim: null };
        row.tr = h("tr", jump(e.t), h("td", { class: "num" }, t0 ? rel(e.t, t0) : clock(e.t)),
          h("td", {}, h("span", { class: "dot", style: `background:${SIDES[e.side]}` }), ` ${e.side}`), row.what);
        J.rows.set(key, row);
      }
      if (row.text !== e.text) row.what.textContent = row.text = e.text;
      const dim = t != null && e.t > t + 1e-6;
      if (row.dim !== dim) { row.dim = dim; row.tr.style.opacity = dim ? ".4" : ""; }
      wanted.push([key, row]);
    }
    wanted.reverse();
    const keys = new Set(wanted.map(([key]) => key));
    for (const [key, row] of J.rows) if (!keys.has(key)) { row.tr.remove(); J.rows.delete(key); }
    if (J.empty) { J.empty.remove(); J.empty = null; }
    // Rows go where they belong; one already there is not touched. A reader who
    // has scrolled down stays on the rows they were reading.
    const before = J.scroll.scrollHeight, at = J.scroll.scrollTop;
    wanted.forEach(([, row], i) => { if (J.tbody.children[i] !== row.tr) J.tbody.insertBefore(row.tr, J.tbody.children[i] || null); });
    if (at > 0) J.scroll.scrollTop = at + (J.scroll.scrollHeight - before);
    if (!wanted.length) J.tbody.append(J.empty = h("tr", {}, h("td", { colspan: 3, class: "empty" },
      Object.values(show).some(Boolean) ? "Nothing has happened yet on the sides shown" : "Every side is switched off: choose one above")));
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
  const origin = r => r.writes.length ? { t: r.writes[0].t, label: "since the first malicious write" } : null;

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
      sub: "Every fact of the run, the newest first. Click a row to show the run at that time.",
      help: "The run as a log, newest fact at the top: the attacker's steps, plans and writes; the defender's findings, beliefs, decisions and actions; the plant's changes of state. Repeated findings and writes within 5 s are grouped. Facts after the time shown are greyed. The buttons choose whose facts to list." },
  ];

  let UI = null;
  // The page invokes this once, with its own handles.
  (window.CyberRangePanels ||= {})["cps"] = ui => {
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
      labels: LABELS,
    };
  };
})();
