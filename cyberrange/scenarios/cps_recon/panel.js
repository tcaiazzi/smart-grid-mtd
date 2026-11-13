// panel.js — the cps-recon scenario's dashboard panel: the cps one, with the
// attack-tree view turned into a BELIEF overlay.
//
// A run here is a cps run whose attacker derived its own tree by reconnaissance,
// so the plant chart, the findings and the topology/knowledge-graph views are the
// same (delegated to the cps panel, which is served alongside this one). What
// differs is the attack-tree view: instead of the true tree with the response
// overlay, it draws the TRUE tree coloured by what the attacker discovered —
// found (green), real but missed (grey, dashed), and any hallucinated leaves
// listed in the legend. The comparison is the run's `tree_fidelity` metric,
// threaded in through a wrapped overlayAt; before a run is scored it falls back
// to each node's own feasibility.
(function () {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  function el(tag, attrs, text) {
    const e = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v != null) e.setAttribute(k, v);
    if (text != null) e.textContent = text;
    return e;
  }
  const clip = (s, n) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };

  function drawBeliefTree(box, st, ov, opts) {
    const tree = st && st.tree && st.tree.attack_tree;
    if (!tree) { box.replaceChildren(el("text", {}, "no attack tree")); return []; }
    const fid = ov && ov.fidelity;
    const discovered = new Set(fid ? fid.discovered || [] : []);
    const extra = fid ? fid.extra || [] : [];

    // Layout: leaves take successive x slots, a parent sits above its children.
    const pos = {};
    let slot = 0;
    (function place(n, depth) {
      const kids = n.children || [];
      if (!kids.length) { pos[n.id] = { x: slot++, d: depth, n }; return pos[n.id]; }
      const cs = kids.map(c => place(c, depth + 1));
      pos[n.id] = { x: (cs[0].x + cs[cs.length - 1].x) / 2, d: depth, n };
      return pos[n.id];
    })(tree, 0);

    const leaves = Math.max(slot, 1);
    const depths = Object.values(pos).map(p => p.d);
    const maxD = Math.max(0, ...depths);
    const W = Math.max((opts && opts.width) || 640, 360), levelH = 92, pad = 24;
    const H = pad * 2 + maxD * levelH + 36;
    const colX = x => pad + 56 + (leaves <= 1 ? (W - 112) / 2 : x * ((W - 112) / (leaves - 1)));
    const colY = d => pad + 18 + d * levelH;
    const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, class: "graph", role: "img",
      "aria-label": "Belief vs true attack tree" });

    for (const p of Object.values(pos))
      for (const c of p.n.children || []) {
        const cp = pos[c.id];
        svg.appendChild(el("line", { x1: colX(p.x), y1: colY(p.d) + 15, x2: colX(cp.x),
          y2: colY(cp.d) - 15, stroke: "var(--axis)" }));
      }
    for (const p of Object.values(pos)) {
      const n = p.n, x = colX(p.x), y = colY(p.d);
      const found = discovered.has(n.id);
      const trueFeasible = n.feasible !== false;
      const color = found ? "var(--good)" : trueFeasible ? "var(--serious)" : "var(--axis)";
      svg.appendChild(el("rect", { x: x - 54, y: y - 15, width: 108, height: 30, rx: 5,
        fill: "none", stroke: color, "stroke-width": 2,
        "stroke-dasharray": trueFeasible && !found ? "4 3" : null }));
      svg.appendChild(el("text", { x, y: y + 4, "text-anchor": "middle", "font-size": 11,
        fill: "var(--muted)" }, clip(n.label || n.id, 18)));
    }
    box.replaceChildren(svg);

    const legend = [["var(--good)", "discovered by recon"],
      ["var(--serious)", "real but missed (dashed)"]];
    if (extra.length) legend.push(["var(--warning)", `hallucinated: ${extra.join(", ")}`]);
    return legend;
  }

  const panels = (window.CyberRangePanels ||= {});
  panels["cps-recon"] = ui => {
    const base = panels["cps"] ? panels["cps"](ui) : {};
    if (!base.graph) return base;
    const overlayAt = (r, t) => ({
      ...base.graph.overlayAt(r, t),
      fidelity: (r.metrics && r.metrics.tree_fidelity) || null,
    });
    return { ...base, graph: { ...base.graph, overlayAt, drawTree: drawBeliefTree } };
  };
})();
