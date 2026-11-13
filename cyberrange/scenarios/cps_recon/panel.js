// panel.js — the cps-recon scenario's dashboard panel: the cps one, with the
// attacker's own knowledge drawn on the attack tree.
//
// A run here is a cps run whose attacker derived its own tree by reconnaissance,
// so every view is the cps panel's (served alongside this one). What this adds
// is what that attacker believes: the attack tree keeps the defender's belief
// and the attacker's progress, and frames in red the real nodes the attacker
// does not know; nodes it believes in that are not real are listed in the
// legend. The belief comes live from the ledger (attacker_belief); a run
// recorded without it falls back to the leaves its scored tree_fidelity lists.
(function () {
  "use strict";
  function ids(node, out) {
    if (!node) return out;
    if (node.feasible !== false) out.add(node.id);
    for (const c of node.children || []) ids(c, out);
    return out;
  }

  const panels = (window.CyberRangePanels ||= {});
  panels["cps-recon"] = ui => {
    const base = panels["cps"] ? panels["cps"](ui) : {};
    if (!base.graph) return base;
    const overlayAt = (r, t) => {
      const ov = base.graph.overlayAt(r, t);
      const belief = r.x && r.x.red && r.x.red.belief;
      if (belief && (t == null || belief.t <= t + 1e-6)) return { ...ov, redKnows: ids(belief.tree, new Set()) };
      const fid = r.metrics && r.metrics.tree_fidelity;
      if (fid) return { ...ov, redKnows: new Set([...(fid.discovered || []), ...(fid.extra || [])]), redLeavesOnly: true };
      return ov;
    };
    return { ...base, graph: { ...base.graph, overlayAt } };
  };
})();
