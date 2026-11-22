// panel.js — the cps-advisor scenario's dashboard panel: the cps one, plus the
// table of a benchmark of harnesses.
//
// The run is a cps run with a different defender, so the plant chart, the
// findings and the structure views are the same. The page looks a panel up by
// the scenario name its ledger reports, hence this entry; what is specific to
// an advising defender (the suggestions and their answers) the page draws for
// any scenario. The panels are served together, so the cps one is there when a
// run is shown; alone, this one draws nothing.
//
// What this scenario adds is a results tab: a campaign of it is a benchmark
// (cps_advisor/campaign.py), and its aggregate carries one row per cell of the
// grid — a harness, the side it played, the opponent — with the mean and 95% CI
// of the columns of that side. The two sides have different columns, so the
// table is drawn once per side. `h` and `num` are the page's.
(function () {
  "use strict";
  const panels = (window.CyberRangePanels ||= {});
  const TAB = { id: "harness", label: "Harnesses" };
  const KEYS = new Set(["group", "side", "runs"]);

  function cell(s) {
    if (!s || !s.n) return "—";
    return s.n === 1 ? String(num(s.mean)) : `${num(s.mean)} [${num(s.ci95_low)}, ${num(s.ci95_high)}]`;
  }

  function harnesses(a, tb) {
    const rows = a.harness || [];
    if (!rows.length) {
      tb.replaceChildren(h("tbody", {}, h("tr", {}, h("td", { class: "empty" }, "No scored games yet"))));
      return;
    }
    const parts = [];
    for (const side of ["red", "blue"]) {
      const own = rows.filter(r => r.side === side);
      if (!own.length) continue;
      const cols = Object.keys(own[0]).filter(k => !KEYS.has(k));
      parts.push(h("thead", {}, h("tr", {}, h("th", {}, `playing ${side}`), h("th", { class: "num" }, "games"),
        ...cols.map(c => h("th", { class: "num" }, c)))));
      parts.push(h("tbody", {}, own.map(r => h("tr", {}, h("td", {}, r.group), h("td", { class: "num" }, r.runs),
        ...cols.map(c => h("td", { class: "num" }, cell(r[c])))))));
    }
    tb.replaceChildren(...parts);
  }

  panels["cps-advisor"] = ui => {
    const cps = panels["cps"] ? panels["cps"](ui) : {};
    const base = cps.results || { tabs: [], render() {} };
    return {
      ...cps,
      results: {
        tabs: [...base.tabs, TAB],
        render: (tab, a, tb) => (tab === TAB.id ? harnesses(a, tb) : base.render(tab, a, tb)),
      },
    };
  };
})();
