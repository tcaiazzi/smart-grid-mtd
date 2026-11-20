// panel.js — the cps-advisor scenario's dashboard panel: the cps one.
//
// The run is a cps run with a different defender, so the plant chart, the
// findings and the structure views are the same. The page looks a panel up by
// the scenario name its ledger reports, hence this entry; what is specific to
// an advising defender (the suggestions and their answers) the page draws for
// any scenario. The panels are served together, so the cps one is there when a
// run is shown; alone, this one draws nothing.
(function () {
  "use strict";
  const panels = (window.CyberRangePanels ||= {});
  panels["cps-advisor"] = ui => (panels["cps"] ? panels["cps"](ui) : {});
})();
