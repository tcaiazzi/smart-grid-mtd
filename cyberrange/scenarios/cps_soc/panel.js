// panel.js — the cps-soc scenario's dashboard panel: the cps one.
//
// The run is a cps-advisor run whose defender works on Wazuh and DFIR-IRIS; the
// ledger carries the same events, so every view is the cps panel's. The page
// looks a panel up by the scenario name its ledger reports, hence this entry.
// The panels are served together, so the cps one is there when a run is shown;
// alone, this one draws nothing.
(function () {
  "use strict";
  const panels = (window.CyberRangePanels ||= {});
  panels["cps-soc"] = ui => (panels["cps"] ? panels["cps"](ui) : {});
})();
