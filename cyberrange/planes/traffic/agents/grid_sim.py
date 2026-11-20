#!/usr/bin/env python3
"""grid_sim.py — pandapower digital twin of LV feeders, the "physical engine" of
the cyber-physical scenario. It is to this scenario what microgrid_sim.py
(pymgrid) is to the MQTT/MTD one, but it is a real power-flow model: per feeder
a line, a load and a distributed generator (DG), with two actuators the PLC
drives over Modbus — the DG active-power setpoint and a feeder breaker.

Copied flat onto the engine machine (see the scenario's guest_files.py);
modbus_engine.py does ``from grid_sim import build_grid, step_grid, GridState``.
numpy and pandapower, as the node image installs them.

The plant is the description ot_registers.plant() reads; one radial 0.4 kV
feeder per Modbus unit, all fed from one slack bus::

    ext_grid --(switch)--feeder-- bus_load --dg_tie-- bus_dg
    (slack)                         load                sgen (DG)

Normal control keeps every bus voltage inside the plant's v_band. A DG setpoint
forced out of range drives an OVERvoltage at the DG bus; opening a feeder's
breaker de-energises its load and DG together (their voltages read 0). Both are
real power-flow results, not scripted numbers.
"""

import time

import numpy as np
import pandapower as pp

# Shared plant contract (the description, bands, scales). Flat import:
# ot_registers.py is copied alongside this module on the engine machine.
import ot_registers as reg

STEP_DT_S = 1.0  # nominal seconds per step (for energy integration)
LOAD_SPAN = (0.6, 1.4)  # the random walk keeps a load within these multiples of its nominal
FEEDER_FIELDS = ("v_load", "v_dg", "line_load", "p_load", "p_dg", "switch_open", "dg_setpoint")


def _isnan(x):
    return x != x


class Feeder:
    """One feeder's elements in the net, and its load's random walk."""

    def __init__(self, spec, rng, bus_load, bus_dg, line, switch, load, sgen):
        self.spec, self.unit, self.rng = spec, spec["unit"], rng
        self.bus_load, self.bus_dg, self.line = bus_load, bus_dg, line
        self.switch, self.load, self.sgen = switch, load, sgen
        self.load_mw = spec["load_kw"] / 1000.0  # current load, random-walked each step


class GridState:
    """Holds the pandapower net, its feeders and a cumulative energy tally, so
    the engine can step it repeatedly."""

    def __init__(self, net, feeders, plant):
        self.net, self.feeders, self.plant = net, feeders, plant
        self.energy_kwh = 0.0  # cumulative energy drawn from the slack
        self.step_i = 0

    @property
    def load_mw(self):
        return self.feeders[0].load_mw

    def feeder(self, unit):
        return next(f for f in self.feeders if f.unit == unit)


def build_grid(seed=None, plant=None) -> GridState:
    """Build the plant's net at its nominal operating point. Each feeder's load
    walks on a stream of its own; the first feeder's is the one a single-feeder
    plant has always drawn from."""
    p = reg.plant(plant)
    net = pp.create_empty_network(name=p["name"])
    line = p["line"]
    slack = pp.create_bus(net, vn_kv=p["vn_kv"], name="slack")
    pp.create_ext_grid(net, slack, vm_pu=p["slack_vm_pu"], name="grid")
    feeders = []
    for i, f in enumerate(p["feeders"]):
        stream = [seed, 0x6D1D] if i == 0 else [seed, 0x6D1D, f["unit"]]
        rng = np.random.default_rng(None if seed is None else stream)
        suffix = "" if i == 0 else f"_{f['unit']}"
        b_load = pp.create_bus(net, vn_kv=p["vn_kv"], name=f"load{suffix}")
        b_dg = pp.create_bus(net, vn_kv=p["vn_kv"], name=f"dg{suffix}")
        # The feeder line carries the breaker that, when opened, de-energizes the
        # whole downstream section (load + DG island, no slack).
        l_feed = pp.create_line_from_parameters(
            net, slack, b_load, length_km=f["feeder_km"], name=f"feeder{suffix}", **line
        )
        pp.create_line_from_parameters(
            net, b_load, b_dg, length_km=f["dg_tie_km"], name=f"dg_tie{suffix}", **line
        )
        sw = pp.create_switch(
            net, bus=slack, element=l_feed, et="l", closed=True, name=f"feeder_breaker{suffix}"
        )
        ld = pp.create_load(
            net, b_load, p_mw=f["load_kw"] / 1000.0, q_mvar=0.0, name=f"load{suffix}"
        )
        sg = pp.create_sgen(net, b_dg, p_mw=f["dg_kw"] / 1000.0, q_mvar=0.0, name=f"dg{suffix}")
        feeders.append(Feeder(f, rng, b_load, b_dg, l_feed, sw, ld, sg))
    return GridState(net, feeders, p)


def step_grid(st: GridState, actuators: dict, dt_s: float = STEP_DT_S) -> dict:
    """Advance one step: apply actuators, random-walk the loads, solve the power
    flow, and return the frame in engineering units.

    ``actuators`` is {unit: {...}} or, for the first feeder alone, {...}; keys
    (engineering units, as decoded from the holding registers):
      - "dg_setpoint" : DG active-power setpoint in kW
      - "switch_cmd"  : feeder breaker, 0 = closed, 1 = open
    Missing keys hold their current value.

    The frame carries the first feeder's readings at its top level, with
    ``abnormal`` true when any feeder is out of its normal state; a plant of
    several feeders also gives each one's readings under ``units``.
    """
    net = st.net
    st.step_i += 1
    if actuators and not all(isinstance(v, dict) for v in actuators.values()):
        actuators = {st.feeders[0].unit: actuators}
    actuators = actuators or {}

    for f in st.feeders:
        a = actuators.get(f.unit) or {}
        # No clamping: an attacker's out-of-range write must reach the physics.
        if a.get("dg_setpoint") is not None:
            net.sgen.at[f.sgen, "p_mw"] = float(a["dg_setpoint"]) / 1000.0
        # 1 = open: the feeder is cut at the slack bus.
        if a.get("switch_cmd") is not None:
            net.switch.at[f.switch, "closed"] = int(round(a["switch_cmd"])) == 0
        # Seeded random-walk of the load around its nominal, within sane bounds.
        nominal = f.spec["load_kw"] / 1000.0
        jitter = f.rng.normal(0.0, f.spec["load_sigma_kw"] / 1000.0)
        f.load_mw = float(np.clip(f.load_mw + jitter, *(nominal * k for k in LOAD_SPAN)))
        net.load.at[f.load, "p_mw"] = f.load_mw

    converged = True
    try:
        pp.runpp(net, numba=False)
    except Exception:
        converged = False

    def _at(table, column, index):
        try:
            return float(getattr(net, table).at[index, column])
        except Exception:
            return float("nan")

    limits = st.plant["limits"]
    band_lo, band_hi = limits["v_band"]
    readings = {}
    for f in st.feeders:
        v_load = _at("res_bus", "vm_pu", f.bus_load) if converged else float("nan")
        v_dg = _at("res_bus", "vm_pu", f.bus_dg) if converged else float("nan")
        line_load = _at("res_line", "loading_percent", f.line) if converged else float("nan")
        p_load = _at("res_load", "p_mw", f.load) * 1000.0 if converged else f.load_mw * 1000.0
        setpoint = float(net.sgen.at[f.sgen, "p_mw"]) * 1000.0
        p_dg = _at("res_sgen", "p_mw", f.sgen) * 1000.0 if converged else setpoint
        # A de-energized / isolated bus shows up as NaN; that is itself abnormal
        # (loss of supply). NaNs are collapsed to 0 for the wire after flagging.
        abnormal = (
            not converged
            or _isnan(v_load)
            or _isnan(v_dg)
            or not band_lo <= v_load <= band_hi
            or not band_lo <= v_dg <= band_hi
            or (not _isnan(line_load) and line_load > limits["line_load_max"])
        )
        clean = [0.0 if _isnan(x) else x for x in (v_load, v_dg, line_load, p_load, p_dg)]
        v_load, v_dg, line_load, p_load, p_dg = clean
        readings[f.unit] = {
            "v_load": round(v_load, 4),
            "v_dg": round(v_dg, 4),
            "line_load": round(line_load, 2),
            "p_load": round(p_load, 2),
            "p_dg": round(p_dg, 2),
            "abnormal": int(bool(abnormal)),
            "switch_open": not bool(net.switch.at[f.switch, "closed"]),
            "dg_setpoint": round(setpoint, 2),
        }

    p_grid = _at("res_ext_grid", "p_mw", 0) * 1000.0 if converged else 0.0
    if _isnan(p_grid):
        p_grid = 0.0
    # Energy drawn from the grid over this step (kWh); negative if exporting.
    st.energy_kwh += p_grid * (dt_s / 3600.0)

    first = readings[st.feeders[0].unit]
    frame = {
        "timestamp": round(time.time(), 3),
        "step": st.step_i,
        "converged": converged,
        **{k: first[k] for k in FEEDER_FIELDS},
        "p_grid": round(p_grid, 2),
        "abnormal": int(any(r["abnormal"] for r in readings.values())),
        "energy_kwh": round(st.energy_kwh, 5),
    }
    if len(readings) > 1:
        frame["units"] = {str(u): r for u, r in readings.items()}
    return frame


def unit_readings(st: GridState, frame: dict) -> dict:
    """{unit: readings} of a frame, whatever the number of feeders: what the
    engine writes into each unit's input registers."""
    if "units" in frame:
        return {int(u): r for u, r in frame["units"].items()}
    first = {k: frame[k] for k in FEEDER_FIELDS}
    return {st.feeders[0].unit: {**first, "abnormal": frame["abnormal"]}}
