#!/usr/bin/env python3
"""grid_sim.py — pandapower digital twin of a small LV feeder, the "physical
engine" of the cyber-physical scenario. It is to this scenario what
microgrid_sim.py (pymgrid) is to the MQTT/MTD one, but it is a real power-flow
model: a few buses, a feeder line, a load and a distributed generator (DG), with
two actuators the PLC drives over Modbus — the DG active-power setpoint and a
feeder breaker.

Copied flat onto the engine machine (see network_scenario/guest_files.py);
modbus_engine.py does ``from grid_sim import build_grid, step_grid, GridState``.

Topology (radial 0.4 kV feeder)::

    ext_grid --line0-- bus_load --line1--(switch)-- bus_dg
    (slack)   bus0      bus1      load      bus2     sgen (DG)

Normal control keeps every bus voltage inside [V_BAND_LOW, V_BAND_HIGH] pu.
A DG setpoint forced out of range drives an OVERvoltage at the DG bus; opening
the feeder breaker (isolating the DG) drives an UNDERvoltage at the load bus.
Both are real power-flow results, not scripted numbers.
"""

import time

import numpy as np
import pandapower as pp

# Shared plant contract (bands, scales). Flat import: ot_registers.py is copied
# alongside this module on the engine machine.
import ot_registers as reg


def _isnan(x):
    return x != x

# ── Model constants ──────────────────────────────────────────────────────────
VN_KV          = 0.4        # LV feeder
LINE0_KM       = 0.14       # slack -> load bus
LINE1_KM       = 0.20       # load bus -> DG bus (long enough that a full-rated
                            # 60 kW DG at nominal load overvolts its bus: an
                            # in-range command can still be unsafe)
R_OHM_PER_KM   = 0.642
X_OHM_PER_KM   = 0.083
C_NF_PER_KM    = 0.0
MAX_I_KA       = 0.142      # ~ sizes the feeder so normal loading is mid-range

LOAD_NOMINAL_KW = 50.0      # mean load
LOAD_SIGMA_KW   = 4.0       # seeded load jitter
DG_NOMINAL_KW   = 20.0      # DG setpoint the PLC normally holds

STEP_DT_S       = 1.0       # nominal seconds per step (for energy integration)


class GridState:
    """Holds the pandapower net plus the slowly-varying load series and a
    cumulative energy tally, so the engine can step it repeatedly."""

    def __init__(self, net, rng, load_mw):
        self.net = net
        self.rng = rng
        self.load_mw = load_mw          # current load (MW), random-walked each step
        self.energy_kwh = 0.0           # cumulative energy drawn from the slack
        self.step_i = 0


def build_grid(seed=None) -> GridState:
    """Build the LV feeder net at its nominal operating point."""
    rng = np.random.default_rng(None if seed is None else [seed, 0x6D1D])
    net = pp.create_empty_network(name="cps-lv-feeder")

    b0 = pp.create_bus(net, vn_kv=VN_KV, name="slack")
    b1 = pp.create_bus(net, vn_kv=VN_KV, name="load")
    b2 = pp.create_bus(net, vn_kv=VN_KV, name="dg")

    pp.create_ext_grid(net, b0, vm_pu=1.02, name="grid")
    # line0 is the main feeder; it carries the breaker that, when opened,
    # de-energizes the whole downstream section (load + DG island, no slack).
    l0 = pp.create_line_from_parameters(net, b0, b1, length_km=LINE0_KM,
                                        r_ohm_per_km=R_OHM_PER_KM, x_ohm_per_km=X_OHM_PER_KM,
                                        c_nf_per_km=C_NF_PER_KM, max_i_ka=MAX_I_KA, name="feeder")
    pp.create_line_from_parameters(net, b1, b2, length_km=LINE1_KM,
                                   r_ohm_per_km=R_OHM_PER_KM, x_ohm_per_km=X_OHM_PER_KM,
                                   c_nf_per_km=C_NF_PER_KM, max_i_ka=MAX_I_KA, name="dg_tie")
    pp.create_switch(net, bus=b0, element=l0, et="l", closed=True, name="feeder_breaker")

    pp.create_load(net, b1, p_mw=LOAD_NOMINAL_KW / 1000.0, q_mvar=0.0, name="load")
    pp.create_sgen(net, b2, p_mw=DG_NOMINAL_KW / 1000.0, q_mvar=0.0, name="dg")

    st = GridState(net, rng, LOAD_NOMINAL_KW / 1000.0)
    return st


def step_grid(st: GridState, actuators: dict, dt_s: float = STEP_DT_S) -> dict:
    """Advance one step: apply actuators, random-walk the load, solve the power
    flow, and return a sensor dict in engineering units.

    `actuators` keys (engineering units, as decoded from the holding registers):
      - "dg_setpoint" : DG active-power setpoint in kW
      - "switch_cmd"  : feeder breaker, 0 = closed, 1 = open
    Missing keys hold their current value.
    """
    net = st.net
    st.step_i += 1

    # Apply DG setpoint actuator (kW -> MW). No clamping here: an attacker's
    # out-of-range write must actually reach the physics.
    if "dg_setpoint" in actuators and actuators["dg_setpoint"] is not None:
        net.sgen.at[0, "p_mw"] = float(actuators["dg_setpoint"]) / 1000.0
    # Apply breaker actuator (1 = open isolates the DG tie line).
    if "switch_cmd" in actuators and actuators["switch_cmd"] is not None:
        net.switch.at[0, "closed"] = (int(round(actuators["switch_cmd"])) == 0)

    # Seeded random-walk of the load around its nominal (kept inside sane bounds).
    jitter = st.rng.normal(0.0, LOAD_SIGMA_KW / 1000.0)
    st.load_mw = float(np.clip(st.load_mw + jitter, 0.030, 0.070))
    net.load.at[0, "p_mw"] = st.load_mw

    converged = True
    try:
        pp.runpp(net, numba=False)
    except Exception:
        converged = False

    def _f(series, i):
        try:
            v = float(series.iloc[i])
        except Exception:
            return float("nan")
        return v

    v_load = _f(net.res_bus.vm_pu, 1) if converged else float("nan")
    v_dg   = _f(net.res_bus.vm_pu, 2) if converged else float("nan")
    line_load = _f(net.res_line.loading_percent, 0) if converged else float("nan")
    p_load = _f(net.res_load.p_mw, 0) * 1000.0 if converged else st.load_mw * 1000.0
    p_dg   = _f(net.res_sgen.p_mw, 0) * 1000.0 if converged else net.sgen.at[0, "p_mw"] * 1000.0
    p_grid = _f(net.res_ext_grid.p_mw, 0) * 1000.0 if converged else 0.0

    # A de-energized / isolated bus shows up as NaN; that is itself abnormal
    # (loss of supply). Collapse NaNs to 0 for the wire after flagging them.
    deenergized = any(_isnan(x) for x in (v_load, v_dg))
    abnormal = (not converged or deenergized
                or v_load < reg.V_BAND_LOW or v_load > reg.V_BAND_HIGH
                or v_dg   < reg.V_BAND_LOW or v_dg   > reg.V_BAND_HIGH
                or (not _isnan(line_load) and line_load > reg.LINE_LOAD_MAX))
    if _isnan(v_load): v_load = 0.0
    if _isnan(v_dg):   v_dg = 0.0
    if _isnan(line_load): line_load = 0.0
    if _isnan(p_load): p_load = 0.0
    if _isnan(p_dg): p_dg = 0.0
    if _isnan(p_grid): p_grid = 0.0

    # Energy drawn from the grid over this step (kWh); negative if exporting.
    st.energy_kwh += p_grid * (dt_s / 3600.0)

    return {
        "timestamp": round(time.time(), 3),
        "step": st.step_i,
        "converged": converged,
        "v_load": round(v_load, 4),
        "v_dg": round(v_dg, 4),
        "line_load": round(line_load, 2),
        "p_load": round(p_load, 2),
        "p_dg": round(p_dg, 2),
        "p_grid": round(p_grid, 2),
        "abnormal": int(bool(abnormal)),
        "energy_kwh": round(st.energy_kwh, 5),
        "switch_open": bool(net.switch.at[0, "closed"] is False or not net.switch.at[0, "closed"]),
        "dg_setpoint": round(float(net.sgen.at[0, "p_mw"]) * 1000.0, 2),
    }
