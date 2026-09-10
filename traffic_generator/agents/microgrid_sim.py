#!/usr/bin/env python3
"""microgrid_sim.py — pymgrid physics shared by simple_client.py (baseline
publisher) and mtd_executor.py (MTD publisher). Copied flat onto every scmc
machine (see network_scenario.guest_files); both publishers build one
Microgrid via build_microgrid() and advance it once per publish via
step_microgrid(), which derives the reported frequency/voltage from the
net power balance.
"""

import time

import numpy as np
from pymgrid import Microgrid
from pymgrid.modules import (
    GensetModule, BatteryModule, LoadModule, RenewableModule,
)

# ── Grid physics constants ────────────────────────────────────────────────────
FREQ_NOMINAL    = 50.0    # Hz  (use 60.0 for North America)
VOLT_NOMINAL    = 230.0   # V   (line-to-neutral, EU standard)
FREQ_DROOP      = 0.01    # Hz per kW of net imbalance  (droop coefficient)
VOLT_DROOP      = 0.5     # V  per kW of load above nominal
LOAD_NOMINAL    = 70.0    # kW  midpoint of our load timeseries


def build_microgrid(steps: int = 10_000) -> Microgrid:
    """PV + battery + genset + load microgrid with realistic timeseries."""
    rng = np.random.default_rng(seed=42)
    pv_series   = np.clip(rng.normal(50, 15, steps),  0, 100)
    load_series = np.clip(rng.normal(70, 10, steps), 20, 120)

    return Microgrid([
        GensetModule(
            running_min_production=10,
            running_max_production=50,
            genset_cost=0.5,
        ),
        BatteryModule(
            min_capacity=0, max_capacity=100,
            max_charge=50,  max_discharge=50,
            efficiency=0.95, init_soc=0.5,
        ),
        ("pv", RenewableModule(time_series=pv_series)),
        LoadModule(time_series=load_series),
    ])


def derive_frequency(net_balance_kw: float) -> float:
    freq = FREQ_NOMINAL + FREQ_DROOP * net_balance_kw
    freq += np.random.normal(0, 0.005)          # ±5 mHz sensor noise
    return round(float(np.clip(freq, 49.0, 51.0)), 4)


def derive_voltage(load_kw: float) -> float:
    volt = VOLT_NOMINAL - VOLT_DROOP * (load_kw - LOAD_NOMINAL)
    volt += np.random.normal(0, 0.3)            # ±0.3 V sensor noise
    return round(float(np.clip(volt, 200.0, 260.0)), 2)


def step_microgrid(mg: Microgrid, scmc_id: str) -> dict:
    action = {
        "genset":  [np.array([1.0, 0.6])],  # on, 60 % of max (normalised)
        "battery": [np.array([0.0])],         # hold
    }
    _, _, _, info = mg.run(action, normalized=True)

    def _kw(key, kind) -> float:
        return float(dict(info.get(key, [])).get(kind, 0.0))

    load_kw   = _kw("load",    "absorbed_energy")
    pv_kw     = _kw("pv",     "provided_energy")
    genset_kw = _kw("genset", "provided_energy")
    bat_kw    = _kw("battery","absorbed_energy")

    net_kw   = pv_kw + genset_kw - load_kw - bat_kw
    power_kw = round(pv_kw + genset_kw, 2)

    return {
        "scmc_id":   scmc_id,
        "timestamp": round(time.time(), 3),
        "power_kw":  power_kw,
        "frequency": derive_frequency(net_kw),
        "voltage":   derive_voltage(load_kw),
        "load_kw":   round(load_kw,  2),
        "pv_kw":     round(pv_kw,    2),
        "genset_kw": round(genset_kw,2),
        "net_kw":    round(net_kw,   2),
        "bat_soc":   round(float(mg.modules["battery"][0].soc), 3),
    }
