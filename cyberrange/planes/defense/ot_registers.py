"""ot_registers.py — the OT "plant contract": the Modbus register map that binds
the physical engine (modbus_engine.py, the Modbus *server*), the PLC
(plc_controller.py, the Modbus *master*) and the passive DPI sensor
(ot_sensor.py) to one agreed layout.

This is the cyber-physical scenario's analogue of cyberrange/planes/attack/thresholds.py: a
single, dependency-free source of truth (pure stdlib — no numpy, no pymodbus, no
pandapower) so every party agrees on which register means what, and the sensor
can stay numpy/stdlib-only. It is copied flat onto the engine, plc and sensor
machines (see the scenario's guest_files.py); all three do
``from ot_registers import ...``.

Modbus holding/input registers are unsigned 16-bit words, so every physical
quantity is carried as a scaled integer: ``raw = round(value * scale)`` clamped
to [0, 65535], and ``value = raw / scale``. Sensors (engine -> PLC) live in the
**input registers** (read-only, function code 0x04). Actuators (PLC -> engine)
live in the **holding registers** (read/write, function codes 0x03 read /
0x06 write-single / 0x10 write-multiple) — writes only ever target holding
registers, which is exactly what the DPI sensor watches for.

The plant itself is a description (``DEFAULT_PLANT``, ``plant()``): feeders of
one radial layout, each served by the engine as a Modbus unit of its own, with
the same register map. What differs between feeders — line lengths, load, the
DG's setpoint and rating — and the plant's limits are data, handed to every
party that needs them as ``--plant-b64``. The module constants below are the
default plant's: what a party that serves or reads one feeder needs.
"""

import base64
import copy
import json

# ── Transport ────────────────────────────────────────────────────────────────
MODBUS_PORT = 5020  # TCP port the engine's Modbus server listens on

# Modbus function codes the sensor cares about (writes to holding registers).
FC_READ_HOLDING_REGISTERS = 0x03
FC_READ_INPUT_REGISTERS = 0x04
FC_WRITE_SINGLE_REGISTER = 0x06
FC_WRITE_MULTIPLE_REGISTERS = 0x10
READ_FUNCTION_CODES = (FC_READ_HOLDING_REGISTERS, FC_READ_INPUT_REGISTERS)
WRITE_FUNCTION_CODES = (FC_WRITE_SINGLE_REGISTER, FC_WRITE_MULTIPLE_REGISTERS)

# ── Input registers: sensors (engine -> PLC, read-only, fc 0x04) ─────────────
# address -> (name, scale, unit)
IR_V_LOAD = 0  # voltage at the load bus          (pu * 1000)
IR_V_DG = 1  # voltage at the DG bus            (pu * 1000)
IR_LINE_LOAD = 2  # feeder line loading              (percent * 10)
IR_P_LOAD = 3  # load active power                (kW * 10)
IR_P_DG = 4  # DG actual active power output    (kW * 10)
IR_ABNORMAL = 5  # 1 if any bus is out of the normal voltage band, else 0

SENSOR_REGISTERS = {
    IR_V_LOAD: ("v_load", 1000.0, "pu"),
    IR_V_DG: ("v_dg", 1000.0, "pu"),
    IR_LINE_LOAD: ("line_load", 10.0, "%"),
    IR_P_LOAD: ("p_load", 10.0, "kW"),
    IR_P_DG: ("p_dg", 10.0, "kW"),
    IR_ABNORMAL: ("abnormal", 1.0, "bool"),
}
SENSOR_COUNT = max(SENSOR_REGISTERS) + 1

# ── Holding registers: actuators (PLC -> engine, read/write) ─────────────────
HR_DG_SETPOINT = 0  # DG active-power setpoint   (kW * 10)
HR_SWITCH_CMD = 1  # feeder breaker: 0 = closed, 1 = open
HR_CTRL_MODE = 2  # control authority: 0 = AUTO (PLC regulates), 1 = MANUAL (operator)

CTRL_AUTO, CTRL_MANUAL = 0, 1

# address -> (name, scale, valid_lo, valid_hi) in ENGINEERING units.
# valid_lo/valid_hi define the legitimate command envelope; a write outside it
# is an out-of-range command (one of the sensor's finding classes).
ACTUATOR_REGISTERS = {
    HR_DG_SETPOINT: ("dg_setpoint", 10.0, 0.0, None),  # up to the feeder's DG rating, below
    HR_SWITCH_CMD: ("switch_cmd", 1.0, 0.0, 1.0),  # boolean breaker
    HR_CTRL_MODE: ("ctrl_mode", 1.0, 0.0, 1.0),  # auto / manual
}
ACTUATOR_COUNT = max(ACTUATOR_REGISTERS) + 1

# Registers whose manipulation can move the physical process — a write here is
# "security-relevant" to the DPI sensor even if the value is in range.
SENSITIVE_ACTUATORS = {HR_DG_SETPOINT, HR_SWITCH_CMD, HR_CTRL_MODE}

# ── Access policy: who may do what over Modbus (the "sanctioned" behaviour) ──
# role -> allowed read function codes / writable holding registers. The PLC
# regulates the DG setpoint; the HMI operator may take manual control and
# dispatch a setpoint. Nobody operates the feeder breaker remotely (it is a
# local/protection device), so any remote breaker write violates policy —
# except from the responder: the boundary device, when the automated response
# returns the plant to a safe state (control authority, setpoint, breaker).
ROLE_POLICY = {
    "plc": {
        "reads": {FC_READ_HOLDING_REGISTERS, FC_READ_INPUT_REGISTERS},
        "writes": {HR_DG_SETPOINT},
    },
    "hmi": {
        "reads": {FC_READ_HOLDING_REGISTERS, FC_READ_INPUT_REGISTERS},
        "writes": {HR_CTRL_MODE, HR_DG_SETPOINT},
    },
    "responder": {
        "reads": {FC_READ_HOLDING_REGISTERS, FC_READ_INPUT_REGISTERS},
        "writes": {HR_CTRL_MODE, HR_DG_SETPOINT, HR_SWITCH_CMD},
    },
}

REG_WORD_MAX = 0xFFFF

# ── The plant ────────────────────────────────────────────────────────────────
# A radial LV feeder per Modbus unit, all fed from one slack bus:
#     slack --(breaker)--feeder-- load bus --dg_tie-- DG bus
# The DG tie is long enough that a full-rated DG at nominal load overvolts its
# bus: an in-range command can still be unsafe.
DEFAULT_PLANT = {
    "name": "cps-lv-feeder",
    "vn_kv": 0.4,
    "slack_vm_pu": 1.02,
    "line": {"r_ohm_per_km": 0.642, "x_ohm_per_km": 0.083, "c_nf_per_km": 0.0, "max_i_ka": 0.142},
    # v_band: the normal operating envelope ("out of normal state" outside it);
    # v_reg: the PLC's regulation band, tighter than the alarm band.
    "limits": {"v_band": [0.95, 1.05], "v_reg": [0.97, 1.03], "line_load_max": 100.0},
    "feeders": [
        {
            "unit": 1,
            "feeder_km": 0.14,
            "dg_tie_km": 0.20,
            "load_kw": 50.0,
            "load_sigma_kw": 4.0,
            "dg_kw": 20.0,  # the setpoint the PLC holds / returns to in AUTO
            "dg_rating_kw": 60.0,  # the top of the setpoint's legitimate envelope
        }
    ],
}
FEEDER_KEYS = (
    "unit",
    "feeder_km",
    "dg_tie_km",
    "load_kw",
    "load_sigma_kw",
    "dg_kw",
    "dg_rating_kw",
)


def plant(arg=None) -> dict:
    """The plant description: ``arg`` is None (the default plant), a dict, or
    its JSON — plain or base64, as ``--plant-b64`` carries it. Checked here, so
    that every party refuses the same malformed plant."""
    if arg is None:
        p = copy.deepcopy(DEFAULT_PLANT)
    elif isinstance(arg, dict):
        p = copy.deepcopy(arg)
    else:
        text = arg if arg.lstrip().startswith("{") else base64.b64decode(arg).decode()
        p = json.loads(text)
    units = [f.get("unit") for f in p.get("feeders", [])]
    if not units:
        raise ValueError("a plant has at least one feeder")
    if len(set(units)) != len(units) or not all(
        isinstance(u, int) and 1 <= u <= 247 for u in units
    ):
        raise ValueError(f"feeder units must be distinct Modbus unit ids (1-247), got {units}")
    for f in p["feeders"]:
        missing = [k for k in FEEDER_KEYS if k not in f]
        if missing:
            raise ValueError(f"feeder {f.get('unit')} misses {missing}")
        if not 0 <= f["dg_kw"] <= f["dg_rating_kw"]:
            raise ValueError(f"feeder {f['unit']}: the DG's setpoint is outside its rating")
    return p


def plant_b64(p) -> str:
    """``p`` as the ``--plant-b64`` argument: JSON, base64, nothing a shell reads."""
    return base64.b64encode(json.dumps(plant(p), sort_keys=True).encode()).decode()


def units(p):
    """The plant's Modbus unit ids, in feeder order."""
    return [f["unit"] for f in p["feeders"]]


def feeder(p, unit=None) -> dict:
    """The feeder served as ``unit`` (default: the first)."""
    if unit is None:
        return p["feeders"][0]
    for f in p["feeders"]:
        if f["unit"] == unit:
            return f
    raise KeyError(f"the plant has no unit {unit}")


def envelope(p, unit=None) -> dict:
    """{address: (name, scale, lo, hi)} of ``unit``'s actuators: the register
    map, with the setpoint's top at that feeder's DG rating."""
    out = dict(ACTUATOR_REGISTERS)
    name, scale, lo, _hi = out[HR_DG_SETPOINT]
    out[HR_DG_SETPOINT] = (name, scale, lo, float(feeder(p, unit)["dg_rating_kw"]))
    return out


# ── The default plant, as constants ──────────────────────────────────────────
_DEFAULT_FEEDER = DEFAULT_PLANT["feeders"][0]
UNIT_ID = _DEFAULT_FEEDER["unit"]  # Modbus unit id of the default plant's feeder
ACTUATOR_REGISTERS[HR_DG_SETPOINT] = (
    *ACTUATOR_REGISTERS[HR_DG_SETPOINT][:3],
    _DEFAULT_FEEDER["dg_rating_kw"],
)
DG_NOMINAL_KW = _DEFAULT_FEEDER["dg_kw"]
V_REG_LOW, V_REG_HIGH = DEFAULT_PLANT["limits"]["v_reg"]
V_BAND_LOW, V_BAND_HIGH = DEFAULT_PLANT["limits"]["v_band"]  # pu
LINE_LOAD_MAX = DEFAULT_PLANT["limits"]["line_load_max"]  # percent


def encode(value: float, scale: float) -> int:
    """Engineering value -> unsigned 16-bit register word (clamped)."""
    raw = int(round(value * scale))
    return max(0, min(REG_WORD_MAX, raw))


def decode(raw: int, scale: float) -> float:
    """Register word -> engineering value."""
    return (raw & REG_WORD_MAX) / scale


def actuator_value(address: int, raw: int):
    """Decode a holding-register word to its engineering value, or None if the
    address is not a known actuator."""
    spec = ACTUATOR_REGISTERS.get(address)
    if spec is None:
        return None
    return decode(raw, spec[1])


def actuator_out_of_range(address: int, raw: int, actuators=None):
    """Return (name, value, lo, hi) if a written actuator value is outside its
    legitimate envelope, else None. Unknown addresses are reported too (a write
    to a non-actuator holding register is itself anomalous). ``actuators`` is
    one unit's envelope (``envelope(plant, unit)``); default: the default plant's."""
    spec = (actuators or ACTUATOR_REGISTERS).get(address)
    if spec is None:
        return ("unknown", None, None, None)
    name, scale, lo, hi = spec
    val = decode(raw, scale)
    if val < lo or val > hi:
        return (name, val, lo, hi)
    return None
