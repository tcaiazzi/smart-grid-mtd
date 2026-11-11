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
"""

# ── Transport ────────────────────────────────────────────────────────────────
MODBUS_PORT = 5020          # TCP port the engine's Modbus server listens on
UNIT_ID     = 1             # Modbus unit / slave id of the physical engine

# Modbus function codes the sensor cares about (writes to holding registers).
FC_READ_HOLDING_REGISTERS   = 0x03
FC_READ_INPUT_REGISTERS     = 0x04
FC_WRITE_SINGLE_REGISTER    = 0x06
FC_WRITE_MULTIPLE_REGISTERS = 0x10
READ_FUNCTION_CODES = (FC_READ_HOLDING_REGISTERS, FC_READ_INPUT_REGISTERS)
WRITE_FUNCTION_CODES = (FC_WRITE_SINGLE_REGISTER, FC_WRITE_MULTIPLE_REGISTERS)

# ── Input registers: sensors (engine -> PLC, read-only, fc 0x04) ─────────────
# address -> (name, scale, unit)
IR_V_LOAD    = 0   # voltage at the load bus          (pu * 1000)
IR_V_DG      = 1   # voltage at the DG bus            (pu * 1000)
IR_LINE_LOAD = 2   # feeder line loading              (percent * 10)
IR_P_LOAD    = 3   # load active power                (kW * 10)
IR_P_DG      = 4   # DG actual active power output    (kW * 10)
IR_ABNORMAL  = 5   # 1 if any bus is out of the normal voltage band, else 0

SENSOR_REGISTERS = {
    IR_V_LOAD:    ("v_load",    1000.0, "pu"),
    IR_V_DG:      ("v_dg",      1000.0, "pu"),
    IR_LINE_LOAD: ("line_load",  10.0,  "%"),
    IR_P_LOAD:    ("p_load",     10.0,  "kW"),
    IR_P_DG:      ("p_dg",       10.0,  "kW"),
    IR_ABNORMAL:  ("abnormal",    1.0,  "bool"),
}
SENSOR_COUNT = max(SENSOR_REGISTERS) + 1

# ── Holding registers: actuators (PLC -> engine, read/write) ─────────────────
HR_DG_SETPOINT = 0   # DG active-power setpoint   (kW * 10)
HR_SWITCH_CMD  = 1   # feeder breaker: 0 = closed, 1 = open
HR_CTRL_MODE   = 2   # control authority: 0 = AUTO (PLC regulates), 1 = MANUAL (operator)

CTRL_AUTO, CTRL_MANUAL = 0, 1

# address -> (name, scale, valid_lo, valid_hi) in ENGINEERING units.
# valid_lo/valid_hi define the legitimate command envelope; a write outside it
# is an out-of-range command (one of the sensor's finding classes).
ACTUATOR_REGISTERS = {
    HR_DG_SETPOINT: ("dg_setpoint", 10.0, 0.0, 60.0),   # DG rated 60 kW
    HR_SWITCH_CMD:  ("switch_cmd",   1.0, 0.0,  1.0),    # boolean breaker
    HR_CTRL_MODE:   ("ctrl_mode",    1.0, 0.0,  1.0),    # auto / manual
}
ACTUATOR_COUNT = max(ACTUATOR_REGISTERS) + 1

# Registers whose manipulation can move the physical process — a write here is
# "security-relevant" to the DPI sensor even if the value is in range.
SENSITIVE_ACTUATORS = {HR_DG_SETPOINT, HR_SWITCH_CMD, HR_CTRL_MODE}

# ── Access policy: who may do what over Modbus (the "sanctioned" behaviour) ──
# role -> allowed read function codes / writable holding registers. The PLC
# regulates the DG setpoint; the HMI operator may take manual control and
# dispatch a setpoint. Nobody operates the feeder breaker remotely (it is a
# local/protection device), so any remote breaker write violates policy.
ROLE_POLICY = {
    "plc": {"reads": {FC_READ_HOLDING_REGISTERS, FC_READ_INPUT_REGISTERS},
            "writes": {HR_DG_SETPOINT}},
    "hmi": {"reads": {FC_READ_HOLDING_REGISTERS, FC_READ_INPUT_REGISTERS},
            "writes": {HR_CTRL_MODE, HR_DG_SETPOINT}},
}

# ── Control constants shared by the PLC and the sensor ───────────────────────
DG_NOMINAL_KW = 20.0     # setpoint the PLC holds / returns to in AUTO
V_REG_LOW  = 0.97        # PLC regulation band (tighter than the alarm band)
V_REG_HIGH = 1.03

# ── Normal operating envelope (defines "out of normal state") ────────────────
V_BAND_LOW  = 0.95   # pu
V_BAND_HIGH = 1.05   # pu
LINE_LOAD_MAX = 100.0  # percent

REG_WORD_MAX = 0xFFFF


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


def actuator_out_of_range(address: int, raw: int):
    """Return (name, value, lo, hi) if a written actuator value is outside its
    legitimate envelope, else None. Unknown addresses are reported too (a write
    to a non-actuator holding register is itself anomalous)."""
    spec = ACTUATOR_REGISTERS.get(address)
    if spec is None:
        return ("unknown", None, None, None)
    name, scale, lo, hi = spec
    val = decode(raw, scale)
    if val < lo or val > hi:
        return (name, val, lo, hi)
    return None
