#!/usr/bin/env python3
"""ot_sensor.py — passive Modbus-DPI sensor + collector for the cyber-physical
scenario. It observes the OT link (where the PLC and the HMI talk to the
physical engine over Modbus/TCP) without any routable presence on it, parses
Modbus requests AND responses, and turns suspicious behaviour into structured
*findings* from two detectors:

rules (detector="rules") — the plant contract, deterministic and explainable:
  - out_of_range_command     : a write outside the actuator's envelope;
  - unauthorized_write[_to_actuator] / unauthorized_read : a client that is in
                               no role of the access policy;
  - policy_violation         : a known role using a function code or writing a
                               register its role may not (e.g. a remote breaker
                               write from the HMI);
  - unsafe_command           : a sensitive write followed, within a few
                               seconds, by the OBSERVED physics leaving the
                               voltage band (state decoded from the read
                               responses on the wire);
  - manual_mode_excursion    : control authority is MANUAL while the observed
                               voltage stays out of band.
model (detector="model") — ot_model.py: per-window behavioural features scored
  by a robust anomaly model calibrated online on the first --learn-seconds.

The PLC's regulation and the HMI operator's safe manual dispatches raise
nothing. Alerts are edge-triggered (raised once per key) and cleared when the
condition goes away, so recovery is measurable.

Copied flat onto the sensor machine (see the scenario's guest_files.py).
Stdlib + numpy only: Ethernet/IPv4/TCP/Modbus are parsed by hand (no scapy).
Findings ride the existing event bus (mtd_telemetry.Telemetry).
See ot_registers for the register map / envelopes / policy this reasons over.
"""

import argparse
import socket
import struct
import time

import ot_registers as reg
from mtd_telemetry import Telemetry

try:
    from ot_model import RobustAnomalyModel, WindowFeaturizer
except Exception:  # model is optional (numpy missing)
    RobustAnomalyModel = WindowFeaturizer = None

try:
    from mtd_dashboard import DashboardServer
except Exception:  # dashboard is optional
    DashboardServer = None

ETH_P_ALL = 0x0003
ETHERTYPE_IPV4 = 0x0800
IPPROTO_TCP = 6
TCP_SYN, TCP_ACK = 0x02, 0x10

UNSAFE_WINDOW_S = 10.0  # a write is blamed for an excursion seen this soon after
ACQUIT_GRACE_S = 2.0  # an in-band observation this long after a write acquits it
# (sensor registers lag the actuators by up to a physics step)
EXCURSION_MIN_OBS = 3  # consecutive out-of-band observations in MANUAL
ALERT_QUIET_S = 10.0  # write-time alerts clear after this long without findings
PENDING_TTL_S = 10.0  # forget unanswered requests


# ── pure parsers (unit-tested off-wire) ──────────────────────────────────────
def parse_ethernet(frame: bytes):
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    return ethertype, frame[14:]


def parse_ipv4(payload: bytes):
    if len(payload) < 20:
        return None
    ver_ihl = payload[0]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if len(payload) < ihl:
        return None
    proto = payload[9]
    src = socket.inet_ntoa(payload[12:16])
    dst = socket.inet_ntoa(payload[16:20])
    return proto, src, dst, payload[ihl:]


def parse_tcp(payload: bytes):
    if len(payload) < 20:
        return None
    sport, dport = struct.unpack("!HH", payload[0:4])
    data_offset = (payload[12] >> 4) * 4
    if len(payload) < data_offset:
        return None
    return sport, dport, payload[data_offset:]


def tcp_flags(payload: bytes) -> int:
    return payload[13] if len(payload) >= 14 else 0


def parse_modbus_adus(tcp_payload: bytes):
    """Split a TCP payload into Modbus/TCP ADUs (MBAP header + PDU), requests or
    responses alike. Returns [{"txn", "unit", "fc", "pdu"}]; stops at the first
    malformed / non-Modbus ADU."""
    adus = []
    buf = tcp_payload
    while len(buf) >= 8:  # MBAP(7) + at least the function code
        txn, proto, length, unit = struct.unpack("!HHHB", buf[0:7])
        if proto != 0:  # not Modbus/TCP
            break
        adu_len = 6 + length  # length counts the unit id + PDU
        if length < 2 or adu_len > len(buf):
            break
        pdu = buf[7:adu_len]
        adus.append({"txn": txn, "unit": unit, "fc": pdu[0], "pdu": pdu})
        buf = buf[adu_len:]
    return adus


def decode_request(adu):
    """Request semantics: reads -> {"address","qty"}; writes -> {"address","values"};
    None when malformed or not a function code the sensor models."""
    fc, pdu = adu["fc"], adu["pdu"]
    if fc in reg.READ_FUNCTION_CODES and len(pdu) >= 5:
        address, qty = struct.unpack("!HH", pdu[1:5])
        return {"address": address, "qty": qty}
    if fc == reg.FC_WRITE_SINGLE_REGISTER and len(pdu) >= 5:
        address, value = struct.unpack("!HH", pdu[1:5])
        return {"address": address, "values": [value]}
    if fc == reg.FC_WRITE_MULTIPLE_REGISTERS and len(pdu) >= 6:
        address, qty = struct.unpack("!HH", pdu[1:5])
        byte_count = pdu[5]
        if len(pdu) >= 6 + byte_count and byte_count == 2 * qty:
            vals = [struct.unpack("!H", pdu[6 + 2 * i : 8 + 2 * i])[0] for i in range(qty)]
            return {"address": address, "values": vals}
    return None


def decode_read_response(adu):
    """Register words of a fc 0x03/0x04 response, or None (exception/malformed)."""
    fc, pdu = adu["fc"], adu["pdu"]
    if fc not in reg.READ_FUNCTION_CODES or len(pdu) < 2:
        return None
    bc = pdu[1]
    if bc % 2 or len(pdu) < 2 + bc:
        return None
    return [struct.unpack("!H", pdu[2 + 2 * i : 4 + 2 * i])[0] for i in range(bc // 2)]


def parse_modbus_writes(tcp_payload: bytes):
    """Modbus WRITE requests in a TCP payload:
      [{"unit", "fc", "address", "values": [..]}]  (values length 1 for fc 0x06).
    Non-write function codes and malformed frames are skipped."""
    writes = []
    for adu in parse_modbus_adus(tcp_payload):
        if adu["fc"] not in reg.WRITE_FUNCTION_CODES:
            continue
        req = decode_request(adu)
        if req is not None:
            writes.append(
                {
                    "unit": adu["unit"],
                    "fc": adu["fc"],
                    "address": req["address"],
                    "values": req["values"],
                }
            )
    return writes


def registers_to_state(fc, address, words):
    """Decode a read response into named process state (engineering units)."""
    state = {}
    for i, raw in enumerate(words):
        a = address + i
        if fc == reg.FC_READ_INPUT_REGISTERS and a in reg.SENSOR_REGISTERS:
            name, scale, _unit = reg.SENSOR_REGISTERS[a]
            state[name] = reg.decode(raw, scale)
        elif fc == reg.FC_READ_HOLDING_REGISTERS and a in reg.ACTUATOR_REGISTERS:
            name, scale, _lo, _hi = reg.ACTUATOR_REGISTERS[a]
            state[name] = reg.decode(raw, scale)
    if "abnormal" in state:
        state["abnormal"] = int(state["abnormal"])
    if "ctrl_mode" in state:
        state["ctrl_mode"] = int(state["ctrl_mode"])
    return state


def _finding(klass, reasons, confidence, src, dst, unit, address, evidence, detector="rules"):
    spec = reg.ACTUATOR_REGISTERS.get(address) if address is not None else None
    return {
        "detector": detector,
        "klass": klass,
        "reasons": reasons,
        "confidence": round(confidence, 3),
        "entities": {
            "src": src,
            "dst": dst,
            "unit": unit,
            "register": address,
            "name": spec[0] if spec else ("unknown" if address is not None else None),
        },
        "evidence": evidence,
    }


def classify_write(src_ip: str, dst_ip: str, write: dict, authorized_writer: str, policy=None):
    """Write-time rules. Return a finding dict for a suspicious write, or None.

    `policy` maps client IP -> role (see ot_registers.ROLE_POLICY). Without it,
    `authorized_writer` (the PLC) is the only known client — the original,
    source-only behaviour."""
    if policy is None:
        policy = {authorized_writer: "plc"} if authorized_writer else {}
    addr = write["address"]
    role = policy.get(src_ip)
    reasons = []
    confidence = 0.0

    for v in write["values"]:
        if reg.actuator_out_of_range(addr, v) is not None:
            reasons.append("out_of_range_command")
            confidence = max(confidence, 0.9)
            break

    sensitive = addr in reg.SENSITIVE_ACTUATORS
    if policy and role is None:
        if sensitive:
            reasons.append("unauthorized_write_to_actuator")
            confidence = max(confidence, 0.95)
        else:
            reasons.append("unauthorized_write")
            confidence = max(confidence, 0.7)
    elif role is not None and addr not in reg.ROLE_POLICY.get(role, {}).get("writes", set()):
        reasons.append("policy_violation")
        confidence = max(confidence, 0.9 if sensitive else 0.7)

    if not reasons:
        return None
    return _finding(
        reasons[0],
        reasons,
        confidence,
        src_ip,
        dst_ip,
        write["unit"],
        addr,
        {
            "fc": write["fc"],
            "raw": write["values"],
            "value": reg.actuator_value(addr, write["values"][0]),
            "role": role,
            "ts": round(time.time(), 3),
        },
    )


def classify_read(src_ip, dst_ip, fc, unit, policy):
    """Read-time rules: reconnaissance from an unknown client, or a function code
    outside the client's role."""
    if not policy:
        return None
    role = policy.get(src_ip)
    if role is None:
        return _finding(
            "unauthorized_read",
            ["unauthorized_read"],
            0.6,
            src_ip,
            dst_ip,
            unit,
            None,
            {"fc": fc, "ts": round(time.time(), 3)},
        )
    if fc not in reg.ROLE_POLICY.get(role, {}).get("reads", set()):
        return _finding(
            "policy_violation",
            ["policy_violation"],
            0.7,
            src_ip,
            dst_ip,
            unit,
            None,
            {"fc": fc, "role": role, "ts": round(time.time(), 3)},
        )
    return None


_ACTUATOR_ADDR = {spec[0]: addr for addr, spec in reg.ACTUATOR_REGISTERS.items()}


class ProcessRules:
    """Stateful, physics-aware rules over the state observed on the wire.

    unsafe_command attribution: a write is a suspect only if it CHANGED an
    actuator (re-writing the value in force — the PLC's steady regulation —
    cannot cause anything) and no in-band observation has acquitted it since
    (one seen more than ACQUIT_GRACE_S after the write, i.e. after the physics
    has stepped on it)."""

    def __init__(self):
        self.last_writes = []  # [(t, src, dst, unit, address, value)] state-changing writes
        self.blamed = set()  # writes already reported as unsafe
        self.hr_state = {}  # address -> value in force (from writes / fc03 reads)
        self.ctrl_mode = reg.CTRL_AUTO
        self.excursion_obs = 0
        self.last_in_band_t = None

    def note_write(self, t, src, dst, unit, address, value):
        if address not in reg.SENSITIVE_ACTUATORS:
            return
        prev = self.hr_state.get(address)
        self.hr_state[address] = value
        if address == reg.HR_CTRL_MODE and value is not None:
            self.ctrl_mode = int(round(value))
        if value is not None and prev is not None and abs(value - prev) < 1e-9:
            return  # no change -> not a suspect
        self.last_writes.append((t, src, dst, unit, address, value))
        self.last_writes = [w for w in self.last_writes if t - w[0] <= UNSAFE_WINDOW_S]

    @staticmethod
    def out_of_band(state):
        vs = [state[k] for k in ("v_load", "v_dg") if state.get(k) is not None]
        if state.get("abnormal"):
            return True
        return any(v < reg.V_BAND_LOW or v > reg.V_BAND_HIGH for v in vs)

    def on_state(self, t, state):
        """-> (findings, active_conditions). active_conditions is the set of
        process alert keys currently true (for raise/clear)."""
        findings, active = [], set()
        if state.get("ctrl_mode") is not None:
            self.ctrl_mode = state["ctrl_mode"]
        for name, addr in _ACTUATOR_ADDR.items():
            if state.get(name) is not None:
                self.hr_state[addr] = state[name]
        has_v = any(state.get(k) is not None for k in ("v_load", "v_dg", "abnormal"))
        if not has_v:
            return findings, None  # e.g. a holding-register read: no voltage info
        oob = self.out_of_band(state)
        ev = {k: state.get(k) for k in ("v_load", "v_dg", "abnormal")}
        if oob:
            acquit_before = (
                self.last_in_band_t - ACQUIT_GRACE_S
                if self.last_in_band_t is not None
                else float("-inf")
            )
            recent = [
                w
                for w in self.last_writes
                if 0 <= t - w[0] <= UNSAFE_WINDOW_S
                and w[0] > acquit_before
                and w not in self.blamed
            ]
            for w in recent:
                self.blamed.add(w)
                wt, src, dst, unit, addr, value = w
                findings.append(
                    _finding(
                        "unsafe_command",
                        ["unsafe_command"],
                        0.85,
                        src,
                        dst,
                        unit,
                        addr,
                        {
                            **ev,
                            "value": value,
                            "write_t": round(wt, 3),
                            "lag_s": round(t - wt, 3),
                            "ts": round(t, 3),
                        },
                    )
                )
            if self.ctrl_mode == reg.CTRL_MANUAL:
                self.excursion_obs += 1
                if self.excursion_obs >= EXCURSION_MIN_OBS:
                    active.add(("manual_mode_excursion",))
                    findings.append(
                        _finding(
                            "manual_mode_excursion",
                            ["manual_mode_excursion"],
                            0.9,
                            None,
                            None,
                            reg.UNIT_ID,
                            reg.HR_CTRL_MODE,
                            {**ev, "observations": self.excursion_obs, "ts": round(t, 3)},
                        )
                    )
            else:
                self.excursion_obs = 0
            active.add(("out_of_band",))
        else:
            self.excursion_obs = 0
            self.last_in_band_t = t
        return findings, active


# ── live sensor ──────────────────────────────────────────────────────────────
class OTSensor:
    def __init__(
        self,
        iface,
        engine_ip,
        engine_port,
        authorized_writer,
        telemetry: Telemetry,
        hmi_ip=None,
        detectors=("rules", "model"),
        learn_seconds=45.0,
        window_s=1.0,
        model_k=6.0,
    ):
        self.iface = iface
        self.engine_ip = engine_ip
        self.engine_port = engine_port
        self.authorized_writer = authorized_writer
        self.telemetry = telemetry
        self.policy = {}
        if authorized_writer:
            self.policy[authorized_writer] = "plc"
        if hmi_ip:
            self.policy[hmi_ip] = "hmi"
        self.detectors = set(detectors)
        self.rules = ProcessRules()
        self._pending = {}  # (client_ip, client_port, txn) -> (fc, address, t)
        self._alerts = {}  # key -> {"klass","last_t","detector"}
        self.learn_seconds = float(learn_seconds)
        self._t0 = None
        self.featurizer = self.model = None
        if "model" in self.detectors and WindowFeaturizer is not None:
            self.featurizer = WindowFeaturizer(
                authorized_writer,
                window_s=window_s,
                setpoint_register=reg.HR_DG_SETPOINT,
                mode_register=reg.HR_CTRL_MODE,
                manual_value=reg.CTRL_MANUAL,
            )
            self.model = RobustAnomalyModel(k=model_k)
        self._model_quiet = 0
        self._early_win = None

    # ── alerts ───────────────────────────────────────────────────────────────
    def _raise(self, key, finding, t):
        a = self._alerts.get(key)
        if a is None:
            self.telemetry.emit(
                "ot_alert",
                state="raised",
                detector=finding["detector"],
                klass=finding["klass"],
                confidence=finding["confidence"],
                entities=finding["entities"],
            )
            a = {
                "klass": finding["klass"],
                "detector": finding["detector"],
                "raised_t": t,
                "entities": finding["entities"],
            }
            self._alerts[key] = a
        a["last_t"] = t

    def _clear(self, key, t):
        a = self._alerts.pop(key, None)
        if a is not None:
            self.telemetry.emit(
                "ot_alert",
                state="cleared",
                detector=a["detector"],
                klass=a["klass"],
                entities=a["entities"],
                duration_s=round(t - a["raised_t"], 3),
            )

    def _emit(self, finding, t, key=None):
        self.telemetry.emit("ot_finding", **finding)
        if key is None:
            e = finding["entities"]
            key = (finding["detector"], finding["klass"], e.get("src"), e.get("register"))
        self._raise(key, finding, t)

    # ── packet path ──────────────────────────────────────────────────────────
    def _handle_frame(self, frame: bytes, now=None):
        now = time.time() if now is None else now
        if self._t0 is None:
            self._t0 = now
        eth = parse_ethernet(frame)
        if not eth or eth[0] != ETHERTYPE_IPV4:
            return
        ip = parse_ipv4(eth[1])
        if not ip or ip[0] != IPPROTO_TCP:
            return
        _proto, src, dst, l4 = ip
        tcp = parse_tcp(l4)
        if not tcp:
            return
        sport, dport, payload = tcp
        to_engine = dport == self.engine_port and (not self.engine_ip or dst == self.engine_ip)
        from_engine = sport == self.engine_port and (not self.engine_ip or src == self.engine_ip)
        if not (to_engine or from_engine):
            return
        self._tick(now)
        if to_engine and (tcp_flags(l4) & (TCP_SYN | TCP_ACK)) == TCP_SYN and self.featurizer:
            self._model_windows(self.featurizer.observe_syn(now, src))
        for adu in parse_modbus_adus(payload):
            if to_engine:
                self._on_request(now, src, dst, sport, adu)
            else:
                self._on_response(now, src, dst, dport, adu)

    def _on_request(self, t, src, dst, sport, adu):
        fc, unit = adu["fc"], adu["unit"]
        req = decode_request(adu)
        if fc in reg.READ_FUNCTION_CODES:
            if req is not None:
                self._pending[(src, sport, adu["txn"])] = (fc, req["address"], t)
            if self.featurizer:
                self._model_windows(self.featurizer.observe_read(t, src, fc))
            if "rules" in self.detectors:
                f = classify_read(src, dst, fc, unit, self.policy)
                if f:
                    self._emit(f, t)
            return
        if fc in reg.WRITE_FUNCTION_CODES and req is not None:
            w = {"unit": unit, "fc": fc, "address": req["address"], "values": req["values"]}
            value = reg.actuator_value(w["address"], w["values"][0])
            self.rules.note_write(t, src, dst, unit, w["address"], value)
            if self.featurizer:
                self._model_windows(self.featurizer.observe_write(t, src, w["address"], value))
                self._model_early(t)
            if "rules" in self.detectors:
                f = classify_write(src, dst, w, self.authorized_writer, policy=self.policy)
                if f:
                    self._emit(f, t)
            return
        if "rules" in self.detectors and self.policy:
            # Any other function code (diagnostics, device id, coils, ...)
            f = classify_read(src, dst, fc, unit, self.policy) or _finding(
                "policy_violation",
                ["policy_violation"],
                0.7,
                src,
                dst,
                unit,
                None,
                {"fc": fc, "role": self.policy.get(src), "ts": round(t, 3)},
            )
            self._emit(f, t)

    def _on_response(self, t, src, dst, dport, adu):
        pend = self._pending.pop((dst, dport, adu["txn"]), None)
        if pend is None:
            return
        fc, address, _t_req = pend
        words = decode_read_response(adu)
        if words is None:
            return
        state = registers_to_state(fc, address, words)
        if not state:
            return
        if self.featurizer:
            self._model_windows(self.featurizer.observe_state(t, state))
        if "rules" in self.detectors:
            findings, active = self.rules.on_state(t, state)
            for f in findings:
                key = ("rules", f["klass"]) if f["klass"] == "manual_mode_excursion" else None
                self._emit(f, t, key=key)
            if active is not None and ("manual_mode_excursion",) not in active:
                self._clear(("rules", "manual_mode_excursion"), t)

    # ── model ────────────────────────────────────────────────────────────────
    def _model_finding(self, w_start, score, z, partial):
        return _finding(
            "behavioral_anomaly",
            ["behavioral_anomaly"],
            min(0.99, 0.5 + 0.05 * score),
            None,
            self.engine_ip,
            reg.UNIT_ID,
            None,
            {
                "score": round(score, 2),
                "threshold": round(self.model.threshold, 2),
                "window_start": round(w_start, 3),
                "partial": partial,
                "top": self.model.explain(z),
                "ts": round(w_start, 3),
            },
            detector="model",
        )

    def _model_early(self, t):
        """Score the still-open window right after a write. Counts and maxima only
        grow inside a window, so a partial window that is already anomalous flags
        the write immediately instead of up to one window later."""
        if not self.model or not self.model.fitted:
            return
        win = self.featurizer.current_window
        if win is None or win == self._early_win:
            return
        anomalous, score, z = self.model.is_anomalous(self.featurizer.peek(t))
        if anomalous:
            self._early_win = win
            self._model_quiet = 0
            f = self._model_finding(win * self.featurizer.window_s, score, z, partial=True)
            self.telemetry.emit("ot_finding", **f)
            self._raise(("model",), f, t)

    def _model_windows(self, closed):
        if not self.model:
            return
        for w_start, vec in closed:
            if not self.model.fitted:
                if (
                    self._t0 is not None
                    and w_start + self.featurizer.window_s <= self._t0 + self.learn_seconds
                ):
                    self.model.add_calibration(vec)
                    continue
                try:
                    self.model.fit()
                    self.telemetry.emit(
                        "model_fitted",
                        threshold=round(self.model.threshold, 3),
                        windows=len(self.model._calib),
                    )
                except ValueError as e:
                    self.telemetry.emit("model_error", error=str(e))
                    self.model = None
                    return
            anomalous, score, z = self.model.is_anomalous(vec)
            if anomalous:
                self._model_quiet = 0
                f = self._model_finding(w_start, score, z, partial=False)
                self.telemetry.emit("ot_finding", **f)
                self._raise(("model",), f, w_start)
            else:
                self._model_quiet += 1
                if self._model_quiet >= 3:
                    self._clear(("model",), w_start)

    def _tick(self, now):
        """Housekeeping: close model windows, expire stale requests, clear
        write-time alerts that went quiet."""
        if self.featurizer:
            self._model_windows(self.featurizer.flush(now))
        for k in [k for k, v in self._pending.items() if now - v[2] > PENDING_TTL_S]:
            del self._pending[k]
        for k, a in list(self._alerts.items()):
            if (
                k[0] == "rules"
                and a["klass"] not in ("manual_mode_excursion",)
                and now - a["last_t"] > ALERT_QUIET_S
            ):
                self._clear(k, now)

    def run(self, duration=0.0):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.bind((self.iface, 0))
        s.settimeout(0.5)
        self.telemetry.emit(
            "sensor_up",
            iface=self.iface,
            engine=self.engine_ip,
            port=self.engine_port,
            policy=self.policy,
            detectors=sorted(self.detectors),
            learn_seconds=self.learn_seconds,
        )
        start = time.time()
        self._t0 = start
        while True:
            try:
                frame, addr = s.recvfrom(65535)
                # AF_PACKET delivers outgoing copies too; the sensor has no IP on
                # this NIC, so every frame is someone else's — keep them all.
                self._handle_frame(frame)
            except socket.timeout:
                self._tick(time.time())
            if duration and (time.time() - start) >= duration:
                break
        s.close()


def main():
    ap = argparse.ArgumentParser(description="Passive Modbus-DPI OT sensor")
    ap.add_argument("--iface", default="eth0", help="OT-link interface to sniff")
    ap.add_argument("--engine-ip", default=None, help="physical engine IP (Modbus slave)")
    ap.add_argument("--engine-port", type=int, default=reg.MODBUS_PORT)
    ap.add_argument(
        "--plc-ip",
        "--authorized-writer",
        dest="plc_ip",
        default=None,
        help="the PLC's IP (role 'plc' in the access policy)",
    )
    ap.add_argument("--hmi-ip", default=None, help="the HMI's IP (role 'hmi')")
    ap.add_argument(
        "--detectors", default="rules,model", help="comma list of detectors to run: rules, model"
    )
    ap.add_argument(
        "--learn-seconds",
        type=float,
        default=45.0,
        help="model calibration period (assumed attack-free)",
    )
    ap.add_argument("--window", type=float, default=1.0, help="model window (s)")
    ap.add_argument("--model-k", type=float, default=6.0, help="model z threshold floor")
    ap.add_argument("--telemetry-file", default="telemetry.jsonl")
    ap.add_argument("--dashboard-port", type=int, default=0)
    ap.add_argument("--duration", type=float, default=0.0)
    args = ap.parse_args()

    tel = Telemetry(args.telemetry_file)
    if args.dashboard_port and DashboardServer is not None:
        DashboardServer(tel, args.dashboard_port).start()
    detectors = tuple(d.strip() for d in args.detectors.split(",") if d.strip())
    OTSensor(
        args.iface,
        args.engine_ip,
        args.engine_port,
        args.plc_ip,
        tel,
        hmi_ip=args.hmi_ip,
        detectors=detectors,
        learn_seconds=args.learn_seconds,
        window_s=args.window,
        model_k=args.model_k,
    ).run(duration=args.duration)


if __name__ == "__main__":
    main()
