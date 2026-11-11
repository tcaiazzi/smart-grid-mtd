"""Synthetic findings for the SOAR tests, shaped like the OT sensor's output.

They are fixtures, not tests, so they live in helpers and not beside the tests
that use them: a test module importing another test module runs part of it as a
side effect, and ties the two together whenever either moves.

See ``ot_sensor._finding`` for the real shape.
"""

from cyberrange.scenarios.cps import topology as cps

HMI, PLC, ROGUE = cps.HMI_IP, cps.PLC_IP, "10.20.0.99"


def finding(klass, t, src=None, name=None, conf=0.9, detector="rules", **evidence):
    """One rules-detector finding."""
    return {
        "i": 0,
        "t": t,
        "kind": "ot_finding",
        "detector": detector,
        "klass": klass,
        "reasons": [klass],
        "confidence": conf,
        "entities": {"src": src, "dst": cps.ENGINE_IP, "unit": 1, "register": None, "name": name},
        "evidence": evidence,
    }


def model(t, *features, conf=0.9):
    """One model-detector finding, with the features that drove it."""
    return finding(
        "behavioral_anomaly",
        t,
        detector="model",
        conf=conf,
        top=[{"feature": f, "z": 10.0} for f in features],
    )
