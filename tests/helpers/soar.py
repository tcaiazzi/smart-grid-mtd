"""Synthetic findings for the SOAR tests, shaped like the OT sensor's output.

These used to live in tests/test_soar_mapping.py, which two other test modules
imported — a test importing another test, so running one quietly ran part of
another and moving either broke both. They are fixtures, not tests, so they
live here.

See ``ot_sensor._finding`` for the real shape.
"""

from cyberrange.scenarios.cps import topology as cps

HMI, PLC, ROGUE = cps.HMI_IP, cps.PLC_IP, "10.20.0.99"


def finding(klass, t, src=None, name=None, conf=0.9, detector="rules", **evidence):
    """One rules-detector finding."""
    return {"i": 0, "t": t, "kind": "ot_finding", "detector": detector, "klass": klass,
            "reasons": [klass], "confidence": conf,
            "entities": {"src": src, "dst": cps.ENGINE_IP, "unit": 1, "register": None,
                         "name": name},
            "evidence": evidence}


def model(t, *features, conf=0.9):
    """One model-detector finding, with the features that drove it."""
    return finding("behavioral_anomaly", t, detector="model", conf=conf,
                   top=[{"feature": f, "z": 10.0} for f in features])
