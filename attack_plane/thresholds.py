"""Attacker decision thresholds, shared across the attack plane and the monitor.

Kept dependency-free (no torch/scapy/pandas) and separate from classify.py on
purpose: monitor/plot_sweep.py imports nothing else from the project, and
importing classify.py there would drag torch + scapy into a pure plotting
script just to read one float.
"""

# Minimum per-IP nanogrid fraction (see classify.rank_nanogrid_ips) for the
# attacker to act on an address: block it (classify._detect_nanogrid_ip) or
# mark it "detected" in a figure (monitor.plot_results, monitor.plot_sweep).
DETECT_THRESHOLD = 0.3
