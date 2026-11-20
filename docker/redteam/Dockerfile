# Kathará node image for the attacker in the cps-recon scenario: the red team's
# own machine, with its reconnaissance tooling (nmap). It is deliberately NOT the
# cps node image — a real attacker brings its tools on its own box; the victim
# hosts (HMI etc.) stay on kathara/cps and are never pre-loaded with a scanner.
# Lean on purpose: the recon agents need the stdlib and networkx only (the
# knowledge graph the attacker derives its attack tree on).
FROM kathara/core:latest

ENV DEBIAN_FRONTEND=noninteractive

# python3 runs the recon/planner agents; nmap is the host/port and ICS discovery
# engine (incl. the modbus-discover NSE script); curl is a handy manual probe.
# iptables/iproute come from the base image for the node's routes.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        nmap \
        curl && \
    rm -rf /var/lib/apt/lists/*

# networkx only; pinned to requirements.txt (tests/core/test_guest_imports.py).
RUN pip3 install --no-cache-dir --break-system-packages networkx==3.6.1

LABEL org.smartgrid-mtd.role="redteam-node" \
      org.smartgrid-mtd.description="attacker box for the recon-driven cps-recon scenario (nmap)"
