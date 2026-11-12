# Kathará node image for the cyber-physical (OT/Modbus) scenario.
# Separate from kathara/mqtt so that image stays lean and reproducible: this one
# additionally carries pandapower (the physical-engine digital twin) and pymodbus
# (the Modbus/TCP engine server + PLC master). Base + the same net/capture tools.
FROM kathara/core:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        tcpdump \
        libpcap0.8 \
        iptables \
        curl && \
    rm -rf /var/lib/apt/lists/*

# Python deps (system-wide; --break-system-packages for Debian 12 PEP 668).
# pandapower pulls pandas/scipy/networkx; pymodbus pinned to the stable classic
# datastore API. numpy is used by the DPI sensor's (stdlib-only) featurizer.
RUN pip3 install --no-cache-dir --break-system-packages \
        numpy==2.4.6 \
        pandapower==3.5.6 \
        pymodbus==3.6.9

LABEL org.smartgrid-mtd.role="cps-node" \
      org.smartgrid-mtd.description="engine/plc/sensor/firewall/appserver/attacker base image (OT scenario)"
