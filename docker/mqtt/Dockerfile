# Custom Kathará node image for the Smart Grid AI-MTD lab.
# Based on kathara/core (Debian 12 + common net tools) with:
#   - mosquitto broker + clients (MQTT)
#   - python3 + paho-mqtt, numpy, scapy (traffic gen, MTD executor, packet capture)
#   - tcpreplay + editcap (wireshark-common) for replaying a real PCAP as
#     background traffic on the backbone collision domain
# Baking these in avoids slow/fragile apt+pip installs on every `lstart`.
FROM kathara/core:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        mosquitto \
        mosquitto-clients \
        python3 \
        python3-pip \
        tcpdump \
        libpcap0.8 \
        tcpreplay \
        wireshark-common && \
    rm -rf /var/lib/apt/lists/*

# Python deps (system-wide; --break-system-packages for Debian 12 PEP 668).
# Pinned to requirements.txt (tests/core/test_guest_imports.py checks it): the
# agents are tested on the host against those versions.
RUN pip3 install --no-cache-dir --break-system-packages \
        paho-mqtt==1.6.1 \
        numpy==2.4.6 \
        scapy==2.7.0 \
        pymgrid==1.2.2 \
        cryptography==48.0.1

# Disable the mosquitto systemd service auto-start; the lab startup script
# launches the broker explicitly with our config.
RUN systemctl disable mosquitto 2>/dev/null || true

LABEL org.smartgrid-mtd.role="node" \
      org.smartgrid-mtd.description="SEMP/SCMC/router/attacker base image"
