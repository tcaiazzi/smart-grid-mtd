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

# Wazuh agent: the hosts on the management network report to the manager on the
# SOC node and run its active responses. Installed on every node of the image,
# started only where the scenario enrols one. Same version as the manager
# (docker/soc/Dockerfile): an agent newer than its manager is refused.
RUN apt-get update && \
    apt-get install -y --no-install-recommends gnupg ca-certificates lsb-release procps && \
    curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends wazuh-agent=4.14.10-1 && \
    rm -rf /var/lib/apt/lists/*

# ttyd: the web terminal a team reaches a node through (nodes/common/team-access.sh).
# Debian 12 does not package it; the upstream static binary is pinned by version
# and checksum, per architecture.
RUN arch="$(dpkg --print-architecture)" && \
    case "$arch" in \
        amd64) bin=ttyd.x86_64; sum=8a217c968aba172e0dbf3f34447218dc015bc4d5e59bf51db2f2cd12b7be4f55 ;; \
        arm64) bin=ttyd.aarch64; sum=b38acadd89d1d396a0f5649aa52c539edbad07f4bc7348b27b4f4b7219dd4165 ;; \
        *) echo "no pinned ttyd for $arch" >&2; exit 1 ;; \
    esac && \
    curl -fsSL -o /usr/local/bin/ttyd "https://github.com/tsl0922/ttyd/releases/download/1.7.7/$bin" && \
    echo "$sum  /usr/local/bin/ttyd" | sha256sum -c - && \
    chmod 755 /usr/local/bin/ttyd

LABEL org.smartgrid-mtd.role="cps-node" \
      org.smartgrid-mtd.description="engine/plc/sensor/firewall/appserver/attacker base image (OT scenario)"
