# Kathará node image for the SOC of the cyber-physical scenario: the Wazuh
# manager the agents on the management network report to, and the analytics that
# read its alerts and ask it for the responses (nodes/soc/). Manager only — no
# indexer and no dashboard, which a lab that reads alerts.json does not need and
# which would triple the image.
FROM kathara/core:latest

ENV DEBIAN_FRONTEND=noninteractive

# python3 runs the analytics; pip installs its one dependency, networkx (the
# knowledge graph). curl is also how the manager's own REST API is driven, as a
# fallback, from inside the node.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        curl \
        gnupg \
        ca-certificates \
        lsb-release \
        procps && \
    curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends wazuh-manager=4.14.10-1 && \
    rm -rf /var/lib/apt/lists/*

# networkx only; pinned to requirements.txt (tests/core/test_guest_imports.py).
RUN pip3 install --no-cache-dir --break-system-packages networkx==3.6.1

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

LABEL org.smartgrid-mtd.role="cps-soc" \
      org.smartgrid-mtd.description="SOC node: Wazuh manager + analytics (OT scenario)"
