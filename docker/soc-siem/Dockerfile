# Kathará node image for the SOC of the cps-soc lab: the cps SOC (kathara/soc:
# Wazuh manager + analytics) with the shipper that puts the manager's alerts in
# the indexer, as the Wazuh server does in a full deployment. A separate image,
# so the cps and cps-advisor SOCs, which read alerts.json only, stay as they are.
FROM kathara/soc

# Filebeat from the Wazuh repository the base image already trusts, at the
# version Wazuh 4.14 ships; its Wazuh module and index template pinned by
# checksum, at the manager's version.
RUN apt-get update && \
    apt-get install -y --no-install-recommends filebeat=7.10.2-2 && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fsSL -o /tmp/wazuh-filebeat.tar.gz \
        https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz && \
    echo "b0683f1d5d7c5d076ea3a565b0aa7ca92e6483f8a14e8b96799e6ee632da2284  /tmp/wazuh-filebeat.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/wazuh-filebeat.tar.gz -C /usr/share/filebeat/module && \
    rm /tmp/wazuh-filebeat.tar.gz && \
    curl -fsSL -o /etc/filebeat/wazuh-template.json \
        https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/extensions/elasticsearch/7.x/wazuh-template.json && \
    echo "b2d182f49cc68957849e77fd2d79528fd2273ebaec1106c9661c9e320577a089  /etc/filebeat/wazuh-template.json" | sha256sum -c - && \
    chmod 644 /etc/filebeat/wazuh-template.json

COPY --from=kathara/wazuh-pki /pki/root-ca.pem /pki/manager.pem /pki/manager-key.pem /pki/

LABEL org.smartgrid-mtd.role="cps-soc-siem" \
      org.smartgrid-mtd.description="SOC node of cps-soc: Wazuh manager + alert shipper + analytics"
