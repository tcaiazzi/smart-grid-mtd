# Kathará node image for the Wazuh dashboard of the cps-soc lab: the official
# image, at the manager's version, with what a lab node needs on top. Its
# configuration comes from nodes/wazuh/dashboard/, staged at deploy.
#
# Root: Kathará runs a node's startup commands as the image's user, and the
# official one cannot address an interface. OpenSearch Dashboards refuses to
# run as root, so the start script drops back to its user (uid 1000).
FROM wazuh/wazuh-dashboard:4.14.10

USER root
# tar: Kathará stages a node's files by unpacking a tar inside it; without
# one the node starts with none of them, its start script included.
RUN dnf install -y iproute iptables-nft tar && dnf clean all

COPY --from=kathara/wazuh-pki /pki/root-ca.pem /pki/dashboard.pem /pki/dashboard-key.pem /pki/

# Kathará runs every command of the node from here, and the platform reads a
# service's console log at the root: the official image works elsewhere.
WORKDIR /

LABEL org.smartgrid-mtd.role="cps-soc-dashboard" \
      org.smartgrid-mtd.description="Wazuh dashboard of the cps-soc lab"
