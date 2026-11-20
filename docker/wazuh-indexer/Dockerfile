# Kathará node image for the Wazuh indexer of the cps-soc lab: the official
# image, at the manager's version (kathara/soc: wazuh-manager 4.14.10), with what
# a lab node needs on top. Its configuration comes from nodes/wazuh/indexer/,
# staged at deploy.
#
# Root: Kathará runs a node's startup commands as the image's user, and the
# official one (wazuh-indexer) cannot address an interface. The service still
# runs as that user: the official entrypoint drops to it.
FROM wazuh/wazuh-indexer:4.14.10

USER root
# tar: Kathará stages a node's files by unpacking a tar inside it; without
# one the node starts with none of them, its start script included.
RUN dnf install -y iproute iptables-nft tar && dnf clean all

COPY --from=kathara/wazuh-pki /pki/root-ca.pem /pki/indexer.pem /pki/indexer-key.pem /pki/admin.pem /pki/admin-key.pem /pki/

# Kathará runs every command of the node from here, and the platform reads a
# service's console log at the root: the official image works elsewhere.
WORKDIR /

LABEL org.smartgrid-mtd.role="cps-soc-indexer" \
      org.smartgrid-mtd.description="Wazuh indexer (OpenSearch) of the cps-soc lab"
