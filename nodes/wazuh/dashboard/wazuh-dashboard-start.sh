#!/bin/bash
# wazuh-dashboard-start.sh — start the cps-soc lab's Wazuh dashboard.
#
#   KIBANASERVER_PASSWORD=… wazuh-dashboard-start.sh
#
# Installs the configuration staged from nodes/wazuh/dashboard/ and the lab's
# certificates (/pki, from the image), then runs the official entrypoint as the
# dashboard's own user: the node runs as root, which Kathará needs to address
# it, and OpenSearch Dashboards refuses to run as root.
#
# Copied flat onto the dashboard node; needs the kathara/wazuh-dashboard image.
set -eu

HOME_DIR=/usr/share/wazuh-dashboard
: "${KIBANASERVER_PASSWORD:?}"

install -m 640 /opensearch_dashboards.yml $HOME_DIR/config/opensearch_dashboards.yml
mkdir -p $HOME_DIR/certs $HOME_DIR/data/wazuh/config
cp /pki/root-ca.pem /pki/dashboard.pem /pki/dashboard-key.pem $HOME_DIR/certs/
install -m 640 /wazuh.yml $HOME_DIR/data/wazuh/config/wazuh.yml
chown -R 1000:1000 $HOME_DIR/config $HOME_DIR/certs $HOME_DIR/data
chmod 600 $HOME_DIR/certs/*

exec chroot --userspec=1000:1000 / env HOME=$HOME_DIR \
    DASHBOARD_USERNAME=kibanaserver DASHBOARD_PASSWORD="$KIBANASERVER_PASSWORD" /entrypoint.sh
