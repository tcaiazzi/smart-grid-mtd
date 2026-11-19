#!/bin/bash
# wazuh-dashboard-start.sh — start the cps-soc lab's Wazuh dashboard.
#
#   KIBANASERVER_PASSWORD=… wazuh-dashboard-start.sh
#
# Installs the configuration staged from nodes/wazuh/dashboard/ and the lab's
# certificates (/pki, from the image), then runs the official entrypoint as the
# dashboard's own user: the node runs as root, which Kathará needs to address
# it, and OpenSearch Dashboards refuses to run as root. Beside it, the lab's own
# views (the attack tree, the knowledge graph) are created as soon as it answers.
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

# In the background: the views can only be created once the dashboard, started
# below, answers. By the name its certificate carries (/etc/hosts has it).
OSD_PASSWORD="$KIBANASERVER_PASSWORD" python3 /dashboard_objects.py \
    --url "https://wazuh.dashboard:5601" --user kibanaserver \
    --ca /pki/root-ca.pem --specs / > /dashboard_objects.log 2>&1 &

exec chroot --userspec=1000:1000 / env HOME=$HOME_DIR \
    DASHBOARD_USERNAME=kibanaserver DASHBOARD_PASSWORD="$KIBANASERVER_PASSWORD" /entrypoint.sh
