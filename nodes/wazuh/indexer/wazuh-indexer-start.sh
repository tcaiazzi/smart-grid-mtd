#!/bin/bash
# wazuh-indexer-start.sh — start the cps-soc lab's Wazuh indexer.
#
#   ADMIN_PASSWORD=… SHIPPER_PASSWORD=… KIBANASERVER_PASSWORD=… BLUE_PASSWORD=… \
#       wazuh-indexer-start.sh
#
# Installs the configuration staged from nodes/wazuh/indexer/ and the lab's
# certificates (/pki, from the image), writes the internal users with this run's
# passwords — admin (nobody's: the security configuration is loaded with the
# admin certificate), filebeat (the manager's alert shipper, which may only write
# alerts: role wazuh_shipper), kibanaserver (the dashboard's own connection) and
# blue (the blue team's login) — and runs the official entrypoint, which drops
# to the indexer's user and loads the security configuration on first start.
#
# Copied flat onto the indexer node; needs the kathara/wazuh-indexer image.
set -eu

HOME_DIR=/usr/share/wazuh-indexer
CONF=$HOME_DIR/config
: "${ADMIN_PASSWORD:?}" "${SHIPPER_PASSWORD:?}" "${KIBANASERVER_PASSWORD:?}" "${BLUE_PASSWORD:?}"

install -m 640 /opensearch.yml $CONF/opensearch.yml
mkdir -p $CONF/certs
# The image ships Wazuh's demonstration certificates here: replaced, so that no
# demonstration key is trusted in the lab.
rm -f $CONF/certs/*
cp /pki/root-ca.pem /pki/indexer.pem /pki/indexer-key.pem /pki/admin.pem /pki/admin-key.pem $CONF/certs/

for f in roles.yml roles_mapping.yml; do
    [ -f "$CONF/opensearch-security/$f.orig" ] || cp "$CONF/opensearch-security/$f" "$CONF/opensearch-security/$f.orig"
done

hash() {
    JAVA_HOME=$HOME_DIR/jdk bash $HOME_DIR/plugins/opensearch-security/tools/hash.sh -p "$1" 2>/dev/null | tail -1
}
cat > $CONF/opensearch-security/internal_users.yml <<USERS
---
_meta:
  type: "internalusers"
  config_version: 2
admin:
  hash: "$(hash "$ADMIN_PASSWORD")"
  reserved: true
  backend_roles: ["admin"]
  description: "Administrator, not handed to anyone"
filebeat:
  hash: "$(hash "$SHIPPER_PASSWORD")"
  reserved: false
  description: "The manager's alert shipper"
kibanaserver:
  hash: "$(hash "$KIBANASERVER_PASSWORD")"
  reserved: true
  description: "The dashboard's own connection"
blue:
  hash: "$(hash "$BLUE_PASSWORD")"
  reserved: false
  backend_roles: ["admin"]
  description: "The blue team"
USERS

# What the shipper may do, and nothing else: load the Wazuh index template and
# the module's ingest pipeline, and write alerts. Appended to the image's own
# roles and mappings, which the other users rely on.
cat "$CONF/opensearch-security/roles.yml.orig" > $CONF/opensearch-security/roles.yml
cat >> $CONF/opensearch-security/roles.yml <<'ROLES'

wazuh_shipper:
  reserved: false
  cluster_permissions:
    - "cluster_monitor"
    - "indices:admin/template/get"
    - "indices:admin/template/put"
    - "cluster:admin/ingest/pipeline/get"
    - "cluster:admin/ingest/pipeline/put"
  index_permissions:
    - index_patterns: ["wazuh-alerts-*", "wazuh-archives-*"]
      allowed_actions: ["crud", "create_index", "indices:admin/mapping/put"]
ROLES
cat "$CONF/opensearch-security/roles_mapping.yml.orig" > $CONF/opensearch-security/roles_mapping.yml
cat >> $CONF/opensearch-security/roles_mapping.yml <<'MAPPING'

wazuh_shipper:
  reserved: false
  users: ["filebeat"]
MAPPING

chown -R 1000:0 $CONF
chmod 600 $CONF/certs/*
exec env OPENSEARCH_JAVA_OPTS="${OPENSEARCH_JAVA_OPTS:--Xms1g -Xmx1g}" /entrypoint.sh opensearchwrapper
