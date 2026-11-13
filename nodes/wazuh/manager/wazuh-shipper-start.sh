#!/bin/bash
# wazuh-shipper-start.sh — ship the manager's alerts to the cps-soc indexer.
#
#   INDEXER_PASSWORD=… wazuh-shipper-start.sh
#
# Installs filebeat.yml (staged from nodes/wazuh/manager/), keeps this run's
# password in Filebeat's keystore rather than in the file, waits for the indexer
# to answer and runs Filebeat in the foreground: it is the component's process.
#
# Copied flat onto the SOC node; needs the kathara/soc-siem image.
set -eu
: "${INDEXER_PASSWORD:?}"

install -m 600 /filebeat.yml /etc/filebeat/filebeat.yml
filebeat keystore create --force >/dev/null
printf '%s' "$INDEXER_PASSWORD" | filebeat keystore add INDEXER_PASSWORD --stdin --force >/dev/null

# The indexer takes a few seconds to come up; Filebeat would otherwise start by
# failing to load the index template, and retry it only much later.
until filebeat test output >/dev/null 2>&1; do sleep 2; done
exec filebeat -e -c /etc/filebeat/filebeat.yml
