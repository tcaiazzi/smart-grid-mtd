#!/bin/bash
# wazuh-manager-setup.sh — start the SOC's Wazuh manager with its agents known.
#
#   wazuh-manager-setup.sh ID:NAME:KEY [ID:NAME:KEY ...]
#
# Each agent is registered with the key its own wazuh-agent-setup.sh is given,
# so no agent has to enrol before it can report.
#
# Copied flat onto the SOC node with cps_rules.xml; needs the wazuh-manager
# package of the kathara/soc image.
set -eu

O=/var/ossec

: > $O/etc/client.keys
for agent in "$@"; do
    IFS=: read -r id name key <<< "$agent"
    echo "$id $name any $key" >> $O/etc/client.keys
done
chown wazuh:wazuh $O/etc/client.keys
chmod 640 $O/etc/client.keys

install -o wazuh -g wazuh -m 660 /cps_rules.xml $O/etc/rules/cps_rules.xml

# The lab has no route to the internet: the periodic update check hangs on it
# and stalls the API for seconds at a time, which delays an active response.
sed -i 's|<update_check>yes</update_check>|<update_check>no</update_check>|' $O/etc/ossec.conf
# The manager's benchmark of its own host: hundreds of alerts at start-up that
# bury the lab's, about a node nobody is assessing.
sed -i '/<sca>/,/<\/sca>/ s|<enabled>yes</enabled>|<enabled>no</enabled>|' $O/etc/ossec.conf

$O/bin/wazuh-control start
echo "manager started, $# agents registered"
