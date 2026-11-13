#!/bin/bash
# wazuh-iris-integration.sh — connect the cps-soc manager to DFIR-IRIS, the way
# Wazuh's own integrations are connected: a custom integration the manager's
# integrator runs for the alerts of the lab's sensor rules.
#
#   IRIS_URL=https://… IRIS_KEY=… wazuh-iris-integration.sh
#
# Installs iris_forward.py (staged from nodes/wazuh/manager/) as
# /var/ossec/integrations/custom-iris.py, behind Wazuh's own launcher (the one
# its Shuffle integration uses, which runs <name>.py with Wazuh's Python), adds
# the <integration> block to ossec.conf, and starts the integrator. The manager
# is started by wazuh-manager-setup.sh, which this waits for: the integrator
# reads the configuration the manager runs with.
#
# Copied flat onto the SOC node; needs the kathara/soc-siem image.
set -eu
: "${IRIS_URL:?}" "${IRIS_KEY:?}"

O=/var/ossec
until $O/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running"; do
    sleep 1
done

install -o root -g wazuh -m 750 $O/integrations/shuffle $O/integrations/custom-iris
install -o root -g wazuh -m 750 /iris_forward.py $O/integrations/custom-iris.py

if ! grep -q "<name>custom-iris</name>" $O/etc/ossec.conf; then
    cat >> $O/etc/ossec.conf <<CONF

<ossec_config>
  <integration>
    <name>custom-iris</name>
    <hook_url>${IRIS_URL}</hook_url>
    <api_key>${IRIS_KEY}</api_key>
    <rule_id>100100,100101</rule_id>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
CONF
fi

# The manager started without an integration, so without its integrator.
$O/bin/wazuh-integratord
echo "integrator started: alerts of rules 100100, 100101 go to ${IRIS_URL}"
