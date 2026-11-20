#!/bin/bash
# wazuh-agent-setup.sh — make this host an agent of the SOC's Wazuh manager.
#
#   wazuh-agent-setup.sh MANAGER_IP AGENT_ID NAME KEY ALLOWLIST_B64 [LOG...]
#
# KEY is pre-shared with the manager (wazuh-manager-setup.sh registers the same
# one), so there is no enrolment round trip: the agent is usable as soon as the
# manager listens. ALLOWLIST_B64 is the base64 of the JSON that maps the
# countermeasures this host may run to their commands (cps_response.py). Each
# LOG is a JSON-lines file shipped to the manager.
#
# Copied flat onto the hosts that run an agent, with wazuh-agent.conf and
# cps_response.py; needs the wazuh-agent package of the node image.
set -eu

manager=$1 id=$2 name=$3 key=$4 allowlist=$5
shift 5
O=/var/ossec

echo "$id $name any $key" > $O/etc/client.keys
chown root:wazuh $O/etc/client.keys
chmod 640 $O/etc/client.keys

sed "s|MANAGER_IP|$manager|" /wazuh-agent.conf > $O/etc/ossec.conf
for log in "$@" $O/logs/cps-response.jsonl; do
    touch "$log"
    printf '<ossec_config>\n  <localfile>\n    <log_format>json</log_format>\n    <location>%s</location>\n  </localfile>\n</ossec_config>\n' "$log" >> $O/etc/ossec.conf
done
chown root:wazuh $O/etc/ossec.conf
chmod 660 $O/etc/ossec.conf

# The manager would push its shared configuration right after the first
# connection and restart the log collector: a finding written in that moment
# is lost. The profile above is the whole configuration.
echo "agent.remote_conf=0" >> $O/etc/local_internal_options.conf
# Look at the shipped logs every second instead of every two: this interval is
# a floor under the time a finding takes to reach the manager.
echo "logcollector.loop_timeout=1" >> $O/etc/local_internal_options.conf

printf '%s' "$allowlist" | base64 -d > $O/etc/cps-response.json
chown root:wazuh $O/etc/cps-response.json
chmod 640 $O/etc/cps-response.json
install -o root -g wazuh -m 750 /cps_response.py $O/active-response/bin/cps-response

# An agent started before the manager listens fails its first connection and
# only retries after time-reconnect.
tries=0
until (exec 3<>"/dev/tcp/$manager/1514") 2>/dev/null; do
    tries=$((tries + 1))
    if [ "$tries" -gt 300 ]; then
        echo "manager $manager:1514 never came up" >&2
        exit 1
    fi
    sleep 0.2
done

$O/bin/wazuh-control start
echo "agent $id ($name) started, manager $manager"
