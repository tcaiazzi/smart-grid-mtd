#!/bin/sh
# Replay a real packet trace onto the backbone collision domain to create
# realistic background traffic. Runs inside the router container (eth0 = backbone).
#
# The trace's original MAC/IP addresses are foreign to the lab, so the bridge
# floods these frames as unknown-unicast to every port — including the attacker,
# whose promiscuous sniffer then captures them alongside the real SCMC traffic.
#
# Usage: replay_background.sh [iface] [mbps] [loops]
#   iface  network interface to replay on   (default eth0 = backbone)
#   mbps   rate limit in Mbit/s             (default 2)
#   loops  number of times to replay; 0=inf (default 0)

IFACE="${1:-eth0}"
MBPS="${2:-2}"
LOOPS="${3:-0}"

PCAP_DIR=/
SRC="$PCAP_DIR/traccia.pcapng"
PCAP="$PCAP_DIR/traccia.pcap"

# tcpreplay needs classic pcap; convert once with editcap and cache the result.
if [ ! -f "$PCAP" ]; then
    echo "[replay] converting $SRC -> $PCAP (one-time)..."
    editcap -F pcap "$SRC" "$PCAP" || { echo "[replay] editcap failed"; exit 1; }
fi

echo "[replay] tcpreplay on $IFACE @ ${MBPS}Mbps loop=$LOOPS"
exec tcpreplay -i "$IFACE" --loop="$LOOPS" --mbps="$MBPS" "$PCAP"
