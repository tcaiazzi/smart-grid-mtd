#!/bin/bash
# player-firewall.sh — what a player's node may reach: its team's console, and
# the model's API. Nothing else.
#
#   player-firewall.sh SEAT_IP SEAT_PORT SEAT_IFACE
#
# A player is a program the range did not write, run on a node with a way out to
# the Internet. Left open, that node would also reach the host the lab runs on
# (the gateway of its bridged interface, where the other team's console is
# published) and whatever private network the host sits in. So: the console,
# on the link to it and only there; name resolution, to the resolvers the node
# was given; HTTPS to public addresses. The rest is refused, in and out.
#
# Run as root before the player starts, which then runs as an unprivileged user
# and cannot change any of this. Copied flat onto a player's node; needs
# iptables from the node image.
set -eu

seat_ip=$1 seat_port=$2 seat_iface=$3

iptables -F OUTPUT
iptables -F INPUT
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
for chain in INPUT OUTPUT; do
    iptables -A "$chain" -m state --state ESTABLISHED,RELATED -j ACCEPT
done
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# The seat: this address and port, on the link made for it.
iptables -A OUTPUT -o "$seat_iface" -p tcp -d "$seat_ip" --dport "$seat_port" -j ACCEPT
iptables -A OUTPUT -o "$seat_iface" -j REJECT

# The resolvers come before the private ranges are closed: a host's resolver is
# often on one (Docker's, WSL's), and without it no API has an address.
while read -r key value _; do
    [ "$key" = nameserver ] || continue
    case "$value" in *:*) continue ;; esac
    iptables -A OUTPUT -p udp -d "$value" --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp -d "$value" --dport 53 -j ACCEPT
done </etc/resolv.conf

# The host and its networks: the bridge's gateway is one of these.
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 127.0.0.0/8; do
    iptables -A OUTPUT -d "$net" -j REJECT
done

iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -j REJECT

# No way out over IPv6 at all: none of the above was written for it.
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -P INPUT DROP 2>/dev/null || true
    ip6tables -P OUTPUT DROP 2>/dev/null || true
    ip6tables -P FORWARD DROP 2>/dev/null || true
    ip6tables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
    ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
fi
