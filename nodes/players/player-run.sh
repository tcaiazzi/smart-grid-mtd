#!/bin/bash
# player-run.sh — start a team's player on its node: close the node's firewall
# around the seat, then run the harness as an unprivileged user and put on the
# transcript how it ended.
#
# Run as root by the range, with no arguments: everything it needs is in the
# files the range wrote next to it, so that neither the team's token nor the
# harness's secrets are ever part of a command line.
#
#   /home/player/terms.env     SEAT_IP, SEAT_PORT, SEAT_IFACE, LAUNCHER, RESOLVERS,
#                              and the CR_* terms the launcher reads (harness_kit.py)
#   /home/player/secrets.env   what the harness needs of the host (an API key)
#   /home/player/seat.token    the team's token
#
# The order is the point: a harness that started before the firewall closed
# would have had the host and its networks within reach. If the firewall cannot
# be set, nothing is started.
#
# Copied flat onto a player's node, with player-firewall.sh.
set -u

home=/home/player
set -a
. "$home/terms.env"
set +a

exited() {
    printf '{"t": %s, "kind": "player_exit", "team": "%s", "rc": %s}\n' \
        "$(date +%s.%3N)" "$CR_TEAM" "$1" >>"$CR_TRANSCRIPT"
}

touch "$CR_TRANSCRIPT" "$home/secrets.env"
chown player "$CR_TRANSCRIPT" "$home/terms.env" "$home/secrets.env" "$home/seat.token"

# A lab node starts with no resolver at all, and a harness that cannot find its
# API's address fails in a way that looks like a harness that cannot play. The
# firewall then opens the way to these and to no other.
: >/etc/resolv.conf
for ns in ${RESOLVERS:-}; do
    echo "nameserver $ns" >>/etc/resolv.conf
done

if ! bash /player-firewall.sh "$SEAT_IP" "$SEAT_PORT" "$SEAT_IFACE"; then
    echo "player-run: the firewall could not be set; the player is not started" >&2
    exited 125
    exit 125
fi

rc=0
# The launcher inherits the terms exported above; the secrets are read by the
# player's own shell, so they are in no environment but the harness's.
su player -s /bin/bash -c "set -a; . $home/secrets.env; set +a; cd $home && exec \$LAUNCHER" || rc=$?
exited "$rc"
exit "$rc"
