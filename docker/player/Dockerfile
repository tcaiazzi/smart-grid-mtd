# Kathará node image for a player's node: the sandbox a harness plays a team
# from. Deliberately bare — a player has the seat of its team and a way out to
# its model's API, and brings nothing else into the lab: no scanner, no lab
# tooling, no copy of the repository. This base is enough for the scripted
# player (stdlib only); each harness builds its own image on top of it
# (docker/player-<harness>/), so that adding or upgrading one never changes
# what another runs on.
FROM kathara/core:latest

ENV DEBIAN_FRONTEND=noninteractive

# python3 runs the seat's adapter and the launchers; ca-certificates lets a
# harness reach its API over TLS. iptables (player-firewall.sh) and iproute
# come from the base image.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# The player runs as this user, never as root: root on the node could lift the
# firewall that keeps it to its seat.
RUN useradd --create-home --shell /bin/bash player

LABEL org.smartgrid-mtd.role="player-node" \
      org.smartgrid-mtd.description="sandbox a harness plays a team's seat from (scripted player)"
