# Kathará node image for a player's node running the claude-code harness:
# kathara/player plus the claude CLI. See docker/player/Dockerfile for what a
# player's node is and why it holds nothing else.
FROM kathara/player:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nodejs \
        npm && \
    rm -rf /var/lib/apt/lists/*

# Pinned: the harness's version is part of what a run measures, and the
# launcher's options (nodes/players/claude_player.py) were read from this
# version's --help. Raise the two together.
RUN npm install -g @anthropic-ai/claude-code@2.1.295 && npm cache clean --force

LABEL org.smartgrid-mtd.role="player-node" \
      org.smartgrid-mtd.description="sandbox for the claude-code harness (claude CLI)"
