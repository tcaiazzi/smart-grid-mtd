"""harnesses.py — the harnesses this scenario can seat at a team's console.

One entry per harness (cyberrange/core/harness.py). Adding one is an entry
here, its launcher under nodes/players/ (staged by a manifest in
guest_files.py) and the image of its node under docker/: nothing else in the
platform, the consoles, the seat's adapter or the metrics is written for a
harness in particular, which is what lets two of them be compared.
"""

from cyberrange.core.harness import Harness
from cyberrange.scenarios.cps_advisor.guest_files import CLAUDE_PLAYER_FILES

HARNESSES = {
    h.name: h
    for h in (
        # Claude Code, headless. Its launcher gives it the seat as its only
        # tools and leaves its own prompt and loop alone. It runs on an API key
        # or on a subscription's token (`claude setup-token`), whichever the
        # host holds.
        Harness(
            "claude-code",
            image="kathara/player-claude",
            launcher="python3 /claude_player.py",
            files=tuple(CLAUDE_PLAYER_FILES),
            secret_env=("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"),
        ),
        # No model: a fixed policy. The yardstick, and the opponent that stays
        # the same while the other seat's harness changes.
        Harness("scripted", image="kathara/player", launcher="python3 /scripted_player.py"),
    )
}
