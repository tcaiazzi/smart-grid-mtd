"""harnesses.py — the harnesses this scenario can seat at a team's console.

One entry per harness (cyberrange/core/harness.py). Adding one is an entry
here, its launcher under nodes/players/ (staged by a manifest in
guest_files.py) and the image of its node under docker/: nothing else in the
platform, the consoles, the seat's adapter or the metrics is written for a
harness in particular, which is what lets two of them be compared.
"""

from cyberrange.core.harness import Harness
from cyberrange.scenarios.cps_advisor.guest_files import CLAUDE_PLAYER_FILES

SCRIPTED = "python3 /scripted_player.py"
# The scripted policies of each side (nodes/players/scripted_player.py), from
# the hardest opponent to none: what a harness in the other seat is graded
# against.
OPPONENTS = {"blue": ("fast", "slow", "absent"), "red": ("loud", "quiet", "idle")}

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
        # the same while the other seat's harness changes. It plays either
        # side with that side's plainest policy; the graded ones are below.
        Harness("scripted", image="kathara/player", launcher=SCRIPTED),
        *(
            Harness(
                f"scripted-{policy}",
                image="kathara/player",
                launcher=f"{SCRIPTED} --policy {policy}",
                seats=(team,),
            )
            for team, policies in OPPONENTS.items()
            for policy in policies
        ),
    )
}
