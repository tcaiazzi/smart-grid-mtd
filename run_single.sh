#!/usr/bin/env bash
# run_single.sh — run ONE experiment with manually-set parameters
#
# Unlike run_sweep.sh (which builds the fixed E0–E4 groups), this script
# exposes every MTD parameter as an editable variable below. Set them, then:
#
#   ./run_single.sh              # run with the parameters set below
#   ./run_single.sh --dry-run    # print commands without running
#
# Outputs land in the same layout as the sweep:
#   output/baseline-mbps<M>/     when NO_MTD=1
#   output/mtd-<slug>/           fixed-timer MTD (slug derived from the params)
#   output/mtdrl-<slug>/         when RL=1 (RL coordinator drives the schedule)
#
# After running:
#   .venv/bin/python plot_sweep.py

set -euo pipefail

# ── EDIT THESE ────────────────────────────────────────────────────────────────
# Label for logs only (does not affect output dir, which is the param slug).
EXPERIMENT="manual-run"

# Set NO_MTD=1 to run the no-MTD baseline instead of an MTD config.
# When NO_MTD=1 only MBPS below matters; the MTD params are ignored.
NO_MTD=0

# Set RL=1 to drive the schedule with a trained RL policy (mtd_rl_coordinator.py)
# instead of the fixed timers. The pools below still define the action space the
# policy hops over, but the per-knob intervals (HOP/PAD_INT/FREQ_INT) are ignored —
# the policy decides timing. Needs a trained policy (RL_POLICY); if it is missing
# the script trains it first via `make train-rl`. Ignored when NO_MTD=1.
RL=1
RL_POLICY="output/rl/policy.npz"
RL_TICK=1.0

# Set RL_ENTROPY=1 (with RL=1) to run the entropy-max RL policy instead of the
# default blend policy: it maximizes diffusion using every knob (ignoring hop cost),
# uses output/rl-entropy/policy.npz, and lands in its own output/mtdrl-entropy-<slug>/
# dir (so it does NOT overwrite the blend RL run). Auto-trains via
# `make train-rl-entropy` if the policy is missing.
RL_ENTROPY=1

HOP=4                                        # broker hop interval (s); also drives source-IP hop
IP_POOL="10.1.0.2,10.1.0.4,10.1.0.5,10.1.0.6,10.1.0.7,10.1.0.8"  # broker IP pool (comma-separated; single value = IP hop off)
PORT_POOL="8883,8884,8885,8886,8887,8888,8889"           # broker port pool (single value = port hop off)
SCMC_POOL="10.0.0.2,10.0.0.4,10.0.0.5,10.0.0.6,10.0.0.7,10.0.0.8" # source-IP pool (single value = source hop off)
PAD_BUCKETS="128,256,384,512,640,768,1024"     # payload padding buckets
PAD_INT=3                                      # padding mutation interval (s)
MBPS=2                                         # background replay noise (Mbit/s)
FREQ_POOL="0.1,0.2,0.4,0.6,0.8,1"              # message-frequency pool (single value = freq hop off)
FREQ_INT=5                                    # message-frequency mutation interval (s)
# ──────────────────────────────────────────────────────────────────────────────

PYTHON=".venv/bin/python"
MANIFEST="output/sweep_manifest.csv"

# Entropy flag selects the entropy-max policy + its own tagged output dir.
RL_TAG=""
if [[ "$RL" -eq 1 && "$RL_ENTROPY" -eq 1 ]]; then
    RL_TAG="entropy"
    RL_POLICY="output/rl-entropy/policy.npz"
fi

DRY=0; [[ "${1:-}" == "--dry-run" ]] && DRY=1

log() { printf '[single %s] %s\n' "$(date +%H:%M:%S)" "$*"; }
run() { if [[ $DRY -eq 1 ]]; then printf '  DRY: %s\n' "$*"; else eval "$*"; fi; }

count_items() { printf '%s' "$1" | tr ',' '\n' | grep -c .; }

make_slug() {
    # Mirrors the Makefile MTD_PARAMS_SLUG formula.
    local hop=$1 padint=$2 ip_pool=$3 port_pool=$4 scmc_pool=$5 pad_buckets=$6 mbps=$7 \
          freqint=$8 freq_pool=$9
    local n_ips n_ports n_src n_pads n_freqs
    n_ips=$(count_items   "$ip_pool")
    n_ports=$(count_items "$port_pool")
    n_src=$(count_items   "$scmc_pool")
    n_pads=$(count_items  "$pad_buckets")
    n_freqs=$(count_items "$freq_pool")
    printf 'hop%d-padint%d-ips%d-ports%d-pads%d-srcips%d-mbps%d-freqint%d-freqs%d' \
        "$hop" "$padint" "$n_ips" "$n_ports" "$n_pads" "$n_src" "$mbps" \
        "$freqint" "$n_freqs"
}

# ── Baseline run (NO_MTD=1) ───────────────────────────────────────────────────
run_baseline() {
    local mbps=$1
    log "  baseline (no MTD, mbps=$mbps)"
    run "make datasets NO_MTD=1 BG_REPLAY_MBPS=$mbps"
    run "make train    NO_MTD=1 BG_REPLAY_MBPS=$mbps"
    run "make evaluate NO_MTD=1 BG_REPLAY_MBPS=$mbps"
    run "make attack   NO_MTD=1 BG_REPLAY_MBPS=$mbps"

    run "$PYTHON plot_results.py --baseline-only \
        --bg-replay-mbps $mbps \
        --plots-dir output/baseline-mbps$mbps"
}

# ── One MTD configuration ─────────────────────────────────────────────────────
run_config() {
    local experiment=$1 hop=$2 ip_pool=$3 port_pool=$4 scmc_pool=$5 \
          pad_buckets=$6 pad_interval=$7 mbps=$8 freq_int=$9 freq_pool=${10}

    local n_ips n_ports n_src n_pads n_freqs slug
    n_ips=$(count_items   "$ip_pool")
    n_ports=$(count_items "$port_pool")
    n_src=$(count_items   "$scmc_pool")
    n_pads=$(count_items  "$pad_buckets")
    n_freqs=$(count_items "$freq_pool")
    slug=$(make_slug "$hop" "$pad_interval" "$ip_pool" "$port_pool" "$scmc_pool" "$pad_buckets" "$mbps" "$freq_int" "$freq_pool")
    # RL runs use the "mtdrl-" prefix (matching the Makefile) so their artifacts
    # sit beside the fixed-timer run's; a tag (e.g. entropy) separates competing
    # RL policies into mtdrl-<tag>-<slug>/.
    local prefix="mtd"
    [[ "$RL" -eq 1 ]] && prefix="mtdrl"
    [[ "$RL" -eq 1 && -n "$RL_TAG" ]] && prefix="mtdrl-$RL_TAG"
    local exp="$prefix-$slug"

    log "  [$experiment] $exp"

    local args=(
        "MTD_HOP_INTERVAL=$hop"
        "MTD_IP_POOL=$ip_pool"
        "MTD_PORT_POOL=$port_pool"
        "MTD_SCMC_IP_POOL=$scmc_pool"
        "MTD_SRC_HOP_INTERVAL=$hop"
        "MTD_PAD_BUCKETS=$pad_buckets"
        "MTD_PAD_INTERVAL=$pad_interval"
        "BG_REPLAY_MBPS=$mbps"
        "MTD_FREQ_INTERVAL=$freq_int"
        "MTD_FREQ_POOL=$freq_pool"
    )
    # Drive every make target (datasets/train/evaluate/entropy/attack) through the
    # RL coordinator and the matching mtdrl- experiment dir.
    if [[ "$RL" -eq 1 ]]; then
        args+=( "RL=1" "RL_POLICY=$RL_POLICY" "RL_TICK=$RL_TICK" )
        [[ -n "$RL_TAG" ]] && args+=( "RL_TAG=$RL_TAG" )
        # entropy tag trains via train-rl-entropy; otherwise the blend policy.
        local train_target="make train-rl"
        [[ "$RL_TAG" == "entropy" ]] && train_target="make train-rl-entropy"
        if [[ ! -f "$RL_POLICY" ]]; then
            log "    RL policy $RL_POLICY missing — training it first ($train_target)"
            run "$train_target"
        fi
    fi

    # Reuse an existing config when its datasets + model are already built.
    if [[ -f "output/$exp/datasets/train.pcap" \
       && -f "output/$exp/datasets/test.pcap" \
       && -f "output/$exp/model/model.pt" ]]; then
        log "    datasets + model present — running attack only"
    else
        log "    datasets/model missing — full rebuild"
        run "rm -rf output/$exp"
        run "make datasets ${args[*]}"
        run "make train    ${args[*]}"
        run "make evaluate ${args[*]}"
        run "make evaluate MODEL_SRC=baseline ${args[*]}"
    fi

    # run "make attack   ${args[*]}"
    run "make attack MODEL_SRC=baseline ${args[*]}"
    run "make entropy ${args[*]}"

    run "$PYTHON plot_results.py \
        --mtd-params-slug '$slug' \
        --bg-replay-mbps $mbps \
        --plots-dir output/$exp"

    [[ $DRY -eq 1 ]] && return
    mkdir -p output
    if [[ ! -f "$MANIFEST" ]]; then
        printf 'experiment,hop,n_ips,n_ports,n_pads,n_src,pad_interval,bg_mbps,freq_interval,n_freqs,slug\n' \
            > "$MANIFEST"
    fi
    if ! grep -qF "$exp" "$MANIFEST" 2>/dev/null; then
        printf '%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s\n' \
            "$experiment" "$hop" "$n_ips" "$n_ports" "$n_pads" "$n_src" \
            "$pad_interval" "$mbps" "$freq_int" "$n_freqs" "$exp" >> "$MANIFEST"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
if [[ "$NO_MTD" -eq 1 ]]; then
    log "=== Single baseline run ==="
    run_baseline "$MBPS"
else
    log "=== Single MTD run ==="
    run_config "$EXPERIMENT" \
        "$HOP" "$IP_POOL" "$PORT_POOL" "$SCMC_POOL" \
        "$PAD_BUCKETS" "$PAD_INT" "$MBPS" "$FREQ_INT" "$FREQ_POOL"
fi

log "=== Done ==="
