#!/usr/bin/env bash
# run_sweep.sh — paper experiment sweep
#
# Runs four experiment groups:
#   E0  main result at default parameters
#   E1  address-space diversity: 2×2 factorial of IP hop × port hop
#   E2  hop interval sweep: 1 2 5 10 30 seconds
#   E3  background noise sweep: 1 2 5 10 Mbit/s
#   E4  message-frequency mutation interval sweep: 1 5 10 30 seconds
#
# Each MTD configuration generates its own dataset + model so results
# are comparable.  The baseline (no-MTD) run is shared for E0/E1/E2
# (same noise level) and re-run independently for each E3 noise level.
#
# Outputs per config (one self-contained dir per experiment):
#   output/<exp-dir>/attack/model-<src>/   attack captures, broker log
#   output/<exp-dir>/summary.csv           detection score + availability
#   exp-dir = baseline-mbps<M> | mtd-<slug>
#
# After the sweep:
#   .venv/bin/python -m monitor.plot_sweep
#
# Usage:
#   ./run_sweep.sh              # full sweep (~3 h)
#   ./run_sweep.sh --dry-run    # print commands without running

set -euo pipefail

PYTHON=".venv/bin/python"
MANIFEST="output/sweep_manifest.csv"

DEFAULT_HOP=2
DEFAULT_IP_POOL="10.1.0.2,10.1.0.4,10.1.0.5,10.1.0.6"
DEFAULT_PORT_POOL="8883,8884,8885,8886,8887"
DEFAULT_SCMC_POOL="10.0.0.2,10.0.0.4,10.0.0.5,10.0.0.6"
DEFAULT_PAD_BUCKETS="128,256,384,512,640,768,1024"
DEFAULT_PAD_INT=3
DEFAULT_MBPS=2
# Multi-valued so message-frequency hopping is active across the sweep; E4 varies
# the mutation interval below.
DEFAULT_FREQ_POOL="0.1,0.2,0.4,0.6,0.8,1"
DEFAULT_FREQ_INT=30

# Source-IP hopping disabled (single SCMC source) — used by the E1 corners that
# isolate one mechanism at a time.
NO_SCMC_POOL="10.0.0.2"

DRY=0; [[ "${1:-}" == "--dry-run" ]] && DRY=1

log() { printf '[sweep %s] %s\n' "$(date +%H:%M:%S)" "$*"; }
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

# ── Baseline run ─────────────────────────────────────────────────────────────
# E3 calls this once per noise level; E0/E1/E2 share the default run.
run_baseline() {
    local mbps=${1:-$DEFAULT_MBPS}
    log "  baseline (no MTD, mbps=$mbps)"
    #run "rm -rf output/baseline-mbps$mbps"
    run "make datasets NO_MTD=1 BG_REPLAY_MBPS=$mbps"
    run "make train    NO_MTD=1 BG_REPLAY_MBPS=$mbps"
    run "make evaluate NO_MTD=1 BG_REPLAY_MBPS=$mbps"
    run "make attack   NO_MTD=1 BG_REPLAY_MBPS=$mbps"

    # Standalone baseline figures (availability + detection) in its own dir.
    run "$PYTHON -m monitor.plot_results --baseline-only \
        --bg-replay-mbps $mbps \
        --plots-dir output/baseline-mbps$mbps"
}

# ── One MTD configuration ─────────────────────────────────────────────────────
run_config() {
    local experiment=$1 hop=$2 ip_pool=$3 port_pool=$4 scmc_pool=$5 \
          pad_buckets=$6 pad_interval=$7 mbps=$8 freq_int=${9:-$DEFAULT_FREQ_INT} \
          freq_pool=${10:-$DEFAULT_FREQ_POOL}

    local n_ips n_ports n_src n_pads n_freqs slug
    n_ips=$(count_items   "$ip_pool")
    n_ports=$(count_items "$port_pool")
    n_src=$(count_items   "$scmc_pool")
    n_pads=$(count_items  "$pad_buckets")
    n_freqs=$(count_items "$freq_pool")
    slug=$(make_slug "$hop" "$pad_interval" "$ip_pool" "$port_pool" "$scmc_pool" "$pad_buckets" "$mbps" "$freq_int" "$freq_pool")
    local exp="mtd-$slug"

    log "  [$experiment] $exp"

    # MTD_SRC_HOP_INTERVAL is tied to the broker hop interval so E2's interval
    # sweep moves both; with a single-entry scmc pool source hopping stays off.
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

    # Reuse an existing config when its datasets + model are already built:
    # regenerating them is the expensive part, so only the attack is re-run.
    # Otherwise build the config from scratch (wipe any partial dir first).
    if [[ -f "output/$exp/datasets/train.pcap" \
       && -f "output/$exp/datasets/test.pcap" \
       && -f "output/$exp/model/model.pt" ]]; then
        log "    datasets + model present — running attack only"
    else
        log "    datasets/model missing — full rebuild"
        run "rm -rf output/$exp"
        run "make datasets ${args[*]}"
        run "make train    ${args[*]}"
        # Evaluate on the held-out test set — writes eval/model-<src>/predictions.csv,
        # which plot_results.py reads for the top-k suspected-flows chart.
        run "make evaluate ${args[*]}"
        # Cross-model eval: MTD test traffic scored with the baseline-trained model.
        run "make evaluate MODEL_SRC=baseline ${args[*]}"
    fi

    # MTD scenario with MTD-trained model
    run "make attack   ${args[*]}"
    # Cross-model: MTD traffic but attacker uses the baseline-trained model
    run "make attack MODEL_SRC=baseline ${args[*]}"

    # Per-config summary.csv (lands in output/$exp/) for plot_sweep.py to collect
    run "$PYTHON -m monitor.plot_results \
        --mtd-params-slug '$slug' \
        --bg-replay-mbps $mbps \
        --plots-dir output/$exp"

    # Manifest (idempotent: skip if already recorded). The slug column holds the
    # experiment dir name so plot_sweep reads output/<slug>/summary.csv.
    [[ $DRY -eq 1 ]] && return    # dry-run: don't mutate the manifest
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
log "=== E0: main result (defaults) ==="
run_baseline "$DEFAULT_MBPS"
run_config "E0-default" \
    $DEFAULT_HOP "$DEFAULT_IP_POOL" "$DEFAULT_PORT_POOL" "$DEFAULT_SCMC_POOL" \
    "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $DEFAULT_MBPS

# ─────────────────────────────────────────────────────────────────────────────
log "=== E1: address-space diversity (IP hop x port hop x source-IP hop) ==="
# E0-default = (IP hop yes, port hop yes, source-IP hop yes) — already done above.
# The corners below each isolate ONE mechanism; the others stay single-valued.
run_config "E1-no-hop" \
    $DEFAULT_HOP "10.1.0.2" "8883" "$NO_SCMC_POOL" \
    "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $DEFAULT_MBPS

run_config "E1-port-only" \
    $DEFAULT_HOP "10.1.0.2" "$DEFAULT_PORT_POOL" "$NO_SCMC_POOL" \
    "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $DEFAULT_MBPS

run_config "E1-ip-only" \
    $DEFAULT_HOP "$DEFAULT_IP_POOL" "8883" "$NO_SCMC_POOL" \
    "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $DEFAULT_MBPS

run_config "E1-src-only" \
    $DEFAULT_HOP "10.1.0.2" "8883" "$DEFAULT_SCMC_POOL" \
    "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $DEFAULT_MBPS

# ─────────────────────────────────────────────────────────────────────────────
log "=== E2: hop interval sweep ==="
# hop=2 = E0-default, already done.
for hop in 1 5 10 30; do
    run_config "E2-hop${hop}" \
        $hop "$DEFAULT_IP_POOL" "$DEFAULT_PORT_POOL" "$DEFAULT_SCMC_POOL" \
        "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $DEFAULT_MBPS
done

# ─────────────────────────────────────────────────────────────────────────────
log "=== E3: background noise sweep ==="
# mbps=2 = E0-default, already done.
# Re-run baseline at each noise level so baseline and MTD see the same SNR.
for mbps in 1 5 10; do
    run_baseline "$mbps"
    run_config "E3-mbps${mbps}" \
        $DEFAULT_HOP "$DEFAULT_IP_POOL" "$DEFAULT_PORT_POOL" "$DEFAULT_SCMC_POOL" \
        "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $mbps
done

# ─────────────────────────────────────────────────────────────────────────────
log "=== E4: message-frequency mutation interval sweep ==="
# Rotate the publish interval across DEFAULT_FREQ_POOL; vary how often it changes.
# freqint=30 = E0-default (same pool + interval), already done — plot folds it in.
for freqint in 1 5 10; do
    run_config "E4-freq${freqint}" \
        $DEFAULT_HOP "$DEFAULT_IP_POOL" "$DEFAULT_PORT_POOL" "$DEFAULT_SCMC_POOL" \
        "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $DEFAULT_MBPS \
        $freqint "$DEFAULT_FREQ_POOL"
done

# ─────────────────────────────────────────────────────────────────────────────
log "=== Sweep complete ==="
log "Manifest : $MANIFEST"
log "Next     : $PYTHON -m monitor.plot_sweep"
