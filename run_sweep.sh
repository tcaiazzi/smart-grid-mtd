#!/usr/bin/env bash
# run_sweep.sh — paper experiment sweep
#
# Runs four experiment groups:
#   E0  main result at default parameters
#   E1  address-space diversity: 2×2 factorial of IP hop × port hop
#   E2  hop interval sweep: 1 2 5 10 30 seconds
#   E3  background noise sweep: 1 2 5 10 Mbit/s
#
# Each MTD configuration generates its own dataset + model so results
# are comparable.  The baseline (no-MTD) run is shared for E0/E1/E2
# (same noise level) and re-run independently for each E3 noise level.
#
# Outputs per config:
#   output/experiment-results/<slug>/   attack captures, broker log
#   output/plots/<slug>/summary.csv     detection score + availability
#
# After the sweep:
#   .venv/bin/python plot_sweep.py
#
# Usage:
#   ./run_sweep.sh              # full sweep (~3 h)
#   ./run_sweep.sh --dry-run    # print commands without running

set -euo pipefail

PYTHON=".venv/bin/python"
MANIFEST="output/sweep_manifest.csv"

DEFAULT_HOP=2
DEFAULT_IP_POOL="10.1.0.2,10.1.0.4,10.1.0.5"
DEFAULT_PORT_POOL="8883,8884,8885,8886,8887"
DEFAULT_PAD_BUCKETS="128,256,384,512,640,768,1024"
DEFAULT_PAD_INT=3
DEFAULT_MBPS=2

DRY=0; [[ "${1:-}" == "--dry-run" ]] && DRY=1

log() { printf '[sweep %s] %s\n' "$(date +%H:%M:%S)" "$*"; }
run() { if [[ $DRY -eq 1 ]]; then printf '  DRY: %s\n' "$*"; else eval "$*"; fi; }

count_items() { printf '%s' "$1" | tr ',' '\n' | grep -c .; }

make_slug() {
    # Mirrors the Makefile MTD_PARAMS_SLUG formula.
    local hop=$1 padint=$2 ip_pool=$3 port_pool=$4 pad_buckets=$5 mbps=$6
    local n_ips n_ports n_pads
    n_ips=$(count_items   "$ip_pool")
    n_ports=$(count_items "$port_pool")
    n_pads=$(count_items  "$pad_buckets")
    printf 'hop%d-padint%d-ips%d-ports%d-pads%d-mbps%d' \
        "$hop" "$padint" "$n_ips" "$n_ports" "$n_pads" "$mbps"
}

# ── Baseline run ─────────────────────────────────────────────────────────────
# E3 calls this once per noise level; E0/E1/E2 share the default run.
run_baseline() {
    local mbps=${1:-$DEFAULT_MBPS}
    log "  baseline (no MTD, mbps=$mbps)"
    run "rm -rf output/models/baseline output/datasets/baseline"
    run "make datasets NO_MTD=1 BG_REPLAY_MBPS=$mbps"
    run "make train    NO_MTD=1"
    run "make attack   NO_MTD=1 BG_REPLAY_MBPS=$mbps"
}

# ── One MTD configuration ─────────────────────────────────────────────────────
run_config() {
    local experiment=$1 hop=$2 ip_pool=$3 port_pool=$4 \
          pad_buckets=$5 pad_interval=$6 mbps=$7

    local n_ips n_ports n_pads slug
    n_ips=$(count_items   "$ip_pool")
    n_ports=$(count_items "$port_pool")
    n_pads=$(count_items  "$pad_buckets")
    slug=$(make_slug "$hop" "$pad_interval" "$ip_pool" "$port_pool" "$pad_buckets" "$mbps")

    log "  [$experiment] $slug"

    # MTD dataset and model change with every parameter combo — always regenerate.
    run "rm -rf output/models/mtd output/datasets/mtd"

    local args=(
        "MTD_HOP_INTERVAL=$hop"
        "MTD_IP_POOL=$ip_pool"
        "MTD_PORT_POOL=$port_pool"
        "MTD_PAD_BUCKETS=$pad_buckets"
        "MTD_PAD_INTERVAL=$pad_interval"
        "BG_REPLAY_MBPS=$mbps"
    )
    run "make datasets ${args[*]}"
    run "make train    ${args[*]}"
    # MTD scenario with MTD-trained model
    run "make attack   ${args[*]}"
    # Cross-model: MTD traffic but attacker uses the baseline-trained model
    run "make attack MODEL_SRC=baseline ${args[*]}"

    # Per-config summary.csv for plot_sweep.py to collect
    run "$PYTHON plot_results.py \
        --mtd-params-slug '$slug' \
        --bg-replay-mbps $mbps \
        --plots-dir output/plots/$slug"

    # Manifest (idempotent: skip if slug already recorded)
    mkdir -p output
    if [[ ! -f "$MANIFEST" ]]; then
        printf 'experiment,hop,n_ips,n_ports,n_pads,pad_interval,bg_mbps,slug\n' \
            > "$MANIFEST"
    fi
    if ! grep -qF "$slug" "$MANIFEST" 2>/dev/null; then
        printf '%s,%d,%d,%d,%d,%d,%d,%s\n' \
            "$experiment" "$hop" "$n_ips" "$n_ports" "$n_pads" \
            "$pad_interval" "$mbps" "$slug" >> "$MANIFEST"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
log "=== E0: main result (defaults) ==="
run_baseline "$DEFAULT_MBPS"
run_config "E0-default" \
    $DEFAULT_HOP "$DEFAULT_IP_POOL" "$DEFAULT_PORT_POOL" \
    "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $DEFAULT_MBPS

# ─────────────────────────────────────────────────────────────────────────────
log "=== E1: address-space diversity (IP hop x port hop) ==="
# E0-default = (IP hop yes, port hop yes) — already done above.
run_config "E1-no-hop" \
    $DEFAULT_HOP "10.1.0.2" "8883" \
    "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $DEFAULT_MBPS

run_config "E1-port-only" \
    $DEFAULT_HOP "10.1.0.2" "$DEFAULT_PORT_POOL" \
    "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $DEFAULT_MBPS

run_config "E1-ip-only" \
    $DEFAULT_HOP "$DEFAULT_IP_POOL" "8883" \
    "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $DEFAULT_MBPS

# ─────────────────────────────────────────────────────────────────────────────
log "=== E2: hop interval sweep ==="
# hop=2 = E0-default, already done.
for hop in 1 5 10 30; do
    run_config "E2-hop${hop}" \
        $hop "$DEFAULT_IP_POOL" "$DEFAULT_PORT_POOL" \
        "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $DEFAULT_MBPS
done

# ─────────────────────────────────────────────────────────────────────────────
log "=== E3: background noise sweep ==="
# mbps=2 = E0-default, already done.
# Re-run baseline at each noise level so baseline and MTD see the same SNR.
for mbps in 1 5 10; do
    run_baseline "$mbps"
    run_config "E3-mbps${mbps}" \
        $DEFAULT_HOP "$DEFAULT_IP_POOL" "$DEFAULT_PORT_POOL" \
        "$DEFAULT_PAD_BUCKETS" $DEFAULT_PAD_INT $mbps
done

# ─────────────────────────────────────────────────────────────────────────────
log "=== Sweep complete ==="
log "Manifest : $MANIFEST"
log "Next     : $PYTHON plot_sweep.py"
