"""MQTT smart-grid scenario (the workshop paper's): a nanogrid's SCMC publishes
to the SEMP broker over mutual TLS, a passive attacker fingerprints the traffic
with a CNN and blackholes the nanogrid, and a moving-target defense (fixed
timers or an RL policy) morphs the traffic to defeat the fingerprinting."""

# What this scenario is made of, by category, for the platform's code-size
# accounting (python -m network_scenario.core loc). Guest agents come from the
# deploy manifests (network_scenario/guest_files.py) of the nodes listed here.
SOURCES = {
    "scenario (topology, episode, CLI, campaign)": [
        "network_scenario/scenarios/mqtt_mtd/*.py", "network_scenario/run_experiment.py",
        "network_scenario/detection_scenario.py", "network_scenario/slug.py", "main.py"],
    "metrics": ["monitor/mqtt_metrics.py"],
    "analysis & paper figures": [
        "monitor/compare_coordinators.py", "monitor/plot_results.py", "monitor/entropy.py",
        "monitor/plot_sweep.py", "defense_plane/plot_tradeoff.py"],
    "host-side domain logic (CNN attacker, RL training, detector training)": [
        "attack_plane/classify.py", "attack_plane/thresholds.py", "defense_plane/mtd_env.py",
        "defense_plane/train_rl_coordinator.py", "defense_plane/train_delivery_detector.py",
        "monitor/delivery_dataset.py", "traffic_generator/split_trace.py"],
}
GUEST_MANIFESTS = ("SEMP_FILES", "SEMP_RL_FILES", "SCMC_FILES", "ROUTER_FILES")
