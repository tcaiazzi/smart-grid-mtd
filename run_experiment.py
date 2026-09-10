import argparse
import logging
import docker
import sys
import tarfile
import io
import os
import time

from Kathara.manager.Kathara import Kathara
from Kathara.setting.Setting import Setting
from Kathara.model.Lab import Lab

from classify import (
    extract_features,
    load_artifacts,
    predict_packets,
    rank_nanogrid_ips,
)
from split_trace import split_trace

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger(__name__)


class _Tee:
    """A write-through stream that fans out to several underlying streams.

    Used to mirror stdout onto a log file while still printing to the console.
    """

    def __init__(self, *streams):
        self._streams = streams

    def write(self, data):
        for s in self._streams:
            s.write(data)
            s.flush()

    def flush(self):
        for s in self._streams:
            s.flush()


def setup_run_log(log_path: str) -> None:
    """Tee stdout and the logging output of this run into log_path.

    Captures both the experiment narration (log.* — deploy/capture/ranking) and
    plain prints (e.g. the model scoring) so each run leaves a self-contained
    transcript next to its artifacts. One shared, line-buffered file object backs
    both sinks so console and file stay in lock-step and a `tail -f` works live.
    """
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
    log_file = open(log_path, "w", buffering=1)
    sys.stdout = _Tee(sys.__stdout__, log_file)
    handler = logging.StreamHandler(log_file)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logging.getLogger().addHandler(handler)
    log.info("Logging this run to %s", log_path)


def generate_shared_key(n_bytes: int = 32) -> str:
    """Generate a random shared key. Returns a hex string."""
    return os.urandom(n_bytes).hex()


def download_file_from_container(
    container: docker.models.containers.Container, src_path: str, dst_path: str
) -> None:
    """
    Download a file from a Docker container to a local destination path.

    Args:
        container: Docker container object.
        src_path:  Absolute path to the file inside the container.
        dst_path:  Local path where the file will be saved.
    """
    bits, _ = container.get_archive(src_path)

    tar_bytes = io.BytesIO(b"".join(bits))
    with tarfile.open(fileobj=tar_bytes) as tar:
        member = tar.getmembers()[0]
        f = tar.extractfile(member)
        if f is None:
            raise ValueError(f"Could not extract file from path: {src_path}")

        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        with open(dst_path, "wb") as out:
            out.write(f.read())


def _drain(exec_stream, to_print=False, log_path=None):
    """Exhaust a DockerExecStream so the command runs to completion."""
    if log_path:
        os.remove(log_path) if os.path.exists(log_path) else None
    try:
        while True:
            e = next(exec_stream)
            if to_print:
                print(e)
            if log_path:
                with open(log_path, "a") as log:
                    log.write(e)
    except StopIteration:
        pass


def detect_nanogrid_ip(pcap_path: str, model_path: str, scaler_path: str) -> tuple:
    """
    Score a captured PCAP with the trained model and rank source IPs by how
    nanogrid-like their traffic is.

    Returns (top_ip, ranking) where ranking is the per-IP DataFrame from
    rank_nanogrid_ips (indexed by src_ip, sorted by nanogrid_frac desc).
    Returns ("", empty) if nothing could be scored.
    """
    df = extract_features(pcap_path)  # unlabeled — attacker has no ground truth
    model, scaler = load_artifacts(model_path, scaler_path)
    pkt_preds = predict_packets(df, model, scaler)
    ranking = rank_nanogrid_ips(pkt_preds)
    if ranking.empty:
        return "", ranking
    return str(ranking.index[0]), ranking


def scmc_client_command(args, duration=None, shared_key=None):
    """Build the SCMC publisher command for the active variant.

    Baseline (--no-mtd) runs the plain simple_client; otherwise the MTD executor.
    When `duration` is set the command is wrapped in `timeout` so it self-terminates.
    `shared_key` (QKD-simulated) encrypts the MTD control channel; passed only to
    the executor (the baseline simple_client has no control channel).
    """
    prefix = f"timeout {duration} " if duration is not None else ""
    if args.no_mtd:
        return (
            prefix
            + "python3 simple_client.py --broker 10.1.0.2 --port 8883 --ssl "
            "--cafile certs/ca.crt --certfile certs/client.crt "
            "--keyfile certs/client.key --log-file simple_client.log"
        )
    shared_key_arg = f" --shared-key {shared_key}" if shared_key else ""
    return (
        prefix
        + "python3 mtd_executor.py --grid-id scmc1 --broker 10.1.0.2 --ssl "
        "--cafile certs/ca.crt --certfile certs/client.crt --keyfile certs/client.key "
        "--semp-control-ip 10.1.0.2 --semp-control-port 9998 "
        f"--scmc-ip-pool {args.mtd_scmc_ip_pool} --log-file mtd_executor.log"
        f"{shared_key_arg}"
    )


def experiment_slug(args) -> str:
    """Compact directory name for one parameter configuration.

    Mirrors the Makefile's EXP_SLUG / MTD_PARAMS_SLUG exactly so a standalone run
    lands in the same output/<slug>/ directory the Makefile expects:
        baseline -> baseline-mbps<M>
        mtd      -> mtd-hop<H>-padint<PI>-ips<NI>-ports<NP>-pads<NB>-mbps<M>
    """
    if args.no_mtd:
        return f"baseline-mbps{args.bg_replay_mbps}"
    n_ips = len(args.mtd_ip_pool.split(","))
    n_ports = len(args.mtd_port_pool.split(","))
    n_pads = len(args.mtd_pad_buckets.split(","))
    n_scmc_ips = len(args.mtd_scmc_ip_pool.split(","))
    n_freqs = len(args.mtd_freq_pool.split(","))
    # An RL-coordinated run uses a distinct prefix so its artifacts sit beside the
    # fixed-timer run's instead of overwriting them (enables the RL-vs-fixed compare).
    # --rl-tag further separates competing RL policies (e.g. mtdrl-entropy-<slug>).
    if args.rl_policy:
        prefix = f"mtdrl-{args.rl_tag}" if args.rl_tag else "mtdrl"
    else:
        prefix = "mtd"
    return (
        f"{prefix}-hop{args.mtd_hop_interval}-padint{args.mtd_pad_interval}"
        f"-ips{n_ips}-ports{n_ports}-pads{n_pads}-srcips{n_scmc_ips}"
        f"-mbps{args.bg_replay_mbps}"
        f"-freqint{args.mtd_freq_interval}-freqs{n_freqs}"
    )


def scmc_ips(args) -> str:
    """Comma-separated SCMC source IPs used this run.

    Baseline uses the single static SCMC address; MTD hops across the pool.
    Downstream tooling (classify.py, plot_results.py) reads this back to know
    which source IPs belong to the SCMC.
    """
    return "10.0.0.2" if args.no_mtd else args.mtd_scmc_ip_pool


def write_scmc_ips(args, dst_dir):
    """Record the SCMC source IPs used this run into <dst_dir>/scmc_ips.txt."""
    os.makedirs(dst_dir, exist_ok=True)
    with open(f"{dst_dir}/scmc_ips.txt", "w") as f:
        f.write(scmc_ips(args) + "\n")


def download_logs(scmc, semp, args, dst_dir, prefix=""):
    """Download the SCMC client log and the broker log into dst_dir.

    `prefix` (e.g. the capture name) is prepended to the filenames so several
    captures can share one directory without colliding (train.client.log vs
    test.client.log); attack runs pass no prefix (client.log / mosquitto.log).
    """
    log.info("Downloading client log")
    download_file_from_container(
        scmc.api_object,
        "simple_client.log" if args.no_mtd else "mtd_executor.log",
        f"{dst_dir}/{prefix}client.log",
    )
    log.info("Downloading broker log")
    download_file_from_container(
        semp.api_object,
        "/var/log/mosquitto/mosquitto.log",
        f"{dst_dir}/{prefix}mosquitto.log",
    )


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Smart-grid MTD experiment")
    p.add_argument(
        "--generate-dataset",
        type=int,
        metavar="DURATION",
        default=None,
        help="Capture a single mixed PCAP (background + SCMC together) "
        "for DURATION seconds.",
    )
    p.add_argument(
        "--name",
        default="dataset",
        help="Name tag for the output PCAP file (default: 'dataset' "
        "→ <datasets-dir>/dataset.pcap). Use different names for "
        "train/test captures, e.g. --name train, --name test.",
    )
    p.add_argument(
        "--trace",
        default="assets/pcap/traccia_2b.pcap",
        help="Local path to the background PCAP trace replayed by tcpreplay "
        "(default: assets/pcap/traccia_2b.pcap).",
    )
    p.add_argument(
        "--split",
        type=float,
        metavar="TRAIN_RATIO",
        default=None,
        help="Split the background trace by packet count before replaying: "
        "the first TRAIN_RATIO fraction goes to "
        "assets/pcap/datasets/<stem>_train.pcap, the rest to "
        "assets/pcap/datasets/<stem>_test.pcap. The test split is replayed "
        "when --name is 'test', the train split otherwise.",
    )
    p.add_argument(
        "--no-mtd",
        action="store_true",
        help="Baseline mode: no MTD. mosquitto listens directly on 8883 "
        "(dedicated config), the coordinator/executor are not started, and the "
        "SCMC runs the plain publisher (simple_client.py). Applies to --attack "
        "and --generate-dataset.",
    )
    p.add_argument(
        "--datasets-dir",
        default=None,
        metavar="DIR",
        help="Directory where the captured dataset PCAP + capture logs are saved "
        "(default: output/<exp-slug>/datasets/).",
    )
    p.add_argument(
        "--results-dir",
        default=None,
        metavar="DIR",
        help="Directory where attack artifacts are saved "
        "(default: output/<exp-slug>/attack/model-<variant>/).",
    )
    p.add_argument(
        "--attack",
        type=int,
        metavar="DURATION",
        default=None,
        help="Run the attacker emulation: sniff for DURATION seconds, score the "
        "capture with the trained model, block the top-ranked nanogrid IP.",
    )
    p.add_argument(
        "--post-attack",
        type=int,
        default=15,
        metavar="SECONDS",
        help="Seconds to keep the router capture running after the block, to "
        "record the post-attack effect (default: 15).",
    )
    p.add_argument(
        "--bg-replay-mbps",
        type=int,
        default=2,
        metavar="MBPS",
        help="Background trace replay rate in Mbit/s (default: 2).",
    )
    p.add_argument(
        "--model",
        default="output/model.pt",
        help="Path to the trained model used by --attack (the Makefile passes the "
        "per-experiment path; default output/model.pt is a standalone placeholder).",
    )
    p.add_argument(
        "--scaler",
        default="output/scaler.pkl",
        help="Path to the fitted scaler (the Makefile passes the per-experiment "
        "path; default output/scaler.pkl is a standalone placeholder).",
    )
    mtd = p.add_argument_group("MTD parameters (ignored in --no-mtd baseline mode)")
    mtd.add_argument(
        "--mtd-hop-interval",
        type=int,
        default=2,
        metavar="SECONDS",
        help="Seconds between hops (default: 2).",
    )
    mtd.add_argument(
        "--mtd-hop-timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="Seconds the coordinator awaits HOP_DONE before declaring a hop "
             "failed and rolling back (default: 10).",
    )
    mtd.add_argument(
        "--mtd-ip-pool",
        default="10.1.0.2,10.1.0.4,10.1.0.5",
        metavar="IPS",
        help="Comma-separated broker IP pool for IP hopping (default: 10.1.0.2,10.1.0.4,10.1.0.5).",
    )
    mtd.add_argument(
        "--mtd-port-pool",
        default="8883,8884,8885,8886,8887",
        metavar="PORTS",
        help="Comma-separated broker port pool for port hopping (default: 8883-8887).",
    )
    mtd.add_argument(
        "--mtd-pad-buckets",
        default="128,256,384,512,640,768,1024",
        metavar="SIZES",
        help="Comma-separated payload padding bucket sizes (default: 7 buckets).",
    )
    mtd.add_argument(
        "--mtd-pad-interval",
        type=int,
        default=3,
        metavar="SECONDS",
        help="Seconds between padding-scheme rotations (default: 3).",
    )
    mtd.add_argument(
        "--mtd-scmc-ip-pool",
        default="10.0.0.2,10.0.0.4,10.0.0.5",
        metavar="IPS",
        help="Comma-separated SCMC source IP pool for source-IP hopping. The first "
        "is the initial source; the SCMC is assigned all of them as aliases and "
        "rebinds across them (default: 10.0.0.2,10.0.0.4,10.0.0.5). A single entry "
        "disables source hopping.",
    )
    mtd.add_argument(
        "--mtd-src-hop-interval",
        type=int,
        default=2,
        metavar="SECONDS",
        help="Seconds between SCMC source-IP hops (default: 2).",
    )
    mtd.add_argument(
        "--mtd-freq-pool",
        default="1.0",
        metavar="SECONDS",
        help="Comma-separated publish intervals (seconds) for message-frequency "
        "hopping. A single entry disables it (default: 1.0).",
    )
    mtd.add_argument(
        "--mtd-freq-interval",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Seconds between publish-frequency changes (default: 30).",
    )
    mtd.add_argument(
        "--rl-policy",
        default=None,
        metavar="NPZ",
        help="Path to a distilled RL policy (.npz from train_rl_coordinator.py). "
        "When set, the RL coordinator (mtd_rl_coordinator.py) decides the schedule "
        "instead of the fixed-timer coordinator. Ignored in --no-mtd baseline mode.",
    )
    mtd.add_argument(
        "--rl-tick",
        type=float,
        default=1.0,
        metavar="SECONDS",
        help="Seconds between RL policy decisions (default: 1.0). Used only with "
        "--rl-policy.",
    )
    mtd.add_argument(
        "--rl-tag",
        default="",
        metavar="TAG",
        help="Optional label distinguishing competing RL policies in the output "
        "dir name (e.g. 'entropy' -> output/mtdrl-entropy-<slug>/). Used only with "
        "--rl-policy.",
    )
    return p.parse_args()


def main():
    args = _parse_args()

    # Variant label used for the per-experiment output dir and the model tag.
    variant = "baseline" if args.no_mtd else "mtd"

    # Tee this run's stdout into a log file next to its artifacts. The output dir
    # is recomputed identically inside the --generate-dataset / --attack branches.
    if args.generate_dataset is not None:
        datasets_dir = args.datasets_dir or f"./output/{experiment_slug(args)}/datasets"
        setup_run_log(f"{datasets_dir}/{args.name}.run.log")
    elif args.attack is not None:
        out_dir = args.results_dir or f"./output/{experiment_slug(args)}/attack/model-{variant}"
        setup_run_log(f"{out_dir}/run.log")

    log.info("Initializing Kathara manager")
    manager = Kathara.get_instance()

    Setting.get_instance().load_from_dict({"network_plugin": "kathara/katharanp_vde"})

    log.info("Creating lab and machines")
    lab = Lab("test")
    scmc = lab.new_machine("scmc", image="kathara/mqtt")
    router = lab.new_machine("router", image="kathara/mqtt")
    semp = lab.new_machine("semp", image="kathara/mqtt")
    attacker = lab.new_machine("attacker")

    log.info("Connecting machines to links")
    lab.connect_machine_obj_to_link(scmc, "A")
    lab.connect_machine_obj_to_link(router, "A")
    lab.connect_machine_obj_to_link(router, "B")
    lab.connect_machine_obj_to_link(semp, "B")
    lab.connect_machine_obj_to_link(attacker, "B")

    log.info("Copying asset files into machines")
    semp.create_file_from_path("assets/qkd/cert_authority.py", "/cert_authority.py")
    semp.create_file_from_path("assets/mtd_coordinator.py", "/mtd_coordinator.py")
    if args.rl_policy and not args.no_mtd:
        # RL coordinator + its numpy-only deps. mtd_coordinator.py (above) is the
        # base class it subclasses; rl_policy.py is imported by both.
        semp.create_file_from_path("assets/mtd_rl_coordinator.py", "/mtd_rl_coordinator.py")
        semp.create_file_from_path("rl_policy.py", "/rl_policy.py")
        semp.create_file_from_path(args.rl_policy, "/policy.npz")
    mosquitto_conf = (
        "assets/mosquitto/mosquitto_nomtd.conf"
        if args.no_mtd
        else "assets/mosquitto/mosquitto.conf"
    )
    semp.create_file_from_path(mosquitto_conf, "/etc/mosquitto/mosquitto.conf")
    scmc.create_file_from_path("assets/mtd_executor.py", "mtd_executor.py")
    scmc.create_file_from_path("assets/simple_client.py", "simple_client.py")
    scmc.create_file_from_path("assets/qkd/cert_client.py", "/cert_client.py")
    router.create_file_from_path("assets/replay_background.sh", "replay_background.sh")

    logging.info("Background trace: %s", args.trace)
    trace_path = args.trace
    if args.split is not None:
        out_dir = "assets/pcap/datasets"
        os.makedirs(out_dir, exist_ok=True)
        stem = os.path.splitext(os.path.basename(args.trace))[0]
        train_path, test_path = split_trace(
            args.trace,
            args.split,
            train_path=os.path.join(out_dir, f"{stem}_train.pcap"),
            test_path=os.path.join(out_dir, f"{stem}_test.pcap"),
        )
        trace_path = test_path if args.name == "test" else train_path
        log.info("Replaying %s split of the background trace: %s",
                 "test" if args.name == "test" else "train", trace_path)
    router.create_file_from_path(trace_path, "traccia.pcap")

    log.info("Creating startup files")
    scmc_startup = [
        "ip address add 10.0.0.2/24 dev eth0",
        "ip route add default via 10.0.0.1 dev eth0",
    ]
    if not args.no_mtd:
        # Extra source IPs the executor hops across (bound as local source on its
        # MQTT + control sockets). Must be assigned before it can bind to them.
        scmc_pool = [x.strip() for x in args.mtd_scmc_ip_pool.split(",")]
        for extra_ip in scmc_pool[1:]:
            scmc_startup.append(f"ip address add {extra_ip}/24 dev eth0")
    lab.create_startup_file_from_list(scmc, scmc_startup)

    semp_startup = [
        "ip address add 10.1.0.2/24 dev eth0",
        "ip route add default via 10.1.0.1 dev eth0",
    ]
    if not args.no_mtd:
        ip_pool = [x.strip() for x in args.mtd_ip_pool.split(",")]
        for extra_ip in ip_pool[1:]:
            semp_startup.append(f"ip address add {extra_ip}/24 dev eth0")
    lab.create_startup_file_from_list(semp, semp_startup)

    lab.create_startup_file_from_list(
        router,
        ["ip address add 10.0.0.1/24 dev eth0", "ip address add 10.1.0.1/24 dev eth1"],
    )

    lab.create_startup_file_from_list(
        attacker,
        [
            "ip address add 10.1.0.3/24 dev eth0",
            "ip route add default via 10.1.0.1 dev eth0",
        ],
    )

    log.info("Undeploying eventually existing lab (to avoid conflicts)")
    manager.undeploy_lab(lab=lab)

    log.info("Deploying lab")
    manager.deploy_lab(lab=lab)

    log.info("Generating shared key simulating QKD")
    shared_key = generate_shared_key()

    log.info("Executing certification authority server")
    manager.exec_obj(
        semp,
        f"python3 cert_authority.py --shared-key {shared_key} --host 0.0.0.0 --port 9999 --out-dir /etc/mosquitto/certs/ --server-cn semp --server-ip {args.mtd_ip_pool} --client-ip {args.mtd_scmc_ip_pool}",
        wait=False,
    )

    log.info("Executing certification client for getting client certificate and key")
    manager.exec_obj(
        scmc,
        f'bash -c "sleep 1; python3 cert_client.py --shared-key {shared_key} --ca-host 10.1.0.2 --cn scmc1 --out-dir certs/"',
        stream=False,
    )

    log.info("Waiting for mosquitto server on semp")
    manager.exec_obj(
        semp,
        'bash -c "chown mosquitto:mosquitto /etc/mosquitto/certs/server.key;'
        "chmod 640 /etc/mosquitto/certs/server.key;"
        "chown mosquitto:mosquitto /etc/mosquitto/certs/ca.crt /etc/mosquitto/certs/server.crt;"
        'chmod 644 /etc/mosquitto/certs/ca.crt /etc/mosquitto/certs/server.crt"',
        stream=False,
    )

    manager.exec_obj(semp, "mosquitto -c /etc/mosquitto/mosquitto.conf -d", wait=True)
    if args.no_mtd:
        log.info("[Baseline] MTD disabled — coordinator not started (mosquitto on 8883)")
    elif args.rl_policy:
        log.info("[MTD] Starting RL coordinator (policy %s, tick %ss)",
                 args.rl_policy, args.rl_tick)
        manager.exec_obj(
            semp,
            f"python3 mtd_rl_coordinator.py --policy policy.npz --tick {args.rl_tick}"
            f" --control-port 9998"
            f" --ip-pool {args.mtd_ip_pool}"
            f" --port-pool {args.mtd_port_pool} --real-port 18883"
            f" --hop-timeout {args.mtd_hop_timeout}"
            f" --pad-buckets {args.mtd_pad_buckets}"
            f" --scmc-ip-pool {args.mtd_scmc_ip_pool}"
            f" --freq-pool {args.mtd_freq_pool}"
            f" --shared-key {shared_key}",
        )
    else:
        manager.exec_obj(
            semp,
            f"python3 mtd_coordinator.py --control-port 9998"
            f" --ip-pool {args.mtd_ip_pool}"
            f" --port-pool {args.mtd_port_pool} --real-port 18883"
            f" --hop-interval {args.mtd_hop_interval}"
            f" --hop-timeout {args.mtd_hop_timeout}"
            f" --pad-buckets {args.mtd_pad_buckets}"
            f" --pad-interval {args.mtd_pad_interval}"
            f" --scmc-ip-pool {args.mtd_scmc_ip_pool}"
            f" --src-hop-interval {args.mtd_src_hop_interval}"
            f" --freq-pool {args.mtd_freq_pool}"
            f" --freq-interval {args.mtd_freq_interval}"
            f" --shared-key {shared_key}",
        )

    if args.generate_dataset is not None:
        duration = args.generate_dataset
        datasets_dir = args.datasets_dir or f"./output/{experiment_slug(args)}/datasets"
        os.makedirs(datasets_dir, exist_ok=True)
        pcap_name = f"{args.name}.pcap"
        local_path = f"{datasets_dir}/{pcap_name}"

        log.info("[Dataset] Capturing mixed traffic (%ds) → %s", duration, local_path)
        log.info("[Dataset] Starting background traffic replay on router at %d Mbps", args.bg_replay_mbps)
        manager.exec_obj(
            router,
            f"timeout {duration} bash ./replay_background.sh eth1 {args.bg_replay_mbps} 0",
        )
        log.info("[Dataset] Starting SCMC client in parallel with the replay")
        agent_stream = manager.exec_obj(scmc, scmc_client_command(args, shared_key=shared_key))
        # _drain(agent_stream, to_print=True)

        # manager.connect_tty_obj(scmc)
        # manager.connect_tty_obj(router)
        # manager.connect_tty_obj(semp)

        capture_stream = manager.exec_obj(
            router,
            f"timeout {duration} tcpdump -i eth1 -w {pcap_name}",
        )
        log.info("[Dataset] Waiting for capture to finish")
        _drain(capture_stream)

        log.info("[Dataset] Downloading dataset from container")
        download_file_from_container(
            router.api_object,
            pcap_name,
            local_path,
        )
        log.info("[Dataset] Dataset saved to %s", local_path)

        download_logs(scmc, semp, args, datasets_dir, prefix=f"{args.name}.")
        write_scmc_ips(args, datasets_dir)

    elif args.attack is not None:
        sniff_duration = args.attack
        out_dir = args.results_dir or f"./output/{experiment_slug(args)}/attack/model-{variant}"
        os.makedirs(out_dir, exist_ok=True)
        attacker_cap = f"{out_dir}/attacker_capture.pcap"

        log.info("[Attack] Starting background traffic replay on router")
        manager.exec_obj(router, f"bash ./replay_background.sh eth1 {args.bg_replay_mbps} 0")

        log.info("[Attack] Starting scmc client")
        agent_stream = manager.exec_obj(scmc, scmc_client_command(args, shared_key=shared_key))
        # _drain(agent_stream, to_print=True)

        log.info("[Attack] Starting router capture (before + after attack)")
        manager.exec_obj(router, "tcpdump -i eth1 -w router_capture.pcap")

        log.info("[Attack] Starting scmc capture (before + after attack)")
        manager.exec_obj(scmc, "tcpdump -i eth0 -w scmc_capture.pcap")

        # Attacker sniffs link B for `sniff_duration` seconds to build its dataset.
        log.info("[Attack] Attacker sniffing for %ds", sniff_duration)
        attacker_stream = manager.exec_obj(
            attacker,
            f"timeout {sniff_duration} tcpdump -i eth0 -w attacker_capture.pcap",
        )
        _drain(attacker_stream)

        log.info("[Attack] Downloading attacker capture")
        download_file_from_container(
            attacker.api_object,
            "attacker_capture.pcap",
            attacker_cap,
        )

        log.info("[Attack] Scoring capture with the trained model")
        detected_ip, ranking = detect_nanogrid_ip(
            attacker_cap, args.model, args.scaler
        )
        log.info("[Attack] Per-IP nanogrid ranking:\n%s", ranking.to_string())

        with open(f"{out_dir}/nanogrid_ranking.csv", "w") as f:
            f.write(ranking.to_csv())

        if detected_ip:
            log.info("[Attack] Blocking nanogrid IP: %s", detected_ip)
            manager.exec_obj(
                router,
                f"iptables -A FORWARD -s {detected_ip} -j DROP",
            )
        else:
            log.warning("[Attack] No nanogrid IP detected — nothing blocked")

        log.info("[Attack] Observing post-attack effect for %ds", args.post_attack)
        post_attack_stream = manager.exec_obj(
            attacker,
            f"timeout {args.post_attack} tcpdump -i eth0 -w post_attack_capture.pcap",
        )
        _drain(post_attack_stream)

        log.info("[Attack] Stopping router capture")
        manager.exec_obj(router, "pkill -INT tcpdump")
        time.sleep(2)  # let tcpdump flush the file before download

        log.info("[Attack] Downloading router capture")
        download_file_from_container(
            router.api_object, "router_capture.pcap", f"{out_dir}/router_capture.pcap"
        )

        download_file_from_container(
            attacker.api_object, "post_attack_capture.pcap", f"{out_dir}/post_attack_capture.pcap"
        )

        log.info("[Attack] Downloading scmc capture")
        download_file_from_container(
            scmc.api_object, "scmc_capture.pcap", f"{out_dir}/scmc_capture.pcap"
        )
        download_logs(scmc, semp, args, out_dir)
        write_scmc_ips(args, out_dir)
        log.info("[Attack] Captures saved to %s/", out_dir)

    log.info("Undeploying lab")
    manager.undeploy_lab(lab=lab)
    log.info("Done")


if __name__ == "__main__":
    main()
