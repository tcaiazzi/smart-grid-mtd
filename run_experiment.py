import argparse
import logging
import docker
import tarfile
import io
import os
import time

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

from classify import (
    extract_features,
    load_artifacts,
    predict_packets,
    rank_nanogrid_ips,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)


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


def _drain(exec_stream, to_print=False):
    """Exhaust a DockerExecStream so the command runs to completion."""
    try:
        while True:
            e = next(exec_stream)
            if to_print:
                print(e)
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
        "→ output/datasets/dataset.pcap). Use different names for "
        "train/test captures, e.g. --name train, --name test.",
    )
    p.add_argument(
        "--trace",
        default="assets/pcap/traccia_2b.pcap",
        help="Local path to the background PCAP trace replayed by tcpreplay "
        "(default: assets/pcap/traccia_2b.pcap).",
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
        "--model",
        default="output/ml_results/model.pt",
        help="Path to the trained model (default: output/ml_results/model.pt).",
    )
    p.add_argument(
        "--scaler",
        default="output/ml_results/scaler.pkl",
        help="Path to the fitted scaler (default: output/ml_results/scaler.pkl).",
    )
    return p.parse_args()


def main():
    args = _parse_args()

    log.info("Initializing Kathara manager")
    manager = Kathara.get_instance()
    manager.wipe()

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
    semp.create_file_from_path(
        "assets/mosquitto/mosquitto.conf", "/etc/mosquitto/mosquitto.conf"
    )
    scmc.create_file_from_path("assets/mtd_executor.py", "mtd_executor.py")
    scmc.create_file_from_path("assets/qkd/cert_client.py", "/cert_client.py")
    router.create_file_from_path("assets/replay_background.sh", "replay_background.sh")
    router.create_file_from_path(args.trace, "traccia.pcap")

    log.info("Creating startup files")
    lab.create_startup_file_from_list(
        scmc,
        [
            "ip address add 10.0.0.2/24 dev eth0",
            "ip route add default via 10.0.0.1 dev eth0",
        ],
    )

    lab.create_startup_file_from_list(
        semp,
        [
            "ip address add 10.1.0.2/24 dev eth0",
            "ip route add default via 10.1.0.1 dev eth0",
        ],
    )

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

    log.info("Deploying lab")
    manager.deploy_lab(lab=lab)

    log.info("Generating shared key simulating QKD")
    shared_key = generate_shared_key()

    log.info("Executing certification authority server")
    manager.exec_obj(
        semp,
        f"python3 cert_authority.py --shared-key {shared_key} --host 0.0.0.0 --port 9999 --out-dir /etc/mosquitto/certs/ --server-cn semp --server-ip 10.1.0.2",
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
    manager.exec_obj(
        semp,
        "python3 mtd_coordinator.py --control-port 9998 --ip-pool 10.1.0.2 --port-pool 8883,8884,8885 --real-port 18883 --hop-interval 5 --pad-buckets 256,512,1024 --pad-interval 5",
    )

    if args.generate_dataset is not None:
        duration = args.generate_dataset
        pcap_name = f"{args.name}.pcap"
        local_path = f"./output/datasets/{pcap_name}"

        log.info("[Dataset] Capturing mixed traffic (%ds) → %s", duration, local_path)
        manager.exec_obj(
            router,
            f"timeout {duration} bash ./replay_background.sh eth1 2 1",
        )
        manager.exec_obj(
            scmc,
            f"timeout {duration} python3 simple_client.py --ssl --cafile certs/ca.crt "
            "--certfile certs/client.crt --keyfile certs/client.key",
        )
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

    elif args.attack is not None:
        sniff_duration = args.attack

        log.info("[Attack] Starting background traffic replay on router")
        manager.exec_obj(router, "bash ./replay_background.sh eth1 2 0")

        log.info("[Attack] Starting scmc client")
        manager.exec_obj(
            scmc,
            "python3 simple_client.py --ssl --cafile certs/ca.crt "
            "--certfile certs/client.crt --keyfile certs/client.key",
        )

        log.info("[Attack] Starting router capture (before + after attack)")
        manager.exec_obj(router, "tcpdump -i eth1 -w router_capture.pcap")

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
            "./output/attacker_capture.pcap",
        )

        log.info("[Attack] Scoring capture with the trained model")
        detected_ip, ranking = detect_nanogrid_ip(
            "./output/attacker_capture.pcap", args.model, args.scaler
        )
        log.info("[Attack] Per-IP nanogrid ranking:\n%s", ranking.to_string())

        if detected_ip:
            log.info("[Attack] Blocking nanogrid IP: %s", detected_ip)
            manager.exec_obj(
                router,
                f"iptables -A FORWARD -s {detected_ip} -j DROP",
            )
        else:
            log.warning("[Attack] No nanogrid IP detected — nothing blocked")

        log.info("[Attack] Observing post-attack effect for %ds", args.post_attack)
        time.sleep(args.post_attack)

        log.info("[Attack] Stopping router capture")
        manager.exec_obj(router, "pkill -INT tcpdump")
        time.sleep(2)  # let tcpdump flush the file before download

        log.info("[Attack] Downloading router capture and broker log")
        download_file_from_container(
            router.api_object, "router_capture.pcap", "./output/router_capture.pcap"
        )
        download_file_from_container(
            semp.api_object,
            "/var/log/mosquitto/mosquitto.log",
            "./output/mosquitto.log",
        )
        log.info("[Attack] Captures saved to output/")

    log.info("Undeploying lab")
    manager.undeploy_lab(lab=lab)
    log.info("Done")


if __name__ == "__main__":
    main()
