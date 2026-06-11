import argparse
import logging
import docker
import tarfile
import io
import os
import time

from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

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


def main(replay_background: bool = True):
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
    router.create_file_from_path("assets/pcap/traccia.pcap", "traccia.pcap")

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
        f"python3 cert_client.py --shared-key {shared_key} --ca-host 10.1.0.2 --cn scmc1 --out-dir certs/",
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
    manager.exec_obj(semp, "python3 mtd_coordinator.py --control-port 9998 --ip-pool 10.1.0.2 --port-pool 8883,8884,8885 --real-port 18883 --hop-interval 5 --pad-buckets 256,512,1024 --pad-interval 5")

    if replay_background:
        log.info("Starting background traffic replay on router")
        manager.exec_obj(router, "bash ./replay_background.sh eth1 2 0")
    else:
        log.info("Skipping background traffic replay (--no-background)")

    log.info("Starting scmc client")
    agent_stream = manager.exec_obj(scmc, "python3 mtd_executor.py --grid-id scmc1 --broker 10.1.0.2 --ssl --cafile certs/ca.crt --certfile certs/client.crt --keyfile certs/client.key --semp-control-ip 10.1.0.2 --semp-control-port 9998")
    # _drain(agent_stream, to_print=True) 

    # Live sniffing 
    log.info("Starting traffic caputure")
    attacker_stream = manager.exec_obj(
        attacker,
        "timeout 30 tcpdump -i eth0 -w attacker_capture.pcap",
    )

    router_stream = manager.exec_obj(
        router,
        "timeout 50 tcpdump -i eth1 -w router_capture.pcap",
    )

    log.info("Waiting attacker capture for creating the live dataset")
    _drain(attacker_stream)

    # Run the model on the captured traffic to get the ip of the mqtt client
    log.info("Processing captured traffic")
    # ... (model execution code would go here)
    time.sleep(2)  # Simulate time taken by model execution
    scmc_ip = "10.0.0.2"
    # Adding filter to drop all traffic from the identified MQTT client IP
    log.info(f"Blocking traffic from identified MQTT client IP: {scmc_ip}")
    manager.exec_obj(
        router,
        f"iptables -A FORWARD -s {scmc_ip} -j DROP",
    )

    log.info("Waiting experiment end")
    _drain(router_stream)

    
    log.info("Downloading files from containers")
    download_file_from_container(attacker.api_object, "attacker_capture.pcap", "./output/attacker_capture.pcap")
    download_file_from_container(router.api_object, "router_capture.pcap", "./output/router_capture.pcap")
    download_file_from_container(
        semp.api_object, "/var/log/mosquitto/mosquitto.log", "./output/mosquitto.log"
    )
    log.info("Capture saved to capture.pcap")

    log.info("Undeploying lab")
    manager.undeploy_lab(lab=lab)
    log.info("Done")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the smart-grid MTD Kathara experiment")
    parser.add_argument(
        "--no-background",
        action="store_true",
        help="Do not replay the background PCAP trace on the router",
    )
    args = parser.parse_args()

    main(replay_background=not args.no_background)
