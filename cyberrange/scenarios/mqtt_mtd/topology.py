"""topology.py — the MQTT smart-grid lab.

    scmc 10.0.0.2 (+ source-IP pool) ── A ── router ── B ── semp 10.1.0.2 (+ broker IP pool)
                                     10.0.0.1  10.1.0.1  └─ attacker 10.1.0.3 (sniffs B)

The router replays a real background trace onto link B; the attacker sniffs B.
With the dashboard on, the semp gets a bridged management NIC + port forward,
kept apart from link B so its traffic never reaches the attacker's capture —
hence the semp's default route is *replaced* onto eth0.
"""

from cyberrange.core.topology import Iface, Node, Route, Topology
from cyberrange.scenarios.mqtt_mtd.guest_files import (
    ROUTER_FILES, SCMC_FILES, SEMP_FILES, SEMP_RL_FILES,
)

LAB_NAME = "test"
IMAGE = "kathara/mqtt"
LINK_A, LINK_B = "A", "B"
SCMC_IP = "10.0.0.2"
ROUTER_A_IP, ROUTER_B_IP = "10.0.0.1", "10.1.0.1"
SEMP_IP = "10.1.0.2"
ATTACKER_IP = "10.1.0.3"
DASHBOARD_GUEST_PORT = 8080
TRACE_GUEST = "traccia.pcap"
POLICY_GUEST, DETECTOR_GUEST = "/policy.npz", "/detector.npz"
MOSQUITTO_CONF = {False: "assets/mosquitto/mosquitto.conf",       # MTD: NATed pool + loopback
                  True: "assets/mosquitto/mosquitto_nomtd.conf"}  # baseline: 8883 directly


def pool(spec):
    return [x.strip() for x in spec.split(",") if x.strip()]


def dashboard_on(args):
    return bool(getattr(args, "dashboard_port", 0)) and not args.no_mtd


def topology(args) -> Topology:
    mtd = not args.no_mtd
    semp_files = list(SEMP_FILES) + [(MOSQUITTO_CONF[args.no_mtd], "/etc/mosquitto/mosquitto.conf")]
    if mtd and args.rl_policy:
        # RL coordinator + its numpy-only deps (it subclasses mtd_coordinator.py).
        semp_files += list(SEMP_RL_FILES) + [(args.rl_policy, POLICY_GUEST)]
    if args.detector_model and mtd:
        semp_files.append((args.detector_model, DETECTOR_GUEST))
    # The MTD hops across these: they must be bound before anything uses them.
    scmc_aliases = [f"{ip}/24" for ip in pool(args.mtd_scmc_ip_pool)[1:]] if mtd else []
    semp_aliases = [f"{ip}/24" for ip in pool(args.mtd_ip_pool)[1:]] if mtd else []
    return Topology(LAB_NAME, default_image=IMAGE, nodes=[
        Node("scmc", [Iface(LINK_A, f"{SCMC_IP}/24", aliases=scmc_aliases)], role="target",
             routes=[Route("default", ROUTER_A_IP, "eth0")], files=SCMC_FILES),
        Node("router", [Iface(LINK_A, f"{ROUTER_A_IP}/24"), Iface(LINK_B, f"{ROUTER_B_IP}/24")],
             role="infra", files=list(ROUTER_FILES) + [(args.trace, TRACE_GUEST)]),
        Node("semp", [Iface(LINK_B, f"{SEMP_IP}/24", aliases=semp_aliases)], role="target",
             routes=[Route("default", ROUTER_B_IP, "eth0", replace=True)], files=semp_files,
             mgmt_port=(f"{args.dashboard_port}:{DASHBOARD_GUEST_PORT}/tcp"
                        if dashboard_on(args) else None)),
        # The attacker runs Kathará's default image (tcpdump only; scoring is host-side).
        Node("attacker", [Iface(LINK_B, f"{ATTACKER_IP}/24")], image="",
             role="attacker", routes=[Route("default", ROUTER_B_IP, "eth0")]),
    ])
