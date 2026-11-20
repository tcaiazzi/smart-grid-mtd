"""scenario.py — the MQTT smart-grid scenario on the platform core.

One run is one of three modes:

  dataset (--generate-dataset N)  capture N s of mixed traffic on link B (the
          attacker's training/test data): <datasets-dir>/<name>.pcap + logs
  attack  (--attack N)            sniff N s, fingerprint the nanogrid with the CNN,
          blackhole the chosen IP (or an oracle's, with benign faults), observe
          --post-attack s: captures + ranking + ground truth in <results-dir>
  idle    (neither)               bring the system up and tear it down

Composition (plane components):
    traffic   BackgroundReplay, ScmcPublisher
    defense   QkdCertBootstrap, MtdCoordinator (fixed | RL)
    attack    PassiveFingerprinter, DeliveryAttack
    monitor   Capture (router, scmc), TelemetryMirror

Output names are the contract of the host tools downstream (classify, entropy,
plot_results, compare_coordinators, delivery_dataset); see docs/platform.md.
"""

import logging
import os

from cyberrange.planes.attack import components as attack
from cyberrange.planes.defense import components as defense
from cyberrange.planes.monitor import components as monitor
from cyberrange.core.context import drain, tee_run_log
from cyberrange.core.scenario import PhaseSpec, Scenario
from cyberrange.scenarios.mqtt_mtd import topology as T
from cyberrange.scenarios.mqtt_mtd.slug import experiment_slug
from cyberrange.planes.traffic import components as traffic

log = logging.getLogger("scenarios.mqtt_mtd")

EXIT_NO_PUBLISH = 3  # exit code of a run whose SCMC never published
OVERHEAD_S = {"deploy": 5.0, "services": 12.0, "score": 15.0, "download": 3.0, "undeploy": 3.0}


# ── run validity ──────────────────────────────────────────────────────────────
def _publish_re():
    import re

    # A line the SCMC publisher logs per publish: mtd_executor "#<n> → ip:port",
    # simple_client "power=...".
    return re.compile(r"\] (?:#\d+ →|power=)")


PUBLISH_RE = _publish_re()


def count_publishes(client_log: str) -> int:
    """Publishes recorded in a downloaded SCMC client log (0 if it is missing)."""
    if not os.path.exists(client_log):
        return 0
    with open(client_log, errors="replace") as f:
        return sum(1 for line in f if PUBLISH_RE.search(line))


def check_published(client_log: str, discard=()) -> bool:
    """True if the SCMC published at least once during this run.

    Otherwise the run is unusable (e.g. the publisher died at startup): log it,
    delete ``discard`` (the run's capture, so Make's order-only rules regenerate
    it instead of training on an empty nanogrid flow) and return False.
    """
    n = count_publishes(client_log)
    if n:
        log.info("SCMC published %d messages", n)
        return True
    log.error(
        "SCMC never published (see %s and the client.console.log next to it) — run discarded",
        client_log,
    )
    for path in discard:
        if os.path.exists(path):
            os.remove(path)
            log.error("Removed %s", path)
    return False


def scmc_ips(args) -> str:
    """The SCMC source IPs of this run (downstream tools read them back)."""
    return T.SCMC_IP if args.no_mtd else args.mtd_scmc_ip_pool


def mode_of(args):
    if args.generate_dataset is not None:
        return "dataset"
    if args.attack is not None:
        return "attack"
    return "idle"


def variant_of(args):
    return "baseline" if args.no_mtd else "mtd"


class MqttMtdScenario(Scenario):
    name = "mqtt-mtd"
    lab_name = T.LAB_NAME
    overhead_s = OVERHEAD_S

    # ── options ──────────────────────────────────────────────────────────────
    def add_arguments(self, ap):
        from cyberrange.planes.attack.thresholds import DETECT_THRESHOLD

        mode = ap.add_mutually_exclusive_group()
        mode.add_argument(
            "--generate-dataset",
            type=int,
            metavar="DURATION",
            default=None,
            help="capture DURATION s of mixed traffic (background + SCMC)",
        )
        mode.add_argument(
            "--attack",
            type=int,
            metavar="DURATION",
            default=None,
            help="sniff DURATION s, score the capture with the trained "
            "model, block the top-ranked nanogrid IP",
        )
        g = ap.add_argument_group("mqtt scenario")
        g.add_argument(
            "--name",
            default="dataset",
            help="dataset mode: capture name (<datasets-dir>/<name>.pcap); it "
            "also seeds the run (train/test captures differ)",
        )
        g.add_argument(
            "--trace",
            default="assets/pcap/traccia.pcap",
            help="background PCAP trace replayed by the router",
        )
        g.add_argument("--bg-replay-mbps", type=int, default=2, metavar="MBPS")
        g.add_argument(
            "--no-mtd",
            action="store_true",
            help="baseline: no MTD (mosquitto on 8883, plain publisher)",
        )
        g.add_argument(
            "--datasets-dir",
            default=None,
            metavar="DIR",
            help="dataset mode output (default output/<slug>/datasets)",
        )
        g.add_argument(
            "--results-dir",
            default=None,
            metavar="DIR",
            help="attack mode output (default output/<slug>/attack/model-<variant>)",
        )
        g.add_argument(
            "--dashboard-port",
            type=int,
            default=8080,
            metavar="PORT",
            help="host port of the live MTD dashboard on the semp (0 = off)",
        )
        a = ap.add_argument_group("mqtt attack")
        a.add_argument(
            "--post-attack",
            type=int,
            default=15,
            metavar="SECONDS",
            help="seconds observed after the block",
        )
        a.add_argument(
            "--block-policy",
            choices=attack.BLOCK_POLICIES,
            default="top1",
            help="top1: always block the top-ranked IP (the paper); threshold: "
            "only if its nanogrid_frac >= --block-threshold",
        )
        a.add_argument("--block-threshold", type=float, default=DETECT_THRESHOLD)
        a.add_argument("--model", default="output/model.pt")
        a.add_argument("--scaler", default="output/scaler.pkl")
        a.add_argument(
            "--oracle-block",
            choices=("src", "broker", "random"),
            default=None,
            help="blackhole the address the SCMC uses right now instead of "
            "the CNN's pick (worst-case attacker)",
        )
        a.add_argument(
            "--block-duration",
            type=float,
            default=None,
            metavar="SECONDS",
            help="lift each blackhole after SECONDS (default: never)",
        )
        a.add_argument("--block-episodes", type=int, default=1, metavar="N")
        a.add_argument(
            "--impair-profile",
            choices=("none", "random"),
            default="none",
            help="random: seeded benign faults in the post-attack phase",
        )
        a.add_argument(
            "--detector-model",
            default=None,
            metavar="NPZ",
            help="run the delivery-attack detector live on the semp",
        )
        m = ap.add_argument_group("MTD (ignored with --no-mtd)")
        m.add_argument("--mtd-hop-interval", type=int, default=2, metavar="SECONDS")
        m.add_argument("--mtd-hop-timeout", type=float, default=10.0, metavar="SECONDS")
        m.add_argument("--mtd-ip-pool", default="10.1.0.2,10.1.0.4,10.1.0.5", metavar="IPS")
        m.add_argument("--mtd-port-pool", default="8883,8884,8885,8886,8887", metavar="PORTS")
        m.add_argument("--mtd-pad-buckets", default="128,256,384,512,640,768,1024")
        m.add_argument("--mtd-pad-interval", type=int, default=3, metavar="SECONDS")
        m.add_argument("--mtd-scmc-ip-pool", default="10.0.0.2,10.0.0.4,10.0.0.5", metavar="IPS")
        m.add_argument("--mtd-src-hop-interval", type=int, default=2, metavar="SECONDS")
        m.add_argument("--mtd-freq-pool", default="1.0", metavar="SECONDS")
        m.add_argument("--mtd-freq-interval", type=int, default=30, metavar="SECONDS")
        m.add_argument(
            "--rl-policy",
            default=None,
            metavar="NPZ",
            help="distilled RL policy: the RL coordinator decides the schedule",
        )
        m.add_argument("--rl-tick", type=float, default=1.0, metavar="SECONDS")
        m.add_argument(
            "--rl-tag",
            default="",
            metavar="TAG",
            help="labels competing RL policies in the default output dir name",
        )

    def topology(self, args):
        return T.topology(args)

    # ── where and what ───────────────────────────────────────────────────────
    def out_dir(self, args):
        slug = experiment_slug(args)
        mode = mode_of(args)
        if mode == "dataset":
            return args.datasets_dir or f"./output/{slug}/datasets"
        if mode == "attack":
            return args.results_dir or f"./output/{slug}/attack/model-{variant_of(args)}"
        return f"./output/{slug}/idle"

    def run_id(self, args):
        if getattr(args, "run_id", None):
            return args.run_id
        if mode_of(args) == "dataset":
            return args.name
        return super().run_id(args)

    def prefix(self, args):
        """Per-capture file prefix: several captures share a datasets dir."""
        return f"{args.name}." if mode_of(args) == "dataset" else ""

    def role(self, args):
        return args.name if mode_of(args) == "dataset" else "attack"

    def prepare(self, args):
        mode = mode_of(args)
        if mode != "idle":
            tee_run_log(os.path.join(self.out_dir(args), f"{self.prefix(args)}run.log"))

    def episode_phases(self, args):
        mode = mode_of(args)
        ph = [PhaseSpec("services", OVERHEAD_S["services"])]
        if mode == "dataset":
            ph.append(PhaseSpec("capture", float(args.generate_dataset), timed=True))
        elif mode == "attack":
            ph += [
                PhaseSpec("sniff", float(args.attack), timed=True),
                PhaseSpec("score", OVERHEAD_S["score"]),
                PhaseSpec("post_attack", float(args.post_attack), timed=True),
            ]
        return ph

    def run_info(self, args):
        return dict(
            mode=mode_of(args),
            variant=variant_of(args),
            seed=args.seed,
            run_seed=self._seed(args),
            name=args.name,
            mbps=args.bg_replay_mbps,
            rl_policy=args.rl_policy,
            oracle_block=args.oracle_block,
        )

    def _seed(self, args):
        from cyberrange.core.context import role_seed

        return role_seed(args.seed, self.role(args))

    def metrics(self, run_dir):
        from cyberrange.scenarios.mqtt_mtd.metrics import compute_metrics

        return compute_metrics(run_dir)

    def panel_js(self):
        """The run queue and detail card for this scenario: the attacker's
        confidence, the MTD actions and what each one cost."""
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.js")

    # ── episode ──────────────────────────────────────────────────────────────
    def episode(self, ctx):
        a = ctx.args
        mtd = not a.no_mtd
        mode = mode_of(a)
        run_seed = ctx.role_seed(self.role(a))
        log.info("Seed: %s (run seed %s)", a.seed, run_seed)
        key = defense.generate_shared_key()  # stands in for the QKD device output

        with ctx.phase("services"):
            ctx.start(
                defense.QkdCertBootstrap("semp", "scmc", key, a.mtd_ip_pool, a.mtd_scmc_ip_pool)
            )
            ctx.run(
                "semp",
                'bash -c "chown mosquitto:mosquitto /etc/mosquitto/certs/server.key;'
                "chmod 640 /etc/mosquitto/certs/server.key;"
                "chown mosquitto:mosquitto /etc/mosquitto/certs/ca.crt "
                "/etc/mosquitto/certs/server.crt;"
                'chmod 644 /etc/mosquitto/certs/ca.crt /etc/mosquitto/certs/server.crt"',
            )
            ctx.exec("semp", "mosquitto -c /etc/mosquitto/mosquitto.conf -d", wait=True)
            if mtd:
                dashboard = T.dashboard_on(a)
                ctx.start(
                    defense.MtdCoordinator(
                        "semp",
                        key,
                        a.mtd_ip_pool,
                        a.mtd_port_pool,
                        a.mtd_pad_buckets,
                        a.mtd_scmc_ip_pool,
                        a.mtd_freq_pool,
                        hop_timeout=a.mtd_hop_timeout,
                        hop_interval=a.mtd_hop_interval,
                        pad_interval=a.mtd_pad_interval,
                        src_hop_interval=a.mtd_src_hop_interval,
                        freq_interval=a.mtd_freq_interval,
                        rl_policy=T.POLICY_GUEST.lstrip("/") if a.rl_policy else None,
                        rl_tick=a.rl_tick,
                        seed=run_seed,
                        dashboard_port=T.DASHBOARD_GUEST_PORT if dashboard else None,
                        detector_model=T.DETECTOR_GUEST.lstrip("/") if a.detector_model else None,
                    )
                )
                ctx.start(monitor.TelemetryMirror())
                if dashboard:
                    log.info("[MTD] Dashboard: http://localhost:%d/", a.dashboard_port)
            else:
                log.info("[Baseline] MTD disabled — coordinator not started (mosquitto on 8883)")

        if mode == "dataset":
            self._dataset(ctx, key, run_seed)
        elif mode == "attack":
            self._attack(ctx, key, run_seed)
        if mode != "idle":
            self._logs(ctx)
            with open(ctx.path("scmc_ips.txt"), "w") as f:
                f.write(scmc_ips(a) + "\n")

    def _publisher(self, ctx, key, run_seed, console_log="client.console.log", state=None):
        a = ctx.args
        return traffic.ScmcPublisher(
            "scmc",
            not a.no_mtd,
            a.mtd_scmc_ip_pool,
            shared_key=key,
            seed=run_seed,
            console_log=console_log,
            state=state,
        )

    def _dataset(self, ctx, key, run_seed):
        a = ctx.args
        duration, pcap = a.generate_dataset, f"{a.name}.pcap"
        log.info("[Dataset] Capturing mixed traffic (%ds) -> %s", duration, ctx.path(pcap))
        with ctx.phase("capture"), ctx.live():
            ctx.start(traffic.BackgroundReplay("router", "eth1", a.bg_replay_mbps, duration))
            self.publisher = ctx.start(self._publisher(ctx, key, run_seed))
            drain(ctx.exec("router", f"timeout {duration} tcpdump -i eth1 -w {pcap}"))
        ctx.add_artifact("router", f"/{pcap}", pcap, required=True)

    def _attack(self, ctx, key, run_seed):
        a = ctx.args
        ctx.start(traffic.BackgroundReplay("router", "eth1", a.bg_replay_mbps))
        self.publisher = ctx.start(self._publisher(ctx, key, run_seed))
        router_cap = ctx.start(monitor.Capture("router", "eth1", "router_capture.pcap"))
        ctx.start(monitor.Capture("scmc", "eth0", "scmc_capture.pcap"))
        fp = ctx.start(
            attack.PassiveFingerprinter(
                "attacker", "eth0", a.model, a.scaler, a.block_policy, a.block_threshold
            )
        )
        with ctx.phase("sniff"), ctx.live():
            capture = fp.sniff(ctx, a.attack)
        with ctx.phase("score"):
            cnn_ip = fp.score(ctx, capture)

        port_pool = T.pool(a.mtd_port_pool) if not a.no_mtd else ["8883"]
        gt = ctx.open_ground_truth(
            variant=variant_of(a),
            rl_policy=a.rl_policy,
            seed=a.seed,
            run_seed=run_seed,
            oracle_block=a.oracle_block,
            block_duration=a.block_duration,
            block_episodes=a.block_episodes,
            impair_profile=a.impair_profile,
            cnn_ip=cnn_ip,
            scmc_ip_pool=scmc_ips(a),
            ip_pool=a.mtd_ip_pool,
            port_pool=",".join(port_pool),
            post_attack=a.post_attack,
        )

        def relaunch(state, n):
            ctx.exec(
                "scmc",
                self._publisher(ctx, key, run_seed).command_for(state),
                console_log=f"client.console.restart{n}.log",
            )

        from cyberrange.scenarios.mqtt_mtd.attacks import FaultInjector

        delivery = ctx.start(
            attack.DeliveryAttack(
                "router",
                "scmc",
                [int(p) for p in port_pool],
                relaunch,
                oracle=a.oracle_block,
                block_duration=a.block_duration,
                block_episodes=a.block_episodes,
                impair=a.impair_profile == "random",
                injector=FaultInjector,
            )
        )
        log.info("[Attack] Observing post-attack effect for %ds", a.post_attack)
        with ctx.phase("post_attack"), ctx.live():
            gt.record("post_attack_start")
            delivery.attack(ctx, cnn_ip)
            drain(
                ctx.exec(
                    "attacker",
                    f"timeout {a.post_attack} tcpdump -i eth0 -w post_attack_capture.pcap",
                )
            )
            restarts = delivery.restarts
            delivery.stop(ctx)
            gt.record("post_attack_end")
        router_cap.stop_capture(ctx)
        ctx.add_artifact(
            "attacker", "/post_attack_capture.pcap", "post_attack_capture.pcap", required=True
        )
        for n in range(1, restarts + 1):
            ctx.add_artifact(
                "scmc", f"/client.console.restart{n}.log", f"client.console.restart{n}.log"
            )

    def _logs(self, ctx):
        """Publisher and broker logs (required: the run is judged on them), and
        the agents' consoles + MTD telemetry (diagnostics)."""
        a, p = ctx.args, self.prefix(ctx.args)
        ctx.add_artifact("scmc", f"/{self.publisher.log_file}", f"{p}client.log", required=True)
        ctx.add_artifact(
            "semp", "/var/log/mosquitto/mosquitto.log", f"{p}mosquitto.log", required=True
        )
        ctx.add_artifact("scmc", "/client.console.log", f"{p}client.console.log")
        if not a.no_mtd:
            ctx.add_artifact("semp", "/coordinator.log", f"{p}coordinator.log")
            ctx.add_artifact("semp", "/telemetry.jsonl", f"{p}telemetry.jsonl")

    def check_run(self, ctx):
        a, p = ctx.args, self.prefix(ctx.args)
        discard = [ctx.path(f"{a.name}.pcap")] if mode_of(a) == "dataset" else []
        if mode_of(a) == "idle":
            return 0
        return (
            0 if check_published(ctx.path(f"{p}client.log"), discard=discard) else EXIT_NO_PUBLISH
        )
