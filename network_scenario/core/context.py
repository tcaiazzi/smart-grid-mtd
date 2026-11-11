"""context.py — RunContext, the handle a scenario's episode drives the lab with,
plus the guest helpers every scenario shares (seeds, console logs, downloads).
"""

import contextlib
import io
import logging
import os
import sys
import tarfile
import threading
import time
import zlib

from network_scenario.core.component import Artifact
from network_scenario.core.streams import GROUND_TRUTH, GroundTruth

log = logging.getLogger("core.context")


# ── guest helpers ──────────────────────────────────────────────────────────────
def role_seed(seed, role: str):
    """Seed for one role of a run, derived from the experiment seed.

    Different roles (train/test capture, attack run; engine, PLC, HMI) get
    distinct but reproducible seeds. None -> None (unseeded run).
    """
    if seed is None:
        return None
    return zlib.crc32(f"{seed}:{role}".encode()) & 0x7FFFFFFF


def seed_arg(seed) -> str:
    """` --seed N` for a guest agent's command line, or "" when unseeded."""
    return "" if seed is None else f" --seed {seed}"


def with_console_log(cmd: str, log_name: str) -> str:
    """Run a guest agent under bash with its stdout+stderr captured to `log_name`.

    The agents' own log files only hold what they log on purpose; a crash
    traceback would otherwise be lost with the unread exec stream. Unbuffered
    so the file is current even when the lab is torn down under the agent.
    """
    return f'bash -c "PYTHONUNBUFFERED=1 {cmd} > {log_name} 2>&1"'


def download_file_from_container(container, src_path: str, dst_path: str) -> None:
    """Copy one file out of a Docker container (``machine.api_object``)."""
    bits, _ = container.get_archive(src_path)
    with tarfile.open(fileobj=io.BytesIO(b"".join(bits))) as tar:
        f = tar.extractfile(tar.getmembers()[0])
        if f is None:
            raise ValueError(f"Could not extract file from path: {src_path}")
        os.makedirs(os.path.dirname(dst_path) or ".", exist_ok=True)
        with open(dst_path, "wb") as out:
            out.write(f.read())


def fetch(machine, guest_path: str, dst_path: str) -> None:
    """Copy ``guest_path`` out of a deployed Kathará machine to ``dst_path``."""
    download_file_from_container(machine.api_object, guest_path, dst_path)


def drain(exec_stream) -> None:
    """Exhaust an exec stream so the command runs to completion. Kathará's
    exec streams (IExecStream) define __next__ but not __iter__: no for-loop."""
    if exec_stream is None:
        return
    try:
        while True:
            next(exec_stream)
    except StopIteration:
        pass


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"


class _Tee:
    """A write-through stream fanning out to several streams."""

    def __init__(self, *streams):
        self._streams = streams

    def write(self, data):
        for s in self._streams:
            s.write(data)
            s.flush()

    def flush(self):
        for s in self._streams:
            s.flush()


def tee_run_log(log_path: str) -> None:
    """Tee stdout and the logging output of this process into ``log_path``,
    so each run leaves a self-contained transcript next to its artifacts
    (line-buffered: ``tail -f`` works live)."""
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
    log_file = open(log_path, "w", buffering=1)
    sys.stdout = _Tee(sys.__stdout__, log_file)
    handler = logging.StreamHandler(log_file)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root = logging.getLogger()
    root.addHandler(handler)
    if root.level > logging.INFO or root.level == logging.NOTSET:
        root.setLevel(logging.INFO)
    log.info("Logging this run to %s", log_path)


# ── run context ────────────────────────────────────────────────────────────────
class RunContext:
    """Everything one run's episode needs: the lab, where to write, how to report.

    ``emit`` is the progress-ledger emitter (already bound to the run id);
    ``state`` is free per-run scratch space for components (poll cursors...).
    """

    def __init__(self, manager, lab, machines, args, out_dir, emit, scenario=None,
                 topology=None):
        self.manager, self.lab, self.machines = manager, lab, machines
        self.args, self.out_dir, self.emit = args, out_dir, emit
        self.scenario, self.topology = scenario, topology
        self.state = {}
        self.components = []
        self.gt = None
        self._extra_artifacts = []

    # seeds
    @property
    def seed(self):
        return getattr(self.args, "seed", None)

    def role_seed(self, role):
        return role_seed(self.seed, role)

    # guest execution
    def machine(self, node):
        return self.machines[node] if isinstance(node, str) else node

    def exec(self, node, cmd, console_log=None, wait=False, stream=True):
        """Run ``cmd`` in ``node``. Background (stream) by default; with
        ``console_log`` its output is captured to that guest file."""
        if console_log:
            cmd = with_console_log(cmd, console_log)
        return self.manager.exec_obj(self.machine(node), cmd, wait=wait, stream=stream)

    def run(self, node, cmd, wait=False):
        """Run to completion; returns (stdout bytes, stderr bytes, rc)."""
        return self.manager.exec_obj(self.machine(node), cmd, wait=wait, stream=False)

    def exec_text(self, node, cmd):
        out, _err, _rc = self.run(node, cmd)
        return (out or b"").decode(errors="replace")

    def path(self, name):
        return name if os.path.isabs(name) else os.path.join(self.out_dir, name)

    def download(self, node, guest_path, local_name, required=True):
        """Copy a guest file into the run's output dir; returns the local path.
        A failure raises when ``required``, else is logged and returns None."""
        dst = self.path(local_name)
        try:
            fetch(self.machine(node), guest_path, dst)
            return dst
        except Exception as e:
            if required:
                raise
            log.warning("could not download %s:%s (%s)", node, guest_path, e)
            return None

    # streams
    def open_ground_truth(self, **run_meta):
        """Open <out_dir>/ground_truth.jsonl (host-only) and record run_meta."""
        if self.gt is None:
            os.makedirs(self.out_dir, exist_ok=True)
            self.gt = GroundTruth(self.path(GROUND_TRUTH))
            self.gt.record("run_meta", scenario=getattr(self.scenario, "name", None),
                           **run_meta)
        return self.gt

    def close_ground_truth(self):
        if self.gt is not None:
            try:
                self.gt.record("run_end")
                self.gt.close()
            except ValueError:
                pass

    @contextlib.contextmanager
    def phase(self, name, **fields):
        """Emit phase start/end around a block (end carries the outcome)."""
        t0 = time.time()
        self.emit("phase", name=name, state="start", **fields)
        ok = False
        try:
            yield
            ok = True
        finally:
            self.emit("phase", name=name, state="end", ok=ok,
                      duration_s=round(time.time() - t0, 3))

    # components
    def start(self, component):
        component.start(self)
        self.components.append(component)
        return component

    def stop_all(self):
        for c in reversed(self.components):
            try:
                c.stop(self)
            except Exception as e:
                log.warning("stopping %r failed: %s", c, e)

    def add_artifact(self, node, guest_path, local_name, required=False):
        self._extra_artifacts.append(Artifact(node, guest_path, local_name, required))

    def artifacts(self):
        seen, out = set(), []
        for a in [a for c in self.components for a in c.artifacts()] + self._extra_artifacts:
            if (a.node, a.guest_path, a.local_name) not in seen:
                seen.add((a.node, a.guest_path, a.local_name))
                out.append(a)
        return out

    def download_artifacts(self):
        for a in self.artifacts():
            self.download(a.node, a.guest_path, a.local_name, required=a.required)

    def telemetry_sources(self):
        return [s for c in self.components for s in c.telemetry()]

    # live observation
    def poll(self):
        for c in self.components:
            try:
                c.poll(self)
            except Exception as e:
                log.debug("poll of %r failed: %s", c, e)

    @contextlib.contextmanager
    def live(self, poll_s=None):
        """Poll the started components from a background thread while the
        block runs (for phases that block on a guest command)."""
        poll_s = float(getattr(self.args, "poll_interval", 0) or 0) if poll_s is None else poll_s
        if poll_s <= 0:
            yield
            return
        halt = threading.Event()

        def loop():
            while not halt.wait(poll_s):
                self.poll()

        t = threading.Thread(target=loop, name="live-poll", daemon=True)
        t.start()
        try:
            yield
        finally:
            halt.set()
            t.join(timeout=poll_s + 5)
            self.poll()

    def observe(self, seconds, poll_s=None):
        """Wait ``seconds`` (deadline-based, so the phase keeps its length),
        polling the started components every ``poll_s`` (0 = just wait)."""
        poll_s = float(getattr(self.args, "poll_interval", 0) or 0) if poll_s is None else poll_s
        deadline = time.time() + seconds
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return
            if poll_s <= 0:
                time.sleep(remaining)
                return
            time.sleep(min(poll_s, remaining))
            self.poll()
