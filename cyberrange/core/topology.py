"""topology.py — declarative description of a scenario's lab.

A scenario describes its network as plain data (Topology -> Node -> Iface,
Route) instead of building a Kathará Lab by hand. The core turns it into:

  * a Kathará Lab (``build_lab``), with the startup commands, the staged guest
    files, the management NIC and an ``addresses`` meta on every machine (so
    tools that walk the Lab model, e.g. the SOAR knowledge graph, need not
    parse commands);
  * a ``lab.conf`` + ``<node>.startup`` directory (``export_lab_conf``) — the
    same lab in Kathará's own format, for documentation and for running it by
    hand with ``kathara lstart``;
  * a JSON summary (``to_dict``) for dashboards and reports.

Interface numbering follows list order: the first Iface of a Node is eth0.

Guest files — the deployment contract
-------------------------------------
``Node.files`` is a list of ``(host_path, guest_path)`` pairs, declared by each
scenario in its own ``guest_files.py``. ``build_lab`` stages them with
``Machine.create_file_from_path``; Kathará unpacks them at the container's
filesystem root, so a guest path is written with a leading "/" for clarity but
lands in the same place without one — the container's working directory *is* "/".

That root is also ``sys.path[0]`` for a script run as ``python3 <name>.py``,
which is why guest agents are flat modules importing each other bare
(``from mtd_crypto import ...``) with no package anywhere. **The name a file is
copied under is a contract other agents depend on**: mtd_rl_coordinator.py does
``from rl_policy import ...``, so rl_policy.py must keep landing as
"/rl_policy.py" no matter where it lives on the host. Host paths may be
reorganised freely; guest paths may not.

``tests/core/test_deploy_contract.py`` freezes the guest side of every manifest, and
``tests/core/test_guest_imports.py`` replays each machine's files into a scratch
directory and imports them, so a missing shared module is caught without
deploying anything.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cyberrange.core import paths


@dataclass
class Iface:
    """One NIC: the collision domain it joins and how it is addressed."""

    link: str
    cidr: Optional[str] = None  # primary address, e.g. "10.0.0.2/24"
    aliases: List[str] = field(default_factory=list)  # extra addresses (MTD pools)
    promisc: bool = False  # passive sniffing NIC (brought up, no address)


@dataclass
class Route:
    dest: str
    via: str
    dev: str
    replace: bool = False  # "replace" when another NIC (bridged mgmt) may own a default

    def command(self) -> str:
        verb = "replace" if self.replace else "add"
        return f"ip route {verb} {self.dest} via {self.via} dev {self.dev}"


@dataclass
class Node:
    name: str
    ifaces: List[Iface] = field(default_factory=list)
    image: Optional[str] = None  # None -> Topology.default_image; "" -> Kathará's default
    role: str = "infra"  # target | attacker | defender | plant | infra ...
    routes: List[Route] = field(default_factory=list)
    startup: List[str] = field(default_factory=list)  # after addressing + routes
    files: List[Tuple[str, str]] = field(default_factory=list)  # (host path, guest path)
    mgmt_port: Optional[str] = None  # "HOST:GUEST/tcp": bridged NIC + port forward

    def addresses(self) -> Dict[str, str]:
        """{ethN: primary cidr} for every addressed NIC (passive NICs omitted)."""
        return {f"eth{i}": f.cidr for i, f in enumerate(self.ifaces) if f.cidr}

    def startup_commands(self) -> List[str]:
        cmds = []
        for i, f in enumerate(self.ifaces):
            if f.promisc:
                cmds += [f"ip link set eth{i} promisc on", f"ip link set eth{i} up"]
        cmds += [f"ip address add {f.cidr} dev eth{i}" for i, f in enumerate(self.ifaces) if f.cidr]
        cmds += [r.command() for r in self.routes]
        cmds += [
            f"ip address add {a} dev eth{i}" for i, f in enumerate(self.ifaces) for a in f.aliases
        ]
        return cmds + list(self.startup)


@dataclass
class Topology:
    name: str  # Kathará lab name (a deploy replaces a lab of this name)
    nodes: List[Node] = field(default_factory=list)
    default_image: Optional[str] = None

    def node(self, name: str) -> Node:
        for n in self.nodes:
            if n.name == name:
                return n
        raise KeyError(name)

    def image_of(self, node: Node) -> Optional[str]:
        return node.image if node.image is not None else self.default_image

    def links(self) -> List[str]:
        seen = []
        for n in self.nodes:
            for f in n.ifaces:
                if f.link not in seen:
                    seen.append(f.link)
        return seen


def build_lab(topo: Topology):
    """Build (do not deploy) the Kathará Lab. Returns (lab, machines, startups):
    machines is {name: Machine}, startups {name: [command, ...]} — the exact
    startup commands, inspectable without materialising the filesystem."""
    from Kathara.model.Lab import Lab  # Kathará only when a lab is actually built

    lab = Lab(topo.name)
    machines, startups = {}, {}
    for n in topo.nodes:
        image = topo.image_of(n)
        machines[n.name] = lab.new_machine(n.name, **({"image": image} if image else {}))
    for n in topo.nodes:
        m = machines[n.name]
        for f in n.ifaces:
            lab.connect_machine_obj_to_link(m, f.link)
        if n.mgmt_port:
            m.add_meta("bridged", True)
            m.add_meta("port", n.mgmt_port)
        for host_path, guest_path in n.files:
            # Manifest host paths are repo-relative; resolve them against the
            # repo rather than the process CWD, so a run started from anywhere
            # stages the same files instead of silently staging none.
            m.create_file_from_path(str(paths.resolve(host_path)), guest_path)
        startups[n.name] = n.startup_commands()
        lab.create_startup_file_from_list(m, startups[n.name])
        # Plain dict meta: Kathará stores unknown meta keys verbatim.
        m.add_meta("addresses", dict(n.addresses()))
    return lab, machines, startups


def to_dict(topo: Topology) -> dict:
    return {
        "name": topo.name,
        "links": topo.links(),
        "nodes": [
            {
                "name": n.name,
                "image": topo.image_of(n),
                "role": n.role,
                "ifaces": [
                    {
                        "name": f"eth{i}",
                        "link": f.link,
                        "cidr": f.cidr,
                        "aliases": list(f.aliases),
                        "promisc": f.promisc,
                    }
                    for i, f in enumerate(n.ifaces)
                ],
                "routes": [r.command() for r in n.routes],
                "files": [g for _h, g in n.files],
                "mgmt_port": n.mgmt_port,
            }
            for n in topo.nodes
        ],
    }


def write_json(topo: Topology, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(to_dict(topo), f, indent=1)


def export_lab_conf(topo: Topology, out_dir: str, copy_files: bool = False) -> str:
    """Write the topology as a Kathará lab directory (lab.conf + .startup files).
    Guest files are listed as comments unless ``copy_files`` (then they are
    copied under <out_dir>/<node>/). Returns the lab.conf path."""
    import shutil

    os.makedirs(out_dir, exist_ok=True)
    lines = [f'LAB_DESCRIPTION="{topo.name}"', ""]
    for n in topo.nodes:
        for i, f in enumerate(n.ifaces):
            lines.append(f'{n.name}[{i}]="{f.link}"')
        image = topo.image_of(n)
        if image:
            lines.append(f'{n.name}[image]="{image}"')
        if n.mgmt_port:
            lines.append(f'{n.name}[bridged]="true"')
            lines.append(f'{n.name}[port]="{n.mgmt_port}"')
        for host_path, guest_path in n.files:
            if copy_files:
                dst = os.path.join(out_dir, n.name, guest_path.lstrip("/"))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(paths.resolve(host_path), dst)
            else:
                lines.append(f"# {n.name}: {guest_path} <- {host_path}")
        lines.append("")
        with open(os.path.join(out_dir, f"{n.name}.startup"), "w") as fh:
            fh.write("\n".join(n.startup_commands()) + "\n")
    path = os.path.join(out_dir, "lab.conf")
    with open(path, "w") as fh:
        fh.write("\n".join(lines))
    return path
