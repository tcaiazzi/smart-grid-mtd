---
name: kathara-api
description: "Use the Kathara Python API correctly. Use when: calling Kathara Python API from code, writing scripts that interact with running Kathara labs, using the Kathara manager/model/parser layer programmatically, interacting with machines via exec or connect, or parsing lab.conf/startup files from Python."
argument-hint: "What you want to do: deploy a lab, exec a command, create machines programmatically, parse a lab.conf, etc."
user-invocable: true
---

# Kathara Python API

## Core Imports

```python
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab
from Kathara.model.Machine import Machine
from Kathara.model.Link import Link
from Kathara.parser.netkit.LabParser import LabParser
from Kathara.parser.netkit.DepParser import DepParser
from Kathara.parser.netkit.ExtParser import ExtParser
from Kathara.setting.Setting import Setting
```

---

## 1. Manager — `Kathara` Singleton

Always obtain the manager via the singleton. Never instantiate directly.

```python
manager = Kathara.get_instance()
```

The backend (Docker or Kubernetes) is determined by `Setting.get_instance().manager_type` (default: `"docker"`). The `Kathara` facade wraps the backend-specific manager transparently.

### Key Manager Methods

| Method | Signature | Notes |
|--------|-----------|-------|
| `deploy_lab` | `(lab, selected_machines=None, excluded_machines=None)` | Both filter params are `Optional[Set[str]]` |
| `undeploy_lab` | `(lab_hash=None, lab_name=None, lab=None, selected_machines=None, excluded_machines=None)` | Provide at least one identifier |
| `deploy_machine` | `(machine)` | Deploy a single machine |
| `undeploy_machine` | `(machine)` | Undeploy a single machine |
| `deploy_link` | `(link)` | Deploy a single collision domain |
| `undeploy_link` | `(link)` | Undeploy a collision domain; raises `LabNotFoundError` if not associated to a scenario |
| `connect_machine_to_link` | `(machine: Machine, link: Link, mac_address=None)` | Connect a **running** machine to an existing link at runtime (takes objects, not names) |
| `disconnect_machine_from_link` | `(machine: Machine, link: Link)` | Disconnect a running machine from a link; raises `MachineCollisionDomainConflictError` if not connected |
| `connect_tty` | `(machine_name, lab_hash=None, lab_name=None, lab=None, shell=None, logs=False, wait=True)` | Opens interactive shell |
| `connect_tty_obj` | `(machine, shell=None, logs=False, wait=True)` | Same, using a `Machine` object |
| `exec` | `(machine_name, command, lab_hash=None, lab_name=None, lab=None, wait=False, stream=True)` | Returns `IExecStream` or `(stdout, stderr, exit_code)` |
| `exec_obj` | `(machine, command, wait=False, stream=True)` | Same, using a `Machine` object |
| `copy_files` | `(machine, guest_to_host)` | `guest_to_host: Dict[str, str\|io.IOBase]` |
| `retrieve_files` | `(machine, src, dst)` | Copy files from a running machine |
| `get_machine_api_object` | `(machine_name, lab_hash=None, lab_name=None, lab=None, all_users=False)` | Raw backend object (e.g., Docker container) |
| `get_machines_api_objects` | `(lab_hash=None, lab_name=None, lab=None, all_users=False)` | Returns `List[Any]` of all device API objects |
| `get_link_api_object` | `(link_name, lab_hash=None, lab_name=None, lab=None, all_users=False)` | Raw backend API object for a single collision domain |
| `get_links_api_objects` | `(lab_hash=None, lab_name=None, lab=None, all_users=False)` | Returns `List[Any]` of all link API objects |
| `get_machine_stats` | `(machine_name, lab_hash=None, lab_name=None, lab=None, all_users=False)` | Generator of stats for a single machine (by name) |
| `get_machine_stats_obj` | `(machine, all_users=False)` | Generator of stats for a single machine (by object) |
| `get_machines_stats` | `(lab_hash=None, lab_name=None, lab=None, machine_name=None, all_users=False)` | Generator of stats for all machines |
| `get_link_stats` | `(link_name, lab_hash=None, lab_name=None, lab=None, all_users=False)` | Generator of stats for a single link (by name) |
| `get_link_stats_obj` | `(link, all_users=False)` | Generator of stats for a single link (by object) |
| `get_links_stats` | `(lab_hash=None, lab_name=None, lab=None, link_name=None, all_users=False)` | Generator of stats for all links |
| `get_lab_from_api` | `(lab_hash=None, lab_name=None)` | Recover a `Lab` object from a running deployment |
| `update_lab_from_api` | `(lab)` | Sync an existing `Lab` object with the running backend state (refreshes `api_object` on all machines) |
| `check_image` | `(image_name)` | Validate image availability; raises `ImageNotFoundError` or `ConnectionError` |
| `wipe` | `(all_users=False)` | Undeploy all running labs |
| `get_release_version` | `()` | Returns `str` current manager version |
| `get_formatted_manager_name` | `()` | Returns `str` formatted manager name |
| `get_available_managers_name` | `()` *(static)* | Returns `Dict[str, str]` of available backends |

### `wait` parameter semantics

`wait` is accepted by `exec`, `exec_obj`, `connect_tty`, `connect_tty_obj`:

| Value | Meaning |
|-------|---------|
| `False` (default for `exec`) | Do not wait; start executing immediately |
| `True` (default for `connect_tty`) | Wait until the machine finishes all its startup commands |
| `(retries, interval_seconds)` e.g. `(10, 2.0)` | Retry up to `retries` times, sleeping `interval_seconds` between each attempt |

---

## 2. Model — `Lab`, `Machine`, `Link`

### `Lab`

```python
lab = Lab(name="my_lab", path="/optional/path")
```

- `lab.hash` — URL-safe hash used everywhere to identify the running lab.
- `lab.name` — human-readable name; also accepted as `lab_name` in all manager calls.
- `lab.machines` — `Dict[str, Machine]`
- `lab.links` — `Dict[str, Link]`
- `lab.fs` — PyFilesystem2 object for the lab directory (use for low-level file ops).

**Building the topology:**

```python
# Create (or get) machines and links
machine_a = lab.get_or_new_machine("router1", image="kathara/quagga")
machine_b = lab.get_or_new_machine("router2")

link = lab.get_or_new_link("A")

# Connect machines to links (returns Interface)
lab.connect_machine_to_link("router1", "A", machine_iface_number=0)
lab.connect_machine_to_link("router2", "A", machine_iface_number=0)

# Or connect via Machine object
lab.connect_machine_obj_to_link(machine_a, "A", machine_iface_number=1)
```

**Lab options and global metadata:**

```python
lab.add_option("hosthome_mount", True)
lab.add_option("shared_mount", False)
lab.add_global_machine_metadata("image", "kathara/base")
```

**Convenience wrapper — set meta via lab:**

```python
# Equivalent to lab.get_machine("router1").add_meta("image", "kathara/frr")
lab.assign_meta_to_machine("router1", "image", "kathara/frr")
```

**Check existence:**

```python
if lab.has_machine("router1"):
    machine = lab.get_machine("router1")

if lab.has_machines({"router1", "router2"}):   # check multiple at once
    ...

if lab.has_link("A"):
    link = lab.get_link("A")

if lab.has_links({"A", "B"}):
    ...
```

**Get links reachable from a set of machines:**

```python
# By machine names (Set[str] or List[str])
links = lab.get_links_from_machines({"router1", "router2"})

# By Machine objects
links = lab.get_links_from_machine_objs([machine_a, machine_b])
```

**Removing a machine (correct way):**

```python
# remove_machine cleans up interface references in all connected collision domains
lab.remove_machine(name="router1")              # look up by name
lab.remove_machine(machine=machine_obj)         # or by object
lab.remove_machine(name="router1", delete_fs=True)  # also delete startup/shutdown/dir from fs
```

> **Never use `del lab.machines[name]`** — it skips link cleanup and leaves stale interface entries.

**Writing files into the lab filesystem (before deployment):**

```python
# Write a file at an arbitrary guest path — works on Lab and Machine objects
lab.create_file_from_string("net.ipv4.ip_forward=1\n", "router1.startup")
lab.create_file_from_list(["zebra=yes", "bgpd=yes"], "router1/etc/frr/daemons")

# Startup file helpers (scoped to a Machine object)
lab.create_startup_file_from_string(machine, "ip addr add 10.0.0.1/24 dev eth0\n")
lab.create_startup_file_from_list(machine, ["ip addr add 10.0.0.1/24 dev eth0"])
lab.create_startup_file_from_path(machine, "/host/path/to/startup")
lab.create_startup_file_from_stream(machine, open_file_object)
lab.update_startup_file_from_string(machine, "ip route add 0.0.0.0/0 via 10.0.0.254\n")
lab.update_startup_file_from_list(machine, ["ip route add ..."])
lab.update_file_from_list(["ip link set eth0 up"], "router1.startup")
lab.update_file_from_string("extra line\n", "router1.startup")  # append
```

**Integrity check before deployment:**

```python
lab.check_integrity()   # raises if topology has inconsistencies
```

**Opening a terminal in a subprocess:**

```python
import subprocess, sys
from Kathara.setting.Setting import Setting

command = (
    '%s -c "from Kathara.manager.Kathara import Kathara; '
    "Kathara.get_instance().connect_tty('%s', lab_name='%s', shell='%s', logs=True)\""
    % (sys.executable, machine.name, machine.lab.name, Setting.get_instance().device_shell)
)
subprocess.Popen([Setting.get_instance().terminal, "-e", command], start_new_session=True)
```

### `Machine`

Created via `Lab.get_or_new_machine()` or `Lab.new_machine()`. Never instantiate directly — `Machine.__init__` requires the parent `Lab`.

```python
machine = lab.get_or_new_machine("router1")
```

**Setting metadata with `add_meta` (additive for list-valued keys):**

```python
machine.add_meta("image", "kathara/frr")
machine.add_meta("mem", "512m")            # key is "mem", NOT "memory"
machine.add_meta("cpus", 2)
machine.add_meta("privileged", True)
machine.add_meta("shell", "/bin/bash")
machine.add_meta("exec", "service zebra start")   # can call multiple times
machine.add_meta("exec", "service ospfd start")
machine.add_meta("sysctl", "net.ipv4.ip_forward=1")  # must be net.* namespace
machine.add_meta("env", "MY_VAR=value")
machine.add_meta("port", "3000:8080/tcp")      # host:guest/proto; omit host -> defaults to 3000
machine.add_meta("num_terms", 2)               # number of terminal windows to open
machine.add_meta("bridged", True)              # attach a bridged interface
machine.add_meta("ipv6", True)                 # enable IPv6
machine.add_meta("entrypoint", "/custom/entrypoint.sh")
machine.add_meta("args", "--verbose")
machine.add_meta("ulimit", "nofile=1024:2048")      # format: key=soft:hard
machine.add_meta("volume", "/host/path|/guest/path|ro")  # format: host|guest|mode (ro/rw/rx)
```

**Setting metadata via `update_meta` kwargs (bulk / constructor-style):**

`Machine.__init__` and `update_meta()` accept these keyword arguments directly, equivalent to calling `add_meta` for each:

```python
machine.update_meta(
    image="kathara/frr",
    mem="512m",
    cpus=2,
    privileged=True,
    bridged=False,
    ipv6=True,
    shell="/bin/bash",
    entrypoint="/sbin/init",
    args="--debug",
    num_terms=1,
    exec_commands=["service zebra start", "service ospfd start"],  # list
    ports=["3000:8080/tcp", "8443:443/tcp"],                       # list
    sysctls=["net.ipv4.ip_forward=1"],                             # list; net.* only
    envs=["MY_VAR=value", "OTHER=x"],                              # list
    ulimits=["nofile=1024:2048"],                                  # list; key=soft:hard
    volumes=["/host|/guest|ro"],                                   # list; host|guest|mode
)
```

**Machine filesystem methods (write files before deployment):**

```python
# Create / overwrite a file
machine.create_file_from_string("hostname router1\n", "/etc/hostname")
machine.create_file_from_list(["zebra=yes", "bgpd=yes"], "/etc/frr/daemons")
machine.create_file_from_path("/host/src/file.conf", "/etc/file.conf")
machine.create_file_from_stream(open_binary_stream, "/etc/file.conf")

# Append to an existing file
machine.update_file_from_string("extra content\n", "/etc/file.conf")
machine.update_file_from_list(["line1", "line2"], "/etc/file.conf")

# Copy an entire directory
machine.copy_directory_from_path("/host/src/dir", "/guest/dst/dir")

# In-place line editing (searched_line is a regex or plain string)
machine.write_line_before("/etc/file.conf", "new_line", "searched_line", first_occurrence=False)
machine.write_line_after("/etc/file.conf", "new_line", "searched_line", first_occurrence=False)
machine.delete_line("/etc/file.conf", "line_to_delete", first_occurrence=False)
# write_line_before/after/delete_line all return int (count of modifications)
```

> All filesystem methods raise `InvocationError` if `machine.fs` is `None`.

**Other useful machine attributes:**

- `machine.name` — device name
- `machine.lab` — back-reference to the parent `Lab`
- `machine.interfaces` — `Dict[int, Interface]` (keyed by interface number)
- `machine.api_object` — raw backend object; only populated after `deploy_machine` or `update_lab_from_api`
- `machine.meta` — `Dict[str, Any]` of all set metadata

### `Link`

```python
link = lab.get_or_new_link("link0")
```

Links are collision domains (virtual switches). Machine interfaces map to links.

- `link.name` — collision domain name
- `link.machines` — `Dict[str, Machine]` of connected machines
- `link.api_object` — raw backend object; populated after `deploy_link`

---

## 3. Settings

```python
setting = Setting.get_instance()

# Read
print(setting.manager_type)   # "docker" or "kubernetes"
print(setting.image)          # default image

# Force a specific backend at runtime without editing the config file
Setting.get_instance().load_from_dict({"manager_type": "docker"})

# Load from disk (~/.config/kathara.conf by default)
setting.load_from_disk()

# Validate (checks Docker/K8s availability)
setting.check()
```

---

## 4. Parsers

### `LabParser` — parse `lab.conf`

```python
lab = LabParser.parse("/path/to/lab")
# Returns a fully populated Lab with machines and links.
```

### `DepParser` — parse `lab.dep`

```python
dependencies = DepParser.parse("/path/to/lab")
if dependencies:
    lab.apply_dependencies(dependencies)
```

### `ExtParser` — parse `lab.ext` (Linux only)

```python
external_links = ExtParser.parse("/path/to/lab")
if external_links:
    lab.attach_external_links(external_links)
```

---

## 5. Full Working Examples

### Deploy a lab from directory

```python
from Kathara.manager.Kathara import Kathara
from Kathara.parser.netkit.LabParser import LabParser
from Kathara.parser.netkit.DepParser import DepParser
from Kathara.parser.netkit.ExtParser import ExtParser

lab_path = "/path/to/my_lab"

lab = LabParser.parse(lab_path)

dependencies = DepParser.parse(lab_path)
if dependencies:
    lab.apply_dependencies(dependencies)

external_links = ExtParser.parse(lab_path)
if external_links:
    lab.attach_external_links(external_links)

Kathara.get_instance().deploy_lab(lab)
```

### Build and deploy a lab programmatically

```python
from Kathara.manager.Kathara import Kathara
from Kathara.model.Lab import Lab

lab = Lab("my_lab")

lab.get_or_new_machine("pc1")
lab.get_or_new_machine("pc2")
lab.get_or_new_machine("router1")

lab.get_or_new_machine("router1").add_meta("image", "kathara/frr")
lab.get_or_new_machine("router1").add_meta("exec", "ip route add 10.0.0.0/8 via 192.168.1.1")

lab.connect_machine_to_link("pc1",     "lan",  machine_iface_number=0)
lab.connect_machine_to_link("pc2",     "lan",  machine_iface_number=0)
lab.connect_machine_to_link("router1", "lan",  machine_iface_number=0)
lab.connect_machine_to_link("router1", "wan",  machine_iface_number=1)

lab.check_integrity()
Kathara.get_instance().deploy_lab(lab)
```

### Execute a command and read streaming output

```python
from Kathara.manager.Kathara import Kathara

exec_stream = Kathara.get_instance().exec(
    machine_name="router1",
    command="ip route show",
    lab_hash="<lab.hash>",
    wait=True,    # wait for machine to finish booting
    stream=True,  # returns IExecStream
)

try:
    while True:
        stdout, stderr = next(exec_stream)
        if stdout:
            print(stdout.decode("utf-8"), end="")
        if stderr:
            print(stderr.decode("utf-8"), end="", file=sys.stderr)
except StopIteration:
    exit_code = exec_stream.exit_code()
```

### Non-streaming exec (wait for completion)

```python
stdout, stderr, exit_code = Kathara.get_instance().exec(
    machine_name="router1",
    command=["ip", "route", "show"],
    lab_hash=lab.hash,
    wait=True,
    stream=False,   # returns (bytes, bytes, int)
)
print(stdout.decode())
```

### Undeploy a lab

```python
# By Lab object
Kathara.get_instance().undeploy_lab(lab=lab)

# By hash (e.g., stored from a previous session)
Kathara.get_instance().undeploy_lab(lab_hash="<hash>")

# By name
Kathara.get_instance().undeploy_lab(lab_name="my_lab")
```

### Connect to a machine terminal

```python
Kathara.get_instance().connect_tty(
    machine_name="router1",
    lab=lab,
    shell="/bin/bash",
    logs=False,
    wait=True,
)
```

### Recover a running lab from the API

```python
# Get a Lab object representing an already-deployed lab (e.g., after a restart)
lab = Kathara.get_instance().get_lab_from_api(lab_name="my_lab")
# lab.machines and lab.links are populated from the running backend
```

### Sync Lab state after manual changes

```python
# After copy_files or external changes, refresh api_object on all machines
Kathara.get_instance().update_lab_from_api(lab)
```

### Deploy/undeploy individual machines dynamically

```python
# Add a new machine to an already-running lab and deploy it
new_machine = lab.get_or_new_machine("probe", image="kathara/base")
lab.connect_machine_obj_to_link(new_machine, "lan")
Kathara.get_instance().deploy_machine(new_machine)

# Later, tear it down and remove from registry (correct way)
Kathara.get_instance().undeploy_machine(new_machine)
lab.remove_machine(machine=new_machine)
```

### Poll machine backend status

```python
import time

# After deploy_machine, wait until the container is running
while True:
    new_machine.api_object.reload()          # refresh from Docker/K8s
    if new_machine.api_object.status == "running":
        break
    time.sleep(2)
```

### Fire-and-forget exec (trigger only, discard output)

```python
exec_output = Kathara.get_instance().exec(
    machine_name=device.name,
    command=shlex.split("ip link set eth0 up"),
    lab_name=device.lab.name,   # device.lab.name is the idiomatic way to pass the lab
)
try:
    next(exec_output)           # trigger the generator
except StopIteration:
    pass
```

### Deploy a lab in ordered chunks

```python
# Deploy critical machines first, then the rest
critical = {"router1", "router2", "switch"}
Kathara.get_instance().deploy_lab(lab, selected_machines=critical)
Kathara.get_instance().deploy_lab(lab, selected_machines=set(lab.machines.keys()) - critical)
```

### Health-check loop before running actions

```python
import time, shlex

def wait_for_health(device, health_cmd):
    while True:
        exec_output = Kathara.get_instance().exec(
            machine_name=device.name,
            command=shlex.split(health_cmd),
            lab_name=device.lab.name,
        )
        try:
            stdout, _ = next(exec_output)
            if stdout and stdout.strip():
                return
        except StopIteration:
            pass
        time.sleep(5)
```

---

## 6. Common Pitfalls

- **Never call `Kathara()` directly.** Always use `Kathara.get_instance()`.
- **Never call `Machine(lab, name)` directly.** Use `lab.get_or_new_machine(name)` — it registers the machine in the lab.
- **`machine.add_meta("mem", ...)`** — the correct key is `"mem"`, NOT `"memory"`. Using `"memory"` silently stores an unrecognised key and has no effect.
- **`lab.hash` is the canonical identifier** for a running lab. Store it if you need to reference the lab after deployment.
- **Interface numbers must be contiguous** starting from 0. Gaps cause `MachineCollisionDomainError`. Let the API auto-assign (`machine_iface_number=None`) unless explicit numbering is required.
- **`exec` with `stream=True` returns a generator.** Exhausting it (or the machine stopping) raises `StopIteration`. Always wrap in try/except.
- **`exec` with `stream=False`** requires `wait=True` to be meaningful — otherwise the machine may not have started.
- **`LabParser.parse()` reads `lab.conf` only.** Call `DepParser` and `ExtParser` separately and apply results to the lab object.
- **`Setting.check()`** raises if Docker daemon is unreachable or K8s is not configured. Call it early to surface config issues before doing anything else.
- **`wipe(all_users=False)`** only removes labs started by the current user. Pass `all_users=True` with care (requires elevated privileges in some backends).
- **Machine names** must be 1–30 characters, lowercase alphanumeric or underscore. Names outside this range raise validation errors in `Machine.check()`.
- **`lab_name` vs `lab_hash` in `exec`**: prefer passing `lab_name=device.lab.name` when you have a machine object — it avoids having to track the hash separately.
- **`update_lab_from_api` before `copy_files`**: if you build a `Lab` programmatically and then call `copy_files` on a running machine, call `update_lab_from_api(lab)` first so `machine.api_object` is populated.
- **`undeploy_lab` accepts a positional hash**: `undeploy_lab(lab.hash)` is equivalent to `undeploy_lab(lab_hash=lab.hash)` — both are valid.
- **File creation methods differ between build-time and run-time**: `lab.create_file_from_string` / `machine.create_file_from_list` write to the lab's local filesystem (before or during build). To push files to a **running** machine use `copy_files`.
- **`deploy_lab` is not idempotent** for machines already running. Use `selected_machines` to deploy only the new ones when updating an existing lab.
- **`del lab.machines[name]`** is wrong — it skips link cleanup and leaves stale interface entries in collision domains. Always use `lab.remove_machine(name=name)`.
- **`new_link` / `new_machine` raise `AlreadyExists` errors** if the name already exists. Use `get_or_new_link` / `get_or_new_machine` for idempotent topology builds.
- **`sysctl` values must be in the `net.*` namespace** (e.g. `net.ipv4.ip_forward=1`). Values in other namespaces are silently rejected.
- **`connect_machine_to_link` on the Manager** takes `Machine` and `Link` *objects* (not names), and an optional `mac_address`. The `Lab.connect_machine_to_link` method (build-time) takes names — different API.
