# Smart Grid AI-MTD

AI-driven Moving Target Defense (MTD) for MQTT communications in a smart grid, emulated with [Kathará](https://github.com/KatharaFramework/Kathara).

The system models a microgrid SCMC publishing telemetry (power, frequency, voltage) over MQTT/TLS to a central SEMP broker, while a passive attacker on the backbone sniffs traffic. A simulated QKD exchange bootstraps mutual TLS; the attacker then captures traffic, identifies the SCMC by IP fingerprinting, and blocks it at the router — demonstrating the threat that MTD must counter.

---

## Architecture

```
  Network A (10.0.0.0/24)          Network B (10.1.0.0/24)
  ┌──────────────────────┐         ┌──────────────────────────┐
  │  SCMC  10.0.0.2      │         │  SEMP (broker)  10.1.0.2 │
  │  pymgrid + paho-mqtt │         │  mosquitto TLS  :8883    │
  └────────┬─────────────┘         └──────────┬───────────────┘
           │                                   │
           └──────────── ROUTER ───────────────┘
                     10.0.0.1 / 10.1.0.1
                     (routes + pcap replay)
                                   │
                         ┌─────────┴──────────┐
                         │  Attacker 10.1.0.3  │
                         │  tcpdump + analysis │
                         └────────────────────┘
```

**Security bootstrap (QKD simulation):** a 256-bit key is generated on the host and injected into both SEMP and SCMC as a stand-in for a Quantum Key Distribution channel. SEMP runs `cert_authority.py` — it self-signs a CA, signs the broker certificate, then listens for clients. SCMC runs `cert_client.py` — it sends its CN encrypted with the shared key, receives the signed cert bundle back encrypted. Mosquitto starts with mutual TLS (`require_certificate true`).

**Fingerprinting attack:** the attacker captures traffic on `eth0` with `tcpdump`. `traffic_analysis.py` parses the PCAP, reconstructs TLS Application Data flows, and identifies the SCMC's source IP. The router then drops all forwarded traffic from that IP.

---

## Prerequisites

| Dependency | Version | Notes |
|---|---|---|
| Python | 3.10+ | use the project venv |
| [Kathará](https://github.com/KatharaFramework/Kathara) | ≥ 3.7 | system binary + Python API |
| Docker | 24+ | Kathará backend |
| `smartgrid/node:latest` | — | custom image (see below) |

---

## Setup

### 1. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install kathara
```

### 2. Build the custom Docker image

All lab nodes use a single image that bakes in mosquitto, paho-mqtt, scapy, tcpreplay, and editcap — avoiding slow/unreliable `apt` runs at container start.

```bash
docker build -t smartgrid/node:latest docker/mqtt/
```

### 3. Background traffic trace (optional)

The experiment replays a real PCAP onto the backbone so the attacker sees realistic noise. Place a `traccia.pcap` (or `traccia.pcapng`) in `assets/pcap/`. The file is gitignored due to size. Without it, the router step will fail — comment out the relevant lines in `run_experiment.py` to skip replay.

---

## Running the experiment

```bash
source .venv/bin/activate
python run_experiment.py
```

The script:
1. Wipes any existing Kathará state and creates a fresh lab
2. Deploys four nodes (SCMC, router, SEMP, attacker) with the IP layout above
3. Generates a random 256-bit QKD key and bootstraps mutual TLS
4. Starts the mosquitto broker and background traffic replay
5. SCMC publishes MQTT telemetry; attacker captures for 10 s
6. Router blocks the identified SCMC IP via `iptables`
7. Downloads captures and broker log to `output/`, then undeploys the lab

---

## Output

| File | Contents |
|---|---|
| `output/attacker_capture.pcap` | Packets seen by the attacker on the backbone |
| `output/router_capture.pcap` | Full traffic through the router's LAN-side interface |
| `output/mosquitto.log` | Mosquitto broker log (connections, publishes) |

### Analysing captures

```bash
python traffic_analysis.py output/attacker_capture.pcap
# optional: filter to a non-standard port
python traffic_analysis.py output/router_capture.pcap --port 8883 1883
```

The parser reconstructs bidirectional TLS Application Data flows (discarding handshake and ACK-only packets) and prints per-flow packet counts and durations.

---

## Project structure

```
smart-grid-mtd/
├── run_experiment.py          # Kathará orchestrator — main entry point
├── traffic_analysis.py        # PCAP parser: extracts TLS/MQTT flows
├── requirements.txt
├── assets/
│   ├── qkd/
│   │   ├── cert_authority.py  # CA server (SEMP): issues certs over QKD-keyed channel
│   │   └── cert_client.py     # Cert client (SCMC): receives signed cert bundle
│   ├── mosquitto/
│   │   └── mosquitto.conf     # TLS broker config (mutual auth, port 8883)
│   ├── simple_client.py       # SCMC: pymgrid simulator + paho-mqtt publisher
│   ├── traffic_generator.py   # Alternative traffic generator
│   ├── replay_background.sh   # tcpreplay wrapper for background noise
│   └── pcap/                  # Real traffic traces (gitignored if large)
├── docker/
│   └── mqtt/Dockerfile        # Custom node image (kathara/core + mosquitto + tooling)
└── output/                    # Experiment outputs (gitignored)
```

---

## Research context

This prototype is the emulation layer for a paper targeting IEEE SmartGridComm / ACM CPS-SPC. The full system will extend this baseline with:

- Three SCMCs publishing concurrently
- LSTM anomaly detection on traffic features
- DQN agent (stable-baselines3) selecting from 8 MTD actions (IP hop, port randomisation, payload padding, …)
- QKD key rotation every 30 s driving cert re-issuance
- Attacker using a RandomForest on 7 traffic features for fingerprinting
- Experiments E1–E7 measuring attacker accuracy under each MTD configuration
