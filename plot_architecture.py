#!/usr/bin/env python3
"""Render the AI-MTD smart-grid system architecture as a publication figure.

Reflects the Kathara lab built in run_experiment.py:
  - Nanogrid LAN 10.0.0.0/24 : SCMC  <-> Router (gw)
  - Public backbone 10.1.0.0/24 : Router <-> SEMP broker + passive Attacker
Components, MTD knobs and the QKD-secured control channel are taken from the
assets/ modules (mtd_coordinator / mtd_rl_coordinator / mtd_executor / qkd).
"""
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

# ---- palette -------------------------------------------------------------
C_LAN = "#e8f0fe"      # nanogrid LAN band
C_PUB = "#fdecea"      # public backbone band
C_NODE = "#ffffff"
C_SCMC = "#cfe3ff"
C_SEMP = "#cdebd4"
C_ROUTER = "#fff2cc"
C_ATTACK = "#f6c6c0"
C_EDGE = "#37474f"
C_CTRL = "#6a1b9a"     # encrypted control channel
C_DATA = "#1565c0"     # MQTT/TLS data
C_QKD = "#00897b"      # QKD key material
C_ATK = "#c62828"      # attack arrow

fig, ax = plt.subplots(figsize=(13, 8))
ax.set_xlim(0, 13)
ax.set_ylim(0, 8)
ax.axis("off")


def node(x, y, w, h, title, lines, fc, fs_t=11, fs_l=8.3):
    box = FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
        linewidth=1.6, edgecolor=C_EDGE, facecolor=fc, zorder=3,
    )
    ax.add_patch(box)
    ax.text(x + w / 2, y + h - 0.30, title, ha="center", va="top",
            fontsize=fs_t, fontweight="bold", zorder=4)
    ax.text(x + w / 2, y + h - 0.72, "\n".join(lines), ha="center", va="top",
            fontsize=fs_l, zorder=4, linespacing=1.45)


def arrow(p1, p2, color, style="-|>", lw=2.0, ls="-", rad=0.0, z=5):
    a = FancyArrowPatch(
        p1, p2, arrowstyle=style, mutation_scale=16, linewidth=lw,
        color=color, linestyle=ls, zorder=z,
        connectionstyle=f"arc3,rad={rad}",
    )
    ax.add_patch(a)


# ---- network bands -------------------------------------------------------
ax.add_patch(Rectangle((0.2, 4.55), 12.6, 3.0, facecolor=C_LAN,
                        edgecolor="none", zorder=0))
ax.add_patch(Rectangle((0.2, 0.45), 12.6, 3.0, facecolor=C_PUB,
                        edgecolor="none", zorder=0))
ax.text(0.45, 7.35, "Nanogrid LAN  —  10.0.0.0/24  (private)",
        fontsize=10, fontweight="bold", color="#1a3c6e", va="top")
ax.text(0.45, 3.27, "Public backbone  —  10.1.0.0/24  (exposed / sniffable)",
        fontsize=10, fontweight="bold", color="#9c2a1f", va="top")

# ---- nodes ---------------------------------------------------------------
# SCMC (microgrid controller) — top left
node(0.6, 4.9, 3.5, 2.3, "SCMC  (microgrid controller)",
     ["IPs 10.0.0.2 / .4 / .5",
      "simple_client.py  — MQTT/TLS pub",
      "mtd_executor.py  — applies knobs",
      "cert_client.py  — QKD enrolment"],
     C_SCMC)

# Router — straddles both bands (center)
node(5.45, 3.45, 2.7, 2.05, "Router / Gateway",
     ["eth0 10.0.0.1  |  eth1 10.1.0.1",
      "NAT (port-hop forwarding)",
      "replay_background.sh",
      "(PCAP noise on backbone)"],
     C_ROUTER)

# SEMP (broker + coordinator) — bottom right
node(9.0, 0.8, 3.7, 2.45, "SEMP  (central broker)",
     ["IPs 10.1.0.2 / .4 / .5",
      "mosquitto  — MQTT over TLS",
      "mtd_coordinator.py  /  _rl_  (PPO)",
      "cert_authority.py  — QKD CA"],
     C_SEMP)

# Attacker — bottom left
node(0.6, 0.8, 3.6, 2.45, "Attacker  (passive)",
     ["IP 10.1.0.3  — eth0 sniff",
      "scapy capture on backbone",
      "classify.py  — RF / CNN",
      "fingerprint + targeted blackhole"],
     C_ATTACK)

# ---- data path: SCMC -> Router -> SEMP (MQTT/TLS) ------------------------
arrow((4.1, 5.65), (5.45, 4.75), C_DATA, rad=-0.12)
arrow((7.3, 3.9), (9.6, 3.25), C_DATA, rad=-0.12)
ax.text(4.7, 5.45, "MQTT / TLS", color=C_DATA, fontsize=8.6,
        fontweight="bold", rotation=-22)
ax.text(8.05, 3.78, "MQTT / TLS", color=C_DATA, fontsize=8.6,
        fontweight="bold", rotation=-20)

# ---- encrypted control channel: SEMP coordinator <-> SCMC executor -------
arrow((9.0, 2.7), (2.0, 4.9), C_CTRL, style="<|-|>", lw=2.0, rad=0.20)
ax.text(4.55, 3.95, "Encrypted control channel (QKD-keyed)\n"
                    "SCHEDULE_HOP  /  DONE-ACK",
        color=C_CTRL, fontsize=8.6, fontweight="bold", ha="center",
        rotation=14)

# ---- QKD key material: CA (SEMP) -> client (SCMC) ------------------------
arrow((9.7, 3.0), (3.6, 4.9), C_QKD, style="-|>", lw=1.8, ls=(0, (5, 3)),
      rad=0.42)
ax.text(7.4, 5.05, "QKD shared key\n→ TLS certs", color=C_QKD, fontsize=8.3,
        fontweight="bold", ha="center")

# ---- attacker passive tap on the backbone --------------------------------
arrow((6.8, 3.45), (3.1, 3.25), C_ATK, style="-|>", lw=1.8, ls=(0, (2, 2)),
      rad=0.18)
ax.text(4.9, 2.95, "passive sniff", color=C_ATK, fontsize=8.4,
        fontweight="bold", ha="center")
arrow((4.2, 1.6), (9.0, 1.6), C_ATK, style="-|>", lw=1.6, ls=(0, (4, 3)),
      rad=-0.16)
ax.text(6.6, 0.62, "targeted blackhole (/32)  →  defeated by IP-hop",
        color=C_ATK, fontsize=8.4, fontweight="bold", ha="center")

# ---- MTD knobs callout ---------------------------------------------------
kx, ky, kw, kh = 9.0, 5.0, 3.7, 2.2
ax.add_patch(FancyBboxPatch((kx, ky), kw, kh,
             boxstyle="round,pad=0.03,rounding_size=0.1",
             linewidth=1.4, edgecolor="#6a1b9a", facecolor="#f3e5f5",
             zorder=3))
ax.text(kx + kw / 2, ky + kh - 0.28, "MTD knobs (coordinated)",
        ha="center", va="top", fontsize=10.5, fontweight="bold",
        color="#6a1b9a")
ax.text(kx + 0.25, ky + kh - 0.72,
        "• broker IP hop      • broker port hop (NAT)\n"
        "• SCMC source-IP hop  • payload padding\n"
        "• publish-frequency hop\n\n"
        "Scheduler: fixed-timer  or  RL (PPO→numpy)",
        ha="left", va="top", fontsize=8.6, linespacing=1.5)

# ---- legend --------------------------------------------------------------
from matplotlib.lines import Line2D
legend = [
    Line2D([0], [0], color=C_DATA, lw=2.4, label="MQTT data (TLS)"),
    Line2D([0], [0], color=C_CTRL, lw=2.4, label="Control channel (encrypted)"),
    Line2D([0], [0], color=C_QKD, lw=2.4, ls=(0, (5, 3)), label="QKD key / cert distribution"),
    Line2D([0], [0], color=C_ATK, lw=2.4, ls=(0, (2, 2)), label="Adversary action"),
]
ax.legend(handles=legend, loc="upper center", bbox_to_anchor=(0.30, 1.005),
          ncol=2, fontsize=8.6, frameon=True, framealpha=0.95)

ax.set_title("AI-driven Moving Target Defense for Smart-Grid MQTT "
             "(Kathará emulation)", fontsize=13.5, fontweight="bold", pad=12)

fig.tight_layout()
for ext in ("pdf", "png"):
    out = f"output/architecture.{ext}"
    fig.savefig(out, dpi=200, bbox_inches="tight")
    print("wrote", out)
