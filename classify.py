import argparse
import os
import pickle
import sys
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, TCP
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report,
    roc_auc_score,
    roc_curve,
    confusion_matrix,
)
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from tqdm import tqdm

FEATURE_COLS = [
    "packet_len",
    "tcp_payload_len",
    "flag_syn",
    "flag_ack",
    "flag_psh",
    "flag_fin",
    "tcp_window_size",
    "ip_ttl",
    "iat",
    "burst_flag",
]
N_FEATURES = len(FEATURE_COLS)  # 10
BURST_THRESHOLD_S = 0.1


def _flow_key(pkt) -> Optional[tuple]:
    if IP not in pkt or TCP not in pkt:
        return None
    return (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)


def _flow_key_str(fk: tuple) -> str:
    return f"{fk[0]}:{fk[1]}->{fk[2]}:{fk[3]}"


def extract_features(
    pcap_path: str,
    scmc_ip: Optional[str] = None,
    semp_ip: Optional[str] = None,
    broker_port: int = 8883,
    force_label: Optional[int] = None,
) -> pd.DataFrame:
    """
    Parse a PCAP and return a DataFrame with one row per IP/TCP packet.
    Labels packets as nanogrid when they belong to the SCMC↔broker connection.
    IAT and burst_flag are computed intra-flow (per 4-tuple).
    """
    packets = rdpcap(str(pcap_path))

    flow_prev_time: dict[tuple, float] = {}
    rows = []

    for pkt in tqdm(packets, desc="Extracting features", unit="pkt"):
        if IP not in pkt or TCP not in pkt:
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]
        timestamp = float(pkt.time)

        fk = _flow_key(pkt)
        if fk is None:
            continue

        prev_t = flow_prev_time.get(fk)
        iat_raw = timestamp - prev_t if prev_t is not None else 0.0
        flow_prev_time[fk] = timestamp
        iat = float(np.log1p(max(iat_raw, 0.0)))
        burst = 1 if (0 < iat_raw < BURST_THRESHOLD_S) else 0

        ip_ttl = int(ip.ttl)
        packet_len = int(ip.len) if ip.len else 0
        ihl_bytes = ip.ihl * 4
        dataofs_bytes = tcp.dataofs * 4
        tcp_payload_len = max(packet_len - ihl_bytes - dataofs_bytes, 0)

        row = {
            "timestamp": timestamp,
            "src_ip": ip.src,
            "flow_key": _flow_key_str(fk),
            "packet_len": packet_len,
            "tcp_payload_len": tcp_payload_len,
            "flag_syn": int(tcp.flags.S),
            "flag_ack": int(tcp.flags.A),
            "flag_psh": int(tcp.flags.P),
            "flag_fin": int(tcp.flags.F),
            "tcp_window_size": int(tcp.window),
            "ip_ttl": ip_ttl,
            "iat": iat,
            "burst_flag": burst,
        }

        if force_label is not None:
            row["is_nanogrid"] = force_label
        elif scmc_ip and semp_ip:
            row["is_nanogrid"] = int(
                (ip.src == scmc_ip and tcp.dport == broker_port)
                or (ip.dst == scmc_ip and tcp.sport == broker_port)
                or (ip.src == semp_ip and tcp.sport == broker_port)
                or (ip.dst == semp_ip and tcp.dport == broker_port)
            )

        rows.append(row)

    df = pd.DataFrame(rows)
    if df.empty:
        raise ValueError(f"No IP/TCP packets found in {pcap_path}")
    return df


def build_packet_windows(
    df: pd.DataFrame,
    scaler: Optional[StandardScaler] = None,
    window_size: int = 32,
    fit_scaler: bool = False,
) -> tuple[np.ndarray, np.ndarray, StandardScaler, pd.DataFrame]:
    """
    Build one context window per packet (packet-level samples).

    For packet i in a flow, the window = the W packets ending at i (left-zero-padded
    if i < W). Label = that packet's own is_nanogrid.

    Returns
    -------
    X       : (N, window_size, F)  float32
    y       : (N,)                 int32
    scaler  : fitted or passed-through StandardScaler
    meta    : (N,) DataFrame with src_ip, flow_key, timestamp for mapping back
    """
    if "is_nanogrid" not in df.columns:
        raise ValueError("DataFrame must have an 'is_nanogrid' column")

    if fit_scaler:
        scaler = StandardScaler()
        scaler.fit(df[FEATURE_COLS].values.astype(np.float32))
    elif scaler is None:
        raise ValueError("Pass a fitted scaler or set fit_scaler=True")

    X_list, y_list, meta_rows = [], [], []

    for fk, flow_df in df.groupby("flow_key", sort=False):
        flow_df = flow_df.reset_index(drop=True)
        scaled = scaler.transform(flow_df[FEATURE_COLS].values.astype(np.float32))
        labels = flow_df["is_nanogrid"].values

        for i in range(len(flow_df)):
            start = i - window_size + 1
            if start >= 0:
                window = scaled[start : i + 1]
            else:
                pad = np.zeros((-start, N_FEATURES), dtype=np.float32)
                window = np.concatenate([pad, scaled[: i + 1]], axis=0)
            X_list.append(window)
            y_list.append(int(labels[i]))
            meta_rows.append(
                {
                    "src_ip": flow_df["src_ip"].iloc[i],
                    "flow_key": fk,
                    "timestamp": flow_df["timestamp"].iloc[i],
                }
            )

    if not X_list:
        raise ValueError("No packets found to build windows from")

    return (
        np.array(X_list, dtype=np.float32),
        np.array(y_list, dtype=np.int32),
        scaler,
        pd.DataFrame(meta_rows),
    )


class FlowClassifierCNN(nn.Module):
    """
    Binary 1D-CNN: input (batch, window_size, n_features) → logit per sample.
    """

    def __init__(self, n_features: int = N_FEATURES, window_size: int = 32):
        super().__init__()
        self.n_features = n_features
        self.window_size = window_size

        self.encoder = nn.Sequential(
            nn.Conv1d(n_features, 32, kernel_size=3, padding=1),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Conv1d(32, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Conv1d(64, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(1),
        )
        self.head = nn.Linear(64, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x.permute(0, 2, 1)
        x = self.encoder(x).squeeze(-1)
        return self.head(x).squeeze(-1)


def train_classifier(
    train_df: pd.DataFrame,
    window_size: int = 32,
    epochs: int = 50,
    batch_size: int = 64,
    lr: float = 1e-3,
    device: Optional[torch.device] = None,
) -> tuple["FlowClassifierCNN", StandardScaler]:
    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    n_ng = int((train_df["is_nanogrid"] == 1).sum())
    n_bg = int((train_df["is_nanogrid"] == 0).sum())
    print(f"[train] Device: {device}")
    print(f"[train] Packets: {len(train_df)}  (nanogrid={n_ng}, background={n_bg})")

    X, y, scaler, _ = build_packet_windows(
        train_df, window_size=window_size, fit_scaler=True
    )
    print(
        f"[train] Packet windows: {len(X)}  "
        f"(nanogrid={y.sum()}, background={(y == 0).sum()})"
    )

    X_t, X_v, y_t, y_v = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=0
    )

    n_pos = int(y_t.sum())
    n_neg = int((y_t == 0).sum())
    pos_weight = torch.tensor(n_neg / max(n_pos, 1), dtype=torch.float32).to(device)
    print(f"[train] pos_weight={pos_weight.item():.2f}  (train pos={n_pos}, neg={n_neg})")

    dl_train = DataLoader(
        TensorDataset(torch.from_numpy(X_t), torch.from_numpy(y_t).float()),
        batch_size=batch_size,
        shuffle=True,
    )
    dl_val = DataLoader(
        TensorDataset(torch.from_numpy(X_v), torch.from_numpy(y_v).float()),
        batch_size=batch_size,
    )

    model = FlowClassifierCNN(n_features=N_FEATURES, window_size=window_size).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    best_val_loss = float("inf")
    best_state = None

    epoch_bar = tqdm(range(1, epochs + 1), desc="Training", unit="epoch")
    for epoch in epoch_bar:
        model.train()
        train_loss = 0.0
        for xb, yb in dl_train:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            loss = criterion(model(xb), yb)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * len(xb)
        train_loss /= len(dl_train.dataset)

        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for xb, yb in dl_val:
                xb, yb = xb.to(device), yb.to(device)
                val_loss += criterion(model(xb), yb).item() * len(xb)
        val_loss /= max(len(dl_val.dataset), 1)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

        epoch_bar.set_postfix(
            train=f"{train_loss:.4f}",
            val=f"{val_loss:.4f}",
            best=f"{best_val_loss:.4f}",
        )

    if best_state:
        model.load_state_dict(best_state)
        print(f"[train] Loaded best weights (val_loss={best_val_loss:.6f})")

    return model, scaler


def predict_packets(
    df: pd.DataFrame,
    model: "FlowClassifierCNN",
    scaler: StandardScaler,
    window_size: int = 32,
    threshold: float = 0.5,
    device: Optional[torch.device] = None,
) -> pd.DataFrame:
    """
    Score every packet in df and return a DataFrame with columns:
    src_ip, flow_key, timestamp, prob, label_pred, [label_true if available].
    """
    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    has_labels = "is_nanogrid" in df.columns

    if not has_labels:
        df = df.copy()
        df["is_nanogrid"] = 0

    X, y, _, meta = build_packet_windows(df, scaler=scaler, window_size=window_size)

    model.eval()
    all_probs = []
    with torch.no_grad():
        for start in tqdm(
            range(0, len(X), 256), desc="Scoring packets", unit="batch"
        ):
            xb = torch.from_numpy(X[start : start + 256]).to(device)
            probs = torch.sigmoid(model(xb)).cpu().numpy()
            all_probs.append(probs)

    probs_all = np.concatenate(all_probs)
    meta = meta.copy()
    meta["prob"] = probs_all
    meta["label_pred"] = (probs_all >= threshold).astype(int)
    if has_labels:
        meta["label_true"] = y

    return meta


def evaluate(
    pkt_preds: pd.DataFrame,
    out_dir: Path,
) -> None:
    """Print packet-level metrics and save the ROC curve and confusion matrix."""
    out_dir.mkdir(parents=True, exist_ok=True)

    if "label_true" not in pkt_preds.columns:
        print("[evaluate] No ground-truth labels — skipping metrics")
        return

    y_true = pkt_preds["label_true"].values
    y_pred = pkt_preds["label_pred"].values
    y_score = pkt_preds["prob"].values

    print("\n=== Packet-level Classification Report ===")
    print(
        classification_report(
            y_true, y_pred, target_names=["background", "nanogrid"], zero_division=0
        )
    )

    try:
        auc = roc_auc_score(y_true, y_score)
        print(f"ROC-AUC: {auc:.4f}")
    except ValueError:
        auc = None
        print("ROC-AUC: N/A (only one class present)")

    cm = confusion_matrix(y_true, y_pred)
    print(f"Confusion matrix:\n{cm}")

    # ROC curve
    if auc is not None:
        fpr, tpr, _ = roc_curve(y_true, y_score)
        fig, ax = plt.subplots(figsize=(6, 6))
        ax.plot(fpr, tpr, label=f"AUC = {auc:.3f}")
        ax.plot([0, 1], [0, 1], linestyle="--", color="grey")
        ax.set_xlabel("False Positive Rate")
        ax.set_ylabel("True Positive Rate")
        ax.set_title("ROC Curve — nanogrid detection (packet-level)")
        ax.legend()
        fig.tight_layout()
        fig.savefig(out_dir / "roc_curve.pdf", dpi=120)
        plt.close(fig)
        print(f"[evaluate] Saved: {out_dir / 'roc_curve.pdf'}")

    # Confusion matrix
    fig, ax = plt.subplots(figsize=(5, 5))
    im = ax.imshow(cm, cmap="Blues")
    labels = ["background", "nanogrid"]
    ax.set_xticks([0, 1], labels=labels)
    ax.set_yticks([0, 1], labels=labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title("Confusion matrix — nanogrid detection (packet-level)")
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j, i, f"{cm[i, j]:d}",
                ha="center", va="center",
                color="white" if cm[i, j] > cm.max() / 2 else "black",
            )
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(out_dir / "confusion_matrix.png", dpi=120)
    plt.close(fig)
    print(f"[evaluate] Saved: {out_dir / 'confusion_matrix.png'}")


def save_artifacts(
    model: FlowClassifierCNN,
    scaler: StandardScaler,
    out_dir: Path,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "model_state": model.state_dict(),
            "n_features": model.n_features,
            "window_size": model.window_size,
        },
        out_dir / "model.pt",
    )
    with open(out_dir / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    print(f"[save] Artifacts saved to {out_dir}/")


def load_artifacts(
    model_path: str, scaler_path: str
) -> tuple["FlowClassifierCNN", StandardScaler]:
    checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
    model = FlowClassifierCNN(
        n_features=checkpoint["n_features"],
        window_size=checkpoint["window_size"],
    )
    model.load_state_dict(checkpoint["model_state"])
    model.eval()
    with open(scaler_path, "rb") as f:
        scaler = pickle.load(f)
    print(f"[load] Model loaded from {model_path}")
    return model, scaler


def rank_nanogrid_ips(pkt_preds: pd.DataFrame) -> pd.DataFrame:
    """
    Rank source IPs by how nanogrid-like their traffic is.

    Returns a DataFrame indexed by src_ip, sorted by nanogrid_frac desc, with
    columns: nanogrid_frac (positives / total), positive_count, n_packets.
    """
    if pkt_preds.empty:
        return pd.DataFrame(columns=["nanogrid_frac", "positive_count", "n_packets"])
    return (
        pkt_preds.groupby("src_ip")["label_pred"]
        .agg(nanogrid_frac="mean", positive_count="sum", n_packets="count")
        .sort_values("nanogrid_frac", ascending=False)
    )


def _detect_nanogrid_ip(pkt_preds: pd.DataFrame, threshold: float = 0.3) -> str:
    """Return the src_ip with the highest nanogrid-packet fraction."""
    ranking = rank_nanogrid_ips(pkt_preds)
    if ranking.empty:
        return ""
    best = ranking.iloc[0]
    if best["nanogrid_frac"] >= threshold:
        print(
            f"[infer] Detected nanogrid IP: {best.name}  "
            f"(nanogrid_frac={best['nanogrid_frac']:.3f}, "
            f"n_packets={int(best['n_packets'])})"
        )
        return str(best.name)
    print("[infer] No nanogrid IP detected above threshold")
    return ""


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Packet-level 1D-CNN — nanogrid traffic classifier"
    )
    p.add_argument(
        "--mode",
        required=True,
        choices=["train", "evaluate", "infer"],
    )
    p.add_argument("--train-pcap", metavar="PCAP", default=None)
    p.add_argument("--test-pcap", metavar="PCAP", default=None)
    p.add_argument("--scmc-ip", default="10.0.0.2")
    p.add_argument("--semp-ip", default="10.1.0.2")
    p.add_argument("--broker-port", type=int, default=8883)
    p.add_argument("--model", default="output/model.pt")
    p.add_argument("--scaler", default="output/scaler.pkl")
    p.add_argument("--out-dir", default="output")
    p.add_argument("--window-size", type=int, default=32)
    p.add_argument("--epochs", type=int, default=50)
    p.add_argument("--batch-size", type=int, default=64)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--threshold", type=float, default=0.5)
    p.add_argument(
        "--load-model",
        action="store_true",
        help="In evaluate mode, load --model/--scaler instead of retraining",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    out_dir = Path(args.out_dir)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    if args.mode == "train":
        if not args.train_pcap:
            sys.exit("[ERROR] --train-pcap required for train mode")
        print(f"[main] Extracting features from {args.train_pcap}")
        train_df = extract_features(
            args.train_pcap,
            scmc_ip=args.scmc_ip,
            semp_ip=args.semp_ip,
            broker_port=args.broker_port,
        )
        print(
            f"[main] Train packets: {len(train_df)}  "
            f"(nanogrid={int((train_df['is_nanogrid'] == 1).sum())}, "
            f"background={int((train_df['is_nanogrid'] == 0).sum())})"
        )
        model, scaler = train_classifier(
            train_df,
            window_size=args.window_size,
            epochs=args.epochs,
            batch_size=args.batch_size,
            lr=args.lr,
            device=device,
        )
        save_artifacts(model, scaler, out_dir)

    elif args.mode == "evaluate":
        if not args.test_pcap:
            sys.exit("[ERROR] --test-pcap required for evaluate mode")

        # Results are written straight to --out-dir; the caller (Makefile) points
        # it at the per-experiment eval/model-<src>/ directory.
        results_dir = out_dir

        if args.load_model:
            model, scaler = load_artifacts(args.model, args.scaler)
            model.to(device)
            window_size = model.window_size
        else:
            if not args.train_pcap:
                sys.exit("[ERROR] --train-pcap required for evaluate mode (or use --load-model)")
            print(f"[main] Extracting train features from {args.train_pcap}")
            train_df = extract_features(
                args.train_pcap,
                scmc_ip=args.scmc_ip,
                semp_ip=args.semp_ip,
                broker_port=args.broker_port,
            )
            print(
                f"[main] Train packets: {len(train_df)}  "
                f"(nanogrid={int((train_df['is_nanogrid'] == 1).sum())}, "
                f"background={int((train_df['is_nanogrid'] == 0).sum())})"
            )
            model, scaler = train_classifier(
                train_df,
                window_size=args.window_size,
                epochs=args.epochs,
                batch_size=args.batch_size,
                lr=args.lr,
                device=device,
            )
            save_artifacts(model, scaler, out_dir)
            window_size = args.window_size

        print(f"[main] Extracting test features from {args.test_pcap}")
        test_df = extract_features(
            args.test_pcap,
            scmc_ip=args.scmc_ip,
            semp_ip=args.semp_ip,
            broker_port=args.broker_port,
        )
        print(
            f"[main] Test packets: {len(test_df)}  "
            f"(nanogrid={int((test_df['is_nanogrid'] == 1).sum())}, "
            f"background={int((test_df['is_nanogrid'] == 0).sum())})"
        )

        pkt_preds = predict_packets(
            test_df, model, scaler,
            window_size=window_size,
            threshold=args.threshold,
            device=device,
        )
        evaluate(pkt_preds, results_dir)

        csv_path = results_dir / "predictions.csv"
        pkt_preds.to_csv(csv_path, index=False)
        print(f"[main] Per-packet predictions saved to {csv_path}")

    elif args.mode == "infer":
        if not args.test_pcap:
            sys.exit("[ERROR] --test-pcap required for infer mode")
        model, scaler = load_artifacts(args.model, args.scaler)
        model.to(device)

        print(f"[main] Extracting features from {args.test_pcap}")
        df = extract_features(args.test_pcap)

        pkt_preds = predict_packets(
            df, model, scaler,
            window_size=args.window_size,
            threshold=args.threshold,
            device=device,
        )
        detected_ip = _detect_nanogrid_ip(pkt_preds)
        if detected_ip:
            print(f"[infer] Nanogrid IP: {detected_ip}")
        else:
            print("[infer] No nanogrid IP detected")


if __name__ == "__main__":
    main()
