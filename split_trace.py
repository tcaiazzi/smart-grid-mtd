#!/usr/bin/env python3
"""
split_trace.py
--------------
Split a background PCAP trace into a training and a test trace based on
packet count: the first `train_ratio` fraction of packets goes to the
training pcap, the rest to the test pcap.

Uses dpkt, which iterates raw (timestamp, bytes) records without dissecting
protocol layers — orders of magnitude faster than scapy on large traces.

Usage:
    python3 split_trace.py background.pcap --train-ratio 0.7

Dependencies:
    pip install dpkt
"""

import argparse
from pathlib import Path

import dpkt


def _iter_packets(reader):
    """Yield (ts, buf) from a dpkt Reader, tolerating a truncated last packet
    (interrupted captures end mid-packet and raise NeedData)."""
    try:
        yield from reader
    except dpkt.NeedData:
        pass


def split_trace(pcap_path: str,
                train_ratio: float = 0.7,
                train_path: str | None = None,
                test_path: str | None = None) -> tuple[str, str]:
    """
    Split a PCAP into train/test by packet count.

    The first `train_ratio` fraction of packets (in capture order) is written
    to the training pcap, the remaining packets to the test pcap. Packets are
    streamed, so arbitrarily large traces can be split without loading them
    into memory.

    Args:
        pcap_path:   Path to the source background trace.
        train_ratio: Fraction of packets for the training set (default 0.7).
        train_path:  Output path for the training pcap
                     (default: <stem>_train.pcap next to the source).
        test_path:   Output path for the test pcap
                     (default: <stem>_test.pcap next to the source).

    Returns:
        (train_path, test_path) of the written files.
    """
    if not 0.0 < train_ratio < 1.0:
        raise ValueError(f"train_ratio must be in (0, 1), got {train_ratio}")

    src = Path(pcap_path)
    if not src.is_file():
        raise FileNotFoundError(src)

    train_path = train_path or str(src.with_name(f"{src.stem}_train.pcap"))
    test_path  = test_path  or str(src.with_name(f"{src.stem}_test.pcap"))

    # First pass: count packets (streaming, no full load)
    with open(src, "rb") as f:
        total = sum(1 for _ in _iter_packets(dpkt.pcap.Reader(f)))
    if total == 0:
        raise ValueError(f"No packets found in {src}")

    n_train = int(total * train_ratio)
    if n_train == 0 or n_train == total:
        raise ValueError(
            f"train_ratio={train_ratio} leaves an empty split "
            f"({total} packets total)"
        )

    # Second pass: write the two output pcaps, preserving snaplen/linktype
    with open(src, "rb") as f, \
         open(train_path, "wb") as f_train, \
         open(test_path, "wb") as f_test:
        reader = dpkt.pcap.Reader(f)
        train_writer = dpkt.pcap.Writer(
            f_train, snaplen=reader.snaplen, linktype=reader.datalink()
        )
        test_writer = dpkt.pcap.Writer(
            f_test, snaplen=reader.snaplen, linktype=reader.datalink()
        )
        for i, (ts, buf) in enumerate(_iter_packets(reader)):
            (train_writer if i < n_train else test_writer).writepkt(buf, ts)

    print(f"[*] {src.name}: {total} packets "
          f"→ train={n_train} ({train_ratio:.0%}), "
          f"test={total - n_train} ({1 - train_ratio:.0%})")
    print(f"[+] Train → {train_path}")
    print(f"[+] Test  → {test_path}")
    return train_path, test_path


def main():
    parser = argparse.ArgumentParser(
        description="Split a background pcap into train/test by packet count"
    )
    parser.add_argument("pcap", help="Source background trace (pcap)")
    parser.add_argument("--train-ratio", type=float, default=0.7,
                        help="Fraction of packets for training (default 0.7)")
    parser.add_argument("--train-out", default=None,
                        help="Training pcap path (default: <stem>_train.pcap)")
    parser.add_argument("--test-out", default=None,
                        help="Test pcap path (default: <stem>_test.pcap)")
    args = parser.parse_args()

    split_trace(args.pcap, args.train_ratio, args.train_out, args.test_out)


if __name__ == "__main__":
    main()
