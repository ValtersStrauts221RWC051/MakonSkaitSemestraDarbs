"""Classify CoreDNS log lines as benign or malicious DNS tunneling.

Reads one log line per stdin line (or from a file argument) and prints the
predicted label and probability. Only [INFO] JSON entries are classified;
other lines are skipped.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import torch
from torch import nn

FEATURES = [
    "dns_domain_name_length",
    "dns_subdomain_name_length",
    "numerical_percentage",
    "character_entropy",
    "max_continuous_numeric_len",
    "max_continuous_alphabet_len",
    "max_continuous_consonants_len",
    "max_continuous_same_alphabet_len",
    "vowels_consonant_ratio",
    "conv_freq_vowels_consonants",
]

VOWELS = set("aeiou")
ALPHA = set("abcdefghijklmnopqrstuvwxyz")
CONSONANTS = ALPHA - VOWELS

INFO_LINE_RE = re.compile(r"^\[INFO\]\s+(\{.*\})\s*$")


class MLP(nn.Module):
    def __init__(self, input_dim: int, num_classes: int = 2):
        super().__init__()
        self.model = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),

            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),

            nn.Linear(64, 32),
            nn.ReLU(),

            nn.Linear(32, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.model(x)


def parse_log_line(line: str) -> dict | None:
    m = INFO_LINE_RE.match(line.strip())
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


def parse_duration(s: str) -> float:
    return float(s.rstrip("s"))


def subdomain_part(name: str) -> str:
    """Everything left of the registrable domain (2LD.TLD)."""
    n = name.rstrip(".")
    parts = n.split(".")
    if len(parts) <= 2:
        return ""
    return ".".join(parts[:-2])


def char_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def max_continuous(s: str, predicate) -> int:
    best = cur = 0
    for ch in s:
        if predicate(ch):
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 0
    return best


def max_continuous_same(s: str) -> int:
    if not s:
        return 0
    best = cur = 1
    for a, b in zip(s, s[1:]):
        if a == b:
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 1
    return best


def numeric_pct(s: str) -> float:
    if not s:
        return 0.0
    return sum(ch.isdigit() for ch in s) / len(s)


def vowels_consonants_ratio(s: str) -> float:
    s = s.lower()
    v = sum(1 for ch in s if ch in VOWELS)
    c = sum(1 for ch in s if ch in CONSONANTS)
    if c == 0:
        return float(v)
    return v / c


def conv_freq_vowels_consonants(s: str) -> float:
    """v<->c transition count normalized by (len(s) - 1), matching the training CSV convention."""
    prev = None
    transitions = 0
    for ch in s.lower():
        cat = "v" if ch in VOWELS else ("c" if ch in CONSONANTS else None)
        if cat is None:
            continue
        if prev is not None and cat != prev:
            transitions += 1
        prev = cat
    denom = len(s) - 1
    if denom <= 0:
        return 0.0
    return transitions / denom


def extract_features(entry: dict) -> np.ndarray:
    raw_name = entry.get("name") or entry.get("query_name", "")
    full = raw_name if raw_name.endswith(".") else raw_name + "."
    flower = full.lower()
    sub = subdomain_part(raw_name)

    values = {
        "dns_domain_name_length": float(len(full)),
        "dns_subdomain_name_length": float(len(sub)),
        "numerical_percentage": numeric_pct(full),
        "character_entropy": char_entropy(full),
        "max_continuous_numeric_len": float(max_continuous(full, str.isdigit)),
        "max_continuous_alphabet_len": float(max_continuous(flower, lambda c: c in ALPHA)),
        "max_continuous_consonants_len": float(max_continuous(flower, lambda c: c in CONSONANTS)),
        "max_continuous_same_alphabet_len": float(max_continuous_same(flower)),
        "vowels_consonant_ratio": vowels_consonants_ratio(full),
        "conv_freq_vowels_consonants": conv_freq_vowels_consonants(full),
    }
    return np.array([values[k] for k in FEATURES], dtype=np.float32)


def load_model(ckpt_path: Path, device: torch.device):
    ckpt = torch.load(ckpt_path, map_location=device, weights_only=False)
    features = ckpt.get("features", FEATURES)
    if list(features) != FEATURES:
        raise ValueError(
            f"checkpoint features differ from inference features:\n"
            f"  ckpt: {features}\n  here: {FEATURES}\n"
            f"retrain with the reduced feature set in train.py."
        )
    model = MLP(input_dim=len(features), num_classes=2)
    model.load_state_dict(ckpt["model_state"])
    model.to(device).eval()
    mean = np.asarray(ckpt["scaler_mean"], dtype=np.float32)
    scale = np.asarray(ckpt["scaler_scale"], dtype=np.float32)
    return model, mean, scale


@torch.no_grad()
def classify(
    entry: dict,
    model: nn.Module,
    mean: np.ndarray,
    scale: np.ndarray,
    device: torch.device,
    threshold: float,
) -> dict:
    x = extract_features(entry)
    x = (x - mean) / scale
    logits = model(torch.from_numpy(x[None, :]).to(device))
    prob = float(torch.softmax(logits, dim=1)[0, 1].item())
    return {
        "name": entry.get("name") or entry.get("query_name", ""),
        "type": entry.get("type") or entry.get("query_type", ""),
        "prob_malicious": prob,
        "label": "malicious" if prob >= threshold else "benign",
    }


def iter_input(path: str | None):
    if path:
        with open(path) as f:
            for line in f:
                yield line
    else:
        for line in sys.stdin:
            yield line


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="model.pt", help="path to trained checkpoint")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("input", nargs="?", help="log file path; reads stdin if omitted")
    args = ap.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model, mean, scale = load_model(Path(args.model), device)

    for line in iter_input(args.input):
        entry = parse_log_line(line)
        if entry is None:
            continue
        r = classify(entry, model, mean, scale, device, args.threshold)
        print(f"{r['label']:>10}  p={r['prob_malicious']:.4f}  {r['type']:>6}  {r['name']}")


if __name__ == "__main__":
    main()
