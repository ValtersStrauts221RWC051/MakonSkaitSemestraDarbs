"""Binary DNS-tunneling classifier: benign vs malicious."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

FEATURES_KEEP = [
    "duration",
    "total_bytes",
    "receiving_bytes",
    "sending_bytes",
    "packets_rate",
    "packets_len_rate",
    "min_packets_len",
    "max_packets_len",
    "mean_packets_len",
    "standard_deviation_packets_len",
    "variance_packets_len",
    "coefficient_of_variation_packets_len",
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
    "distinct_ttl_values",
    "ttl_values_min",
    "ttl_values_max",
    "ttl_values_mean",
    "ttl_values_mode",
    "ttl_values_median",
    "distinct_A_records",
]

LABEL_COL = "label"


def load_dataset(csv_list_path: Path) -> pd.DataFrame:
    paths = [Path(p) for p in csv_list_path.read_text().splitlines() if p.strip()]
    frames = []
    for p in paths:
        df = pd.read_csv(p, usecols=FEATURES_KEEP + [LABEL_COL], low_memory=False)
        frames.append(df)
        print(f"  loaded {p.parent.name}/{p.name}: {len(df):>8} rows")
    full = pd.concat(frames, ignore_index=True)
    full[LABEL_COL] = (full[LABEL_COL].str.lower() == "malicious").astype(np.int64)
    for col in FEATURES_KEEP:
        full[col] = pd.to_numeric(full[col], errors="coerce")
    before = len(full)
    full = full.dropna(subset=FEATURES_KEEP).reset_index(drop=True)
    dropped = before - len(full)
    if dropped:
        print(f"  dropped {dropped} rows with NaN in numeric features")
    return full


def balance_undersample(df: pd.DataFrame, seed: int) -> pd.DataFrame:
    pos = df[df[LABEL_COL] == 1]
    neg = df[df[LABEL_COL] == 0]
    n = min(len(pos), len(neg))
    pos_s = pos.sample(n=n, random_state=seed)
    neg_s = neg.sample(n=n, random_state=seed)
    return pd.concat([pos_s, neg_s]).sample(frac=1.0, random_state=seed).reset_index(drop=True)


class MLP(nn.Module):
    def __init__(self, in_dim: int, hidden: int = 128, dropout: float = 0.3):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, hidden),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden, hidden // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden // 2, 1),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x).squeeze(-1)


def pick_device() -> torch.device:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device.type == "cuda":
        print(f"device: cuda ({torch.cuda.get_device_name(0)})")
    else:
        print("device: cpu")
    return device


def make_loader(x: np.ndarray, y: np.ndarray, batch: int, shuffle: bool) -> DataLoader:
    ds = TensorDataset(torch.from_numpy(x).float(), torch.from_numpy(y).float())
    return DataLoader(ds, batch_size=batch, shuffle=shuffle, num_workers=0, pin_memory=True)


@torch.no_grad()
def evaluate(model: nn.Module, loader: DataLoader, device: torch.device) -> dict:
    model.eval()
    logits_all, y_all = [], []
    for xb, yb in loader:
        xb = xb.to(device, non_blocking=True)
        logits_all.append(model(xb).cpu())
        y_all.append(yb)
    logits = torch.cat(logits_all).numpy()
    y_true = torch.cat(y_all).numpy().astype(int)
    probs = 1.0 / (1.0 + np.exp(-logits))
    y_pred = (probs >= 0.5).astype(int)
    return {
        "loss": float(nn.functional.binary_cross_entropy_with_logits(
            torch.from_numpy(logits), torch.from_numpy(y_true.astype(np.float32))
        )),
        "acc": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "auc": roc_auc_score(y_true, probs),
    }


def train(args: argparse.Namespace) -> None:
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    print(f"loading dataset list from {args.csv_list}")
    df = load_dataset(Path(args.csv_list))
    print(f"total rows: {len(df)}  | benign: {(df[LABEL_COL]==0).sum()}  malicious: {(df[LABEL_COL]==1).sum()}")

    df = balance_undersample(df, seed=args.seed)
    print(f"after undersample: {len(df)} rows (50/50)")

    x = df[FEATURES_KEEP].to_numpy(dtype=np.float32)
    y = df[LABEL_COL].to_numpy(dtype=np.int64)

    x_tr, x_tmp, y_tr, y_tmp = train_test_split(
        x, y, test_size=0.30, stratify=y, random_state=args.seed
    )
    x_val, x_te, y_val, y_te = train_test_split(
        x_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=args.seed
    )

    scaler = StandardScaler().fit(x_tr)
    x_tr = scaler.transform(x_tr).astype(np.float32)
    x_val = scaler.transform(x_val).astype(np.float32)
    x_te = scaler.transform(x_te).astype(np.float32)

    device = pick_device()
    model = MLP(in_dim=len(FEATURES_KEEP), hidden=args.hidden, dropout=args.dropout).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-5)
    loss_fn = nn.BCEWithLogitsLoss()

    tr_loader = make_loader(x_tr, y_tr.astype(np.float32), args.batch, shuffle=True)
    val_loader = make_loader(x_val, y_val.astype(np.float32), args.batch, shuffle=False)
    te_loader = make_loader(x_te, y_te.astype(np.float32), args.batch, shuffle=False)

    best_val = float("inf")
    best_state = None
    patience_left = args.patience

    for epoch in range(1, args.epochs + 1):
        model.train()
        running = 0.0
        n = 0
        for xb, yb in tr_loader:
            xb = xb.to(device, non_blocking=True)
            yb = yb.to(device, non_blocking=True)
            opt.zero_grad()
            logits = model(xb)
            loss = loss_fn(logits, yb)
            loss.backward()
            opt.step()
            running += loss.item() * xb.size(0)
            n += xb.size(0)
        tr_loss = running / n
        val = evaluate(model, val_loader, device)
        print(
            f"epoch {epoch:>3} | train_loss {tr_loss:.4f} | "
            f"val_loss {val['loss']:.4f} acc {val['acc']:.4f} f1 {val['f1']:.4f} auc {val['auc']:.4f}"
        )
        if val["loss"] < best_val - 1e-4:
            best_val = val["loss"]
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            patience_left = args.patience
        else:
            patience_left -= 1
            if patience_left <= 0:
                print(f"early stopping at epoch {epoch}")
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    test = evaluate(model, te_loader, device)
    print("\n=== test set ===")
    for k, v in test.items():
        print(f"  {k:>9}: {v:.4f}")

    if args.save:
        out = Path(args.save)
        torch.save(
            {
                "model_state": model.state_dict(),
                "scaler_mean": scaler.mean_,
                "scaler_scale": scaler.scale_,
                "features": FEATURES_KEEP,
                "test_metrics": test,
            },
            out,
        )
        print(f"saved model to {out}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--csv-list", default="csv_files.txt", help="file with one CSV path per line")
    p.add_argument("--epochs", type=int, default=30)
    p.add_argument("--batch", type=int, default=512)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--hidden", type=int, default=128)
    p.add_argument("--dropout", type=float, default=0.3)
    p.add_argument("--patience", type=int, default=4, help="early-stopping patience on val loss")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--save", default="model.pt", help="path to save best model; empty to skip")
    return p.parse_args()


if __name__ == "__main__":
    train(parse_args())
