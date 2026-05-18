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

LABEL_COL = "label"


def load_and_split_dataset(
    csv_list_path: Path, seed: int, val_frac: float = 0.15, test_frac: float = 0.15
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split each CSV individually into train/val/test, then concat the splits.

    Ensures every source (benign + each tunneling tool) is proportionally
    represented in train, val, and test.
    """
    paths = [Path(p) for p in csv_list_path.read_text().splitlines() if p.strip()]
    tr_parts, va_parts, te_parts = [], [], []
    for p in paths:
        df = pd.read_csv(p, usecols=FEATURES_KEEP + [LABEL_COL], low_memory=False)
        df[LABEL_COL] = (df[LABEL_COL].str.lower() == "malicious").astype(np.int64)
        for col in FEATURES_KEEP:
            df[col] = pd.to_numeric(df[col], errors="coerce")
        before = len(df)
        df = df.dropna(subset=FEATURES_KEEP).reset_index(drop=True)

        tr, tmp = train_test_split(df, test_size=val_frac + test_frac, random_state=seed)
        va, te = train_test_split(tmp, test_size=test_frac / (val_frac + test_frac), random_state=seed)
        tr_parts.append(tr)
        va_parts.append(va)
        te_parts.append(te)
        suffix = f" (dropped {before - len(df)} NaN)" if before - len(df) else ""
        print(f"  {p.parent.name}/{p.name}: train={len(tr)} val={len(va)} test={len(te)}{suffix}")

    return (
        pd.concat(tr_parts, ignore_index=True),
        pd.concat(va_parts, ignore_index=True),
        pd.concat(te_parts, ignore_index=True),
    )


def balance_undersample(df: pd.DataFrame, seed: int) -> pd.DataFrame:
    pos = df[df[LABEL_COL] == 1]
    neg = df[df[LABEL_COL] == 0]
    n = min(len(pos), len(neg))
    pos_s = pos.sample(n=n, random_state=seed)
    neg_s = neg.sample(n=n, random_state=seed)
    return pd.concat([pos_s, neg_s]).sample(frac=1.0, random_state=seed).reset_index(drop=True)


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


def pick_device() -> torch.device:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if device.type == "cuda":
        print(f"device: cuda ({torch.cuda.get_device_name(0)})")
    else:
        print("device: cpu")
    return device


def make_loader(x: np.ndarray, y: np.ndarray, batch: int, shuffle: bool, drop_last: bool = False) -> DataLoader:
    ds = TensorDataset(torch.from_numpy(x).float(), torch.from_numpy(y).long())
    return DataLoader(ds, batch_size=batch, shuffle=shuffle, num_workers=0, pin_memory=True, drop_last=drop_last)


@torch.no_grad()
def evaluate(model: nn.Module, loader: DataLoader, device: torch.device) -> dict:
    model.eval()
    logits_all, y_all = [], []
    for xb, yb in loader:
        xb = xb.to(device, non_blocking=True)
        logits_all.append(model(xb).cpu())
        y_all.append(yb)
    logits = torch.cat(logits_all)
    y_true = torch.cat(y_all).numpy().astype(int)
    probs = torch.softmax(logits, dim=1).numpy()
    y_pred = probs.argmax(axis=1)
    return {
        "loss": float(nn.functional.cross_entropy(logits, torch.from_numpy(y_true).long())),
        "acc": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "auc": roc_auc_score(y_true, probs[:, 1]),
    }


def train(args: argparse.Namespace) -> None:
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    print(f"loading dataset list from {args.csv_list}")
    train_df, val_df, test_df = load_and_split_dataset(Path(args.csv_list), seed=args.seed)

    for name, d in (("train", train_df), ("val", val_df), ("test", test_df)):
        print(f"  {name}: {len(d)} (benign={(d[LABEL_COL]==0).sum()} malicious={(d[LABEL_COL]==1).sum()})")

    train_df = balance_undersample(train_df, seed=args.seed)
    val_df = balance_undersample(val_df, seed=args.seed)
    test_df = balance_undersample(test_df, seed=args.seed)
    print(f"after undersample: train={len(train_df)} val={len(val_df)} test={len(test_df)} (50/50 each)")

    x_tr = train_df[FEATURES_KEEP].to_numpy(dtype=np.float32)
    y_tr = train_df[LABEL_COL].to_numpy(dtype=np.int64)
    x_val = val_df[FEATURES_KEEP].to_numpy(dtype=np.float32)
    y_val = val_df[LABEL_COL].to_numpy(dtype=np.int64)
    x_te = test_df[FEATURES_KEEP].to_numpy(dtype=np.float32)
    y_te = test_df[LABEL_COL].to_numpy(dtype=np.int64)

    scaler = StandardScaler().fit(x_tr)
    x_tr = scaler.transform(x_tr).astype(np.float32)
    x_val = scaler.transform(x_val).astype(np.float32)
    x_te = scaler.transform(x_te).astype(np.float32)

    device = pick_device()
    model = MLP(input_dim=len(FEATURES_KEEP), num_classes=2).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-5)
    loss_fn = nn.CrossEntropyLoss()

    tr_loader = make_loader(x_tr, y_tr, args.batch, shuffle=True, drop_last=True)
    val_loader = make_loader(x_val, y_val, args.batch, shuffle=False)
    te_loader = make_loader(x_te, y_te, args.batch, shuffle=False)

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
    p.add_argument("--patience", type=int, default=4, help="early-stopping patience on val loss")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--save", default="model.pt", help="path to save best model; empty to skip")
    return p.parse_args()


if __name__ == "__main__":
    train(parse_args())
