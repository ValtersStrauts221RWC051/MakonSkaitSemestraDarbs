"""Export the trained PyTorch checkpoint to ONNX for demo use.

The exported graph:
  * input  : `features` — float32 tensor of shape [N, 10] (raw, unscaled)
  * output : `prob_malicious` — float32 tensor of shape [N]

Preprocessing (StandardScaler from the checkpoint) and the softmax are baked into
the graph, so the demo does not need any normalization or post-processing logic.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import torch
from torch import nn

from train import MLP, FEATURES_KEEP


class InferenceModel(nn.Module):
    """Wraps the trained MLP with StandardScaler + softmax → P(malicious)."""

    def __init__(self, mlp: nn.Module, mean: np.ndarray, scale: np.ndarray):
        super().__init__()
        self.mlp = mlp
        # Buffers so they travel with the model and end up as ONNX constants
        self.register_buffer("mean", torch.from_numpy(mean.astype(np.float32)))
        self.register_buffer("scale", torch.from_numpy(scale.astype(np.float32)))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = (x - self.mean) / self.scale
        logits = self.mlp(x)
        return torch.softmax(logits, dim=1)[:, 1]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="model.pt", help="trained checkpoint")
    ap.add_argument("--out", default="model.onnx", help="output ONNX path")
    ap.add_argument("--opset", type=int, default=18)
    args = ap.parse_args()

    ckpt = torch.load(args.model, map_location="cpu", weights_only=False)
    features = ckpt.get("features", FEATURES_KEEP)
    if list(features) != FEATURES_KEEP:
        raise ValueError(
            f"checkpoint feature order differs from train.py:\n"
            f"  ckpt: {features}\n  here: {FEATURES_KEEP}"
        )

    mlp = MLP(input_dim=len(features), num_classes=2)
    mlp.load_state_dict(ckpt["model_state"])
    mlp.eval()

    wrapper = InferenceModel(
        mlp,
        mean=np.asarray(ckpt["scaler_mean"], dtype=np.float32),
        scale=np.asarray(ckpt["scaler_scale"], dtype=np.float32),
    )
    wrapper.eval()

    # Dummy input — batch dim is dynamic; feature dim must be 10
    dummy = torch.zeros(1, len(features), dtype=torch.float32)
    out_path = Path(args.out)
    torch.onnx.export(
        wrapper,
        dummy,
        out_path,
        opset_version=args.opset,
        input_names=["features"],
        output_names=["prob_malicious"],
        dynamic_axes={"features": {0: "batch"}, "prob_malicious": {0: "batch"}},
        do_constant_folding=True,
    )
    print(f"wrote {out_path} ({out_path.stat().st_size / 1024:.1f} KB)")

    # Parity check: PyTorch vs ONNX Runtime on random inputs
    import onnx
    import onnxruntime as ort

    onnx.checker.check_model(onnx.load(out_path))
    rng = np.random.default_rng(0)
    sample = rng.normal(size=(16, len(features))).astype(np.float32) * 10 + 5
    with torch.no_grad():
        pt_out = wrapper(torch.from_numpy(sample)).numpy()
    sess = ort.InferenceSession(str(out_path), providers=["CPUExecutionProvider"])
    ort_out = sess.run(["prob_malicious"], {"features": sample})[0]
    max_abs = float(np.abs(pt_out - ort_out).max())
    print(f"parity check: max |pt - ort| = {max_abs:.3e}  (16 random samples)")
    if max_abs > 1e-5:
        raise SystemExit("ONNX output diverges from PyTorch — aborting")

    print(f"feature order (input column meaning):")
    for i, name in enumerate(features):
        print(f"  [{i}] {name}")


if __name__ == "__main__":
    main()
