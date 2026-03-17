"""
train_lstm.py
-------------
LSTM Sequence Autoencoder Training Pipeline.

Training strategy:
  - Train ONLY on normal sequences (unsupervised anomaly detection)
  - Model learns to reconstruct normal event patterns
  - Attack sequences produce high reconstruction error at inference

Output:
  models/lstm_anomaly.pt  — saved checkpoint with calibration thresholds

Run from project root:
  python scripts/train_lstm.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset, random_split
from typing import Tuple

from backend.lstm_model import LSTMAutoencoder, PAD_IDX, MODEL_PATH

# ── Hyperparameters ───────────────────────────────────────────────────────────
BATCH_SIZE    = 64
NUM_EPOCHS    = 30
LEARNING_RATE = 1e-3
WEIGHT_DECAY  = 1e-5
VAL_SPLIT     = 0.15
PATIENCE      = 5       # early stopping patience

# Paths
DATA_DIR    = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
MODELS_DIR  = os.path.dirname(MODEL_PATH)


def load_data() -> Tuple[np.ndarray, np.ndarray]:
    """Load normal and attack sequences from disk."""
    normal_path = os.path.join(DATA_DIR, "sequences_normal.npy")
    attack_path = os.path.join(DATA_DIR, "sequences_attack.npy")

    if not os.path.exists(normal_path) or not os.path.exists(attack_path):
        print("Dataset not found! Running generate_dataset.py first...")
        import subprocess
        subprocess.run([sys.executable, "scripts/generate_dataset.py"], check=True)

    normal = np.load(normal_path).astype(np.int64)
    attack = np.load(attack_path).astype(np.int64)
    return normal, attack


def compute_threshold(model: LSTMAutoencoder, data_loader: DataLoader) -> float:
    """Compute mean reconstruction loss on a dataset (for threshold calibration)."""
    model.eval()
    losses = []
    with torch.no_grad():
        for (x,) in data_loader:
            loss = model.reconstruction_loss(x)
            losses.extend(loss.tolist())
    return float(np.mean(losses))


def train():
    print("=" * 60)
    print("LLM-SOC ANALYST  |  LSTM Anomaly Detector Training")
    print("=" * 60)

    os.makedirs(MODELS_DIR, exist_ok=True)

    # ── Load data ─────────────────────────────────────────────────────────────
    normal_seqs, attack_seqs = load_data()
    print(f"Loaded: {len(normal_seqs)} normal, {len(attack_seqs)} attack sequences")

    # ── Prepare tensors ───────────────────────────────────────────────────────
    tensor_normal = torch.tensor(normal_seqs, dtype=torch.long)
    dataset = TensorDataset(tensor_normal)

    val_size   = int(len(dataset) * VAL_SPLIT)
    train_size = len(dataset) - val_size
    train_ds, val_ds = random_split(dataset, [train_size, val_size])

    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True)
    val_loader   = DataLoader(val_ds,   batch_size=BATCH_SIZE, shuffle=False)

    print(f"Train samples: {train_size}  |  Val samples: {val_size}")

    # ── Model ─────────────────────────────────────────────────────────────────
    model = LSTMAutoencoder()
    param_count = sum(p.numel() for p in model.parameters())
    print(f"Model parameters: {param_count:,}")

    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=3, factor=0.5)

    # ── Training loop ─────────────────────────────────────────────────────────
    best_val_loss = float("inf")
    patience_counter = 0
    train_history = []
    val_history   = []

    print(f"\nTraining for up to {NUM_EPOCHS} epochs (early stopping patience={PATIENCE})...")
    print("-" * 60)

    for epoch in range(1, NUM_EPOCHS + 1):
        # Train
        model.train()
        train_losses = []
        for (x,) in train_loader:
            optimizer.zero_grad()
            per_sample_loss = model.reconstruction_loss(x)
            loss = per_sample_loss.mean()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            train_losses.append(loss.item())

        # Validate
        model.eval()
        val_losses = []
        with torch.no_grad():
            for (x,) in val_loader:
                per_sample_loss = model.reconstruction_loss(x)
                val_losses.append(per_sample_loss.mean().item())

        avg_train = np.mean(train_losses)
        avg_val   = np.mean(val_losses)
        train_history.append(avg_train)
        val_history.append(avg_val)

        scheduler.step(avg_val)

        print(f"Epoch {epoch:3d}/{NUM_EPOCHS}  train_loss={avg_train:.4f}  val_loss={avg_val:.4f}", end="")

        # Early stopping
        if avg_val < best_val_loss:
            best_val_loss = avg_val
            patience_counter = 0
            # Save best model (temporary state_dict)
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            print("  ✓ best", end="")
        else:
            patience_counter += 1
            if patience_counter >= PATIENCE:
                print(f"\nEarly stopping at epoch {epoch}")
                break

        print()

    # ── Restore best model ────────────────────────────────────────────────────
    model.load_state_dict(best_state)
    model.eval()

    # ── Calibration thresholds ────────────────────────────────────────────────
    print("\nCalibrating anomaly thresholds...")

    # Normal threshold: 95th percentile of normal validation loss
    model.eval()
    normal_losses = []
    with torch.no_grad():
        normal_full = DataLoader(TensorDataset(tensor_normal), batch_size=BATCH_SIZE)
        for (x,) in normal_full:
            loss = model.reconstruction_loss(x)
            normal_losses.extend(loss.tolist())

    threshold_normal = float(np.percentile(normal_losses, 95))
    print(f"  Normal loss  (95th pct): {threshold_normal:.4f}")

    # Attack threshold: mean loss on attack sequences
    tensor_attack = torch.tensor(attack_seqs, dtype=torch.long)
    attack_loader = DataLoader(TensorDataset(tensor_attack), batch_size=BATCH_SIZE)
    attack_losses = []
    with torch.no_grad():
        for (x,) in attack_loader:
            loss = model.reconstruction_loss(x)
            attack_losses.extend(loss.tolist())

    threshold_attack = float(np.mean(attack_losses))
    print(f"  Attack loss  (mean):     {threshold_attack:.4f}")
    print(f"  Separation factor:       {threshold_attack / max(threshold_normal, 0.001):.2f}x")

    # ── Save checkpoint ───────────────────────────────────────────────────────
    checkpoint = {
        "model_state_dict":   model.state_dict(),
        "threshold_normal":   threshold_normal,
        "threshold_attack":   threshold_attack,
        "train_history":      train_history,
        "val_history":        val_history,
        "best_val_loss":      best_val_loss,
        "hyperparams": {
            "batch_size":    BATCH_SIZE,
            "epochs":        NUM_EPOCHS,
            "learning_rate": LEARNING_RATE,
        },
    }

    torch.save(checkpoint, MODEL_PATH)
    print(f"\nModel saved → {MODEL_PATH}")

    # ── Loss curve (ASCII) ────────────────────────────────────────────────────
    print("\n Training curve (val loss):")
    maxv = max(val_history)
    for i, v in enumerate(val_history):
        bar_len = int((v / maxv) * 40)
        print(f"  Epoch {i+1:3d}: {'█' * bar_len} {v:.4f}")

    print("\nTraining complete!")
    print(f"  Best validation loss : {best_val_loss:.4f}")
    print(f"  Normal threshold     : {threshold_normal:.4f}")
    print(f"  Attack threshold     : {threshold_attack:.4f}")


if __name__ == "__main__":
    train()
