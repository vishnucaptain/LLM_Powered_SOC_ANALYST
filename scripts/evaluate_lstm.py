"""
evaluate_lstm.py
----------------
Evaluation metrics for the LSTM anomaly detection model.

Metrics computed:
  - ROC-AUC score
  - Optimal threshold (via Youden's J)
  - Precision, Recall, F1 at optimal threshold
  - Confusion matrix
  - Full sklearn classification report

Run from project root:
  python scripts/evaluate_lstm.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import torch
from torch.utils.data import DataLoader, TensorDataset

from backend.models.lstm_model import LSTMAutoencoder, MODEL_PATH


DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def load_all_data():
    """Load normal and attack sequences + labels."""
    normal  = np.load(os.path.join(DATA_DIR, "sequences_normal.npy")).astype(np.int64)
    attack  = np.load(os.path.join(DATA_DIR, "sequences_attack.npy")).astype(np.int64)

    n_labels = np.zeros(len(normal), dtype=np.int32)
    a_labels = np.ones(len(attack),  dtype=np.int32)

    all_seqs   = np.vstack([normal, attack])
    all_labels = np.concatenate([n_labels, a_labels])

    # Shuffle
    idx = np.random.permutation(len(all_seqs))
    return all_seqs[idx], all_labels[idx]


def get_reconstruction_losses(model: LSTMAutoencoder, seqs: np.ndarray) -> np.ndarray:
    """Compute per-sample reconstruction loss for all sequences."""
    model.eval()
    tensor = torch.tensor(seqs, dtype=torch.long)
    loader = DataLoader(TensorDataset(tensor), batch_size=128, shuffle=False)
    losses = []
    with torch.no_grad():
        for (x,) in loader:
            loss = model.reconstruction_loss(x)
            losses.extend(loss.tolist())
    return np.array(losses)


def confusion_matrix_manual(y_true, y_pred):
    """Simple 2x2 confusion matrix without sklearn requirement."""
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    return tp, tn, fp, fn


def roc_auc_manual(y_true, scores):
    """Compute ROC-AUC via trapezoidal rule without sklearn."""
    thresholds = np.sort(np.unique(scores))[::-1]
    tprs = [0.0]
    fprs = [0.0]
    n_pos = np.sum(y_true == 1)
    n_neg = np.sum(y_true == 0)
    for t in thresholds:
        pred = (scores >= t).astype(int)
        tp   = np.sum((pred == 1) & (y_true == 1))
        fp   = np.sum((pred == 1) & (y_true == 0))
        tprs.append(tp / max(n_pos, 1))
        fprs.append(fp / max(n_neg, 1))
    tprs.append(1.0)
    fprs.append(1.0)
    # Trapezoidal AUC
    auc = float(np.trapz(tprs, fprs))
    return abs(auc), np.array(thresholds), np.array(tprs[1:-1]), np.array(fprs[1:-1])


def evaluate():
    print("=" * 60)
    print("LLM-SOC ANALYST  |  LSTM Anomaly Detector Evaluation")
    print("=" * 60)

    # ── Load model ────────────────────────────────────────────────────────────
    if not os.path.exists(MODEL_PATH):
        print(f"Model not found at {MODEL_PATH}")
        print("Run 'python scripts/train_lstm.py' first.")
        sys.exit(1)

    checkpoint = torch.load(MODEL_PATH, map_location="cpu", weights_only=False)
    model = LSTMAutoencoder()
    model.load_state_dict(checkpoint["model_state_dict"])
    threshold_normal = checkpoint.get("threshold_normal", 0.5)
    threshold_attack = checkpoint.get("threshold_attack", 2.0)

    print(f"Loaded model from {MODEL_PATH}")
    print(f"  Threshold (normal): {threshold_normal:.4f}")
    print(f"  Threshold (attack): {threshold_attack:.4f}\n")

    # ── Load data ─────────────────────────────────────────────────────────────
    np.random.seed(99)
    seqs, labels = load_all_data()
    print(f"Evaluation dataset: {len(seqs)} samples  "
          f"({np.sum(labels==0)} normal, {np.sum(labels==1)} attack)\n")

    # ── Get scores ────────────────────────────────────────────────────────────
    print("Computing reconstruction losses...")
    losses = get_reconstruction_losses(model, seqs)

    # ── ROC-AUC ───────────────────────────────────────────────────────────────
    auc, thresholds, tprs, fprs = roc_auc_manual(labels, losses)
    print(f"ROC-AUC Score: {auc:.4f}")

    # ── Optimal threshold (Youden's J = TPR - FPR) ───────────────────────────
    youdens_j = tprs - fprs
    opt_idx   = np.argmax(youdens_j)
    opt_threshold = thresholds[opt_idx] if len(thresholds) > opt_idx else threshold_normal
    print(f"Optimal threshold (Youden's J): {opt_threshold:.4f}")

    # Also try the calibrated threshold
    calib_threshold = (threshold_normal + threshold_attack) / 2
    print(f"Calibrated threshold (midpoint): {calib_threshold:.4f}\n")

    # ── Metrics at optimal threshold ──────────────────────────────────────────
    for thresh_name, thresh in [
        ("Youden Optimal", opt_threshold),
        ("Calibrated",     calib_threshold),
    ]:
        preds = (losses >= thresh).astype(int)
        tp, tn, fp, fn = confusion_matrix_manual(labels, preds)

        precision = tp / max(tp + fp, 1)
        recall    = tp / max(tp + fn, 1)
        f1        = 2 * precision * recall / max(precision + recall, 1e-8)
        accuracy  = (tp + tn) / max(len(labels), 1)
        fpr       = fp / max(fp + tn, 1)

        print(f"─── Metrics at {thresh_name} threshold ({thresh:.4f}) ───")
        print(f"  Accuracy  : {accuracy:.4f}  ({accuracy*100:.1f}%)")
        print(f"  Precision : {precision:.4f}")
        print(f"  Recall    : {recall:.4f}")
        print(f"  F1 Score  : {f1:.4f}")
        print(f"  FPR       : {fpr:.4f}")
        print(f"  Confusion Matrix:")
        print(f"    TP={tp}  FP={fp}")
        print(f"    FN={fn}  TN={tn}")
        print()

    # ── Loss distribution ─────────────────────────────────────────────────────
    normal_losses = losses[labels == 0]
    attack_losses = losses[labels == 1]

    print("─── Loss Distribution ───")
    print(f"  Normal  — mean: {normal_losses.mean():.4f}  std: {normal_losses.std():.4f}  "
          f"p95: {np.percentile(normal_losses, 95):.4f}")
    print(f"  Attack  — mean: {attack_losses.mean():.4f}  std: {attack_losses.std():.4f}  "
          f"p05: {np.percentile(attack_losses, 5):.4f}")
    print(f"  Separation: {attack_losses.mean() - normal_losses.mean():.4f}")

    # ── ASCII density chart ───────────────────────────────────────────────────
    print("\n─── Loss Histogram (≈ Normal vs Attack) ───")
    all_min = min(losses.min(), 0)
    all_max = losses.max()
    bins = np.linspace(all_min, all_max, 16)
    n_hist, _  = np.histogram(normal_losses, bins=bins)
    a_hist, _  = np.histogram(attack_losses, bins=bins)
    max_h = max(n_hist.max(), a_hist.max(), 1)
    bar_width = 20

    print(f"  {'Bin':>8}  {'Normal':^{bar_width}}  {'Attack':^{bar_width}}")
    for i in range(len(bins) - 1):
        n_bar = int(n_hist[i] / max_h * bar_width)
        a_bar = int(a_hist[i] / max_h * bar_width)
        print(f"  {bins[i]:>8.3f}: {'N'*n_bar:<{bar_width}}  {'A'*a_bar:<{bar_width}}")

    print("\nEvaluation complete!")


if __name__ == "__main__":
    evaluate()
