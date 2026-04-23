"""
generate_results.py
-------------------
Master evaluation & results-generation script for the LLM-Powered SOC Analyst.

Produces all artifacts needed for an IEEE research paper and PowerPoint presentation:
  1. LSTM anomaly-detection metrics  (Accuracy, Precision, Recall, F1, FPR)
  2. Confusion matrix heatmap         → results/confusion_matrix.png
  3. Metrics bar chart                → results/metrics_bar_chart.png
  4. ROC curve                        → results/roc_curve.png
  5. Loss distribution histogram      → results/loss_distribution.png
  6. RAG retrieval evaluation          → results/rag_evaluation.json
  7. Classification report (text)     → results/classification_report.txt
  8. Metrics CSV                      → results/metrics.csv
  9. Full results JSON                → results/results.json

Run from project root:
    python scripts/generate_results.py
"""

import sys
import os
import json
import csv
import time

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import numpy as np

# ── Optional imports (graceful degradation) ──────────────────────────────────
try:
    import matplotlib
    matplotlib.use("Agg")  # non-interactive backend — works on headless servers
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("[WARN] matplotlib not installed — plots will be skipped.")

try:
    import seaborn as sns
    HAS_SNS = True
except ImportError:
    HAS_SNS = False
    print("[WARN] seaborn not installed — heatmap will use matplotlib fallback.")

try:
    import torch
    from torch.utils.data import DataLoader, TensorDataset
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    print("[WARN] PyTorch not installed — using heuristic scorer.")

# ── Local project imports ────────────────────────────────────────────────────
from backend.models.lstm_model import (
    LSTMAutoencoder, MODEL_PATH, TORCH_AVAILABLE, score_sequence,
)

# ── Paths ────────────────────────────────────────────────────────────────────
DATA_DIR    = os.path.join(PROJECT_ROOT, "data")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

# ── Colour palette (professional, paper-friendly) ───────────────────────────
PALETTE = {
    "primary":    "#2563EB",  # blue-600
    "secondary":  "#7C3AED",  # violet-600
    "success":    "#059669",  # emerald-600
    "danger":     "#DC2626",  # red-600
    "warning":    "#D97706",  # amber-600
    "bg_dark":    "#1E293B",  # slate-800
    "bg_light":   "#F8FAFC",  # slate-50
    "text":       "#0F172A",  # slate-900
    "grid":       "#E2E8F0",  # slate-200
}


# ═══════════════════════════════════════════════════════════════════════════════
# 1.  DATA LOADING
# ═══════════════════════════════════════════════════════════════════════════════

def load_dataset():
    """Load normal + attack sequences and construct a labelled dataset."""
    normal_path = os.path.join(DATA_DIR, "sequences_normal.npy")
    attack_path = os.path.join(DATA_DIR, "sequences_attack.npy")

    if not os.path.exists(normal_path) or not os.path.exists(attack_path):
        print("[!] Dataset not found. Generating synthetic data first ...")
        import subprocess
        subprocess.run([sys.executable, os.path.join(PROJECT_ROOT, "scripts", "generate_dataset.py")], check=True)

    normal = np.load(normal_path).astype(np.int64)
    attack = np.load(attack_path).astype(np.int64)

    # Labels: 0 = normal, 1 = attack
    y_true = np.concatenate([
        np.zeros(len(normal), dtype=np.int32),
        np.ones(len(attack),  dtype=np.int32),
    ])
    sequences = np.vstack([normal, attack])

    # Deterministic shuffle
    rng = np.random.RandomState(42)
    idx = rng.permutation(len(sequences))
    return sequences[idx], y_true[idx]


# ═══════════════════════════════════════════════════════════════════════════════
# 2.  ANOMALY SCORING
# ═══════════════════════════════════════════════════════════════════════════════

def get_anomaly_scores(sequences: np.ndarray) -> np.ndarray:
    """
    Score every sequence for anomaly using the LSTM autoencoder.
    Returns raw reconstruction losses (higher = more anomalous).
    Falls back to heuristic scorer if model is unavailable.
    """
    if TORCH_AVAILABLE and os.path.exists(MODEL_PATH):
        print("  Using trained LSTM autoencoder for scoring ...")
        checkpoint = torch.load(MODEL_PATH, map_location="cpu", weights_only=False)
        model = LSTMAutoencoder()
        model.load_state_dict(checkpoint["model_state_dict"])
        model.eval()

        tensor = torch.tensor(sequences, dtype=torch.long)
        loader = DataLoader(TensorDataset(tensor), batch_size=128, shuffle=False)
        losses = []
        with torch.no_grad():
            for (x,) in loader:
                loss = model.reconstruction_loss(x)
                losses.extend(loss.tolist())
        return np.array(losses)
    else:
        print("  LSTM model not available — using heuristic scorer ...")
        return np.array([score_sequence(seq.tolist()) for seq in sequences])


# ═══════════════════════════════════════════════════════════════════════════════
# 3.  METRICS COMPUTATION
# ═══════════════════════════════════════════════════════════════════════════════

def compute_confusion(y_true, y_pred):
    """Return TP, TN, FP, FN."""
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    return tp, tn, fp, fn


def compute_metrics(y_true, y_pred):
    """Compute all classification metrics from binary predictions."""
    tp, tn, fp, fn = compute_confusion(y_true, y_pred)
    total = tp + tn + fp + fn

    accuracy  = (tp + tn) / max(total, 1)
    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * precision * recall / max(precision + recall, 1e-8)
    fpr       = fp / max(fp + tn, 1)
    specificity = tn / max(tn + fp, 1)

    return {
        "accuracy":     round(accuracy, 4),
        "precision":    round(precision, 4),
        "recall":       round(recall, 4),
        "f1_score":     round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "specificity":  round(specificity, 4),
        "true_positives":  tp,
        "true_negatives":  tn,
        "false_positives": fp,
        "false_negatives": fn,
        "total_samples":   total,
    }


def compute_roc(y_true, scores):
    """Compute ROC curve data and AUC."""
    thresholds = np.sort(np.unique(scores))[::-1]
    n_pos = max(np.sum(y_true == 1), 1)
    n_neg = max(np.sum(y_true == 0), 1)

    tprs = [0.0]
    fprs = [0.0]

    for t in thresholds:
        pred = (scores >= t).astype(int)
        tp = np.sum((pred == 1) & (y_true == 1))
        fp = np.sum((pred == 1) & (y_true == 0))
        tprs.append(tp / n_pos)
        fprs.append(fp / n_neg)

    tprs.append(1.0)
    fprs.append(1.0)

    # Trapezoidal AUC (np.trapz removed in NumPy 2.x → use np.trapezoid)
    _trapz = getattr(np, "trapezoid", getattr(np, "trapz", None))
    auc = abs(float(_trapz(tprs, fprs)))

    # Optimal threshold (Youden's J = TPR − FPR)
    j_scores = np.array(tprs[1:-1]) - np.array(fprs[1:-1])
    opt_idx = np.argmax(j_scores) if len(j_scores) > 0 else 0
    opt_threshold = float(thresholds[opt_idx]) if len(thresholds) > opt_idx else 0.5

    return {
        "tprs": tprs,
        "fprs": fprs,
        "thresholds": thresholds.tolist(),
        "auc": round(auc, 4),
        "optimal_threshold": round(opt_threshold, 4),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 4.  RAG RETRIEVAL EVALUATION
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_rag(k_values=(1, 3, 5)):
    """
    Evaluate RAG retrieval quality using known MITRE ATT&CK queries.
    Measures Top-K accuracy and hit rate for known technique queries.
    """
    from backend.rag.rag_engine import retrieve_context

    # Ground-truth: queries where we know the expected technique IDs
    test_queries = [
        {"query": "T1110 Brute Force password spraying credential stuffing",
         "expected_ids": ["T1110"]},
        {"query": "T1059 PowerShell Command and Scripting Interpreter malicious script",
         "expected_ids": ["T1059"]},
        {"query": "T1021 Remote Services lateral movement SMB PsExec",
         "expected_ids": ["T1021"]},
        {"query": "T1486 Data Encrypted for Impact ransomware file encryption",
         "expected_ids": ["T1486"]},
        {"query": "T1041 Exfiltration Over C2 Channel data theft",
         "expected_ids": ["T1041"]},
        {"query": "T1547 Boot or Logon Autostart Execution persistence registry",
         "expected_ids": ["T1547"]},
        {"query": "T1566 Phishing spearphishing macro attachment",
         "expected_ids": ["T1566"]},
        {"query": "T1078 Valid Accounts default credential abuse",
         "expected_ids": ["T1078"]},
        {"query": "T1562 Impair Defenses disable security tools",
         "expected_ids": ["T1562"]},
        {"query": "T1071 Application Layer Protocol C2 beacon HTTPS",
         "expected_ids": ["T1071"]},
    ]

    results = {}

    for k in k_values:
        hits = 0
        total = len(test_queries)

        for tq in test_queries:
            context = retrieve_context(tq["query"], k=k)
            # Check if any expected technique ID appears in the retrieved context
            found = any(tid in context for tid in tq["expected_ids"])
            if found:
                hits += 1

        hit_rate = round(hits / max(total, 1), 4)
        results[f"top_{k}"] = {
            "hits": hits,
            "total": total,
            "hit_rate": hit_rate,
        }

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# 5.  VISUALISATION
# ═══════════════════════════════════════════════════════════════════════════════

def _apply_style(fig, ax):
    """Apply a consistent, publication-quality style to all plots."""
    ax.set_facecolor(PALETTE["bg_light"])
    fig.patch.set_facecolor("white")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(PALETTE["grid"])
    ax.spines["bottom"].set_color(PALETTE["grid"])
    ax.tick_params(colors=PALETTE["text"], labelsize=11)
    ax.grid(axis="y", color=PALETTE["grid"], linewidth=0.5, alpha=0.7)


def plot_confusion_matrix(y_true, y_pred):
    """Generate and save confusion matrix heatmap."""
    if not HAS_MPL:
        return

    tp, tn, fp, fn = compute_confusion(y_true, y_pred)
    cm = np.array([[tn, fp], [fn, tp]])
    labels = ["Normal\n(Benign)", "Attack\n(Anomalous)"]

    fig, ax = plt.subplots(figsize=(7, 6))

    if HAS_SNS:
        sns.heatmap(
            cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=labels, yticklabels=labels,
            linewidths=2, linecolor="white",
            annot_kws={"size": 18, "weight": "bold"},
            cbar_kws={"label": "Count"},
            ax=ax,
        )
    else:
        im = ax.imshow(cm, cmap="Blues", interpolation="nearest")
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                        fontsize=18, fontweight="bold",
                        color="white" if cm[i, j] > cm.max() / 2 else PALETTE["text"])
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(labels)
        ax.set_yticklabels(labels)
        fig.colorbar(im, ax=ax, label="Count")

    ax.set_xlabel("Predicted Label", fontsize=13, fontweight="bold", color=PALETTE["text"])
    ax.set_ylabel("True Label", fontsize=13, fontweight="bold", color=PALETTE["text"])
    ax.set_title("Confusion Matrix — LSTM Anomaly Detector",
                 fontsize=15, fontweight="bold", color=PALETTE["text"], pad=16)
    fig.patch.set_facecolor("white")

    path = os.path.join(RESULTS_DIR, "confusion_matrix.png")
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  ✓ Confusion matrix  → {path}")


def plot_metrics_bar(metrics: dict):
    """Generate and save a bar chart of main classification metrics."""
    if not HAS_MPL:
        return

    metric_names  = ["Accuracy", "Precision", "Recall", "F1 Score"]
    metric_values = [metrics["accuracy"], metrics["precision"],
                     metrics["recall"], metrics["f1_score"]]
    colors = [PALETTE["primary"], PALETTE["secondary"],
              PALETTE["success"], PALETTE["warning"]]

    fig, ax = plt.subplots(figsize=(8, 5))
    _apply_style(fig, ax)

    bars = ax.bar(metric_names, metric_values, color=colors, width=0.55,
                  edgecolor="white", linewidth=1.5, zorder=3)

    # Value labels on bars
    for bar, val in zip(bars, metric_values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.015,
                f"{val:.3f}", ha="center", va="bottom",
                fontsize=13, fontweight="bold", color=PALETTE["text"])

    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Score", fontsize=13, fontweight="bold", color=PALETTE["text"])
    ax.set_title("Classification Metrics — LSTM Anomaly Detector",
                 fontsize=15, fontweight="bold", color=PALETTE["text"], pad=16)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1, decimals=0))

    path = os.path.join(RESULTS_DIR, "metrics_bar_chart.png")
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  ✓ Metrics bar chart → {path}")


def plot_roc_curve(roc_data: dict):
    """Generate and save the ROC curve."""
    if not HAS_MPL:
        return

    fig, ax = plt.subplots(figsize=(7, 6))
    _apply_style(fig, ax)

    ax.plot(roc_data["fprs"], roc_data["tprs"],
            color=PALETTE["primary"], linewidth=2.5, zorder=3,
            label=f'LSTM Autoencoder (AUC = {roc_data["auc"]:.4f})')
    ax.plot([0, 1], [0, 1], "--", color=PALETTE["grid"], linewidth=1.5,
            label="Random classifier", zorder=2)
    ax.fill_between(roc_data["fprs"], roc_data["tprs"],
                    alpha=0.12, color=PALETTE["primary"], zorder=1)

    ax.set_xlabel("False Positive Rate", fontsize=13, fontweight="bold", color=PALETTE["text"])
    ax.set_ylabel("True Positive Rate", fontsize=13, fontweight="bold", color=PALETTE["text"])
    ax.set_title("ROC Curve — LSTM Anomaly Detector",
                 fontsize=15, fontweight="bold", color=PALETTE["text"], pad=16)
    ax.legend(loc="lower right", fontsize=11, framealpha=0.9)

    path = os.path.join(RESULTS_DIR, "roc_curve.png")
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  ✓ ROC curve         → {path}")


def plot_loss_distribution(scores, y_true):
    """Generate and save the loss distribution histogram for normal vs attack."""
    if not HAS_MPL:
        return

    normal_scores = scores[y_true == 0]
    attack_scores = scores[y_true == 1]

    fig, ax = plt.subplots(figsize=(8, 5))
    _apply_style(fig, ax)

    ax.hist(normal_scores, bins=50, alpha=0.65, color=PALETTE["primary"],
            label=f"Normal (n={len(normal_scores)})", edgecolor="white", linewidth=0.5, zorder=3)
    ax.hist(attack_scores, bins=50, alpha=0.65, color=PALETTE["danger"],
            label=f"Attack (n={len(attack_scores)})", edgecolor="white", linewidth=0.5, zorder=3)

    ax.axvline(x=np.mean(normal_scores), color=PALETTE["primary"], linestyle="--",
               linewidth=1.5, alpha=0.8, label=f"Normal μ = {np.mean(normal_scores):.3f}")
    ax.axvline(x=np.mean(attack_scores), color=PALETTE["danger"], linestyle="--",
               linewidth=1.5, alpha=0.8, label=f"Attack μ = {np.mean(attack_scores):.3f}")

    ax.set_xlabel("Reconstruction Loss / Anomaly Score", fontsize=13,
                  fontweight="bold", color=PALETTE["text"])
    ax.set_ylabel("Frequency", fontsize=13, fontweight="bold", color=PALETTE["text"])
    ax.set_title("Loss Distribution — Normal vs Attack Sequences",
                 fontsize=15, fontweight="bold", color=PALETTE["text"], pad=16)
    ax.legend(fontsize=10, framealpha=0.9)

    path = os.path.join(RESULTS_DIR, "loss_distribution.png")
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  ✓ Loss distribution → {path}")


def plot_rag_evaluation(rag_results: dict):
    """Generate and save RAG top-k hit rate bar chart."""
    if not HAS_MPL or not rag_results:
        return

    k_labels = [f"Top-{k.split('_')[1]}" for k in rag_results.keys()]
    hit_rates = [v["hit_rate"] for v in rag_results.values()]

    fig, ax = plt.subplots(figsize=(6, 4.5))
    _apply_style(fig, ax)

    bars = ax.bar(k_labels, hit_rates, color=[PALETTE["primary"], PALETTE["secondary"], PALETTE["success"]],
                  width=0.45, edgecolor="white", linewidth=1.5, zorder=3)

    for bar, val in zip(bars, hit_rates):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                f"{val:.0%}", ha="center", va="bottom",
                fontsize=13, fontweight="bold", color=PALETTE["text"])

    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Hit Rate", fontsize=13, fontweight="bold", color=PALETTE["text"])
    ax.set_title("RAG Retrieval — Top-K Hit Rate (MITRE ATT&CK)",
                 fontsize=14, fontweight="bold", color=PALETTE["text"], pad=16)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1, decimals=0))

    path = os.path.join(RESULTS_DIR, "rag_topk_accuracy.png")
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  ✓ RAG Top-K chart   → {path}")


# ═══════════════════════════════════════════════════════════════════════════════
# 6.  EXPORT  (CSV + JSON + Classification Report)
# ═══════════════════════════════════════════════════════════════════════════════

def export_csv(metrics: dict, roc_data: dict):
    """Save metrics to CSV for use in LaTeX tables / Excel slides."""
    path = os.path.join(RESULTS_DIR, "metrics.csv")
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Accuracy",             metrics["accuracy"]])
        writer.writerow(["Precision",            metrics["precision"]])
        writer.writerow(["Recall",               metrics["recall"]])
        writer.writerow(["F1 Score",             metrics["f1_score"]])
        writer.writerow(["False Positive Rate",  metrics["false_positive_rate"]])
        writer.writerow(["Specificity",          metrics["specificity"]])
        writer.writerow(["ROC-AUC",              roc_data["auc"]])
        writer.writerow(["Optimal Threshold",    roc_data["optimal_threshold"]])
        writer.writerow(["True Positives",       metrics["true_positives"]])
        writer.writerow(["True Negatives",       metrics["true_negatives"]])
        writer.writerow(["False Positives",      metrics["false_positives"]])
        writer.writerow(["False Negatives",      metrics["false_negatives"]])
        writer.writerow(["Total Samples",        metrics["total_samples"]])
    print(f"  ✓ Metrics CSV       → {path}")


def export_json(metrics: dict, roc_data: dict, rag_results: dict,
                loss_stats: dict, elapsed: float):
    """Save complete results to JSON."""
    path = os.path.join(RESULTS_DIR, "results.json")
    output = {
        "system": "LLM-Powered SOC Analyst",
        "model": "LSTM Sequence Autoencoder",
        "dataset": {
            "normal_samples":  metrics["true_negatives"] + metrics["false_positives"],
            "attack_samples":  metrics["true_positives"] + metrics["false_negatives"],
            "total_samples":   metrics["total_samples"],
        },
        "classification_metrics": {
            "accuracy":           metrics["accuracy"],
            "precision":          metrics["precision"],
            "recall":             metrics["recall"],
            "f1_score":           metrics["f1_score"],
            "false_positive_rate": metrics["false_positive_rate"],
            "specificity":        metrics["specificity"],
        },
        "roc_auc":              roc_data["auc"],
        "optimal_threshold":    roc_data["optimal_threshold"],
        "confusion_matrix": {
            "TP": metrics["true_positives"],
            "TN": metrics["true_negatives"],
            "FP": metrics["false_positives"],
            "FN": metrics["false_negatives"],
        },
        "loss_distribution": loss_stats,
        "rag_evaluation": rag_results,
        "evaluation_time_seconds": round(elapsed, 2),
    }
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"  ✓ Results JSON      → {path}")


def export_classification_report(metrics: dict, roc_data: dict, loss_stats: dict):
    """Save a human-readable classification report."""
    path = os.path.join(RESULTS_DIR, "classification_report.txt")
    report = f"""\
╔════════════════════════════════════════════════════════════════════╗
║       LLM-POWERED SOC ANALYST — CLASSIFICATION REPORT            ║
╚════════════════════════════════════════════════════════════════════╝

Model         : LSTM Sequence Autoencoder (Unsupervised)
Dataset       : {metrics['total_samples']} samples (Normal + Attack sequences)
ROC-AUC       : {roc_data['auc']:.4f}
Opt. Threshold: {roc_data['optimal_threshold']:.4f}

─── Classification Metrics ────────────────────────────────────────
  Accuracy          : {metrics['accuracy']:.4f}   ({metrics['accuracy']*100:.1f}%)
  Precision         : {metrics['precision']:.4f}
  Recall (TPR)      : {metrics['recall']:.4f}
  F1 Score          : {metrics['f1_score']:.4f}
  False Pos. Rate   : {metrics['false_positive_rate']:.4f}
  Specificity (TNR) : {metrics['specificity']:.4f}

─── Confusion Matrix ──────────────────────────────────────────────
                    Predicted Normal   Predicted Attack
  Actual Normal     TN = {metrics['true_negatives']:<14d} FP = {metrics['false_positives']}
  Actual Attack     FN = {metrics['false_negatives']:<14d} TP = {metrics['true_positives']}

─── Loss Distribution ─────────────────────────────────────────────
  Normal μ  : {loss_stats['normal_mean']:.4f}  (σ = {loss_stats['normal_std']:.4f})
  Attack μ  : {loss_stats['attack_mean']:.4f}  (σ = {loss_stats['attack_std']:.4f})
  Separation: {loss_stats['separation']:.4f}

═════════════════════════════════════════════════════════════════════
"""
    with open(path, "w") as f:
        f.write(report)
    print(f"  ✓ Report text       → {path}")


# ═══════════════════════════════════════════════════════════════════════════════
# 7.  MAIN  —  Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    start_time = time.time()

    print("=" * 64)
    print("  LLM-POWERED SOC ANALYST — RESULTS GENERATION")
    print("=" * 64)

    # ── 1. Load dataset ──────────────────────────────────────────────────────
    print("\n[1/7] Loading dataset ...")
    sequences, y_true = load_dataset()
    n_normal = int(np.sum(y_true == 0))
    n_attack = int(np.sum(y_true == 1))
    print(f"  Dataset: {len(sequences)} samples ({n_normal} normal, {n_attack} attack)")

    # ── 2. Score sequences ───────────────────────────────────────────────────
    print("\n[2/7] Computing anomaly scores ...")
    scores = get_anomaly_scores(sequences)

    # Loss distribution stats
    normal_scores = scores[y_true == 0]
    attack_scores = scores[y_true == 1]
    loss_stats = {
        "normal_mean": round(float(np.mean(normal_scores)), 4),
        "normal_std":  round(float(np.std(normal_scores)), 4),
        "attack_mean": round(float(np.mean(attack_scores)), 4),
        "attack_std":  round(float(np.std(attack_scores)), 4),
        "separation":  round(float(np.mean(attack_scores) - np.mean(normal_scores)), 4),
    }
    print(f"  Normal loss μ={loss_stats['normal_mean']:.4f} σ={loss_stats['normal_std']:.4f}")
    print(f"  Attack loss μ={loss_stats['attack_mean']:.4f} σ={loss_stats['attack_std']:.4f}")

    # ── 3. ROC analysis ──────────────────────────────────────────────────────
    print("\n[3/7] Computing ROC curve and optimal threshold ...")
    roc_data = compute_roc(y_true, scores)
    threshold = roc_data["optimal_threshold"]
    print(f"  ROC-AUC             = {roc_data['auc']:.4f}")
    print(f"  Optimal threshold   = {threshold:.4f}")

    # ── 4. Binary predictions at optimal threshold ───────────────────────────
    y_pred = (scores >= threshold).astype(int)
    metrics = compute_metrics(y_true, y_pred)

    print("\n[4/7] Classification metrics (at optimal threshold) ...")
    print(f"  Accuracy            = {metrics['accuracy']:.4f}")
    print(f"  Precision           = {metrics['precision']:.4f}")
    print(f"  Recall              = {metrics['recall']:.4f}")
    print(f"  F1 Score            = {metrics['f1_score']:.4f}")
    print(f"  False Positive Rate = {metrics['false_positive_rate']:.4f}")

    # ── 5. RAG evaluation ────────────────────────────────────────────────────
    print("\n[5/7] Evaluating RAG retrieval quality ...")
    try:
        rag_results = evaluate_rag(k_values=(1, 3, 5))
        for k_name, v in rag_results.items():
            print(f"  {k_name}: {v['hits']}/{v['total']} hits  (hit rate = {v['hit_rate']:.0%})")
    except Exception as e:
        print(f"  [WARN] RAG evaluation skipped: {e}")
        rag_results = {}

    # ── 6. Generate plots ────────────────────────────────────────────────────
    print("\n[6/7] Generating visualisations ...")
    plot_confusion_matrix(y_true, y_pred)
    plot_metrics_bar(metrics)
    plot_roc_curve(roc_data)
    plot_loss_distribution(scores, y_true)
    plot_rag_evaluation(rag_results)

    # ── 7. Export results ────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    print("\n[7/7] Exporting results ...")
    export_csv(metrics, roc_data)
    export_json(metrics, roc_data, rag_results, loss_stats, elapsed)
    export_classification_report(metrics, roc_data, loss_stats)

    # ── Final summary ────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    print("\n" + "=" * 64)
    print(f"  ALL RESULTS SAVED TO: {RESULTS_DIR}/")
    print(f"  Total time: {elapsed:.1f}s")
    print("=" * 64)

    # List all generated files
    print("\n  Generated files:")
    for fname in sorted(os.listdir(RESULTS_DIR)):
        fpath = os.path.join(RESULTS_DIR, fname)
        size = os.path.getsize(fpath)
        if size > 1024:
            print(f"    {fname:<35s} {size/1024:.1f} KB")
        else:
            print(f"    {fname:<35s} {size} B")

    print()


if __name__ == "__main__":
    main()
