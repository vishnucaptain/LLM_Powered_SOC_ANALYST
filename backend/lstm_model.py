"""
lstm_model.py
-------------
PyTorch LSTM Sequence Autoencoder for behavioural anomaly detection.

Architecture:
  Embedding (vocab=10 event types, dim=32)
  → LSTM Encoder (hidden=128, layers=2, bidirectional=False)
  → Linear bottleneck (128 → 64)
  → LSTM Decoder (hidden=128, layers=1)
  → Linear output (128 → vocab_size)
  → Cross-entropy reconstruction loss

Anomaly score = mean reconstruction loss, normalised to [0, 1]
via a sigmoid-like mapping calibrated during training.

Training is unsupervised: only normal sequences are used.
At inference, high reconstruction loss → the model did NOT expect
this sequence → anomalous.
"""

import os
import torch
import torch.nn as nn
import numpy as np
from typing import List, Optional, Tuple

# ── Constants ─────────────────────────────────────────────────────────────────
VOCAB_SIZE  = 10      # number of event types (matches EVENT_TYPE_MAP)
EMBED_DIM   = 32
HIDDEN_SIZE = 128
NUM_LAYERS  = 2
MAX_SEQ_LEN = 50
PAD_IDX     = 0       # padding token (same as NORMAL event code)

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models", "lstm_anomaly.pt"
)


# ── Model Definition ──────────────────────────────────────────────────────────

class LSTMAutoencoder(nn.Module):
    """
    LSTM-based sequence autoencoder.
    Encodes an event-type sequence, then decodes it step-by-step.
    Reconstruction error is the anomaly signal.
    """

    def __init__(
        self,
        vocab_size: int = VOCAB_SIZE,
        embed_dim: int  = EMBED_DIM,
        hidden_size: int = HIDDEN_SIZE,
        num_layers: int  = NUM_LAYERS,
    ):
        super().__init__()
        self.vocab_size  = vocab_size
        self.embed_dim   = embed_dim
        self.hidden_size = hidden_size
        self.num_layers  = num_layers

        # Shared embedding layer
        self.embedding = nn.Embedding(
            num_embeddings=vocab_size,
            embedding_dim=embed_dim,
            padding_idx=PAD_IDX,
        )

        # Encoder LSTM
        self.encoder = nn.LSTM(
            input_size=embed_dim,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0.0,
        )

        # Bottleneck: compress encoder output
        self.bottleneck = nn.Linear(hidden_size, hidden_size // 2)
        self.bn_act      = nn.ReLU()
        self.expand      = nn.Linear(hidden_size // 2, hidden_size)

        # Decoder LSTM
        self.decoder = nn.LSTM(
            input_size=embed_dim,
            hidden_size=hidden_size,
            num_layers=1,
            batch_first=True,
        )

        # Project decoder output to vocab logits
        self.output_proj = nn.Linear(hidden_size, vocab_size)

        # Dropout for regularisation
        self.dropout = nn.Dropout(0.1)

    def encode(self, x: torch.Tensor) -> Tuple[torch.Tensor, tuple]:
        """
        Encode a padded sequence of event-type tokens.
        x: (batch, seq_len) int tensor
        Returns: (context_vector, decoder_init_hidden)
        """
        embedded = self.dropout(self.embedding(x))          # (B, L, E)
        _, (hidden, cell) = self.encoder(embedded)          # hidden: (layers, B, H)

        # Use top encoder layer for bottleneck
        top_hidden = hidden[-1]                             # (B, H)
        compressed = self.bn_act(self.bottleneck(top_hidden))  # (B, H/2)
        expanded   = self.expand(compressed)               # (B, H)

        # Initialise decoder with expanded context
        dec_h = expanded.unsqueeze(0)                       # (1, B, H)
        dec_c = torch.zeros_like(dec_h)
        return expanded, (dec_h, dec_c)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Full autoencoder forward pass.
        x: (batch, seq_len) int tensor
        Returns: logits (batch, seq_len, vocab_size)
        """
        _, (dec_h, dec_c) = self.encode(x)

        # Teacher-forced decoding: feed embedded input sequence to decoder
        embedded = self.dropout(self.embedding(x))          # (B, L, E)
        dec_out, _ = self.decoder(embedded, (dec_h, dec_c)) # (B, L, H)
        logits = self.output_proj(dec_out)                  # (B, L, V)
        return logits

    def reconstruction_loss(self, x: torch.Tensor) -> torch.Tensor:
        """
        Compute mean cross-entropy reconstruction loss per sample.
        x: (batch, seq_len) int tensor
        Returns: (batch,) float tensor — per-sample loss
        """
        logits = self.forward(x)                            # (B, L, V)
        B, L, V = logits.shape

        # Flatten for cross-entropy
        logits_flat = logits.reshape(B * L, V)
        targets_flat = x.reshape(B * L)

        loss_fn = nn.CrossEntropyLoss(ignore_index=PAD_IDX, reduction="none")
        per_token_loss = loss_fn(logits_flat, targets_flat)  # (B*L,)
        per_sample_loss = per_token_loss.reshape(B, L).mean(dim=1)  # (B,)
        return per_sample_loss


# ── Inference Utilities ───────────────────────────────────────────────────────

_model: Optional[LSTMAutoencoder] = None
# Calibration thresholds (populated after training or loaded from checkpoint)
_threshold_normal: float = 0.5   # typical loss for normal sequences
_threshold_attack: float = 2.0   # typical loss for attack sequences


def load_model(model_path: str = MODEL_PATH) -> Optional[LSTMAutoencoder]:
    """
    Load LSTM model from disk. Returns None if weights not found
    (system falls back to heuristic scoring).
    """
    global _model, _threshold_normal, _threshold_attack

    if _model is not None:
        return _model

    if not os.path.exists(model_path):
        return None

    checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
    model = LSTMAutoencoder()
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    # Load calibration thresholds if present
    _threshold_normal = checkpoint.get("threshold_normal", 0.5)
    _threshold_attack  = checkpoint.get("threshold_attack", 2.0)

    _model = model
    return _model


def pad_sequence(seq: List[int], max_len: int = MAX_SEQ_LEN) -> List[int]:
    """Pad or truncate sequence to fixed length."""
    if len(seq) >= max_len:
        return seq[:max_len]
    return seq + [PAD_IDX] * (max_len - len(seq))


def score_sequence(sequence: List[int]) -> float:
    """
    Score a single event sequence for anomaly.

    Returns float in [0.0, 1.0]:
      0.0 = completely normal
      1.0 = highly anomalous

    Falls back to a heuristic scoring if model not trained.
    """
    global _model

    if _model is None:
        _model = load_model()

    if _model is None:
        # ── Heuristic fallback ────────────────────────────────────────────
        # Score based on presence of high-risk event codes
        # Event codes: 5=PRIV_ESC, 6=SUSPICIOUS_EXEC, 7=LATERAL_MOVE,
        #              8=DEFENSE_EVADE, 9=EXFILTRATION
        HIGH_RISK_CODES = {5, 6, 7, 8, 9}
        MEDIUM_RISK_CODES = {1, 3}  # LOGIN, OUTBOUND_CONN

        if not sequence:
            return 0.0

        high_count   = sum(1 for c in sequence if c in HIGH_RISK_CODES)
        medium_count = sum(1 for c in sequence if c in MEDIUM_RISK_CODES)
        total = len(sequence)

        # Check for multi-stage attack patterns
        unique_high = len(set(sequence) & HIGH_RISK_CODES)
        chain_bonus = min(unique_high * 0.1, 0.3)  # up to 0.3 bonus for diverse stages

        raw_score = (high_count * 0.3 + medium_count * 0.1) / total + chain_bonus
        return round(min(raw_score, 1.0), 4)

    # ── Neural model scoring ──────────────────────────────────────────────
    padded = pad_sequence(sequence)
    tensor = torch.tensor([padded], dtype=torch.long)  # (1, max_len)

    with torch.no_grad():
        loss = _model.reconstruction_loss(tensor)  # (1,)
        raw_loss = loss.item()

    # Normalise to [0, 1] using calibration range
    span = max(_threshold_attack - _threshold_normal, 0.1)
    normalised = (raw_loss - _threshold_normal) / span
    return round(float(np.clip(normalised, 0.0, 1.0)), 4)
