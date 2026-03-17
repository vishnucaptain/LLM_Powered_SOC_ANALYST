"""
generate_dataset.py
-------------------
Generates a synthetic labeled dataset of security event sequences
for training and evaluating the LSTM anomaly detection model.

Normal sequences: routine user activity patterns
Attack sequences: multi-stage APT attack patterns

Output files:
  data/sequences_normal.npy   — (N, seq_len) int array
  data/sequences_attack.npy   — (M, seq_len) int array
  data/labels_normal.npy      — (N,) array of 0s
  data/labels_attack.npy      — (M,) array of 1s

Run from project root:
  python scripts/generate_dataset.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from typing import List

# Event type integer codes (from event_extractor.EVENT_TYPE_MAP)
NORMAL          = 0
LOGIN           = 1
FILE_ACCESS     = 2
OUTBOUND_CONN   = 3
RECON           = 4
PRIV_ESC        = 5
SUSPICIOUS_EXEC = 6
LATERAL_MOVE    = 7
DEFENSE_EVADE   = 8
EXFILTRATION    = 9

MAX_SEQ_LEN = 50
N_NORMAL    = 3000   # number of normal sequences
N_ATTACK    = 1000   # number of attack sequences

np.random.seed(42)


def pad(seq: List[int], length: int = MAX_SEQ_LEN) -> List[int]:
    """Pad or truncate sequence to fixed length."""
    if len(seq) >= length:
        return seq[:length]
    return seq + [NORMAL] * (length - len(seq))


# ── Normal sequence templates ─────────────────────────────────────────────────
def generate_normal_sequence() -> List[int]:
    """
    Simulate legitimate user activity:
    - Morning login, file access, outbound connections throughout the day
    - Occasional sudo for system tasks
    - No privilege escalation chains, no suspicious execution
    """
    pattern = np.random.choice([
        # Office worker: login → file work → web browsing
        "basic_work",
        # Developer: login → file access → build → outbound (package downloads)
        "developer",
        # Admin: login → file access → low-risk commands
        "admin_routine",
    ])

    seq = []

    if pattern == "basic_work":
        seq.append(LOGIN)
        for _ in range(np.random.randint(3, 8)):
            seq.append(FILE_ACCESS)
        for _ in range(np.random.randint(1, 4)):
            seq.append(OUTBOUND_CONN)
        seq.append(FILE_ACCESS)

    elif pattern == "developer":
        seq.append(LOGIN)
        seq.extend([FILE_ACCESS] * np.random.randint(2, 6))
        seq.extend([OUTBOUND_CONN] * np.random.randint(1, 3))
        seq.extend([FILE_ACCESS] * np.random.randint(2, 5))
        seq.append(OUTBOUND_CONN)

    elif pattern == "admin_routine":
        seq.append(LOGIN)
        seq.extend([FILE_ACCESS] * np.random.randint(1, 4))
        seq.extend([OUTBOUND_CONN] * np.random.randint(0, 2))
        seq.extend([FILE_ACCESS] * np.random.randint(1, 3))

    # Add some natural noise (random normal events)
    n_noise = np.random.randint(0, 4)
    for _ in range(n_noise):
        noise_event = np.random.choice([NORMAL, LOGIN, FILE_ACCESS, OUTBOUND_CONN])
        insert_pos = np.random.randint(0, len(seq) + 1)
        seq.insert(insert_pos, int(noise_event))

    # Ensure minimum length
    while len(seq) < 5:
        seq.append(NORMAL)

    return pad(seq)


# ── Attack sequence templates ─────────────────────────────────────────────────
def generate_attack_sequence() -> List[int]:
    """
    Simulate multi-stage attack patterns.
    Each template follows a real-world attack kill chain.
    """
    attack_type = np.random.choice([
        "brute_force_and_escalate",
        "lateral_movement",
        "data_exfiltration",
        "ransomware",
        "apt_full_chain",
        "insider_threat",
    ])

    seq = []

    if attack_type == "brute_force_and_escalate":
        # Initial Access → Credential Access → Privilege Escalation → Execution
        seq.extend([LOGIN] * np.random.randint(4, 10))  # failed logins
        seq.append(LOGIN)                                 # successful login
        seq.append(PRIV_ESC)
        seq.append(SUSPICIOUS_EXEC)
        seq.extend([FILE_ACCESS] * np.random.randint(1, 3))
        seq.append(OUTBOUND_CONN)

    elif attack_type == "lateral_movement":
        # Initial Access → Credential Theft → Lateral Movement → Collection
        seq.append(LOGIN)
        seq.append(SUSPICIOUS_EXEC)   # mimikatz / credential dump
        seq.append(LATERAL_MOVE)
        seq.append(PRIV_ESC)
        seq.append(LATERAL_MOVE)
        seq.extend([FILE_ACCESS] * np.random.randint(2, 5))
        seq.append(OUTBOUND_CONN)

    elif attack_type == "data_exfiltration":
        # C2 Beacon → Collection → Exfiltration
        seq.append(LOGIN)
        seq.extend([FILE_ACCESS] * np.random.randint(3, 7))
        seq.append(OUTBOUND_CONN)  # C2
        seq.extend([FILE_ACCESS] * np.random.randint(2, 4))
        seq.append(EXFILTRATION)
        seq.append(OUTBOUND_CONN)

    elif attack_type == "ransomware":
        # Phishing → Execution → C2 → Defense Evasion → Impact
        seq.append(SUSPICIOUS_EXEC)   # macro/dropper
        seq.append(OUTBOUND_CONN)     # C2 beacon
        seq.append(DEFENSE_EVADE)     # shadow copy delete / AV kill
        seq.extend([FILE_ACCESS] * np.random.randint(5, 12))  # encryption loop
        seq.append(EXFILTRATION)

    elif attack_type == "apt_full_chain":
        # Full APT kill chain
        seq.extend([RECON] * np.random.randint(1, 3))
        seq.extend([LOGIN] * np.random.randint(3, 7))  # brute force
        seq.append(LOGIN)                               # success
        seq.append(PRIV_ESC)
        seq.append(SUSPICIOUS_EXEC)
        seq.append(LATERAL_MOVE)
        seq.append(DEFENSE_EVADE)
        seq.extend([FILE_ACCESS] * np.random.randint(2, 5))
        seq.append(OUTBOUND_CONN)
        seq.append(EXFILTRATION)

    elif attack_type == "insider_threat":
        # Legitimate login → mass file access → exfiltration
        seq.append(LOGIN)
        seq.extend([FILE_ACCESS] * np.random.randint(10, 20))
        seq.append(OUTBOUND_CONN)
        seq.append(EXFILTRATION)

    # Add some decoy normal events to make it realistic
    n_decoy = np.random.randint(0, 3)
    for _ in range(n_decoy):
        decoy = np.random.choice([NORMAL, FILE_ACCESS])
        insert_pos = np.random.randint(0, max(len(seq), 1))
        seq.insert(insert_pos, int(decoy))

    return pad(seq)


def main():
    # ── Output directory ──────────────────────────────────────────────────────
    out_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data"
    )
    os.makedirs(out_dir, exist_ok=True)

    print(f"Generating {N_NORMAL} normal sequences...")
    normal_seqs = np.array([generate_normal_sequence() for _ in range(N_NORMAL)], dtype=np.int32)
    labels_normal = np.zeros(N_NORMAL, dtype=np.int32)

    print(f"Generating {N_ATTACK} attack sequences...")
    attack_seqs = np.array([generate_attack_sequence() for _ in range(N_ATTACK)], dtype=np.int32)
    labels_attack = np.ones(N_ATTACK, dtype=np.int32)

    # ── Save ──────────────────────────────────────────────────────────────────
    np.save(os.path.join(out_dir, "sequences_normal.npy"), normal_seqs)
    np.save(os.path.join(out_dir, "sequences_attack.npy"), attack_seqs)
    np.save(os.path.join(out_dir, "labels_normal.npy"), labels_normal)
    np.save(os.path.join(out_dir, "labels_attack.npy"), labels_attack)

    print(f"\n Dataset saved to {out_dir}/")
    print(f"   sequences_normal.npy : shape {normal_seqs.shape}")
    print(f"   sequences_attack.npy : shape {attack_seqs.shape}")
    print(f"   labels_normal.npy    : shape {labels_normal.shape}")
    print(f"   labels_attack.npy    : shape {labels_attack.shape}")

    # ── Quick stats ───────────────────────────────────────────────────────────
    print("\n Normal sequence stats:")
    print(f"   Unique event codes: {sorted(set(normal_seqs.flatten().tolist()))}")
    print(f"   Mean seq length (non-pad): {np.sum(normal_seqs > 0, axis=1).mean():.1f}")

    print("\n Attack sequence stats:")
    print(f"   Unique event codes: {sorted(set(attack_seqs.flatten().tolist()))}")
    print(f"   Mean seq length (non-pad): {np.sum(attack_seqs > 0, axis=1).mean():.1f}")

    print("\nDataset generation complete.")


if __name__ == "__main__":
    main()
