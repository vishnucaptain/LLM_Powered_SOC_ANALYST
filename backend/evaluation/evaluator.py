"""
evaluator.py
------------
Evaluation module for SOC Analyst incident-detection pipeline.

Provides:
  - Labelled test dataset (10 samples: 6 attacks, 4 benign)
  - IncidentEvaluator class with full confusion-matrix metrics
  - run_evaluation() convenience function callable from CLI or API

Usage:
    from backend.evaluation.evaluator import run_evaluation
    metrics = run_evaluation()               # uses mock detector
    metrics = run_evaluation(my_detector)    # uses real pipeline function
"""

import logging
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


# ── Labelled test dataset ──────────────────────────────────────────────────────

TEST_DATASET: List[Dict[str, Any]] = [
    {
        "id": "test_001",
        "description": "SSH brute-force → privilege escalation",
        "logs": (
            "2024-01-15 03:22:11 Failed password for admin from 185.220.101.5 port 54231 ssh2\n"
            "2024-01-15 03:22:14 Failed password for admin from 185.220.101.5 port 54234 ssh2\n"
            "2024-01-15 03:22:17 Failed password for root from 185.220.101.5 port 54237 ssh2\n"
            "2024-01-15 03:22:20 Accepted password for admin from 185.220.101.5 port 54251 ssh2\n"
            "2024-01-15 03:22:31 sudo: admin : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"
        ),
        "is_attack": True,
        "expected_techniques": ["T1110"],
        "expected_severity": "HIGH",
    },
    {
        "id": "test_002",
        "description": "PsExec lateral movement",
        "logs": (
            "2024-01-15 09:14:03 User jsmith authenticated to WORKSTATION-01 via NTLM\n"
            "2024-01-15 09:14:45 PsExec executed on FILESERVER-02 from WORKSTATION-01 by jsmith\n"
            "2024-01-15 09:15:12 Net use \\\\FILESERVER-02\\ADMIN$ established\n"
            "2024-01-15 09:15:20 cmd.exe launched as SYSTEM on FILESERVER-02 remotely"
        ),
        "is_attack": True,
        "expected_techniques": ["T1021"],
        "expected_severity": "HIGH",
    },
    {
        "id": "test_003",
        "description": "DNS-tunnelled data exfiltration",
        "logs": (
            "2024-01-15 14:30:01 Large file transfer initiated from 192.168.1.105 to 45.33.32.156\n"
            "2024-01-15 14:30:15 DNS query storm: 192.168.1.105 querying suspicious.exfil-domain.ru\n"
            "2024-01-15 14:31:00 Outbound traffic spike: 2.4 GB via port 443 in 60 seconds\n"
            "2024-01-15 14:32:45 Encrypted archive uploaded via HTTPS to cloud storage"
        ),
        "is_attack": True,
        "expected_techniques": ["T1041"],
        "expected_severity": "CRITICAL",
    },
    {
        "id": "test_004",
        "description": "Normal user session (benign)",
        "logs": (
            "2024-01-15 10:30:00 User jsmith logged in from 192.168.1.50\n"
            "2024-01-15 10:35:15 jsmith accessed file: /home/jsmith/projects/report.xlsx\n"
            "2024-01-15 10:40:22 jsmith executed: ls -la /home/jsmith/documents\n"
            "2024-01-15 11:00:45 jsmith disconnected"
        ),
        "is_attack": False,
        "expected_techniques": [],
        "expected_severity": "LOW",
    },
    {
        "id": "test_005",
        "description": "Scheduled database backup (benign)",
        "logs": (
            "2024-01-15 15:20:10 Database backup started\n"
            "2024-01-15 15:25:30 Backup progress: 45% completed\n"
            "2024-01-15 15:35:00 Backup completed successfully\n"
            "2024-01-15 15:35:15 Backup file stored: /backups/db_backup_2024-01-15.bak"
        ),
        "is_attack": False,
        "expected_techniques": [],
        "expected_severity": "LOW",
    },
    {
        "id": "test_006",
        "description": "Macro-enabled phishing → C2 beacon",
        "logs": (
            "2024-01-15 22:01:05 Suspicious macro execution in Word document\n"
            "2024-01-15 22:01:10 PowerShell.exe spawned by WINWORD.EXE\n"
            "2024-01-15 22:01:15 PowerShell download cradle detected\n"
            "2024-01-15 22:01:22 C2 beacon established to 91.108.4.1:8080"
        ),
        "is_attack": True,
        "expected_techniques": ["T1059"],
        "expected_severity": "CRITICAL",
    },
    {
        "id": "test_007",
        "description": "User opens legitimate PDF (benign)",
        "logs": (
            "2024-01-15 08:15:00 User opened email from external sender\n"
            "2024-01-15 08:16:30 PDF reader launched for attachment\n"
            "2024-01-15 08:17:00 PDF file: invoice_2024.pdf read successfully"
        ),
        "is_attack": False,
        "expected_techniques": [],
        "expected_severity": "LOW",
    },
    {
        "id": "test_008",
        "description": "Registry persistence + C2 on port 4444",
        "logs": (
            "2024-01-15 16:45:00 Abnormal process spawned: System process initiated unusual action\n"
            "2024-01-15 16:45:15 Registry modified: HKLM\\Software\\Microsoft\\Windows\\Run\n"
            "2024-01-15 16:45:30 New service registered: suspicious_service\n"
            "2024-01-15 16:46:00 C2 communication detected on port 4444"
        ),
        "is_attack": True,
        "expected_techniques": ["T1547"],
        "expected_severity": "HIGH",
    },
    {
        "id": "test_009",
        "description": "Windows Update + scheduled maintenance (benign)",
        "logs": (
            "2024-01-15 12:00:00 Scheduled task created: Task Scheduler initialized\n"
            "2024-01-15 12:01:15 Windows Update check executed\n"
            "2024-01-15 12:02:30 System maintenance completed"
        ),
        "is_attack": False,
        "expected_techniques": [],
        "expected_severity": "LOW",
    },
    {
        "id": "test_010",
        "description": "Ransomware — shadow copy deletion + mass encryption",
        "logs": (
            "2024-01-15 19:30:00 Volume Shadow Copy deletion detected\n"
            "2024-01-15 19:30:15 Backup service stopped\n"
            "2024-01-15 19:31:00 Mass file encryption in progress: .docx -> .locked\n"
            "2024-01-15 19:32:30 README_DECRYPT.txt created in multiple directories"
        ),
        "is_attack": True,
        "expected_techniques": ["T1486"],
        "expected_severity": "CRITICAL",
    },
]


# ── Metrics dataclass ─────────────────────────────────────────────────────────

@dataclass
class EvaluationMetrics:
    """Container for all evaluation metrics with human-readable display."""

    total_samples:      int
    true_positives:     int
    false_positives:    int
    true_negatives:     int
    false_negatives:    int
    detected_attacks:   int   # = TP + FP (all positive predictions)

    precision:          float  # TP / (TP + FP)
    recall:             float  # TP / (TP + FN)
    f1_score:           float
    specificity:        float  # TN / (TN + FP)
    accuracy:           float
    false_positive_rate: float # FP / (FP + TN)

    def __str__(self) -> str:
        return (
            "\n"
            "╔════════════════════════════════════════════════════════════╗\n"
            "║              SOC ANALYST — EVALUATION REPORT              ║\n"
            "╚════════════════════════════════════════════════════════════╝\n"
            "\n"
            "📊 Confusion Matrix\n"
            "─────────────────────────────────────────────────────────────\n"
            f"  Total Samples    : {self.total_samples}\n"
            f"  True Positives   : {self.true_positives}  (attacks correctly flagged)\n"
            f"  False Positives  : {self.false_positives}  (benign incorrectly flagged)\n"
            f"  True Negatives   : {self.true_negatives}  (benign correctly cleared)\n"
            f"  False Negatives  : {self.false_negatives}  (attacks missed)\n"
            "\n"
            "📈 Quality Metrics\n"
            "─────────────────────────────────────────────────────────────\n"
            f"  Precision        : {self.precision:.3f}   (of alerts raised, how many real?)\n"
            f"  Recall           : {self.recall:.3f}   (of attacks present, how many caught?)\n"
            f"  F1 Score         : {self.f1_score:.3f}   (harmonic mean)\n"
            f"  Specificity      : {self.specificity:.3f}   (benign correctly cleared)\n"
            f"  Accuracy         : {self.accuracy:.3f}   (overall)\n"
            f"  False Pos. Rate  : {self.false_positive_rate:.3f}   (alert fatigue indicator)\n"
            "═════════════════════════════════════════════════════════════\n"
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Evaluator class ───────────────────────────────────────────────────────────

class IncidentEvaluator:
    """
    Evaluates the SOC pipeline against a labelled test dataset.

    Pass your own detection function to test the real pipeline, or
    leave it as None to use the built-in heuristic mock detector.
    """

    def __init__(self, dataset: Optional[List[Dict[str, Any]]] = None):
        self.dataset = dataset or TEST_DATASET

    # ── Public interface ──────────────────────────────────────────────────────

    def run_evaluation(
        self,
        detection_func: Optional[Callable[[str], Dict[str, Any]]] = None,
        verbose: bool = True,
    ) -> EvaluationMetrics:
        """
        Run evaluation over every sample in the dataset.

        Args:
            detection_func: Takes raw log string → returns incident dict
                            (must have "severity" and "mitre_technique" keys).
                            If None, the built-in mock heuristic detector is used.
            verbose:        Print per-sample results and summary table.

        Returns:
            EvaluationMetrics with all computed metrics.
        """
        detector = detection_func or self._mock_detector

        tp = fp = tn = fn = 0
        per_sample: List[Dict[str, Any]] = []

        for sample in self.dataset:
            sid = sample["id"]
            ground_truth = sample["is_attack"]

            try:
                result = detector(sample["logs"])
                predicted_attack = self._classify_as_attack(result)
            except Exception as exc:
                logger.error(f"[{sid}] Detection error: {exc}")
                result = {}
                predicted_attack = False

            if predicted_attack and ground_truth:
                tp += 1
                outcome = "TP"
            elif predicted_attack and not ground_truth:
                fp += 1
                outcome = "FP"
            elif not predicted_attack and ground_truth:
                fn += 1
                outcome = "FN"
            else:
                tn += 1
                outcome = "TN"

            per_sample.append({
                "id":           sid,
                "description":  sample.get("description", ""),
                "ground_truth": ground_truth,
                "predicted":    predicted_attack,
                "outcome":      outcome,
                "severity":     result.get("severity", "N/A"),
                "techniques":   result.get("mitre_technique", []),
                "confidence":   result.get("confidence", 0.0),
            })

        total = len(self.dataset)
        precision  = tp / (tp + fp)          if (tp + fp) > 0 else 0.0
        recall     = tp / (tp + fn)          if (tp + fn) > 0 else 0.0
        f1         = (2 * precision * recall / (precision + recall)
                      if (precision + recall) > 0 else 0.0)
        specificity = tn / (tn + fp)         if (tn + fp) > 0 else 0.0
        accuracy   = (tp + tn) / total
        fpr        = fp / (fp + tn)          if (fp + tn) > 0 else 0.0

        metrics = EvaluationMetrics(
            total_samples=total,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            detected_attacks=tp + fp,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            specificity=round(specificity, 4),
            accuracy=round(accuracy, 4),
            false_positive_rate=round(fpr, 4),
        )

        if verbose:
            self._print_per_sample(per_sample)
            print(metrics)

        logger.info(
            f"Evaluation complete | P={precision:.3f} R={recall:.3f} "
            f"F1={f1:.3f} FPR={fpr:.3f}"
        )
        return metrics

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _classify_as_attack(self, incident: Dict[str, Any]) -> bool:
        """
        Predict 'attack' if severity is HIGH/CRITICAL OR any MITRE technique
        was detected. Benign prediction = LOW/MEDIUM severity AND no techniques.
        """
        severity = str(incident.get("severity", "LOW")).upper()
        techniques = incident.get("mitre_technique", [])
        return severity in {"HIGH", "CRITICAL"} or len(techniques) > 0

    def _mock_detector(self, logs: str) -> Dict[str, Any]:
        """
        Built-in heuristic detector used when no real pipeline is provided.
        Mirrors the keyword patterns used by event_extractor.py so metrics
        reflect the rule-based baseline before LLM enrichment.
        """
        lower = logs.lower()
        techniques: List[str] = []
        severity = "LOW"
        explanation_parts: List[str] = []

        # Brute force / credential access
        if "failed password" in lower or "authentication fail" in lower:
            techniques.append("T1110")
            severity = "HIGH"
            explanation_parts.append("Multiple failed login attempts detected → T1110 Brute Force.")

        # Lateral movement
        if "psexec" in lower or "net use" in lower or "wmiexec" in lower:
            techniques.append("T1021")
            severity = max(severity, "HIGH", key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[s])
            explanation_parts.append("Lateral movement tool detected → T1021 Remote Services.")

        # Exfiltration
        if ("outbound" in lower and "traffic" in lower) or "exfil" in lower or "dns query storm" in lower:
            techniques.append("T1041")
            severity = "CRITICAL"
            explanation_parts.append("Data exfiltration pattern detected → T1041.")

        # Execution / malicious script
        if "powershell" in lower and ("download" in lower or "cradle" in lower or "beacon" in lower):
            techniques.append("T1059")
            severity = "CRITICAL"
            explanation_parts.append("Malicious PowerShell execution detected → T1059.")

        # Persistence
        if "registry modified" in lower or "service registered" in lower:
            techniques.append("T1547")
            if severity == "LOW":
                severity = "HIGH"
            explanation_parts.append("Persistence mechanism detected → T1547.")

        # Defense evasion / ransomware
        if "shadow copy" in lower or "encryption in progress" in lower or "readme_decrypt" in lower:
            techniques.append("T1562")
            techniques.append("T1486")
            severity = "CRITICAL"
            explanation_parts.append("Ransomware or defense-evasion activity detected → T1562 / T1486.")

        confidence = 0.75 if techniques else 0.2

        return {
            "attack_stage":        "Multi-Stage Attack" if len(techniques) > 1 else (
                                   "Unknown" if not techniques else "Active Intrusion"),
            "mitre_technique":     list(dict.fromkeys(techniques)),   # deduplicate
            "severity":            severity,
            "confidence":          confidence,
            "explanation":         " ".join(explanation_parts) or "No significant anomalies detected.",
            "recommended_actions": (
                ["Isolate affected host", "Preserve logs", "Escalate to IR team"]
                if techniques else ["Monitor and log for baseline"]
            ),
        }

    def _print_per_sample(self, results: List[Dict[str, Any]]) -> None:
        """Print a clean per-sample breakdown table."""
        ICONS = {"TP": "✅", "TN": "✅", "FP": "⚠️ ", "FN": "❌"}
        print("\n" + "═" * 72)
        print("  PER-SAMPLE RESULTS")
        print("═" * 72)
        for r in results:
            icon = ICONS.get(r["outcome"], "?")
            gt  = "Attack" if r["ground_truth"] else "Benign"
            pdt = "Attack" if r["predicted"]    else "Benign"
            tech_str = ", ".join(r["techniques"]) if r["techniques"] else "—"
            print(
                f"\n{icon} [{r['outcome']}] {r['id']}  —  {r['description']}\n"
                f"     Ground Truth : {gt}  |  Predicted : {pdt}\n"
                f"     Severity     : {r['severity']}  |  Confidence : {r['confidence']:.2f}\n"
                f"     Techniques   : {tech_str}"
            )
        print("\n" + "═" * 72 + "\n")


# ── Convenience function ───────────────────────────────────────────────────────

def run_evaluation(
    detection_func: Optional[Callable[[str], Dict[str, Any]]] = None,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    Convenience wrapper.  Import and call this from any module or the API.

    Args:
        detection_func: Your pipeline's detection callable (logs_str → incident_dict).
                        Pass None to benchmark the heuristic baseline.
        verbose:        Print detailed results to stdout.

    Returns:
        Metrics as a plain dictionary (JSON-serialisable).
    """
    evaluator = IncidentEvaluator()
    metrics = evaluator.run_evaluation(detection_func, verbose=verbose)
    return metrics.to_dict()


# ── CLI entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    print("Running SOC Analyst evaluation with built-in heuristic detector …\n")
    result = run_evaluation(verbose=True)

    print(f"\nJSON-serialisable metrics summary:")
    import json
    print(json.dumps(result, indent=2))
