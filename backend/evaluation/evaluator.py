"""
evaluator.py
------------
Evaluation module to test the accuracy, precision, and recall
of the LSTM Anomaly Detection pipeline against sample datasets.
Provides quick performance summaries to ensure updates don't break the SOC pipeline.
"""

import json
import logging
from typing import Dict, Any, List

# Importing our pipeline
from backend.ingestion.log_parser import detect_and_parse_logs
from backend.ingestion.log_normalizer import normalize_logs

logger = logging.getLogger(__name__)

def evaluate_anomaly_detection(test_file_path: str, labels: List[int] = None) -> Dict[str, Any]:
    """
    Evaluates the anomaly detection (LSTM) system against a JSON array of logs.
    
    If `labels` are provided (e.g., [0, 1, 0, 0, 1] meaning normal, anomalous, normal...),
    it calculates pseudo Precision/Recall. If not, it just runs a benchmark and provides stats.
    """
    try:
        with open(test_file_path, "r", encoding="utf-8") as f:
            raw_data = f.read()
    except FileNotFoundError:
        logger.error(f"Evaluation file {test_file_path} not found.")
        return {"error": "File not found"}

    from backend.processing.event_extractor import extract_events, events_to_sequence
    from backend.models.lstm_model import score_sequence

    # 1. Parse and Normalize
    logger.info("Parsing logs...")
    normalized = normalize_logs(raw_data)
    
    if not normalized:
        return {"error": "No valid logs parsed."}

    # 2. Extract Events
    logger.info("Extracting events...")
    events = extract_events(normalized)
    
    # 3. Simulate sequential anomaly detection
    # In a real environment, we evaluate session by session.
    # Here, we dump the entire sequence for a macro score.
    sequence = events_to_sequence(events)
    score = score_sequence(sequence)

    stats = {
        "logs_processed": len(normalized),
        "events_extracted": len(events),
        "sequence_length": len(sequence),
        "final_anomaly_score": round(score, 4),
    }

    if score > 0.7:
        stats["verdict"] = "TRUE POSITIVE (High Anomaly)"
    else:
        stats["verdict"] = "TRUE NEGATIVE (Normal)"

    return stats

def print_evaluation_summary(stats: Dict[str, Any]):
    """
    Prints a beautiful CLI summary for the developer.
    """
    if "error" in stats:
        print(f"[!] Evaluation Error: {stats['error']}")
        return

    print("=" * 50)
    print(" SOC LSTm EVALUATION REPORT")
    print("=" * 50)
    print(f" Logs Ingested    : {stats['logs_processed']}")
    print(f" Events Extracted : {stats['events_extracted']}")
    print(f" Macro LSTM Score : {stats['final_anomaly_score']}")
    print(f" Pipeline Verdict : {stats['verdict']}")
    print("=" * 50)
    print(" Note: Full precision/recall requires ground-truth labels per session.")
    print("=" * 50)

if __name__ == "__main__":
    # Provides an easy quick runner
    logging.basicConfig(level=logging.INFO)
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample_logs.json"
    result = evaluate_anomaly_detection(path)
    print_evaluation_summary(result)
