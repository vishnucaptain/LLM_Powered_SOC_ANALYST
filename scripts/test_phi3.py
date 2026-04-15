"""
test_phi3.py
------------
A quick smoke test to verify that the Phi-3.5 local LLM is working.
It loads the model and runs a simple fake log through the investigation pipeline.
"""
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.llm_agent import investigate_logs
import time

print("="*60)
print(" 🚀 Testing Phi-3.5 Local LLM Inference")
print("="*60)
print("Loading model into memory (this will take a moment)...")

t0 = time.time()
try:
    # We pass a simple fake scenario to the LLM agent
    result = investigate_logs(
        log_text="2024-05-12 10:22:14 sshd[123]: Failed password for root from 192.168.1.100 port 22",
        event_sequence=["LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_FAILED", "PRIV_ESC"],
        anomaly_score=0.85,
        threat_intel_summary="192.168.1.100 is known for brute force attacks.",
        attack_graph_summary="Attacker attempted brute force and privilege escalation.",
        rag_context="T1110 Brute Force: Adversaries may use brute force techniques to gain access to accounts."
    )
    
    t1 = time.time()
    print(f"\n✅ Model loaded and generated response in {t1-t0:.1f} seconds.\n")
    print("=== LLM OUTPUT ===")
    print(result)
    print("==================\n")
    print("If you see the structured incident report above, your LLM is working perfectly!")

except Exception as e:
    print(f"\n❌ LLM Test Failed: {e}")
