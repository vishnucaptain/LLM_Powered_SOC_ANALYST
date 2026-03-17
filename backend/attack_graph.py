"""
attack_graph.py
---------------
Reconstructs the attack path as a directed graph using NetworkX.

Each node represents an attacker action (event type).
Each edge represents temporal succession.

Output format:
{
    "nodes": [{"id": str, "label": str, "type": str, "count": int}],
    "edges": [{"source": str, "target": str, "weight": int}],
    "stages": [str],        # ordered attack kill-chain stages
    "kill_chain_stage": str # mapped ATT&CK tactic
}
"""

import networkx as nx
from typing import List, Dict, Any, Optional
from collections import Counter

# MITRE ATT&CK Kill Chain mapping
# Maps our event types to Lockheed Martin / MITRE kill-chain stages
KILL_CHAIN_MAP: Dict[str, str] = {
    "NORMAL":          "Benign",
    "RECON":           "Reconnaissance",
    "LOGIN":           "Initial Access / Credential Access",
    "SUSPICIOUS_EXEC": "Execution",
    "PRIV_ESC":        "Privilege Escalation",
    "LATERAL_MOVE":    "Lateral Movement",
    "DEFENSE_EVADE":   "Defense Evasion",
    "FILE_ACCESS":     "Collection",
    "OUTBOUND_CONN":   "Command & Control",
    "EXFILTRATION":    "Exfiltration",
}

# Stage severity order for determining the "furthest" kill-chain stage
STAGE_ORDER = [
    "Benign",
    "Reconnaissance",
    "Initial Access / Credential Access",
    "Execution",
    "Privilege Escalation",
    "Lateral Movement",
    "Defense Evasion",
    "Collection",
    "Command & Control",
    "Exfiltration",
]


def build_attack_graph(events: list) -> Dict[str, Any]:
    """
    Build a directed attack graph from a list of SecurityEvent objects.

    Each unique (event_type, actor) pair is a node.
    Edges are created between consecutive event nodes.

    Returns a dict with nodes, edges, stages, and kill-chain info.
    """
    G = nx.DiGraph()

    if not events:
        return {"nodes": [], "edges": [], "stages": [], "kill_chain_stage": "Benign"}

    # Build node IDs and add to graph
    # Node ID = event_type (aggregated — we compress multiple of the same type)
    node_counts: Counter = Counter()
    for event in events:
        node_counts[event.event_type] += 1

    # Add nodes
    for event_type, count in node_counts.items():
        G.add_node(
            event_type,
            label=event_type.replace("_", " ").title(),
            event_type=event_type,
            count=count,
            kill_chain=KILL_CHAIN_MAP.get(event_type, "Unknown"),
        )

    # Add directed edges (event[i] → event[i+1])
    edge_weights: Counter = Counter()
    for i in range(len(events) - 1):
        src = events[i].event_type
        dst = events[i + 1].event_type
        if src != dst:  # skip self-loops for clarity
            edge_weights[(src, dst)] += 1

    for (src, dst), weight in edge_weights.items():
        if G.has_node(src) and G.has_node(dst):
            G.add_edge(src, dst, weight=weight)

    # Compute kill-chain stages present (ordered)
    present_stages = []
    for stage in STAGE_ORDER:
        if any(
            KILL_CHAIN_MAP.get(et) == stage for et in node_counts.keys()
        ):
            present_stages.append(stage)

    # Furthest kill-chain stage reached
    furthest_stage = present_stages[-1] if present_stages else "Benign"

    # Serialize
    nodes = [
        {
            "id":         n,
            "label":      G.nodes[n].get("label", n),
            "type":       G.nodes[n].get("event_type", n),
            "count":      G.nodes[n].get("count", 1),
            "kill_chain": G.nodes[n].get("kill_chain", "Unknown"),
        }
        for n in G.nodes()
    ]

    edges = [
        {
            "source": u,
            "target": v,
            "weight": G.edges[u, v].get("weight", 1),
        }
        for u, v in G.edges()
    ]

    # Topological sort of the attack path (if DAG).
    # Graphs with cycles (repeated event types) fall back to frequency-ordered list.
    try:
        attack_path = list(nx.topological_sort(G))
    except (nx.NetworkXError, nx.NetworkXUnfeasible):
        # Sort nodes by first-appearance order in the event sequence
        seen = {}
        for event in events:
            if event.event_type not in seen:
                seen[event.event_type] = len(seen)
        attack_path = sorted(node_counts.keys(), key=lambda n: seen.get(n, 999))

    return {
        "nodes":            nodes,
        "edges":            edges,
        "stages":           present_stages,
        "kill_chain_stage": furthest_stage,
        "attack_path":      attack_path,
        "node_count":       G.number_of_nodes(),
        "edge_count":       G.number_of_edges(),
    }


def attack_graph_summary(graph: Dict[str, Any]) -> str:
    """Return a human-readable summary of the attack graph."""
    if not graph["nodes"]:
        return "No attack graph data."
    path = " → ".join(graph.get("attack_path", []))
    return (
        f"Attack progression: {path}\n"
        f"Kill-chain stage reached: {graph['kill_chain_stage']}\n"
        f"Stages observed: {', '.join(graph['stages'])}"
    )
