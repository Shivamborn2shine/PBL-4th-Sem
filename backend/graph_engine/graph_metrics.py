"""
graph_metrics.py – Graph Intelligence Metrics Module

Computes graph-based threat metrics: frequency, centrality, burst detection,
and overall graph suspicion scores from the Firebase Firestore graph collections.
"""

import os
from datetime import datetime, timezone, timedelta

from utils.firebase_client import get_nodes_collection, get_edges_collection, get_reports_collection


# ─── Metric Computation Functions ────────────────────────────────────────────

def compute_frequency_score(domain: str) -> float:
    """
    Compute how frequently this domain has been scanned/reported.
    Higher frequency → higher suspicion.

    Returns:
        float: Normalized frequency score (0-1)
    """
    try:
        node_id = f'domain:{domain}'
        doc_id = node_id.replace('/', '_').replace('.', '_')
        collection = get_nodes_collection()
        doc = collection.document(doc_id).get()

        if not doc.exists:
            return 0.0

        node = doc.to_dict()
        scan_count = int(node.get('scan_count', 0))

        # Normalize: 1 scan = 0, 10+ scans = 1.0
        if scan_count <= 1:
            return 0.0
        elif scan_count >= 10:
            return 1.0
        else:
            return round((scan_count - 1) / 9.0, 4)

    except Exception:
        return 0.0


def compute_centrality_score(node_id: str) -> float:
    """
    Compute the centrality (connectedness) of a node in the graph.
    Nodes with many connections are more suspicious.

    Uses degree centrality: (number of connections) / (max possible connections)

    Returns:
        float: Normalized centrality score (0-1)
    """
    try:
        edges_collection = get_edges_collection()

        # Count outgoing edges
        outgoing = edges_collection.where('source_node', '==', node_id).stream()
        out_count = sum(1 for _ in outgoing)

        # Count incoming edges
        incoming = edges_collection.where('target_node', '==', node_id).stream()
        in_count = sum(1 for _ in incoming)

        total_connections = out_count + in_count

        # Normalize: 0-1 connections = 0, 20+ = 1.0
        if total_connections <= 1:
            return 0.0
        elif total_connections >= 20:
            return 1.0
        else:
            return round((total_connections - 1) / 19.0, 4)

    except Exception:
        return 0.0


def compute_burst_score(domain: str, window_hours: int = 24) -> float:
    """
    Detect sudden bursts of reports for a domain within a time window.
    A burst indicates coordinated attack or trending threat.

    Args:
        domain: Domain to check
        window_hours: Time window in hours to check for bursts

    Returns:
        float: Burst score (0-1), higher = more bursty
    """
    try:
        collection = get_reports_collection()
        cutoff_time = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()

        # Query for recent reports matching this domain
        # Note: Firestore requires a composite index for multi-field queries
        # For simplicity, we filter by timestamp and check domain in code
        query = collection.where('timestamp', '>=', cutoff_time)
        docs = query.stream()

        recent_count = 0
        for doc in docs:
            data = doc.to_dict()
            input_value = data.get('input_value', '')
            if domain in input_value:
                recent_count += 1

        # Normalize: 0-1 reports = 0, 10+ reports in window = 1.0
        if recent_count <= 1:
            return 0.0
        elif recent_count >= 10:
            return 1.0
        else:
            return round((recent_count - 1) / 9.0, 4)

    except Exception:
        return 0.0


def compute_graph_suspicion(domain: str) -> dict:
    """
    Compute the overall graph-based suspicion score for a domain.

    Formula: graph_score = (frequency_score + centrality_score + burst_score) / 3

    Returns:
        dict with:
            - graph_score (float): Overall suspicion score (0-1)
            - frequency_score (float): Domain scan frequency metric
            - centrality_score (float): Node connectivity metric
            - burst_score (float): Recent report burst metric
    """
    node_id = f'domain:{domain}'

    frequency_score = compute_frequency_score(domain)
    centrality_score = compute_centrality_score(node_id)
    burst_score = compute_burst_score(domain)

    graph_score = round(
        (frequency_score + centrality_score + burst_score) / 3.0,
        4
    )

    return {
        'graph_score': graph_score,
        'frequency_score': frequency_score,
        'centrality_score': centrality_score,
        'burst_score': burst_score,
    }


def compute_graph_suspicion_offline(domain: str, scan_count: int = 1) -> dict:
    """
    Compute graph suspicion without Firestore access (for local/offline testing).
    Uses simple heuristics based on available data.

    Args:
        domain: Domain to evaluate
        scan_count: Known number of times this domain was scanned

    Returns:
        dict with graph suspicion metrics
    """
    import hashlib

    # Simulated frequency based on scan_count
    if scan_count <= 1:
        frequency_score = 0.0
    elif scan_count >= 10:
        frequency_score = 1.0
    else:
        frequency_score = round((scan_count - 1) / 9.0, 4)

    # Simulated centrality based on domain hash
    domain_hash = int(hashlib.md5(domain.encode()).hexdigest()[:4], 16)
    centrality_score = round((domain_hash % 50) / 100.0, 4)

    # Simulated burst (low by default for offline)
    burst_score = 0.1

    graph_score = round(
        (frequency_score + centrality_score + burst_score) / 3.0,
        4
    )

    return {
        'graph_score': graph_score,
        'frequency_score': frequency_score,
        'centrality_score': centrality_score,
        'burst_score': burst_score,
    }
