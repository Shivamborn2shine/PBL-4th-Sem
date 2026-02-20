"""
graph_metrics.py – Graph Intelligence Metrics Module

Computes graph-based threat metrics: frequency, centrality, burst detection,
and overall graph suspicion scores from the DynamoDB graph tables.
"""

import os
from datetime import datetime, timezone, timedelta
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError


def _get_dynamodb():
    """Get DynamoDB resource."""
    endpoint_url = os.environ.get('DYNAMODB_ENDPOINT')
    if endpoint_url:
        return boto3.resource('dynamodb', endpoint_url=endpoint_url)
    return boto3.resource('dynamodb')


def _get_nodes_table():
    table_name = os.environ.get('GRAPH_NODES_TABLE', 'SentinelSphere-GraphNodes')
    return _get_dynamodb().Table(table_name)


def _get_edges_table():
    table_name = os.environ.get('GRAPH_EDGES_TABLE', 'SentinelSphere-GraphEdges')
    return _get_dynamodb().Table(table_name)


def _get_reports_table():
    table_name = os.environ.get('THREAT_REPORTS_TABLE', 'SentinelSphere-ThreatReports')
    return _get_dynamodb().Table(table_name)


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
        table = _get_nodes_table()
        response = table.get_item(Key={'node_id': node_id})
        node = response.get('Item')

        if not node:
            return 0.0

        scan_count = int(node.get('scan_count', 0))

        # Normalize: 1 scan = 0, 10+ scans = 1.0
        if scan_count <= 1:
            return 0.0
        elif scan_count >= 10:
            return 1.0
        else:
            return round((scan_count - 1) / 9.0, 4)

    except ClientError:
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
        edges_table = _get_edges_table()

        # Count outgoing edges
        outgoing = edges_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('source_node').eq(node_id),
            Select='COUNT'
        )
        out_count = outgoing.get('Count', 0)

        # Count incoming edges (requires scan)
        incoming = edges_table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('target_node').eq(node_id),
            Select='COUNT'
        )
        in_count = incoming.get('Count', 0)

        total_connections = out_count + in_count

        # Normalize: 0-1 connections = 0, 20+ = 1.0
        if total_connections <= 1:
            return 0.0
        elif total_connections >= 20:
            return 1.0
        else:
            return round((total_connections - 1) / 19.0, 4)

    except ClientError:
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
        table = _get_reports_table()
        cutoff_time = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()

        # Scan for recent reports matching this domain
        response = table.scan(
            FilterExpression=(
                boto3.dynamodb.conditions.Attr('input_value').contains(domain) &
                boto3.dynamodb.conditions.Attr('timestamp').gte(cutoff_time)
            ),
            Select='COUNT'
        )

        recent_count = response.get('Count', 0)

        # Normalize: 0-1 reports = 0, 10+ reports in window = 1.0
        if recent_count <= 1:
            return 0.0
        elif recent_count >= 10:
            return 1.0
        else:
            return round((recent_count - 1) / 9.0, 4)

    except ClientError:
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
    Compute graph suspicion without DynamoDB access (for local/offline testing).
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
