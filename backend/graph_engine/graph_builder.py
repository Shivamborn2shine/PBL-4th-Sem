"""
graph_builder.py – Graph Intelligence Builder Module

Creates and manages threat intelligence graph nodes and edges in DynamoDB.
Tracks relationships between users, domains, IPs, and emails.
"""

import os
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


# ─── DynamoDB Configuration ──────────────────────────────────────────────────

def _get_dynamodb():
    """Get DynamoDB resource (supports local and AWS environments)."""
    endpoint_url = os.environ.get('DYNAMODB_ENDPOINT')
    if endpoint_url:
        return boto3.resource('dynamodb', endpoint_url=endpoint_url)
    return boto3.resource('dynamodb')


def _get_nodes_table():
    """Get the GraphNodes DynamoDB table."""
    table_name = os.environ.get('GRAPH_NODES_TABLE', 'SentinelSphere-GraphNodes')
    return _get_dynamodb().Table(table_name)


def _get_edges_table():
    """Get the GraphEdges DynamoDB table."""
    table_name = os.environ.get('GRAPH_EDGES_TABLE', 'SentinelSphere-GraphEdges')
    return _get_dynamodb().Table(table_name)


# ─── Node Operations ─────────────────────────────────────────────────────────

def create_node(node_id: str, node_type: str, metadata: dict = None) -> dict:
    """
    Create or update a graph node in DynamoDB.

    Args:
        node_id: Unique identifier for the node
        node_type: Type of node (USER, IP, DOMAIN, EMAIL)
        metadata: Optional additional metadata

    Returns:
        dict: The created/updated node item
    """
    table = _get_nodes_table()
    now = datetime.now(timezone.utc).isoformat()

    item = {
        'node_id': node_id,
        'node_type': node_type,
        'created_at': now,
        'updated_at': now,
        'scan_count': 1,
    }

    if metadata:
        item['metadata'] = metadata

    try:
        # Try to update existing node (increment scan_count)
        response = table.update_item(
            Key={'node_id': node_id},
            UpdateExpression='SET node_type = :nt, updated_at = :ua, scan_count = if_not_exists(scan_count, :zero) + :inc',
            ExpressionAttributeValues={
                ':nt': node_type,
                ':ua': now,
                ':inc': 1,
                ':zero': 0,
            },
            ReturnValues='ALL_NEW'
        )
        return response.get('Attributes', item)
    except ClientError:
        # Fallback: put the item directly
        table.put_item(Item=item)
        return item


def get_node(node_id: str) -> dict:
    """
    Retrieve a graph node by its ID.

    Returns:
        dict or None: Node item if found
    """
    table = _get_nodes_table()
    try:
        response = table.get_item(Key={'node_id': node_id})
        return response.get('Item')
    except ClientError:
        return None


# ─── Edge Operations ─────────────────────────────────────────────────────────

def create_edge(source_node: str, target_node: str, relation_type: str, weight: float = 1.0) -> dict:
    """
    Create or update a graph edge in DynamoDB.

    Args:
        source_node: Source node ID
        target_node: Target node ID
        relation_type: Type of relationship (e.g., 'scanned', 'resolves_to')
        weight: Edge weight (strength of relationship)

    Returns:
        dict: The created/updated edge item
    """
    table = _get_edges_table()
    now = datetime.now(timezone.utc).isoformat()

    item = {
        'source_node': source_node,
        'target_node': target_node,
        'relation_type': relation_type,
        'weight': str(weight),  # DynamoDB doesn't support float directly
        'timestamp': now,
        'occurrence_count': 1,
    }

    try:
        # Update existing edge (increment occurrence_count, update weight)
        response = table.update_item(
            Key={
                'source_node': source_node,
                'target_node': target_node,
            },
            UpdateExpression='SET relation_type = :rt, weight = :w, #ts = :ts, occurrence_count = if_not_exists(occurrence_count, :zero) + :inc',
            ExpressionAttributeNames={
                '#ts': 'timestamp'
            },
            ExpressionAttributeValues={
                ':rt': relation_type,
                ':w': str(weight),
                ':ts': now,
                ':inc': 1,
                ':zero': 0,
            },
            ReturnValues='ALL_NEW'
        )
        return response.get('Attributes', item)
    except ClientError:
        table.put_item(Item=item)
        return item


def get_edges_from(source_node: str) -> list:
    """
    Get all outgoing edges from a source node.

    Returns:
        list: List of edge items
    """
    table = _get_edges_table()
    try:
        response = table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key('source_node').eq(source_node)
        )
        return response.get('Items', [])
    except ClientError:
        return []


def get_edges_to(target_node: str) -> list:
    """
    Get all incoming edges to a target node (requires scan).

    Returns:
        list: List of edge items pointing to this node
    """
    table = _get_edges_table()
    try:
        response = table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('target_node').eq(target_node)
        )
        return response.get('Items', [])
    except ClientError:
        return []


# ─── Graph Construction Orchestrator ──────────────────────────────────────────

def build_scan_graph(user_id: str, domain: str, ip: str = None, email: str = None) -> dict:
    """
    Build the threat intelligence graph for a scan event.
    Creates nodes and relationships between entities.

    Args:
        user_id: The user performing the scan
        domain: The scanned domain
        ip: Optional resolved IP address
        email: Optional email address involved

    Returns:
        dict with created nodes and edges
    """
    created_nodes = []
    created_edges = []

    # ── Create User Node ──────────────────────────────────────────
    user_node = create_node(
        node_id=f'user:{user_id}',
        node_type='USER',
        metadata={'user_id': user_id}
    )
    created_nodes.append(user_node)

    # ── Create Domain Node ────────────────────────────────────────
    domain_node = create_node(
        node_id=f'domain:{domain}',
        node_type='DOMAIN',
        metadata={'domain': domain}
    )
    created_nodes.append(domain_node)

    # ── USER → scanned → DOMAIN ──────────────────────────────────
    edge1 = create_edge(
        source_node=f'user:{user_id}',
        target_node=f'domain:{domain}',
        relation_type='scanned',
        weight=1.0
    )
    created_edges.append(edge1)

    # ── Create IP Node (if available) ─────────────────────────────
    if ip:
        ip_node = create_node(
            node_id=f'ip:{ip}',
            node_type='IP',
            metadata={'ip_address': ip}
        )
        created_nodes.append(ip_node)

        # DOMAIN → resolves_to → IP
        edge2 = create_edge(
            source_node=f'domain:{domain}',
            target_node=f'ip:{ip}',
            relation_type='resolves_to',
            weight=1.0
        )
        created_edges.append(edge2)

    # ── Create Email Node (if available) ──────────────────────────
    if email:
        email_node = create_node(
            node_id=f'email:{email}',
            node_type='EMAIL',
            metadata={'email': email}
        )
        created_nodes.append(email_node)

        # EMAIL → associated_with → DOMAIN
        edge3 = create_edge(
            source_node=f'email:{email}',
            target_node=f'domain:{domain}',
            relation_type='associated_with',
            weight=0.8
        )
        created_edges.append(edge3)

    return {
        'nodes': created_nodes,
        'edges': created_edges,
        'node_count': len(created_nodes),
        'edge_count': len(created_edges)
    }
