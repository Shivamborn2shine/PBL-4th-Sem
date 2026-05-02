"""
graph_builder.py – Graph Intelligence Builder Module

Creates and manages threat intelligence graph nodes and edges in Firebase Firestore.
Tracks relationships between users, domains, IPs, and emails.
"""

import os
from datetime import datetime, timezone

from utils.firebase_client import get_nodes_collection, get_edges_collection


# ─── Node Operations ─────────────────────────────────────────────────────────

def create_node(node_id: str, node_type: str, metadata: dict = None) -> dict:
    """
    Create or update a graph node in Firestore.

    Args:
        node_id: Unique identifier for the node
        node_type: Type of node (USER, IP, DOMAIN, EMAIL)
        metadata: Optional additional metadata

    Returns:
        dict: The created/updated node item
    """
    collection = get_nodes_collection()
    now = datetime.now(timezone.utc).isoformat()

    # Sanitize node_id for use as Firestore document ID
    doc_id = node_id.replace('/', '_').replace('.', '_')

    item = {
        'node_id': node_id,
        'node_type': node_type,
        'updated_at': now,
    }

    if metadata:
        item['metadata'] = metadata

    try:
        doc_ref = collection.document(doc_id)
        doc = doc_ref.get()

        if doc.exists:
            # Update existing node (increment scan_count)
            from google.cloud.firestore_v1 import Increment
            doc_ref.update({
                'node_type': node_type,
                'updated_at': now,
                'scan_count': Increment(1),
            })
            updated = doc_ref.get().to_dict()
            return updated
        else:
            # Create new node
            item['created_at'] = now
            item['scan_count'] = 1
            doc_ref.set(item)
            return item

    except Exception:
        # Fallback: set the item directly
        item['created_at'] = now
        item['scan_count'] = 1
        collection.document(doc_id).set(item)
        return item


def get_node(node_id: str) -> dict:
    """
    Retrieve a graph node by its ID.

    Returns:
        dict or None: Node item if found
    """
    collection = get_nodes_collection()
    doc_id = node_id.replace('/', '_').replace('.', '_')
    try:
        doc = collection.document(doc_id).get()
        if doc.exists:
            return doc.to_dict()
        return None
    except Exception:
        return None


# ─── Edge Operations ─────────────────────────────────────────────────────────

def create_edge(source_node: str, target_node: str, relation_type: str, weight: float = 1.0) -> dict:
    """
    Create or update a graph edge in Firestore.

    Args:
        source_node: Source node ID
        target_node: Target node ID
        relation_type: Type of relationship (e.g., 'scanned', 'resolves_to')
        weight: Edge weight (strength of relationship)

    Returns:
        dict: The created/updated edge item
    """
    collection = get_edges_collection()
    now = datetime.now(timezone.utc).isoformat()

    # Create a composite document ID
    doc_id = f"{source_node}__{target_node}".replace('/', '_').replace('.', '_')

    item = {
        'source_node': source_node,
        'target_node': target_node,
        'relation_type': relation_type,
        'weight': weight,
        'timestamp': now,
        'occurrence_count': 1,
    }

    try:
        doc_ref = collection.document(doc_id)
        doc = doc_ref.get()

        if doc.exists:
            # Update existing edge
            from google.cloud.firestore_v1 import Increment
            doc_ref.update({
                'relation_type': relation_type,
                'weight': weight,
                'timestamp': now,
                'occurrence_count': Increment(1),
            })
            updated = doc_ref.get().to_dict()
            return updated
        else:
            doc_ref.set(item)
            return item

    except Exception:
        collection.document(doc_id).set(item)
        return item


def get_edges_from(source_node: str) -> list:
    """
    Get all outgoing edges from a source node.

    Returns:
        list: List of edge items
    """
    collection = get_edges_collection()
    try:
        query = collection.where('source_node', '==', source_node)
        docs = query.stream()
        return [doc.to_dict() for doc in docs]
    except Exception:
        return []


def get_edges_to(target_node: str) -> list:
    """
    Get all incoming edges to a target node.

    Returns:
        list: List of edge items pointing to this node
    """
    collection = get_edges_collection()
    try:
        query = collection.where('target_node', '==', target_node)
        docs = query.stream()
        return [doc.to_dict() for doc in docs]
    except Exception:
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
