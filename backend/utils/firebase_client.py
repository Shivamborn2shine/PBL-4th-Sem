"""
firebase_client.py – Firebase Admin SDK Client Module

Provides Firestore database access for all backend modules,
replacing the previous DynamoDB/boto3 integration.
"""

import os
import json
import firebase_admin
from firebase_admin import credentials, firestore


# ─── Firebase Initialization ────────────────────────────────────────────────

_app = None
_db = None


def _initialize_firebase():
    """Initialize Firebase Admin SDK (singleton)."""
    global _app, _db

    if _app is not None:
        return

    # Option 1: Service account key file path
    cred_path = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
    if cred_path and os.path.exists(cred_path):
        cred = credentials.Certificate(cred_path)
        _app = firebase_admin.initialize_app(cred)
    # Option 2: Service account JSON in environment variable
    elif os.environ.get('FIREBASE_CREDENTIALS_JSON'):
        cred_dict = json.loads(os.environ['FIREBASE_CREDENTIALS_JSON'])
        cred = credentials.Certificate(cred_dict)
        _app = firebase_admin.initialize_app(cred)
    # Option 3: Default credentials (GCP environment)
    else:
        try:
            _app = firebase_admin.initialize_app()
        except ValueError:
            # Already initialized
            _app = firebase_admin.get_app()

    _db = firestore.client()


def get_firestore_db():
    """Get the Firestore database client."""
    _initialize_firebase()
    return _db


# ─── Collection Names ───────────────────────────────────────────────────────

THREAT_REPORTS_COLLECTION = os.environ.get('THREAT_REPORTS_COLLECTION', 'threat_reports')
GRAPH_NODES_COLLECTION = os.environ.get('GRAPH_NODES_COLLECTION', 'graph_nodes')
GRAPH_EDGES_COLLECTION = os.environ.get('GRAPH_EDGES_COLLECTION', 'graph_edges')


# ─── Helper Functions ───────────────────────────────────────────────────────

def get_collection(collection_name: str):
    """Get a Firestore collection reference."""
    db = get_firestore_db()
    return db.collection(collection_name)


def get_reports_collection():
    """Get the threat reports collection."""
    return get_collection(THREAT_REPORTS_COLLECTION)


def get_nodes_collection():
    """Get the graph nodes collection."""
    return get_collection(GRAPH_NODES_COLLECTION)


def get_edges_collection():
    """Get the graph edges collection."""
    return get_collection(GRAPH_EDGES_COLLECTION)
