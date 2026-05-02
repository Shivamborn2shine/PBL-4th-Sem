"""
scan_url.py – Lambda Handler for URL Scanning

Endpoint: POST /api/v1/scan-url
Orchestrates URL threat analysis using all backend modules.
"""

import json
import os
import uuid
import traceback
from datetime import datetime, timezone
from urllib.parse import urlparse


def lambda_handler(event, context):
    """
    AWS Lambda handler for URL scanning.

    Request Body:
        {
            "user_id": "string",
            "url": "string"
        }

    Response:
        {
            "risk_score": 0.87,
            "risk_level": "HIGH",
            "explanation": [...],
            "graph_suspicion": 0.62
        }
    """
    # ── CORS headers ──────────────────────────────────────────────
    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
    }

    # Handle preflight
    if event.get('httpMethod') == 'OPTIONS':
        return {'statusCode': 200, 'headers': headers, 'body': ''}

    try:
        # ── Parse request ─────────────────────────────────────────
        body = json.loads(event.get('body', '{}'))
        user_id = body.get('user_id', 'anonymous')
        url = body.get('url', '')

        if not url:
            return {
                'statusCode': 400,
                'headers': headers,
                'body': json.dumps({'error': 'URL is required'})
            }

        # ── Extract domain ────────────────────────────────────────
        try:
            parsed = urlparse(url if '://' in url else f'http://{url}')
            domain = parsed.netloc or parsed.path.split('/')[0]
        except Exception:
            domain = url

        # ── Run URL Analysis ──────────────────────────────────────
        from threat_modules.url_analyzer import analyze_url
        analysis = analyze_url(url)

        # ── Check Reputation ──────────────────────────────────────
        from threat_modules.reputation_checker import get_combined_reputation
        reputation_score = get_combined_reputation(domain)

        # ── Build Graph ───────────────────────────────────────────
        graph_data = None
        try:
            from graph_engine.graph_builder import build_scan_graph
            graph_data = build_scan_graph(user_id=user_id, domain=domain)
        except Exception as e:
            print(f'Graph build warning: {str(e)}')

        # ── Compute Graph Suspicion ───────────────────────────────
        try:
            from graph_engine.graph_metrics import compute_graph_suspicion
            graph_metrics = compute_graph_suspicion(domain)
            graph_score = graph_metrics['graph_score']
        except Exception:
            from graph_engine.graph_metrics import compute_graph_suspicion_offline
            graph_metrics = compute_graph_suspicion_offline(domain)
            graph_score = graph_metrics['graph_score']

        # ── Calculate Final Risk ──────────────────────────────────
        from risk_engine.risk_calculator import calculate_risk
        risk_result = calculate_risk(
            ml_score=analysis['ml_score'],
            reputation_score=reputation_score,
            graph_score=graph_score,
            rule_based_score=analysis['rule_based_score']
        )

        # ── Store Report in Firebase Firestore ────────────────────
        report_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        report = {
            'report_id': report_id,
            'user_id': user_id,
            'input_type': 'URL',
            'input_value': url,
            'risk_score': risk_result['risk_score'],
            'risk_level': risk_result['risk_level'],
            'explanation': analysis['explanations'],
            'timestamp': timestamp,
            'score_breakdown': risk_result['score_breakdown'],
        }

        try:
            from utils.firebase_client import get_reports_collection
            get_reports_collection().document(report_id).set(report)
        except Exception as e:
            print(f'Firestore write warning: {str(e)}')

        # ── Build Response ────────────────────────────────────────
        response_body = {
            'report_id': report_id,
            'risk_score': risk_result['risk_score'],
            'risk_level': risk_result['risk_level'],
            'explanation': analysis['explanations'],
            'graph_suspicion': graph_score,
            'score_breakdown': risk_result['score_breakdown'],
            'confidence': risk_result['confidence'],
            'domain': domain,
            'timestamp': timestamp,
        }

        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps(response_body)
        }

    except Exception as e:
        print(f'Error in scan_url: {traceback.format_exc()}')
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }
