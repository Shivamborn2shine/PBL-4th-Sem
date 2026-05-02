"""
scan_email.py – Lambda Handler for Email Scanning

Endpoint: POST /api/v1/scan-email
Orchestrates email phishing analysis using all backend modules.
"""

import json
import os
import re
import uuid
import traceback
from datetime import datetime, timezone


def lambda_handler(event, context):
    """
    AWS Lambda handler for email scanning.

    Request Body:
        {
            "user_id": "string",
            "email_text": "string"
        }

    Response:
        {
            "risk_score": 0.76,
            "risk_level": "MEDIUM",
            "explanation": [...]
        }
    """
    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
    }

    if event.get('httpMethod') == 'OPTIONS':
        return {'statusCode': 200, 'headers': headers, 'body': ''}

    try:
        # ── Parse request ─────────────────────────────────────────
        body = json.loads(event.get('body', '{}'))
        user_id = body.get('user_id', 'anonymous')
        email_text = body.get('email_text', '')

        if not email_text:
            return {
                'statusCode': 400,
                'headers': headers,
                'body': json.dumps({'error': 'email_text is required'})
            }

        # ── Run Email Analysis ────────────────────────────────────
        from threat_modules.email_analyzer import analyze_email
        analysis = analyze_email(email_text)

        # ── Extract domains from email for reputation check ───────
        reputation_score = 0.0
        domain = None
        try:
            # Extract sender domain
            from_match = re.search(r'@([\w.-]+)', email_text)
            if from_match:
                domain = from_match.group(1)
                from threat_modules.reputation_checker import get_combined_reputation
                reputation_score = get_combined_reputation(domain)
        except Exception as e:
            print(f'Reputation check warning: {str(e)}')

        # ── Build Graph (if domain found) ─────────────────────────
        graph_score = 0.0
        if domain:
            try:
                from graph_engine.graph_builder import build_scan_graph
                build_scan_graph(user_id=user_id, domain=domain, email=email_text[:50])
            except Exception as e:
                print(f'Graph build warning: {str(e)}')

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
            'input_type': 'EMAIL',
            'input_value': email_text[:500],  # Truncate for storage
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
            'score_breakdown': risk_result['score_breakdown'],
            'confidence': risk_result['confidence'],
            'timestamp': timestamp,
        }

        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps(response_body)
        }

    except Exception as e:
        print(f'Error in scan_email: {traceback.format_exc()}')
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }
