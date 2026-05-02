"""
scan_qr.py – Lambda Handler for QR Code Scanning

Endpoint: POST /api/v1/scan-qr
Decodes QR codes and delegates URL analysis to scan_url logic.
"""

import json
import os
import uuid
import traceback
from datetime import datetime, timezone
from urllib.parse import urlparse


def lambda_handler(event, context):
    """
    AWS Lambda handler for QR code scanning.

    Request Body:
        {
            "user_id": "string",
            "image_base64": "string"
        }

    Process:
        1. Decode QR code from base64 image
        2. Extract URL from decoded data
        3. Run URL scanning internally

    Response:
        Same as /scan-url response with additional qr_data field
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
        image_base64 = body.get('image_base64', '')

        if not image_base64:
            return {
                'statusCode': 400,
                'headers': headers,
                'body': json.dumps({'error': 'image_base64 is required'})
            }

        # ── Decode QR Code ────────────────────────────────────────
        from threat_modules.qr_decoder import decode_qr
        qr_result = decode_qr(image_base64)

        if not qr_result['success']:
            return {
                'statusCode': 400,
                'headers': headers,
                'body': json.dumps({
                    'error': 'QR decode failed',
                    'message': qr_result.get('error', 'Could not decode QR code')
                })
            }

        extracted_url = qr_result.get('url')
        raw_data = qr_result.get('raw_data', '')

        if not extracted_url:
            return {
                'statusCode': 400,
                'headers': headers,
                'body': json.dumps({
                    'error': 'No URL found in QR code',
                    'raw_data': raw_data
                })
            }

        # ── Extract domain ────────────────────────────────────────
        try:
            parsed = urlparse(extracted_url if '://' in extracted_url else f'http://{extracted_url}')
            domain = parsed.netloc or parsed.path.split('/')[0]
        except Exception:
            domain = extracted_url

        # ── Run URL Analysis (same as scan_url) ───────────────────
        from threat_modules.url_analyzer import analyze_url
        analysis = analyze_url(extracted_url)

        # ── Check Reputation ──────────────────────────────────────
        from threat_modules.reputation_checker import get_combined_reputation
        reputation_score = get_combined_reputation(domain)

        # ── Build Graph ───────────────────────────────────────────
        try:
            from graph_engine.graph_builder import build_scan_graph
            build_scan_graph(user_id=user_id, domain=domain)
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
            'input_type': 'QR',
            'input_value': extracted_url,
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
            'extracted_url': extracted_url,
            'qr_raw_data': raw_data,
            'timestamp': timestamp,
        }

        return {
            'statusCode': 200,
            'headers': headers,
            'body': json.dumps(response_body)
        }

    except Exception as e:
        print(f'Error in scan_qr: {traceback.format_exc()}')
        return {
            'statusCode': 500,
            'headers': headers,
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }
