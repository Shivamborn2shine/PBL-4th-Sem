"""
risk_calculator.py – Risk Scoring Engine

Combines ML, reputation, graph intelligence, and rule-based scores
into a final risk assessment using a weighted formula.
"""


# ─── Risk Level Thresholds ────────────────────────────────────────────────────
RISK_THRESHOLDS = {
    'SAFE': (0.0, 0.3),
    'SUSPICIOUS': (0.3, 0.6),
    'HIGH': (0.6, 1.0),
}

# ─── Score Weights ────────────────────────────────────────────────────────────
WEIGHTS = {
    'ml_score': 0.4,
    'reputation_score': 0.2,
    'graph_score': 0.2,
    'rule_based_score': 0.2,
}


def calculate_risk(
    ml_score: float,
    reputation_score: float,
    graph_score: float,
    rule_based_score: float
) -> dict:
    """
    Calculate the final risk score using weighted combination.

    Formula:
        final_score = (ml_score * 0.4) + (reputation_score * 0.2) +
                      (graph_score * 0.2) + (rule_based_score * 0.2)

    Args:
        ml_score: Machine learning model probability (0-1)
        reputation_score: Domain/IP reputation score (0-1)
        graph_score: Graph intelligence suspicion score (0-1)
        rule_based_score: Rule-based analysis score (0-1)

    Returns:
        dict with:
            - risk_score (float): Final weighted score (0-1)
            - risk_level (str): 'SAFE', 'SUSPICIOUS', or 'HIGH'
            - score_breakdown (dict): Individual score components
            - confidence (float): Confidence in the assessment
    """
    # ── Clamp all inputs to [0, 1] ────────────────────────────────
    ml_score = max(0.0, min(1.0, float(ml_score)))
    reputation_score = max(0.0, min(1.0, float(reputation_score)))
    graph_score = max(0.0, min(1.0, float(graph_score)))
    rule_based_score = max(0.0, min(1.0, float(rule_based_score)))

    # ── Weighted combination ──────────────────────────────────────
    final_score = (
        (ml_score * WEIGHTS['ml_score']) +
        (reputation_score * WEIGHTS['reputation_score']) +
        (graph_score * WEIGHTS['graph_score']) +
        (rule_based_score * WEIGHTS['rule_based_score'])
    )
    final_score = round(max(0.0, min(1.0, final_score)), 4)

    # ── Classify risk level ───────────────────────────────────────
    risk_level = classify_risk(final_score)

    # ── Compute confidence ────────────────────────────────────────
    confidence = _compute_confidence(ml_score, reputation_score, graph_score, rule_based_score)

    return {
        'risk_score': final_score,
        'risk_level': risk_level,
        'score_breakdown': {
            'ml_score': round(ml_score, 4),
            'reputation_score': round(reputation_score, 4),
            'graph_score': round(graph_score, 4),
            'rule_based_score': round(rule_based_score, 4),
        },
        'weights': WEIGHTS,
        'confidence': confidence,
    }


def classify_risk(score: float) -> str:
    """
    Classify a risk score into a risk level.

    Args:
        score: Risk score (0-1)

    Returns:
        str: 'SAFE' (0-0.3), 'SUSPICIOUS' (0.3-0.6), or 'HIGH' (0.6+)
    """
    score = max(0.0, min(1.0, float(score)))

    if score < 0.3:
        return 'SAFE'
    elif score < 0.6:
        return 'SUSPICIOUS'
    else:
        return 'HIGH'


def _compute_confidence(ml_score, reputation_score, graph_score, rule_based_score) -> float:
    """
    Compute confidence in the risk assessment.
    Higher agreement between scores = higher confidence.

    Returns:
        float: Confidence score (0-1)
    """
    scores = [ml_score, reputation_score, graph_score, rule_based_score]

    # Standard deviation of scores (lower = more agreement)
    mean_score = sum(scores) / len(scores)
    variance = sum((s - mean_score) ** 2 for s in scores) / len(scores)
    std_dev = variance ** 0.5

    # Convert: low std_dev → high confidence
    # std_dev of 0 = perfect agreement = confidence 1.0
    # std_dev of 0.5 = max disagreement = confidence ~0.0
    confidence = max(0.0, 1.0 - (std_dev * 2.0))

    return round(confidence, 4)


def get_risk_summary(risk_result: dict) -> str:
    """
    Generate a human-readable risk summary.

    Args:
        risk_result: Output from calculate_risk()

    Returns:
        str: Summary text
    """
    level = risk_result['risk_level']
    score = risk_result['risk_score']
    confidence = risk_result['confidence']

    summaries = {
        'SAFE': f'Low risk detected (score: {score:.2f}). No significant threats identified. Confidence: {confidence:.0%}',
        'SUSPICIOUS': f'Medium risk detected (score: {score:.2f}). Some threat indicators present. Proceed with caution. Confidence: {confidence:.0%}',
        'HIGH': f'High risk detected (score: {score:.2f}). Multiple threat indicators flagged. Avoid interaction. Confidence: {confidence:.0%}',
    }

    return summaries.get(level, f'Risk score: {score:.2f} ({level})')
