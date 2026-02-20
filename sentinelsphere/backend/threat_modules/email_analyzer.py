"""
email_analyzer.py – Email Phishing Analysis Module

Analyzes email text for phishing indicators using NLP features and ML scoring.
"""

from utils.feature_extractor import extract_email_features, generate_email_explanations
from utils.ml_model import predict_email_threat


def analyze_email(email_text: str) -> dict:
    """
    Perform comprehensive email phishing analysis.

    Args:
        email_text: The raw email text content to analyze

    Returns:
        dict with keys:
            - ml_score (float): ML model phishing probability (0-1)
            - rule_based_score (float): Rule-based phishing score (0-1)
            - features (dict): Extracted email features
            - explanations (list): Human-readable phishing indicators
    """
    # ── Extract features ──────────────────────────────────────────
    features = extract_email_features(email_text)

    # ── ML-based scoring ──────────────────────────────────────────
    ml_score = predict_email_threat(features)

    # ── Rule-based scoring ────────────────────────────────────────
    rule_based_score = _compute_rule_based_score(features)

    # ── Generate explanations ─────────────────────────────────────
    explanations = generate_email_explanations(features)

    return {
        'ml_score': ml_score,
        'rule_based_score': rule_based_score,
        'features': features,
        'explanations': explanations,
    }


def _compute_rule_based_score(features: dict) -> float:
    """
    Compute a rule-based phishing score from email features.

    Returns:
        float: normalized score between 0.0 (safe) and 1.0 (phishing)
    """
    score = 0.0
    max_score = 10.0

    # Urgency keywords
    urgency = features.get('urgency_keywords_count', 0)
    if urgency >= 4:
        score += 2.5
    elif urgency >= 2:
        score += 1.5
    elif urgency >= 1:
        score += 0.5

    # Financial terms
    financial = features.get('financial_terms_count', 0)
    if financial >= 3:
        score += 2.0
    elif financial >= 1:
        score += 1.0

    # Sender domain mismatch
    if features.get('sender_domain_match', 1) == 0:
        score += 2.5

    # Reply-to mismatch
    if features.get('reply_to_mismatch', 0) == 1:
        score += 2.0

    # Excessive exclamation marks
    excl_freq = features.get('exclamation_frequency', 0)
    if excl_freq > 0.05:
        score += 1.5
    elif excl_freq > 0.02:
        score += 0.5

    # Too many URLs
    url_count = features.get('url_count', 0)
    if url_count > 5:
        score += 1.5
    elif url_count > 3:
        score += 0.5

    # High caps ratio
    caps = features.get('caps_ratio', 0)
    if caps > 0.5:
        score += 1.5
    elif caps > 0.3:
        score += 0.5

    # Suspicious attachment mention
    if features.get('suspicious_attachment_mention', 0) > 0:
        score += 1.5

    return round(min(score / max_score, 1.0), 4)
