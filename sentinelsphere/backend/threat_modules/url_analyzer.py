"""
url_analyzer.py – URL Threat Analysis Module

Analyzes URLs for potential threats using ML-based scoring and rule-based checks.
"""

from utils.feature_extractor import extract_url_features, generate_url_explanations
from utils.ml_model import predict_url_threat


def analyze_url(url: str) -> dict:
    """
    Perform comprehensive URL threat analysis.

    Args:
        url: The URL string to analyze

    Returns:
        dict with keys:
            - ml_score (float): ML model threat probability (0-1)
            - rule_based_score (float): Rule-based threat score (0-1)
            - features (dict): Extracted URL features
            - explanations (list): Human-readable threat indicators
    """
    # ── Extract features ──────────────────────────────────────────
    features = extract_url_features(url)

    # ── ML-based scoring ──────────────────────────────────────────
    ml_score = predict_url_threat(features)

    # ── Rule-based scoring ────────────────────────────────────────
    rule_based_score = _compute_rule_based_score(features)

    # ── Generate explanations ─────────────────────────────────────
    explanations = generate_url_explanations(features)

    return {
        'ml_score': ml_score,
        'rule_based_score': rule_based_score,
        'features': features,
        'explanations': explanations,
    }


def _compute_rule_based_score(features: dict) -> float:
    """
    Compute a rule-based threat score from URL features.
    Each rule contributes a weighted penalty.

    Returns:
        float: normalized score between 0.0 (safe) and 1.0 (dangerous)
    """
    score = 0.0
    max_score = 10.0  # Maximum possible accumulated score

    # Domain age check
    domain_age = features.get('domain_age_days', 365)
    if domain_age < 7:
        score += 2.5
    elif domain_age < 30:
        score += 1.5
    elif domain_age < 90:
        score += 0.5

    # HTTPS check
    if features.get('https_status', 1) == 0:
        score += 1.5

    # IP address instead of domain
    if features.get('has_ip_address', 0) == 1:
        score += 2.0

    # Contains @ symbol
    if features.get('contains_at', 0) == 1:
        score += 1.5

    # Suspicious keywords
    suspicious_words = features.get('contains_suspicious_words', 0)
    score += suspicious_words * 2.0

    # Suspicious TLD
    if features.get('suspicious_tld', 0) == 1:
        score += 1.5

    # Excessive URL length
    url_length = features.get('url_length', 0)
    if url_length > 150:
        score += 1.5
    elif url_length > 100:
        score += 0.5

    # Excessive subdomains
    num_subdomains = features.get('num_subdomains', 0)
    if num_subdomains > 4:
        score += 1.5
    elif num_subdomains > 2:
        score += 0.5

    # High entropy
    if features.get('url_entropy', 0) > 4.5:
        score += 1.0

    # IP reputation
    ip_rep = features.get('ip_reputation_score', 0)
    if ip_rep > 0.7:
        score += 2.0
    elif ip_rep > 0.5:
        score += 1.0

    # Normalize to 0-1 range
    return round(min(score / max_score, 1.0), 4)
