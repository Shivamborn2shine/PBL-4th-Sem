"""
feature_extractor.py – URL & Email Feature Extraction Module

Extracts numerical features from URLs and email text for ML-based threat scoring.
"""

import re
import hashlib
from urllib.parse import urlparse
from datetime import datetime


# ─── Suspicious keyword lists ────────────────────────────────────────────────
SUSPICIOUS_URL_KEYWORDS = [
    'login', 'verify', 'update', 'secure', 'account', 'banking',
    'confirm', 'password', 'suspend', 'alert', 'urgent', 'click',
    'free', 'winner', 'prize', 'offer', 'deal', 'limited',
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix',
    'signin', 'security', 'authenticate', 'wallet', 'crypto'
]

URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'asap', 'right now', 'within 24 hours',
    'expires', 'deadline', 'act now', 'don\'t delay', 'hurry',
    'final notice', 'last chance', 'time sensitive', 'respond now',
    'action required', 'important notice', 'warning', 'alert'
]

FINANCIAL_TERMS = [
    'bank', 'account', 'credit card', 'debit card', 'payment',
    'transfer', 'wire', 'deposit', 'withdrawal', 'balance',
    'invoice', 'billing', 'transaction', 'refund', 'tax',
    'irs', 'social security', 'ssn', 'routing number', 'pin'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw',
    '.cc', '.click', '.link', '.info', '.buzz', '.work', '.party'
]


def extract_url_features(url: str) -> dict:
    """
    Extract numerical features from a URL for ML-based threat analysis.

    Returns:
        dict with keys: domain_age_days, url_length, num_dots, contains_at,
        contains_suspicious_words, https_status, ip_reputation_score,
        num_subdomains, has_ip_address, path_length, num_params,
        suspicious_tld, url_entropy
    """
    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
    except Exception:
        parsed = urlparse(f'http://{url}')

    domain = parsed.netloc or parsed.path.split('/')[0]
    path = parsed.path or ''

    # ── Core features ──────────────────────────────────────────────
    url_length = len(url)
    num_dots = url.count('.')
    contains_at = 1 if '@' in url else 0
    https_status = 1 if parsed.scheme == 'https' else 0

    # ── Suspicious word detection ──────────────────────────────────
    url_lower = url.lower()
    suspicious_word_count = sum(1 for kw in SUSPICIOUS_URL_KEYWORDS if kw in url_lower)
    contains_suspicious_words = min(suspicious_word_count / 5.0, 1.0)

    # ── Domain analysis ────────────────────────────────────────────
    num_subdomains = max(0, domain.count('.') - 1)
    has_ip_address = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain) else 0

    # ── Path & query analysis ──────────────────────────────────────
    path_length = len(path)
    num_params = len(parsed.query.split('&')) if parsed.query else 0

    # ── TLD suspicion ──────────────────────────────────────────────
    suspicious_tld = 0
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            suspicious_tld = 1
            break

    # ── URL entropy (randomness indicator) ─────────────────────────
    url_entropy = _calculate_entropy(url)

    # ── Domain age (simulated – in production use WHOIS) ───────────
    domain_hash = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)
    domain_age_days = domain_hash % 3650  # Simulated 0-10 years

    # ── IP reputation (simulated) ──────────────────────────────────
    ip_reputation_score = _simulate_ip_reputation(domain)

    return {
        'domain_age_days': domain_age_days,
        'url_length': url_length,
        'num_dots': num_dots,
        'contains_at': contains_at,
        'contains_suspicious_words': contains_suspicious_words,
        'https_status': https_status,
        'ip_reputation_score': ip_reputation_score,
        'num_subdomains': num_subdomains,
        'has_ip_address': has_ip_address,
        'path_length': path_length,
        'num_params': num_params,
        'suspicious_tld': suspicious_tld,
        'url_entropy': url_entropy,
    }


def extract_email_features(email_text: str) -> dict:
    """
    Extract numerical features from email text for ML-based phishing analysis.

    Returns:
        dict with keys: urgency_keywords_count, financial_terms_count,
        sender_domain_match, reply_to_mismatch, exclamation_frequency,
        url_count, email_length, caps_ratio, suspicious_attachment_mention
    """
    text_lower = email_text.lower()

    # ── Keyword counts ─────────────────────────────────────────────
    urgency_keywords_count = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
    financial_terms_count = sum(1 for kw in FINANCIAL_TERMS if kw in text_lower)

    # ── Sender domain analysis ─────────────────────────────────────
    sender_domain_match = _check_sender_domain(email_text)
    reply_to_mismatch = _check_reply_to_mismatch(email_text)

    # ── Text features ──────────────────────────────────────────────
    exclamation_frequency = email_text.count('!') / max(len(email_text), 1)
    url_count = len(re.findall(r'https?://\S+', email_text))
    email_length = len(email_text)

    # ── Caps ratio ─────────────────────────────────────────────────
    alpha_chars = [c for c in email_text if c.isalpha()]
    caps_ratio = sum(1 for c in alpha_chars if c.isupper()) / max(len(alpha_chars), 1)

    # ── Suspicious attachment mentions ─────────────────────────────
    attachment_keywords = ['attachment', 'attached', 'download', 'open file', 'see attached']
    suspicious_attachment_mention = sum(1 for kw in attachment_keywords if kw in text_lower)

    return {
        'urgency_keywords_count': urgency_keywords_count,
        'financial_terms_count': financial_terms_count,
        'sender_domain_match': sender_domain_match,
        'reply_to_mismatch': reply_to_mismatch,
        'exclamation_frequency': exclamation_frequency,
        'url_count': url_count,
        'email_length': email_length,
        'caps_ratio': caps_ratio,
        'suspicious_attachment_mention': suspicious_attachment_mention,
    }


def generate_url_explanations(features: dict) -> list:
    """Generate human-readable explanations from URL features."""
    explanations = []

    if features.get('domain_age_days', 365) < 30:
        explanations.append('Domain age less than 30 days')
    if features.get('ip_reputation_score', 0) > 0.5:
        explanations.append('IP flagged in abuse database')
    if features.get('contains_suspicious_words', 0) > 0.3:
        explanations.append('Suspicious keyword detected in URL')
    if features.get('contains_at', 0) == 1:
        explanations.append('URL contains @ symbol (potential redirect)')
    if features.get('has_ip_address', 0) == 1:
        explanations.append('URL uses IP address instead of domain name')
    if features.get('https_status', 1) == 0:
        explanations.append('Connection not secured with HTTPS')
    if features.get('suspicious_tld', 0) == 1:
        explanations.append('Domain uses suspicious top-level domain')
    if features.get('url_length', 0) > 100:
        explanations.append('Unusually long URL detected')
    if features.get('num_subdomains', 0) > 3:
        explanations.append('Excessive subdomains detected')
    if features.get('url_entropy', 0) > 4.5:
        explanations.append('High randomness in URL (potential obfuscation)')

    return explanations if explanations else ['No specific threat indicators found']


def generate_email_explanations(features: dict) -> list:
    """Generate human-readable explanations from email features."""
    explanations = []

    if features.get('urgency_keywords_count', 0) > 2:
        explanations.append('Multiple urgency keywords detected')
    elif features.get('urgency_keywords_count', 0) > 0:
        explanations.append('Urgency keyword detected')

    if features.get('financial_terms_count', 0) > 2:
        explanations.append('Multiple financial terms detected')
    elif features.get('financial_terms_count', 0) > 0:
        explanations.append('Financial terminology detected')

    if features.get('sender_domain_match', 0) == 0:
        explanations.append('Sender domain mismatch detected')
    if features.get('reply_to_mismatch', 0) == 1:
        explanations.append('Reply-to address differs from sender')
    if features.get('exclamation_frequency', 0) > 0.02:
        explanations.append('Excessive exclamation marks detected')
    if features.get('caps_ratio', 0) > 0.4:
        explanations.append('Excessive use of capital letters')
    if features.get('url_count', 0) > 3:
        explanations.append('Multiple URLs embedded in email')
    if features.get('suspicious_attachment_mention', 0) > 0:
        explanations.append('Suspicious attachment referenced')

    return explanations if explanations else ['No specific phishing indicators found']


# ─── Private helper functions ─────────────────────────────────────────────────

def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (measures randomness)."""
    import math
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 4)


def _simulate_ip_reputation(domain: str) -> float:
    """
    Simulate IP reputation score (0 = clean, 1 = malicious).
    In production, this would query real threat intelligence APIs.
    """
    domain_hash = int(hashlib.md5(domain.encode()).hexdigest()[:4], 16)
    # Generate a deterministic score based on domain hash
    score = (domain_hash % 100) / 100.0
    return round(score, 2)


def _check_sender_domain(email_text: str) -> int:
    """
    Check if sender domain matches the claimed organization.
    Returns 1 if match (safe), 0 if mismatch (suspicious).
    """
    # Look for From: header pattern
    from_match = re.search(r'[Ff]rom:\s*.*?@(\S+)', email_text)
    if not from_match:
        return 1  # No From header found, assume neutral

    sender_domain = from_match.group(1).lower().strip('>')

    # Check if well-known brands are mentioned but sent from different domain
    brand_domains = {
        'paypal': 'paypal.com', 'apple': 'apple.com',
        'google': 'google.com', 'microsoft': 'microsoft.com',
        'amazon': 'amazon.com', 'netflix': 'netflix.com',
        'bank': 'bank.com',
    }

    text_lower = email_text.lower()
    for brand, official_domain in brand_domains.items():
        if brand in text_lower and official_domain not in sender_domain:
            return 0  # Brand mentioned but sent from different domain

    return 1


def _check_reply_to_mismatch(email_text: str) -> int:
    """
    Check if Reply-To differs from From address.
    Returns 1 if mismatch (suspicious), 0 if match or not present.
    """
    from_match = re.search(r'[Ff]rom:\s*.*?@(\S+)', email_text)
    reply_match = re.search(r'[Rr]eply-[Tt]o:\s*.*?@(\S+)', email_text)

    if from_match and reply_match:
        from_domain = from_match.group(1).lower().strip('>')
        reply_domain = reply_match.group(1).lower().strip('>')
        return 0 if from_domain == reply_domain else 1

    return 0  # No Reply-To header, assume OK
