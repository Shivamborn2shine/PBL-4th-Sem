"""
reputation_checker.py – IP/Domain Reputation Scoring Module

Checks domains and IPs against known threat indicators and abuse databases.
Uses simulated checks for MVP; integrate with real APIs in production
(e.g., VirusTotal, AbuseIPDB, Google Safe Browsing).
"""

import hashlib
import re
from datetime import datetime


# ─── Known malicious indicators ──────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw',
    '.cc', '.click', '.link', '.buzz', '.work', '.party',
    '.racing', '.download', '.stream', '.gdn', '.bid', '.win'
}

KNOWN_PHISHING_KEYWORDS = {
    'paypal-verify', 'apple-id-confirm', 'account-update',
    'secure-login', 'bank-verify', 'microsoft-alert',
    'google-security', 'amazon-refund', 'netflix-payment',
    'facebook-confirm', 'instagram-verify', 'twitter-secure'
}

KNOWN_ABUSE_IP_RANGES = [
    '185.220.',  # Tor exit nodes (common abuse)
    '45.33.',    # Known scanning ranges
    '104.244.',  # Common VPN/proxy
    '192.42.',   # Tor directory
]

# Well-known safe domains (whitelist)
SAFE_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
    'apple.com', 'microsoft.com', 'github.com', 'stackoverflow.com',
    'wikipedia.org', 'twitter.com', 'linkedin.com', 'netflix.com',
    'reddit.com', 'instagram.com', 'whatsapp.com', 'zoom.us',
}


def check_domain_reputation(domain: str) -> dict:
    """
    Check domain reputation against known threat indicators.

    Args:
        domain: Domain name to check (e.g., 'example.com')

    Returns:
        dict with:
            - reputation_score (float): 0 = clean, 1 = malicious
            - indicators (list): List of flagged indicators
            - whitelisted (bool): Whether domain is in safe list
    """
    domain = domain.lower().strip()
    indicators = []
    score = 0.0

    # ── Whitelist check ───────────────────────────────────────────
    base_domain = _get_base_domain(domain)
    if base_domain in SAFE_DOMAINS:
        return {
            'reputation_score': 0.0,
            'indicators': ['Domain is whitelisted as safe'],
            'whitelisted': True
        }

    # ── Suspicious TLD check ──────────────────────────────────────
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 0.25
            indicators.append(f'Suspicious TLD: {tld}')
            break

    # ── Phishing keyword check ────────────────────────────────────
    for keyword in KNOWN_PHISHING_KEYWORDS:
        if keyword in domain:
            score += 0.35
            indicators.append(f'Phishing keyword in domain: {keyword}')
            break

    # ── Domain length analysis ────────────────────────────────────
    if len(domain) > 50:
        score += 0.15
        indicators.append('Unusually long domain name')

    # ── Excessive subdomains ──────────────────────────────────────
    subdomain_count = domain.count('.') - 1
    if subdomain_count > 3:
        score += 0.15
        indicators.append(f'Excessive subdomains ({subdomain_count})')

    # ── Numeric domain check ──────────────────────────────────────
    domain_parts = domain.split('.')
    if any(part.isdigit() for part in domain_parts[:-1]):
        score += 0.1
        indicators.append('Numeric characters in domain name')

    # ── Hyphen abuse ──────────────────────────────────────────────
    if domain.count('-') > 3:
        score += 0.1
        indicators.append('Excessive hyphens in domain')

    # ── Simulated threat intelligence lookup ──────────────────────
    ti_score = _simulate_threat_intel_lookup(domain)
    if ti_score > 0.5:
        score += ti_score * 0.3
        indicators.append('Flagged by threat intelligence')

    if not indicators:
        indicators.append('No reputation issues found')

    return {
        'reputation_score': round(min(score, 1.0), 4),
        'indicators': indicators,
        'whitelisted': False
    }


def check_ip_reputation(ip: str) -> dict:
    """
    Check IP address reputation against known abuse indicators.

    Args:
        ip: IP address string (e.g., '192.168.1.1')

    Returns:
        dict with:
            - reputation_score (float): 0 = clean, 1 = malicious
            - indicators (list): List of flagged indicators
    """
    indicators = []
    score = 0.0

    # ── Known abuse range check ───────────────────────────────────
    for abuse_range in KNOWN_ABUSE_IP_RANGES:
        if ip.startswith(abuse_range):
            score += 0.4
            indicators.append(f'IP in known abuse range: {abuse_range}*')
            break

    # ── Private IP check ──────────────────────────────────────────
    if _is_private_ip(ip):
        score += 0.1
        indicators.append('Private/internal IP address detected')

    # ── Simulated abuse database lookup ───────────────────────────
    abuse_score = _simulate_abuse_db_lookup(ip)
    if abuse_score > 0.3:
        score += abuse_score * 0.4
        indicators.append('IP flagged in abuse database')

    if not indicators:
        indicators.append('No IP reputation issues found')

    return {
        'reputation_score': round(min(score, 1.0), 4),
        'indicators': indicators
    }


def get_combined_reputation(domain: str, ip: str = None) -> float:
    """
    Get combined reputation score for a domain and optional IP.

    Returns:
        float: Combined reputation score (0-1)
    """
    domain_rep = check_domain_reputation(domain)
    domain_score = domain_rep['reputation_score']

    if ip:
        ip_rep = check_ip_reputation(ip)
        ip_score = ip_rep['reputation_score']
        # Weighted combination: domain reputation is more important
        combined = (domain_score * 0.6) + (ip_score * 0.4)
    else:
        combined = domain_score

    return round(min(combined, 1.0), 4)


# ─── Private helper functions ─────────────────────────────────────────────────

def _get_base_domain(domain: str) -> str:
    """Extract the base domain from a full domain string."""
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def _simulate_threat_intel_lookup(domain: str) -> float:
    """
    Simulate a threat intelligence API lookup.
    In production, replace with VirusTotal, Google Safe Browsing, etc.
    """
    # Deterministic score based on domain hash
    domain_hash = int(hashlib.sha256(domain.encode()).hexdigest()[:6], 16)
    return round((domain_hash % 100) / 100.0, 2)


def _simulate_abuse_db_lookup(ip: str) -> float:
    """
    Simulate an abuse database lookup (e.g., AbuseIPDB).
    In production, replace with real API calls.
    """
    ip_hash = int(hashlib.sha256(ip.encode()).hexdigest()[:6], 16)
    return round((ip_hash % 100) / 100.0, 2)


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private range."""
    private_ranges = [
        ('10.', ),
        ('172.16.', '172.17.', '172.18.', '172.19.',
         '172.20.', '172.21.', '172.22.', '172.23.',
         '172.24.', '172.25.', '172.26.', '172.27.',
         '172.28.', '172.29.', '172.30.', '172.31.'),
        ('192.168.',),
        ('127.',),
    ]
    for range_group in private_ranges:
        for prefix in range_group:
            if ip.startswith(prefix):
                return True
    return False
