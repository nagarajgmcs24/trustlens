"""
URL Analyzer — Layer 1 signal extraction for suspicious URLs.

Checks for:
  - HTTP (unencrypted) connections
  - URL shortener services (expanded list)
  - IP-address destinations
  - Suspicious userinfo patterns
  - Deceptive domain keyword combinations
  - Excessive subdomain depth (obfuscation)
  - Homograph / punycode domain abuse
  - Numeric-heavy domain names (generated domains)
  - Malformed / incomplete URL structure
"""

import re
from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "tiny.cc",
    "buff.ly",
    "lnkd.in",
    "rebrand.ly",
    "cutt.ly",
    # Extended list — common shorteners encountered in phishing campaigns
    "shorte.st",
    "adf.ly",
    "bc.vc",
    "sh.st",
    "clck.ru",
    "shrinkme.io",
    "ouo.io",
    "za.gl",
    "rb.gy",
    "shorturl.at",
    "tinycc.com",
    "urlshort.in",
    "v.gd",
    "x.co",
    "qr.ae",
    "go2l.ink",
    "snip.ly",
}


def extract_urls(text: str) -> list[str]:
    url_pattern = re.compile(r"(?:https?:\/\/|www\.)[^\s)\]>\"]+", re.IGNORECASE)
    matches = url_pattern.findall(text)
    cleaned = []
    for match in matches:
        fixed = match.rstrip(".,;:)")
        cleaned.append(fixed)
    return cleaned


def _has_homograph_or_punycode(domain: str) -> bool:
    """Detect punycode-encoded domains (potential homograph attacks)."""
    labels = domain.split(".")
    return any(label.startswith("xn--") for label in labels)


def _is_numeric_heavy_domain(registered_label: str) -> bool:
    """Flag domains where more than half the registered-label chars are digits."""
    if not registered_label:
        return False
    digits = sum(c.isdigit() for c in registered_label)
    return digits / len(registered_label) > 0.5


def _count_subdomains(hostname: str) -> int:
    """Count subdomain levels (parts above the registered domain + TLD)."""
    parts = hostname.rstrip(".").split(".")
    # registered_label is parts[-2], TLD is parts[-1]; anything above is subdomains
    return max(0, len(parts) - 2)


def analyze_url(url: str) -> dict:
    normalized_url = url.strip()
    if not normalized_url:
        return {"url": normalized_url, "is_suspicious": False, "reasons": []}

    if not normalized_url.startswith(("http://", "https://")):
        normalized_url = "https://" + normalized_url

    parsed = urlparse(normalized_url)
    domain = parsed.netloc.lower().replace("www.", "")
    # Strip port for domain matching
    hostname = domain.rsplit(":", 1)[0]
    reasons: list[str] = []
    suspicious = False

    # 1. HTTP (unencrypted)
    if parsed.scheme.lower() == "http":
        reasons.append("URL uses HTTP instead of HTTPS, which is a caution signal.")
        suspicious = True

    # 2. Known URL shorteners (exact domain match only — no suffix tricks)
    if any(hostname == shortener or hostname.endswith("." + shortener) for shortener in SHORTENERS):
        reasons.append("URL uses a URL shortener commonly used to hide the real destination.")
        suspicious = True

    # 3. IP-address destination
    if re.search(r"\d+\.\d+\.\d+\.\d+", hostname):
        reasons.append("URL uses an IP address instead of a normal domain name.")
        suspicious = True

    # 4. Suspicious userinfo (@ in domain portion)
    if "@" in domain:
        reasons.append("URL contains a suspicious userinfo pattern that can confuse users.")
        suspicious = True

    # 5. Deceptive keyword combination in registered label
    host_labels = hostname.split(".")
    registered_label = host_labels[-2] if len(host_labels) >= 2 else host_labels[0]
    deceptive_host_terms = {"account", "bank", "confirm", "login", "secure", "update", "verify"}
    host_tokens = set(re.split(r"[-_]", registered_label))
    high_risk_host_terms = host_tokens & deceptive_host_terms
    if len(high_risk_host_terms) >= 2:
        reasons.append(
            "Domain combines account-security or verification terms in its registered name."
        )
        suspicious = True

    # 6. Excessive subdomains (≥ 3 subdomain levels suggest obfuscation)
    subdomain_count = _count_subdomains(hostname)
    if subdomain_count >= 3:
        reasons.append(
            f"URL has {subdomain_count} subdomain levels, which can be used to disguise the real domain."
        )
        suspicious = True

    # 7. Punycode / homograph domain encoding
    if _has_homograph_or_punycode(hostname):
        reasons.append(
            "URL domain uses punycode encoding (xn-- prefix), which can be used for homograph attacks "
            "where a fake domain looks visually identical to a legitimate one."
        )
        suspicious = True

    # 8. Numeric-heavy registered label (common in randomly generated phishing domains)
    if _is_numeric_heavy_domain(registered_label):
        reasons.append(
            "The registered domain name is mostly numeric, which is uncommon for legitimate organisations."
        )
        suspicious = True

    # 9. Missing netloc
    if not parsed.netloc:
        reasons.append("URL format looks incomplete or malformed.")
        suspicious = True

    return {
        "url": url,
        "domain": domain,
        "is_suspicious": suspicious,
        "reasons": reasons,
    }
