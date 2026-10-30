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
}


def extract_urls(text: str) -> list[str]:
    url_pattern = re.compile(r"(?:https?:\/\/|www\.)[^\s)\]>\"]+", re.IGNORECASE)
    matches = url_pattern.findall(text)
    cleaned = []
    for match in matches:
        fixed = match.rstrip(".,;:)")
        cleaned.append(fixed)
    return cleaned


def analyze_url(url: str) -> dict:
    normalized_url = url.strip()
    if not normalized_url:
        return {"url": normalized_url, "is_suspicious": False, "reasons": []}

    if not normalized_url.startswith(("http://", "https://")):
        normalized_url = "https://" + normalized_url

    parsed = urlparse(normalized_url)
    domain = parsed.netloc.lower().replace("www.", "")
    reasons: list[str] = []
    suspicious = False

    if parsed.scheme.lower() == "http":
        reasons.append("URL uses HTTP instead of HTTPS, which is a caution signal.")
        suspicious = True

    if any(domain == shortener or domain.endswith(f".{shortener}") for shortener in SHORTENERS):
        reasons.append("URL uses a URL shortener commonly used to hide the real destination.")
        suspicious = True

    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        reasons.append("URL uses an IP address instead of a normal domain name.")
        suspicious = True

    if "@" in domain:
        reasons.append("URL contains a suspicious userinfo pattern that can confuse users.")
        suspicious = True

    hostname = domain.rsplit(":", 1)[0]
    host_labels = hostname.split(".")
    registered_label = host_labels[-2] if len(host_labels) >= 2 else host_labels[0]
    deceptive_host_terms = {
        "account",
        "bank",
        "confirm",
        "login",
        "secure",
        "update",
        "verify",
    }
    host_tokens = set(re.split(r"[-_]", registered_label))
    high_risk_host_terms = host_tokens & deceptive_host_terms
    if len(high_risk_host_terms) >= 2:
        reasons.append(
            "Domain combines account-security or verification terms in its registered name."
        )
        suspicious = True

    if not parsed.netloc:
        reasons.append("URL format looks incomplete or malformed.")
        suspicious = True

    return {
        "url": url,
        "domain": domain,
        "is_suspicious": suspicious,
        "reasons": reasons,
    }
