"""
Context Analyzer — Layer 2 of the TRUSTLENS multi-signal detection pipeline.

This module evaluates the *relationships* between already-detected signals rather
than matching new phrases independently.  It never modifies the base risk score
produced by compute_score(); instead it returns:

  - A list of named context combination patterns that fired.
  - A bonus score (always non-negative) that is added on top of the base score
    before final clamping to 100.
  - Narrative explanations for each combination.

The bonus weights are intentionally modest so that a single base-category match
alone does not escalate risk; only meaningful co-occurrence clusters trigger a bonus.

Sender identity mismatch analysis is also centralised here.
"""

from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Combination rules
# Each entry defines:
#   required   — categories that MUST ALL be present
#   bonus      — score points added to the base score (on top of category weights)
#   name       — short machine-readable identifier
#   narrative  — human-readable explanation of why the combination is dangerous
# ---------------------------------------------------------------------------
COMBINATION_RULES: list[dict[str, Any]] = [
    {
        "name": "credential_theft_cluster",
        "required": {"sensitive_info", "account_threat"},
        "bonus": 15,
        "narrative": (
            "The message combines a credential request (OTP / password / PIN) with an account-threat message. "
            "This co-occurrence is a strong indicator of credential-theft phishing: the threat creates panic "
            "while the credential request harvests the secret."
        ),
    },
    {
        "name": "high_pressure_credential_theft",
        "required": {"sensitive_info", "account_threat", "urgency"},
        "bonus": 10,
        "narrative": (
            "An OTP/credential request is combined with an account threat AND urgency language. "
            "Scammers stack multiple pressure techniques to prevent the recipient from pausing to verify."
        ),
    },
    {
        "name": "bank_impersonation_with_credentials",
        "required": {"financial_impersonation", "sensitive_info"},
        "bonus": 12,
        "narrative": (
            "A financial/KYC impersonation claim is combined with a request for banking credentials. "
            "This pattern is consistent with bank-impersonation phishing aimed at account takeover."
        ),
    },
    {
        "name": "job_payment_scam",
        "required": {"job_reward", "upfront_payment"},
        "bonus": 5,
        "narrative": (
            "A guaranteed job or easy-income lure is combined with an upfront fee request. "
            "Legitimate employers never require a registration or processing fee before employment."
        ),
    },
    {
        "name": "prize_payment_scam",
        "required": {"reward_scam", "upfront_payment"},
        "bonus": 5,
        "narrative": (
            "An unsolicited prize or lottery claim is paired with a payment request. "
            "Authentic prize programmes never require a fee to release winnings."
        ),
    },
    {
        "name": "prize_shortener_scam",
        "required": {"reward_scam", "suspicious_url"},
        "bonus": 5,
        "narrative": (
            "A prize claim is combined with a suspicious or shortened URL. "
            "Shortened links in prize messages hide the true destination to harvest personal information."
        ),
    },
    {
        "name": "government_impersonation_with_payment",
        "required": {"government_impersonation", "upfront_payment"},
        "bonus": 8,
        "narrative": (
            "A government benefit or grant claim is combined with a processing-fee request. "
            "Real government schemes never charge a fee before releasing a benefit."
        ),
    },
    {
        "name": "account_suspension_with_verification_link",
        "required": {"account_threat", "account_verification", "suspicious_url"},
        "bonus": 12,
        "narrative": (
            "An account-suspension threat is paired with a verification request and a suspicious link. "
            "This three-signal cluster is a hallmark of phishing: the threat drives urgency, the "
            "verification request provides a pretext, and the suspicious link is the attack vector."
        ),
    },
    {
        "name": "time_pressure_credential_demand",
        "required": {"time_pressure", "sensitive_info"},
        "bonus": 8,
        "narrative": (
            "A short, specific deadline is combined with a credential request. "
            "Extreme time pressure is used to stop recipients from thinking critically before handing over secrets."
        ),
    },
    {
        "name": "triple_pressure_attack",
        "required": {"account_threat", "time_pressure", "sensitive_info"},
        "bonus": 15,
        "narrative": (
            "Account threat, time pressure, and a credential request all appear together. "
            "This triple-pressure cluster is one of the strongest indicators of credential-theft phishing."
        ),
    },
]


# ---------------------------------------------------------------------------
# Sender identity analysis
# ---------------------------------------------------------------------------

# Keywords that suggest a message claims to be from a bank or financial institution
_BANK_CLAIM_PATTERNS = re.compile(
    r"\b(?:bank|sbi|hdfc|icici|axis|kotak|pnb|canara|union bank|yes bank|"
    r"indusind|rbl|federal bank|idbi|uco|boi|bob)\b|बैंक|बैंकिंग|ಬ್ಯಾಂಕ್",
    re.IGNORECASE,
)

# Keywords that suggest a government body
_GOV_CLAIM_PATTERNS = re.compile(
    r"\b(?:government|ministry|department|irdai|sebi|rbi|trai|epfo|uidai|"
    r"income.?tax|gst|nsdl|cdsl|nic|nhpc|ongc|bsnl|railway|police)\b|"
    r"सरकार|सरकारी|मंत्रालय|विभाग|ಸರ್ಕಾರ|ಸರ್ಕಾರಿ|ಸಚಿವಾಲಯ|ಇಲಾಖೆ",
    re.IGNORECASE,
)

# Known legitimate TLDs / domain markers for banks (non-exhaustive list of real patterns)
_LEGITIMATE_BANK_DOMAINS = {
    "sbi.co.in", "onlinesbi.com", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "kotakbank.com", "pnbindia.in", "canarabank.com",
    "unionbankofindia.com", "yesbank.in", "indusind.com", "rblbank.com",
    "federalbank.co.in", "idbi.com", "ucobank.com", "bankofbaroda.in",
}

_LEGITIMATE_GOV_DOMAINS = {
    "gov.in", "nic.in", "india.gov.in", "mygov.in", "incometax.gov.in",
    "gst.gov.in", "epfindia.gov.in", "uidai.gov.in", "trai.gov.in",
    "sebi.gov.in", "rbi.org.in",
}

_BANK_BRAND_DOMAINS = {
    "sbi": {"sbi.co.in", "onlinesbi.com"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "axis": {"axisbank.com"},
    "kotak": {"kotakbank.com"},
    "pnb": {"pnbindia.in"},
    "canara": {"canarabank.com"},
    "union bank": {"unionbankofindia.com"},
    "yes bank": {"yesbank.in"},
    "indusind": {"indusind.com"},
    "rbl": {"rblbank.com"},
    "federal bank": {"federalbank.co.in"},
    "idbi": {"idbi.com"},
    "uco": {"ucobank.com"},
    "bank of baroda": {"bankofbaroda.in"},
}


def _extract_email_domain(sender_email: str | None) -> str | None:
    if not sender_email:
        return None
    match = re.search(r"@([\w.\-]+)", sender_email)
    return match.group(1).lower() if match else None


def _domain_looks_legitimate(domain: str, legitimate_domains: set[str]) -> bool:
    """Return True if the domain ends with any known legitimate suffix."""
    domain = domain.lower()
    return any(domain == d or domain.endswith("." + d) for d in legitimate_domains)


def _claimed_bank_domains(claim: str) -> set[str]:
    normalized_claim = claim.casefold()
    for brand, domains in _BANK_BRAND_DOMAINS.items():
        if re.search(rf"\b{re.escape(brand)}\b", normalized_claim):
            return domains
    return _LEGITIMATE_BANK_DOMAINS


def analyze_sender_identity(
    message: str,
    sender_name: str | None,
    sender_email: str | None,
    detected_categories: set[str],
    claimed_organization: str | None = None,
) -> dict[str, Any]:
    """
    Evaluate sender identity signals.

    Returns a dict with:
      is_suspicious  — bool
      reasons        — list[str]
      bonus          — int (additional score points)
      indicators     — list[str] (machine-readable tags)
    """
    reasons: list[str] = []
    indicators: list[str] = []
    bonus = 0

    email_domain = _extract_email_domain(sender_email)

    # --- Check: claimed bank identity with mismatched sender domain ---
    organization_claim = claimed_organization or ""
    message_claims_bank = bool(
        _BANK_CLAIM_PATTERNS.search(f"{message} {organization_claim}")
        or {"financial_impersonation", "bank_impersonation"} & detected_categories
    )
    sender_claims_bank = bool(
        _BANK_CLAIM_PATTERNS.search(sender_name or "")
        or _BANK_CLAIM_PATTERNS.search(sender_email or "")
    )

    if message_claims_bank or sender_claims_bank:
        claimed_bank_text = f"{message} {organization_claim} {sender_name or ''}"
        accepted_domains = _claimed_bank_domains(claimed_bank_text)
        if email_domain and not _domain_looks_legitimate(email_domain, accepted_domains):
            reasons.append(
                f"The message or sender claims a bank identity, but the sender email domain "
                f"'{email_domain}' does not match the known domain pattern for that claim. "
                "This is a common impersonation signal."
            )
            indicators.append("bank_domain_mismatch")
            bonus += 10

    # --- Check: claimed government identity with mismatched sender domain ---
    message_claims_gov = bool(
        _GOV_CLAIM_PATTERNS.search(f"{message} {organization_claim}")
        or "government_impersonation" in detected_categories
    )
    sender_claims_gov = bool(
        _GOV_CLAIM_PATTERNS.search(sender_name or "")
        or _GOV_CLAIM_PATTERNS.search(sender_email or "")
    )

    if message_claims_gov or sender_claims_gov:
        if email_domain and not _domain_looks_legitimate(email_domain, _LEGITIMATE_GOV_DOMAINS):
            reasons.append(
                f"The message or sender claims to represent a government body, but the sender email domain "
                f"'{email_domain}' does not match any known government domain (.gov.in / .nic.in). "
                "Verify the sender through the official agency website before acting."
            )
            indicators.append("gov_domain_mismatch")
            bonus += 8

    return {
        "is_suspicious": bool(reasons),
        "reasons": reasons,
        "bonus": bonus,
        "indicators": indicators,
    }


# ---------------------------------------------------------------------------
# Main context analysis function
# ---------------------------------------------------------------------------

def analyze_context(
    detected_categories: list[str],
    message: str,
    sender_name: str | None,
    sender_email: str | None,
    claimed_organization: str | None = None,
) -> dict[str, Any]:
    """
    Layer 2: Context Analysis.

    Evaluates relationships between already-detected signal categories and
    returns combination patterns, bonuses, and narrative explanations.

    Args:
        detected_categories: List of category names returned by compute_score().
        message: The original (unnormalized) message text.
        sender_name: Optional sender display name.
        sender_email: Optional sender email address.

    Returns:
        dict with keys:
          combinations        — list of combination pattern dicts that fired
          context_bonus       — total bonus score from combinations + sender identity
          context_narratives  — list of human-readable combination explanations
          sender_analysis     — dict from analyze_sender_identity()
    """
    category_set = set(detected_categories)
    fired_combinations: list[dict[str, Any]] = []
    total_bonus = 0
    narratives: list[str] = []

    for rule in COMBINATION_RULES:
        if rule["required"].issubset(category_set):
            fired_combinations.append({
                "name": rule["name"],
                "triggered_by": sorted(rule["required"]),
                "bonus": rule["bonus"],
                "narrative": rule["narrative"],
            })
            narratives.append(rule["narrative"])

    if fired_combinations:
        applied_combination = max(fired_combinations, key=lambda combo: combo["bonus"])
        total_bonus = applied_combination["bonus"]
        for combination in fired_combinations:
            combination["points_contributed"] = (
                combination["bonus"] if combination is applied_combination else 0
            )
            combination["bonus_applied"] = combination is applied_combination

    sender_analysis = analyze_sender_identity(
        message, sender_name, sender_email, category_set, claimed_organization
    )
    total_bonus += sender_analysis["bonus"]
    narratives.extend(sender_analysis["reasons"])

    return {
        "combinations": fired_combinations,
        "context_bonus": total_bonus,
        "context_narratives": narratives,
        "sender_analysis": sender_analysis,
    }
