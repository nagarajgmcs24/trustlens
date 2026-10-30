from typing import Iterable

CATEGORY_WEIGHTS = {
    "account_threat": 30,
    "urgency": 10,
    "time_pressure": 12,
    "sensitive_info": 30,
    "financial_impersonation": 18,
    "account_verification": 15,
    "government_impersonation": 20,
    "job_reward": 15,
    "upfront_payment": 25,
    "reward_scam": 15,
    "suspicious_url": 15,
    "impersonation": 15,
    "payment_request": 20,
    "other_suspicious": 10,
}


def classify_risk(score: int) -> str:
    if score <= 29:
        return "LOW RISK"
    if score <= 59:
        return "MEDIUM RISK"
    return "HIGH RISK"


def compute_score(evidence: Iterable[dict]) -> tuple[int, list[str], list[str]]:
    score = 0
    reasons: list[str] = []
    categories: list[str] = []
    category_weights: dict[str, int] = {}

    for signal in evidence:
        category = signal.get("category")
        weight = max(0, int(signal.get("weight", 0)))
        if category:
            category_weights[category] = max(category_weights.get(category, 0), weight)
        reason = signal.get("reason")
        if reason:
            reasons.append(reason)
        if category and category not in categories:
            categories.append(category)

    score = sum(category_weights.values())
    final_score = min(score, 100)
    return final_score, reasons, categories
