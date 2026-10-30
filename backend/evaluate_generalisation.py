import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from services.detection_engine import analyze_message


DATASET_PATH = Path(__file__).parent / "tests" / "fixtures" / "generalisation_messages.json"


def _metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(case["expected_positive"] and case["predicted_positive"] for case in cases)
    tn = sum(not case["expected_positive"] and not case["predicted_positive"] for case in cases)
    fp = sum(not case["expected_positive"] and case["predicted_positive"] for case in cases)
    fn = sum(case["expected_positive"] and not case["predicted_positive"] for case in cases)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "total": len(cases),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "confusion_matrix": {
            "actual_suspicious": {
                "predicted_suspicious": tp,
                "predicted_legitimate": fn,
            },
            "actual_legitimate": {
                "predicted_suspicious": fp,
                "predicted_legitimate": tn,
            },
        },
    }


def main() -> None:
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    evaluated: list[dict[str, Any]] = []

    for sample in dataset:
        selected_language = sample.get("selected_language", sample["language"])
        result = analyze_message(
            sample["message"],
            language=selected_language,
            channel="Other",
        )
        evaluated.append({
            **sample,
            "selected_language": selected_language,
            "expected_positive": sample["label"] == "suspicious",
            "predicted_positive": result["effective_risk_level"] != "LOW RISK",
            "risk_score": result["risk_score"],
            "effective_risk_score": result["effective_risk_score"],
            "effective_risk_level": result["effective_risk_level"],
            "detected_categories": result["detected_categories"],
            "matched_evidence": [
                {
                    "category": item["category"],
                    "phrase": item["matched_phrase"],
                    "language": item["language"],
                }
                for item in result["evidence"]
            ],
        })

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in evaluated:
        grouped[case["language"]].append(case)
    category_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in evaluated:
        category_groups[case["category"]].append(case)

    output = {
        "overall": _metrics(evaluated),
        "case_results": [
            {
                "id": case["id"],
                "language": case["language"],
                "category": case["category"],
                "expected": "suspicious" if case["expected_positive"] else "legitimate",
                "predicted": "suspicious" if case["predicted_positive"] else "legitimate",
                "risk_score": case["risk_score"],
                "effective_risk_score": case["effective_risk_score"],
                "effective_risk_level": case["effective_risk_level"],
            }
            for case in evaluated
        ],
        "by_language": {language: _metrics(group) for language, group in sorted(grouped.items())},
        "by_category": {
            category: {
                "cases": len(group),
                "tp": sum(case["expected_positive"] and case["predicted_positive"] for case in group),
                "fp": sum(not case["expected_positive"] and case["predicted_positive"] for case in group),
                "fn": sum(case["expected_positive"] and not case["predicted_positive"] for case in group),
            }
            for category, group in sorted(category_groups.items())
        },
        "false_positives": [
            {
                "id": case["id"],
                "language": case["language"],
                "category": case["category"],
                "message": case["message"],
                "risk_score": case["effective_risk_score"],
                "risk_level": case["effective_risk_level"],
                "detected_categories": case["detected_categories"],
                "matched_evidence": case["matched_evidence"],
            }
            for case in evaluated
            if not case["expected_positive"] and case["predicted_positive"]
        ],
        "false_negatives": [
            {
                "id": case["id"],
                "language": case["language"],
                "category": case["category"],
                "message": case["message"],
                "risk_score": case["effective_risk_score"],
                "risk_level": case["effective_risk_level"],
                "detected_categories": case["detected_categories"],
                "matched_evidence": case["matched_evidence"],
            }
            for case in evaluated
            if case["expected_positive"] and not case["predicted_positive"]
        ],
        "score_distribution": {
            "risk_levels": dict(Counter(case["effective_risk_level"] for case in evaluated)),
        },
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
