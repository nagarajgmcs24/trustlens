import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from services.detection_engine import analyze_message


DATASET_PATH = (
    Path(__file__).parent
    / "tests"
    / "fixtures"
    / "independent_holdout_messages.json"
)


def metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(case["expected_positive"] and case["predicted_positive"] for case in cases)
    tn = sum(not case["expected_positive"] and not case["predicted_positive"] for case in cases)
    fp = sum(not case["expected_positive"] and case["predicted_positive"] for case in cases)
    fn = sum(case["expected_positive"] and not case["predicted_positive"] for case in cases)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    return {
        "total": len(cases),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "confusion_matrix": [[tp, fn], [fp, tn]],
    }


def evaluate() -> dict[str, Any]:
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    if len(dataset) < 100:
        raise ValueError(f"Holdout must contain at least 100 cases; found {len(dataset)}.")
    if len({case["id"] for case in dataset}) != len(dataset):
        raise ValueError("Holdout contains duplicate case IDs.")

    evaluated = []
    for sample in dataset:
        result = analyze_message(
            sample["message"],
            language=sample["selected_language"],
            channel="Other",
        )
        evaluated.append({
            **sample,
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
                    "points": item["points_contributed"],
                }
                for item in result["evidence"]
            ],
        })

    language_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    category_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in evaluated:
        language_groups[case["language"]].append(case)
        category_groups[case["category"]].append(case)

    errors = []
    for case in evaluated:
        if case["expected_positive"] != case["predicted_positive"]:
            errors.append({
                "id": case["id"],
                "language": case["language"],
                "selected_language": case["selected_language"],
                "category": case["category"],
                "expected": case["label"],
                "predicted": "suspicious" if case["predicted_positive"] else "legitimate",
                "message": case["message"],
                "effective_risk_score": case["effective_risk_score"],
                "effective_risk_level": case["effective_risk_level"],
                "detected_categories": case["detected_categories"],
                "matched_evidence": case["matched_evidence"],
            })

    return {
        "dataset": DATASET_PATH.name,
        "total_cases": len(evaluated),
        "overall": metrics(evaluated),
        "by_language": {
            language: metrics(cases)
            for language, cases in sorted(language_groups.items())
        },
        "by_category": {
            category: metrics(cases)
            for category, cases in sorted(category_groups.items())
        },
        "false_positives": [item for item in errors if item["expected"] == "legitimate"],
        "false_negatives": [item for item in errors if item["expected"] == "suspicious"],
        "errors": errors,
        "cases": [
            {
                "id": case["id"],
                "language": case["language"],
                "category": case["category"],
                "label": case["label"],
                "risk_score": case["risk_score"],
                "effective_risk_score": case["effective_risk_score"],
                "effective_risk_level": case["effective_risk_level"],
                "detected_categories": case["detected_categories"],
            }
            for case in evaluated
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = json.dumps(evaluate(), ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(report + "\n", encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
