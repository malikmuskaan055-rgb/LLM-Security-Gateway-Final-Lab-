import csv
import json
import os
import time
from injection import detect_injection
from semantic_detector import detect_semantic
from presidio_engine import analyze_pii
from policy_engine import make_decision
from language_detector import detect_language

DATASET_PATH = "data/final_eval.csv"
RESULTS_PATH = "results/evaluation_results.csv"
METRICS_PATH = "results/metrics_summary.json"

os.makedirs("results", exist_ok=True)


def run_pipeline(text: str) -> dict:
    """Runs the full gateway pipeline on one text input."""
    language       = detect_language(text)
    rule_result    = detect_injection(text)
    semantic_result = detect_semantic(text)
    pii_result     = analyze_pii(text)
    policy_result  = make_decision(rule_result, semantic_result, pii_result)
    return {
        "language":       language,
        "rule_score":     rule_result["rule_score"],
        "semantic_score": semantic_result["semantic_score"],
        "final_risk":     policy_result["final_risk"],
        "decision":       policy_result["decision"],
        "reason_codes":   policy_result["reason_codes"],
    }


def compute_metrics(results: list) -> dict:
    """
    Computes accuracy, precision, recall, F1 for BLOCK detection.
    Also computes per-language recall.
    """
    tp = fp = tn = fn = 0
    lang_stats = {}

    for r in results:
        expected = r["expected_policy"]
        predicted = r["predicted_policy"]
        lang = r["language"]

        # Binary: BLOCK = positive, non-BLOCK = negative
        is_attack_expected  = (expected == "BLOCK")
        is_attack_predicted = (predicted == "BLOCK")

        if is_attack_expected and is_attack_predicted:   tp += 1
        elif not is_attack_expected and is_attack_predicted: fp += 1
        elif not is_attack_expected and not is_attack_predicted: tn += 1
        elif is_attack_expected and not is_attack_predicted: fn += 1

        # Per-language
        if lang not in lang_stats:
            lang_stats[lang] = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
        if is_attack_expected and is_attack_predicted:
            lang_stats[lang]["tp"] += 1
        elif is_attack_expected and not is_attack_predicted:
            lang_stats[lang]["fn"] += 1
        elif not is_attack_expected and is_attack_predicted:
            lang_stats[lang]["fp"] += 1
        else:
            lang_stats[lang]["tn"] += 1

    total = tp + fp + tn + fn
    accuracy  = round((tp + tn) / total, 4) if total else 0
    precision = round(tp / (tp + fp), 4) if (tp + fp) else 0
    recall    = round(tp / (tp + fn), 4) if (tp + fn) else 0
    f1        = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0

    # Per-language recall
    per_lang = {}
    for lang, s in lang_stats.items():
        denom = s["tp"] + s["fn"]
        per_lang[lang] = {
            "recall": round(s["tp"] / denom, 4) if denom else "N/A",
            "tp": s["tp"], "fn": s["fn"], "fp": s["fp"], "tn": s["tn"],
        }

    return {
        "total_cases":     total,
        "true_positives":  tp,
        "false_positives": fp,
        "true_negatives":  tn,
        "false_negatives": fn,
        "accuracy":        accuracy,
        "precision":       precision,
        "recall":          recall,
        "f1_score":        f1,
        "per_language":    per_lang,
    }


def main():
    print("=" * 60)
    print("LLM Security Gateway — Evaluation Script")
    print("=" * 60)

    if not os.path.exists(DATASET_PATH):
        print(f"[ERROR] Dataset not found at {DATASET_PATH}")
        return

    results = []
    latencies = []

    with open(DATASET_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print(f"\nRunning evaluation on {len(rows)} test cases...\n")

    for row in rows:
        text          = row["prompt"]
        expected      = row["expected_policy"]
        case_id       = row["id"]
        attack_type   = row["attack_type"]
        language_col  = row["language"]

        start = time.time()
        result = run_pipeline(text)
        latency = round((time.time() - start) * 1000, 3)
        latencies.append(latency)

        predicted = result["decision"]
        correct   = (predicted == expected)

        results.append({
            "id":               case_id,
            "prompt":           text[:60] + "..." if len(text) > 60 else text,
            "language":         language_col,
            "attack_type":      attack_type,
            "expected_policy":  expected,
            "predicted_policy": predicted,
            "rule_score":       result["rule_score"],
            "semantic_score":   result["semantic_score"],
            "final_risk":       result["final_risk"],
            "correct":          correct,
            "latency_ms":       latency,
            "reason_codes":     "|".join(result["reason_codes"]),
        })

        status = "✓" if correct else "✗"
        print(f"  [{status}] Case {case_id:>3} | {expected:5} → {predicted:5} | {text[:45]}")

    # ── Save Results CSV ──────────────────────────────────
    with open(RESULTS_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    # ── Compute Metrics ───────────────────────────────────
    metrics = compute_metrics(results)

    # Add latency stats
    sorted_lat = sorted(latencies)
    metrics["latency"] = {
        "mean_ms":   round(sum(latencies) / len(latencies), 2),
        "median_ms": round(sorted_lat[len(sorted_lat) // 2], 2),
        "p95_ms":    round(sorted_lat[int(len(sorted_lat) * 0.95)], 2),
        "max_ms":    round(max(latencies), 2),
    }

    # ── Save Metrics JSON ─────────────────────────────────
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)

    # ── Print Summary ─────────────────────────────────────
    print("\n" + "=" * 60)
    print("EVALUATION SUMMARY")
    print("=" * 60)
    print(f"  Total Cases:       {metrics['total_cases']}")
    print(f"  Accuracy:          {metrics['accuracy']}")
    print(f"  Precision:         {metrics['precision']}")
    print(f"  Recall:            {metrics['recall']}")
    print(f"  F1 Score:          {metrics['f1_score']}")
    print(f"  True Positives:    {metrics['true_positives']}")
    print(f"  False Positives:   {metrics['false_positives']}")
    print(f"  True Negatives:    {metrics['true_negatives']}")
    print(f"  False Negatives:   {metrics['false_negatives']}")
    print(f"\n  Mean Latency:      {metrics['latency']['mean_ms']} ms")
    print(f"  P95 Latency:       {metrics['latency']['p95_ms']} ms")

    print("\n  Per-Language Recall:")
    for lang, s in metrics["per_language"].items():
        print(f"    {lang:>10}: recall={s['recall']}  tp={s['tp']}  fn={s['fn']}")

    print(f"\n  Results saved to: {RESULTS_PATH}")
    print(f"  Metrics saved to: {METRICS_PATH}")
    print("=" * 60)


if __name__ == "__main__":
    main()
