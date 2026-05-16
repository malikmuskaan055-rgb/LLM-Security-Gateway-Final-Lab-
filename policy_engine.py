from config import POLICY_SETTINGS, RISK_WEIGHTS


def compute_final_risk(rule_score: float, semantic_score: float,
                        pii_detected: bool, composite_risks: list) -> float:
    """
    Risk Formula:
        final_risk = max(rule_score, semantic_score)
                     + pii_weight  (if PII detected)
                     + secret_weight (if composite/high-risk PII)

    All weights are configurable in config.py.
    Result is capped at 1.0.
    """
    base_risk = max(rule_score, semantic_score)

    pii_addition = RISK_WEIGHTS["pii_weight"] if pii_detected else 0.0
    secret_addition = RISK_WEIGHTS["secret_weight"] if composite_risks else 0.0

    final_risk = base_risk + pii_addition + secret_addition
    return round(min(final_risk, 1.0), 4)


def make_decision(rule_result: dict, semantic_result: dict, pii_result: dict) -> dict:
    """
    Combines all detector results and applies policy thresholds.

    Logic:
    - BLOCK  if final_risk >= block_threshold OR injection detected
    - MASK   if PII detected but no injection
    - ALLOW  if everything is clean
    """
    rule_score     = rule_result["rule_score"]
    semantic_score = semantic_result["semantic_score"]
    pii_detected   = pii_result["pii_detected"]
    composite_risks = pii_result["composite_risks"]

    final_risk = compute_final_risk(
        rule_score, semantic_score, pii_detected, composite_risks
    )

    # Collect all reason codes from detectors
    reason_codes = []
    reason_codes.extend(rule_result.get("reason_codes", []))
    reason_codes.extend(semantic_result.get("reason_codes", []))
    if composite_risks:
        reason_codes.append("COMPOSITE_PII_RISK")
    if pii_detected and not reason_codes:
        reason_codes.append("PII_DETECTED")

    reason_codes = list(set(reason_codes))  # remove duplicates

    # ── Apply Thresholds ──────────────────────────────────
    block_threshold = POLICY_SETTINGS["block_threshold"]
    mask_threshold  = POLICY_SETTINGS["mask_threshold"]

    if final_risk >= block_threshold or composite_risks:
        decision   = "BLOCK"
        safe_text  = None
        reason     = f"Risk score {final_risk} exceeds block threshold or composite PII detected"
    elif pii_detected:
        decision   = "MASK"
        safe_text  = pii_result["anonymized_text"]
        reason     = "PII entities detected and anonymized"
    else:
        decision   = "ALLOW"
        safe_text  = "Input passed all security checks"
        reason     = "Input is safe — no injection or PII detected"

    return {
        "final_risk":   final_risk,
        "decision":     decision,
        "safe_text":    safe_text,
        "reason":       reason,
        "reason_codes": reason_codes,
    }
