import time
from config import (
    INJECTION_PATTERNS,
    URDU_INJECTION_PATTERNS,
    KOREAN_INJECTION_PATTERNS,
    INJECTION_THRESHOLD,
)


def calculate_rule_score(text: str) -> tuple:
    """
    Scans text against all multilingual injection patterns.
    Returns (score, matched_patterns, reason_codes).
    """
    text_lower = text.lower()
    score = 0.0
    matched = []
    reason_codes = []

    # ── English patterns ──────────────────────────────────
    for pattern, weight in INJECTION_PATTERNS.items():
        if pattern in text_lower:
            score += weight
            matched.append(pattern)
            # Assign reason codes based on pattern type
            if any(k in pattern for k in ["system prompt", "reveal", "print", "show", "display", "hidden"]):
                if "SYSTEM_PROMPT_EXTRACTION" not in reason_codes:
                    reason_codes.append("SYSTEM_PROMPT_EXTRACTION")
            elif any(k in pattern for k in ["jailbreak", "dan mode", "do anything", "unrestricted", "bypass", "roleplay", "pretend", "act as"]):
                if "JAILBREAK" not in reason_codes:
                    reason_codes.append("JAILBREAK")
            elif any(k in pattern for k in ["api key", "password", "token"]):
                if "SECRET_EXTRACTION" not in reason_codes:
                    reason_codes.append("SECRET_EXTRACTION")
            elif any(k in pattern for k in ["ignore", "forget", "disregard", "override"]):
                if "DIRECT_INJECTION" not in reason_codes:
                    reason_codes.append("DIRECT_INJECTION")
            elif any(k in pattern for k in ["ign0re", "instruct!ons", "prev!ous", "sh0w", "pr0mpt"]):
                if "OBFUSCATED_ATTACK" not in reason_codes:
                    reason_codes.append("OBFUSCATED_ATTACK")
            elif any(k in pattern for k in ["retrieved document", "override your policy", "system instruction"]):
                if "RAG_MANIPULATION" not in reason_codes:
                    reason_codes.append("RAG_MANIPULATION")

    # ── Urdu patterns ─────────────────────────────────────
    for pattern, weight in URDU_INJECTION_PATTERNS.items():
        if pattern in text or pattern in text_lower:
            score += weight
            matched.append(f"[UR] {pattern}")
            if "MULTILINGUAL_INJECTION" not in reason_codes:
                reason_codes.append("MULTILINGUAL_INJECTION")

    # ── Korean patterns ───────────────────────────────────
    for pattern, weight in KOREAN_INJECTION_PATTERNS.items():
        if pattern in text:
            score += weight
            matched.append(f"[KO] {pattern}")
            if "MULTILINGUAL_INJECTION" not in reason_codes:
                reason_codes.append("MULTILINGUAL_INJECTION")

    # Cap at 1.0
    score = min(score, 1.0)
    return score, matched, reason_codes


def detect_injection(text: str) -> dict:
    """
    Runs rule-based detection and returns structured result.
    """
    start = time.time()
    score, matched_patterns, reason_codes = calculate_rule_score(text)
    latency = round((time.time() - start) * 1000, 3)

    return {
        "rule_score":        round(score, 4),
        "is_injection":      score >= INJECTION_THRESHOLD,
        "matched_patterns":  matched_patterns,
        "reason_codes":      reason_codes,
        "latency_ms":        latency,
    }
