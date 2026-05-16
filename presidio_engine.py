import time
import re
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine

# ── NLP Engine Setup ──────────────────────────────────────
provider = NlpEngineProvider(nlp_configuration={
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]
})
nlp_engine = provider.create_engine()
analyzer   = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
anonymizer = AnonymizerEngine()

# ── Entities to detect ────────────────────────────────────
SENSITIVE_ENTITIES = [
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "CREDIT_CARD",
    "IBAN_CODE",
    "NRP",
    "MEDICAL_LICENSE",
    "US_SSN",
    "IP_ADDRESS",
    "API_KEY",
    "PAK_PHONE",
    "CNIC",
    "STUDENT_ID",
    "INTERNAL_ID",
    "LOCATION_ADDRESS",
]

# ── Custom Recognizer 1: Pakistani Phone ──────────────────
pak_phone_recognizer = PatternRecognizer(
    supported_entity="PAK_PHONE",
    patterns=[Pattern(
        name="pak_phone_pattern",
        regex=r"\b((\+92|0092|92|0)[0-9]{10})\b",
        score=0.85,
    )],
    context=["phone", "call", "contact", "number", "whatsapp", "mobile"],
)

# ── Custom Recognizer 2: CNIC ──────────────────────────────
cnic_recognizer = PatternRecognizer(
    supported_entity="CNIC",
    patterns=[Pattern(
        name="cnic_pattern",
        regex=r"\b[0-9]{5}-[0-9]{7}-[0-9]\b",
        score=0.95,
    )],
    context=["cnic", "identity", "national", "id card", "nadra"],
)

# ── Custom Recognizer 3: Student ID ───────────────────────
student_id_recognizer = PatternRecognizer(
    supported_entity="STUDENT_ID",
    patterns=[Pattern(
        name="student_id_pattern",
        regex=r"\b(FA|SP|BCS|BSE|BIT|BBA|MBA)[0-9]{2}-[A-Z]{2,4}-[0-9]{2,4}\b",
        score=0.92,
    )],
    context=["student", "registration", "reg", "roll", "id", "number"],
)

# ── Custom Recognizer 4: API Key ──────────────────────────
api_key_recognizer = PatternRecognizer(
    supported_entity="API_KEY",
    patterns=[Pattern(
        name="api_key_pattern",
        regex=r"\b(sk-[a-zA-Z0-9]{20,}|AIza[0-9A-Za-z\-_]{35}|ghp_[a-zA-Z0-9]{36})\b",
        score=0.9,
    )],
    context=["api", "key", "token", "secret", "access", "bearer"],
)

# ── Custom Recognizer 5: Internal Employee ID ─────────────
internal_id_recognizer = PatternRecognizer(
    supported_entity="INTERNAL_ID",
    patterns=[Pattern(
        name="internal_id_pattern",
        regex=r"\bEMP-[0-9]{4,6}\b",
        score=0.88,
    )],
    context=["employee", "id", "staff", "internal", "reg", "worker"],
)

# ── Custom Recognizer 6: Location Address ─────────────────
location_address_recognizer = PatternRecognizer(
    supported_entity="LOCATION_ADDRESS",
    patterns=[Pattern(
        name="street_address_pattern",
        regex=(
            r"\b(house|flat|plot|apartment|apt|floor|block|sector|street|st\.?|road|rd\.?|avenue|ave\.?|phase)"
            r"[\s\-#\.]*[0-9A-Za-z\-/]+\b"
        ),
        score=0.80,
    )],
    context=["address", "live", "located", "residing", "home", "office", "near"],
)

# Register all custom recognizers
analyzer.registry.add_recognizer(pak_phone_recognizer)
analyzer.registry.add_recognizer(cnic_recognizer)
analyzer.registry.add_recognizer(student_id_recognizer)
analyzer.registry.add_recognizer(api_key_recognizer)
analyzer.registry.add_recognizer(internal_id_recognizer)
analyzer.registry.add_recognizer(location_address_recognizer)

# ── Context-Aware Score Boosting ──────────────────────────
CONTEXT_BOOST = {
    "PHONE_NUMBER":     ["call", "phone", "contact", "reach", "number"],
    "PAK_PHONE":        ["phone", "call", "whatsapp", "mobile", "contact"],
    "EMAIL_ADDRESS":    ["email", "send", "mail", "contact"],
    "API_KEY":          ["api", "key", "token", "secret", "access"],
    "CNIC":             ["cnic", "identity", "national", "nadra"],
    "STUDENT_ID":       ["student", "registration", "roll", "id"],
    "LOCATION_ADDRESS": ["address", "live", "located", "home", "office"],
}

def apply_context_boost(results, text: str):
    """Boosts confidence score when context keywords appear near entity."""
    text_lower = text.lower()
    boosted = []
    for r in results:
        boost = 0.0
        for word in CONTEXT_BOOST.get(r.entity_type, []):
            if word in text_lower:
                boost += 0.05
        r.score = min(r.score + boost, 1.0)
        boosted.append(r)
    return boosted

# ── Composite Entity Detection ────────────────────────────
def detect_composite_entities(text: str) -> list:
    """
    Flags high-risk combinations of PII entities.
    e.g. Email + Phone = identity combo risk.
    """
    composite = []
    has_phone = bool(re.search(r'\b((\+92|0)[0-9]{10})\b', text))
    has_email = bool(re.search(r'\b[\w.\-]+@[\w.\-]+\.\w+\b', text))
    has_card  = bool(re.search(r'\b[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b', text))
    has_cnic  = bool(re.search(r'\b[0-9]{5}-[0-9]{7}-[0-9]\b', text))
    has_sid   = bool(re.search(r'\b(FA|SP|BCS|BSE|BIT|BBA|MBA)[0-9]{2}-[A-Z]{2,4}-[0-9]{2,4}\b', text))

    if has_email and has_phone:
        composite.append("EMAIL+PHONE combo — high identity risk")
    if has_card and has_phone:
        composite.append("CARD+PHONE combo — financial risk")
    if has_card and has_email:
        composite.append("CARD+EMAIL combo — financial risk")
    if has_cnic and has_phone:
        composite.append("CNIC+PHONE combo — identity theft risk")
    if has_sid and has_email:
        composite.append("STUDENT_ID+EMAIL combo — student identity risk")
    return composite

# ── Main PII Analysis Function ────────────────────────────
def analyze_pii(text: str) -> dict:
    start = time.time()

    results = analyzer.analyze(
        text=text,
        language="en",
        entities=SENSITIVE_ENTITIES,
    )

    results = apply_context_boost(results, text)
    composite = detect_composite_entities(text)
    anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
    latency = round((time.time() - start) * 1000, 3)

    return {
        "entities_found": [
            {
                "type":  r.entity_type,
                "score": round(r.score, 2),
                "start": r.start,
                "end":   r.end,
                "value": text[r.start:r.end],
            }
            for r in results
        ],
        "composite_risks":  composite,
        "anonymized_text":  anonymized.text,
        "pii_detected":     len(results) > 0,
        "latency_ms":       latency,
    }