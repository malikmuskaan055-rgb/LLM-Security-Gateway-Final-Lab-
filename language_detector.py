from langdetect import detect, LangDetectException

def detect_language(text: str) -> str:
    """
    Detects the language of the input text.
    Returns ISO 639-1 language code (e.g. 'en', 'ur', 'ko').
    Falls back to 'en' if detection fails.
    """
    try:
        lang = detect(text)
        return lang
    except LangDetectException:
        return "en"
