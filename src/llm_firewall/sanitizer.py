"""Input sanitization: neutralize detected payloads instead of blocking them."""

import html
import re
import unicodedata

from llm_firewall import heuristics

# Phrases that are replaced with a neutral placeholder during sanitization.
NEUTRALIZED_PHRASES = (
    r"ignore\s+(all\s+)?(my\s+|the\s+|your\s+)?(previous|earlier|prior|above|past)\s+(instructions|messages|prompts|orders)",
    r"ignore\s+(everything|all)\s+(i\s+)?(said|wrote|told\s+you|sent)",
    r"disregard\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above)\s+(instructions|messages|prompts|orders|rules)",
    r"forget\s+(all\s+|everything\s+|the\s+|your\s+)?(previous|prior|above)?\s*(instructions|prompts|messages|orders|rules|system\s+prompt)",
    r"override\s+(the\s+|your\s+)?(system\s+prompt|instructions)",
    r"reveal\s+(your|the|its)\s+(system\s+)?prompt",
    r"show\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions)",
    r"output\s+(your|the)\s+(system\s+)?(prompt|instructions)",
    r"repeat\s+(the\s+)?(system\s+)?(prompt|instructions)",
    r"you\s+are\s+now\s+dan\b",
    r"dan\s+mode",
    r"do\s+anything\s+now",
)

PLACEHOLDER = "[filtered]"

TAG_BLOCK = re.compile(
    r"<\s*(system|instructions|prompt)[^>]*>.*?</\s*\1\s*>",
    re.IGNORECASE | re.DOTALL,
)


def normalize_unicode(text):
    """NFKC normalization plus homoglyph folding to defeat lookalike bypasses."""
    folded = "".join(heuristics.HOMOGLYPHS.get(ch, ch) for ch in text)
    return unicodedata.normalize("NFKC", folded)


def neutralize(text):
    """Replace known injection phrases with a benign placeholder."""
    out = TAG_BLOCK.sub(PLACEHOLDER, text)
    for pattern in NEUTRALIZED_PHRASES:
        out = re.sub(pattern, PLACEHOLDER, out, flags=re.IGNORECASE)
    return out


def escape_delimiters(text):
    """Escape markup and quote characters that confuse prompt boundaries."""
    out = text.replace("<", "&lt;").replace(">", "&gt;")
    out = out.replace("[", "&#91;").replace("]", "&#93;")
    out = out.replace("{", "&#123;").replace("}", "&#125;")
    return html.escape(out, quote=False)


def truncate(text, max_chars=4000):
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..." + "[truncated]"


def sanitize(text, max_chars=4000):
    """Full sanitization pipeline: normalize, neutralize, escape, truncate."""
    out = normalize_unicode(text)
    out = neutralize(out)
    out = escape_delimiters(out)
    return truncate(out, max_chars)


def sanitize_payload(payload, max_chars=4000):
    """Sanitize text fields in an OpenAI-style request payload in place."""
    if isinstance(payload, str):
        return sanitize(payload, max_chars)
    if isinstance(payload, dict):
        for key in ("prompt", "input", "content"):
            if isinstance(payload.get(key), str):
                payload[key] = sanitize(payload[key], max_chars)
        messages = payload.get("messages")
        if isinstance(messages, list):
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                content = msg.get("content")
                if isinstance(content, str):
                    msg["content"] = sanitize(content, max_chars)
                elif isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            part["text"] = sanitize(part["text"], max_chars)
    return payload
