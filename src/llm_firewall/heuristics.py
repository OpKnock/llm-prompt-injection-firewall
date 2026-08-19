"""Heuristic analysis for prompt injection detection.

Pattern matching alone is easy to bypass with encoding tricks. These
heuristics look at the shape of the input: entropy, base64 blobs, unicode
homoglyphs, escape sequences and instruction-framed language. The homoglyph
fold and leet-speak decoder also help rule matching catch encoded bypasses.
"""

import base64
import math
import re
import unicodedata

BASE64_CHARS = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
HEX_CHARS = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
INSTRUCTION_VERBS = (
    "ignore", "forget", "disregard", "override", "reveal", "output",
    "repeat", "pretend", "act", "unban", "leak", "print", "show",
    "tell", "follow", "obey", "bypass", "decode", "decrypt",
)

# Confusable Cyrillic / Greek characters mapped to their ASCII lookalikes.
HOMOGLYPHS = {
    "\u0430": "a", "\u0410": "A", "\u0435": "e", "\u0415": "E",
    "\u0456": "i", "\u0406": "I", "\u043e": "o", "\u041e": "O",
    "\u0440": "p", "\u0420": "P", "\u0441": "c", "\u0421": "C",
    "\u0443": "y", "\u0423": "Y", "\u0445": "x", "\u0425": "X",
    "\u043d": "h", "\u041d": "H", "\u043c": "m", "\u041c": "M",
    "\u0442": "t", "\u0422": "T", "\u043a": "k", "\u041a": "K",
    "\u03bf": "o", "\u039f": "O", "\u03c1": "p", "\u03a1": "P",
    "\u03c4": "t", "\u03a4": "T", "\u03b9": "i", "\u0399": "I",
    "\u03b5": "e", "\u0395": "E", "\u03b1": "a", "\u0391": "A",
    "\u03c5": "y", "\u03a5": "Y",
}

LEET_MAP = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s", "!": "i", "8": "b",
}

# Some leet words spell "1" as an l ("f0110w" -> "follow"), others as an i.
LEET_MAP_L = dict(LEET_MAP)
LEET_MAP_L["1"] = "l"


def fold_homoglyphs(text):
    """Replace confusable non-ASCII characters with ASCII lookalikes."""
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in text)


def deleet(text, mapping=LEET_MAP):
    """Decode leet-speak digits back to letters."""
    return "".join(mapping.get(ch, ch) for ch in text)


def normalize_for_rules(text):
    """Normalize input before rule matching: homoglyph fold + leet decode."""
    return deleet(fold_homoglyphs(text))


def shannon_entropy(data):
    """Shannon entropy in bits per byte for the given bytes."""
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def entropy_bits(text):
    """Entropy of the text as bytes."""
    return shannon_entropy(text.encode("utf-8", errors="replace"))


def longest_base64_run(text):
    """Length of the longest contiguous base64-alphabet run in the text."""
    longest = 0
    current = 0
    alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    for ch in text:
        if ch in alphabet:
            current += 1
            if current > longest:
                longest = current
        else:
            current = 0
    return longest


def is_base64_payload(chunk):
    """True if chunk is a plausible base64-encoded payload."""
    if len(chunk) < 16:
        return False
    if not BASE64_CHARS.match(chunk):
        return False
    if len(chunk) % 4 == 0:
        try:
            base64.b64decode(chunk, validate=True)
            return True
        except Exception:
            return False
    return True


def is_hex_payload(chunk):
    if len(chunk) < 16 or len(chunk) % 2 != 0:
        return False
    return bool(HEX_CHARS.match(chunk))


def homoglyph_characters(text):
    """Non-ASCII characters that map to ASCII via the confusable table."""
    return [(ch, HOMOGLYPHS[ch]) for ch in text if ch in HOMOGLYPHS]


def instruction_word_ratio(text):
    """Fraction of words that are instruction verbs, else 0.0 for empty text."""
    words = re.findall(r"[A-Za-z']+", text.lower())
    if not words:
        return 0.0
    hits = sum(1 for w in words if w in INSTRUCTION_VERBS)
    return hits / len(words)


def nested_tag_count(text):
    """Count of angle-bracket and bracket tag pairs that look like markup."""
    return (
        len(re.findall(r"<[^>]{1,80}>", text))
        + len(re.findall(r"\[[^\]]{1,80}\]", text))
    )


class HeuristicResult:
    __slots__ = (
        "entropy", "entropy_high", "base64_run", "has_base64",
        "has_hex", "homoglyphs", "unicode_escapes", "tag_count",
        "instruction_ratio", "language_switch",
    )

    def __init__(self):
        self.entropy = 0.0
        self.entropy_high = False
        self.base64_run = 0
        self.has_base64 = False
        self.has_hex = False
        self.homoglyphs = []
        self.unicode_escapes = 0
        self.tag_count = 0
        self.instruction_ratio = 0.0
        self.language_switch = False

    def as_dict(self):
        return {
            "entropy": round(self.entropy, 3),
            "entropy_high": self.entropy_high,
            "base64_run": self.base64_run,
            "has_base64": self.has_base64,
            "has_hex": self.has_hex,
            "homoglyph_count": len(self.homoglyphs),
            "unicode_escapes": self.unicode_escapes,
            "tag_count": self.tag_count,
            "instruction_ratio": round(self.instruction_ratio, 3),
            "language_switch": self.language_switch,
        }


def analyze(text):
    """Run all heuristics over the input text."""
    result = HeuristicResult()
    result.entropy = entropy_bits(text)
    result.entropy_high = result.entropy >= 4.6 and len(text) >= 24

    for word in re.findall(r"[A-Za-z0-9+/=]+", text):
        if is_hex_payload(word):
            result.has_hex = True
        elif is_base64_payload(word):
            result.has_base64 = True
    result.base64_run = longest_base64_run(text)

    result.homoglyphs = homoglyph_characters(text)
    result.unicode_escapes = len(re.findall(r"\\u[0-9a-fA-F]{4}", text))
    result.tag_count = nested_tag_count(text)
    result.instruction_ratio = instruction_word_ratio(text)
    result.language_switch = 0.04 <= result.instruction_ratio <= 0.6
    return result


def heuristic_bonus(result):
    """Convert heuristic signals into score points (0..100)."""
    bonus = 0
    if result.entropy_high:
        bonus += min(12, int((result.entropy - 4.5) * 10))
    if result.has_base64 and result.base64_run >= 16:
        bonus += 18
    elif result.base64_run >= 24:
        bonus += 12
    if result.has_hex:
        bonus += 12
    if len(result.homoglyphs) >= 3:
        bonus += 15
    if result.unicode_escapes >= 2:
        bonus += 10
    if result.tag_count >= 2:
        bonus += 8
    if result.language_switch:
        bonus += 6
    return min(100, bonus)
