"""Composite scoring and decision engine for the prompt injection firewall."""

from dataclasses import dataclass, field

from llm_firewall import heuristics
from llm_firewall.rules import find_matches

DEFAULT_CONFIG = {
    "warn_threshold": 45,
    "block_threshold": 70,
    "actions": {
        "direct": "block",
        "jailbreak": "block",
        "extraction": "block",
        "encoding": "sanitize",
        "delimiter": "sanitize",
        "indirect": "warn",
        "role_switch": "warn",
    },
    "sanitize_on_warn": False,
    "log_only": False,
    "max_input_length": 8000,
}


@dataclass
class Finding:
    category: str
    pattern: str
    weight: int
    match: str


@dataclass
class Verdict:
    score: int
    decision: str
    findings: list = field(default_factory=list)
    heuristics: dict = field(default_factory=dict)
    reasons: list = field(default_factory=list)

    def summary(self):
        if not self.reasons:
            return "allow"
        return f"{self.decision} ({', '.join(self.reasons)})"


class FirewallEngine:
    """Detects and scores prompt injection attempts in user text."""

    def __init__(self, config=None):
        self.config = dict(DEFAULT_CONFIG)
        if config:
            self.config.update(config)

    @property
    def warn_threshold(self):
        return self.config["warn_threshold"]

    @property
    def block_threshold(self):
        return self.config["block_threshold"]

    def analyze(self, text):
        """Score one input and decide allow / warn / block."""
        findings = [
            Finding(rule.category, rule.description, rule.weight, str(match))
            for rule, match in find_matches(text)
        ]
        heur = heuristics.analyze(text)
        bonus = heuristics.heuristic_bonus(heur)

        base = sum(f.weight for f in findings)
        score = min(100, base + bonus)

        reasons = sorted({f.category for f in findings})
        if bonus >= 10:
            reasons.append("heuristics")

        decision = self._decide(score, findings, reasons)
        return Verdict(
            score=score,
            decision=decision,
            findings=findings,
            heuristics=heur.as_dict(),
            reasons=reasons,
        )

    def _decide(self, score, findings, reasons):
        if self.config.get("log_only"):
            return "warn"
        if score >= self.block_threshold:
            return "block"
        if score >= self.warn_threshold:
            category_actions = {f.category for f in findings}
            if any(self.config["actions"].get(c, "warn") == "block" for c in category_actions):
                return "block"
            return "warn"
        return "allow"

    def inspect_messages(self, payload):
        """Extract user text from an OpenAI-style request payload."""
        if isinstance(payload, str):
            return payload
        if isinstance(payload, dict):
            if isinstance(payload.get("prompt"), str):
                return payload["prompt"]
            if isinstance(payload.get("input"), str):
                return payload["input"]
            if isinstance(payload.get("content"), str):
                return payload["content"]
            messages = payload.get("messages")
            if isinstance(messages, list):
                texts = []
                for msg in messages:
                    if not isinstance(msg, dict):
                        continue
                    content = msg.get("content")
                    if isinstance(content, str):
                        texts.append(content)
                    elif isinstance(content, list):
                        for part in content:
                            if isinstance(part, dict) and isinstance(part.get("text"), str):
                                texts.append(part["text"])
                return "\n".join(texts)
        return ""
