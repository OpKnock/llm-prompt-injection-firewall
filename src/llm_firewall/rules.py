"""Pattern-based detection rules for prompt injection.

Rules are grouped into categories with per-category severity weights. The
engine sums the weights of every matching rule into a 0-100 threat score.
Rule matching runs on a normalized copy of the input (homoglyph folding +
leet-speak de-coding), so encoding-based bypasses are caught as well.
"""

import re

CATEGORIES = (
    "direct",
    "jailbreak",
    "extraction",
    "encoding",
    "delimiter",
    "indirect",
    "role_switch",
)


class Rule:
    __slots__ = ("category", "pattern", "weight", "description")

    def __init__(self, category, pattern, weight, description):
        self.category = category
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.weight = weight
        self.description = description

    def find(self, text):
        return self.pattern.findall(text)


DIRECT = 65
JAILBREAK = 60
EXTRACTION = 60
ENCODING = 45
DELIMITER = 45
INDIRECT = 45
ROLE_SWITCH = 45

RULES = [
    # direct injection: overriding the system prompt
    Rule("direct", r"ignore\s+(all\s+|any\s+|the\s+|your\s+|my\s+)?(previous|earlier|prior|above|past|system|former)\s+(instructions|messages|message|prompts|orders|rules|text|content)", DIRECT, "ignore previous instructions"),
    Rule("direct", r"ignore\s+(everything|all)\s+(that\s+)?(i\s*'?ve?\s*|you\s+were\s+told\s+)?(said|say|wrote|typed|sent|text|above)", DIRECT, "ignore everything said before"),
    Rule("direct", r"ignore\s+(the\s+|all\s+|any\s+)?(content|text|message|messages)\s+above", DIRECT, "ignore content above"),
    Rule("direct", r"ignore\s+(the\s+)?above", DIRECT, "ignore the above"),
    Rule("direct", r"ignore\s+your\s+(programming|training|instructions)", DIRECT, "ignore your programming"),
    Rule("direct", r"disregard\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier)\s+(instructions|messages|prompts|orders|rules)", DIRECT, "disregard previous instructions"),
    Rule("direct", r"disregard\s+(the\s+|your\s+|these\s+|all\s+following\s+)?(instructions|content|text|rules)", DIRECT, "disregard instructions"),
    Rule("direct", r"forget\s+(all\s+|everything\s+|the\s+|your\s+)?(previous|prior|above|earlier|system)?\s*(instructions|prompts|messages|orders|rules|system\s+prompt)", DIRECT, "forget instructions"),
    Rule("direct", r"forget\s+(everything|all)\s+you\s+were\s+(told|taught|given)", DIRECT, "forget everything you were told"),
    Rule("direct", r"you\s+(are|will|must)\s+(now\s+)?(ignore|disregard|forget)\s+(everything|all|the\s+instructions)", DIRECT, "you will ignore everything"),
    Rule("direct", r"(don'?t|do\s+not)\s+(follow|obey|listen\s+to|respect)\s+(the\s+|your\s+)?(instructions|system\s+prompt|rules)", DIRECT, "do not follow instructions"),
    Rule("direct", r"override\s+(the\s+|your\s+)?(system\s+)?(prompt|instructions|directives)", DIRECT, "override system prompt"),
    Rule("direct", r"you\s+are\s+no\s+longer\s+(bound\s+by|required\s+to\s+follow)", DIRECT, "no longer bound by instructions"),
    Rule("direct", r"(new|changed)\s+instructions\s*[:\.]", DIRECT, "new/changed instructions prefix"),
    Rule("direct", r"from\s+now\s+on\s+you\s+will", DIRECT, "from now on you will"),
    Rule("direct", r"(i\s+have|here\s+are|these\s+are)\s+new\s+(orders|instructions|rules)", DIRECT, "new orders declared"),

    # jailbreak techniques
    Rule("jailbreak", r"dan\s+mode", JAILBREAK, "DAN mode"),
    Rule("jailbreak", r"you\s+are\s+now\s+dan\b", JAILBREAK, "you are now DAN"),
    Rule("jailbreak", r"(play|pretend|become)\s+dan\b", JAILBREAK, "play DAN"),
    Rule("jailbreak", r"jail\s*break(\s+(mode|activated|enabled))?", JAILBREAK, "jailbreak"),
    Rule("jailbreak", r"developer\s+mode", JAILBREAK, "developer mode"),
    Rule("jailbreak", r"sudo\s+mode", JAILBREAK, "sudo mode"),
    Rule("jailbreak", r"unrestricted\s+mode", JAILBREAK, "unrestricted mode"),
    Rule("jailbreak", r"do\s+anything\s+now", JAILBREAK, "do anything now"),
    Rule("jailbreak", r"(no|without|don'?t\s+apply)\s+(filters|restrictions|content\s+policies)", JAILBREAK, "no filters"),
    Rule("jailbreak", r"pretend\s+(you\s+are|to\s+be)\s+(dan|an\s+ai\s+(without|with\s+no))", JAILBREAK, "pretend to be DAN"),
    Rule("jailbreak", r"act\s+(as|like)\s+(dan|an\s+ai\s+(with\s+no|without)|if\s+you\s+have\s+no)", JAILBREAK, "act as unrestricted AI"),
    Rule("jailbreak", r"unbanned\s+(version|mode)", JAILBREAK, "unbanned version"),
    Rule("jailbreak", r"bypass\s+(the\s+)?(filter|safety|content\s+policy)", JAILBREAK, "filter bypass"),
    Rule("jailbreak", r"answer\s+without\s+(any|the)\s+(restrictions|limitations|rules)", JAILBREAK, "answer without restrictions"),

    # data extraction / prompt stealing
    Rule("extraction", r"reveal\s+(your|the|its)\s+(system\s+)?prompt", EXTRACTION, "reveal system prompt"),
    Rule("extraction", r"show\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions)", EXTRACTION, "show system prompt"),
    Rule("extraction", r"(output|print|display)\s+(your|the)\s+(system\s+)?(prompt|instructions)", EXTRACTION, "print system prompt"),
    Rule("extraction", r"what\s+are\s+(your|the)\s+(instructions|directives|system\s+prompt)", EXTRACTION, "ask for instructions"),
    Rule("extraction", r"tell\s+(me\s+)?(your|the|what)\s+(instructions|directives|system\s+prompt)", EXTRACTION, "tell me instructions"),
    Rule("extraction", r"repeat\s+((the|your|the\s+system)\s+)?(prompt|instructions)\s*(above|verbatim|exactly|word\s+for\s+word)?", EXTRACTION, "repeat prompt"),
    Rule("extraction", r"leak\s+(your|the|its)\s+(system\s+)?(prompt|instructions)", EXTRACTION, "leak prompt"),
    Rule("extraction", r"summarize\s+(the|your|it)?\s*(system\s+)?prompt", EXTRACTION, "summarize prompt"),
    Rule("extraction", r"what\s+did\s+the\s+(system|assistant)\s+tell\s+you", EXTRACTION, "what did system say"),
    Rule("extraction", r"(initial|original)\s+(instructions|prompt|directives)\s*(you\s+were\s+given|given\s+to\s+you)?", EXTRACTION, "initial instructions"),

    # delimiter / template injection
    Rule("delimiter", r"<\s*\\?system[^>]*>", DELIMITER, "system tag"),
    Rule("delimiter", r"<\s*\\?instructions[^>]*>", DELIMITER, "instructions tag"),
    Rule("delimiter", r"<\|im_start\|>", DELIMITER, "ChatML token"),
    Rule("delimiter", r"<\s*\\?prompt[^>]*>", DELIMITER, "prompt tag"),
    Rule("delimiter", r"\[\s*system\s*\]", DELIMITER, "bracketed system"),
    Rule("delimiter", r"^system\s*:", DELIMITER, "system colon prefix"),

    # encoding-based attacks
    Rule("encoding", r"\bbase64\b", ENCODING, "base64 mention"),
    Rule("encoding", r"\brot13\b|\bcaesar\s+(cipher|shift)\b", ENCODING, "rot13/caesar mention"),
    Rule("encoding", r"\bhex\s*(decode|encoded|string)\b", ENCODING, "hex encoding mention"),
    Rule("encoding", r"\bhex\s*[:=]", ENCODING, "hex payload prefix"),
    Rule("encoding", r"\\u[0-9a-f]{4}", ENCODING, "unicode escape sequences"),
    Rule("encoding", r"read\s+(the\s+)?text\s+backwards|reverse\s+(this\s+)?(string|text)", ENCODING, "reverse text"),
    Rule("encoding", r"(decoded|decode|decrypt)\s*(the\s*)?(payload|message|text|string)", ENCODING, "decode payload"),
    Rule("encoding", r"decode\s+(this|the)\s+(base64|text|string|message|payload)", ENCODING, "decode this base64"),

    # indirect injection via retrieved content
    Rule("indirect", r"important\s*:\s*ignore", INDIRECT, "important ignore"),
    Rule("indirect", r"please\s+forget\s+(everything|all)", INDIRECT, "please forget"),
    Rule("indirect", r"note\s*:\s*(the\s+)?(above|previous|document|text|email)", INDIRECT, "note about above"),
    Rule("indirect", r"(document|text|email|website|webpage|article)\s+(above\s+|below\s+)?contains\s+(instructions|commands)", INDIRECT, "retrieved content contains instructions"),
    Rule("indirect", r"(follow|obey|carry\s+out)\s+(the\s+)?(instructions|commands)\s+in\s+(this|the)\s+(document|text|email|website)", INDIRECT, "follow instructions in content"),
    Rule("indirect", r"(continue|proceed)\s+(with|as\s+per)\s+(the\s+)?(instructions|commands)", INDIRECT, "proceed as per instructions"),

    # generic role switching / suspicious framing
    Rule("role_switch", r"you\s+are\s+(now\s+)?(a\s+|an\s+)?([a-z]+\s+){0,3}(assistant|ai|bot|model)\s+that\s+(can\s+)?do\s+anything", ROLE_SWITCH, "assistant that can do anything"),
    Rule("role_switch", r"(act|pretend)\s+(as|to\s+be)\s+(my\s+)?\w+[\w\s]{0,20}\b(with\s+unlimited|no\s+(rules|limits|restrictions))", ROLE_SWITCH, "pretend with no limits"),
    Rule("role_switch", r"(your\s+)?(only|sole)\s+instruction", ROLE_SWITCH, "sole instruction"),
    Rule("role_switch", r"(mentor|assistant)\s+with\s+unlimited\b", ROLE_SWITCH, "mentor with unlimited power"),
]


def all_rules():
    return list(RULES)


def rules_for_category(category):
    return [r for r in RULES if r.category == category]


def find_matches(text):
    """Return a list of (Rule, match_text) pairs for every matching rule.

    The input is matched against three normalized variants (raw, homoglyph
    folded, folded + leet-decoded) so encoding-based bypasses are caught.
    Each rule contributes at most one finding regardless of how many variants
    it matched.
    """
    from llm_firewall import heuristics

    folded = heuristics.fold_homoglyphs(text)
    variants = [
        text,
        folded,
        heuristics.deleet(folded, heuristics.LEET_MAP),
        heuristics.deleet(folded, heuristics.LEET_MAP_L),
    ]
    hits = []
    matched_rules = set()
    for variant in variants:
        for rule in RULES:
            if id(rule) in matched_rules:
                continue
            matches = rule.find(variant)
            if matches:
                matched_rules.add(id(rule))
                hits.append((rule, matches[0]))
    return hits
