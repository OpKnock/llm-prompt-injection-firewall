"""Command line interface for the prompt injection firewall."""

import argparse
import json
import logging
import sys

from llm_firewall.engine import FirewallEngine
from llm_firewall.middleware import run_proxy
from llm_firewall.rules import all_rules
from llm_firewall.sanitizer import sanitize


def cmd_check(args):
    engine = FirewallEngine()
    verdict = engine.analyze(args.text)
    if args.json:
        print(json.dumps({
            "text": args.text,
            "score": verdict.score,
            "decision": verdict.decision,
            "reasons": verdict.reasons,
            "findings": [f.category for f in verdict.findings],
            "heuristics": verdict.heuristics,
        }, indent=2))
    else:
        print(f"score:      {verdict.score}/100")
        print(f"decision:   {verdict.decision}")
        print(f"reasons:    {', '.join(verdict.reasons) or 'none'}")
        if verdict.findings:
            print("findings:")
            for f in verdict.findings:
                print(f"  - [{f.category}] {f.pattern}")
        for key, value in verdict.heuristics.items():
            print(f"heuristic {key}: {value}")
    return 0 if verdict.decision == "allow" else 1


def cmd_sanitize(args):
    print(sanitize(args.text, max_chars=args.max_chars))
    return 0


def cmd_rules(args):
    rules = all_rules()
    print(f"{len(rules)} rules across categories:")
    seen = set()
    for rule in rules:
        if rule.category not in seen:
            print(f"\n{rule.category}:")
            seen.add(rule.category)
        print(f"  {rule.description}")
    return 0


def cmd_proxy(args):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    run_proxy(
        upstream=args.upstream,
        listen=args.listen,
        warn_action=args.warn_action,
    )
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="llm-firewall",
        description="Detect and block prompt injection attempts on LLM API traffic.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="score a single text input")
    check.add_argument("text", help="input text to analyze")
    check.add_argument("--json", action="store_true", help="emit JSON")
    check.set_defaults(func=cmd_check)

    san = sub.add_parser("sanitize", help="sanitize a text input")
    san.add_argument("text", help="input text to sanitize")
    san.add_argument("--max-chars", type=int, default=4000)
    san.set_defaults(func=cmd_sanitize)

    rules = sub.add_parser("rules", help="list detection rules")
    rules.set_defaults(func=cmd_rules)

    proxy = sub.add_parser("proxy", help="run the HTTP proxy")
    proxy.add_argument("--listen", default="127.0.0.1:9000", help="bind address")
    proxy.add_argument("--upstream", required=True, help="upstream LLM API URL")
    proxy.add_argument("--warn-action", choices=("sanitize", "pass", "block"), default="sanitize")
    proxy.set_defaults(func=cmd_proxy)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
