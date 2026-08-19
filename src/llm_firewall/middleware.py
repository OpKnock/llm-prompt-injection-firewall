"""HTTP proxy middleware that inspects LLM API requests before forwarding.

Implements a ThreadingHTTPServer that accepts OpenAI-style JSON POSTs,
runs the detection engine, and either blocks the request (403), sanitizes
and forwards it, or passes it through untouched.
"""

import json
import logging
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from llm_firewall.engine import FirewallEngine
from llm_firewall.sanitizer import sanitize_payload

log = logging.getLogger("llm_firewall.proxy")


class RequestStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.blocked = 0
        self.sanitized = 0
        self.allowed = 0
        self.by_reason = {}

    def record(self, decision, reason=None):
        with self.lock:
            self.total += 1
            if decision == "block":
                self.blocked += 1
            elif decision == "warn":
                self.sanitized += 1
            else:
                self.allowed += 1
            if reason:
                key = reason if isinstance(reason, str) else ",".join(reason)
                self.by_reason[key] = self.by_reason.get(key, 0) + 1

    def snapshot(self):
        with self.lock:
            return {
                "total": self.total,
                "blocked": self.blocked,
                "sanitized": self.sanitized,
                "allowed": self.allowed,
                "reasons": self.by_reason,
            }


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "LLMFirewallProxy/0.1"
    engine = None
    upstream = None
    stats = None
    warn_action = "sanitize"
    timeout = 30

    def log_message(self, fmt, *args):
        log.debug("%s - %s", self.address_string(), fmt % args)

    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({"status": "ok"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/metrics":
            body = json.dumps(self.stats.snapshot()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8", errors="replace"))
        except (ValueError, KeyError):
            self.send_error(400, "invalid JSON body")
            return

        text = self.engine.inspect_messages(payload)
        if not text:
            self._forward(payload)
            return

        verdict = self.engine.analyze(text)
        log.info("decision=%s score=%d reasons=%s", verdict.decision, verdict.score, verdict.reasons)

        if verdict.decision == "block":
            self.stats.record("block", verdict.reasons)
            reason = verdict.reasons[0] if verdict.reasons else "policy"
            body = json.dumps({
                "error": {
                    "message": "request blocked by prompt injection firewall",
                    "type": "blocked",
                    "score": verdict.score,
                    "reason": reason,
                }
            }).encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if verdict.decision == "warn":
            self.stats.record("warn", verdict.reasons)
            if self.warn_action == "sanitize":
                sanitize_payload(payload)
            elif self.warn_action == "block":
                body = json.dumps({"error": {"message": "request blocked (warn threshold)", "type": "blocked"}}).encode()
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        else:
            self.stats.record("allow")

        self._forward(payload)

    def _forward(self, payload):
        req = urllib.request.Request(
            self.upstream,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = resp.read()
                self.send_response(resp.status)
                for key, value in resp.headers.items():
                    if key.lower() in ("content-length", "transfer-encoding"):
                        continue
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as err:
            data = err.read()
            self.send_response(err.code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as err:
            log.warning("upstream failure: %s", err)
            body = json.dumps({"error": {"message": "upstream unavailable"}}).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def run_proxy(upstream, listen="127.0.0.1:9000", engine=None, warn_action="sanitize"):
    """Start the proxy server; blocks until interrupted."""
    handler = ProxyHandler
    handler.engine = engine or FirewallEngine()
    handler.upstream = upstream
    handler.stats = RequestStats()
    handler.warn_action = warn_action

    host, port = listen.rsplit(":", 1)
    httpd = ThreadingHTTPServer((host, int(port)), handler)
    log.info("llm firewall proxy listening on %s, upstream %s", listen, upstream)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return httpd
