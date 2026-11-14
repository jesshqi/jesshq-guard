"""Jesshq Guard — root endpoint (Vercel serverless)."""

import json
from http.server import BaseHTTPRequestHandler


class handler(BaseHTTPRequestHandler):
    def _send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send_json(200, {
            "agent": "Jesshq Guard",
            "description": "Wallet & transaction guard agent. Screens "
            "a smart contract (and optional wallet approvals) before "
            "you sign anything. Read-only, no signing, no spending.",
            "screen": "POST /api/screen with "
            '{"contract": "0x...", "wallet": "0x..." (optional), '
            '"spender": "0x..." (optional), "chain": 56 (optional)}',
            "example": {
                "contract": "0xA74081fd9bc9623A2d9321223C35b41016A7fd65",
                "chain": 56,
            },
            "competition": "zkVerify Agent Games 2026 — Wildcard track",
            "source": "https://github.com/jesshqi/jesshq-guard",
        })

    def log_message(self, *args):
        pass
