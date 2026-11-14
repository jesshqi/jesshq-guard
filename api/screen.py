"""Jesshq Guard — public HTTPS endpoint (Vercel serverless).

POST /api/screen
  Body (JSON): {"contract": "0x...", "wallet": "0x..." (optional),
                "spender": "0x..." (optional), "chain": 56 (optional)}
  Returns: verdict (SAFE / REVIEW / AVOID), 100-point score, checks,
  risks, and a plain-language explanation.

GET  /api/screen  -> usage info (JSON).
GET  /            -> agent info (JSON, served by api/index.py).

Read-only: this endpoint never signs, sends, or spends anything. It
only reads public on-chain data and Sourcify. No API keys, no secrets.
"""

import json
import sys
import os
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guard import screen  # noqa: E402


def _usage():
    return {
        "agent": "Jesshq Guard",
        "description": "Wallet & transaction guard. Screens a smart "
        "contract (and optional wallet approvals) before you sign.",
        "endpoint": "POST /api/screen",
        "body": {
            "contract": "0x... (required)",
            "wallet": "0x... (optional, wallet to check approvals for)",
            "spender": "0x... (optional, spender/operator to check)",
            "chain": "56 (optional, default BSC; 1 = Ethereum, "
            "8453 = Base)",
        },
        "returns": "verdict SAFE / REVIEW / AVOID, score 0-100, "
        "checks, risks, explanation",
        "note": "Read-only. No signing, no spending, no keys.",
    }


class handler(BaseHTTPRequestHandler):
    def _send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send_json(200, _usage())

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            self._send_json(400, {"error": "invalid JSON body"})
            return
        contract = data.get("contract")
        if not contract:
            self._send_json(400, {"error": "field 'contract' is required"})
            return
        try:
            result = screen(
                contract,
                wallet=data.get("wallet"),
                spender=data.get("spender"),
                chain_id=int(data.get("chain") or 56),
            )
        except ValueError as e:
            self._send_json(400, {"error": str(e)})
            return
        except RuntimeError as e:
            self._send_json(502, {"error": str(e)})
            return
        self._send_json(200, result)

    def log_message(self, *args):
        pass
