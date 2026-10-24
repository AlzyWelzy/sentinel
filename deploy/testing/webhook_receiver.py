"""Tiny webhook receiver for end-to-end tests: verifies the HMAC signature and
appends each delivery to a JSON-lines file.

    python3 deploy/testing/webhook_receiver.py 18999 change-me-webhook-secret /tmp/hooks.jsonl
"""

import hashlib
import hmac
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT, SECRET, OUT = int(sys.argv[1]), sys.argv[2].encode(), sys.argv[3]


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        expected = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(expected, self.headers.get("X-Pulsegrid-Signature", ""))
        with open(OUT, "a") as f:
            f.write(json.dumps({"signature_valid": ok, "body": json.loads(body)}) + "\n")
        self.send_response(200 if ok else 401)
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
