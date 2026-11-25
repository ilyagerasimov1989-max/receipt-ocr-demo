"""Stateless HTTP probe for a synthetic receipt. Does not write payment records."""

import hashlib
import hmac
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def recognize(data: bytes) -> dict[str, str]:
    result = subprocess.run(
        ["tesseract", "stdin", "stdout", "--psm", "6"],
        input=data,
        capture_output=True,
        timeout=10,
        check=True,
    )
    return {
        key.strip(): value.strip()
        for key, separator, value in (line.partition(":") for line in result.stdout.decode().splitlines())
        if separator
    }


class ReceiptProbe(BaseHTTPRequestHandler):
    def reply(self, code: int, **body):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, status="ok", test_only=True)
        else:
            self.reply(404, status="not_found")

    def do_POST(self):
        if self.path != "/test/receipts":
            return self.reply(404, status="not_found")
        token = os.environ.get("RECEIPT_TEST_TOKEN", "")
        fixture_digest = os.environ.get("RECEIPT_TEST_SHA256", "")
        if len(token) < 32 or len(fixture_digest) != 64:
            return self.reply(503, status="test_disabled")
        authorization = self.headers.get("Authorization", "").encode()
        if not hmac.compare_digest(authorization, f"Bearer {token}".encode()):
            return self.reply(401, status="unauthorized")
        length = self.headers.get("Content-Length", "")
        if not length.isascii() or not length.isdecimal() or not 0 < int(length) <= 1_000_000:
            return self.reply(400, status="invalid_size")
        if self.headers.get_content_type() != "image/png":
            return self.reply(415, status="invalid_type")
        self.connection.settimeout(10)
        try:
            data = self.rfile.read(int(length))
        except TimeoutError:
            return self.reply(408, status="timeout")
        if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), fixture_digest):
            return self.reply(422, status="unknown_test_fixture")
        try:
            fields = recognize(data)
        except (OSError, subprocess.SubprocessError, UnicodeError):
            return self.reply(422, status="ocr_failed")
        if fields.get("AMOUNT") != "4500.00 RUB" or fields.get("OPERATION") != "123456789012":
            return self.reply(422, status="ocr_fields_mismatch")
        return self.reply(200, status="recognized", amount_kopecks=450000, operation="123456789012")

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "10000"))), ReceiptProbe).serve_forever()
