"""Stateless HTTP probe for a synthetic receipt. Does not write payment records."""

import base64
import binascii
import hashlib
import hmac
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from re import fullmatch
from tempfile import TemporaryDirectory
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def download_fixture(url: str) -> bytes:
    allowed = os.environ.get("RECEIPT_TEST_FIXTURE_URL", "")
    if url != allowed or not fullmatch(
        r"https://files\.salebot\.pro/uploads/file_item/file/[0-9]+/[a-zA-Z0-9_-]+\.png",
        allowed,
    ):
        raise ValueError("Unrecognized fixture URL")
    with build_opener(NoRedirect()).open(allowed, timeout=4) as response:
        data = response.read(1_000_001)
    if len(data) > 1_000_000:
        raise ValueError("Fixture exceeds size limit")
    return data


def recognize(data: bytes) -> dict[str, str]:
    with TemporaryDirectory(prefix="receipt-fixture-") as directory:
        image = Path(directory) / "fixture.png"
        image.write_bytes(data)
        result = subprocess.run(
            ["tesseract", image, "stdout", "-l", "eng", "--psm", "6"],
            env={**os.environ, "OMP_THREAD_LIMIT": "1"},
            capture_output=True,
            timeout=7,
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
        media_type = self.headers.get_content_type()
        self.connection.settimeout(10)
        try:
            data = self.rfile.read(int(length))
        except TimeoutError:
            return self.reply(408, status="timeout")
        if media_type == "application/json" or data.lstrip().startswith(b"{"):
            try:
                payload = json.loads(data)
                if not isinstance(payload, dict):
                    return self.reply(400, status="invalid_test_payload")
                if set(payload) == {"image_url"}:
                    data = download_fixture(payload["image_url"])
                elif set(payload) == {"image_base64"}:
                    data = base64.b64decode(payload["image_base64"], validate=True)
                else:
                    return self.reply(400, status="invalid_test_payload")
            except (UnicodeError, ValueError, TypeError, binascii.Error):
                return self.reply(400, status="invalid_test_payload")
            except (URLError, OSError):
                return self.reply(502, status="fixture_unavailable")
        elif media_type != "image/png":
            return self.reply(415, status="invalid_type")
        if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), fixture_digest):
            return self.reply(422, status="unknown_test_fixture")
        try:
            fields = recognize(data)
        except subprocess.CalledProcessError as error:
            print(f"Synthetic fixture OCR exited {error.returncode}: {error.stderr[:400]!r}", flush=True)
            return self.reply(422, status="ocr_failed")
        except (OSError, subprocess.SubprocessError, UnicodeError) as error:
            print(f"Synthetic fixture OCR failed: {type(error).__name__}", flush=True)
            return self.reply(422, status="ocr_failed")
        if fields.get("AMOUNT") != "4500.00 RUB" or fields.get("OPERATION") != "123456789012":
            return self.reply(422, status="ocr_fields_mismatch")
        return self.reply(200, status="recognized", amount_kopecks=450000, operation="123456789012")

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "10000"))), ReceiptProbe).serve_forever()
