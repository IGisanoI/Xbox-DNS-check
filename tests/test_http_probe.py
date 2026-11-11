"""HTTP classification and request-shape tests using only a local server."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from dnschecker import http_probe


@pytest.mark.parametrize("code,state,category", [
    (200, "ok", "expected"),
    (400, "ok", "expected"),
    (401, "ok", "expected"),
    (403, "forbidden", "blocked"),
    (451, "forbidden", "blocked"),
    (500, "server_error", "server_error"),
    (502, "server_error", "server_error"),
    (503, "server_error", "server_error"),
    (302, "redirect", "redirect"),
    (404, "unexpected", "unexpected"),
])
def test_response_categories(code, state, category):
    res = http_probe.parse_response(f"HTTP/1.1 {code} Test\r\nX-Test: yes\r\n\r\nbody".encode(), 12)
    assert (res["state"], res["category"], res["code"]) == (state, category, code)
    assert res["body"] == "body" and res["head"].endswith("X-Test: yes")


def test_expected_redirect_is_an_ok_response_with_redirect_category():
    res = http_probe.parse_response(b"HTTP/1.1 302 Found\r\n\r\n", 5, expected=[200, 302])
    assert res["state"] == "ok" and res["category"] == "redirect"


def test_expected_client_error_is_not_a_block():
    res = http_probe.parse_response(b"HTTP/1.1 422 Bad token\r\n\r\n", 5, expected=[400, 422])
    assert res["state"] == "ok" and res["category"] == "expected"


def test_malformed_response_is_separate_from_server_error():
    res = http_probe.parse_response(b"not HTTP", 5)
    assert res["state"] == "no_http" and res["category"] == "invalid_response"


def test_post_sends_json_headers_payload_and_returns_body():
    received = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received["path"] = self.path
            received["contract"] = self.headers.get("x-xbl-contract-version")
            received["type"] = self.headers.get("Content-Type")
            received["json"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(401)
            self.send_header("X-Test", "present")
            self.end_headers()
            self.wfile.write(b'{"error":"invalid token"}')

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.handle_request)
    thread.start()
    try:
        res = http_probe.probe(
            "127.0.0.1", "example.com", "http", 2, method="POST", path="/xsts/authorize",
            headers={"x-xbl-contract-version": "1"}, payload={"UserTokens": ["invalid"]},
            expected=[400, 401], port=server.server_port)
    finally:
        thread.join(timeout=2)
        server.server_close()
    assert received == {"path": "/xsts/authorize", "contract": "1", "type": "application/json",
                        "json": {"UserTokens": ["invalid"]}}
    assert res["state"] == "ok" and res["code"] == 401
    assert "invalid token" in res["body"]


def test_header_injection_is_rejected():
    with pytest.raises(ValueError):
        http_probe.probe("127.0.0.1", "example.com", "http", 1, headers={"X-Test": "ok\r\nX-Evil: yes"})
