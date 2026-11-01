"""Local GUI: backend logic and HTTP hardening, against a real server on a free port."""

from __future__ import annotations

import http.client
import json
import re
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from conftest import ROOT

from pr_sentinel.gui import GuiError, SentinelApp, create_server


@pytest.fixture
def app(tmp_path: Path) -> SentinelApp:
    config = tmp_path / "c.yml"
    config.write_text("review: {ai: {provider: gemini}}")
    return SentinelApp(ROOT, config)


@pytest.fixture
def server(app: SentinelApp) -> Iterator[tuple[int, str]]:
    srv, token = create_server(app, port=0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv.server_address[1], token
    srv.shutdown()
    srv.server_close()


def call(port: int, method: str, path: str, body: Any = None, headers: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json"} | (headers or {})
    conn.request(method, path, body=data, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), raw


def test_demo_review_with_demo_ai(app: SentinelApp) -> None:
    data = app.review({"source": "demo", "ai": "demo"})
    assert data["counts"]["critical"] == 1 and data["counts"]["high"] == 4
    assert {f["source"] for f in data["findings"]} == {"check", "rule", "ai"}
    assert data["ai"]["dropped"] == {"low_confidence": 1, "ungrounded": 1, "unknown_file": 1}
    assert [c["name"] for c in data["checks"]] == ["tests", "lint", "secrets", "dependencies"]


def test_ai_off_and_missing_key(app: SentinelApp) -> None:
    off = app.review({"source": "demo", "ai": "off"})
    assert off["ai"]["status"] == "disabled in configuration"
    assert all(f["source"] != "ai" for f in off["findings"])
    real = app.review({"source": "demo", "ai": "provider"})  # conftest removes real keys
    assert "GEMINI_API_KEY" in real["ai"]["status"]


def test_pasted_diff_and_validation(app: SentinelApp) -> None:
    diff = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+data = yaml.load(stream)\n"
    data = app.review({"source": "paste", "ai": "off", "diff": diff})
    assert [f["rule_id"] for f in data["findings"]] == ["py-yaml-unsafe-load"]
    for bad, msg in [("", "Paste a unified diff"), ("hello world", "No files found")]:
        with pytest.raises(GuiError, match=msg):
            app.review({"source": "paste", "ai": "off", "diff": bad})
    with pytest.raises(GuiError, match="Invalid request"):
        app.review({"source": "../etc", "ai": "off"})


def test_page_is_served_with_token_and_strict_csp(server: tuple[int, str]) -> None:
    port, token = server
    status, headers, body = call(port, "GET", "/", headers={"Host": f"127.0.0.1:{port}"})
    assert status == 200
    html = body.decode()
    assert f'content="{token}"' in html
    csp = headers["Content-Security-Policy"]
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)  # type: ignore[union-attr]
    assert f'<script nonce="{nonce}">' in html and "'unsafe-inline'" not in csp
    assert "innerHTML" not in html, "results must be rendered as text only"


def test_api_requires_token(server: tuple[int, str]) -> None:
    port, token = server
    status, _, _ = call(port, "POST", "/api/info", {})
    assert status == 403
    status, _, _ = call(port, "POST", "/api/info", {}, {"X-Sentinel-Token": "wrong"})
    assert status == 403
    status, _, raw = call(port, "POST", "/api/review", {"source": "demo", "ai": "off"}, {"X-Sentinel-Token": token})
    assert status == 200 and json.loads(raw)["counts"]["critical"] == 1


def test_dns_rebinding_host_is_rejected(server: tuple[int, str]) -> None:
    port, token = server
    for method, path in (("GET", "/"), ("POST", "/api/info")):
        status, _, _ = call(port, method, path, {}, {"Host": f"evil.example:{port}", "X-Sentinel-Token": token})
        assert status == 403


def test_bad_requests_get_clean_errors(server: tuple[int, str]) -> None:
    port, token = server
    auth = {"X-Sentinel-Token": token}
    status, _, raw = call(port, "POST", "/api/review", {"source": "paste", "ai": "off", "diff": "x"}, auth)
    assert status == 400 and "No files found" in json.loads(raw)["error"]
    status, _, _ = call(port, "POST", "/api/nope", {}, auth)
    assert status == 404
    status, _, _ = call(port, "POST", "/api/info", {}, auth | {"Content-Type": "text/plain"})
    assert status == 415
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.putrequest("POST", "/api/review")
    for k, v in (auth | {"Content-Type": "application/json", "Content-Length": "999999999"}).items():
        conn.putheader(k, v)
    conn.endheaders()
    assert conn.getresponse().status == 413
    conn.close()
