"""Local web GUI: `pr-sentinel gui` serves a single page on 127.0.0.1 and opens the browser.

The page reviews the demo PR, your uncommitted/unpushed changes (`git diff main`), or a pasted
diff, using the same `analyze()` pipeline as GitHub, and can run the test suite.

Local-server hardening (a browser can be tricked into calling localhost):
* Binds to 127.0.0.1 only.
* Every API call needs a random per-launch token, delivered only inside the served page.
  Other sites cannot read that page (same-origin policy), so they cannot call the API.
* The Host header must be this server, which defeats DNS-rebinding.
* Request bodies are capped; commands run are fixed argv lists, never built from input.
* The page has a strict CSP and renders all results as text, never as HTML.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import subprocess
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any

from pr_sentinel import __version__
from pr_sentinel.ai.factory import provider_factory
from pr_sentinel.config import SentinelConfig, load_config
from pr_sentinel.diff import DiffParseError, parse_unified_diff
from pr_sentinel.models import Severity
from pr_sentinel.pipeline import analyze, load_artifact
from pr_sentinel.redact import redact

log = logging.getLogger(__name__)

MAX_BODY = 2_000_000
TEST_TIMEOUT = 600


class GuiError(Exception):
    """A user-facing problem with the request (shown in the page, HTTP 400)."""


class SentinelApp:
    """The GUI's backend logic, independent of HTTP so it can be tested directly."""

    def __init__(self, root: Path, config_path: Path) -> None:
        self.root = root
        self.config_path = config_path
        self.demo_dir = root / "examples" / "demo"
        self._test_lock = threading.Lock()

    def _config(self) -> SentinelConfig:
        return load_config(self.config_path).model_copy(deep=True)

    def info(self) -> dict[str, Any]:
        ai = self._config().review.ai
        key_name = {"gemini": "GEMINI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}.get(ai.provider)
        return {
            "version": __version__,
            "demo_available": (self.demo_dir / "pr.diff").is_file(),
            "provider": ai.provider,
            "model": ai.model_name,
            "key_name": key_name,
            "key_present": bool(key_name and os.environ.get(key_name)),
        }

    def _git_diff(self) -> str:
        try:
            proc = subprocess.run(
                ["git", "diff", "main"],  # noqa: S607 - git from PATH, same as a developer would run
                cwd=self.root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )
        except FileNotFoundError as exc:
            raise GuiError("git is not installed or not on PATH.") from exc
        if proc.returncode != 0:
            raise GuiError(f"git diff failed: {proc.stderr.strip()[:200]}")
        if not proc.stdout.strip():
            raise GuiError("No changes compared to main. Edit some files, then review again.")
        return proc.stdout

    def review(self, req: dict[str, Any]) -> dict[str, Any]:
        source, ai_mode = req.get("source"), req.get("ai")
        if source not in ("demo", "local", "paste") or ai_mode not in ("off", "demo", "provider"):
            raise GuiError("Invalid request.")
        config = self._config()
        title, checks, fake_response = "", None, None

        if source == "demo":
            if not (self.demo_dir / "pr.diff").is_file():
                raise GuiError("Demo files not found (examples/demo).")
            text = (self.demo_dir / "pr.diff").read_text(encoding="utf-8")
            title = "Add user export"
            artifact, _ = load_artifact(self.demo_dir / "checks", config.review.limits.max_artifact_bytes)
            checks = artifact.checks if artifact else None
            if ai_mode == "demo":
                fake_response = self.demo_dir / "ai-response.json"
        elif source == "local":
            text = self._git_diff()
        else:
            pasted = req.get("diff")
            if not isinstance(pasted, str) or not pasted.strip():
                raise GuiError("Paste a unified diff first (for example the output of `git diff`).")
            text = pasted

        try:
            files = parse_unified_diff(text)
        except DiffParseError as exc:
            raise GuiError(f"That doesn't look like a valid diff: {exc}") from exc
        if not files:
            raise GuiError("No files found. Paste the full output of `git diff`, starting with `diff --git`.")

        if ai_mode == "off":
            config.review.ai.enabled = False
        elif ai_mode == "demo":
            config.review.ai.provider, config.review.ai.model = "fake", None
        factory = provider_factory(config, fake_response) if ai_mode != "off" else None

        result = analyze(
            files,
            config,
            factory,
            check_findings=[f for c in checks for f in c.findings] if checks else [],
            pr_title=title,
        )
        counts = {s.value: 0 for s in Severity}
        for f in result.findings:
            counts[f.severity.value] += 1
        return {
            "source": source,
            "files_changed": len(files),
            "counts": counts,
            "findings": [
                f.model_dump(mode="json") | {"fingerprint": f.fingerprint, "location": f.location}
                for f in result.findings
            ],
            "checks": [c.model_dump(mode="json", exclude={"findings"}) for c in checks] if checks else [],
            "ai": {
                "status": result.ai_status,
                "dropped": dict(result.ai.dropped) if result.ai else {},
                "files_reviewed": len(set(result.ai.files_reviewed)) if result.ai else 0,
            },
            "skipped": [{"path": s.path, "reason": s.reason} for s in result.skipped],
        }

    def run_tests(self) -> dict[str, Any]:
        if not self._test_lock.acquire(blocking=False):
            raise GuiError("Tests are already running.")
        try:
            proc = subprocess.run(
                # `-o addopts=` drops the project's extra -q so pytest prints its "N passed" line.
                [sys.executable, "-m", "pytest", "-o", "addopts=", "-q", "--color=no", "-p", "no:cacheprovider"],
                cwd=self.root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=TEST_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise GuiError(f"Tests timed out after {TEST_TIMEOUT}s.") from exc
        finally:
            self._test_lock.release()
        output = redact((proc.stdout + proc.stderr)[-8000:])
        summary = next((ln for ln in reversed(output.splitlines()) if " passed" in ln or " failed" in ln), "")
        return {
            "passed": proc.returncode == 0,
            "exit_code": proc.returncode,
            "summary": summary.strip(),
            "output": output,
        }


def _page(token: str, nonce: str) -> bytes:
    html = resources.files("pr_sentinel").joinpath("gui_static/index.html").read_text(encoding="utf-8")
    return html.replace("__TOKEN__", token).replace("__NONCE__", nonce).encode("utf-8")


def make_handler(app: SentinelApp, token: str, allowed_hosts: set[str]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "PR-Sentinel-GUI"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:
            log.debug("%s - %s", self.address_string(), format % args)

        def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: dict[str, Any]) -> None:
            self._send(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in allowed_hosts

        def _drain(self) -> None:
            """Consume any request body (capped) so replying never leaves unread bytes behind,
            which makes Windows reset the connection before the client reads the response."""
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if 0 < length <= MAX_BODY:
                self.rfile.read(length)
            elif length > MAX_BODY:
                self.close_connection = True

        def do_GET(self) -> None:
            self._drain()
            if not self._host_ok():
                self._json(HTTPStatus.FORBIDDEN, {"error": "bad host"})
                return
            if self.path in ("/", "/index.html"):
                nonce = secrets.token_urlsafe(16)
                csp = (
                    f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                    "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; "
                    "frame-ancestors 'none'"
                )
                self._send(
                    HTTPStatus.OK, _page(token, nonce), "text/html; charset=utf-8", {"Content-Security-Policy": csp}
                )
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY:
                self.close_connection = True  # the body was not read, so the connection is unusable
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request too large (max 2 MB)"})
                return
            # Read the (capped) body before any rejection: replying with unread request bytes in the
            # socket makes Windows reset the connection before the client sees the response.
            raw = self.rfile.read(length)
            if not self._host_ok():
                self._json(HTTPStatus.FORBIDDEN, {"error": "bad host"})
                return
            if not hmac.compare_digest(self.headers.get("X-Sentinel-Token", ""), token):
                self._json(HTTPStatus.FORBIDDEN, {"error": "missing or invalid token"})
                return
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "expected application/json"})
                return
            try:
                body = json.loads(raw or b"{}")
                if not isinstance(body, dict):
                    raise GuiError("Invalid request.")
                routes = {
                    "/api/info": lambda: app.info(),
                    "/api/review": lambda: app.review(body),
                    "/api/tests": lambda: app.run_tests(),
                }
                route = routes.get(self.path)
                if route is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                self._json(HTTPStatus.OK, route())
            except (GuiError, json.JSONDecodeError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc) or "Invalid JSON."})
            except Exception:
                log.exception("GUI request failed")
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "Internal error - see the terminal window."})

    return Handler


def create_server(app: SentinelApp, port: int = 8765) -> tuple[ThreadingHTTPServer, str]:
    token = secrets.token_urlsafe(32)
    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    except OSError:
        server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)  # port busy: pick a free one
    actual = server.server_address[1]
    server.RequestHandlerClass = make_handler(app, token, {f"127.0.0.1:{actual}", f"localhost:{actual}"})
    return server, token


def serve(root: Path, config_path: Path, port: int = 8765, open_browser: bool = True) -> None:
    server, _ = create_server(SentinelApp(root, config_path), port)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"\n  PR Sentinel GUI running at {url}\n  Keep this window open. Press Ctrl+C to stop.\n", flush=True)
    if open_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.", flush=True)
    finally:
        server.server_close()
