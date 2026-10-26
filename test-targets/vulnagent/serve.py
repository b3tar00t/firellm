"""VulnAgent — dependency-free stdlib server over agent_core.

Exposes the same endpoints as app.py (FastAPI) without any third-party package, so
the instrumented target runs anywhere Python runs. Use when FastAPI/uvicorn are
not available.

    python serve.py [--host 127.0.0.1] [--port 8003]

Endpoints: POST /chat, GET /_toollog?session_id=.., POST /_reset?session_id=..,
GET /health. Same request/response shapes as app.py.
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import agent_core


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # silence per-request stderr noise
        pass

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _query(self) -> dict:
        return {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            return self._send(200, {"status": "ok"})
        if path == "/_toollog":
            session_id = self._query().get("session_id", "")
            return self._send(200, agent_core.tool_log_response(session_id))
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        if path == "/chat":
            try:
                data = json.loads(raw or b"{}")
            except ValueError:
                return self._send(400, {"error": "invalid JSON"})
            result = agent_core.process_chat(
                data.get("messages", []), data.get("session_id"), data.get("context")
            )
            return self._send(200, result)
        if path == "/_reset":
            session_id = self._query().get("session_id", "")
            return self._send(200, agent_core.reset_session(session_id))
        self._send(404, {"error": "not found"})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8003)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"VulnAgent (stdlib) listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
