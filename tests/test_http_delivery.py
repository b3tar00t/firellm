from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from firellm.delivery import HTTPPromptDeliveryAdapter


class _EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        payload = f"echo:{body}"
        self.wfile.write(payload.encode("utf-8"))

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def test_http_delivery_adapter_round_trips_prompt() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        adapter = HTTPPromptDeliveryAdapter(f"http://127.0.0.1:{port}/")
        response = adapter.send("hello world")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert response == "echo:hello world"
