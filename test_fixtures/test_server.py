"""
A real local HTTP server exposing several endpoints, each implementing
a different real-world CORS policy (one deliberately broken in a
specific, named way, one correctly configured) - so the scanner's
probes run against real HTTP responses, not mocked header dicts.
"""

import http.server
import threading

TRUSTED_ORIGIN = "https://trusted.example"
TRUSTED_DOMAIN = "trusted.example"


class CorsTestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, status, headers, body=b"{}"):
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._handle()

    def do_GET(self):
        self._handle()

    def _handle(self):
        origin = self.headers.get("Origin")
        path = self.path

        if path == "/reflect-all-with-credentials":
            headers = {}
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
            self._send(200, headers)

        elif path == "/trust-null-origin":
            headers = {}
            if origin in (TRUSTED_ORIGIN, "null"):
                headers["Access-Control-Allow-Origin"] = origin
            self._send(200, headers)

        elif path == "/wildcard-plus-credentials-bug":
            # A real (broken) framework config: someone set both without
            # realizing the combination is meaningless to real browsers.
            headers = {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
            self._send(200, headers)

        elif path == "/naive-suffix-check":
            # The classic bug: origin.endswith(TRUSTED_DOMAIN) instead of
            # a real domain-boundary match.
            headers = {}
            if origin and origin.endswith(TRUSTED_DOMAIN):
                headers["Access-Control-Allow-Origin"] = origin
            self._send(200, headers)

        elif path == "/accepts-http-and-https":
            headers = {}
            if origin in (TRUSTED_ORIGIN, "http://" + TRUSTED_DOMAIN):
                headers["Access-Control-Allow-Origin"] = origin
            self._send(200, headers)

        elif path == "/dynamic-no-vary":
            # Correctly checks the allowlist, but forgets Vary: Origin.
            headers = {}
            if origin == TRUSTED_ORIGIN:
                headers["Access-Control-Allow-Origin"] = origin
            self._send(200, headers)

        elif path == "/properly-configured":
            headers = {}
            if origin == TRUSTED_ORIGIN:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
                headers["Vary"] = "Origin"
            self._send(200, headers)

        else:
            self._send(404, {})


def start_server(port):
    server = http.server.HTTPServer(("127.0.0.1", port), CorsTestHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server
