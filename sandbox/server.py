import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from runner import run_action


TOKEN = os.environ.get("AGENTSHIELD_SANDBOX_TOKEN", "")
if len(TOKEN.encode("utf-8")) < 32:
    raise RuntimeError("Sandbox token must contain at least 32 bytes")


class SandboxHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        if self.path != "/run":
            self.send_error(404)
            return
        provided_token = self.headers.get("X-AgentShield-Sandbox-Token", "")
        if not hmac.compare_digest(provided_token, TOKEN):
            self.send_error(401)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 4096:
                raise ValueError("Invalid request size")
            request = json.loads(self.rfile.read(length))
            result = run_action(request)
        except (ValueError, json.JSONDecodeError):
            self.send_error(400)
            return
        body = json.dumps(result).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), SandboxHandler).serve_forever()
