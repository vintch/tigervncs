"""Exercise the production Windows HTTP transport against isolated mock plugs."""
import base64
import hashlib
import http.server
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import urllib.request

probe = pathlib.Path(sys.argv[1]).resolve()
password = "mock-only-secret"


class Plug(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    mode = "basic"
    calls = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.close_connection = True
        authorization = self.headers.get("Authorization", "")
        valid = authorization == "Basic " + base64.b64encode(("admin:" + password).encode()).decode()
        if self.mode == "digest" and authorization.startswith("Digest "):
            fields = urllib.request.parse_keqv_list(urllib.request.parse_http_list(authorization[7:]))
            digest = lambda value: hashlib.sha256(value.encode()).hexdigest()
            expected = digest(digest("admin:test:" + password) + ":testnonce:00000001:" + fields.get("cnonce", "") + ":auth:" + digest("GET:" + self.path))
            valid = fields.get("response") == expected and fields.get("uri") == self.path
        if not valid:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Digest realm="test", nonce="testnonce", algorithm=SHA-256, qop="auth"' if self.mode == "digest" else 'Basic realm="test"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        self.calls.append((query["turn"][0], query["timer"][0]))
        body = json.dumps({"ison": query["turn"] == ["on"], "has_timer": query["turn"] == ["off"] and self.mode != "no-timer"}).encode()
        self.send_response(302 if self.mode == "redirect" else 500 if self.mode == "error" else 200)
        if self.mode == "redirect":
            self.send_header("Location", "/must-not-follow")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Plug)
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    with tempfile.TemporaryDirectory(prefix="tigervncs-shelly-") as directory:
        config = str(pathlib.Path(directory) / "tigervncs.json")
        subprocess.run([str(probe), "seed", config, f"127.0.0.1:{server.server_port}", "admin"], input=password + "\n", text=True, check=True, capture_output=True)
        assert password not in pathlib.Path(config).read_text()
        for mode, delay, cancel in [("basic", 1, -1), ("digest", 15, 100)]:
            Plug.mode, Plug.calls = mode, []
            result = subprocess.run([str(probe), "cycle", config, str(delay), str(cancel)], text=True, capture_output=True, timeout=20)
            assert result.returncode == 0, (mode, result.stdout, result.stderr)
            assert Plug.calls == [("off", str(delay)), ("on", "0")], Plug.calls
            print(mode + ": " + result.stdout.strip())
        for mode in ["error", "redirect", "no-timer"]:
            Plug.mode, Plug.calls = mode, []
            result = subprocess.run([str(probe), "cycle", config, "15", "-1"], text=True, capture_output=True, timeout=20)
            assert result.returncode == 1, result.stdout
            expected = [("off", "15"), ("on", "0")]
            if mode != "no-timer": expected.append(("on", "0"))
            assert Plug.calls == expected, Plug.calls
            print(mode + ": failure handled, power restoration attempted")
        Plug.mode, Plug.calls = "basic", []
        subprocess.run([str(probe), "seed", config, f"127.0.0.1:{server.server_port}", "admin"], input="incorrect-password\n", text=True, check=True, capture_output=True)
        result = subprocess.run([str(probe), "on", config], text=True, capture_output=True, timeout=10)
        assert result.returncode == 1 and not Plug.calls
        print("authentication: incorrect password rejected")
finally:
    server.shutdown()
