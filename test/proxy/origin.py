"""Local reference origin for the proxy authentication integration tests.

Only the fixed fixture user and routes are supported. Keeping the digest
calculation in Python's standard library makes it independent of the C++
client under test and avoids relying on the availability of a public site.
"""

import hashlib
import hmac
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import parse_http_list, parse_keqv_list


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    realm = "proxy-origin-fixture"
    nonce = "fixed-test-nonce"

    def do_GET(self):
        authorization = self.headers.get("Authorization", "")
        algorithm = None
        authenticated = False
        if self.path == "/basic-auth/hello/world":
            authenticated = authorization == "Basic aGVsbG86d29ybGQ="
            challenge = f'Basic realm="{self.realm}"'
        elif self.path.startswith("/digest-auth/auth/hello/world"):
            suffix = self.path.removeprefix("/digest-auth/auth/hello/world")
            algorithm = suffix.removeprefix("/") or "MD5"
            algorithms = {"MD5": "md5", "SHA-256": "sha256", "SHA-512": "sha512"}
            if algorithm not in algorithms:
                self.respond(404, {})
                return
            challenge = (f'Digest realm="{self.realm}", nonce="{self.nonce}", '
                         f'algorithm={algorithm}, qop="auth"')
            if authorization.startswith("Digest "):
                fields = parse_keqv_list(parse_http_list(authorization[7:]))
                digest = lambda value: hashlib.new(
                    algorithms[algorithm], value.encode("utf-8")).hexdigest()
                first = digest(f"hello:{self.realm}:world")
                second = digest(f"GET:{self.path}")
                expected = digest(":".join([
                    first, self.nonce, fields.get("nc", ""),
                    fields.get("cnonce", ""), "auth", second]))
                authenticated = (
                    fields.get("username") == "hello"
                    and fields.get("realm") == self.realm
                    and fields.get("nonce") == self.nonce
                    and fields.get("uri") == self.path
                    and fields.get("qop") == "auth"
                    and fields.get("algorithm", "MD5").upper() == algorithm
                    and hmac.compare_digest(fields.get("response", ""), expected))
        else:
            self.respond(404, {})
            return
        if not authenticated:
            self.respond(401, {}, challenge)
            return
        result = {"authenticated": True, "user": "hello"}
        if algorithm:
            result = {"algorithm": algorithm, **result}
        self.respond(200, result)

    def respond(self, status, result, challenge=None):
        payload = json.dumps(result).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        if self.close_connection:
            # BaseHTTPRequestHandler honors a client's Connection: close but
            # does not advertise it in the response. A Digest retry must know
            # to establish a fresh TLS connection before resending credentials.
            self.send_header("Connection", "close")
        if challenge:
            self.send_header("WWW-Authenticate", challenge)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    plain = ThreadingHTTPServer(("0.0.0.0", 80), Origin)
    secure = ThreadingHTTPServer(("0.0.0.0", 443), Origin)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/app/cert.pem", "/app/key.pem")
    secure.socket = context.wrap_socket(secure.socket, server_side=True)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    secure.serve_forever()
