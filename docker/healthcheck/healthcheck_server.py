#!/usr/bin/env python3
import http.server

HEALTHCHECK_PATH = "/.well-known/acme-challenge/healthcheck"


class HealthcheckHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == HEALTHCHECK_PATH:
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = b"not found"
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 80), HealthcheckHandler)
    server.serve_forever()
