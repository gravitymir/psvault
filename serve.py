"""Tiny static dev server that disables caching.

`python -m http.server` caches aggressively, so edited JS/HTML can be served
stale during development. This sends `Cache-Control: no-store` on every response.

Usage:  python serve.py [port] [directory]
"""
import http.server
import socketserver
import sys
import os

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
directory = sys.argv[2] if len(sys.argv) > 2 else "web"
os.chdir(directory)


class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store, max-age=0")
        super().end_headers()

    def log_message(self, *args):
        pass  # keep the console quiet


with socketserver.TCPServer(("127.0.0.1", port), NoCacheHandler) as httpd:
    print(f"Serving {os.getcwd()} at http://127.0.0.1:{port}/  (no-cache)")
    httpd.serve_forever()
