"""An HTTP server whose class is imported under the name Server: not an MCP server."""

from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer as Server


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()


httpd = Server(("", 8000), Handler)
httpd.serve_forever()
