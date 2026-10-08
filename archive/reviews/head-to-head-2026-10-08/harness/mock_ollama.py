import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        if self.path == "/": return self._send(200, "Ollama is running", "text/plain; charset=utf-8")
        if self.path == "/api/version": return self._send(200, {"version": "0.1.33"})
        if self.path == "/api/tags": return self._send(200, {"models": [{"name": "llama3:8b", "model": "llama3:8b", "size": 4661224676, "digest": "365c0bd3c000", "details": {"family": "llama", "parameter_size": "8B", "quantization_level": "Q4_0"}}]})
        if self.path == "/api/ps": return self._send(200, {"models": []})
        return self._send(404, "404 page not found", "text/plain")
    def do_POST(self):
        if self.path in ("/api/generate", "/api/chat", "/api/show"): return self._send(200, {"model": "llama3:8b", "response": "ok", "done": True})
        return self._send(404, "404 page not found", "text/plain")
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 11434), H).serve_forever()
