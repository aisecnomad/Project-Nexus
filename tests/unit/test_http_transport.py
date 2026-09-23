"""Exercise the destination policy through real requests/urllib3 TLS sockets."""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from shadowscan.utils.http import HttpClient


def test_https_adapter_connects_vetted_address_and_checks_original_hostname(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "service.example")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("service.example")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"keys": []}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert_path, key_path)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    port = server.server_port

    def resolve(host, requested_port, *args, **kwargs):
        assert host in {"service.example", "wrong.example"}
        assert requested_port == port
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port))]

    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolve)
    allowed = HttpClient(allow_private_origin=True, timeout=2, max_retries=0)
    blocked = HttpClient(timeout=2, max_retries=0)
    try:
        # A hostname, rather than an IP URL, reaches the adapter. It must retain
        # that name for certificate verification while connecting the vetted IP.
        assert allowed.get_json(f"https://service.example:{port}/keys", verify=str(cert_path), max_bytes=64) == {"keys": []}
        with pytest.raises(requests.exceptions.SSLError):
            allowed.get_json(f"https://wrong.example:{port}/keys", verify=str(cert_path), max_bytes=64)
        with pytest.raises(ValueError, match="Refusing"):
            blocked.get_json(f"https://service.example:{port}/keys", verify=str(cert_path), max_bytes=64)
    finally:
        allowed.session.close()
        blocked.session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
