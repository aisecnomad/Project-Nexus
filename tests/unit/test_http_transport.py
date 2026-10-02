"""Exercise the destination policy through real requests/urllib3 TLS sockets."""

from __future__ import annotations

import socket
import ssl
import threading
import time
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


def _certificate(tmp_path):
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
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return cert_path, key_path


def _serve_tls(handler, cert_path, key_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(cert_path, key_path)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    return server, thread


def _resolve_to(port, monkeypatch, hosts=frozenset({"service.example"})):
    def resolve(host, requested_port, *args, **kwargs):
        assert host in hosts
        assert requested_port == port
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port))]

    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolve)


def test_https_adapter_connects_vetted_address_and_checks_original_hostname(tmp_path, monkeypatch):
    cert_path, key_path = _certificate(tmp_path)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"keys": []}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server, thread = _serve_tls(Handler, cert_path, key_path)
    port = server.server_port
    _resolve_to(port, monkeypatch, frozenset({"service.example", "wrong.example"}))
    allowed = HttpClient(allow_private_origin=True, timeout=2, max_retries=0)
    blocked = HttpClient(timeout=2, max_retries=0)
    try:
        # A hostname, rather than an IP URL, reaches the adapter. It must retain
        # that name for certificate verification while connecting the vetted IP.
        assert allowed.get_json(
            f"https://service.example:{port}/keys", verify=str(cert_path), max_bytes=64
        ) == {"keys": []}
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


# A valid JSON document the server sends one byte every DRIP_INTERVAL seconds:
# always inside the client's per-read timeout, but taking about twelve seconds,
# far beyond the one-second deadline even when a loaded runner delays the client.
DRIP_BODY = b'{"items": []}'.rjust(240)
DRIP_INTERVAL = 0.05
READ_TIMEOUT = 0.5  # the whole-body deadline is twice this


@pytest.mark.parametrize("framing", ["content-length", "chunked", "close-delimited"])
def test_slow_drip_body_fails_at_the_read_deadline_instead_of_holding_the_worker(
    tmp_path, monkeypatch, framing
):
    cert_path, key_path = _certificate(tmp_path)
    stop = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        # HTTP/1.0 without a length ends the body when the server closes it.
        protocol_version = "HTTP/1.0" if framing == "close-delimited" else "HTTP/1.1"

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if framing == "content-length":
                self.send_header("Content-Length", str(len(DRIP_BODY)))
            elif framing == "chunked":
                self.send_header("Transfer-Encoding", "chunked")
            if framing != "close-delimited":
                self.send_header("Connection", "close")
            self.end_headers()
            try:
                for byte in DRIP_BODY:
                    if stop.is_set():
                        return
                    data = bytes([byte])
                    self.wfile.write(b"1\r\n" + data + b"\r\n" if framing == "chunked" else data)
                    time.sleep(DRIP_INTERVAL)
                if framing == "chunked":
                    self.wfile.write(b"0\r\n\r\n")
            except OSError:
                return  # the client gave up on the response

        def log_message(self, *args):
            pass

    server, thread = _serve_tls(Handler, cert_path, key_path)
    port = server.server_port
    _resolve_to(port, monkeypatch)
    http = HttpClient(allow_private_origin=True, timeout=READ_TIMEOUT, max_retries=0)
    try:
        started = time.monotonic()
        with pytest.raises(ValueError, match="read deadline") as caught:
            http.get_json(f"https://service.example:{port}/items", verify=str(cert_path))
        elapsed = time.monotonic() - started
    finally:
        stop.set()
        http.session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert http.read_deadline == 2 * READ_TIMEOUT
    # The deadline interrupts a read blocked inside one 64 KiB chunk rather than
    # waiting for the server to finish its body (about twelve seconds).
    assert elapsed < len(DRIP_BODY) * DRIP_INTERVAL * 0.75
    # No transport detail is chained onto the fail-closed diagnostic.
    assert caught.value.__cause__ is None and caught.value.__context__ is None


def test_bodies_read_within_the_deadline_return_their_connection_to_the_pool(tmp_path, monkeypatch):
    cert_path, key_path = _certificate(tmp_path)
    clients = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"  # keep the connection open between requests

        def do_GET(self):
            clients.append(self.client_address)
            body = b'{"items": []}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server, thread = _serve_tls(Handler, cert_path, key_path)
    port = server.server_port
    _resolve_to(port, monkeypatch)
    http = HttpClient(allow_private_origin=True, timeout=2, max_retries=0)
    try:
        for _ in range(3):
            items = http.get_json(f"https://service.example:{port}/items", verify=str(cert_path))
            assert items == {"items": []}
    finally:
        http.session.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    # The read-deadline watchdog guards each connection's release to the pool;
    # every request still reuses the one kept-alive connection.
    assert len(clients) == 3 and len(set(clients)) == 1
