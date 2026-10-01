"""Okta rate-limit headers, wall-clock read cap, retry cancellation and an explicit private CA bundle."""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from shadowscan.utils.http import (
    MAX_RETRY_DELAY,
    HttpClient,
    _retry_delay,
    reset_request_deadline,
    set_request_deadline,
)

NOW = 1_800_000_000.0


def response(data=None, status=200, headers=None):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(data).encode()
    result._content_consumed = True
    result.headers.update(headers or {})
    return result


def client(*responses, **kwargs):
    session = Mock(headers={})
    session.request.side_effect = responses
    return HttpClient("https://api.example.com/v1", session=session, **kwargs), session


def okta_429(reset_in: float, remaining: str = "0"):
    return response(
        {"errorCode": "E0000047"},
        status=429,
        headers={
            "X-Rate-Limit-Limit": "100",
            "X-Rate-Limit-Remaining": remaining,
            "X-Rate-Limit-Reset": str(int(NOW + reset_in)),
        },
    )


# --------------------------------------------------------------- Okta limits
@pytest.fixture
def fixed_clock(monkeypatch):
    monkeypatch.setattr("shadowscan.utils.http.time.time", lambda: NOW)


def test_okta_reset_header_sets_the_retry_delay(fixed_clock):
    assert _retry_delay(okta_429(30), attempt=1) == 31.0


def test_okta_reset_header_is_honored_on_later_attempts(fixed_clock):
    assert _retry_delay(okta_429(45), attempt=4) == 46.0


def test_okta_reset_is_bounded(fixed_clock):
    assert _retry_delay(okta_429(10**9), attempt=1) == MAX_RETRY_DELAY
    assert _retry_delay(okta_429(10**9), attempt=1) <= 120


def test_okta_reset_in_the_past_falls_back_to_backoff(fixed_clock):
    assert 0.5 <= _retry_delay(okta_429(-500), attempt=1) <= 2.0


def test_okta_reset_header_is_ignored_when_the_limit_was_not_hit(fixed_clock):
    ok = response(
        {"ok": True},
        status=503,
        headers={"X-Rate-Limit-Remaining": "7", "X-Rate-Limit-Reset": str(int(NOW + 90))},
    )
    assert _retry_delay(ok, attempt=1) <= 2.0


@pytest.mark.parametrize("value", ["", "soon", "-5", "1e9", "٣٠"])
def test_malformed_okta_reset_header_is_ignored(fixed_clock, value):
    bad = response({}, status=429, headers={"X-Rate-Limit-Remaining": "0", "X-Rate-Limit-Reset": value})
    assert _retry_delay(bad, attempt=1) <= 2.0


def test_github_style_headers_still_work(fixed_clock):
    github = response(
        {}, status=403, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(NOW + 12))}
    )
    assert _retry_delay(github, attempt=1) == 13.0


def test_client_sleeps_until_the_okta_window_resets(monkeypatch, fixed_clock):
    sleep = Mock()
    monkeypatch.setattr("shadowscan.utils.http.time.sleep", sleep)
    http, session = client(okta_429(20), response({"ok": True}))
    assert http.get_json("/apps") == {"ok": True}
    sleep.assert_called_once_with(21.0)
    assert session.request.call_count == 2


# ------------------------------------------------------ retry cancel/deadline
def test_cancelled_scan_does_not_sleep_through_a_retry(monkeypatch):
    sleep = Mock()
    monkeypatch.setattr("shadowscan.utils.http.time.sleep", sleep)
    cancelled = threading.Event()
    cancelled.set()
    http, session = client(
        response(status=429, headers={"Retry-After": "30"}), response({"ok": True}), cancelled=cancelled
    )
    with pytest.raises(TimeoutError, match="deadline"):
        http.get_json("/items")
    sleep.assert_not_called()
    assert session.request.call_count == 1


def test_retry_that_cannot_finish_before_the_deadline_is_not_attempted(monkeypatch):
    sleep = Mock()
    monkeypatch.setattr("shadowscan.utils.http.time.sleep", sleep)
    http, session = client(
        response(status=429, headers={"Retry-After": "30"}),
        response({"ok": True}),
        deadline=time.monotonic() + 5,
    )
    with pytest.raises(TimeoutError, match="deadline"):
        http.get_json("/items")
    sleep.assert_not_called()
    assert session.request.call_count == 1


def test_scan_wide_deadline_hook_reaches_clients_built_inside_the_connector(monkeypatch):
    monkeypatch.setattr("shadowscan.utils.http.time.sleep", Mock())
    cancelled = threading.Event()
    token = set_request_deadline(None, cancelled)
    try:
        http, _ = client(response(status=429, headers={"Retry-After": "1"}), response({"ok": True}))
    finally:
        reset_request_deadline(token)
    cancelled.set()
    with pytest.raises(TimeoutError, match="deadline"):
        http.get_json("/items")
    late, _ = client(response({"ok": True}))
    assert late.get_json("/items") == {"ok": True}


def test_without_a_deadline_retry_behavior_is_unchanged(monkeypatch):
    sleep = Mock()
    monkeypatch.setattr("shadowscan.utils.http.time.sleep", sleep)
    http, _ = client(response(status=429, headers={"Retry-After": "3"}), response({"ok": True}))
    assert http.get_json("/items") == {"ok": True}
    sleep.assert_called_once()


# ------------------------------------------------------ real TLS server tests
def _write_certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "internal.example")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("internal.example"),
                    x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "ca.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return cert_path, key_path


@pytest.fixture
def tls_server(tmp_path):
    import ssl

    cert_path, key_path = _write_certificate(tmp_path)
    stop = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/drip":
                self.send_response(200)
                self.send_header("Content-Length", "100000")
                self.end_headers()
                try:
                    for _ in range(100000):
                        if stop.is_set():
                            return
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.05)
                except OSError:
                    return
                return
            body = b'{"keys": []}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert_path, key_path)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_port}", cert_path
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_slow_drip_response_is_bounded_by_the_wall_clock(tls_server):
    base, cert = tls_server
    http = HttpClient(
        allow_private_origin=True, timeout=5, max_retries=0, ca_bundle=str(cert), max_read_seconds=1.0
    )
    started = time.monotonic()
    try:
        with pytest.raises(requests.exceptions.ReadTimeout):
            http.get_json(f"{base}/drip")
    finally:
        http.session.close()
    assert time.monotonic() - started < 5


def test_fast_response_within_the_wall_clock_cap_is_unaffected(tls_server):
    base, cert = tls_server
    http = HttpClient(
        allow_private_origin=True, timeout=5, max_retries=0, ca_bundle=str(cert), max_read_seconds=5.0
    )
    try:
        assert http.get_json(f"{base}/keys") == {"keys": []}
    finally:
        http.session.close()


def test_private_ca_needs_the_explicit_bundle_and_verification_stays_on(tls_server, monkeypatch):
    base, cert = tls_server
    # Ambient variables are never trusted; only the explicit option adds a CA.
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(cert))
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    default = HttpClient(allow_private_origin=True, timeout=5, max_retries=0)
    trusted = HttpClient(allow_private_origin=True, timeout=5, max_retries=0, ca_bundle=str(cert))
    try:
        with pytest.raises(requests.exceptions.SSLError):
            default.get_json(f"{base}/keys")
        assert trusted.get_json(f"{base}/keys") == {"keys": []}
        assert trusted.session.verify == str(cert)
        with pytest.raises(ValueError, match="verification cannot be disabled"):
            trusted.get_json(f"{base}/keys", verify=False)
    finally:
        default.session.close()
        trusted.session.close()


# ---------------------------------------------------------- option validation
def test_ca_bundle_must_be_an_existing_regular_file(tmp_path):
    missing = tmp_path / "missing.pem"
    with pytest.raises(ValueError, match="ca_bundle"):
        HttpClient(ca_bundle=str(missing))
    with pytest.raises(ValueError, match="ca_bundle"):
        HttpClient(ca_bundle=str(tmp_path))
    with pytest.raises(ValueError, match="ca_bundle"):
        HttpClient(ca_bundle="")
    for bad in (False, 0, b"/etc/ssl/certs"):
        with pytest.raises((TypeError, ValueError), match="ca_bundle"):
            HttpClient(ca_bundle=bad)  # type: ignore[arg-type]


def test_ca_bundle_defaults_leave_certifi_verification_untouched():
    http = HttpClient()
    assert http.session.verify is True
    http.session.close()


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), True, "30"])
def test_read_time_cap_must_be_a_positive_finite_number(value):
    with pytest.raises(ValueError, match="max_read_seconds"):
        HttpClient(max_read_seconds=value)  # type: ignore[arg-type]


# --------------------------------------------------------------- JWKS and CA
def test_jwks_fetch_trusts_an_explicit_private_ca_only_when_configured(tls_server):
    from shadowscan.utils.http import reset_allow_private_origin, set_allow_private_origin
    from shadowscan.utils.jwks import fetch_jwks

    base, cert = tls_server
    token = set_allow_private_origin(True)
    try:
        assert fetch_jwks(f"{base}/keys", ca_bundle=str(cert)) == {"keys": []}
        with pytest.raises(requests.exceptions.SSLError):
            fetch_jwks(f"{base}/keys")
    finally:
        reset_allow_private_origin(token)


def test_jwt_connector_passes_the_configured_ca_bundle_to_the_jwks_fetch(index, monkeypatch, tmp_path):
    from shadowscan.connectors import ConnectorContext
    from shadowscan.connectors.identity.jwt import JwtConnector

    bundle = tmp_path / "ca.pem"
    bundle.write_text("placeholder")
    seen = []

    def fetch(url, **kwargs):
        seen.append((url, kwargs))
        return {"keys": []}

    monkeypatch.setattr("shadowscan.connectors.identity.jwt.fetch_jwks", fetch)
    with_bundle = JwtConnector(ConnectorContext(index=index, config={"ca_bundle": str(bundle)}))
    assert with_bundle._jwks_document("https://keys.example/jwks") == {"keys": []}
    without = JwtConnector(ConnectorContext(index=index, config={}))
    assert without._jwks_document("https://keys.example/jwks") == {"keys": []}
    assert seen == [
        ("https://keys.example/jwks", {"ca_bundle": str(bundle)}),
        ("https://keys.example/jwks", {}),
    ]
    assert "ca_bundle" in JwtConnector.config_keys
