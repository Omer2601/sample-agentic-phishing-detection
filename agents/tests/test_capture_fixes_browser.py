# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""open_capture against a real local Chromium and local servers only.

- a local HTTPS server with a freshly generated self-signed certificate: the first navigation
  fails with net::ERR_CERT_AUTHORITY_INVALID, the retry in a certificate-tolerant context sees
  the page and records `tls_certificate`; the original context stays strict;
- a local server that answers with a Content-Disposition attachment: the navigation becomes a
  fingerprinted download record and the file is never opened.

Skipped when no local Chromium can be launched (set PLAYWRIGHT_NODEJS_PATH on hosts whose glibc
is older than the bundled node needs). The url_safety guard refuses loopback, so these tests
allow 127.0.0.1 explicitly; nothing leaves the host.
"""

import datetime
import hashlib
import ipaddress
import ssl
import threading
from contextlib import AsyncExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from agent_fakes import local_playwright
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from playwright.async_api import Error as PlaywrightError

from phish_agents.common import browser, capture_recovery, http_probe, url_safety
from phish_contracts.models import Severity

PAGE = b"<!DOCTYPE html><html><head><title>Local fixture</title></head><body>hello</body></html>"
FILE = b"PK\x03\x04" + b"local archive fixture" * 100


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        if self.path.startswith("/file"):
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="payload.zip"')
            self.send_header("Content-Length", str(len(FILE)))
            self.end_headers()
            self.wfile.write(FILE)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *_args):
        pass


def _self_signed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _serve(tls_paths=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    scheme = "http"
    if tls_paths:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(*tls_paths)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"{scheme}://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def allow_loopback(monkeypatch):
    monkeypatch.setattr(browser, "request_allowed", lambda _url: None)
    monkeypatch.setattr(
        url_safety, "checked_addresses", lambda _url: (None, url_safety.HOST_OK, ["127.0.0.1"])
    )


@pytest.fixture
async def local_page():
    async with local_playwright() as pw:
        try:
            chromium = await pw.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"no local Chromium: {str(exc).splitlines()[0]}")
        context = await chromium.new_context()
        await context.route("**/*", browser.guard_route)
        page = await context.new_page()
        try:
            yield page
        finally:
            await chromium.close()


async def _open(page, url):
    return await browser.navigate(
        page, url, nav_timeout_ms=5000, settle_state="load", settle_ms=500
    )


async def test_a_self_signed_site_is_captured_once_with_certificate_checks_ignored(
    tmp_path, allow_loopback, local_page
):
    server, base = _serve(_self_signed(tmp_path))
    try:
        async with AsyncExitStack() as stack:
            nav, page = await capture_recovery.open_capture(
                stack, local_page, f"{base}/login", _open, lambda: 8000, 500
            )
            assert page is not local_page
            assert nav["status"] == 200
            assert nav["title"] == "Local fixture"
            assert nav["tls_certificate"] == {
                "type": "self_signed_or_unknown_ca",
                "code": "net::ERR_CERT_AUTHORITY_INVALID",
                "certificate_checks": capture_recovery.TLS_CHECKS_IGNORED,
            }
            assert "hello" in await page.content()
            signal = browser.tls_certificate_signal(nav)
            assert signal.name == browser.TLS_CERTIFICATE_ERROR
            # Only the retry context is lenient: the original one still refuses the cert.
            with pytest.raises(PlaywrightError, match="ERR_CERT_AUTHORITY_INVALID"):
                await local_page.goto(f"{base}/again", timeout=5000)
    finally:
        server.shutdown()
        server.server_close()


async def test_the_certificate_retry_is_skipped_without_time_left(
    tmp_path, allow_loopback, local_page
):
    server, base = _serve(_self_signed(tmp_path))
    try:
        async with AsyncExitStack() as stack:
            with pytest.raises(PlaywrightError, match="ERR_CERT_AUTHORITY_INVALID"):
                await capture_recovery.open_capture(
                    stack, local_page, f"{base}/", _open, lambda: 100, 500
                )
    finally:
        server.shutdown()
        server.server_close()


async def test_a_download_is_fingerprinted_never_opened(allow_loopback, local_page):
    server, base = _serve()
    try:
        async with AsyncExitStack() as stack:
            nav, page = await capture_recovery.open_capture(
                stack,
                local_page,
                f"{base}/file",
                _open,
                lambda: 8000,
                500,
                fingerprint=http_probe.download_fingerprint,
            )
        assert page is local_page
        dl = nav["download"]
        assert dl["filename"] == "payload.zip"
        assert dl["sha256"] == hashlib.sha256(FILE).hexdigest()
        assert dl["size"] == len(FILE)
        assert dl["kind"] == "archive"
        assert dl["content_type"] == "application/zip"
        assert dl["truncated"] is False
        assert browser.download_signal(nav).severity == Severity.MEDIUM
        assert browser.page_observed(None, nav) is False
    finally:
        server.shutdown()
        server.server_close()
