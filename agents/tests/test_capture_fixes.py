# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Capture fixes from the 2026-10-31 capture-failure analysis (no browser needed).

S3 website endpoints over http, certificate-error typing, download fingerprinting, the
deterministic takedown / parked page state, and DNS transient-error labelling and retry.
Every network test talks to a local server or an httpx transport; no eval URL is used.
"""

import asyncio
import hashlib
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from playwright.async_api import Error as PlaywrightError

from phish_agents.common import browser, capture_recovery, http_probe, page_state, url_safety
from phish_agents.common.browser import CaptureFailure
from phish_contracts.models import PageState, PageStateObservation, Severity

FIXTURES = Path(__file__).parent / "fixtures" / "page_state"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


# --- 1. S3 website endpoints over http -------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://my-bucket.s3-website-us-east-1.amazonaws.com/index.html?a=1#x",
            "http://my-bucket.s3-website-us-east-1.amazonaws.com/index.html?a=1#x",
        ),
        (
            "https://my-bucket.s3-website.eu-west-2.amazonaws.com/",
            "http://my-bucket.s3-website.eu-west-2.amazonaws.com/",
        ),
        (
            "https://My.Bucket.S3-Website-AP-Southeast-1.amazonaws.com",
            "http://my.bucket.s3-website-ap-southeast-1.amazonaws.com",
        ),
        (
            "https://b.s3-website.us-gov-west-1.amazonaws.com/p",
            "http://b.s3-website.us-gov-west-1.amazonaws.com/p",
        ),
        (
            "https://b.s3-website.cn-north-1.amazonaws.com.cn/",
            "http://b.s3-website.cn-north-1.amazonaws.com.cn/",
        ),
        (
            "https://b.s3-website-us-east-1.amazonaws.com:443/x",
            "http://b.s3-website-us-east-1.amazonaws.com/x",
        ),
    ],
)
def test_s3_website_endpoints_are_opened_over_http(url, expected):
    assert capture_recovery.s3_website_http_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://b.s3-website-us-east-1.amazonaws.com/",
        "https://b.s3.us-east-1.amazonaws.com/key",
        "https://b.s3.amazonaws.com/key",
        "https://s3-website-us-east-1.amazonaws.com.evil.example/",
        "https://b.s3-website-us-east-1.amazonaws.com.evil.example/",
        "https://example.com/b.s3-website-us-east-1.amazonaws.com",
        "https://b.s3-website-us-east-1.amazonaws.com:8443/",
        "https://[::1/",
    ],
)
def test_other_urls_are_left_alone(url):
    assert capture_recovery.s3_website_http_url(url) == url


def test_brand_and_code_captures_use_the_http_url():
    from phish_agents.brand_visual.capture import BrandCapture
    from phish_agents.code_analyst.capture import CodeCapture

    url = "https://site.s3-website-us-east-1.amazonaws.com/login"
    brand = BrandCapture(url, "scan-00000001", None, None, "bucket")
    code = CodeCapture(url, "scan-00000001", None, None, "bucket")
    assert brand.url == code.url == "http://site.s3-website-us-east-1.amazonaws.com/login"


async def test_precheck_navigates_the_http_url(monkeypatch, public_dns):
    from phish_agents.tools_server import server

    seen: list[str] = []

    async def preflight(url):
        seen.append(url)

    class Page:
        pass

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def open_page(_recorder, _name, **_kw):
        yield Page()

    async def precheck_navigation(_page, url):
        seen.append(url)
        return {"final_url": url, "status": 200, "hops": []}

    monkeypatch.setattr(server, "precheck_navigation", precheck_navigation)
    out = json.loads(
        await server.run_precheck_url(
            "https://site.s3-website-us-east-1.amazonaws.com/",
            "scan-00000001",
            open_page_fn=open_page,
            preflight_fn=preflight,
        )
    )
    assert seen == ["http://site.s3-website-us-east-1.amazonaws.com/"] * 2
    assert out["outcome"] == "ok"


# --- 2. Certificate error typing and the tls_certificate_error signal ------------------------


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("net::ERR_CERT_AUTHORITY_INVALID", "self_signed_or_unknown_ca"),
        ("net::ERR_CERT_COMMON_NAME_INVALID", "hostname_mismatch"),
        ("net::ERR_CERT_DATE_INVALID", "expired_or_not_yet_valid"),
        ("net::ERR_CERT_REVOKED", "invalid_certificate"),
        ("net::ERR_SSL_PROTOCOL_ERROR", None),
        ("net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH", None),
    ],
)
def test_certificate_error_type(code, expected):
    assert browser.certificate_error_type(CaptureFailure(browser.TLS_ERROR, code)) == expected


def test_certificate_error_type_ignores_other_failures():
    assert browser.certificate_error_type(None) is None
    assert (
        browser.certificate_error_type(
            CaptureFailure(browser.SITE_UNREACHABLE, "net::ERR_CERT_AUTHORITY_INVALID")
        )
        is None
    )


def test_tls_certificate_signal_is_low_infra_evidence():
    nav = {
        "final_url": "https://self-signed.example/",
        "status": 200,
        "tls_certificate": {
            "type": "self_signed_or_unknown_ca",
            "code": "net::ERR_CERT_AUTHORITY_INVALID",
            "certificate_checks": capture_recovery.TLS_CHECKS_IGNORED,
        },
    }
    signals = {s.name: s for s in browser.capture_signals(nav)}
    sig = signals[browser.TLS_CERTIFICATE_ERROR]
    assert sig.severity == Severity.LOW
    assert "self_signed_or_unknown_ca" in sig.evidence
    assert "not authenticated" in sig.evidence
    assert browser.page_observed(None, nav) is True


# --- 3. Download responses -------------------------------------------------------------------


def test_classify_failure_labels_a_download():

    failure = browser.classify_failure(PlaywrightError("Page.goto: Download is starting"))
    assert (failure.category, failure.code) == (browser.BROWSER_ERROR, browser.DOWNLOAD_STARTED)


@pytest.mark.parametrize(
    ("head", "mime", "kind"),
    [
        (b"MZ\x90\x00", "application/x-msdownload", "executable"),
        (b"\x7fELF\x02", "application/x-elf", "executable"),
        (b"PK\x03\x04rest", "application/zip", "archive"),
        (b"%PDF-1.7", "application/pdf", "document"),
        (b"\xef\xbb\xbf  <!DOCTYPE html><html>", "text/html", "html"),
        (b"plain bytes", "application/octet-stream", "other"),
    ],
)
def test_sniff_file_type_reads_magic_bytes(head, mime, kind):
    got_mime, got_kind = http_probe.sniff_file_type(head)
    assert got_kind == kind
    assert got_mime == mime


def _file_transport(body: bytes, headers: dict | None = None, seen: list | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(str(request.url))
        if request.url.path == "/go":
            return httpx.Response(302, headers={"location": "/files/invoice.zip"})
        return httpx.Response(200, headers=headers or {}, stream=httpx.ByteStream(body))

    return httpx.MockTransport(handler)


async def test_download_fingerprint_hashes_a_small_file(public_dns):
    body = b"PK\x03\x04" + b"x" * 5000
    out = await http_probe.download_fingerprint(
        "https://files.example/go",
        transport=_file_transport(
            body,
            {
                "content-type": "application/octet-stream",
                "content-disposition": 'attachment; filename="invoice.zip"',
            },
        ),
    )
    assert out["outcome"] == "ok"
    assert out["final_url"] == "https://files.example/files/invoice.zip"
    assert out["sha256"] == hashlib.sha256(body).hexdigest()
    assert out["size"] == out["bytes_read"] == len(body)
    assert out["truncated"] is False
    assert out["kind"] == "archive"
    assert out["sniffed_type"] == "application/zip"
    assert out["content_type"] == "application/octet-stream"
    assert "invoice.zip" in out["content_disposition"]


async def test_download_fingerprint_stops_at_the_size_cap(public_dns):
    body = b"MZ" + b"\0" * 9000
    out = await http_probe.download_fingerprint(
        "https://files.example/big.exe", max_bytes=4096, transport=_file_transport(body)
    )
    assert out["truncated"] is True
    assert out["sha256"] is None
    assert out["bytes_read"] == 4096
    assert out["size_cap"] == 4096
    assert out["kind"] == "executable"


async def test_a_compressed_download_is_not_fingerprinted(public_dns):
    out = await http_probe.download_fingerprint(
        "https://files.example/doc.pdf",
        transport=_file_transport(b"\x1f\x8b\x08\x00", {"content-encoding": "gzip"}),
    )
    assert out["outcome"] == "unreachable"
    assert "gzip" in out["reason"]
    assert out["sha256"] is None


async def test_a_file_exactly_at_the_cap_keeps_its_hash(public_dns):
    body = b"%PDF-1.7\n" + b"\0" * (4096 - 9)
    out = await http_probe.download_fingerprint(
        "https://files.example/exact.pdf", max_bytes=4096, transport=_file_transport(body)
    )
    assert out["truncated"] is False
    assert out["sha256"] == hashlib.sha256(body).hexdigest()
    assert out["size"] == out["bytes_read"] == 4096


async def test_download_fingerprint_is_guarded(monkeypatch):
    def private_dns(host, *_a, **_k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", private_dns)
    seen: list = []
    out = await http_probe.download_fingerprint(
        "https://inside.example/f.bin", transport=_file_transport(b"x", seen=seen)
    )
    assert out["outcome"] == "blocked"
    assert out["sha256"] is None
    assert seen == []


async def test_download_fingerprint_never_raises(public_dns):
    async def boom(_request):
        raise httpx.ConnectError("refused")

    out = await http_probe.download_fingerprint(
        "https://files.example/f.bin", transport=httpx.MockTransport(boom)
    )
    assert out["outcome"] in {"site_down", "unreachable", "error"}
    assert out["sha256"] is None


class _AttachmentHandler(BaseHTTPRequestHandler):
    body = b"%PDF-1.4 local fixture\n" + b"0" * 2048

    def do_GET(self):  # noqa: N802 - http.server API
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", 'attachment; filename="../../etc/statement.pdf"')
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *_args):
        pass


@pytest.fixture
def attachment_server(monkeypatch):
    """A local server that answers every GET with a Content-Disposition attachment.

    The guard refuses loopback, so checked_addresses is replaced with an allow-only answer
    for 127.0.0.1; the pinned transport then dials that address for real."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AttachmentHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(
        url_safety,
        "checked_addresses",
        lambda _url: (None, url_safety.HOST_OK, ["127.0.0.1"]),
    )
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


async def test_download_nav_fingerprints_a_real_local_attachment(attachment_server):
    class Download:
        url = f"{attachment_server}/statement"
        suggested_filename = ""
        cancelled = False

        async def cancel(self):
            Download.cancelled = True

    class Page:
        def on(self, *_a):
            pass

        def remove_listener(self, *_a):
            pass

    watch = capture_recovery.DownloadWatch(Page())
    watch.download = Download()
    nav = await capture_recovery.download_nav(
        watch, f"{attachment_server}/statement", lambda: 5000, http_probe.download_fingerprint
    )
    dl = nav["download"]
    assert Download.cancelled is True
    assert dl["filename"] == "statement.pdf"
    assert dl["sha256"] == hashlib.sha256(_AttachmentHandler.body).hexdigest()
    assert dl["size"] == len(_AttachmentHandler.body)
    assert dl["content_type"] == "application/pdf"
    assert dl["kind"] == "document"
    assert dl["fetched"] == "guarded_refetch"
    assert nav["status"] == 200
    signal = browser.download_signal(nav)
    assert signal.name == browser.DOWNLOAD_RESPONSE
    assert signal.severity == Severity.LOW
    assert dl["sha256"] in signal.evidence
    assert browser.page_observed(None, nav) is False


@pytest.mark.parametrize(
    ("kind", "severity"),
    [
        ("executable", Severity.MEDIUM),
        ("archive", Severity.MEDIUM),
        ("html", Severity.MEDIUM),
        ("document", Severity.LOW),
        ("other", Severity.LOW),
    ],
)
def test_download_signal_severity(kind, severity):
    nav = {"download": {"kind": kind, "filename": "f", "sha256": "ab", "size": 3}}
    assert browser.download_signal(nav).severity == severity


@pytest.mark.parametrize(
    ("raw", "safe"),
    [
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\x\\evil.exe", "evil.exe"),
        ("a\x00b\x1f.txt", "a_b_.txt"),
        ("x" * 300 + ".bin", "x" * 120),
        ("", ""),
        (None, ""),
    ],
)
def test_safe_filename(raw, safe):
    assert capture_recovery.safe_filename(raw) == safe


# --- 4. Deterministic page state ------------------------------------------------------------


@pytest.mark.parametrize(
    ("nav", "expected"),
    [
        (
            {"status": 403, "dom_html": fixture("s3_all_access_disabled.xml")},
            (PageState.TAKEN_DOWN, "s3_all_access_disabled"),
        ),
        (
            {"status": 403, "dom_html": fixture("s3_xml_viewer.html")},
            (PageState.TAKEN_DOWN, "s3_all_access_disabled"),
        ),
        (
            {"status": 403, "visible_text": fixture("s3_access_denied.xml")},
            (PageState.S3_ACCESS_DENIED, "s3_access_denied"),
        ),
        (
            {
                "status": 451,
                "title": "451: Deployment Unavailable",
                "dom_html": fixture("vercel_451.html"),
            },
            (PageState.TAKEN_DOWN, "vercel_451_deployment_unavailable"),
        ),
        (
            {"status": 403, "title": "Site suspended", "dom_html": fixture("vista_suspended.html")},
            (PageState.TAKEN_DOWN, "provider_suspended_page"),
        ),
        (
            {
                "status": 200,
                "title": "Link unavailable",
                "dom_html": fixture("shortio_suspended.html"),
            },
            (PageState.TAKEN_DOWN, "provider_suspended_page"),
        ),
        (
            {
                "status": 200,
                "final_url": "https://parked.example/lander",
                "title": "",
                "dom_html": "<p>parked.example</p>",
            },
            (PageState.PARKED, "godaddy_lander"),
        ),
        (
            {"status": 200, "dom_html": fixture("godaddy_lander_redirect.html")},
            (PageState.PARKED, "godaddy_lander"),
        ),
        (
            {
                "status": 403,
                "final_url": "https://forsale.godaddy.com/forsale/parked.example",
                "redirect_chain": [{"url": "https://parked.example/lander"}],
            },
            (PageState.PARKED, "for_sale_lander"),
        ),
        (
            {"status": 200, "final_url": "https://www.hugedomains.com/domain_profile.cfm?d=x"},
            (PageState.PARKED, "for_sale_lander"),
        ),
        (
            {
                "status": 200,
                "title": "example-brand.shop is for sale",
                "dom_html": fixture("for_sale.html"),
            },
            (PageState.PARKED, "for_sale_lander"),
        ),
    ],
)
def test_page_state_classifier(nav, expected):
    assert page_state.classify(nav) == expected


@pytest.mark.parametrize(
    "nav",
    [
        {
            "status": 200,
            "title": "Account suspended - verify now",
            "dom_html": fixture("account_suspended_lure.html"),
        },
        {"status": 200, "dom_html": fixture("s3_word_only.html")},
        {"status": 200, "dom_html": fixture("s3_all_access_disabled.xml")},
        {"status": 403, "dom_html": "<Error><Code>AllAccessDisabled</Code></Error>"},
        {"status": 200, "title": "451: Deployment Unavailable"},
        {"status": 200, "final_url": "https://shop.example/landers/a"},
        {"status": 200, "final_url": "https://notsedo.com.example/"},
        # Attacker-controlled text never earns a benign state on a page that asks for input.
        {
            "status": 403,
            "title": "Site suspended",
            "dom_html": '<form action="/s"><input type="password" name="p"></form>',
        },
        {
            "status": 200,
            "dom_html": "<p>This domain is for sale</p><form><input name=email></form>",
        },
        {
            "status": 200,
            "final_url": "https://lure.example/lander",
            "dom_html": "<form><input type=password></form>",
        },
        # Text-only rules need the DOM to rule out a form.
        {"status": 200, "visible_text": "This domain is for sale"},
        {"status": 200, "visible_text": "provider has suspended it for abuse"},
        {"status": 200, "final_url": "https://lure.example/lander"},
        # The suspended title alone needs an error status.
        {"status": 200, "title": "Site suspended", "dom_html": "<p>gone</p>"},
        {},
    ],
)
def test_page_state_needs_the_exact_pattern(nav):
    assert page_state.classify(nav) is None


def test_a_marketplace_host_is_parked_even_with_its_own_offer_form():
    nav = {
        "status": 200,
        "final_url": "https://www.hugedomains.com/domain_profile.cfm?d=x",
        "dom_html": "<form><input name=offer></form>",
    }
    assert page_state.classify(nav) == (PageState.PARKED, "for_sale_lander")


def test_only_the_final_url_counts_for_a_marketplace_host():
    nav = {
        "status": 200,
        "final_url": "https://lure.example/login",
        "redirect_chain": [{"url": "https://www.sedo.com/search"}],
        "dom_html": "<p>welcome</p>",
    }
    assert page_state.classify(nav) is None


def test_page_state_is_code_only_and_never_a_model_visible_signal():
    nav = {"status": 451, "title": "451: Deployment Unavailable", "final_url": "https://x.example/"}
    assert browser.recognised_page_state(None, nav) == PageStateObservation(
        page_state=PageState.TAKEN_DOWN, reason="vercel_451_deployment_unavailable"
    )
    names = {s.name for s in browser.capture_signals(nav)}
    assert not any(n.startswith(("taken_down", "parked")) or n == "s3_access_denied" for n in names)
    assert browser.recognised_page_state(None, {"status": 200}) is None
    failure = CaptureFailure(browser.TLS_ERROR, "net::ERR_CERT_AUTHORITY_INVALID", "x")
    assert browser.recognised_page_state(failure, nav) is None
    assert browser.recognised_page_state(None, {**nav, "download": {"kind": "other"}}) is None


def test_the_captures_record_page_state_for_the_finding():
    from phish_agents.brand_visual.capture import BrandCapture
    from phish_agents.code_analyst.capture import CodeCapture

    data = {"status": 403, "dom_html": fixture("s3_all_access_disabled.xml"), "final_url": "u"}
    for cls in (BrandCapture, CodeCapture):
        cap = cls("https://x.example/", "scan-00000001", None, None, "bucket")
        cap.data = data
        assert cap.page_state() == PageStateObservation(
            page_state=PageState.TAKEN_DOWN, reason="s3_all_access_disabled"
        )


def test_every_new_signal_is_in_the_catalog():
    from importlib import resources

    catalog = json.loads(
        resources.files("phish_contracts").joinpath("signal_catalog.json").read_text()
    )
    new = {browser.TLS_CERTIFICATE_ERROR, browser.DOWNLOAD_RESPONSE, browser.DNS_TRANSIENT_ERROR}
    assert new <= set(catalog)


# --- 5. DNS transient errors -----------------------------------------------------------------


def _resolver(failures: list[BaseException], calls: list):
    def getaddrinfo(host, *_a, **_k):
        calls.append(host)
        if failures:
            raise failures.pop(0)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    return getaddrinfo


@pytest.fixture
def fast_backoff(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(url_safety.time, "sleep", sleeps.append)
    return sleeps


@pytest.mark.parametrize(
    "first",
    [OSError(16, "Device or resource busy"), socket.gaierror(socket.EAI_AGAIN, "try again")],
)
def test_a_transient_dns_failure_is_retried_once(monkeypatch, fast_backoff, first):
    calls: list = []
    monkeypatch.setattr(url_safety.socket, "getaddrinfo", _resolver([first], calls))
    host = f"retry-ok-{type(first).__name__.lower()}.example"
    reason, kind = url_safety.host_check(f"https://{host}/")
    assert (reason, kind) == (None, url_safety.HOST_OK)
    assert calls == [host, host]
    assert fast_backoff == [url_safety.DNS_RETRY_BACKOFF_S]


def test_a_persistent_transient_failure_is_labelled_dns_transient_error(monkeypatch, fast_backoff):
    calls: list = []
    failures = [OSError(16, "busy"), OSError(16, "busy")]
    monkeypatch.setattr(url_safety.socket, "getaddrinfo", _resolver(failures, calls))
    reason, kind = url_safety.host_check("https://still-busy.example/")
    assert kind == url_safety.HOST_UNRESOLVED
    assert url_safety.DNS_TRANSIENT_ERROR in reason
    assert len(calls) == 2


def test_nxdomain_is_not_retried(monkeypatch, fast_backoff):
    calls: list = []
    failures = [socket.gaierror(socket.EAI_NONAME, "Name or service not known")]
    monkeypatch.setattr(url_safety.socket, "getaddrinfo", _resolver(failures, calls))
    _reason, kind = url_safety.host_check("https://gone-for-good.example/")
    assert kind == url_safety.HOST_NXDOMAIN
    assert calls == ["gone-for-good.example"]
    assert fast_backoff == []


def test_the_per_request_guard_does_not_retry(monkeypatch, fast_backoff):
    """Only the one-shot page lookups retry; every subresource request stays one lookup."""
    calls: list = []
    monkeypatch.setattr(url_safety.socket, "getaddrinfo", _resolver([OSError(16, "busy")], calls))
    url_safety.request_allowed.cache_clear()
    assert url_safety.request_allowed("https://cdn-busy.example/app.js") is not None
    assert calls == ["cdn-busy.example"]
    assert fast_backoff == []


def test_checked_addresses_retries_like_host_check(monkeypatch, fast_backoff):
    calls: list = []
    monkeypatch.setattr(url_safety.socket, "getaddrinfo", _resolver([OSError(16, "busy")], calls))
    reason, kind, addresses = url_safety.checked_addresses("https://probe-busy.example/")
    assert (reason, kind, addresses) == (None, url_safety.HOST_OK, ["93.184.216.34"])
    assert len(calls) == 2


async def test_preflight_reports_dns_transient_error_not_blocked_by_guard(
    monkeypatch, fast_backoff
):
    failures = [OSError(16, "busy"), OSError(16, "busy")]
    monkeypatch.setattr(url_safety.socket, "getaddrinfo", _resolver(failures, []))
    with pytest.raises(browser.DnsTransientError) as info:
        await browser.preflight("https://busy-resolver.example/")
    failure = browser.classify_failure(info.value)
    assert failure.category == browser.DNS_TRANSIENT_ERROR
    assert failure.category != browser.BLOCKED_BY_GUARD
    signal = failure.signal()
    assert signal.name == browser.DNS_TRANSIENT_ERROR
    assert signal.severity == Severity.LOW
    assert browser.DNS_TRANSIENT_ERROR in failure.tool_text()


async def test_precheck_treats_a_dns_transient_error_as_inconclusive_not_dead(
    monkeypatch, fast_backoff
):
    from phish_agents.tools_server import server

    failures = [OSError(16, "busy")] * 4
    monkeypatch.setattr(url_safety.socket, "getaddrinfo", _resolver(failures, []))
    out = json.loads(
        await server.run_precheck_url("https://busy-precheck.example/", "scan-00000002")
    )
    assert out["outcome"] == "unreachable"
    assert browser.DNS_TRANSIENT_ERROR in out["reason"]


def test_the_retry_runs_off_the_event_loop():
    """host_check is always awaited through asyncio.to_thread, so the backoff sleep never
    blocks the loop; this guards that preflight still does so."""
    import inspect

    assert "asyncio.to_thread" in inspect.getsource(browser.preflight)
    assert asyncio.iscoroutinefunction(browser.preflight)


class _NoNewContextBrowser:
    async def new_context(self, **_kw):
        raise PlaywrightError("Browser.newContext: not supported over this connection")


class _CertFailingPage:
    viewport_size = {"width": 1280, "height": 800}

    def __init__(self) -> None:
        self.context = type("Ctx", (), {"browser": _NoNewContextBrowser()})()


async def test_a_failed_tolerant_context_reports_the_original_certificate_error():
    """If the managed browser cannot open a second context, the capture fails as before."""
    from contextlib import AsyncExitStack

    async def open_url(_page, _url):
        raise PlaywrightError("page.goto: net::ERR_CERT_AUTHORITY_INVALID at https://x.example/")

    async with AsyncExitStack() as stack:
        with pytest.raises(PlaywrightError) as info:
            await capture_recovery.open_capture(
                stack, _CertFailingPage(), "https://x.example/", open_url, lambda: 10_000, 1_000
            )
    failure = browser.classify_failure(info.value)
    assert (failure.category, failure.code) == (
        browser.TLS_ERROR,
        "net::ERR_CERT_AUTHORITY_INVALID",
    )


async def test_page_state_never_reaches_the_orchestrator_over_mcp():
    """Finding.page_state is persisted for the worker but left out of the MCP reply."""
    import time

    from phish_agents.common import server
    from phish_agents.common.finding import error_finding
    from phish_contracts.models import Usage

    async def analyze(_url, _scan_id, **_kw):
        finding = error_finding(
            "code_analyst",
            "fixture",
            usage=Usage(model_id="m"),
            started=time.monotonic(),
            calls=[],
        )
        finding.page_state = PageStateObservation(
            page_state=PageState.PARKED, reason="godaddy_lander"
        )
        return finding

    out = json.loads(
        await server.safe_analyze("code_analyst", analyze, "https://a.example", "scan-12345678")
    )
    assert out["agent"] == "code_analyst"
    assert "page_state" not in out


def test_every_code_heuristic_signal_is_in_the_catalog():
    from importlib import resources

    from phish_agents.code_analyst import heuristics

    catalog = json.loads(
        resources.files("phish_contracts").joinpath("signal_catalog.json").read_text()
    )
    assert {name for name, _, _ in heuristics._PATTERNS} <= set(catalog)
