# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import asyncio
import time

import pytest
from agent_fakes import (
    FakeBrowserClient,
    FakeCDPSession,
    FakeContext,
    FakePage,
    FakePlaywright,
)

from phish_agents.common import browser
from phish_agents.common.timing import CallRecorder

pytestmark = pytest.mark.usefixtures("public_dns")


def factories(page):
    pw = FakePlaywright(page)
    return {"client_factory": FakeBrowserClient, "playwright_factory": lambda: pw}, pw


async def test_session_started_used_and_stopped():
    page = FakePage(final_url="https://example.com/landing", title="Landing")
    kw, pw = factories(page)
    rec = CallRecorder()
    async with browser.open_page(rec, "brand_visual", init_script="window.x=1", **kw) as p:
        nav = await browser.navigate(p, "https://example.com")
    client = FakeBrowserClient.instances[-1]
    assert client.started and client.stopped and pw.browser.closed
    assert nav == {
        "final_url": "https://example.com/landing",
        "status": 200,
        "title": "Landing",
        "redirect_chain": [
            {"url": "https://example.com", "via": "start"},
            {"url": "https://example.com/landing", "via": "http"},
        ],
    }
    ctx = pw.browser.contexts[0]
    assert ctx.init_scripts == ["window.x=1"] and ctx.routes[0][0] == "**/*"
    assert rec.calls[0].kind == "browser" and rec.calls[0].status == "ok"


async def test_session_stopped_when_navigation_fails():
    page = FakePage(goto_error=TimeoutError("nav timeout"))
    kw, _ = factories(page)
    rec = CallRecorder()
    with pytest.raises(TimeoutError):
        async with browser.open_page(rec, "code_analyst", **kw) as p:
            await browser.navigate(p, "https://example.com")
    assert FakeBrowserClient.instances[-1].stopped
    assert rec.calls[0].status == "error"


class FakeRoute:
    def __init__(self, url):
        self.request = type("R", (), {"url": url})()
        self.outcome = None

    async def abort(self, reason):
        self.outcome = ("abort", reason)

    async def continue_(self):
        self.outcome = ("continue",)


async def test_guard_aborts_internal_address():
    # accessdenied (net::ERR_ACCESS_DENIED), not blockedbyclient: the managed browser
    # itself refuses some URLs with ERR_BLOCKED_BY_CLIENT, and the two must stay apart.
    route = FakeRoute("http://169.254.169.254/latest")
    await browser.guard_route(route)
    assert route.outcome == ("abort", "accessdenied")


async def test_guard_continues_data_url():
    route = FakeRoute("data:image/png;base64,AA")
    await browser.guard_route(route)
    assert route.outcome == ("continue",)


async def test_navigate_refuses_internal_redirect_hop():
    page = FakePage(
        final_url="https://example.com/done",
        redirect_chain=["https://example.com/start", "http://169.254.169.254/latest/meta-data"],
    )
    with pytest.raises(browser.BlockedNavigation):
        await browser.navigate(page, "https://example.com/start")


async def test_navigate_refuses_internal_final_url():
    page = FakePage(final_url="http://10.0.0.5/admin", redirect_chain=["https://example.com/"])
    with pytest.raises(browser.BlockedNavigation):
        await browser.navigate(page, "https://example.com/")


async def test_navigate_allows_public_redirect_chain():
    page = FakePage(final_url="https://www.example.com/", redirect_chain=["https://example.com/"])
    nav = await browser.navigate(page, "https://example.com/")
    assert nav["final_url"] == "https://www.example.com/"


async def test_blocked_redirect_discards_code_capture():
    from agent_fakes import FakeS3

    from phish_agents.code_analyst.capture import CodeCapture

    page = FakePage(final_url="http://169.254.169.254/", redirect_chain=["https://example.com/"])
    pw = FakePlaywright(page)
    s3 = FakeS3()

    def open_page_fn(recorder, name, **kwargs):
        return browser.open_page(
            recorder,
            name,
            client_factory=FakeBrowserClient,
            playwright_factory=lambda: pw,
            **kwargs,
        )

    cap = CodeCapture(
        "https://example.com/", "scan-12345678", CallRecorder(), s3, "b", open_page_fn
    )
    data = await cap.capture()
    assert data == {
        "error": "capture_failed",
        "category": "blocked_by_guard",
        "reason": "url_safety",
    }
    assert s3.objects == {}


# D8: every capture failure is classified, so logs and Findings say why a page is missing.
@pytest.mark.parametrize(
    ("message", "category", "code"),
    [
        (
            "Page.goto: net::ERR_NAME_NOT_RESOLVED at https://x.example/",
            "site_unreachable",
            "net::ERR_NAME_NOT_RESOLVED",
        ),
        (
            "Page.goto: net::ERR_CONNECTION_REFUSED at https://x/",
            "site_unreachable",
            "net::ERR_CONNECTION_REFUSED",
        ),
        # A certificate or TLS error means the host answered: tls_error, not site_unreachable.
        (
            "Page.goto: net::ERR_CERT_COMMON_NAME_INVALID at https://www.a.vercel.app/",
            "tls_error",
            "net::ERR_CERT_COMMON_NAME_INVALID",
        ),
        (
            "Page.goto: net::ERR_CERT_AUTHORITY_INVALID at https://x.example/",
            "tls_error",
            "net::ERR_CERT_AUTHORITY_INVALID",
        ),
        (
            "Page.goto: net::ERR_CERT_DATE_INVALID at https://x.example/",
            "tls_error",
            "net::ERR_CERT_DATE_INVALID",
        ),
        (
            "Page.goto: net::ERR_SSL_PROTOCOL_ERROR at https://x.example/",
            "tls_error",
            "net::ERR_SSL_PROTOCOL_ERROR",
        ),
        (
            "Page.goto: net::ERR_ACCESS_DENIED at http://10.0.0.1/",
            "blocked_by_guard",
            "net::ERR_ACCESS_DENIED",
        ),
        # Release run 2026-09-30: 11 phishing hosts refused this way with no guard refusal.
        (
            "Page.goto: net::ERR_BLOCKED_BY_CLIENT at http://www.goo.su/hbXzr/",
            "blocked_by_browser",
            "net::ERR_BLOCKED_BY_CLIENT",
        ),
        (
            "Page.goto: net::ERR_BLOCKED_BY_ADMINISTRATOR at http://x.example/",
            "blocked_by_browser",
            "net::ERR_BLOCKED_BY_ADMINISTRATOR",
        ),
        (
            "Page.goto: net::ERR_BLOCKED_BY_RESPONSE at https://x.example/",
            "blocked_by_site",
            "net::ERR_BLOCKED_BY_RESPONSE",
        ),
        ("Page.goto: net::ERR_ABORTED at https://x/file.zip", "browser_error", "net::ERR_ABORTED"),
        ("Target page, context or browser has been closed", "browser_error", "Error"),
    ],
)
def test_playwright_errors_are_classified(message, category, code):
    from playwright.async_api import Error

    failure = browser.classify_failure(Error(message))
    assert (failure.category, failure.code) == (category, code)


def test_other_failures_are_classified():
    from botocore.exceptions import ClientError
    from playwright.async_api import TimeoutError as PwTimeout

    throttled = ClientError({"Error": {"Code": "ThrottlingException"}}, "StartBrowserSession")
    assert browser.classify_failure(throttled).code == "session_throttled"
    assert browser.classify_failure(PwTimeout("t")).category == "navigation_timeout"
    guard = browser.classify_failure(browser.BlockedNavigation("port 8082 is not allowed"))
    assert (guard.category, guard.code, guard.detail) == (
        "blocked_by_guard",
        "url_safety",
        "port 8082 is not allowed",
    )
    refused = browser.classify_failure(browser.BrowserRefused("chrome-error://chromewebdata/"))
    assert (refused.category, refused.code) == ("blocked_by_browser", "chrome_error_page")
    assert browser.classify_failure(browser.SiteUnreachable("dns_nxdomain")).code == "dns_nxdomain"
    assert browser.classify_failure(KeyError("k")).category == "internal_error"


def test_evidence_failures_become_signals_and_gaps_do_not():
    signal = browser.CaptureFailure("site_unreachable", "dns_nxdomain").signal()
    assert signal.name == "site_unreachable" and signal.severity == "medium"
    assert browser.CaptureFailure("internal_error", "KeyError").signal() is None
    assert browser.CaptureFailure("navigation_timeout", "timeout").signal() is None


def test_browser_block_is_a_low_capture_gap_not_evidence():
    # Managed-browser blocklists include ad and extension lists: 188 of 188 such scans were
    # judged phishing when this was high evidence, including a dead S3 site (v3 round).
    failure = browser.CaptureFailure("blocked_by_browser", "net::ERR_BLOCKED_BY_CLIENT")
    signal = failure.signal()
    assert signal.name == "blocked_by_browser" and signal.severity == "low"
    assert "ERR_BLOCKED_BY_CLIENT" in signal.evidence
    assert "not evidence" in signal.evidence
    text = failure.tool_text()
    assert text.startswith("blocked_by_browser")
    assert "not evidence" in text and "phishing evidence" not in text


def test_guard_refusal_is_a_low_signal_with_the_reason():
    failure = browser.CaptureFailure("blocked_by_guard", "url_safety", "resolves to 10.0.0.5")
    signal = failure.signal()
    assert signal.name == "blocked_by_guard" and signal.severity == "low"
    assert "resolves to 10.0.0.5" in signal.evidence
    assert failure.tool_text().startswith("blocked_by_guard")


def test_site_refusal_during_navigation_is_a_low_signal():
    signal = browser.CaptureFailure("blocked_by_site", "net::ERR_BLOCKED_BY_RESPONSE").signal()
    assert signal.name == "blocked_by_site" and signal.severity == "low"


@pytest.mark.parametrize(
    ("status", "title", "expected"),
    [
        (403, "Forbidden", "HTTP 403"),
        (429, "", "HTTP 429"),
        (200, "Just a moment...", "Just a moment"),
        (200, "Attention Required! | Cloudflare", "Attention Required"),
        (503, "DDoS-Guard", "DDoS-Guard"),
        (200, "PayPal: Log in", None),
        (404, "Not Found", None),
        (None, "", None),
    ],
)
def test_site_block_detects_block_pages_and_bot_walls(status, title, expected):
    signal = browser.site_block_signal({"status": status, "title": title, "final_url": "x"})
    if expected is None:
        assert signal is None
    else:
        assert signal.name in {"blocked_by_site", "bot_challenge"} and signal.severity == "low"
        assert expected in signal.evidence


async def test_navigate_reports_chrome_error_page_as_browser_refusal():
    page = FakePage(final_url="chrome-error://chromewebdata/")
    with pytest.raises(browser.BrowserRefused):
        await browser.navigate(page, "https://blocked.example/")
    assert (
        browser.CaptureFailure("site_unreachable", "x").tool_text().startswith("site_unreachable")
    )


def test_failure_log_has_class_and_first_line_only(caplog):
    from playwright.async_api import Error

    exc = Error("Page.goto: net::ERR_NAME_NOT_RESOLVED at https://x/\nCall log:\n  - page text")
    with caplog.at_level("INFO", logger="phish_agents.common.browser"):
        browser.log_capture_failure("brand_visual", exc)
    line = caplog.records[-1].getMessage()
    assert "category=site_unreachable" in line and "error=Error" in line
    assert "ERR_NAME_NOT_RESOLVED" in line and "Call log" not in line and "page text" not in line


async def test_preflight_reports_nxdomain_without_a_session(monkeypatch):
    import socket

    from phish_agents.common import url_safety

    def nxdomain(*_a, **_k):
        raise socket.gaierror(socket.EAI_NONAME, "not known")

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", nxdomain)
    url_safety.request_allowed.cache_clear()
    with pytest.raises(browser.SiteUnreachable) as err:
        await browser.preflight("https://gone.example/")
    assert err.value.code == "dns_nxdomain"


async def test_preflight_passes_a_resolving_host():
    await browser.preflight("https://example.com/")


async def test_guard_tolerates_a_closed_page():
    from playwright.async_api import Error

    class ClosedRoute(FakeRoute):
        async def continue_(self):
            raise Error("Route.continue_: Target page, context or browser has been closed")

    await browser.guard_route(ClosedRoute("https://example.com/a.js"))


async def test_navigate_bounded_settle_never_waits_for_networkidle():
    page = FakePage()
    await browser.navigate(
        page, "https://example.com", nav_timeout_ms=8_000, settle_state="load", settle_ms=2_000
    )
    assert page.goto_kwargs == [{"wait_until": "domcontentloaded", "timeout": 8_000}]
    assert page.load_states == [("load", 2_000)]


async def test_navigate_default_settle_is_unchanged_for_code_analyst():
    page = FakePage()
    await browser.navigate(page, "https://example.com")
    assert page.goto_kwargs[0]["timeout"] == browser.NAV_TIMEOUT_MS
    assert page.load_states == [("networkidle", browser.SETTLE_TIMEOUT_MS)]


async def test_navigate_settles_only_until_the_settle_deadline():
    page = FakePage()
    await browser.navigate(
        page,
        "https://example.com",
        settle_state="load",
        settle_ms=2_000,
        settle_deadline=time.monotonic() + 0.5,
    )
    [(state, timeout)] = page.load_states
    assert state == "load" and 0 < timeout <= 500


async def test_navigate_skips_the_settle_when_no_time_is_left():
    page = FakePage()
    nav = await browser.navigate(
        page,
        "https://example.com",
        settle_state="load",
        settle_ms=2_000,
        settle_deadline=time.monotonic() - 1,
    )
    # Playwright reads timeout=0 as "wait forever", so no time left means no wait at all.
    assert page.load_states == [] and nav["status"] == 200


def cdp_page(**kwargs):
    page = FakePage(**kwargs)
    FakeContext(page)
    return page


async def test_viewport_png_stops_loading_and_captures_over_cdp():
    page = cdp_page()
    png = await browser.viewport_png(page, 2_000)
    assert png == b"\x89PNG fake"
    # Stop first: a page still loading is what made page.screenshot time out.
    assert page.cdp_calls == ["Page.stopLoading", "Page.captureScreenshot"]
    assert page.screenshot_kwargs == [
        {"cdp": True, "format": "png", "captureBeyondViewport": False, "fromSurface": True}
    ]
    assert page.cdp_detached


def fallback_kwargs(page) -> dict:
    [kwargs] = [k for k in page.screenshot_kwargs if not k.get("cdp")]
    return kwargs


async def test_viewport_png_falls_back_when_cdp_times_out():
    page = cdp_page(cdp_hang=True)
    started = time.monotonic()
    png = await browser.viewport_png(page, 1_000)
    took = time.monotonic() - started
    assert png == b"\x89PNG fake" and page.cdp_detached
    # CDP had its share of the budget, the fallback the rest: the whole call stays bounded.
    assert took < 1.0 + 0.2
    kwargs = fallback_kwargs(page)
    assert kwargs["animations"] == "disabled" and kwargs["caret"] == "hide"
    assert kwargs["type"] == "png" and kwargs["full_page"] is False
    assert 0 < kwargs["timeout"] <= 1_000 * (1 - browser.CDP_SHARE) + 20


async def test_viewport_png_falls_back_when_cdp_errors():
    from playwright.async_api import Error

    page = cdp_page()
    session_send = FakeCDPSession.send

    async def failing_send(self, method, params=None):
        if method == "Page.captureScreenshot":
            raise Error("Protocol error (Page.captureScreenshot): Target closed")
        return await session_send(self, method, params)

    FakeCDPSession.send = failing_send
    try:
        png = await browser.viewport_png(page, 2_000)
    finally:
        FakeCDPSession.send = session_send
    assert png == b"\x89PNG fake" and fallback_kwargs(page)["animations"] == "disabled"


async def test_viewport_png_is_bounded_when_both_paths_hang():
    page = cdp_page(hang=frozenset({"screenshot"}))
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(browser.viewport_png(page, 50), 0.5)
    assert page.cdp_detached


async def test_viewport_png_falls_back_to_playwright_without_cdp():
    page = cdp_page(cdp_unavailable=True)
    png = await browser.viewport_png(page, 2_000)
    assert png == b"\x89PNG fake" and page.cdp_calls == []
    kwargs = fallback_kwargs(page)
    assert kwargs["animations"] == "disabled" and 0 < kwargs["timeout"] <= 2_000


@pytest.mark.parametrize("url", ["chrome://new-tab-page/", "about:blank", "", "data:text/html,x"])
async def test_nothing_rendered_when_the_tab_never_left_a_browser_page(url):
    # A navigation that never committed leaves Chromium's own new-tab page on screen.
    assert await browser.rendered_after_timeout(FakePage(final_url=url)) is None


async def test_navigate_does_not_wait_on_a_stuck_title():
    # A busy page main thread never answers page.title(); navigate must still return.
    page = FakePage(hang=frozenset({"title"}))
    nav = await asyncio.wait_for(browser.navigate(page, "https://example.com"), 3)
    assert nav["title"] == "" and nav["status"] == 200


def test_page_not_found_signal_only_for_a_404_final_status():
    signal = browser.page_not_found_signal({"status": 404, "title": "Not Found", "final_url": "x"})
    assert signal.name == "page_not_found" and signal.severity == "low"
    assert "404" in signal.evidence
    for status in (200, 403, 410, 500, None):
        assert browser.page_not_found_signal({"status": status, "final_url": "x"}) is None


# One rule for certificate and TLS errors: a low capture gap that says the site is up.
def test_tls_error_is_a_low_capture_gap_that_is_not_site_down():
    failure = browser.CaptureFailure("tls_error", "net::ERR_CERT_COMMON_NAME_INVALID")
    signal = failure.signal()
    assert signal.name == "tls_error" and signal.severity == "low"
    assert "not down" in signal.evidence
    text = failure.tool_text()
    assert text.startswith("tls_error (net::ERR_CERT_COMMON_NAME_INVALID)")
    assert "not site_down" in text and "not evidence of phishing" in text
    assert "evidence in itself" not in text
    assert "not evidence of phishing" in browser.capture_note(failure, None)


async def _until(check, timeout_s: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while not check() and time.monotonic() < deadline:
        await asyncio.sleep(0.01)
    return check()


async def test_a_session_that_starts_after_its_caller_was_cancelled_is_stopped():
    import threading

    release = threading.Event()

    class LateStart(FakeBrowserClient):
        def start(self, **kwargs):
            release.wait(5)
            return super().start(**kwargs)

    pw = FakePlaywright(FakePage())

    async def capture():
        async with browser.open_page(
            CallRecorder(), "code_analyst", client_factory=LateStart, playwright_factory=lambda: pw
        ):
            pass

    task = asyncio.create_task(capture())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    client = FakeBrowserClient.instances[-1]
    assert not client.started and not client.stopped
    # The start thread finishes after nobody waits for it: the session it opened is stopped.
    release.set()
    assert await _until(lambda: client.stopped) and client.started


async def test_a_stop_that_fails_after_the_bound_is_still_logged(monkeypatch, caplog):
    import logging

    monkeypatch.setattr(browser, "CLOSE_TIMEOUT_S", 0.05)

    class SlowFailingStop(FakeBrowserClient):
        def stop(self):
            time.sleep(0.3)
            raise RuntimeError("stop refused")

    pw = FakePlaywright(FakePage())
    with caplog.at_level(logging.WARNING, logger=browser.logger.name):
        started = time.monotonic()
        async with browser.open_page(
            CallRecorder(),
            "code_analyst",
            client_factory=SlowFailingStop,
            playwright_factory=lambda: pw,
        ):
            pass
        assert time.monotonic() - started < 0.25
        assert await _until(
            lambda: any("session stop failed" in r.getMessage() for r in caplog.records)
        )
    assert any("stop refused" in r.getMessage() for r in caplog.records)
