# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""CAPTURE_BLOCK_RETRY against a real local Chromium and a local server only.

- /shop answers headless Chromium with the 214-byte "Access denied" 403 the 2026-11-01 fake
  shops served, and a desktop Chrome user agent with en-US Accept-Language with the page: the
  desktop-profile retry recovers it;
- /wall answers every client with that 403: the retry records still_blocked;
- a navigation the browser refuses with net::ERR_BLOCKED_BY_CLIENT (as the managed browser did
  for http:// URLs whose certificate does not match the host) gets the certificate-tolerant
  retry, and its tls_certificate says the certificate error was not confirmed.

Skipped when no local Chromium can be launched (see test_capture_fixes_browser).
"""

import threading
import time
from contextlib import AsyncExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from agent_fakes import local_playwright
from playwright.async_api import Error as PlaywrightError

from phish_agents.common import browser, capture_recovery, url_safety
from phish_contracts.models import PageState

BLOCKED = (
    b"<html><head><title>Access denied</title></head>"
    b"<body><h1>403</h1><p>Access denied</p></body></html>"
)
SHOP = b"<!DOCTYPE html><html><head><title>Real shop</title></head><body>Add to cart</body></html>"


class _Handler(BaseHTTPRequestHandler):
    seen_user_agents: list[str] = []

    def do_GET(self):  # noqa: N802 - http.server API
        ua = self.headers.get("User-Agent", "")
        self.seen_user_agents.append(ua)
        desktop = "HeadlessChrome" not in ua and "en-US" in self.headers.get("Accept-Language", "")
        if self.path.startswith("/slow") and desktop:
            time.sleep(3)
            status, body = 200, SHOP
        elif self.path.startswith("/shop") and desktop:
            status, body = 200, SHOP
        elif self.path.startswith(("/shop", "/wall", "/slow")):
            status, body = 403, BLOCKED
        else:
            status, body = 200, SHOP
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@pytest.fixture
def server():
    _Handler.seen_user_agents = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture
def allow_loopback(monkeypatch):
    monkeypatch.setattr(browser, "request_allowed", lambda _url: None)
    monkeypatch.setattr(
        url_safety, "checked_addresses", lambda _url: (None, url_safety.HOST_OK, ["127.0.0.1"])
    )


@pytest.fixture
def retry_on(monkeypatch):
    monkeypatch.setenv(browser.BLOCK_RETRY_ENV, "1")


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


async def test_a_bot_wall_is_recovered_with_the_desktop_profile(
    allow_loopback, retry_on, server, local_page
):
    prepared = []
    async with AsyncExitStack() as stack:
        nav, page = await capture_recovery.open_capture(
            stack, local_page, f"{server}/shop", _open, lambda: 8000, 500, prepare=prepared.append
        )
        assert page is not local_page and prepared == [page]
        assert (nav["status"], nav["title"]) == (200, "Real shop")
        assert nav["block_retry"] == {
            "reason": "block_page",
            "first_status": 403,
            "profile": capture_recovery.BLOCK_RETRY_PROFILE,
            "outcome": "recovered",
        }
        assert "Add to cart" in await page.content()
        assert await page.evaluate("navigator.language") == "en-US"
        assert page.viewport_size == {"width": 1366, "height": 768}
    assert browser.page_observed(None, nav) is True
    assert browser.recognised_page_state(None, nav) is None
    assert "HeadlessChrome" in _Handler.seen_user_agents[0]
    assert "HeadlessChrome" not in _Handler.seen_user_agents[-1]


async def test_a_wall_for_every_client_is_still_blocked(
    allow_loopback, retry_on, server, local_page
):
    async with AsyncExitStack() as stack:
        nav, _page = await capture_recovery.open_capture(
            stack, local_page, f"{server}/wall", _open, lambda: 8000, 500
        )
    assert nav["status"] == 403
    assert nav["block_retry"]["outcome"] == "still_blocked"
    assert browser.page_observed(None, nav) is False
    state = browser.recognised_page_state(None, nav)
    assert (state.page_state, state.reason) == (PageState.BOT_BLOCKED, "block_page")
    assert len(_Handler.seen_user_agents) == 2


async def test_a_retry_that_runs_out_of_its_budget_keeps_the_first_capture(
    monkeypatch, allow_loopback, retry_on, server, local_page
):
    # 2 s, still under the 3 s the slow wall takes: at 1 s a loaded machine (load average
    # 30 to 90) had not opened the retry context yet, so prepare never ran.
    monkeypatch.setattr(capture_recovery, "BLOCK_RETRY_MS", 2_000)
    restored = []

    def prepare(_target):
        return lambda: restored.append(True)

    started = time.monotonic()
    async with AsyncExitStack() as stack:
        nav, page = await capture_recovery.open_capture(
            stack, local_page, f"{server}/slow", _open, lambda: 8000, 500, prepare=prepare
        )
        assert page is local_page
        assert "Access denied" in await page.content()
    assert time.monotonic() - started < 3.5
    assert (nav["status"], nav["block_retry"]["outcome"]) == (403, "retry_timed_out")
    assert restored == [True]
    state = browser.recognised_page_state(None, nav)
    assert (state.page_state, state.reason) == (PageState.BOT_BLOCKED, "block_page")


async def test_a_half_rendered_retry_is_not_a_recovery(
    allow_loopback, retry_on, server, local_page
):
    calls = []

    async def open_marking_the_retry_timed_out(page, url):
        nav = await _open(page, url)
        calls.append(url)
        return {**nav, "navigation_timed_out": True} if len(calls) == 2 else nav

    async with AsyncExitStack() as stack:
        nav, page = await capture_recovery.open_capture(
            stack, local_page, f"{server}/shop", open_marking_the_retry_timed_out, lambda: 8000, 500
        )
    assert page is local_page and len(calls) == 2
    assert (nav["status"], nav["block_retry"]["outcome"]) == (403, "retry_timed_out")
    assert "navigation_timed_out" not in nav


async def test_the_retry_is_skipped_without_time_left(allow_loopback, retry_on, server, local_page):
    async with AsyncExitStack() as stack:
        nav, page = await capture_recovery.open_capture(
            stack, local_page, f"{server}/shop", _open, lambda: 100, 500
        )
    assert page is local_page
    assert nav["status"] == 403
    assert nav["block_retry"]["outcome"] == "skipped_no_time"
    assert len(_Handler.seen_user_agents) == 1


async def test_without_the_flag_nothing_is_retried(monkeypatch, allow_loopback, server, local_page):
    monkeypatch.delenv(browser.BLOCK_RETRY_ENV, raising=False)
    async with AsyncExitStack() as stack:
        nav, page = await capture_recovery.open_capture(
            stack, local_page, f"{server}/shop", _open, lambda: 8000, 500
        )
    assert page is local_page
    assert nav["status"] == 403 and "block_retry" not in nav
    assert browser.recognised_page_state(None, nav) is None
    assert len(_Handler.seen_user_agents) == 1


async def _refuse(route):
    await route.abort("blockedbyclient")


async def test_a_browser_refusal_gets_the_certificate_tolerant_retry(
    allow_loopback, retry_on, server, local_page
):
    await local_page.route("**/*", _refuse)
    async with AsyncExitStack() as stack:
        nav, page = await capture_recovery.open_capture(
            stack, local_page, f"{server}/", _open, lambda: 8000, 500
        )
        assert page is not local_page
        assert (nav["status"], nav["title"]) == (200, "Real shop")
        assert nav["tls_certificate"] == {
            "type": browser.TLS_UNCONFIRMED,
            "code": "net::ERR_BLOCKED_BY_CLIENT",
            "certificate_checks": capture_recovery.TLS_CHECKS_IGNORED,
        }
        assert "block_retry" not in nav
    assert browser.tls_certificate_signal(nav) is not None


async def test_a_browser_refusal_is_final_without_the_flag(
    monkeypatch, allow_loopback, server, local_page
):
    monkeypatch.delenv(browser.BLOCK_RETRY_ENV, raising=False)
    await local_page.route("**/*", _refuse)
    async with AsyncExitStack() as stack:
        with pytest.raises(PlaywrightError, match="ERR_BLOCKED_BY_CLIENT"):
            await capture_recovery.open_capture(
                stack, local_page, f"{server}/", _open, lambda: 8000, 500
            )


async def test_a_refusal_the_tolerant_context_shares_is_reported_as_the_original(
    monkeypatch, allow_loopback, retry_on, server, local_page
):
    await local_page.route("**/*", _refuse)
    # The tolerant context installs browser.guard_route; here it refuses too.
    monkeypatch.setattr(browser, "guard_route", _refuse)
    async with AsyncExitStack() as stack:
        with pytest.raises(PlaywrightError, match="ERR_BLOCKED_BY_CLIENT"):
            await capture_recovery.open_capture(
                stack, local_page, f"{server}/", _open, lambda: 8000, 500
            )


async def test_a_failed_retry_keeps_the_first_capture_and_its_evidence(
    monkeypatch, allow_loopback, retry_on, server, local_page
):
    evidence = ["first page request"]
    restored = []

    def prepare(target):
        kept = list(evidence)
        evidence.clear()

        def restore():
            evidence[:] = kept
            restored.append(target)

        return restore

    # The retry context installs browser.guard_route; here it refuses, so the retry fails.
    monkeypatch.setattr(browser, "guard_route", _refuse)
    async with AsyncExitStack() as stack:
        nav, page = await capture_recovery.open_capture(
            stack, local_page, f"{server}/wall", _open, lambda: 8000, 500, prepare=prepare
        )
    assert page is local_page
    assert nav["status"] == 403
    assert nav["block_retry"]["outcome"] == "retry_failed"
    assert evidence == ["first page request"] and len(restored) == 1
    assert len(_Handler.seen_user_agents) == 1


async def test_a_tolerant_capture_keeps_its_certificate_record_through_the_retry(
    allow_loopback, retry_on, server, local_page
):
    await local_page.route("**/*", _refuse)
    async with AsyncExitStack() as stack:
        nav, page = await capture_recovery.open_capture(
            stack, local_page, f"{server}/wall", _open, lambda: 8000, 500
        )
    assert nav["status"] == 403
    assert nav["block_retry"]["outcome"] == "still_blocked"
    assert nav["tls_certificate"]["type"] == browser.TLS_UNCONFIRMED
    assert browser.tls_certificate_signal(nav) is not None
    assert len(_Handler.seen_user_agents) == 2


async def test_the_desktop_retry_context_is_guarded(
    monkeypatch, allow_loopback, retry_on, server, local_page
):
    real_guard = browser.guard_route
    guarded = []

    async def recording_guard(route):
        guarded.append(route.request.url)
        await real_guard(route)

    monkeypatch.setattr(browser, "guard_route", recording_guard)
    async with AsyncExitStack() as stack:
        nav, _page = await capture_recovery.open_capture(
            stack, local_page, f"{server}/shop", _open, lambda: 8000, 500
        )
    assert nav["block_retry"]["outcome"] == "recovered"
    assert guarded == [f"{server}/shop"]
