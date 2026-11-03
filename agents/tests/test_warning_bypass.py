# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The one click past a Cloudflare warning, in a local headless Chromium.

Every request is answered by a route from saved interstitial markup (tests/fixtures), so no
network is used. Fulfilled 3xx responses are avoided on purpose: Chromium does not route the
hop a fulfilled redirect points to, so it would reach the real network. Server hops are
covered with test doubles in test_browser.py. Skipped when Chromium is not installed.
"""

from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from agent_fakes import FakeS3
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from phish_agents.brand_visual.capture import BrandCapture
from phish_agents.common import browser, redirects
from phish_agents.common.timing import CallRecorder
from phish_agents.common.url_safety import request_allowed
from phish_contracts.models import Finding, Usage, Verdict
from phish_contracts.observation import cap_unobserved_warning

pytestmark = pytest.mark.usefixtures("public_dns")

FIXTURES = Path(__file__).parent / "fixtures"
TURNSTILE = (FIXTURES / "cloudflare_malware_turnstile.html").read_text(encoding="utf-8")
MISLEADING = (FIXTURES / "cloudflare_misleading_turnstile.html").read_text(encoding="utf-8")
NO_BYPASS = (FIXTURES / "cloudflare_phishing_no_bypass.html").read_text(encoding="utf-8")
# The same warning, but Turnstile clears by itself 200 ms after load (no interaction).
SELF_CLEARING = TURNSTILE.replace(
    '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async="" defer="">'
    "</script>",
    "<script>setTimeout(() => onTurnstileSuccess('t'), 200)</script>",
)
assert SELF_CLEARING != TURNSTILE
START = "https://kit-a1b2c3.pages.dev/"
REAL_PAGE = (
    "<html><head><title>Sign in to your account</title></head><body>"
    "<form action='/collect' method='post'><input name='u'><input type='password' name='p'>"
    "<button>Sign in</button></form></body></html>"
)


def bypass_to(target: str) -> str:
    # Cloudflare answers the bypass GET with a 302 back to original_path; a script stands in.
    return f"<html><body><script>location.replace({target!r})</script></body></html>"


class Site:
    """Routes for one scan: the warning until the bypass is used, then the real page."""

    def __init__(self, warning: str, *, after_bypass: str = "/", real: str = REAL_PAGE):
        self.warning, self.after_bypass, self.real = warning, after_bypass, real
        self.bypassed = False
        self.seen: list[str] = []

    async def handle(self, route) -> None:
        url = route.request.url
        self.seen.append(url)
        # The same refusal the production route guard gives an internal address.
        if request_allowed(url):
            await route.abort(browser.GUARD_ABORT)
        elif url.startswith(START + "cdn-cgi/phish-bypass?"):
            self.bypassed = True
            await route.fulfill(
                status=200, content_type="text/html", body=bypass_to(self.after_bypass)
            )
        elif url == START:
            body, status = (self.real, 200) if self.bypassed else (self.warning, 403)
            await route.fulfill(status=status, content_type="text/html", body=body)
        elif url.startswith("https://dead-host.example/"):
            await route.abort("namenotresolved")
        else:
            await route.abort("failed")


@pytest.fixture
async def chromium():
    async with async_playwright() as pw:
        try:
            instance = await pw.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"local Chromium unavailable: {exc.message.splitlines()[0]}")
        try:
            yield instance
        finally:
            await instance.close()


@pytest.fixture(autouse=True)
def short_turnstile_wait(monkeypatch):
    monkeypatch.setattr(browser, "BYPASS_ENABLE_WAIT_MS", 600)


async def open_site(chromium, site: Site):
    context = await chromium.new_context()
    await context.route("**/*", site.handle)
    return await context.new_page()


async def visit(chromium, site: Site) -> dict:
    page = await open_site(chromium, site)
    return await browser.navigate(page, START, settle_state="load", settle_ms=500)


async def test_turnstile_gated_warning_is_not_clicked_and_is_a_capture_gap(chromium):
    site = Site(TURNSTILE)
    nav = await visit(chromium, site)
    assert nav["title"] == "Suspected Malware | Cloudflare" and nav["status"] == 403
    assert nav["provider_warning"] == {
        "signal": "cloudflare_malware_warning",
        "kind": "Suspected Malware",
        "url": START,
        "status": 403,
        "outcome": "blocked",
        "reason": "turnstile",
    }
    assert not site.bypassed
    assert not any("phish-bypass" in u for u in site.seen)
    names = {s.name: s for s in browser.capture_signals(nav)}
    assert names["cloudflare_malware_warning"].severity == "high"
    assert "not observed" in names["cloudflare_malware_warning"].evidence
    assert names["warning_bypass_blocked"].severity == "low"
    assert "Turnstile" in names["warning_bypass_blocked"].evidence
    assert browser.page_observed(None, nav) is False
    assert nav["redirect_chain"] == [{"url": START, "via": "start", "status": 403}]


async def test_misleading_website_warning_is_recognized_and_capped(chromium):
    # Repro 52536b85: read as a plain 403 block, it got no click-through attempt and no
    # deterministic warning signal, so the page-not-observed cap rested on model wording.
    site = Site(MISLEADING)
    nav = await visit(chromium, site)
    assert nav["provider_warning"] == {
        "signal": "cloudflare_phishing_warning",
        "kind": "Suspected Misleading Website",
        "url": START,
        "status": 403,
        "outcome": "blocked",
        "reason": "turnstile",
    }
    assert not site.bypassed
    signals = {s.name: s for s in browser.capture_signals(nav)}
    assert set(signals) == {"cloudflare_phishing_warning", "warning_bypass_blocked"}
    assert "'Suspected Misleading Website'" in signals["cloudflare_phishing_warning"].evidence
    assert browser.page_observed(None, nav) is False
    note = browser.capture_note(None, browser.site_block_signal(nav), nav["provider_warning"])
    assert note.startswith("Cloudflare showed its own misleading website warning")
    finding = Finding(
        agent="brand_visual",
        status="ok",
        verdict="phishing",
        confidence=80,
        signals=list(signals.values()),
        usage=Usage(model_id="m"),
        latency_ms=1,
        page_observed=False,
    )
    capped = cap_unobserved_warning(
        Verdict(verdict="phishing", risk_score=85, confidence="high", action="block", summary="x"),
        [finding],
    )
    assert (capped.verdict, capped.risk_score, capped.action) == ("suspicious", 69, "warn")


async def test_warning_without_a_proceed_button_is_blocked(chromium):
    nav = await visit(chromium, Site(NO_BYPASS))
    assert nav["provider_warning"]["outcome"] == "blocked"
    assert nav["provider_warning"]["reason"] == "no_proceed_control"
    assert nav["provider_warning"]["signal"] == "cloudflare_phishing_warning"
    note = browser.capture_note(None, browser.site_block_signal(nav), nav["provider_warning"])
    assert "could not get past it" in note and "not observed" in note


async def test_self_clearing_check_is_clicked_once_and_the_real_page_is_captured(chromium):
    site = Site(SELF_CLEARING)
    nav = await visit(chromium, site)
    assert nav["provider_warning"]["outcome"] == "proceeded"
    assert nav["title"] == "Sign in to your account" and nav["status"] == 200
    assert browser.page_observed(None, nav) is True
    assert [h["via"] for h in nav["redirect_chain"]] == ["start", "warning_bypass", "client"]
    assert nav["redirect_chain"][1]["url"].startswith(START + "cdn-cgi/phish-bypass?atok=TEST")
    # One click, and nothing on the real page was submitted.
    assert sum("phish-bypass" in u for u in site.seen) == 1
    assert not any(u.endswith("/collect") for u in site.seen)
    signals = {s.name: s for s in browser.capture_signals(nav)}
    assert "captured the real page" in signals["cloudflare_malware_warning"].evidence
    assert "warning_bypass_blocked" not in signals


async def test_enabled_proceed_button_is_used_without_any_wait(chromium):
    enabled = NO_BYPASS.replace(
        '<a href="https://www.cloudflare.com/learning/access-management/phishing-attack/"',
        '<button type="submit" id="bypass-button">Ignore &amp; Proceed</button><a href="#"',
    )
    nav = await visit(chromium, Site(enabled))
    assert nav["provider_warning"]["outcome"] == "proceeded"
    assert nav["provider_warning"]["signal"] == "cloudflare_phishing_warning"


async def test_click_through_to_an_internal_address_is_refused(chromium):
    site = Site(SELF_CLEARING, after_bypass="http://169.254.169.254/latest/meta-data/")
    page = await open_site(chromium, site)
    with pytest.raises(Exception) as caught:
        await browser.navigate(page, START, settle_state="load", settle_ms=500)
    assert browser.classify_failure(caught.value).category == browser.BLOCKED_BY_GUARD


async def test_click_through_to_a_dead_host_is_site_unreachable(chromium):
    site = Site(SELF_CLEARING, after_bypass="https://dead-host.example/landing")
    page = await open_site(chromium, site)
    with pytest.raises(Exception) as caught:
        await browser.navigate(page, START, settle_state="load", settle_ms=500)
    failure = browser.classify_failure(caught.value)
    assert (failure.category, failure.code) == ("site_unreachable", "net::ERR_NAME_NOT_RESOLVED")


async def test_script_redirect_to_a_dead_host_is_site_unreachable(chromium):
    # Not a warning at all: the page itself sends the visitor to a host that does not resolve.
    site = Site(bypass_to("https://dead-host.example/x"))
    site.bypassed = True
    site.real = bypass_to("https://dead-host.example/x")
    page = await open_site(chromium, site)
    with pytest.raises(Exception) as caught:
        await browser.navigate(page, START, settle_state="load", settle_ms=1500)
    assert browser.classify_failure(caught.value).category == "site_unreachable"


async def test_brand_capture_screenshots_the_real_page_and_records_the_chain(chromium):
    site = Site(SELF_CLEARING)

    @asynccontextmanager
    async def open_page_fn(recorder, name, **_):
        yield await open_site(chromium, site)

    s3 = FakeS3()
    cap = BrandCapture(START, "scan-12345678", CallRecorder(), s3, "b", open_page_fn)
    data = await cap.capture()
    assert data["title"] == "Sign in to your account"
    assert "scans/scan-12345678/screenshot.png" in s3.objects
    assert cap.page_observed() is True
    assert "proceeded past it once" in cap.note()
    chain = redirects.annotate(cap.chain())
    assert [h.via for h in chain] == ["start", "warning_bypass", "client"]
    meta = cap.tool_result(False)["content"][0]["text"]
    assert "cloudflare_malware_warning" in meta and "redirect_chain" in meta
