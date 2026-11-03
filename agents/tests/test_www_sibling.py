# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""www. sibling capture: a certificate that does not cover the www. name (2026-10-26 rerun)."""

from urllib.parse import urlparse

import pytest
from agent_fakes import FakeBrowserClient, FakePage, FakePlaywright, FakeS3
from playwright.async_api import Error as PlaywrightError

from phish_agents.brand_visual.capture import BrandCapture
from phish_agents.code_analyst.capture import CodeCapture
from phish_agents.common import browser
from phish_agents.common.browser import CaptureFailure, www_sibling_url
from phish_agents.common.timing import CallRecorder

pytestmark = pytest.mark.usefixtures("public_dns")

NAME_ERROR = CaptureFailure("tls_error", "net::ERR_CERT_COMMON_NAME_INVALID")
SUBMITTED = "https://www.clone-demo.vercel.app/login?x=1"
SIBLING = "https://clone-demo.vercel.app/login?x=1"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (SUBMITTED, SIBLING),
        ("https://WWW.Example.COM/A?b=C", "https://example.com/A?b=C"),
        ("https://www.example.com:8443/p", "https://example.com:8443/p"),
        ("https://www.example.com/#frag", "https://example.com/"),
        ("https://www.bücher.example/", "https://bücher.example/"),
        ("https://www.xn--bcher-kva.example/", "https://xn--bcher-kva.example/"),
        # A certificate error on http:// means it was sent on to https.
        ("http://www.example.com/p", "https://example.com/p"),
        # www. alone, or a single label left: no sibling.
        ("https://www/", None),
        ("https://www.example/", None),
        ("https://example.com/", None),
        ("https://wwwexample.com/", None),
        ("https://www.example.com./", None),
        ("ftp://www.example.com/", None),
        ("https://www.example.com:99999/", None),
    ],
)
def test_www_sibling_url(url, expected):
    assert www_sibling_url(url, NAME_ERROR) == expected


@pytest.mark.parametrize(
    "failure",
    [
        None,
        CaptureFailure("tls_error", "net::ERR_CERT_AUTHORITY_INVALID"),
        CaptureFailure("tls_error", "net::ERR_CERT_DATE_INVALID"),
        CaptureFailure("site_unreachable", "net::ERR_CERT_COMMON_NAME_INVALID"),
        CaptureFailure("navigation_timeout", "timeout"),
    ],
)
def test_no_sibling_for_other_failures(failure):
    assert www_sibling_url(SUBMITTED, failure) is None


def cert_error(url: str) -> PlaywrightError:
    return PlaywrightError(f"Page.goto: net::ERR_CERT_COMMON_NAME_INVALID at {url}")


class WwwCertPage(FakePage):
    """Every www. host fails with the certificate name error; the bare host loads (or fails
    with sibling_error)."""

    def __init__(self, *, sibling_error: Exception | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.sibling_error = sibling_error

    async def goto(self, url: str, **kwargs):
        if (urlparse(url).hostname or "").startswith("www."):
            self.goto_calls.append(url)
            raise cert_error(url)
        if self.sibling_error is not None:
            self.goto_calls.append(url)
            raise self.sibling_error
        self.url = url
        return await super().goto(url, **kwargs)


def make_open_page(page):
    pw = FakePlaywright(page)

    def open_page_fn(recorder, name, **kwargs):
        return browser.open_page(
            recorder,
            name,
            client_factory=FakeBrowserClient,
            playwright_factory=lambda: pw,
            **kwargs,
        )

    return open_page_fn


def brand(page, url=SUBMITTED, s3=None):
    return BrandCapture(
        url, "scan-12345678", CallRecorder(), s3 or FakeS3(), "b", make_open_page(page)
    )


def code(page, url=SUBMITTED):
    return CodeCapture(url, "scan-12345678", CallRecorder(), FakeS3(), "b", make_open_page(page))


async def test_brand_visual_captures_the_sibling_and_keeps_the_tls_error_visible():
    page = WwwCertPage(title="Netflix", body_text="Sign In")
    s3 = FakeS3()
    cap = brand(page, s3=s3)
    data = await cap.capture()
    assert page.goto_calls == [SUBMITTED, SIBLING]
    assert cap.failure is None
    assert data["sibling_capture"] == {
        "submitted_url": SUBMITTED,
        "captured_url": SIBLING,
        "reason": "the certificate does not cover the www. name",
    }
    assert [s.name for s in cap.signals()] == ["tls_error", "www_sibling_capture"]
    assert all(s.severity == "low" for s in cap.signals())
    evidence = cap.signals()[1].evidence
    assert SUBMITTED in evidence and SIBLING in evidence
    # The submitted page was not observed: a visitor gets a certificate warning.
    assert cap.page_observed() is False
    assert "Visitors to this link see a certificate warning" in cap.note()
    # The screenshot is evidence, saved under the usual key.
    assert cap.artifacts == ["scans/scan-12345678/screenshot.png"]
    assert "scans/scan-12345678/screenshot.png" in s3.objects
    text = cap.tool_result(sanitize=False)["content"][0]["text"]
    assert text.startswith(browser.WWW_SIBLING_TOOL_TEXT)
    assert "same site without www." in text and "certificate warning to visitors" in text
    assert text.index(browser.WWW_SIBLING_TOOL_TEXT) < text.index("<<<UNTRUSTED_PAGE_CONTENT>>>")


async def test_brand_visual_keeps_the_original_tls_error_when_the_sibling_fails_too():
    page = WwwCertPage(sibling_error=PlaywrightError("Page.goto: net::ERR_CONNECTION_REFUSED at x"))
    cap = brand(page)
    data = await cap.capture()
    assert page.goto_calls == [SUBMITTED, SIBLING]
    assert (cap.failure.category, cap.failure.code) == (
        "tls_error",
        "net::ERR_CERT_COMMON_NAME_INVALID",
    )
    assert data["error"] == "capture_failed" and "sibling_capture" not in data
    assert [s.name for s in cap.signals()] == ["tls_error"]


async def test_code_analyst_analyses_the_sibling_dom():
    page = WwwCertPage(evaluate_result={"forms": [], "inline_scripts": ["x()"]})
    cap = code(page)
    data = await cap.capture()
    assert page.goto_calls == [SUBMITTED, SIBLING]
    assert cap.failure is None and data["final_url"] == SIBLING
    assert data["sibling_capture"]["captured_url"] == SIBLING
    assert data["www_sibling_capture"] and data["tls_error"]
    assert [s.name for s in cap.signals()] == ["tls_error", "www_sibling_capture"]
    assert cap.page_observed() is False
    assert cap.insights() is not None
    view = cap.model_view(sanitize=False)
    assert view.startswith(browser.WWW_SIBLING_TOOL_TEXT)


async def test_code_analyst_keeps_the_original_tls_error_when_the_sibling_is_refused(monkeypatch):
    # The sibling goes through the same preflight and guard: a refusal there keeps tls_error.
    async def refuse(url):
        if url == SIBLING:
            raise browser.BlockedNavigation("internal address")

    monkeypatch.setattr(browser, "preflight", refuse)
    page = WwwCertPage()
    cap = code(page)
    await cap.capture()
    assert page.goto_calls == [SUBMITTED]
    assert cap.failure.category == "tls_error"


async def test_no_sibling_without_www():
    page = FakePage(goto_error=cert_error("https://clone-demo.vercel.app/"))
    cap = brand(page, url="https://clone-demo.vercel.app/")
    await cap.capture()
    assert page.goto_calls == ["https://clone-demo.vercel.app/"]
    assert cap.failure.category == "tls_error"


async def test_sibling_is_tried_once_and_skipped_without_time():
    calls = []

    async def always_fails(url):
        calls.append(url)
        raise cert_error(url)

    with pytest.raises(PlaywrightError):
        await browser.open_with_www_sibling(SUBMITTED, always_fails, lambda: 0, 1_000)
    assert calls == [SUBMITTED]

    calls.clear()
    with pytest.raises(PlaywrightError) as raised:
        await browser.open_with_www_sibling(
            "https://www.www.a.example/", always_fails, lambda: 5_000, 1_000
        )
    # One sibling attempt, never recursive, and the original error is the one raised.
    assert calls == ["https://www.www.a.example/", "https://www.a.example/"]
    assert "www.www.a.example" in str(raised.value)


async def test_sibling_retries_once_after_the_error_page_interrupts_it(monkeypatch):
    async def allow(url):
        return None

    monkeypatch.setattr(browser, "preflight", allow)
    calls = []

    async def opener(url):
        calls.append(url)
        if url == SUBMITTED:
            raise cert_error(url)
        if calls.count(url) == 1:
            raise PlaywrightError(
                f'Page.goto: Navigation to "{url}" is interrupted by another navigation to '
                '"chrome-error://chromewebdata/"'
            )
        return {"final_url": url, "status": 200, "title": "t"}

    nav = await browser.open_with_www_sibling(SUBMITTED, opener, lambda: 5_000, 1_000)
    assert calls == [SUBMITTED, SIBLING, SIBLING]
    assert nav["sibling_capture"]["captured_url"] == SIBLING
