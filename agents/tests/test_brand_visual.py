# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import asyncio

import pytest
from agent_fakes import (
    FakeAgentFactory,
    FakeBrowserClient,
    FakePage,
    FakePlaywright,
    FakeResult,
    FakeS3,
)

from phish_agents.brand_visual import agent as brand_agent
from phish_agents.brand_visual import capture
from phish_agents.brand_visual.capture import BrandCapture
from phish_agents.common import browser
from phish_agents.common.finding import FindingDraft, SignalDraft
from phish_agents.common.timing import CallRecorder

pytestmark = pytest.mark.usefixtures("public_dns")


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


async def test_capture_uploads_screenshot_and_builds_tool_result():
    page = FakePage(
        final_url="https://paypa1-login.xyz/", title="PayPal: Log in", body_text="Log in to PayPal"
    )
    s3 = FakeS3()
    cap = BrandCapture(
        "https://paypa1-login.xyz", "scan-12345678", CallRecorder(), s3, "b", make_open_page(page)
    )
    data = await cap.capture()
    assert data["title"] == "PayPal: Log in"
    assert s3.objects["scans/scan-12345678/screenshot.png"]["ContentType"] == "image/png"
    result = cap.tool_result(sanitize=False)
    assert result["status"] == "success"
    assert result["content"][1]["image"]["format"] == "png"
    assert "<<<UNTRUSTED_PAGE_CONTENT>>>" in result["content"][0]["text"]
    assert cap.artifacts == ["scans/scan-12345678/screenshot.png"]


async def test_capture_failure_is_reported_as_text():
    # Nothing committed before the timeout, so the tab is still blank.
    page = FakePage(goto_error=TimeoutError("nav"), final_url="about:blank")
    cap = BrandCapture(
        "https://slow.example", "scan-12345678", CallRecorder(), FakeS3(), "b", make_open_page(page)
    )
    data = await cap.capture()
    assert data["error"] == "capture_failed"
    assert cap.tool_result(sanitize=False)["content"][0]["text"].startswith("capture_failed")


async def test_analyze_end_to_end_with_fakes():
    page = FakePage(
        final_url="https://paypa1-login.xyz/", title="PayPal", body_text="Your account is suspended"
    )
    draft = FindingDraft(
        verdict="phishing",
        confidence=94,
        signals=[
            SignalDraft(
                name="brand_domain_mismatch",
                severity="critical",
                evidence="PayPal on paypa1-login.xyz",
            )
        ],
    )
    s3 = FakeS3()
    finding = await brand_agent.analyze(
        "https://paypa1-login.xyz",
        "scan-12345678",
        s3=s3,
        agent_factory=FakeAgentFactory([FakeResult(draft)]),
        open_page_fn=make_open_page(page),
    )
    assert finding.agent == "brand_visual" and finding.verdict == "phishing"
    assert finding.artifacts == ["scans/scan-12345678/screenshot.png"]
    assert {c.kind for c in finding.calls} >= {"browser", "model"}
    assert "scans/scan-12345678/findings/brand_visual.json" in s3.objects


async def test_capture_runs_only_once_even_if_tool_called_twice():
    page = FakePage()
    cap = BrandCapture(
        "https://example.com", "scan-12345678", CallRecorder(), FakeS3(), "b", make_open_page(page)
    )
    await cap.capture()
    await cap.capture()
    assert page.goto_calls == ["https://example.com"]


async def test_unreachable_site_is_a_deterministic_signal_and_opens_no_session(monkeypatch):
    import socket

    from phish_agents.common import url_safety

    def nxdomain(*_a, **_k):
        raise socket.gaierror(socket.EAI_NONAME, "not known")

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", nxdomain)
    url_safety.request_allowed.cache_clear()
    before = len(FakeBrowserClient.instances)
    draft = FindingDraft(verdict="suspicious", confidence=40, signals=[])
    factory = FakeAgentFactory([FakeResult(draft)])
    finding = await brand_agent.analyze(
        "https://gone.example",
        "scan-12345678",
        s3=FakeS3(),
        agent_factory=factory,
        open_page_fn=make_open_page(FakePage()),
    )
    assert len(FakeBrowserClient.instances) == before
    assert finding.status == "ok"
    assert [s.name for s in finding.signals] == ["site_unreachable"]
    assert factory.tool_outputs[0]["content"][0]["text"].startswith("site_unreachable")


async def test_browser_block_is_a_low_signal_in_the_finding():
    from playwright.async_api import Error

    page = FakePage(goto_error=Error("Page.goto: net::ERR_BLOCKED_BY_CLIENT at http://x.example/"))
    draft = FindingDraft(verdict="suspicious", confidence=60, signals=[])
    factory = FakeAgentFactory([FakeResult(draft)])
    finding = await brand_agent.analyze(
        "http://x.example/",
        "scan-12345678",
        s3=FakeS3(),
        agent_factory=factory,
        open_page_fn=make_open_page(page),
    )
    assert [(s.name, s.severity) for s in finding.signals] == [("blocked_by_browser", "low")]
    assert factory.tool_outputs[0]["content"][0]["text"].startswith("blocked_by_browser")


async def test_bot_wall_page_is_captured_with_a_bot_challenge_signal():
    page = FakePage(title="Just a moment...", body_text="Checking your browser", status=403)
    s3 = FakeS3()
    cap = BrandCapture(
        "https://walled.example", "scan-12345678", CallRecorder(), s3, "b", make_open_page(page)
    )
    data = await cap.capture()
    assert data["status"] == 403 and "error" not in data
    assert [s.name for s in cap.signals()] == ["bot_challenge"]
    assert "scans/scan-12345678/screenshot.png" in s3.objects
    assert "bot_challenge" in cap.tool_result(sanitize=False)["content"][0]["text"]


def brand_capture(page, s3=None, url="https://example.com"):
    return BrandCapture(
        url, "scan-12345678", CallRecorder(), s3 or FakeS3(), "b", make_open_page(page)
    )


async def test_capture_navigates_with_a_bounded_wait_and_explicit_timeouts():
    page = FakePage()
    await brand_capture(page).capture()
    goto = page.goto_kwargs[0]
    assert goto["wait_until"] in {"domcontentloaded", "commit"}
    assert goto["timeout"] <= capture.CAPTURE_BUDGET_S * 1000
    assert all(state != "networkidle" for state, _ in page.load_states)
    assert all(timeout is not None and timeout <= 3_000 for _, timeout in page.load_states)
    # The screenshot goes over CDP, bounded by SCREENSHOT_TIMEOUT_MS; Playwright's own
    # default for a screenshot or a text read is 30 s, the wall brand_visual kept hitting.
    assert page.cdp_calls == ["Page.stopLoading", "Page.captureScreenshot"]
    assert 0 < capture.SCREENSHOT_TIMEOUT_MS <= 3_000
    assert 0 < page.inner_text_kwargs[0]["timeout"] <= 3_000


class SlowStartClient(FakeBrowserClient):
    """Session start and CDP connect that take 5 s on the capture clock, as measured
    against AgentCore Browser on 2026-10-01 (4.3 to 5.3 s before the first goto)."""

    clock = [0.0]

    def start(self, **kwargs):
        SlowStartClient.clock[0] += 5.0
        return super().start(**kwargs)


async def test_navigation_gets_what_the_session_start_leaves_minus_a_small_reserve(
    monkeypatch,
):
    SlowStartClient.clock = [100.0]
    monkeypatch.setattr(capture, "_clock", lambda: SlowStartClient.clock[0])
    page = FakePage()
    pw = FakePlaywright(page)

    def open_page_fn(recorder, name, **kwargs):
        return browser.open_page(
            recorder,
            name,
            client_factory=SlowStartClient,
            playwright_factory=lambda: pw,
            **kwargs,
        )

    cap = BrandCapture(
        "https://example.com", "scan-12345678", CallRecorder(), FakeS3(), "b", open_page_fn
    )
    await cap.capture()
    # 14 s budget, 5 s start-up: the old 7.5 s reserve left navigation 1.5 s. A slow
    # phishing page (tetes-air.pages.dev) needed 5.1 s to commit.
    assert page.goto_kwargs[0]["timeout"] >= 5_000
    # The settle comes out of what navigation left, never out of the screenshot reserve.
    assert all(t <= capture.SETTLE_MS for _, t in page.load_states)


def scaled_budget(monkeypatch):
    # The 14 s budget at a tenth of the scale, so the test runs on the real clock.
    monkeypatch.setattr(capture, "CAPTURE_BUDGET_S", 1.4)
    monkeypatch.setattr(capture, "NAV_TIMEOUT_MS", 800)
    monkeypatch.setattr(capture, "SETTLE_MS", 100)
    monkeypatch.setattr(capture, "SCREENSHOT_TIMEOUT_MS", 250)
    monkeypatch.setattr(capture, "UPLOAD_RESERVE_MS", 100)
    monkeypatch.setattr(capture, "_AFTER_NAV_MS", 350)
    monkeypatch.setattr(capture, "_MIN_NAV_MS", 100)


async def test_slow_navigation_cannot_spend_the_screenshot_budget(monkeypatch):
    # tetes-air.pages.dev on 2026-10-01: the page committed and painted, then kept
    # loading past every timeout. The screenshot must still be taken of what rendered.
    scaled_budget(monkeypatch)
    s3 = FakeS3()
    page = FakePage(final_url="https://slow.example/", slow={"goto": 30.0})
    cap = brand_capture(page, s3, url="https://slow.example/")
    data = await cap.capture()
    assert page.goto_kwargs[0]["timeout"] <= 1_400 - 350
    assert data["navigation_timed_out"] and "error" not in data
    assert page.cdp_calls[-1] == "Page.captureScreenshot"
    assert SHOT_KEY in s3.objects and cap.capture_status() == "partial"


async def test_slow_settle_ends_at_the_navigation_deadline(monkeypatch):
    # domcontentloaded came quickly but load never fired: the settle is cut at the
    # navigation deadline, not at SETTLE_MS on top of it.
    scaled_budget(monkeypatch)
    monkeypatch.setattr(capture, "SETTLE_MS", 5_000)
    s3 = FakeS3()
    page = FakePage(slow={"wait_for_load_state": 30.0})
    cap = brand_capture(page, s3)
    await cap.capture()
    [(_, settle_ms)] = page.load_states
    assert settle_ms <= 1_400 - 350
    assert SHOT_KEY in s3.objects and cap.capture_status() == "complete"


async def test_screenshot_falls_back_to_playwright_when_cdp_stalls(monkeypatch):
    s3 = FakeS3()
    page = FakePage(cdp_hang=True)
    cap = brand_capture(page, s3)
    await cap.capture()
    [fallback] = [k for k in page.screenshot_kwargs if not k.get("cdp")]
    assert fallback["animations"] == "disabled" and fallback["caret"] == "hide"
    assert 0 < fallback["timeout"] <= capture.SCREENSHOT_TIMEOUT_MS
    assert SHOT_KEY in s3.objects and cap.capture_status() == "complete"


async def test_whole_capture_is_capped_by_the_budget(monkeypatch):
    monkeypatch.setattr(capture, "CAPTURE_BUDGET_S", 0.2)
    # A goto that ignores its own timeout, as a stalled remote CDP connection does.
    page = FakePage(hang=frozenset({"goto"}))
    cap = brand_capture(page)
    data = await asyncio.wait_for(cap.capture(), 2)
    assert data["error"] == "capture_failed" and data["category"] == "navigation_timeout"
    assert data["reason"] == "capture_budget"
    assert cap.capture_status() == "failed (navigation_timeout: capture_budget)"
    assert FakeBrowserClient.instances[-1].stopped


SHOT_KEY = "scans/scan-12345678/screenshot.png"


async def test_screenshot_is_uploaded_before_the_text_read():
    s3 = FakeS3()
    page = FakePage()
    seen = []
    page.before_inner_text = lambda: seen.append(SHOT_KEY in s3.objects)
    await brand_capture(page, s3).capture()
    assert seen == [True]


async def test_screenshot_is_kept_when_the_text_read_fails():
    from playwright.async_api import TimeoutError as PlaywrightTimeout

    s3 = FakeS3()
    page = FakePage(inner_text_error=PlaywrightTimeout("Timeout 1500ms exceeded"))
    cap = brand_capture(page, s3)
    data = await cap.capture()
    assert "error" not in data and data["visible_text"] == ""
    assert SHOT_KEY in s3.objects and cap.artifacts == [SHOT_KEY]
    assert cap.tool_result(sanitize=False)["content"][1]["image"]["format"] == "png"


class OrderCheckingFactory(FakeAgentFactory):
    """Records whether the screenshot was already in S3 when the agent was built."""

    def __init__(self, s3, outcomes):
        super().__init__(outcomes)
        self.s3, self.shot_ready = s3, []

    def __call__(self, **kwargs):
        self.shot_ready.append(SHOT_KEY in self.s3.objects)
        return super().__call__(**kwargs)


async def test_analyze_keeps_the_eager_capture_when_the_model_never_calls_the_tool():
    # The capture starts alongside the model's first turn; a model that never calls
    # capture_page still leaves one capture (and its screenshot) on the Finding.
    s3 = FakeS3()
    page = FakePage()
    factory = OrderCheckingFactory(
        s3, [FakeResult(FindingDraft(verdict="legitimate", confidence=80))]
    )
    finding = await brand_agent.analyze(
        "https://example.com",
        "scan-12345678",
        s3=s3,
        agent_factory=factory,
        open_page_fn=make_open_page(page),
    )
    assert page.goto_calls == ["https://example.com"]
    assert finding.artifacts == [SHOT_KEY]
    assert SHOT_KEY in s3.objects
    assert finding.page_observed is True


def nav_timeout():
    from playwright.async_api import TimeoutError as PlaywrightTimeout

    return PlaywrightTimeout("Page.goto: Timeout 8000ms exceeded.")


async def test_navigation_timeout_still_screenshots_what_rendered():
    s3 = FakeS3()
    page = FakePage(
        goto_error=nav_timeout(), final_url="https://slow.example/login", title="Sign in"
    )
    cap = brand_capture(page, s3, url="https://slow.example/login")
    data = await cap.capture()
    assert "error" not in data and data["navigation_timed_out"] is True
    assert data["final_url"] == "https://slow.example/login" and data["title"] == "Sign in"
    assert SHOT_KEY in s3.objects and cap.artifacts == [SHOT_KEY]
    assert cap.signals() == []
    result = cap.tool_result(sanitize=False)
    assert "did not finish loading" in result["content"][0]["text"]
    assert result["content"][1]["image"]["format"] == "png"


async def test_navigation_timeout_on_a_blank_page_is_a_failed_capture():
    s3 = FakeS3()
    page = FakePage(goto_error=nav_timeout(), final_url="about:blank")
    cap = brand_capture(page, s3)
    data = await cap.capture()
    assert data["category"] == "navigation_timeout"
    assert page.screenshot_kwargs == [] and s3.objects == {} and cap.artifacts == []


async def test_navigation_timeout_on_the_new_tab_page_is_a_failed_capture():
    # Seen live: the tab still showed chrome://new-tab-page/, titled "Loading <url>".
    s3 = FakeS3()
    page = FakePage(goto_error=nav_timeout(), final_url="chrome://new-tab-page/")
    cap = brand_capture(page, s3)
    data = await cap.capture()
    assert data["category"] == "navigation_timeout"
    assert page.screenshot_kwargs == [] and s3.objects == {} and cap.artifacts == []


async def test_navigation_timeout_on_an_internal_url_is_refused_not_captured():
    s3 = FakeS3()
    page = FakePage(goto_error=nav_timeout(), final_url="http://10.0.0.5/admin")
    cap = brand_capture(page, s3)
    data = await cap.capture()
    assert data["category"] == "blocked_by_guard"
    assert page.screenshot_kwargs == [] and s3.objects == {}


class StuckModelFactory(FakeAgentFactory):
    """A model turn that never returns, the way a slow Bedrock call meets the deadline."""

    def __init__(self):
        super().__init__([])

    async def invoke_async(self, prompt, structured_output_model=None):
        self.prompts.append(prompt)
        await asyncio.Event().wait()


@pytest.fixture
def short_deadline(monkeypatch):
    from phish_agents.common import server

    # 1.0 / 0.5 s and 3.0 / 1.0 s flaked in the full pre-push run on a loaded machine: the
    # fake capture or the wrap-up overran. 3 s for each leaves room for an event loop stall.
    monkeypatch.setattr(server, "PAGE_DEADLINE_S", 6.0)
    monkeypatch.setattr(brand_agent, "DEADLINE_MARGIN_S", 3.0)


async def run_stuck(page, url="https://example.com"):
    from phish_agents.common import server as server_module

    s3 = FakeS3()
    finding = await asyncio.wait_for(
        brand_agent.analyze(
            url,
            "scan-12345678",
            s3=s3,
            agent_factory=StuckModelFactory(),
            open_page_fn=make_open_page(page),
        ),
        # A backstop well past the deadline, so it never races the agent's own stop.
        server_module.PAGE_DEADLINE_S + 10,
    )
    return finding, s3


@pytest.mark.usefixtures("short_deadline")
async def test_deadline_after_capture_keeps_the_screenshot_and_reports_capture_status():
    finding, s3 = await run_stuck(FakePage())
    assert finding.status == "error" and finding.artifacts == [SHOT_KEY]
    evidence = finding.signals[0].evidence
    assert "capture_status=complete" in evidence and SHOT_KEY in evidence
    assert not evidence.startswith("timeout")
    assert "browser" in {c.kind for c in finding.calls}
    assert "scans/scan-12345678/findings/brand_visual.json" in s3.objects


@pytest.mark.usefixtures("short_deadline")
async def test_capture_still_running_at_the_model_deadline_is_settled_into_the_finding(
    monkeypatch,
):
    # Model deadline 6 - 4.5 = 1.5 s; reading the title takes 2 s (it has no browser timeout of
    # its own, unlike the screenshot here), so the eager capture ends after
    # the model deadline fires and well before the specialist's own 6 s deadline.
    monkeypatch.setattr(brand_agent, "DEADLINE_MARGIN_S", 4.5)
    page = FakePage(slow={"title": 2.0})
    finding, _ = await run_stuck(page)
    assert finding.artifacts == [SHOT_KEY]
    evidence = finding.signals[0].evidence
    assert "capture_status=complete" in evidence and SHOT_KEY in evidence
    assert finding.capture_status == "complete"


@pytest.mark.usefixtures("short_deadline")
async def test_deadline_after_a_partial_capture_reports_partial():
    page = FakePage(goto_error=nav_timeout(), final_url="https://slow.example/")
    finding, _ = await run_stuck(page, url="https://slow.example/")
    assert finding.artifacts == [SHOT_KEY]
    assert "capture_status=partial" in finding.signals[0].evidence


@pytest.mark.usefixtures("short_deadline")
async def test_deadline_after_a_failed_capture_keeps_the_capture_signal():
    from playwright.async_api import Error

    page = FakePage(goto_error=Error("Page.goto: net::ERR_BLOCKED_BY_CLIENT at http://x.example/"))
    finding, _ = await run_stuck(page, url="http://x.example/")
    assert finding.artifacts == []
    assert "capture_status=failed (blocked_by_browser" in finding.signals[0].evidence
    assert "blocked_by_browser" in [s.name for s in finding.signals]


async def test_server_deadline_returns_the_brand_visual_finding_not_a_bare_timeout(monkeypatch):
    from phish_agents.common import server
    from phish_contracts.models import Finding

    # Wide enough that the fake capture always fits inside the margin on a loaded machine
    # (1.0 / 0.5 failed there); the model still never answers, so the deadline path runs.
    monkeypatch.setattr(server, "PAGE_DEADLINE_S", 6.0)
    monkeypatch.setattr(brand_agent, "DEADLINE_MARGIN_S", 3.0)
    s3 = FakeS3()
    page = FakePage()

    async def analyze(url, scan_id, *, recorder):
        return await brand_agent.analyze(
            url,
            scan_id,
            recorder=recorder,
            s3=s3,
            agent_factory=StuckModelFactory(),
            open_page_fn=make_open_page(page),
        )

    raw = await server.safe_analyze(
        "brand_visual", analyze, "https://example.com", "scan-12345678", s3=s3
    )
    finding = Finding.model_validate_json(raw)
    assert finding.artifacts == [SHOT_KEY]
    assert "capture_status=complete" in finding.signals[0].evidence


async def test_capture_status_is_on_the_persisted_finding():
    import json

    draft = FindingDraft(verdict="legitimate", confidence=80, signals=[])
    s3 = FakeS3()
    finding = await brand_agent.analyze(
        "https://example.com",
        "scan-12345678",
        s3=s3,
        agent_factory=FakeAgentFactory([FakeResult(draft)]),
        open_page_fn=make_open_page(FakePage()),
    )
    assert finding.capture_status == "complete"
    stored = json.loads(s3.objects["scans/scan-12345678/findings/brand_visual.json"]["Body"])
    assert stored["capture_status"] == "complete"


async def test_capture_status_on_a_failed_capture_finding():
    from playwright.async_api import Error

    page = FakePage(goto_error=Error("Page.goto: net::ERR_BLOCKED_BY_CLIENT at http://x.example/"))
    draft = FindingDraft(verdict="suspicious", confidence=60, signals=[])
    finding = await brand_agent.analyze(
        "http://x.example/",
        "scan-12345678",
        s3=FakeS3(),
        agent_factory=FakeAgentFactory([FakeResult(draft)]),
        open_page_fn=make_open_page(page),
    )
    assert finding.capture_status.startswith("failed (blocked_by_browser")


@pytest.mark.usefixtures("short_deadline")
async def test_capture_status_on_the_deadline_finding():
    finding, _ = await run_stuck(FakePage())
    assert finding.status == "error" and finding.capture_status == "complete"


async def test_capture_status_when_the_url_is_refused():
    finding = await brand_agent.analyze(
        "http://10.0.0.5/admin",
        "scan-12345678",
        s3=FakeS3(),
        agent_factory=FakeAgentFactory([]),
        open_page_fn=make_open_page(FakePage()),
    )
    assert finding.status == "error" and finding.capture_status == "not_captured"


async def test_fast_session_start_gives_navigation_the_rest_of_the_budget():
    # sopport-service.app, 2026-10-01: a fixed 8 s goto timeout fired with 3.7 s unused.
    page = FakePage()
    await brand_capture(page).capture()
    budget_ms = capture.CAPTURE_BUDGET_S * 1000
    assert page.goto_kwargs[0]["timeout"] > 8_000
    assert page.goto_kwargs[0]["timeout"] <= budget_ms - capture._AFTER_NAV_MS


async def test_stuck_title_still_gets_the_screenshot_saved():
    s3 = FakeS3()
    page = FakePage(hang=frozenset({"title"}))
    cap = brand_capture(page, s3)
    await asyncio.wait_for(cap.capture(), capture.CAPTURE_BUDGET_S)
    assert SHOT_KEY in s3.objects and cap.capture_status() == "complete"


async def test_404_page_is_captured_with_a_page_not_found_signal():
    page = FakePage(title="404 Not Found", body_text="The page you requested is gone", status=404)
    s3 = FakeS3()
    cap = BrandCapture(
        "https://gone.example/login", "scan-12345678", CallRecorder(), s3, "b", make_open_page(page)
    )
    data = await cap.capture()
    assert data["status"] == 404 and "error" not in data
    assert [(s.name, s.severity) for s in cap.signals()] == [("page_not_found", "low")]
    text = cap.tool_result(sanitize=False)["content"][0]["text"]
    assert "page_not_found" in text and "404" in text


async def test_a_setup_failure_starts_no_capture_to_orphan():
    opened = []

    def open_page_fn(recorder, name, **kwargs):
        opened.append(name)
        raise AssertionError("the capture must not start when setup fails")

    def broken_web_search(url, recorder):
        raise RuntimeError("web search client unavailable")

    with pytest.raises(RuntimeError, match="web search client unavailable"):
        await brand_agent.analyze(
            "https://example.com",
            "scan-12345678",
            s3=FakeS3(),
            agent_factory=FakeAgentFactory([]),
            open_page_fn=open_page_fn,
            web_search_factory=broken_web_search,
        )
    # An orphaned eager capture would reach open_page within this wait.
    await asyncio.sleep(0.5)
    assert opened == []
