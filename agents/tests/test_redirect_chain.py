# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Redirect chains and the warning click-through, with test doubles (no browser, no network).

test_warning_bypass.py drives the same code in a real local Chromium when one is installed.
"""

import functools
import json
import socket

import httpx
import pytest
from agent_fakes import FakeAgentFactory, FakePage, FakeResult, FakeS3
from playwright.async_api import TimeoutError as PlaywrightTimeout

from phish_agents.code_analyst.capture import CodeCapture
from phish_agents.common import browser, http_probe, redirects, url_safety
from phish_agents.common.finding import FindingDraft
from phish_agents.common.remote_tools import apply_payload, capture_payload
from phish_agents.common.timing import CallRecorder
from phish_agents.tools_server import server as tools_server
from phish_agents.url_analyst import agent as url_agent

pytestmark = pytest.mark.usefixtures("public_dns")

WARNING_TITLE = "Suspected Malware | Cloudflare"


# --- NavigationLog -------------------------------------------------------------------


class Frame:
    parent_frame = None


class Req:
    def __init__(self, url, redirected_from=None, nav=True, failure=None):
        self.url, self.redirected_from, self.failure = url, redirected_from, failure
        self._nav = nav
        self.frame = Frame()

    def is_navigation_request(self):
        return self._nav


class Resp:
    def __init__(self, request, status):
        self.request, self.status = request, status


def test_navigation_log_names_every_kind_of_hop():
    page = FakePage()
    log = browser.NavigationLog(page)
    emit = {e: page.handlers[e][0] for e in ("request", "response", "requestfailed")}
    start = Req("https://short.example/a")
    hop = Req("https://kit.pages.dev/", redirected_from=start)
    emit["request"](start)
    emit["response"](Resp(start, 302))
    emit["request"](hop)
    emit["response"](Resp(hop, 403))
    emit["request"](Req("https://kit.pages.dev/sub.js", nav=False))  # a subresource: no hop
    log.next_via = redirects.WARNING_BYPASS
    bypass = Req("https://kit.pages.dev/cdn-cgi/phish-bypass?atok=x")
    emit["request"](bypass)
    script = Req("https://dead.example/")
    emit["request"](script)
    emit["requestfailed"](Req("https://dead.example/", failure="net::ERR_NAME_NOT_RESOLVED"))
    script.failure = "net::ERR_NAME_NOT_RESOLVED"
    emit["requestfailed"](script)
    assert log.hops == [
        {"url": "https://short.example/a", "via": "start", "status": 302},
        {"url": "https://kit.pages.dev/", "via": "http", "status": 403},
        {"url": "https://kit.pages.dev/cdn-cgi/phish-bypass?atok=x", "via": "warning_bypass"},
        {"url": "https://dead.example/", "via": "client", "error": "net::ERR_NAME_NOT_RESOLVED"},
    ]


async def test_navigate_refuses_an_internal_hop_seen_only_in_the_log():
    # A 3xx hop of a later navigation is never routed; the log is what the guard checks.
    page = FakePage(final_url="https://example.com/")
    original = page.wait_for_load_state

    async def settle_moves(state="load", **kw):
        page.handlers["request"][0](Req("http://169.254.169.254/latest/meta-data/"))
        await original(state, **kw)

    page.wait_for_load_state = settle_moves
    with pytest.raises(browser.BlockedNavigation):
        await browser.navigate(page, "https://example.com/")


# --- proceed_past_warning with a double -----------------------------------------------


class WarningPage(FakePage):
    """A Cloudflare warning page whose proceed control behaves as configured."""

    def __init__(self, *, control=True, enabled=True, turnstile=False, enables=False, **kw):
        super().__init__(final_url="https://kit.pages.dev/", title=WARNING_TITLE, status=403, **kw)
        self.state = {"control": control, "enabled": enabled, "turnstile": turnstile}
        self.enables = enables
        self.clicks: list[str] = []

    async def evaluate(self, _script, *_args):
        return dict(self.state)

    async def wait_for_function(self, _script, **kwargs):
        if not self.enables:
            raise PlaywrightTimeout(f"Timeout {kwargs.get('timeout')}ms exceeded.")

    def expect_navigation(self, **_kwargs):
        page = self

        class Info:
            def __init__(self):
                async def value():
                    return type("R", (), {"status": 200})()

                self.value = value()

        class Waiter:
            async def __aenter__(self):
                return Info()

            async def __aexit__(self, *exc):
                if not page.clicks:
                    raise PlaywrightTimeout("no navigation")
                page.url, page._title = "https://kit.pages.dev/", "Sign in"
                return False

        return Waiter()

    async def click(self, selector, **_kwargs):
        self.clicks.append(selector)


def warning_nav():
    return {"final_url": "https://kit.pages.dev/", "status": 403, "title": WARNING_TITLE}


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"control": False}, "no_proceed_control"),
        ({"enabled": False, "turnstile": True}, "turnstile"),
        ({"enabled": False}, "proceed_disabled"),
    ],
)
async def test_click_through_stops_without_clicking(kwargs, reason):
    page = WarningPage(**kwargs)
    nav = await browser.proceed_past_warning(page, warning_nav(), browser.NavigationLog(page))
    assert nav["provider_warning"]["outcome"] == "blocked"
    assert nav["provider_warning"]["reason"] == reason
    assert page.clicks == [] and nav["title"] == WARNING_TITLE


async def test_click_through_needs_time_left():
    page = WarningPage()
    nav = await browser.proceed_past_warning(
        page, warning_nav(), browser.NavigationLog(page), deadline=0.0
    )
    assert nav["provider_warning"]["reason"] == "no_time" and page.clicks == []


async def test_click_through_clicks_the_bypass_control_once():
    page = WarningPage(enabled=False, turnstile=True, enables=True)
    nav = await browser.proceed_past_warning(page, warning_nav(), browser.NavigationLog(page))
    assert page.clicks == [browser.BYPASS_CONTROL]
    assert browser.BYPASS_CONTROL.startswith('form[action="/cdn-cgi/phish-bypass"]')
    assert nav["title"] == "Sign in" and nav["status"] == 200
    assert nav["provider_warning"]["outcome"] == "proceeded"


async def test_pages_that_are_not_warnings_are_left_alone():
    page = WarningPage()
    nav = {"final_url": "https://a.example/", "status": 200, "title": "Welcome"}
    assert await browser.proceed_past_warning(page, nav, browser.NavigationLog(page)) is nav
    assert page.clicks == []


# --- signals, notes and page_observed -------------------------------------------------


def blocked_nav(reason="turnstile"):
    return {
        **warning_nav(),
        "provider_warning": {
            "signal": "cloudflare_malware_warning",
            "url": "https://kit.pages.dev/",
            "status": 403,
            "outcome": "blocked",
            "reason": reason,
        },
    }


def test_blocked_warning_signals_and_note():
    nav = blocked_nav()
    signals = browser.capture_signals(nav)
    assert [s.name for s in signals] == ["cloudflare_malware_warning", "warning_bypass_blocked"]
    assert [s.severity for s in signals] == ["high", "low"]
    assert browser.page_observed(None, nav) is False
    note = browser.capture_note(None, browser.site_block_signal(nav), nav["provider_warning"])
    assert note.startswith("Cloudflare showed its own malware warning")
    assert "Turnstile" in note and "_" not in note


def test_proceeded_warning_keeps_the_warning_and_judges_the_real_page():
    nav = {
        "final_url": "https://kit.pages.dev/",
        "status": 404,
        "title": "Not found",
        "provider_warning": {**blocked_nav()["provider_warning"], "outcome": "proceeded"},
    }
    signals = browser.capture_signals(nav)
    assert [s.name for s in signals] == ["cloudflare_malware_warning", "page_not_found"]
    assert browser.page_observed(None, nav) is True


@pytest.mark.parametrize(
    ("nav", "observed"),
    [
        ({"final_url": "https://a.example/", "status": 200, "title": "Shop"}, True),
        ({"final_url": "https://a.example/", "status": 429, "title": "Just a moment..."}, False),
        ({"final_url": "https://a.example/", "status": 403, "title": "Access denied"}, False),
        ({"error": "capture_failed", "category": "site_unreachable", "reason": "x"}, False),
        (None, False),
    ],
)
def test_page_observed(nav, observed):
    assert browser.page_observed(None, nav) is observed


def test_remote_payload_keeps_the_warning_and_the_chain():
    cap = CodeCapture("https://kit.pages.dev/", "scan-12345678", CallRecorder(), FakeS3(), "b")
    cap.data = {**blocked_nav(), "redirect_chain": [{"url": "https://kit.pages.dev/"}]}
    cap.site_block = browser.site_block_signal(cap.data)
    other = CodeCapture("https://kit.pages.dev/", "scan-12345678", CallRecorder(), FakeS3(), "b")
    apply_payload(other, json.loads(json.dumps(capture_payload(cap))))
    assert [s.name for s in other.signals()] == [s.name for s in cap.signals()]
    assert other.page_observed() is False and other.chain() == cap.chain()


# --- redirects.annotate and facts -----------------------------------------------------


def test_annotate_flags_site_changes_free_hosting_and_shorteners():
    chain = redirects.annotate(
        [
            {"url": "https://bit.ly/abc", "via": "start", "status": 301},
            {"url": "https://kit-one.pages.dev/", "via": "http", "status": 302},
            {"url": "https://kit-two.pages.dev/login", "via": "client"},
            {"url": "https://kit-two.pages.dev/next", "via": "client"},
            {"url": "https://login.example-brand.com/", "via": "http", "status": 200},
        ]
    )
    assert [h.shortener for h in chain] == [True, False, False, False, False]
    assert [h.free_hosting for h in chain] == [False, True, True, True, False]
    # A new pages.dev subdomain is a new site; a path change on the same host is not.
    assert [h.cross_domain for h in chain] == [False, True, True, False, True]
    facts = redirects.facts("https://bit.ly/abc", chain)
    assert facts["cross_domain_hops"] == 3 and facts["final_host_differs"] is True
    assert facts["via_free_hosting_or_shortener"] is True
    assert facts["hops"][0] == {"url": "https://bit.ly/abc", "status": 301, "shortener": True}


def test_annotate_caps_hops_and_urls():
    chain = redirects.annotate([{"url": "https://a.example/" + "x" * 5000}] * 30)
    assert len(chain) == 10 and len(chain[0].url) == 1024


def test_same_site_chain_is_not_cross_domain():
    chain = redirects.annotate(
        [{"url": "http://example.com/"}, {"url": "https://www.example.com/", "via": "http"}]
    )
    assert not any(h.cross_domain for h in chain)
    assert redirects.facts("http://example.com/", chain)["final_host_differs"] is False


# --- url_analyst gets the HTTP chain --------------------------------------------------


def mock_transport(routes):
    def handler(request):
        status, headers = routes[str(request.url)]
        # A stream, as from a socket: the probe reads raw bytes, and content= is pre-read.
        return httpx.Response(status, headers=headers, stream=httpx.ByteStream(b""))

    return httpx.MockTransport(handler)


async def test_url_analyst_sees_the_redirect_chain_and_stores_it():
    probe = functools.partial(
        http_probe.http_probe,
        transport=mock_transport(
            {
                "https://bit.ly/x": (301, {"location": "https://kit-a.pages.dev/"}),
                "https://kit-a.pages.dev/": (200, {}),
            }
        ),
    )
    factory = FakeAgentFactory([FakeResult(FindingDraft(verdict="suspicious", confidence=60))])
    finding = await url_agent.analyze(
        "https://bit.ly/x",
        "scan-12345678",
        s3=FakeS3(),
        agent_factory=factory,
        lookup=lambda d: {"domain": d},
        probe=probe,
    )
    assert [(h.url, h.via) for h in finding.redirect_chain] == [
        ("https://bit.ly/x", "start"),
        ("https://kit-a.pages.dev/", "http"),
    ]
    assert finding.redirect_chain[1].cross_domain and finding.redirect_chain[1].free_hosting
    tool_text = next(t for t in factory.tool_outputs if "[redirects]" in t)
    assert "<<<UNTRUSTED_PAGE_CONTENT>>>" in tool_text
    view = json.loads(tool_text.split("[redirects]\n", 1)[1].rsplit("\n<<<END", 1)[0])
    assert view["outcome"] == "ok" and view["cross_domain_hops"] == 1
    assert view["final_host_differs"] is True


async def test_redirect_to_a_dead_host_is_site_down_evidence_for_url_analyst(monkeypatch):
    real = url_safety.socket.getaddrinfo

    def dns(host, *a, **k):
        if host == "dead.example":
            raise socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided")
        return real(host, *a, **k)

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", dns)
    probe = functools.partial(
        http_probe.http_probe,
        transport=mock_transport(
            {"https://a.example/": (302, {"location": "https://dead.example/"})}
        ),
    )
    factory = FakeAgentFactory([FakeResult(FindingDraft(verdict="unknown", confidence=20))])
    finding = await url_agent.analyze(
        "https://a.example/",
        "scan-12345678",
        s3=FakeS3(),
        agent_factory=factory,
        lookup=lambda d: {"domain": d},
        probe=probe,
    )
    signal = next(s for s in finding.signals if s.name == "site_unreachable")
    assert "site that is down" in signal.evidence and "dead.example" in signal.evidence
    assert finding.redirect_chain[-1].url == "https://dead.example/"
    assert finding.redirect_chain[-1].error


async def test_precheck_redirect_to_a_dead_host_is_site_down(monkeypatch):
    # The browser follows the 302 and fails on the dead host; the HTTP probe walks the same
    # redirect, finds the host gone and the scan ends on the site_down fast path.
    from playwright.async_api import Error as PlaywrightError
    from test_tools_server import open_page_fn

    real = url_safety.socket.getaddrinfo

    def dns(host, *a, **k):
        if host == "dead.example":
            raise socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided")
        return real(host, *a, **k)

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", dns)
    page = FakePage(
        goto_error=PlaywrightError("net::ERR_NAME_NOT_RESOLVED at https://dead.example/")
    )
    probe = functools.partial(
        http_probe.http_probe,
        transport=mock_transport(
            {"https://a.example/": (302, {"location": "https://dead.example/"})}
        ),
    )
    out = json.loads(
        await tools_server.run_precheck_url(
            "https://a.example/",
            "scan-12345678",
            open_page_fn=open_page_fn(page),
            http_probe_fn=probe,
        )
    )
    assert out["outcome"] == "site_down" and out["probe"] == "http"
    assert out["hops"] == ["https://a.example/", "https://dead.example/"]
