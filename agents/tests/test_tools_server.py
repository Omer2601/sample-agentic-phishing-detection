# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The shared tools MCP server, and a specialist talking to it through a loop-back client."""

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
from test_code_analyst import DOM

from phish_agents.brand_visual import agent as brand_agent
from phish_agents.code_analyst import agent as code_agent
from phish_agents.common import browser, remote_tools
from phish_agents.common import server as common_server
from phish_agents.common.finding import FindingDraft, SignalDraft
from phish_agents.common.remote_tools import ToolsClient, ToolsGatewayError
from phish_agents.tools_server import server as tools_server
from phish_agents.url_analyst import agent as url_agent

pytestmark = pytest.mark.usefixtures("public_dns")
PNG = b"\x89PNG-fake"


class ReadableS3(FakeS3):
    """FakeS3 plus the get_object read-back the specialist does for the screenshot."""

    def get_object(self, **kwargs):
        body = self.objects[kwargs["Key"]]["Body"]

        class _Body:
            def read(self_inner):
                return body

        return {"Body": _Body()}


def open_page_fn(page):
    pw = FakePlaywright(page)

    def fn(recorder, name, **kwargs):
        return browser.open_page(
            recorder,
            name,
            client_factory=FakeBrowserClient,
            playwright_factory=lambda: pw,
            **kwargs,
        )

    return fn


class LoopbackClient:
    """Stands in for ToolsClient: routes tool calls to the server's own functions."""

    def __init__(self, s3, page, lookup=None, fail=False):
        self.s3, self.page, self.lookup, self.fail = s3, page, lookup, fail
        self.calls: list[tuple[str, dict]] = []
        self.closed = False

    async def call_json(self, tool, arguments, timeout_s):
        self.calls.append((tool, arguments))
        if self.fail:
            raise ToolsGatewayError(f"{tool}: HTTPStatusError")
        if tool == "capture_page":
            out = await tools_server.run_capture_page(
                **arguments, s3=self.s3, open_page_fn=open_page_fn(self.page)
            )
        elif tool == "capture_page_code":
            out = await tools_server.run_capture_page_code(
                **arguments, s3=self.s3, open_page_fn=open_page_fn(self.page)
            )
        else:
            out = await tools_server.run_whois_lookup(**arguments, lookup=self.lookup)
        return json.loads(out)

    async def aclose(self):
        self.closed = True


async def test_server_exposes_four_tools():
    tools = await tools_server.build_server().list_tools()
    assert sorted(t.name for t in tools) == [
        "capture_page",
        "capture_page_code",
        "precheck_url",
        "whois_lookup",
    ]
    by_name = {t.name: set(t.input_schema["properties"]) for t in tools}
    assert by_name["capture_page"] == {"url", "scan_id"}
    assert by_name["whois_lookup"] == {"url"}
    assert by_name["precheck_url"] == {"url", "scan_id"}


def test_tools_server_is_served_like_the_specialists():
    app = tools_server.build_server().streamable_http_app(
        host="127.0.0.1", **common_server.HTTP_OPTIONS
    )
    assert app is not None


async def test_capture_page_stores_screenshot_and_returns_no_image():
    s3 = ReadableS3()
    out = json.loads(
        await tools_server.run_capture_page(
            "https://paypa1-login.xyz",
            "scan-12345678",
            s3=s3,
            open_page_fn=open_page_fn(FakePage(title="PayPal", body_text="hi")),
        )
    )
    assert out["artifacts"] == ["scans/scan-12345678/screenshot.png"]
    assert "scans/scan-12345678/screenshot.png" in s3.objects
    assert "png" not in json.dumps(out).lower().replace("screenshot.png", "")
    assert out["failure"] is None and out["data"]["title"] == "PayPal"


async def test_each_capture_logs_its_server_side_wall_time(caplog):
    with caplog.at_level("INFO", logger="phish_agents.tools_server.server"):
        await tools_server.run_capture_page(
            "https://paypa1-login.xyz",
            "scan-12345678",
            s3=ReadableS3(),
            open_page_fn=open_page_fn(FakePage(title="PayPal", body_text="hi")),
        )
        await tools_server.run_capture_page_code(
            "https://paypa1-login.xyz",
            "scan-12345678",
            s3=ReadableS3(),
            open_page_fn=open_page_fn(FakePage(title="PayPal", body_text="hi")),
        )
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("tool timing")]
    assert [line.split()[2] for line in lines] == ["name=capture_page", "name=capture_page_code"]
    assert all("scan=scan-12345678" in line for line in lines)


@pytest.mark.parametrize(
    "url", ["http://169.254.169.254/latest", "http://localhost/", "file:///etc/passwd"]
)
async def test_capture_tools_refuse_internal_urls_without_opening_a_browser(url):
    def no_browser(*_a, **_k):
        raise AssertionError("a browser session was started")

    for run in (tools_server.run_capture_page, tools_server.run_capture_page_code):
        out = json.loads(await run(url, "scan-12345678", s3=ReadableS3(), open_page_fn=no_browser))
        assert out["failure"]["category"] == "blocked_by_guard"
        assert out["artifacts"] == []


async def test_tools_reject_a_scan_id_that_could_escape_the_prefix():
    with pytest.raises(ValueError):
        await tools_server.run_capture_page("https://a.com", "../etc", s3=ReadableS3())


async def test_whois_takes_a_url_and_refuses_internal_ones():
    seen = []

    def lookup(domain):
        seen.append(domain)
        return {"domain": domain, "age_days": 3}

    ok = json.loads(
        await tools_server.run_whois_lookup("https://login.evil.co.uk/x", lookup=lookup)
    )
    assert ok == {"domain": "evil.co.uk", "age_days": 3} and seen == ["evil.co.uk"]
    refused = json.loads(await tools_server.run_whois_lookup("http://10.0.0.1/", lookup=lookup))
    assert refused["error"] == "url_refused" and seen == ["evil.co.uk"]


async def test_brand_visual_through_the_gateway_reads_the_screenshot_back():
    s3 = ReadableS3()
    client = LoopbackClient(s3, FakePage(final_url="https://paypa1-login.xyz/", title="PayPal"))
    draft = FindingDraft(
        verdict="phishing",
        confidence=90,
        signals=[SignalDraft(name="brand_domain_mismatch", severity="high", evidence="PayPal")],
    )
    factory = FakeAgentFactory([FakeResult(draft)])
    finding = await brand_agent.analyze(
        "https://paypa1-login.xyz",
        "scan-12345678",
        s3=s3,
        agent_factory=factory,
        tools_factory=lambda: client,
        web_search_factory=lambda *_: None,
    )
    assert [c[0] for c in client.calls] == ["capture_page"]
    assert finding.artifacts == ["scans/scan-12345678/screenshot.png"]
    assert finding.capture_status == "complete"
    assert client.closed
    assert {c.kind for c in finding.calls} >= {"browser", "model"}


async def test_brand_visual_gateway_failure_degrades_to_a_failed_capture():
    s3 = ReadableS3()
    client = LoopbackClient(s3, FakePage(), fail=True)
    draft = FindingDraft(verdict="suspicious", confidence=40, signals=[])
    finding = await brand_agent.analyze(
        "https://a.example",
        "scan-12345678",
        s3=s3,
        agent_factory=FakeAgentFactory([FakeResult(draft)]),
        tools_factory=lambda: client,
        web_search_factory=lambda *_: None,
    )
    assert finding.capture_status.startswith("failed (browser_error: tools_gateway)")
    assert client.closed


async def test_code_analyst_through_the_gateway():
    page = FakePage(
        final_url="https://paypal-verify.xyz/",
        evaluate_result=DOM,
        responses=[FakeResponse(200, "https://cdn.evil.ru/k.js", "script", "document.onkeydown=1")],
    )
    s3 = ReadableS3()
    client = LoopbackClient(s3, page)
    draft = FindingDraft(verdict="phishing", confidence=95, signals=[])
    finding = await code_agent.analyze(
        "https://paypal-verify.xyz",
        "scan-12345678",
        s3=s3,
        agent_factory=FakeAgentFactory([FakeResult(draft)]),
        tools_factory=lambda: client,
    )
    assert finding.artifacts == ["scans/scan-12345678/capture.json"]
    assert client.closed


async def test_url_analyst_through_the_gateway_and_gateway_failure():
    draft = FindingDraft(verdict="suspicious", confidence=55, signals=[])
    s3 = ReadableS3()
    good = LoopbackClient(s3, None, lookup=lambda d: {"domain": d, "age_days": 2})
    factory = FakeAgentFactory([FakeResult(draft)], tool_args={"whois_lookup": {}})
    await url_agent.analyze(
        "https://login.evil.xyz",
        "scan-12345678",
        s3=s3,
        agent_factory=factory,
        tools_factory=lambda: good,
    )
    assert [c[0] for c in good.calls] == ["whois_lookup"]
    assert good.calls[0][1] == {"url": "https://login.evil.xyz"}
    assert good.closed
    bad = LoopbackClient(s3, None, fail=True)
    result = await remote_tools.remote_whois(bad, "https://login.evil.xyz", "evil.xyz")
    assert result == {"domain": "evil.xyz", "error": "lookup_failed"}


class FakeMcp:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.started, self.stopped, self.seen = result, error, 0, 0, []

    def start(self):
        self.started += 1
        return self

    def stop(self, *_a):
        self.stopped += 1

    async def call_tool_async(self, tool_use_id, name, arguments=None, read_timeout_seconds=None):
        self.seen.append((name, arguments, read_timeout_seconds.total_seconds()))
        if self.error:
            raise self.error
        return self.result


async def test_tools_client_prefixes_the_target_reuses_one_session_and_parses_json():
    mcp = FakeMcp({"content": [{"text": '{"a": 1}'}], "isError": False})
    client = ToolsClient("https://g.example/mcp", "us-west-2", client=mcp)
    assert await client.call_json("whois_lookup", {"url": "u"}, 10) == {"a": 1}
    assert await client.call_json("whois_lookup", {"url": "u"}, 10) == {"a": 1}
    assert mcp.seen[0] == ("tools___whois_lookup", {"url": "u"}, 10.0)
    await client.aclose()
    assert mcp.stopped == 1


@pytest.mark.parametrize(
    "result",
    [
        {"content": [{"text": "boom"}], "isError": True},
        {"content": [{"text": "not json"}], "isError": False},
        {"content": [{"text": "[1]"}], "isError": False},
    ],
)
async def test_tools_client_turns_bad_results_into_one_error_type(result):
    client = ToolsClient("https://g.example/mcp", "us-west-2", client=FakeMcp(result))
    with pytest.raises(ToolsGatewayError):
        await client.call_json("capture_page", {}, 5)


async def test_tools_client_wraps_transport_errors():
    client = ToolsClient("https://g.example/mcp", "us-west-2", client=FakeMcp(error=OSError("x")))
    with pytest.raises(ToolsGatewayError, match="OSError"):
        await client.call_json("capture_page", {}, 5)


def test_from_env_needs_https_and_is_off_without_the_variable():
    assert ToolsClient.from_env({"AWS_REGION": "us-west-2"}) is None
    with pytest.raises(ToolsGatewayError):
        ToolsClient.from_env({"TOOLS_GATEWAY_URL": "http://x", "AWS_REGION": "us-west-2"})
    c = ToolsClient.from_env(
        {
            "TOOLS_GATEWAY_URL": "https://g.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp",
            "AWS_REGION": "us-west-2",
        }
    )
    assert c is not None and c.region == "us-east-1" and c.target == "tools"


# precheck_url: navigate only, report the final status.
async def precheck(page, url="https://example.com/old", **kw):
    return json.loads(
        await tools_server.run_precheck_url(
            url, "scan-12345678", open_page_fn=open_page_fn(page), **kw
        )
    )


async def test_precheck_final_404_is_error_404():
    page = FakePage(status=404, final_url="https://example.com/gone")
    out = await precheck(page)
    assert out == {
        "outcome": "error_404",
        "final_status": 404,
        "final_url": "https://example.com/gone",
        "hops": ["https://example.com/gone"],
        "reason": "HTTP 404",
        "probe": "browser",
        "browser_refused": False,
    }
    # Navigate only: domcontentloaded, no settle wait, no screenshot, no page text.
    assert page.goto_kwargs[0]["wait_until"] == "domcontentloaded"
    assert page.goto_kwargs[0]["timeout"] <= 10_000
    assert page.load_states == [] and page.screenshot_kwargs == [] and page.cdp_calls == []


async def test_precheck_200_is_ok():
    out = await precheck(FakePage(status=200))
    assert out["outcome"] == "ok" and out["final_status"] == 200


@pytest.mark.parametrize("status", [403, 410, 500, 301])
async def test_precheck_other_statuses_are_not_error_404(status):
    out = await precheck(FakePage(status=status))
    assert out["outcome"] == "ok" and out["final_status"] == status


async def test_precheck_404_after_redirect_uses_the_final_response():
    page = FakePage(
        status=404, final_url="https://example.com/missing", redirect_chain=["https://a.com/"]
    )
    out = await precheck(page, "https://a.com/")
    assert out["outcome"] == "error_404" and out["final_url"] == "https://example.com/missing"
    assert out["hops"] == ["https://a.com/", "https://example.com/missing"]


async def test_precheck_redirect_to_internal_origin_is_blocked():
    page = FakePage(
        status=404, final_url="https://example.com/x", redirect_chain=["http://169.254.169.254/"]
    )
    out = await precheck(page, http_probe_fn=no_http_probe)
    assert out["outcome"] == "blocked" and out["final_status"] is None


@pytest.mark.parametrize(
    "url", ["http://169.254.169.254/latest", "http://localhost/", "file:///etc/passwd"]
)
async def test_precheck_refuses_internal_urls_without_a_browser(url):
    def no_browser(*_a, **_k):
        raise AssertionError("a browser session was started")

    out = json.loads(
        await tools_server.run_precheck_url(url, "scan-12345678", open_page_fn=no_browser)
    )
    assert out["outcome"] == "blocked"


async def no_http_probe(*_a, **_k):
    raise AssertionError("the HTTP probe ran")


def http_answer(outcome, status=None, reason=""):
    calls: list = []

    async def fn(url, *, total_s):
        calls.append((url, total_s))
        hops = [url]
        return {
            "outcome": outcome,
            "final_status": status,
            "final_url": url,
            "hops": hops,
            "reason": reason,
        }

    fn.calls = calls
    return fn


async def test_precheck_dead_dns_is_site_down_via_the_http_probe_without_a_browser():
    from phish_agents.common.browser import SiteUnreachable

    async def nxdomain(_url):
        raise SiteUnreachable("dns_nxdomain")

    def no_browser(*_a, **_k):
        raise AssertionError("a browser session was started")

    probe = http_answer("site_down", reason="The domain 'dead.example' does not resolve.")
    out = json.loads(
        await tools_server.run_precheck_url(
            "https://dead.example/",
            "scan-12345678",
            open_page_fn=no_browser,
            preflight_fn=nxdomain,
            http_probe_fn=probe,
        )
    )
    assert out["outcome"] == "site_down" and out["probe"] == "http"
    assert "does not resolve" in out["reason"] and out["browser_refused"] is False
    assert probe.calls[0][1] <= 8.0


async def test_precheck_connection_error_asks_the_http_probe():
    from playwright.async_api import Error as PlaywrightError

    page = FakePage(goto_error=PlaywrightError("net::ERR_CONNECTION_REFUSED at https://a.com/"))
    out = await precheck(page, http_probe_fn=http_answer("site_down", reason="could not connect"))
    assert out["outcome"] == "site_down" and out["probe"] == "http"


async def test_precheck_browser_refusal_with_a_live_site_is_ok_and_marked():
    from playwright.async_api import Error as PlaywrightError

    page = FakePage(goto_error=PlaywrightError("net::ERR_BLOCKED_BY_CLIENT at https://a.com/"))
    out = await precheck(page, http_probe_fn=http_answer("ok", 200, "HTTP 200"))
    assert out["outcome"] == "ok" and out["final_status"] == 200
    assert out["browser_refused"] is True and out["probe"] == "http"


async def test_precheck_browser_refusal_with_a_404_is_error_404():
    from playwright.async_api import Error as PlaywrightError

    page = FakePage(goto_error=PlaywrightError("net::ERR_BLOCKED_BY_CLIENT at https://a.com/"))
    out = await precheck(page, http_probe_fn=http_answer("error_404", 404, "HTTP 404"))
    assert out["outcome"] == "error_404" and out["browser_refused"] is True


@pytest.mark.parametrize(
    "code", ["ERR_CERT_COMMON_NAME_INVALID", "ERR_CERT_AUTHORITY_INVALID", "ERR_CERT_DATE_INVALID"]
)
async def test_precheck_certificate_error_is_unreachable_never_site_down(code):
    # The host answered, so the scan runs in full; a plain GET would meet the same certificate.
    from playwright.async_api import Error as PlaywrightError

    page = FakePage(goto_error=PlaywrightError(f"net::{code} at https://a.com/"))
    out = await precheck(page, http_probe_fn=no_http_probe)
    assert out["outcome"] == "unreachable" and out["probe"] == "browser"
    assert out["reason"] == f"tls_error: net::{code}"


async def test_precheck_browser_errors_other_than_the_three_skip_the_http_probe():
    from playwright.async_api import Error as PlaywrightError

    page = FakePage(goto_error=PlaywrightError("net::ERR_ABORTED at https://a.com/"))
    out = await precheck(page, http_probe_fn=no_http_probe)
    assert out["outcome"] == "unreachable" and out["probe"] == "browser"


async def test_precheck_hard_deadline_returns_unreachable(monkeypatch):
    # The browser used the whole cap, so no time is left for the HTTP probe.
    monkeypatch.setattr(tools_server, "PRECHECK_DEADLINE_S", 0.2)
    out = await precheck(FakePage(hang=frozenset({"goto"})), http_probe_fn=no_http_probe)
    assert out["outcome"] == "unreachable" and out["final_status"] is None


async def test_precheck_rejects_a_scan_id_that_could_escape_the_prefix():
    with pytest.raises(ValueError):
        await tools_server.run_precheck_url("https://a.com", "../etc")


async def test_code_analyst_raw_html_fallback_crosses_the_gateway(monkeypatch):
    from playwright.async_api import TimeoutError as PlaywrightTimeout
    from test_code_analyst import fake_probe

    from phish_agents.code_analyst import capture

    monkeypatch.setattr(capture, "http_probe", fake_probe())
    page = FakePage(goto_error=PlaywrightTimeout("Timeout 14000ms exceeded."))
    s3 = ReadableS3()
    factory = FakeAgentFactory([FakeResult(FindingDraft(verdict="phishing", confidence=70))])
    finding = await code_agent.analyze(
        "https://lure.example/games/1",
        "scan-12345678",
        s3=s3,
        agent_factory=factory,
        tools_factory=lambda: LoopbackClient(s3, page),
    )
    assert "raw HTML excerpt, not rendered, scripts not run" in factory.tool_outputs[0]
    assert "static_html_only" in {s.name for s in finding.signals}
    assert finding.page_observed is False and "raw HTML" in finding.capture_note
    assert finding.artifacts == ["scans/scan-12345678/capture.json"]
