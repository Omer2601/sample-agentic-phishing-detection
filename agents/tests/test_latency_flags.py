# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""-c latencyBudgets and -c codeTextBudget: the values each module picks with the flag on, and
that nothing changes with it off."""

import importlib.util

import pytest
from test_brand_visual import SHOT_KEY, FakePage, FakeS3, brand_capture
from test_runtime_tools_client import ARN, _ok, _Runtime

from phish_agents.brand_visual import capture as brand_capture_mod
from phish_agents.common import latency
from phish_agents.common.remote_tools import RuntimeToolsClient, ToolsGatewayError
from phish_contracts.models import tools_session_id

MODULES = (
    "phish_agents.code_analyst.capture",
    "phish_agents.brand_visual.capture",
    "phish_agents.common.server",
    "phish_agents.common.remote_tools",
    "phish_agents.dispatcher.server",
    "phish_agents.tools_server.server",
)


def fresh(name: str):
    """A new copy of the module, executed now (sys.modules keeps the original)."""
    spec = importlib.util.find_spec(name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def loaded(monkeypatch, *, tight=False, half=False) -> dict:
    monkeypatch.setattr(latency, "TIGHT_BUDGETS", tight)
    monkeypatch.setattr(latency, "HALF_CODE_TEXT", half)
    return {
        name.rsplit(".", 2)[-2] + "." + name.rsplit(".", 1)[-1]: fresh(name) for name in MODULES
    }


def test_off_keeps_the_earlier_values(monkeypatch):
    m = loaded(monkeypatch)
    code, brand = m["code_analyst.capture"], m["brand_visual.capture"]
    assert (code.CAPTURE_BUDGET_S, code.HTML_FALLBACK_S) == (20.0, 4.0)
    assert code.SETTLE_MS == code.browser.SETTLE_TIMEOUT_MS
    assert (code.PER_SCRIPT_LIMIT, code.TOTAL_SCRIPT_LIMIT, code.DOM_HTML_LIMIT) == (
        15_000,
        60_000,
        20_000,
    )
    assert brand._MIN_SCREENSHOT_MS == 500
    assert m["common.server"].PAGE_DEADLINE_S == 35
    tools = m["common.remote_tools"]
    assert (tools.CAPTURE_TIMEOUT_S, tools.CODE_CAPTURE_TIMEOUT_S) == (22.0, 25.0)
    assert m["dispatcher.server"].RUNTIME_READ_TIMEOUT_S == 45
    assert m["tools_server.server"].CODE_CAPTURE_DEADLINE_S == 22


def test_latency_budgets_values(monkeypatch):
    m = loaded(monkeypatch, tight=True)
    code, brand = m["code_analyst.capture"], m["brand_visual.capture"]
    assert (code.CAPTURE_BUDGET_S, code.HTML_FALLBACK_S, code.SETTLE_MS) == (18.0, 3.0, 1_500)
    assert (brand._MIN_SCREENSHOT_MS, brand.SCREENSHOT_MAX_MS) == (1_500, 5_000)
    tools = m["common.remote_tools"]
    assert (tools.CAPTURE_TIMEOUT_S, tools.CODE_CAPTURE_TIMEOUT_S) == (28.0, 30.0)
    assert m["tools_server.server"].CODE_CAPTURE_DEADLINE_S == 20
    page_deadline = m["common.server"].PAGE_DEADLINE_S
    assert page_deadline == 42
    # The client's longest wait still leaves a model turn inside the page deadline, and the
    # dispatcher's read timeout stays 10 s clear of that deadline.
    assert page_deadline - tools.CODE_CAPTURE_TIMEOUT_S >= 10
    assert m["dispatcher.server"].RUNTIME_READ_TIMEOUT_S - page_deadline == 10
    # The server backstop stays above the capture's own budget and below the client wait.
    assert code.CAPTURE_BUDGET_S < 20 < tools.CODE_CAPTURE_TIMEOUT_S


def test_code_text_budget_half(monkeypatch):
    code = loaded(monkeypatch, half=True)["code_analyst.capture"]
    assert (code.PER_SCRIPT_LIMIT, code.TOTAL_SCRIPT_LIMIT, code.DOM_HTML_LIMIT) == (
        10_000,
        30_000,
        12_000,
    )
    # The budgets are a separate flag.
    assert code.CAPTURE_BUDGET_S == 20.0


class _FlakyRuntime(_Runtime):
    """Fails the first call at once (a refused connection), then answers."""

    def invoke_agent_runtime(self, **kwargs):
        if not self.requests:
            self.requests.append(kwargs)
            raise ConnectionError("refused")
        return super().invoke_agent_runtime(**kwargs)


@pytest.mark.parametrize("tight", [False, True])
async def test_a_fast_failure_is_retried_once_only_with_latency_budgets(monkeypatch, tight):
    monkeypatch.setattr(latency, "TIGHT_BUDGETS", tight)
    runtime = _FlakyRuntime(_ok({"ok": True}))
    client = RuntimeToolsClient(ARN, "us-east-1", client_factory=lambda t: runtime)
    if tight:
        assert await client.call_json("capture_page", {"url": "u"}, 22.0) == {"ok": True}
        assert len(runtime.requests) == 2
    else:
        with pytest.raises(ToolsGatewayError):
            await client.call_json("capture_page", {"url": "u"}, 22.0)
        assert len(runtime.requests) == 1


async def test_a_scan_bound_client_reuses_the_scans_one_session():
    runtime = _Runtime(_ok({"ok": True}))
    client = RuntimeToolsClient(
        ARN, "us-east-1", client_factory=lambda t: runtime, session_per_scan=True
    )
    client.bind_scan("scan-1234abcd")
    await client.call_json("capture_page", {"url": "u", "scan_id": "scan-1234abcd"}, 22.0)
    await client.call_json("whois_lookup", {"url": "u"}, 10.0)
    assert {r["runtimeSessionId"] for r in runtime.requests} == {tools_session_id("scan-1234abcd")}


async def test_binding_is_a_no_op_without_session_per_scan():
    runtime = _Runtime(_ok({"ok": True}))
    client = RuntimeToolsClient(ARN, "us-east-1", client_factory=lambda t: runtime)
    client.bind_scan("scan-1234abcd")
    await client.call_json("whois_lookup", {"url": "u"}, 10.0)
    await client.call_json("whois_lookup", {"url": "u"}, 10.0)
    assert len({r["runtimeSessionId"] for r in runtime.requests}) == 2


def test_session_per_scan_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("TOOLS_RUNTIME_ARN", ARN)
    monkeypatch.setenv("TOOLS_SESSION_PER_SCAN", "1")
    assert RuntimeToolsClient.from_env().session_per_scan is True
    monkeypatch.setenv("TOOLS_SESSION_PER_SCAN", "0")
    assert RuntimeToolsClient.from_env().session_per_scan is False


@pytest.mark.parametrize("scan_id", ["abcd1234", "a" * 64, "0b6f6c1e-3f1a-4c2e-9d55-1a2b3c4d5e6f"])
def test_tools_session_id_is_a_valid_runtime_session_id(scan_id):
    import re

    sid = tools_session_id(scan_id)
    assert 33 <= len(sid) <= 256 and re.fullmatch(r"[A-Za-z0-9-]+", sid)
    assert sid == tools_session_id(scan_id) and scan_id in sid


async def _failing_shot(page, timeout_ms):
    from playwright.async_api import TimeoutError as PlaywrightTimeout

    raise PlaywrightTimeout("screenshot timed out")


async def test_a_failed_screenshot_keeps_the_loaded_page_with_latency_budgets(monkeypatch):
    monkeypatch.setattr(latency, "TIGHT_BUDGETS", True)
    monkeypatch.setattr(brand_capture_mod, "viewport_png", _failing_shot)
    s3 = FakeS3()
    cap = brand_capture(FakePage(), s3)
    data = await cap.capture()
    assert data["screenshot_failed"] is True and "error" not in data
    assert cap.png is None and SHOT_KEY not in s3.objects
    assert "appearance is unknown, not benign" in str(cap.tool_result(sanitize=False))


async def test_a_failed_screenshot_still_fails_the_capture_without_the_flag(monkeypatch):
    monkeypatch.setattr(latency, "TIGHT_BUDGETS", False)
    monkeypatch.setattr(brand_capture_mod, "viewport_png", _failing_shot)
    data = await brand_capture(FakePage()).capture()
    assert data.get("error") == "capture_failed" and "screenshot_failed" not in data
