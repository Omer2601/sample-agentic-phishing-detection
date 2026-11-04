# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
import re
import time
from pathlib import Path

from agent_fakes import FakeS3

from phish_agents.common import server
from phish_agents.common.finding import error_finding
from phish_contracts.models import Usage

DOCKERFILE = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()


def container_host() -> str:
    """HOST as the image sets it, the address AgentCore Runtime connects to."""
    return re.search(r"\bHOST=(\S+)", DOCKERFILE).group(1)


USAGE = Usage(model_id="m")


async def good(url, scan_id, **_):
    return error_finding(
        "url_analyst", f"ok {url} {scan_id}", usage=USAGE, started=time.monotonic(), calls=[]
    )


async def boom(url, scan_id, **_):
    raise RuntimeError("secret internal detail")


async def test_safe_analyze_returns_finding_json():
    out = json.loads(
        await server.safe_analyze("url_analyst", good, "https://a.com", "scan-12345678")
    )
    assert out["agent"] == "url_analyst"


async def test_safe_analyze_hides_exception_detail():
    out = json.loads(
        await server.safe_analyze(
            "brand_visual", boom, "https://a.com", "scan-12345678", s3=FakeS3()
        )
    )
    assert out["status"] == "error" and "secret" not in out["signals"][0]["evidence"]
    assert "ref " in out["signals"][0]["evidence"]


async def test_safe_analyze_rejects_bad_scan_id():
    out = json.loads(
        await server.safe_analyze("code_analyst", good, "https://a.com", "../etc", s3=FakeS3())
    )
    assert out["status"] == "error"


async def test_server_lists_single_analyze_tool():
    mcp = server.build_server("url_analyst", good)
    tools = await mcp.list_tools()
    assert [t.name for t in tools] == ["analyze"]
    assert set(tools[0].input_schema["properties"]) == {"url", "scan_id"}


def test_http_contract_lists_analyze_on_mcp_path():
    from starlette.testclient import TestClient

    app = server.build_server("url_analyst", good).streamable_http_app(
        host=container_host(),  # mirrors serve() in the image; no socket is bound
        **server.HTTP_OPTIONS,
    )
    with TestClient(app) as client:
        response = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={"accept": "application/json, text/event-stream"},
        )
    assert response.status_code == 200
    assert [t["name"] for t in response.json()["result"]["tools"]] == ["analyze"]


class FailingS3:
    def put_object(self, **_kw):
        raise RuntimeError("s3 down")


async def boom_after_a_call(url, scan_id, *, recorder):
    from phish_contracts.models import CallKind

    with recorder.record(CallKind.BROWSER, "capture"):
        pass
    raise RuntimeError("secret internal detail")


async def test_error_finding_is_persisted_with_recorded_calls():
    s3 = FakeS3()
    out = json.loads(
        await server.safe_analyze(
            "code_analyst", boom_after_a_call, "https://a.com", "scan-12345678", s3=s3
        )
    )
    assert out["status"] == "error"
    assert [c["name"] for c in out["calls"]] == ["capture"]
    stored = json.loads(s3.objects["scans/scan-12345678/findings/code_analyst.json"]["Body"])
    assert stored["status"] == "error" and len(stored["calls"]) == 1


async def test_error_finding_returned_even_when_persist_fails():
    out = json.loads(
        await server.safe_analyze(
            "url_analyst", boom_after_a_call, "https://a.com", "scan-12345678", s3=FailingS3()
        )
    )
    assert out["status"] == "error"


async def test_analysis_past_the_deadline_becomes_persisted_timeout_finding(monkeypatch):
    import asyncio

    async def slow(url, scan_id, *, recorder):
        await asyncio.sleep(5)

    monkeypatch.setattr(server, "PAGE_DEADLINE_S", 0.05)
    s3 = FakeS3()
    out = json.loads(
        await server.safe_analyze("brand_visual", slow, "https://a.com", "scan-12345678", s3=s3)
    )
    assert out["status"] == "error"
    assert out["signals"][0]["evidence"].startswith("timeout")
    assert "scans/scan-12345678/findings/brand_visual.json" in s3.objects


def test_deadline_bounds_the_scan_tail():
    # One slow page holds the whole scan, so the deadline stays well under the old 40 s
    # but above navigation plus one model turn.
    from phish_agents.common import browser

    assert server.ANALYZE_DEADLINE_S == 30
    assert browser.NAV_TIMEOUT_MS / 1000 + browser.SETTLE_TIMEOUT_MS / 1000 < 20
    assert server.ANALYZE_DEADLINE_S >= browser.NAV_TIMEOUT_MS / 1000 + 10


def test_page_specialists_get_the_longer_deadline():
    assert server.deadline_s("code_analyst") == server.deadline_s("brand_visual") == 35
    assert server.PAGE_DEADLINE_S == 35
    assert server.deadline_s("url_analyst") == 30


async def test_code_analyst_timeout_uses_its_own_deadline(monkeypatch):
    import asyncio

    async def slow(url, scan_id, *, recorder):
        await asyncio.sleep(0.2)
        return None

    monkeypatch.setattr(server, "ANALYZE_DEADLINE_S", 0.05)
    monkeypatch.setattr(server, "PAGE_DEADLINE_S", 0.05)
    out = json.loads(
        await server.safe_analyze(
            "code_analyst", slow, "https://a.com", "scan-12345678", s3=FakeS3()
        )
    )
    assert out["status"] == "error" and out["signals"][0]["evidence"].startswith("timeout")


def test_bind_host_defaults_to_loopback(monkeypatch):
    monkeypatch.delenv("HOST", raising=False)
    assert server.bind_host() == "127.0.0.1"


def test_image_binds_all_interfaces_for_agentcore_runtime(monkeypatch):
    # AgentCore Runtime contract: 0.0.0.0:8000 inside the container.
    assert container_host().split(".") == ["0"] * 4
    monkeypatch.setenv("HOST", container_host())
    calls = {}
    mcp = server.build_server("url_analyst", good)
    monkeypatch.setattr(mcp, "run", lambda **kwargs: calls.update(kwargs))
    server.serve(mcp)
    assert (calls["host"], calls["port"]) == (container_host(), 8000)
    assert calls["transport"] == "streamable-http"


def test_every_mcp_server_is_stateless():
    """Stateless mode keeps no StreamableHTTP session store (CVE-2026-59951, fixed in the
    pinned mcp 2.2.0, was unbounded session accumulation there), so the servers stay stateless
    as a second line."""
    assert server.HTTP_OPTIONS["stateless_http"] is True
    pkg = Path(server.__file__).resolve().parents[1]
    runners = [p for p in pkg.rglob("*.py") if ".run(" in p.read_text()]
    assert runners == [Path(server.__file__).resolve()]
    for name in ("tools_server", "dispatcher"):
        assert "common_server.serve(" in (pkg / name / "server.py").read_text()
