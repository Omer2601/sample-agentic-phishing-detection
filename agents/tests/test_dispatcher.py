# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The dispatcher runs the three specialist Runtimes at once and always returns three Findings."""

import io
import json
import threading
import time

import pytest
from agent_fakes import FakeS3

from phish_agents.dispatcher import server as dispatcher
from phish_contracts.models import SPECIALISTS, Finding

SCAN = "scan-12345678"


def ok_finding(agent: str) -> Finding:
    return Finding.model_validate(
        {
            "agent": agent,
            "status": "ok",
            "verdict": "phishing",
            "confidence": 80,
            "signals": [],
            "artifacts": [],
            "usage": {"input_tokens": 1, "output_tokens": 1, "model_id": "m"},
            "latency_ms": 1,
            "calls": [],
        }
    )


@pytest.fixture(autouse=True)
def runtime_arns(monkeypatch):
    for name in SPECIALISTS:
        monkeypatch.setenv(
            f"{name.upper()}_RUNTIME_ARN", f"arn:aws:bedrock-agentcore:us-west-2:1:runtime/{name}"
        )


class Recorder:
    """A call_fn that records start times and applies per-agent behaviour."""

    def __init__(self, behaviours=None, delay=0.2):
        self.behaviours, self.delay = behaviours or {}, delay
        self.starts, self.lock = {}, threading.Lock()
        self.release = threading.Event()

    def __call__(self, _client, arn, url, scan_id):
        agent = arn.rsplit("/", 1)[-1]
        with self.lock:
            self.starts[agent] = time.monotonic()
        behaviour = self.behaviours.get(agent)
        if behaviour == "raise":
            raise RuntimeError("runtime down")
        if behaviour == "hang":
            self.release.wait(5)
            raise RuntimeError("released")
        time.sleep(self.delay)
        assert (url, scan_id) == ("https://a.com", SCAN)
        return ok_finding(agent)


async def run(call_fn, s3=None, **kwargs):
    s3 = s3 or FakeS3()
    out = await dispatcher.run_analyze_all(
        "https://a.com",
        SCAN,
        client_factory=lambda: object(),
        s3_factory=lambda: s3,
        call_fn=call_fn,
        **kwargs,
    )
    return json.loads(out), s3


async def test_all_ok_runs_concurrently_in_stable_order():
    call = Recorder()
    t0 = time.monotonic()
    out, s3 = await run(call)
    assert time.monotonic() - t0 < 0.5  # three 0.2 s calls, not 0.6 s
    assert [f["agent"] for f in out["findings"]] == list(SPECIALISTS)
    assert all(f["status"] == "ok" for f in out["findings"])
    assert max(call.starts.values()) - min(call.starts.values()) < 0.15
    assert s3.objects == {}  # the specialists write their own Findings, not the dispatcher


async def test_one_specialist_times_out_becomes_error_finding():
    # The healthy calls finish far inside the deadline: a 0.2 s call against 0.3 s timed out
    # on a loaded machine and turned a healthy specialist into an error.
    call = Recorder({"brand_visual": "hang"}, delay=0.01)
    out, s3 = await run(call, deadline_s=0.3)
    call.release.set()
    by_agent = {f["agent"]: f for f in out["findings"]}
    assert [f["agent"] for f in out["findings"]] == list(SPECIALISTS)
    assert by_agent["brand_visual"]["status"] == "error"
    assert by_agent["brand_visual"]["signals"][0]["name"] == "analysis_error"
    assert by_agent["url_analyst"]["status"] == by_agent["code_analyst"]["status"] == "ok"
    (kwargs,) = s3.objects.values()
    assert kwargs.get("IfNoneMatch") == "*"


async def test_one_specialist_raises_error_finding_written_if_absent():
    s3 = FakeS3()
    out, _ = await run(Recorder({"code_analyst": "raise"}), s3=s3)
    code = next(f for f in out["findings"] if f["agent"] == "code_analyst")
    assert code["status"] == "error" and "RuntimeError" in code["signals"][0]["evidence"]
    assert "runtime down" not in json.dumps(code)
    (kwargs,) = s3.objects.values()
    assert kwargs.get("IfNoneMatch") == "*"


async def test_ordering_is_stable_when_the_first_specialist_is_slowest():
    class Slow(Recorder):
        def __call__(self, client, arn, url, scan_id):
            if arn.endswith("url_analyst"):
                time.sleep(0.3)
            return super().__call__(client, arn, url, scan_id)

    out, _ = await run(Slow(delay=0.0))
    assert [f["agent"] for f in out["findings"]] == list(SPECIALISTS)


async def test_all_fail_still_three_findings():
    out, _ = await run(Recorder({n: "raise" for n in SPECIALISTS}))
    assert [f["status"] for f in out["findings"]] == ["error"] * 3


async def test_bad_scan_id_returns_three_error_findings_without_calls():
    call = Recorder()
    out = json.loads(
        await dispatcher.run_analyze_all(
            "https://a.com", "../x", client_factory=lambda: object(), call_fn=call
        )
    )
    assert [f["status"] for f in out["findings"]] == ["error"] * 3
    assert call.starts == {}


async def test_missing_runtime_arn_env_is_an_error_finding(monkeypatch):
    monkeypatch.delenv("URL_ANALYST_RUNTIME_ARN")
    out, _ = await run(Recorder())
    assert out["findings"][0]["status"] == "error"
    assert [f["status"] for f in out["findings"][1:]] == ["ok", "ok"]


async def test_client_creation_failure_never_raises():
    def boom():
        raise KeyError("AWS_REGION")

    out = json.loads(await dispatcher.run_analyze_all("https://a.com", SCAN, client_factory=boom))
    assert [f["status"] for f in out["findings"]] == ["error"] * 3


async def test_s3_failure_does_not_replace_the_error_finding():
    def no_s3():
        raise RuntimeError("no s3")

    out = json.loads(
        await dispatcher.run_analyze_all(
            "https://a.com",
            SCAN,
            client_factory=lambda: object(),
            s3_factory=no_s3,
            call_fn=Recorder({"url_analyst": "raise"}),
        )
    )
    assert out["findings"][0]["status"] == "error"


def test_calls_the_specialist_analyze_tool_with_one_tools_call_request(monkeypatch):
    seen = {}

    class Client:
        def invoke_agent_runtime(self, **kw):
            seen.update(kw)
            body = {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [
                        {"type": "text", "text": ok_finding("url_analyst").model_dump_json()}
                    ]
                },
            }
            return {"response": io.BytesIO(json.dumps(body).encode())}

    finding = dispatcher.call_specialist(Client(), "arn", "https://a.com", SCAN)
    assert finding.agent == "url_analyst"
    req = json.loads(seen["payload"])
    assert req["params"] == {
        "name": "analyze",
        "arguments": {"url": "https://a.com", "scan_id": SCAN},
    }


def test_server_exposes_analyze_all_with_url_and_scan_id():
    import asyncio

    mcp = dispatcher.build_server()
    tools = asyncio.run(mcp.list_tools())
    (tool,) = tools
    assert tool.name == "analyze_all"
    assert set(tool.input_schema["properties"]) == {"url", "scan_id"}


def test_read_timeout_is_under_the_deadline_backstop():
    assert dispatcher.DISPATCH_DEADLINE_S > dispatcher.RUNTIME_READ_TIMEOUT_S


def test_runtime_client_never_retries_a_non_idempotent_invoke(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    cfg = dispatcher._runtime_client().meta.config
    assert cfg.retries["total_max_attempts"] == 1
    assert cfg.read_timeout == dispatcher.RUNTIME_READ_TIMEOUT_S


def test_runtime_read_timeout_outlasts_the_specialist_deadline():
    # The specialist must answer (even with an error Finding) before the dispatcher gives up.
    from phish_agents.common import server

    for agent in ("url_analyst", "brand_visual", "code_analyst"):
        assert dispatcher.RUNTIME_READ_TIMEOUT_S >= server.deadline_s(agent) + 10


async def test_the_three_calls_overlap():
    # Each fake specialist blocks until all three are inside their calls at the same time, so
    # this passes only if the dispatcher runs them concurrently (a serial run breaks the barrier).
    barrier = threading.Barrier(len(SPECIALISTS), timeout=2)

    def call(_client, arn, _url, _scan_id):
        barrier.wait()
        return ok_finding(arn.rsplit("/", 1)[-1])

    out, _ = await run(call)
    assert [f["status"] for f in out["findings"]] == ["ok"] * 3


async def test_status_latency_and_usage_pass_through_unchanged():
    def call(_client, arn, _url, _scan_id):
        agent = arn.rsplit("/", 1)[-1]
        finding = ok_finding(agent)
        return finding.model_copy(
            update={
                "latency_ms": 1234,
                "usage": finding.usage.model_copy(update={"input_tokens": 42, "output_tokens": 7}),
            }
        )

    out, _ = await run(call)
    for f in out["findings"]:
        assert f["latency_ms"] == 1234
        assert (f["usage"]["input_tokens"], f["usage"]["output_tokens"]) == (42, 7)
        assert Finding.model_validate(f).status == "ok"
