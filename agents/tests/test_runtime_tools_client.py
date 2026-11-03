# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import io
import json
import time

import pytest

from phish_agents.common.remote_tools import (
    RuntimeToolsClient,
    ToolsClient,
    ToolsGatewayError,
    remote_whois,
    tools_client_from_env,
)

ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/phish_tools_server-abc"


class _Runtime:
    """An in-process bedrock-agentcore client: records each request, answers with raw bytes."""

    def __init__(self, raw: bytes | str, delay_s: float = 0.0) -> None:
        self.raw, self.delay_s, self.requests = raw, delay_s, []

    def invoke_agent_runtime(self, **kwargs):
        self.requests.append(kwargs)
        time.sleep(self.delay_s)
        return {
            "response": io.BytesIO(self.raw if isinstance(self.raw, bytes) else self.raw.encode())
        }


def _client(runtime: _Runtime) -> tuple[RuntimeToolsClient, list[int]]:
    timeouts: list[int] = []

    def factory(read_timeout_s: int):
        timeouts.append(read_timeout_s)
        return runtime

    return RuntimeToolsClient(ARN, "us-east-1", client_factory=factory), timeouts


def _ok(payload: dict) -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": json.dumps(payload)}]},
        }
    )


async def test_call_json_sends_one_tools_call_on_a_fresh_session():
    runtime = _Runtime(_ok({"domain": "example.com", "age_days": 9000}))
    client, timeouts = _client(runtime)
    first = await client.call_json("whois_lookup", {"url": "https://example.com/"}, 10.0)
    await client.call_json("whois_lookup", {"url": "https://example.com/"}, 10.0)
    assert first == {"domain": "example.com", "age_days": 9000}
    assert timeouts == [10]  # one boto client per read timeout, reused
    a, b = runtime.requests
    assert a["agentRuntimeArn"] == ARN
    assert a["runtimeSessionId"] != b["runtimeSessionId"]
    assert len(a["runtimeSessionId"]) >= 33
    body = json.loads(a["payload"])
    assert body["method"] == "tools/call"
    assert body["params"] == {"name": "whois_lookup", "arguments": {"url": "https://example.com/"}}


async def test_call_json_reads_a_single_sse_message():
    runtime = _Runtime("event: message\ndata: " + _ok({"ok": True}) + "\n\n")
    client, _ = _client(runtime)
    assert await client.call_json("capture_page", {"url": "u", "scan_id": "s"}, 22.0) == {
        "ok": True
    }


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x"}}),
        json.dumps(
            {"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": [{"text": "boom"}]}}
        ),
        json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"text": "[1, 2]"}]}}),
    ],
)
async def test_call_json_turns_every_bad_answer_into_one_error_type(raw):
    client, _ = _client(_Runtime(raw))
    with pytest.raises(ToolsGatewayError):
        await client.call_json("whois_lookup", {"url": "u"}, 5.0)


async def test_call_json_has_a_hard_deadline_above_the_read_timeout():
    client, _ = _client(_Runtime(_ok({}), delay_s=3.5))
    started = time.monotonic()
    with pytest.raises(ToolsGatewayError, match="TimeoutError"):
        await client.call_json("whois_lookup", {"url": "u"}, 1.0)
    assert time.monotonic() - started < 3.4


async def test_remote_whois_reads_a_runtime_failure_as_a_failed_lookup():
    client, _ = _client(_Runtime("garbage"))
    assert await remote_whois(client, "https://a.example/", "a.example") == {
        "domain": "a.example",
        "error": "lookup_failed",
    }


def test_runtime_arn_wins_over_the_gateway(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv(
        "TOOLS_GATEWAY_URL", "https://g.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp"
    )
    monkeypatch.setenv("TOOLS_RUNTIME_ARN", ARN)
    assert isinstance(tools_client_from_env(), RuntimeToolsClient)
    monkeypatch.delenv("TOOLS_RUNTIME_ARN")
    assert isinstance(tools_client_from_env(), ToolsClient)
    monkeypatch.delenv("TOOLS_GATEWAY_URL")
    assert tools_client_from_env() is None


def test_a_malformed_runtime_arn_is_refused(monkeypatch):
    monkeypatch.setenv("TOOLS_RUNTIME_ARN", "https://not-an-arn")
    with pytest.raises(ToolsGatewayError):
        RuntimeToolsClient.from_env()
