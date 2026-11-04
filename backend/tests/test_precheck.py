# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The tools-runtime precheck client, against stubbed boto3 clients."""

import io
import json
import time

import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from phish_backend.common import precheck

ARN = "arn:aws:bedrock-agentcore:us-west-2:123456789012:runtime/tools"


class StubRuntime:
    def __init__(self, body=None, error=None, delay=0.0, raw=None):
        self.body, self.error, self.delay, self.raw = body, error, delay, raw
        self.calls = []

    def invoke_agent_runtime(self, **kwargs):
        self.calls.append(kwargs)
        if self.delay:
            time.sleep(self.delay)
        if self.error:
            raise self.error
        raw = self.raw if self.raw is not None else json.dumps(self.body).encode()
        return {"response": io.BytesIO(raw)}


def rpc(payload, **result_over):
    result = {"content": [{"type": "text", "text": json.dumps(payload)}], **result_over}
    return {"jsonrpc": "2.0", "id": 1, "result": result}


def test_request_is_one_stateless_tools_call():
    stub = StubRuntime(rpc({"outcome": "error_404", "final_status": 404, "final_url": "u"}))
    result = precheck.precheck_url(stub, ARN, "https://a.example/", "scan-1")
    assert result.is_404 and result.final_status == 404 and result.final_url == "u"
    (call,) = stub.calls
    sent = json.loads(call["payload"])
    assert sent["method"] == "tools/call"
    assert sent["params"] == {
        "name": "precheck_url",
        "arguments": {"url": "https://a.example/", "scan_id": "scan-1"},
    }
    assert call["agentRuntimeArn"] == ARN and len(call["runtimeSessionId"]) >= 33
    assert "text/event-stream" in call["accept"]


@pytest.mark.parametrize("outcome", ["ok", "unreachable", "blocked"])
def test_other_outcomes_are_not_404(outcome):
    stub = StubRuntime(rpc({"outcome": outcome, "final_status": None, "final_url": ""}))
    result = precheck.precheck_url(stub, ARN, "https://a.example/", "s")
    assert not result.is_404 and result.final_status is None


def test_structured_content_and_sse_bodies_are_accepted():
    payload = {"outcome": "error_404", "final_status": 404, "final_url": "u"}
    wrapped = StubRuntime({"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": payload}})
    assert precheck.precheck_url(wrapped, ARN, "https://a/", "s").is_404
    sse = "event: message\ndata: " + json.dumps(rpc(payload)) + "\n\n"
    assert precheck.precheck_url(StubRuntime(raw=sse.encode()), ARN, "https://a/", "s").is_404


@pytest.mark.parametrize(
    "stub",
    [
        StubRuntime(raw=b"not json"),
        StubRuntime({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "x"}}),
        StubRuntime(rpc({"outcome": "ok"}, isError=True)),
        StubRuntime(rpc({"outcome": "weird"})),
        StubRuntime({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}),
        StubRuntime(error=ClientError({"Error": {"Code": "AccessDeniedException"}}, "Invoke")),
        StubRuntime(error=ReadTimeoutError(endpoint_url="https://x")),
    ],
)
def test_every_failure_is_a_precheck_error(stub):
    with pytest.raises(precheck.PrecheckError):
        precheck.precheck_url(stub, ARN, "https://a/", "s")


def test_hard_timeout_does_not_wait_for_the_call():
    stub = StubRuntime(rpc({"outcome": "ok"}), delay=1.0)
    started = time.monotonic()
    with pytest.raises(precheck.PrecheckError, match="exceeded"):
        precheck.precheck_url(stub, ARN, "https://a/", "s", timeout_s=0.1)
    assert time.monotonic() - started < 0.8


def test_structured_content_result_is_a_json_string_as_the_live_runtime_returns_it():
    """Shape captured from the deployed tools runtime on 2026-10-05."""
    payload = {"outcome": "error_404", "final_status": 404, "final_url": "https://example.com/x"}
    live = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [{"type": "text", "text": json.dumps(payload)}],
            "isError": False,
            "structuredContent": {"result": json.dumps(payload)},
        },
    }
    assert precheck._tool_payload(live) == payload


def test_old_payload_parses_with_v3_defaults():
    stub = StubRuntime(rpc({"outcome": "ok", "final_status": 200, "final_url": "u"}))
    result = precheck.precheck_url(stub, ARN, "https://a/", "s")
    assert result.hops == () and result.reason == "" and result.probe == "browser"
    assert result.browser_refused is False and not result.is_site_down


def test_site_down_payload_carries_hops_and_reason():
    payload = {
        "outcome": "site_down",
        "final_status": None,
        "final_url": "https://dead.example/",
        "hops": ["https://a.example/", "https://dead.example/"],
        "reason": "DNS lookup failed for dead.example",
        "probe": "http",
        "browser_refused": True,
    }
    result = precheck.precheck_url(StubRuntime(rpc(payload)), ARN, "https://a.example/", "s")
    assert result.is_site_down and not result.is_404
    assert result.hops == ("https://a.example/", "https://dead.example/")
    assert result.reason == "DNS lookup failed for dead.example"
    assert result.probe == "http" and result.browser_refused is True


def test_v3_fields_are_bounded_and_type_checked():
    payload = {
        "outcome": "site_down",
        "hops": ["h" * 5000, 7, None, *[f"https://h{i}/" for i in range(30)]],
        "reason": "r" * 2000,
        "probe": "carrier-pigeon",
        "browser_refused": "yes",
    }
    result = precheck.precheck_url(StubRuntime(rpc(payload)), ARN, "https://a/", "s")
    assert len(result.hops) == precheck.HOPS_MAX
    assert len(result.hops[0]) == 2048 and all(isinstance(h, str) for h in result.hops)
    assert len(result.reason) == 300
    assert result.probe == "browser" and result.browser_refused is False


def test_hops_that_are_not_a_list_are_ignored():
    payload = {"outcome": "site_down", "hops": "https://a/"}
    assert precheck.precheck_url(StubRuntime(rpc(payload)), ARN, "https://a/", "s").hops == ()


def test_a_shared_session_id_is_used_as_given():
    from phish_contracts.models import tools_session_id

    stub = StubRuntime(rpc({"outcome": "ok", "final_status": 200, "final_url": "u"}))
    sid = tools_session_id("scan-1234abcd")
    precheck.precheck_url(stub, ARN, "https://a.example/", "scan-1234abcd", session_id=sid)
    precheck.precheck_url(stub, ARN, "https://a.example/", "scan-1234abcd")
    assert stub.calls[0]["runtimeSessionId"] == sid
    assert stub.calls[1]["runtimeSessionId"] != sid
