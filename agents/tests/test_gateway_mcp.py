# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
from datetime import timedelta

import httpx
import pytest
from botocore.credentials import Credentials

from phish_agents.brand_visual import web_search
from phish_agents.brand_visual.web_search import WebSearch
from phish_agents.common.gateway_mcp import (
    PROTOCOL_VERSION,
    GatewayMcpClient,
    GatewayMcpError,
)
from phish_agents.common.sigv4 import SigV4HttpxAuth
from phish_agents.common.timing import CallRecorder

GATEWAY = "https://gw-1.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp"
RESULTS = {"id": "q1", "results": [{"url": "https://www.paypal.com/", "title": "PayPal"}]}


def creds() -> Credentials:
    return Credentials("testing", "testing", "session-token")


class FakeGateway:
    """Behaves like the AgentCore Gateway: refuses any protocol version but its own."""

    def __init__(self, sse: bool = False, session: str | None = None) -> None:
        self.sse, self.session = sse, session
        self.requests: list[tuple[dict, httpx.Headers]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append((body, request.headers))
        if "id" not in body:
            return httpx.Response(202)
        if body["method"] == "initialize":
            if body["params"]["protocolVersion"] != "2025-06-18":
                return httpx.Response(
                    400,
                    json={"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32602}},
                )
            headers = {"mcp-session-id": self.session} if self.session else {}
            return self._reply(body["id"], {"protocolVersion": "2025-06-18"}, headers)
        if body["method"] == "tools/call":
            if body["params"]["name"] == "broken":
                return self._error(body["id"])
            return self._reply(
                body["id"],
                {"isError": False, "content": [{"type": "text", "text": json.dumps(RESULTS)}]},
            )
        return self._error(body["id"])

    def _reply(self, request_id, result, headers=None) -> httpx.Response:
        message = {"jsonrpc": "2.0", "id": request_id, "result": result}
        if self.sse:
            return httpx.Response(
                200,
                text=f"event: message\ndata: {json.dumps(message)}\n\n",
                headers={"content-type": "text/event-stream", **(headers or {})},
            )
        return httpx.Response(200, json=message, headers=headers or {})

    def _error(self, request_id) -> httpx.Response:
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "no"}},
        )


def client(fake: FakeGateway) -> GatewayMcpClient:
    return GatewayMcpClient(
        GATEWAY,
        "us-east-1",
        auth=SigV4HttpxAuth("us-east-1", credentials_provider=creds),
        transport=httpx.MockTransport(fake),
    )


def test_handshake_pins_the_protocol_version_the_gateway_accepts():
    fake = FakeGateway()
    client(fake).start()
    (init, headers), (notified, _) = fake.requests
    assert init["method"] == "initialize"
    assert init["params"]["protocolVersion"] == PROTOCOL_VERSION == "2025-06-18"
    assert notified == {"jsonrpc": "2.0", "method": "notifications/initialized"}
    assert headers["authorization"].startswith("AWS4-HMAC-SHA256")
    assert "/us-east-1/bedrock-agentcore/aws4_request" in headers["authorization"]


@pytest.mark.parametrize("sse", [False, True])
async def test_tool_call_returns_the_result_shape_web_search_reads(sse):
    fake = FakeGateway(sse=sse)
    mcp = client(fake).start()
    payload = await mcp.call_tool_async(
        "t1", "web-search___WebSearch", {"query": "PayPal official website"}, timedelta(seconds=6)
    )
    assert payload["status"] == "success" and payload["toolUseId"] == "t1"
    assert web_search._results(payload) == RESULTS["results"]
    call, _ = fake.requests[-1]
    assert call["params"] == {
        "name": "web-search___WebSearch",
        "arguments": {"query": "PayPal official website"},
    }


def test_session_id_from_initialize_is_sent_on_later_requests():
    fake = FakeGateway(session="sess-1")
    client(fake).start().call_tool("t1", "web-search___WebSearch", {"query": "q"})
    assert "mcp-session-id" not in fake.requests[0][1]
    assert all(h["mcp-session-id"] == "sess-1" for _, h in fake.requests[1:])


def test_json_rpc_error_raises():
    mcp = client(FakeGateway()).start()
    with pytest.raises(GatewayMcpError, match="-32601"):
        mcp.call_tool("t1", "broken", {})


def test_http_error_raises():
    def refuse(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "denied"})

    mcp = GatewayMcpClient(
        GATEWAY,
        "us-east-1",
        auth=SigV4HttpxAuth("us-east-1", credentials_provider=creds),
        transport=httpx.MockTransport(refuse),
    )
    with pytest.raises(httpx.HTTPStatusError):
        mcp.start()


async def test_web_search_end_to_end_through_the_gateway_client():
    fake = FakeGateway(sse=True)
    recorder = CallRecorder()
    search = WebSearch(
        GATEWAY,
        "us-east-1",
        "https://paypa1-login.xyz/",
        recorder,
        client_factory=lambda url, region: client(fake),
    )
    text = await search.lookup("PayPal")
    await search.close()
    assert "paypal.com | PayPal" in text
    assert fake.requests[0][0]["params"]["protocolVersion"] == "2025-06-18"


def test_default_factory_uses_the_gateway_client():
    assert isinstance(web_search._mcp_client(GATEWAY, "us-east-1"), GatewayMcpClient)
