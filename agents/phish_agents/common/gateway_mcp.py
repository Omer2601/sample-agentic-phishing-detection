# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A minimal MCP client for an IAM-authorized AgentCore Gateway: initialize, then tools/call.

Why not the Strands MCPClient: mcp 2.2.0 (as 2.1.1) negotiates protocol 2026-07-28, and the Gateway
rejects that initialize with HTTP 400 ("Missing required '_meta' for protocol version
2026-07-28"), so the session never starts and every lookup fails soft (seen in the v2.1
deploy). This client pins the protocol version the Gateway speaks and only does the three
JSON-RPC calls a lookup needs, over the same SigV4 httpx.Auth.
"""

from __future__ import annotations

import asyncio
import itertools
import json
from datetime import timedelta
from typing import Any

import httpx

from phish_agents.common.sigv4 import SigV4HttpxAuth

# The version the AgentCore Gateway answers with; pinned so a client library upgrade cannot
# silently move the handshake to a version the Gateway refuses.
PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "phish-brand-visual", "version": "2.1"}
_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
SESSION_HEADER = "mcp-session-id"


class GatewayMcpError(RuntimeError):
    pass


def _parse(response: httpx.Response, request_id: int) -> dict:
    """The JSON-RPC response for request_id, from a JSON body or a text/event-stream body."""
    if "text/event-stream" in response.headers.get("content-type", ""):
        messages = [
            json.loads(line[5:])
            for line in response.text.splitlines()
            if line.startswith("data:") and line[5:].strip()
        ]
    else:
        messages = [response.json()]
    for message in messages:
        if isinstance(message, dict) and message.get("id") == request_id:
            if "error" in message:
                error = message["error"] or {}
                raise GatewayMcpError(
                    f"gateway error {error.get('code')}: {str(error.get('message'))[:200]}"
                )
            return message.get("result") or {}
    raise GatewayMcpError("gateway response has no result for the request")


class GatewayMcpClient:
    """Same surface WebSearch uses from the Strands MCPClient: start, stop, call_tool_async."""

    def __init__(
        self,
        url: str,
        region: str,
        *,
        timeout_s: float = 6.0,
        auth: httpx.Auth | None = None,
        transport: httpx.BaseTransport | None = None,
        client_info: dict[str, str] | None = None,
    ) -> None:
        self.url = url
        self._client_info = client_info or CLIENT_INFO
        self._client = httpx.Client(
            auth=auth or SigV4HttpxAuth(region), timeout=timeout_s, transport=transport
        )
        self._ids = itertools.count(1)
        self._session: str | None = None

    def _post(self, payload: dict, timeout_s: float | None = None) -> httpx.Response:
        headers = dict(_HEADERS)
        if self._session:
            headers[SESSION_HEADER] = self._session
        response = self._client.post(
            self.url,
            json=payload,
            headers=headers,
            **({"timeout": timeout_s} if timeout_s else {}),
        )
        response.raise_for_status()
        return response

    def _call(self, method: str, params: dict, timeout_s: float | None = None) -> dict:
        request_id = next(self._ids)
        response = self._post(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}, timeout_s
        )
        if method == "initialize" and response.headers.get(SESSION_HEADER):
            self._session = response.headers[SESSION_HEADER]
        return _parse(response, request_id)

    def start(self) -> GatewayMcpClient:
        self._call(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": self._client_info,
            },
        )
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return self

    def stop(self, exc_type: Any = None, exc_val: Any = None, exc_tb: Any = None) -> None:
        self._client.close()

    def call_tool(
        self,
        tool_use_id: str,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
    ) -> dict:
        timeout_s = read_timeout_seconds.total_seconds() if read_timeout_seconds else None
        result = self._call("tools/call", {"name": name, "arguments": arguments or {}}, timeout_s)
        is_error = bool(result.get("isError"))
        payload = {
            "status": "error" if is_error else "success",
            "toolUseId": tool_use_id,
            "content": result.get("content") or [],
            "isError": is_error,
        }
        if isinstance(result.get("structuredContent"), dict):
            payload["structuredContent"] = result["structuredContent"]
        return payload

    async def call_tool_async(
        self,
        tool_use_id: str,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
    ) -> dict:
        return await asyncio.to_thread(
            self.call_tool, tool_use_id, name, arguments, read_timeout_seconds
        )
