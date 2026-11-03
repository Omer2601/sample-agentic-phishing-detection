# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Call the shared tools MCP server (capture_page, capture_page_code, whois_lookup) through its
AgentCore Gateway, from a specialist that no longer runs those tools in process.

The stack sets TOOLS_GATEWAY_URL on every specialist. Without it (local runs and tests) the
specialists keep their in-process tools.

The capture classes keep their own logic. The tools server runs them and returns their state as
a payload (capture_payload); the specialist rebuilds a capture object from it (apply_payload),
so prompts, retries, signals and Finding assembly behave exactly as they did in process.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from collections.abc import Mapping
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from botocore.exceptions import BotoCoreError, ClientError, ReadTimeoutError

from phish_agents.brand_visual.capture import BrandCapture
from phish_agents.code_analyst.capture import CodeCapture
from phish_agents.common import latency
from phish_agents.common.browser import BROWSER_ERROR, CaptureFailure
from phish_agents.common.gateway_mcp import GatewayMcpClient
from phish_agents.common.timing import CallRecorder
from phish_contracts.models import CallKind, Signal, tools_session_id

logger = logging.getLogger(__name__)

# The Gateway names a target's tools {target}___{tool} (the infra target is named "tools").
DEFAULT_TARGET = "tools"
# A capture is 14 s for brand_visual and 20 s for code_analyst (22 s server backstop);
# these are the client read timeouts, a little above each. code_analyst's 35 s deadline
# must still hold a model turn on each side of the call.
# -c latencyBudgets=true: 28 s and 30 s, the server budget plus the tools Runtime's start lag
# (the source fork saw 42% of capture calls wait 9 to 12 s before the capture began); the page
# deadline is then 42 s, so a model turn still fits after the wait.
CAPTURE_TIMEOUT_S = 28.0 if latency.TIGHT_BUDGETS else 22.0
CODE_CAPTURE_TIMEOUT_S = 30.0 if latency.TIGHT_BUDGETS else 25.0
# -c latencyBudgets=true, direct tools Runtime calls only: one retry, only for a call that
# failed fast (throttling, a refused connection). A slow failure may still be capturing
# server-side, and a second call would start a second browser session for the same page.
RETRY_FAST_FAILURE_S = 5.0
RETRY_MIN_LEFT_S = 8.0
WHOIS_TIMEOUT_S = 10.0
CONNECT_TIMEOUT_S = 5.0
_SCREENSHOT_KEY = re.compile(r"^scans/[A-Za-z0-9-]{8,64}/screenshot\.png$")
_CLIENT_INFO = {"name": "phish-specialist", "version": "2.2"}
_REGION_IN_HOST = re.compile(r"\.bedrock-agentcore\.([a-z0-9-]+)\.")


class ToolsGatewayError(RuntimeError):
    """The tools Gateway or the tool itself failed; the message is safe to log."""


class ToolsClient:
    """One MCP session to the tools Gateway, reused for the specialist's calls."""

    def __init__(self, url: str, region: str, *, target: str = DEFAULT_TARGET, client=None) -> None:
        self.url, self.region, self.target = url, region, target
        self._client = client
        self._lock = asyncio.Lock()

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> ToolsClient | None:
        url = (env.get("TOOLS_GATEWAY_URL") or "").strip()
        if not url:
            return None
        if not url.startswith("https://"):
            raise ToolsGatewayError("TOOLS_GATEWAY_URL must be an https URL")
        match = _REGION_IN_HOST.search(urlsplit(url).netloc)
        region = env.get("TOOLS_GATEWAY_REGION") or (match.group(1) if match else env["AWS_REGION"])
        return cls(url, region, target=env.get("TOOLS_TARGET") or DEFAULT_TARGET)

    def _start(self) -> GatewayMcpClient:
        # mcp 2.2.0 negotiates a protocol the Gateway refuses; GatewayMcpClient pins 2025-06-18.
        client = self._client or GatewayMcpClient(
            self.url, self.region, timeout_s=CONNECT_TIMEOUT_S, client_info=_CLIENT_INFO
        )
        client.start()
        return client

    async def call_json(self, tool: str, arguments: dict[str, Any], timeout_s: float) -> dict:
        try:
            async with self._lock:
                if self._client is None:
                    self._client = await asyncio.to_thread(self._start)
            result = await self._client.call_tool_async(
                f"tools-{tool}",
                f"{self.target}___{tool}",
                arguments,
                read_timeout_seconds=timedelta(seconds=timeout_s),
            )
        except Exception as exc:  # noqa: BLE001 - every transport failure becomes one error type
            raise ToolsGatewayError(f"{tool}: {type(exc).__name__}") from exc
        text = next((c.get("text", "") for c in result.get("content") or [] if "text" in c), "")
        if result.get("isError"):
            raise ToolsGatewayError(f"{tool}: tool error: {text[:160]}")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ToolsGatewayError(f"{tool}: response is not JSON") from exc
        if not isinstance(payload, dict):
            raise ToolsGatewayError(f"{tool}: response is not an object")
        return payload

    async def aclose(self) -> None:
        if self._client is not None:
            await asyncio.to_thread(self._client.stop)
            self._client = None


def _jsonrpc_result(raw: str, tool: str) -> dict:
    """The JSON-RPC `result` of a plain JSON or single-message SSE response."""
    text = raw.strip()
    if text.startswith(("event:", "data:")):
        data = [ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:")]
        text = data[-1] if data else ""
    try:
        body = json.loads(text)
    except ValueError as exc:
        raise ToolsGatewayError(f"{tool}: runtime response is not JSON") from exc
    if not isinstance(body, dict) or "error" in body:
        raise ToolsGatewayError(f"{tool}: JSON-RPC error")
    result = body.get("result")
    if not isinstance(result, dict):
        raise ToolsGatewayError(f"{tool}: JSON-RPC response has no result")
    return result


class RuntimeToolsClient:
    """The tools Runtime called directly with InvokeAgentRuntime, not through its Gateway.

    Same call_json contract as ToolsClient. The tools server is a stateless MCP server
    (json_response=True), so one tools/call message on a fresh runtime session is a complete
    exchange, as for the worker's precheck_url. Measured 2026-10-31: 0.8-1.7 s per whois_lookup
    this way against 10 s Gateway read timeouts under eval load. One attempt per call (one more
    for a fast failure with -c latencyBudgets=true, see call_json): a retry
    would start a second browser session for the same capture.
    """

    def __init__(
        self,
        runtime_arn: str,
        region: str,
        *,
        client_factory=None,
        session_per_scan: bool = False,
    ) -> None:
        self.runtime_arn, self.region = runtime_arn, region
        self._client_factory = client_factory or self._boto_client
        self._clients: dict[int, Any] = {}
        self.session_per_scan = session_per_scan
        self._session_id: str | None = None

    def bind_scan(self, scan_id: str) -> None:
        """With session_per_scan, every call of this client uses the scan's tools session."""
        if self.session_per_scan:
            self._session_id = tools_session_id(scan_id)

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> RuntimeToolsClient | None:
        arn = (env.get("TOOLS_RUNTIME_ARN") or "").strip()
        if not arn:
            return None
        if not arn.startswith("arn:") or ":runtime/" not in arn:
            raise ToolsGatewayError("TOOLS_RUNTIME_ARN must be an AgentCore Runtime ARN")
        return cls(
            arn,
            env.get("AWS_REGION") or arn.split(":")[3],
            session_per_scan=(env.get("TOOLS_SESSION_PER_SCAN") or "").strip() == "1",
        )

    def _boto_client(self, read_timeout_s: int):
        import boto3
        from botocore.config import Config

        return boto3.client(
            "bedrock-agentcore",
            region_name=self.region,
            config=Config(
                read_timeout=read_timeout_s,
                connect_timeout=CONNECT_TIMEOUT_S,
                retries={"total_max_attempts": 1},
            ),
        )

    def _client(self, timeout_s: float):
        key = max(1, int(timeout_s + 0.999))
        if key not in self._clients:
            self._clients[key] = self._client_factory(key)
        return self._clients[key]

    def _invoke(self, client, tool: str, arguments: dict[str, Any]) -> str:
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
        response = client.invoke_agent_runtime(
            agentRuntimeArn=self.runtime_arn,
            runtimeSessionId=self._session_id or f"tools-{tool[:12]}-{uuid.uuid4().hex}",
            payload=json.dumps(request),
            contentType="application/json",
            accept="application/json, text/event-stream",
        )
        raw = response["response"].read()
        return raw.decode("utf-8") if isinstance(raw, bytes) else raw

    async def call_json(self, tool: str, arguments: dict[str, Any], timeout_s: float) -> dict:
        deadline = time.monotonic() + timeout_s
        attempt = 1
        while True:
            started = time.monotonic()
            left = deadline - started
            try:
                client = self._client(left)
                # The boto read timeout is per socket read; this bounds the whole exchange.
                raw = await asyncio.wait_for(
                    asyncio.to_thread(self._invoke, client, tool, arguments), left + 2.0
                )
                break
            except Exception as exc:  # noqa: BLE001 - every transport failure becomes one error type
                if (
                    latency.TIGHT_BUDGETS
                    and attempt == 1
                    and time.monotonic() - started < RETRY_FAST_FAILURE_S
                    and deadline - time.monotonic() > RETRY_MIN_LEFT_S
                    and not isinstance(exc, (TimeoutError, ReadTimeoutError))
                ):
                    logger.warning(
                        "tools runtime %s failed fast (%s); retrying once", tool, type(exc).__name__
                    )
                    attempt = 2
                    continue
                raise ToolsGatewayError(f"{tool}: {type(exc).__name__}") from exc
        result = _jsonrpc_result(raw, tool)
        text = next((c.get("text", "") for c in result.get("content") or [] if "text" in c), "")
        if result.get("isError"):
            raise ToolsGatewayError(f"{tool}: tool error: {text[:160]}")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ToolsGatewayError(f"{tool}: response is not JSON") from exc
        if not isinstance(payload, dict):
            raise ToolsGatewayError(f"{tool}: response is not an object")
        return payload

    async def aclose(self) -> None:
        self._clients.clear()


def tools_client_from_env() -> ToolsClient | RuntimeToolsClient | None:
    """The tools Runtime directly when TOOLS_RUNTIME_ARN is set, else its Gateway, else None."""
    return RuntimeToolsClient.from_env() or ToolsClient.from_env()


def capture_payload(cap: BrandCapture | CodeCapture) -> dict:
    """The capture state the specialist needs, as JSON (the screenshot is not in it)."""
    failure = cap.failure
    return {
        "data": cap.data,
        "artifacts": list(cap.artifacts),
        "failure": (
            {"category": failure.category, "code": failure.code, "detail": failure.detail}
            if failure
            else None
        ),
        "site_block": cap.site_block.model_dump(mode="json") if cap.site_block else None,
    }


def apply_payload(cap: BrandCapture | CodeCapture, payload: dict) -> None:
    cap.data = payload.get("data") or {"error": "capture_failed", "reason": "empty response"}
    cap.artifacts = [str(a) for a in payload.get("artifacts") or []]
    failure = payload.get("failure")
    cap.failure = CaptureFailure(**failure) if failure else None
    block = payload.get("site_block")
    cap.site_block = Signal(**block) if block else None


def _gateway_failure(cap: BrandCapture | CodeCapture, exc: Exception) -> None:
    logger.warning("tools gateway capture failed error=%s", exc)
    cap.failure = CaptureFailure(BROWSER_ERROR, "tools_gateway")
    cap.data = {"error": "capture_failed", "category": BROWSER_ERROR, "reason": "tools_gateway"}


class RemoteBrandCapture(BrandCapture):
    """BrandCapture whose capture runs in the tools server; the model still sees the image.

    The tools server uploads the screenshot to S3 itself. This process reads the same object
    back only to hand the model its pixels, so the bytes never travel through the Gateway.
    """

    def __init__(self, url, scan_id, recorder: CallRecorder, s3, bucket, client: ToolsClient):
        super().__init__(url, scan_id, recorder, s3, bucket, open_page_fn=None)
        self.client = client

    async def capture(self) -> dict:
        if self.data is not None:
            return self.data
        try:
            with self.recorder.record(CallKind.BROWSER, "capture_page"):
                payload = await self.client.call_json(
                    "capture_page", {"url": self.url, "scan_id": self.scan_id}, CAPTURE_TIMEOUT_S
                )
            apply_payload(self, payload)
        except (ToolsGatewayError, TypeError, ValueError) as exc:
            _gateway_failure(self, exc)
            return self.data
        key = f"scans/{self.scan_id}/screenshot.png"
        if key in self.artifacts and _SCREENSHOT_KEY.match(key):
            self.png = await self._read_png(key)
        return self.data

    async def _read_png(self, key: str) -> bytes | None:
        try:
            response = await asyncio.to_thread(self.s3.get_object, Bucket=self.bucket, Key=key)
            return await asyncio.to_thread(response["Body"].read)
        except (BotoCoreError, ClientError) as exc:
            # The Finding keeps the artifact; only this model turn loses the image.
            logger.warning("screenshot read-back failed error=%s", type(exc).__name__)
            return None


class RemoteCodeCapture(CodeCapture):
    def __init__(self, url, scan_id, recorder: CallRecorder, s3, bucket, client: ToolsClient):
        super().__init__(url, scan_id, recorder, s3, bucket, open_page_fn=None)
        self.client = client

    async def capture(self) -> dict:
        if self.data is not None:
            return self.data
        try:
            with self.recorder.record(CallKind.BROWSER, "capture_page_code"):
                payload = await self.client.call_json(
                    "capture_page_code",
                    {"url": self.url, "scan_id": self.scan_id},
                    CODE_CAPTURE_TIMEOUT_S,
                )
            apply_payload(self, payload)
        except (ToolsGatewayError, TypeError, ValueError) as exc:
            _gateway_failure(self, exc)
        return self.data


async def remote_whois(client: ToolsClient, url: str, domain: str) -> dict:
    """RDAP through the tools server; a Gateway failure reads as a failed lookup."""
    try:
        return await client.call_json("whois_lookup", {"url": url}, WHOIS_TIMEOUT_S)
    except ToolsGatewayError as exc:
        logger.warning("tools gateway whois failed error=%s", exc)
        return {"domain": domain, "error": "lookup_failed"}


async def settle_capture(task: asyncio.Future, timeout_s: float) -> None:
    """Finish an eagerly started capture once the model loop is over.

    The capture is awaited, so the Finding's capture facts (page_observed, capture_status,
    the screenshot artifact) are there even when the model never called the tool; when the
    tool did call it, the task is already done and this costs nothing. Only a capture still
    running after timeout_s is cancelled. A failure was already recorded on the capture
    object, so its exception is consumed here, never raised.
    """
    try:
        await asyncio.wait_for(asyncio.shield(task), max(timeout_s, 0.0))
    except TimeoutError:
        task.cancel()
        logger.warning("eager capture still running after %.1f s; cancelled", timeout_s)
    except asyncio.CancelledError:
        if not task.done():
            task.cancel()
        raise
    except Exception as exc:  # noqa: BLE001 - the capture object already holds the failure
        logger.warning("eager capture failed error=%s", type(exc).__name__)


__all__ = [
    "RemoteBrandCapture",
    "RemoteCodeCapture",
    "RuntimeToolsClient",
    "ToolsClient",
    "ToolsGatewayError",
    "apply_payload",
    "capture_payload",
    "remote_whois",
    "settle_capture",
    "tools_client_from_env",
]
