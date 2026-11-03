# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Client for the tools runtime's `precheck_url` MCP tool (404 and site-down fast paths).

The tools runtime is a stateless streamable-HTTP MCP server (json_response=True), the same
shape as the specialists, so one `tools/call` JSON-RPC message sent through
bedrock-agentcore `invoke_agent_runtime` is a complete exchange: no `initialize`
handshake and no Mcp-Session-Id to carry (eval/evaluate_agents.py calls the specialists the
same way). A fresh runtime session id is used for every call.

The precheck is an optimisation. Every failure surfaces as PrecheckError so the caller can
log it and run the normal scan; it must never fail a scan.
"""

import json
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass

from phish_backend.common.clients import PRECHECK_TIMEOUT_SECONDS

logger = logging.getLogger(__name__)

TOOL_NAME = "precheck_url"
OUTCOMES = frozenset({"ok", "error_404", "site_down", "unreachable", "blocked"})
PROBES = frozenset({"browser", "http"})
HOPS_MAX = 10
URL_MAX = 2048
REASON_MAX = 300


class PrecheckError(Exception):
    """The precheck could not produce a usable answer (transport, protocol or timeout)."""


@dataclass(frozen=True)
class PrecheckResult:
    outcome: str
    final_status: int | None
    final_url: str
    duration_ms: int
    # v3 fields; an older tools runtime omits them and they keep these defaults.
    hops: tuple[str, ...] = ()
    reason: str = ""
    probe: str = "browser"
    browser_refused: bool = False

    @property
    def is_404(self) -> bool:
        return self.outcome == "error_404"

    @property
    def is_site_down(self) -> bool:
        return self.outcome == "site_down"


def _hops(value) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(h[:URL_MAX] for h in value if isinstance(h, str) and h)[:HOPS_MAX]


def _jsonrpc_body(raw: str) -> dict:
    """The JSON-RPC object of a response that is plain JSON or a single SSE message."""
    text = raw.strip()
    if text.startswith(("event:", "data:")):
        data = [ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:")]
        text = data[-1] if data else ""
    try:
        body = json.loads(text)
    except ValueError as exc:
        raise PrecheckError("response is not JSON") from exc
    if not isinstance(body, dict):
        raise PrecheckError("response is not a JSON-RPC object")
    return body


def _tool_payload(body: dict) -> dict:
    if "error" in body:
        raise PrecheckError("tools/call returned a JSON-RPC error")
    result = body.get("result")
    if not isinstance(result, dict) or result.get("isError"):
        raise PrecheckError("tools/call reported a tool error")
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        # FastMCP wraps a returned value as {"result": ...}; the live tools runtime returns the
        # tool's JSON as a STRING there ({"result": "{\"outcome\": ...}"}), so decode it.
        inner = structured.get("result")
        if isinstance(inner, str):
            try:
                inner = json.loads(inner)
            except ValueError:
                inner = None
        if isinstance(inner, dict):
            return inner
        if "outcome" in structured:
            return structured
    try:
        payload = json.loads(result["content"][0]["text"])
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise PrecheckError("tool result has no JSON text content") from exc
    if not isinstance(payload, dict):
        raise PrecheckError("tool result is not an object")
    return payload


def _call(client, runtime_arn: str, url: str, scan_id: str, session_id: str | None = None) -> dict:
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": TOOL_NAME, "arguments": {"url": url, "scan_id": scan_id}},
    }
    response = client.invoke_agent_runtime(
        agentRuntimeArn=runtime_arn,
        runtimeSessionId=session_id or f"{scan_id}-pre-{uuid.uuid4().hex}",
        payload=json.dumps(request),
        contentType="application/json",
        accept="application/json, text/event-stream",
    )
    raw = response["response"].read()
    return _tool_payload(_jsonrpc_body(raw.decode("utf-8") if isinstance(raw, bytes) else raw))


def precheck_url(
    client,
    runtime_arn: str,
    url: str,
    scan_id: str,
    *,
    timeout_s: float = PRECHECK_TIMEOUT_SECONDS,
    session_id: str | None = None,
) -> PrecheckResult:
    """Ask the tools runtime to open the URL and report how it answered.

    Raises PrecheckError on any failure, including exceeding timeout_s overall. The worker
    thread of a timed-out call is abandoned (it ends on the client's own read timeout).
    """
    started = time.monotonic()
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        payload = pool.submit(_call, client, runtime_arn, url, scan_id, session_id).result(
            timeout=timeout_s
        )
    except FutureTimeout as exc:
        raise PrecheckError(f"precheck exceeded {timeout_s:.0f}s") from exc
    except PrecheckError:
        raise
    except Exception as exc:  # noqa: BLE001 - boto3/botocore errors vary; all mean "no precheck"
        raise PrecheckError(type(exc).__name__) from exc
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    outcome = payload.get("outcome")
    if outcome not in OUTCOMES:
        raise PrecheckError("unknown precheck outcome")
    status = payload.get("final_status")
    return PrecheckResult(
        outcome=outcome,
        final_status=status if isinstance(status, int) and not isinstance(status, bool) else None,
        final_url=str(payload.get("final_url") or "")[:URL_MAX],
        duration_ms=int((time.monotonic() - started) * 1000),
        hops=_hops(payload.get("hops")),
        reason=str(payload.get("reason") or "")[:REASON_MAX],
        probe=payload.get("probe") if payload.get("probe") in PROBES else "browser",
        browser_refused=payload.get("browser_refused") is True,
    )
