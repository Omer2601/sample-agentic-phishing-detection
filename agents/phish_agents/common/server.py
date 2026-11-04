# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Expose one specialist as an MCP server for AgentCore Runtime (0.0.0.0:8000/mcp)."""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from collections.abc import Awaitable, Callable

import boto3
from mcp.server import MCPServer

from phish_agents.common import latency
from phish_agents.common.finding import error_finding, persist_error_finding, validate_scan_id
from phish_agents.common.timing import CallRecorder
from phish_contracts.models import MODEL_HIDDEN_FINDING_FIELDS, Finding, SpecialistName, Usage

logger = logging.getLogger(__name__)

# analyze(url, scan_id, *, recorder) records its calls on the recorder it is given, so
# the calls made before a failure still reach the error Finding.
Analyze = Callable[..., Awaitable[Finding]]
# Stateless JSON responses: the Runtime may route each request to a different
# microVM, so no MCP session state can live in this process.
# Per-specialist deadline. Finishing before the Gateway's tool call times out means the
# orchestrator gets an error Finding instead of a transport timeout.
# 30 s: browser navigation (15 s) plus settle, screenshot and one model turn (p95 about
# 17 s end to end). The old 40 s let one stuck page hold every scan in a batch 10 s longer.
ANALYZE_DEADLINE_S = 30
# The two page specialists run a browser capture and then their longest model turn:
# code_analyst's successful runs reached 29.4 s (about 1.5% hit 30 s, week of 2026-10-19) and
# brand_visual's model ran out of time on 5 of 317 scans of a 25-in-flight batch (2026-10-26),
# each costing a second round. 35 s keeps the dispatcher's 45 s read timeout 10 s clear.
# -c latencyBudgets=true: 42 s, because the capture client then waits up to 30 s
# (remote_tools.CODE_CAPTURE_TIMEOUT_S, the tools Runtime start lag included) and a model turn
# follows it; the dispatcher's read timeout moves with it and stays 10 s clear.
PAGE_DEADLINE_S = 42 if latency.TIGHT_BUDGETS else 35
PAGE_SPECIALISTS = frozenset({"code_analyst", "brand_visual"})


def deadline_s(agent: SpecialistName) -> float:
    return PAGE_DEADLINE_S if agent in PAGE_SPECIALISTS else ANALYZE_DEADLINE_S


HTTP_OPTIONS = {"streamable_http_path": "/mcp", "stateless_http": True, "json_response": True}
# AgentCore Runtime reaches the container on port 8000 from outside it, so the image sets
# HOST to all interfaces (agents/Dockerfile). Anywhere else the server stays on loopback.
DEFAULT_HOST = "127.0.0.1"
PORT = 8000


def bind_host() -> str:
    return os.environ.get("HOST", DEFAULT_HOST)


def _s3():
    return boto3.client("s3", region_name=os.environ["AWS_REGION"])


async def safe_analyze(
    agent: SpecialistName, analyze: Analyze, url: str, scan_id: str, *, s3=None
) -> str:
    started = time.monotonic()
    recorder = CallRecorder()
    try:
        validate_scan_id(scan_id)
        finding = await asyncio.wait_for(
            analyze(url, scan_id, recorder=recorder), deadline_s(agent)
        )
        return finding.model_dump_json(exclude=set(MODEL_HIDDEN_FINDING_FIELDS))
    except Exception as exc:  # noqa: BLE001 - the orchestrator must always get a Finding back
        ref = uuid.uuid4().hex[:12]
        if isinstance(exc, TimeoutError):
            logger.warning(
                "analyze timed out agent=%s ref=%s after %ss", agent, ref, deadline_s(agent)
            )
            reason = "timeout"
        else:
            logger.exception("analyze failed agent=%s ref=%s", agent, ref)
            reason = str(exc) if isinstance(exc, ValueError) else "internal error"
        finding = error_finding(
            agent,
            f"{reason} (ref {ref})",
            usage=Usage(model_id=os.environ.get("MODEL_ID", "")),
            started=started,
            calls=list(recorder.calls),
        )
        # The orchestrator and the results page read findings from S3, so an error that
        # only lives in the MCP response would look like a missing specialist.
        try:
            client = s3 or _s3()
        except Exception as s3_exc:  # noqa: BLE001 - persistence is best effort
            logger.warning("no s3 client for error finding: %s", type(s3_exc).__name__)
        else:
            persist_error_finding(client, os.environ.get("ARTIFACTS_BUCKET"), scan_id, finding)
        return finding.model_dump_json(exclude=set(MODEL_HIDDEN_FINDING_FIELDS))


def build_server(agent: SpecialistName, analyze: Analyze) -> MCPServer:
    mcp = MCPServer(f"phish-{agent}")

    @mcp.tool(
        name="analyze",
        description=(
            f"Run the {agent} phishing specialist on one URL. Returns a Finding JSON object with "
            "verdict, confidence 0-100, signals, artifacts, token usage and call timings."
        ),
    )
    async def analyze_tool(url: str, scan_id: str) -> str:
        return await safe_analyze(agent, analyze, url, scan_id)

    return mcp


def serve(mcp: MCPServer) -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format='{"level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
    )
    mcp.run(
        transport="streamable-http",
        host=bind_host(),
        port=PORT,
        **HTTP_OPTIONS,
    )
