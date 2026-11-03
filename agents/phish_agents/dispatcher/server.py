# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The dispatcher MCP server: one Gateway tool, `analyze_all`, that runs the three specialists
at the same time and returns their three Findings.

The AgentCore Harness runs same-turn Gateway tool calls one after another, so three specialist
tools cost the sum of their latencies (spike 2026-10-16). The orchestrator calls
`dispatcher___analyze_all` once and the wait is the slowest specialist. It returns
`{"findings": [Finding, Finding, Finding]}`, each the specialist's own Finding (status,
signals, latency_ms, usage and calls unchanged). It never raises: a failed or timed-out
specialist becomes an error Finding, written to S3 only if the specialist has not already
written its own. The per-specialist Gateway tools stay for the optional second round.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.config import Config
from mcp.server import MCPServer

from phish_agents.common import latency
from phish_agents.common import server as common_server
from phish_agents.common.finding import error_finding, persist_error_finding, validate_scan_id
from phish_agents.common.timing import CallRecorder
from phish_contracts.models import (
    MODEL_HIDDEN_FINDING_FIELDS,
    SPECIALISTS,
    CallKind,
    Finding,
    SpecialistName,
    Usage,
)

logger = logging.getLogger(__name__)

# Must stay above every common/server.py deadline_s() plus session start-up (tested).
RUNTIME_READ_TIMEOUT_S = 52 if latency.TIGHT_BUDGETS else 45
# Backstop above the boto read timeout: a hung socket must not hold the Gateway call. The
# boto timeout normally fires first and gives the more specific error.
DISPATCH_DEADLINE_S = RUNTIME_READ_TIMEOUT_S + 5


def _runtime_client():
    return boto3.client(
        "bedrock-agentcore",
        region_name=os.environ["AWS_REGION"],
        # One attempt only: a ReadTimeout retry would start a second, billed specialist run
        # for the same scan while the first is still working.
        config=Config(
            read_timeout=RUNTIME_READ_TIMEOUT_S,
            connect_timeout=5,
            retries={"total_max_attempts": 1},
        ),
    )


def _s3():
    return boto3.client("s3", region_name=os.environ["AWS_REGION"])


def call_specialist(client, runtime_arn: str, url: str, scan_id: str) -> Finding:
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "analyze", "arguments": {"url": url, "scan_id": scan_id}},
    }
    response = client.invoke_agent_runtime(
        agentRuntimeArn=runtime_arn,
        runtimeSessionId=f"{scan_id}-{uuid.uuid4().hex}",
        payload=json.dumps(request),
        contentType="application/json",
        accept="application/json, text/event-stream",
    )
    body = json.loads(response["response"].read())
    text = body["result"]["content"][0]["text"]
    return Finding.model_validate_json(text)


def _failed(
    agent: SpecialistName, reason: str, started: float, recorder: CallRecorder | None = None
) -> Finding:
    return error_finding(
        agent,
        reason,
        usage=Usage(model_id=""),
        started=started,
        calls=list(recorder.calls) if recorder else [],
    )


async def dispatch(
    url: str,
    scan_id: str,
    *,
    client_factory=_runtime_client,
    s3_factory=_s3,
    call_fn=call_specialist,
    deadline_s: float = DISPATCH_DEADLINE_S,
) -> list[Finding]:
    """Three Findings in SPECIALISTS order, whatever happens."""
    started = time.monotonic()
    try:
        validate_scan_id(scan_id)
    except ValueError as exc:
        return [_failed(a, str(exc), started) for a in SPECIALISTS]
    try:
        client = client_factory()
    except Exception as exc:  # noqa: BLE001 - the orchestrator must always get three Findings
        logger.exception("no runtime client")
        reason = f"dispatcher unavailable: {type(exc).__name__}"
        return [_failed(a, reason, started) for a in SPECIALISTS]
    bucket = os.environ.get("ARTIFACTS_BUCKET")
    loop = asyncio.get_running_loop()
    # Own pool, sized to the specialists, so the three calls are always concurrent. It is
    # shut down without waiting: a thread stuck past the deadline must not hold the reply.
    pool = ThreadPoolExecutor(max_workers=len(SPECIALISTS), thread_name_prefix="dispatch")

    async def one(agent: SpecialistName) -> Finding:
        recorder = CallRecorder()

        def blocking() -> Finding:
            with recorder.record(CallKind.SPECIALIST, agent):
                return call_fn(client, os.environ[f"{agent.upper()}_RUNTIME_ARN"], url, scan_id)

        try:
            return await asyncio.wait_for(loop.run_in_executor(pool, blocking), deadline_s)
        except Exception as exc:  # noqa: BLE001 - one failed specialist must not hide the others
            ref = uuid.uuid4().hex[:12]
            logger.exception("specialist call failed agent=%s ref=%s", agent, ref)
            error = _failed(
                agent,
                f"specialist unavailable (ref {ref}): {type(exc).__name__}",
                started,
                recorder,
            )
            try:
                # if_absent: a specialist that finished after our timeout has already written
                # its real Finding, which this error must not overwrite.
                await asyncio.to_thread(
                    persist_error_finding, s3_factory(), bucket, scan_id, error, if_absent=True
                )
            except Exception as s3_exc:  # noqa: BLE001 - persistence is best effort
                logger.warning("no s3 client for error finding: %s", type(s3_exc).__name__)
            return error

    try:
        findings = await asyncio.gather(*(one(a) for a in SPECIALISTS))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    logger.info("dispatch done scan=%s ms=%d", scan_id, int((time.monotonic() - started) * 1000))
    return list(findings)


async def run_analyze_all(url: str, scan_id: str, **kwargs) -> str:
    try:
        findings = await dispatch(url, scan_id, **kwargs)
    except Exception as exc:  # noqa: BLE001 - last resort: still three Findings
        logger.exception("dispatch crashed")
        started = time.monotonic()
        findings = [
            _failed(a, f"dispatcher failed: {type(exc).__name__}", started) for a in SPECIALISTS
        ]
    return json.dumps(
        {
            "findings": [
                f.model_dump(mode="json", exclude=set(MODEL_HIDDEN_FINDING_FIELDS))
                for f in findings
            ]
        }
    )


def build_server(**kwargs) -> MCPServer:
    mcp = MCPServer("phish-dispatcher")

    @mcp.tool(
        name="analyze_all",
        description=(
            "Run all three phishing specialists (url_analyst, brand_visual, code_analyst) on one "
            'URL at the same time and return {"findings": [...]} with one Finding each, in that '
            "order. A specialist that fails comes back as a Finding with status error."
        ),
    )
    async def analyze_all(url: str, scan_id: str) -> str:
        return await run_analyze_all(url, scan_id, **kwargs)

    return mcp


def main() -> None:
    common_server.serve(build_server())


if __name__ == "__main__":
    main()
