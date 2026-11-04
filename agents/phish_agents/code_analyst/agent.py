# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""code_analyst: reads the page's DOM, scripts and network behaviour."""

from __future__ import annotations

import asyncio
import os
import time

import boto3
from strands import Agent, tool

from phish_agents.code_analyst.capture import CodeCapture
from phish_agents.common import redirects
from phish_agents.common import server as common_server
from phish_agents.common.browser import open_page
from phish_agents.common.finding import build_finding, error_finding, persist_finding
from phish_agents.common.model import load_prompt, model_id, run_specialist
from phish_agents.common.remote_tools import (
    RemoteCodeCapture,
    settle_capture,
    tools_client_from_env,
)
from phish_agents.common.timing import CallRecorder
from phish_agents.common.untrusted import wrap_untrusted
from phish_agents.common.url_safety import validate_url
from phish_contracts.models import Finding, Usage, VerdictLabel

NAME = "code_analyst"
PROMPT = load_prompt("phish_agents.code_analyst")


async def analyze(
    url: str,
    scan_id: str,
    *,
    recorder: CallRecorder | None = None,
    s3=None,
    agent_factory=Agent,
    open_page_fn=open_page,
    tools_factory=tools_client_from_env,
) -> Finding:
    started = time.monotonic()
    recorder = recorder or CallRecorder()
    s3 = s3 or boto3.client("s3", region_name=os.environ["AWS_REGION"])
    bucket = os.environ["ARTIFACTS_BUCKET"]
    reason = validate_url(url)
    if reason:
        finding = error_finding(
            NAME, reason, usage=Usage(model_id=model_id()), started=started, calls=recorder.calls
        )
        persist_finding(s3, bucket, scan_id, finding)
        return finding

    # With TOOLS_GATEWAY_URL (set by the stack) the capture runs in the shared tools server
    # behind the Gateway; without it (local runs), in this process.
    tools_client = tools_factory()
    if hasattr(tools_client, "bind_scan"):
        # -c directTools: the captures run on the scan's one tools session.
        tools_client.bind_scan(scan_id)
    cap = (
        RemoteCodeCapture(url, scan_id, recorder, s3, bucket, tools_client)
        if tools_client
        else CodeCapture(url, scan_id, recorder, s3, bucket, open_page_fn)
    )
    state = {"sanitize": False}

    @tool
    async def capture_page_code() -> str:
        """Open the scan URL in an instrumented AgentCore Browser.

        Returns forms, scripts, network requests, listeners and data sinks.
        """
        await asyncio.shield(capture_task)
        return cap.model_view(state["sanitize"])

    def on_retry() -> str:
        state["sanitize"] = True
        return (
            "Analyse the code of the page at this URL. Call capture_page_code first. "
            + wrap_untrusted("url", url, 2048)
        )

    # Started now, not when the model asks for it: the browser loads the page while the
    # model's first turn decides to call the tool, which then waits for this one capture.
    # Started right before the try, so its finally always settles it.
    capture_task = asyncio.ensure_future(cap.capture())
    try:
        run = await run_specialist(
            name=NAME,
            system_prompt=PROMPT,
            user_text="Analyse the code of the page at this URL. Call capture_page_code first. "
            + wrap_untrusted("url", url, 2048),
            tools=[capture_page_code],
            recorder=recorder,
            on_retry=on_retry,
            agent_factory=agent_factory,
            # The page code tool result is the last message before the answer: never re-read.
            cache_messages=False,
        )
    finally:
        await settle_capture(
            capture_task, common_server.deadline_s(NAME) - 1.0 - (time.monotonic() - started)
        )
        if tools_client is not None:
            await tools_client.aclose()
    finding = build_finding(
        NAME,
        run.draft,
        blocked=run.blocked,
        usage=run.usage,
        started=started,
        calls=recorder.calls,
        artifacts=cap.artifacts,
        extra_signals=cap.signals(),
    )
    if cap.static_only() and finding.verdict == VerdictLabel.LEGITIMATE:
        # Raw HTML that shows nothing is not evidence of safety: a kit can cloak from a plain
        # GET and build its form by script. The model's signals and confidence stay.
        finding.verdict = VerdictLabel.UNKNOWN
    finding.capture_note = cap.note()
    finding.insights = cap.insights()
    finding.page_observed = cap.page_observed()
    finding.page_state = cap.page_state()
    finding.redirect_chain = redirects.annotate(cap.chain())
    persist_finding(s3, bucket, scan_id, finding)
    return finding
