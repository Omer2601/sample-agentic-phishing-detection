# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""brand_visual: does the page impersonate a brand, and is it built to deceive."""

from __future__ import annotations

import asyncio
import logging
import os
import time

import boto3
from strands import Agent, tool

from phish_agents.brand_visual.capture import BrandCapture
from phish_agents.brand_visual.web_search import WebSearch
from phish_agents.common import redirects
from phish_agents.common import server as common_server
from phish_agents.common.browser import open_page
from phish_agents.common.finding import build_finding, error_finding, persist_finding
from phish_agents.common.model import load_prompt, model_id, run_specialist
from phish_agents.common.remote_tools import (
    RemoteBrandCapture,
    settle_capture,
    tools_client_from_env,
)
from phish_agents.common.timing import CallRecorder
from phish_agents.common.untrusted import wrap_untrusted
from phish_agents.common.url_safety import validate_url
from phish_contracts.models import Finding, Usage

logger = logging.getLogger(__name__)

NAME = "brand_visual"
PROMPT = load_prompt("phish_agents.brand_visual")
# Stop the model this long before common/server.py deadline_s(), so the Finding
# that reaches the orchestrator keeps the saved screenshot and says how far capture got.
DEADLINE_MARGIN_S = 1.5


def _deadline_finding(cap: BrandCapture, started: float, recorder: CallRecorder) -> Finding:
    saved = f"screenshot saved at {cap.artifacts[0]}" if cap.artifacts else "no screenshot saved"
    reason = (
        f"model_deadline: the model did not finish inside the "
        f"{common_server.deadline_s(NAME):g} s analysis deadline; "
        f"capture_status={cap.capture_status()}; {saved}"
    )
    finding = error_finding(
        NAME,
        reason,
        usage=Usage(model_id=model_id()),
        started=started,
        calls=recorder.calls,
        artifacts=cap.artifacts,
    )
    # Facts measured during capture (site_unreachable, blocked_by_browser) still count.
    finding.signals.extend(cap.signals())
    return finding


def _add_capture_facts(finding: Finding, cap: BrandCapture) -> None:
    """What code measured about the capture, never the model's word for it."""
    finding.capture_status = cap.capture_status()
    finding.capture_note = cap.note()
    finding.page_observed = cap.page_observed()
    finding.page_state = cap.page_state()
    finding.redirect_chain = redirects.annotate(cap.chain())


async def analyze(
    url: str,
    scan_id: str,
    *,
    recorder: CallRecorder | None = None,
    s3=None,
    agent_factory=Agent,
    open_page_fn=open_page,
    web_search_factory=WebSearch.from_env,
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
        finding.capture_status = "not_captured"
        persist_finding(s3, bucket, scan_id, finding)
        return finding

    # With TOOLS_GATEWAY_URL (set by the stack) the capture runs in the shared tools server
    # behind the Gateway; without it (local runs), in this process.
    tools_client = tools_factory()
    if hasattr(tools_client, "bind_scan"):
        # -c directTools: the captures run on the scan's one tools session.
        tools_client.bind_scan(scan_id)
    cap = (
        RemoteBrandCapture(url, scan_id, recorder, s3, bucket, tools_client)
        if tools_client
        else BrandCapture(url, scan_id, recorder, s3, bucket, open_page_fn)
    )
    state = {"sanitize": False}

    @tool
    async def capture_page() -> dict:
        """Return the capture of the scan URL, taken in an isolated AgentCore Browser.

        Returns the screenshot, title, final URL and visible text.
        """
        await asyncio.shield(capture_task)
        return cap.tool_result(state["sanitize"])

    tools = [capture_page]
    # None when -c webSearch=false or the gateway URL is missing: the agent runs as before.
    web = web_search_factory(url, recorder)
    if web is not None:

        @tool
        async def lookup_official_domain(brand: str) -> str:
            """Search the web for a brand's official website.

            Returns up to 5 results (host, title, URL, snippet) as untrusted text.

            Args:
                brand: The brand name the page claims, for example "PayPal".
            """
            return await web.lookup(brand)

        tools.append(lookup_official_domain)

    def on_retry() -> str:
        state["sanitize"] = True
        return "Analyse the page at this URL. Call capture_page first. " + wrap_untrusted(
            "url", url, 2048
        )

    left_s = common_server.deadline_s(NAME) - DEADLINE_MARGIN_S - (time.monotonic() - started)
    deadline = asyncio.timeout(max(left_s, 0.0))
    settled = False

    async def settle() -> None:
        nonlocal settled
        if not settled:
            settled = True
            await settle_capture(
                capture_task,
                common_server.deadline_s(NAME) - 0.5 - (time.monotonic() - started),
            )

    # Started now and awaited by the tool: the browser loads the page while the model's first
    # turn decides to call capture_page, instead of the model waiting for the whole capture.
    # Started after every setup step that can raise, so the finally below always settles it.
    capture_task = asyncio.ensure_future(cap.capture())
    try:
        async with deadline:
            run = await run_specialist(
                name=NAME,
                system_prompt=PROMPT,
                user_text="Analyse the page at this URL. Call capture_page first. "
                + wrap_untrusted("url", url, 2048),
                tools=tools,
                recorder=recorder,
                on_retry=on_retry,
                agent_factory=agent_factory,
            )
    except TimeoutError:
        if not deadline.expired():
            raise
        # The capture may still be running when the model's deadline fires: the deadline
        # Finding must report its final state, so the capture is settled first.
        await settle()
        logger.warning(
            "model deadline agent=%s capture_status=%s artifacts=%d",
            NAME,
            cap.capture_status(),
            len(cap.artifacts),
        )
        finding = _deadline_finding(cap, started, recorder)
        _add_capture_facts(finding, cap)
        persist_finding(s3, bucket, scan_id, finding)
        return finding
    finally:
        await settle()
        if web is not None:
            await web.close()
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
    _add_capture_facts(finding, cap)
    persist_finding(s3, bucket, scan_id, finding)
    return finding
