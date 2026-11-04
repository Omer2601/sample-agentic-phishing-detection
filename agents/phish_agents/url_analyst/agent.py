# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""url_analyst: URL structure, RDAP registration data and the URL's HTTP redirect chain."""

from __future__ import annotations

import asyncio
import json
import os
import time
from urllib.parse import urlparse

import boto3
from strands import Agent, tool

from phish_agents.common import redirects
from phish_agents.common.finding import build_finding, error_finding, persist_finding
from phish_agents.common.http_probe import http_probe
from phish_agents.common.model import load_prompt, model_id, run_specialist
from phish_agents.common.remote_tools import remote_whois, tools_client_from_env
from phish_agents.common.timing import CallRecorder
from phish_agents.common.untrusted import sanitize_for_retry, sanitize_values, wrap_untrusted
from phish_agents.common.url_safety import validate_url
from phish_agents.url_analyst.whois import rdap_lookup, registered_domain
from phish_contracts.models import CallKind, Finding, RedirectHop, Severity, Signal, Usage

NAME = "url_analyst"
PROMPT = load_prompt("phish_agents.url_analyst")
# The redirect probe (common/http_probe.py: guarded GETs, redirects followed by hand, nothing
# rendered) starts with the scan and runs while the model reads the URL.
REDIRECT_PROBE_S = 6.0


def _probe_hops(result: dict) -> list[dict]:
    hops = [
        {"url": u, "via": redirects.START if i == 0 else redirects.HTTP}
        for i, u in enumerate(result.get("hops") or [])
    ]
    if hops:
        hops[-1]["status"] = result.get("final_status")
        if result.get("outcome") == "site_down":
            hops[-1]["error"] = result.get("reason") or "site down"
    return hops


def _site_down_signal(result: dict) -> Signal | None:
    """A redirect to a host that is gone (or a dead start host) is a fact: the site is down."""
    if result.get("outcome") != "site_down":
        return None
    return Signal(
        name="site_unreachable",
        severity=Severity.MEDIUM,
        evidence=(
            "Following the URL's redirects reached a site that is down: "
            f"{str(result.get('reason') or 'no answer')[:160]}."
        ),
    )


def _local_rdap() -> bool:
    return os.environ.get("LOCAL_RDAP", "").strip().lower() in {"1", "true", "yes", "on"}


async def analyze(
    url: str,
    scan_id: str,
    *,
    recorder: CallRecorder | None = None,
    s3=None,
    agent_factory=Agent,
    lookup=rdap_lookup,
    tools_factory=tools_client_from_env,
    probe=None,
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

    domain = registered_domain(urlparse(url).hostname or "")
    state = {"result": None, "sanitize": False}
    probe_task = asyncio.create_task((probe or http_probe)(url, total_s=REDIRECT_PROBE_S))
    # With TOOLS_GATEWAY_URL (set by the stack) RDAP runs in the shared tools server, unless
    # LOCAL_RDAP is set: then this process asks RDAP itself (same SSRF-guarded client and
    # cache), sparing the tools Runtime one session per scan.
    tools_client = None if _local_rdap() else tools_factory()

    async def _lookup() -> dict:
        with recorder.record(CallKind.WHOIS, "whois_lookup", keep_cancelled=False):
            if tools_client is not None:
                return await remote_whois(tools_client, url, domain)
            return await asyncio.to_thread(lookup, domain)

    # Started now, not at the model's tool call: the first model turn and the lookup overlap.
    whois_task = asyncio.ensure_future(_lookup())

    @tool
    async def whois_lookup() -> str:
        """Look up RDAP registration data (age, registrar, status) for the scan's domain."""
        if state["result"] is None:
            state["result"] = await asyncio.shield(whois_task)
        result = sanitize_values(state["result"], 500) if state["sanitize"] else state["result"]
        return wrap_untrusted("rdap", json.dumps(result), 4000)

    chain: list[RedirectHop] = []

    async def probed() -> dict:
        nonlocal chain
        result = await probe_task
        chain = redirects.annotate(_probe_hops(result))
        return result

    @tool
    async def check_redirects() -> str:
        """Follow the URL's HTTP redirects and return every hop with site-change flags."""
        result = await probed()
        view = {
            "outcome": result.get("outcome"),
            "reason": result.get("reason"),
            **redirects.facts(url, chain),
        }
        if state["sanitize"]:
            view = sanitize_values(view, 500)
        return wrap_untrusted("redirects", json.dumps(view), 6000)

    def on_retry() -> str:
        state["sanitize"] = True
        return "Analyse this URL. " + wrap_untrusted("url", sanitize_for_retry(url, 2048), 2048)

    try:
        run = await run_specialist(
            name=NAME,
            system_prompt=PROMPT,
            user_text="Analyse this URL. " + wrap_untrusted("url", url, 2048),
            tools=[whois_lookup, check_redirects],
            recorder=recorder,
            on_retry=on_retry,
            agent_factory=agent_factory,
        )
    except BaseException:
        # Without a run there is no Finding to put the chain in: stop the probe rather than
        # leave it pending once analyze has unwound. Its outcome (result, error or
        # cancellation) is consumed, never raised, so the run's own exception propagates.
        probe_task.cancel()
        await asyncio.gather(probe_task, return_exceptions=True)
        raise
    finally:
        # Cancelling a finished task is a no-op; awaiting it retrieves its result or exception,
        # so a lookup the model never asked for cannot leave an unretrieved task exception.
        whois_task.cancel()
        await asyncio.gather(whois_task, return_exceptions=True)
        if tools_client is not None:
            await tools_client.aclose()
    # The chain is evidence in the Finding even when the model skipped the tool. The probe
    # never raises and is bounded by REDIRECT_PROBE_S, so this wait is too.
    result = await probed()
    finding = build_finding(
        NAME,
        run.draft,
        blocked=run.blocked,
        usage=run.usage,
        started=started,
        calls=recorder.calls,
        artifacts=[],
        extra_signals=[s for s in (_site_down_signal(result),) if s],
    )
    finding.redirect_chain = chain
    persist_finding(s3, bucket, scan_id, finding)
    return finding
