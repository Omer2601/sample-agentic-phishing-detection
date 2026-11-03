# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Bedrock Guardrails kept from v1: screen submitted URLs and the final report.

A guardrail result is evidence, not a gate: an intervention is recorded on the scan and
shown to the user, and the scan always runs to COMPLETE or FAILED (no scan is dropped).
"""

import logging
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from phish_backend.common.config import settings
from phish_contracts.models import Verdict

logger = logging.getLogger(__name__)
INPUT_EVENT = "input_guardrail_intervened"
OUTPUT_EVENT = "output_guardrail_intervened"
UNAVAILABLE_EVENT = "guardrail_unavailable"
_UNAVAILABLE = "UNAVAILABLE"
_INTERVENED = "GUARDRAIL_INTERVENED"
_REPORT_NOTE = (
    "\n\n> Parts of this report were withheld by the output guardrail. The verdict is unchanged."
)
# Batch rows are screened concurrently; adaptive retries absorb ApplyGuardrail throttling.
_SCREEN_WORKERS = 8


@lru_cache(maxsize=1)
def _client():
    return boto3.client(
        "bedrock-runtime",
        region_name=settings().region,
        config=Config(retries={"mode": "adaptive", "max_attempts": 5}),
    )


def _apply(guardrail_id: str, version: str, source: str, text: str) -> tuple[str | None, dict]:
    """Return (action, response). Action is "UNAVAILABLE" on error, None when not configured."""
    if not guardrail_id:
        return None, {}
    try:
        response = _client().apply_guardrail(
            guardrailIdentifier=guardrail_id,
            guardrailVersion=version or "DRAFT",
            source=source,
            content=[{"text": {"text": text}}],
        )
    except (ClientError, BotoCoreError) as exc:
        # An outage must not drop scans; the event makes the gap visible on the scan.
        logger.warning("ApplyGuardrail %s unavailable: %s", source, type(exc).__name__)
        return _UNAVAILABLE, {}
    return response.get("action", "NONE"), response


def screen_url(url: str) -> list[str]:
    cfg = settings()
    action, _ = _apply(cfg.guardrail_input_id, cfg.guardrail_input_version, "INPUT", url)
    if action == _INTERVENED:
        return [INPUT_EVENT]
    if action == _UNAVAILABLE:
        return [UNAVAILABLE_EVENT]
    return []


def screen_urls(urls: list[str]) -> list[list[str]]:
    """screen_url for many URLs, in input order."""
    if not settings().guardrail_input_id or not urls:
        return [[] for _ in urls]
    with ThreadPoolExecutor(max_workers=_SCREEN_WORKERS) as pool:
        return list(pool.map(screen_url, urls))


def screen_report(verdict: Verdict) -> tuple[Verdict, list[str]]:
    cfg = settings()
    action, response = _apply(
        cfg.guardrail_output_id, cfg.guardrail_output_version, "OUTPUT", verdict.report_markdown
    )
    if action == _UNAVAILABLE:
        return verdict, [UNAVAILABLE_EVENT]
    if action != _INTERVENED:
        return verdict, []
    outputs = response.get("outputs") or []
    text = "".join(o.get("text", "") for o in outputs if isinstance(o, dict))
    text = text or "The report was withheld by the output guardrail."
    return verdict.model_copy(update={"report_markdown": text + _REPORT_NOTE}), [OUTPUT_EVENT]
