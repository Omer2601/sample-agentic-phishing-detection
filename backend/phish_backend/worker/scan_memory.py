# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Episodic memory of past scans in Amazon Bedrock AgentCore Memory.

After a scan completes the worker stores one line (defanged URL, verdict, risk, reason).
Before the next scan it retrieves the most similar lines and hands them to the
orchestrator as labelled context. Memory is best effort: a failed read or write is
logged and the scan carries on exactly as it would without memory.

Records are written directly with BatchCreateMemoryRecords rather than as events for an
extraction strategy, so nothing is paraphrased by a model and no extra model call reads
text that started on a hostile page.
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime

from phish_contracts.models import PAST_SCANS_MAX, Verdict, defang, past_scan_line

logger = logging.getLogger(__name__)

NAMESPACE = "scans"
# The record text and metadata hold no owner id, principal ARN or email: the memory is
# shared by every user of the deployment. The scan id lets the API show a user only the
# matches that are their own scans.
SCAN_ID_KEY = "scan_id"
REASON_CHARS = 160
URL_CHARS = 100


@dataclass(frozen=True)
class PastScan:
    summary: str
    # None for a record written without scan id metadata; it is still context for the
    # orchestrator but is never shown to a user.
    scan_id: str | None


def _scan_id(record: dict) -> str | None:
    value = (record.get("metadata") or {}).get(SCAN_ID_KEY) or {}
    scan_id = value.get("stringValue") if isinstance(value, dict) else None
    return str(scan_id) if scan_id else None


def summarize(url: str, verdict: Verdict) -> str:
    """One line per scan; the URL is defanged so a stored summary is never a live link."""
    first_line = (verdict.summary or "").strip().splitlines()[:1]
    reason = past_scan_line(first_line[0] if first_line else "")[:REASON_CHARS].strip()
    return (
        f"{past_scan_line(defang(url))[:URL_CHARS]} | verdict={verdict.verdict.value} | "
        f"risk={verdict.risk_score} | reason: {reason}"
    )


def recall(client, memory_id: str, url: str) -> list[PastScan]:
    """Up to PAST_SCANS_MAX summaries of earlier scans most similar to this URL."""
    if not memory_id:
        return []
    started = time.monotonic()
    try:
        response = client.retrieve_memory_records(
            memoryId=memory_id,
            namespace=NAMESPACE,
            searchCriteria={"searchQuery": defang(url), "topK": PAST_SCANS_MAX},
            maxResults=PAST_SCANS_MAX,
        )
        records = response.get("memoryRecordSummaries") or []
        found = [
            PastScan(str(r["content"].get("text") or "").strip(), _scan_id(r))
            for r in records
            if isinstance(r, dict) and isinstance(r.get("content"), dict)
        ]
    except Exception as exc:  # noqa: BLE001 - memory is best effort; a scan never fails on it
        logger.warning(
            "episodic memory read failed (%s); scanning without past context",
            type(exc).__name__,
        )
        return []
    found = [p for p in found if p.summary][:PAST_SCANS_MAX]
    logger.info(
        "episodic memory read",
        extra={"memory_hits": len(found), "memory_ms": int((time.monotonic() - started) * 1000)},
    )
    return found


def remember(
    client, memory_id: str, scan_id: str, url: str, verdict: Verdict, at: datetime
) -> bool:
    """Store this scan's summary. The scan id is the idempotency token, so a redelivered
    message that completes the same scan again does not add a second record."""
    if not memory_id:
        return False
    try:
        response = client.batch_create_memory_records(
            memoryId=memory_id,
            clientToken=scan_id,
            records=[
                {
                    "requestIdentifier": scan_id,
                    "namespaces": [NAMESPACE],
                    "content": {"text": summarize(url, verdict)},
                    "timestamp": at,
                    "metadata": {
                        "verdict": {"stringValue": verdict.verdict.value},
                        SCAN_ID_KEY: {"stringValue": scan_id},
                    },
                }
            ],
        )
    except Exception as exc:  # noqa: BLE001 - memory is best effort; a scan never fails on it
        logger.warning("episodic memory write failed (%s)", type(exc).__name__)
        return False
    failed = response.get("failedRecords") or []
    if failed:
        logger.warning(
            "episodic memory write failed (record rejected: %s)",
            str(failed[0].get("errorMessage", "unknown"))[:200],
        )
        return False
    return True
