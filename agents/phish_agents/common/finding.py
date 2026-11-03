# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Model output schema and conversion into the shared Finding contract."""

from __future__ import annotations

import logging
import re
import time

from pydantic import BaseModel, Field

from phish_contracts.models import (
    Call,
    Finding,
    FindingStatus,
    Severity,
    Signal,
    SpecialistName,
    Usage,
    VerdictLabel,
)

logger = logging.getLogger(__name__)

_SCAN_ID = re.compile(r"^[A-Za-z0-9-]{8,64}$")


class SignalDraft(BaseModel):
    name: str = Field(
        description="snake_case indicator name, for example credential_form_off_domain"
    )
    severity: Severity
    evidence: str = Field(description="One concrete observation, at most 30 words")


class FindingDraft(BaseModel):
    """What the model returns. Timing, usage and status are filled in by code, not the model."""

    verdict: VerdictLabel
    confidence: int = Field(ge=0, le=100)
    signals: list[SignalDraft] = Field(default_factory=list, max_length=6)


def validate_scan_id(scan_id: str) -> str:
    # scan_id becomes part of an S3 key; refuse anything that could escape the prefix.
    if not isinstance(scan_id, str) or not _SCAN_ID.match(scan_id):
        raise ValueError("scan_id must be 8 to 64 characters of letters, digits and hyphens")
    return scan_id


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def build_finding(
    agent: SpecialistName,
    draft: FindingDraft | None,
    *,
    blocked: bool,
    usage: Usage,
    started: float,
    calls: list[Call],
    artifacts: list[str],
    extra_signals: list[Signal] | None = None,
) -> Finding:
    """extra_signals are facts measured in code (site_unreachable); they are added
    whatever the model wrote, and skipped when the model already used the same name."""
    extra = list(extra_signals or [])
    if blocked or draft is None:
        return Finding(
            agent=agent,
            status=FindingStatus.BLOCKED,
            verdict=VerdictLabel.UNKNOWN,
            confidence=0,
            signals=[
                Signal(
                    name="model_guardrail_block",
                    severity=Severity.MEDIUM,
                    evidence=(
                        "The model refused this page content twice, including a sanitized retry."
                    ),
                ),
                *extra,
            ],
            artifacts=artifacts,
            usage=usage,
            latency_ms=_elapsed_ms(started),
            calls=calls,
        )
    return Finding(
        agent=agent,
        status=FindingStatus.OK,
        verdict=draft.verdict,
        confidence=draft.confidence,
        signals=[
            *(e for e in extra if e.name not in {s.name for s in draft.signals}),
            *(Signal(name=s.name, severity=s.severity, evidence=s.evidence) for s in draft.signals),
        ],
        artifacts=artifacts,
        usage=usage,
        latency_ms=_elapsed_ms(started),
        calls=calls,
    )


def error_finding(
    agent: SpecialistName,
    reason: str,
    *,
    usage: Usage,
    started: float,
    calls: list[Call],
    artifacts: list[str] | None = None,
) -> Finding:
    return Finding(
        agent=agent,
        status=FindingStatus.ERROR,
        verdict=VerdictLabel.UNKNOWN,
        confidence=0,
        signals=[Signal(name="analysis_error", severity=Severity.LOW, evidence=reason)],
        artifacts=artifacts or [],
        usage=usage,
        latency_ms=_elapsed_ms(started),
        calls=calls,
    )


def persist_finding(
    s3, bucket: str, scan_id: str, finding: Finding, *, if_absent: bool = False
) -> str:
    key = f"scans/{validate_scan_id(scan_id)}/findings/{finding.agent}.json"
    extra = {"IfNoneMatch": "*"} if if_absent else {}
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=finding.model_dump_json().encode(),
        ContentType="application/json",
        **extra,
    )
    return key


def persist_error_finding(
    s3, bucket: str | None, scan_id: str, finding: Finding, *, if_absent: bool = False
) -> None:
    """Best effort: the caller still returns the Finding when S3 is unreachable."""
    if not bucket or not isinstance(scan_id, str) or not _SCAN_ID.match(scan_id):
        logger.warning("error finding not persisted agent=%s: no bucket or scan_id", finding.agent)
        return
    try:
        persist_finding(s3, bucket, scan_id, finding, if_absent=if_absent)
    except Exception as exc:  # noqa: BLE001 - persistence failure must not replace the Finding
        logger.warning(
            "error finding not persisted agent=%s error=%s", finding.agent, type(exc).__name__
        )
