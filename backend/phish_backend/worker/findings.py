# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Load the three specialist Findings the agents wrote to S3."""

import logging

from botocore.exceptions import ClientError
from pydantic import ValidationError

from phish_backend.common import clients
from phish_backend.common.config import settings
from phish_contracts.models import (
    SPECIALISTS,
    Finding,
    FindingStatus,
    Severity,
    Signal,
    Usage,
    VerdictLabel,
)

logger = logging.getLogger(__name__)

# Bounds the scans item well under DynamoDB's 400 KB limit.
MAX_SIGNALS = 20
_MISSING_CODES = ("NoSuchKey", "404")
# Without s3:ListBucket, S3 answers AccessDenied (not NoSuchKey) for a key that does not
# exist. Infra grants s3:ListBucket on the artifacts bucket with prefix scans/, so a
# denial is unexpected; it still counts as a missing Finding so the scan completes.
_DENIED_CODES = ("AccessDenied", "AccessDeniedException", "403")
_denied_logged = False


def _note_denied(key: str) -> None:
    global _denied_logged
    if _denied_logged:
        return
    _denied_logged = True
    logger.warning(
        "AccessDenied reading %s; treated as a missing finding. Check s3:GetObject on "
        "scans/* and s3:ListBucket (prefix scans/) on the artifacts bucket. Logged once.",
        key,
    )


def missing_finding(agent: str, model_id: str, reason: str) -> Finding:
    return Finding(
        agent=agent,
        status=FindingStatus.ERROR,
        verdict=VerdictLabel.UNKNOWN,
        confidence=0,
        signals=[Signal(name="missing_finding", severity=Severity.LOW, evidence=reason)],
        usage=Usage(model_id=model_id),
        latency_ms=0,
    )


def clear_findings(scan_id: str) -> int:
    """Delete every object under scans/{scan_id}/findings/ before a new attempt runs.

    Specialists write their Finding at a fixed key, so without this an attempt whose
    specialist wrote nothing would silently reuse the previous attempt's Finding.
    Needs s3:ListBucket (prefix scans/) and s3:DeleteObject on scans/*.
    """
    s3 = clients.s3()
    bucket = settings().artifacts_bucket
    prefix = f"scans/{scan_id}/findings/"
    keys = [
        obj["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
        for obj in page.get("Contents", [])
    ]
    for start in range(0, len(keys), 1000):
        response = s3.delete_objects(
            Bucket=bucket,
            Delete={"Objects": [{"Key": k} for k in keys[start : start + 1000]], "Quiet": True},
        )
        if response.get("Errors"):
            raise RuntimeError(f"{len(response['Errors'])} stale findings could not be deleted")
    return len(keys)


def load_findings(scan_id: str, model_id: str) -> list[Finding]:
    s3 = clients.s3()
    bucket = settings().artifacts_bucket
    results = []
    for agent in SPECIALISTS:
        key = f"scans/{scan_id}/findings/{agent}.json"
        try:
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            finding = Finding.model_validate_json(body)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _DENIED_CODES:
                _note_denied(key)
            elif code not in _MISSING_CODES:
                raise
            results.append(missing_finding(agent, model_id, f"{agent} wrote no finding"))
            continue
        except ValidationError:
            logger.warning("finding %s failed validation", key)
            results.append(missing_finding(agent, model_id, f"{agent} finding failed validation"))
            continue
        results.append(finding.model_copy(update={"signals": finding.signals[:MAX_SIGNALS]}))
    return results
