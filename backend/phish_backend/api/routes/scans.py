# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""POST /scan and GET /scans/{id}."""

import logging
import time
from datetime import UTC, datetime

from botocore.exceptions import BotoCoreError, ClientError

from phish_backend.api import idempotency
from phish_backend.api.http import ApiError, Request, json_response, public_dump, scan_dump
from phish_backend.common import clients, guardrails, scans, store
from phish_backend.common.config import settings
from phish_backend.common.timeutil import utcnow
from phish_backend.common.url_input import InvalidUrl, validate_submitted_url
from phish_contracts.models import ScanRecord, ScanStatus

logger = logging.getLogger(__name__)
PRESIGN_SECONDS = 900
NOT_QUEUED = "the scan could not be queued; try again"
QUEUE_FAILURE_REASON = "the scan could not be queued (send failed twice)"
KEY_REUSED = f"{idempotency.HEADER} was already used with a different url"
IN_FLIGHT = f"a request with this {idempotency.HEADER} is still being processed; retry shortly"
REPLAY_HEADER = "Idempotent-Replayed"
RETRY_AFTER_SECONDS = 2


def create(req: Request) -> dict:
    """Start a scan, replay an Idempotency-Key, or (when dedup is on) return a recent scan.

    Body: {"url": str, "force": bool (optional, default false)}. A key the caller already
    used with the same url answers 200 with the original scan_id and its current status
    (header Idempotent-Replayed: true); with a different url, 422; while the first request
    is still in flight, 409 and Retry-After. A key wins over force and dedup. Otherwise
    force=true always starts a fresh scan, and dedup (-c scanDedup, off by default) may hand
    back the caller's own scan of the same URL: 202 with deduplicated=true. The web console
    is never deduplicated, so "scan again" there always runs a new scan.
    """
    body = req.json()
    try:
        url = validate_submitted_url(body.get("url"))
    except InvalidUrl as exc:
        raise ApiError(400, str(exc)) from exc
    force = body.get("force", False)
    if not isinstance(force, bool):
        raise ApiError(400, "force must be a boolean")
    raw_key = req.header(idempotency.HEADER)
    key = None
    stale: str | None = None
    if raw_key is not None:
        if not idempotency.configured():
            raise ApiError(501, idempotency.NOT_CONFIGURED)
        try:
            key = idempotency.validate_key(raw_key)
        except idempotency.InvalidKey as exc:
            raise ApiError(400, str(exc)) from exc
        held = idempotency.find(req.owner, key)
        if held is not None:
            response = _replay(req, held, url)
            if response is not None:
                return response
            stale = held.scan_id
    reused = None if force or req.console else scans.find_reusable(req.owner, url)
    if reused is not None:
        if key is not None:
            held = idempotency.claim(
                req.owner, key, reused.scan_id, url, replace_scan_id=stale, deduplicated=True
            )
            if not held.won:
                return _replay(req, held, url) or _in_flight()
        logger.info("scan %s reused (%s)", reused.scan_id, reused.status.value)
        return json_response(
            202,
            {"scan_id": reused.scan_id, "status": reused.status.value, "deduplicated": True},
        )
    record = scans.new_scan(req.owner, url, guardrail_events=guardrails.screen_url(url))
    if key is not None:
        held = idempotency.claim(req.owner, key, record.scan_id, url, replace_scan_id=stale)
        if not held.won:
            # Another request took the key first; a dead claim it replaced has no row yet.
            return _replay(req, held, url) or _in_flight()
    try:
        queued = _queue(record)
    except BaseException:
        if key is not None:
            idempotency.release(req.owner, key, record.scan_id)
        raise
    if not queued:
        if key is not None:
            # The scan is FAILED and nothing runs it, so the same key may start a new one.
            idempotency.release(req.owner, key, record.scan_id)
        raise ApiError(503, NOT_QUEUED)
    return json_response(
        202, {"scan_id": record.scan_id, "status": record.status.value, "deduplicated": False}
    )


def _in_flight() -> dict:
    return json_response(
        409, {"error": IN_FLIGHT}, headers={"Retry-After": str(RETRY_AFTER_SECONDS)}
    )


def _replay(req: Request, held: idempotency.Claim, url: str) -> dict | None:
    """The answer for a key already held, or None when its request died and may be replaced."""
    if held.url != url:
        raise ApiError(422, KEY_REUSED)
    # Strongly consistent: a stale miss after the lease would take over a live scan's claim.
    existing = store.get_scan(held.scan_id, consistent=True)
    if existing is not None and existing.owner == req.owner:
        return json_response(
            200,
            {
                "scan_id": held.scan_id,
                "status": existing.status.value,
                "deduplicated": held.deduplicated,
            },
            headers={REPLAY_HEADER: "true"},
        )
    if time.time() - held.created_at < idempotency.LEASE_SECONDS:
        return _in_flight()
    logger.warning("idempotency claim for scan %s has no scan row; taking it over", held.scan_id)
    return None


def _queue(record: ScanRecord) -> bool:
    """Write and queue the scan, retrying the send once. False: it is FAILED, not queued.

    A FAILED row with a 503 tells the caller to submit again; a PENDING row left for the
    requeue sweeper would look queued while nothing runs it for up to 20 minutes.
    """
    try:
        scans.create_and_enqueue([record])
        return True
    except scans.EnqueueError:
        logger.warning("scan %s not queued; retrying the send once", record.scan_id)
    try:
        scans.enqueue([record])
        return True
    except scans.EnqueueError:
        pass
    if store.fail_pending_scan(record.scan_id, error=QUEUE_FAILURE_REASON, completed_at=utcnow()):
        logger.error("scan %s could not be queued; marked FAILED", record.scan_id)
        return False
    # Strongly consistent: a stale read here would answer 503 for a scan already running.
    current = store.get_scan(record.scan_id, consistent=True)
    if current is not None and current.status in (ScanStatus.RUNNING, ScanStatus.COMPLETE):
        logger.warning("scan %s is %s after a failed send", record.scan_id, current.status.value)
        return True
    logger.error("scan %s could not be queued", record.scan_id)
    return False


def get(req: Request) -> dict:
    record = store.get_scan(req.path_id())
    if record is None or record.owner != req.owner:
        raise ApiError(404, "scan not found")
    wanted = f"scans/{record.scan_id}/screenshot.png"
    has_shot = any(a == wanted for f in record.findings for a in f.artifacts)
    screenshot = (
        clients.s3().generate_presigned_url(
            "get_object",
            Params={"Bucket": settings().artifacts_bucket, "Key": wanted},
            ExpiresIn=PRESIGN_SECONDS,
        )
        if has_shot
        else None
    )
    body = scan_dump(record)
    body["similar_scans"] = _own_similar_scans(record.scan_id, req.owner)
    body["artifacts"] = {"screenshot": screenshot}
    return json_response(200, body)


def lookup(req: Request) -> dict:
    """Has the caller scanned this URL, and if so with what result and how long ago?

    Query: url (required), include_failed (optional true/false, default false). Read-only:
    it never starts a scan and works whether dedup is on or off. Only the caller's own scans
    are matched, by the same owner and normalised URL as dedup. age_seconds counts from
    completed_at, or from queued_at while the scan is not complete.
    """
    try:
        url = validate_submitted_url(req.query.get("url"))
    except InvalidUrl as exc:
        raise ApiError(400, str(exc)) from exc
    raw = (req.query.get("include_failed") or "false").strip().lower()
    if raw not in {"true", "false", "1", "0"}:
        raise ApiError(400, "include_failed must be true or false")
    record = scans.latest_scan(req.owner, url, include_failed=raw in {"true", "1"})
    if record is None:
        return json_response(200, {"found": False, "url": url})
    verdict = record.verdict
    since = record.completed_at or record.queued_at
    dumped = public_dump(record)
    return json_response(
        200,
        {
            "found": True,
            "url": url,
            "scan_id": record.scan_id,
            "status": record.status.value,
            "verdict": verdict.verdict.value if verdict else None,
            "risk_score": verdict.risk_score if verdict else None,
            "confidence": verdict.confidence.value if verdict else None,
            "completed_at": dumped.get("completed_at"),
            "queued_at": dumped.get("queued_at"),
            "age_seconds": max(0, int((utcnow() - _aware(since)).total_seconds())),
        },
    )


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _own_similar_scans(scan_id: str, owner: str) -> list[dict[str, str]]:
    """Episodic memory matches that are the requester's own scans, nothing else.

    Memory is shared by the whole deployment (the orchestrator sees every match as context),
    but a user must never learn that another owner's scan exists, so each match is looked
    up and kept only when this owner owns it. A failed lookup shows no list at all.
    """
    try:
        matches = store.memory_matches(scan_id)
        ids = [str(m["scan_id"]) for m in matches if m.get("scan_id") and m["scan_id"] != scan_id]
        owners = store.scan_owners(ids) if ids else {}
    except (ClientError, BotoCoreError) as exc:
        logger.warning("similar scans hidden for %s (%s)", scan_id, type(exc).__name__)
        return []
    return [
        {"scan_id": str(m["scan_id"]), "summary": str(m.get("summary") or "")}
        for m in matches
        if m.get("scan_id") and m["scan_id"] != scan_id and owners.get(m["scan_id"]) == owner
    ]
