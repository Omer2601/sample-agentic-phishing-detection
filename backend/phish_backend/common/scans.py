# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Create scan rows and queue them. Single scans and batches share this path."""

import json
import logging
import uuid
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError

from phish_backend.common import clients, store
from phish_backend.common.config import settings
from phish_backend.common.timeutil import utcnow
from phish_backend.common.url_key import dedup_key
from phish_contracts.models import ScanRecord, ScanStatus

logger = logging.getLogger(__name__)


class EnqueueError(Exception):
    pass


def new_scan(
    owner: str,
    url: str,
    *,
    batch_id: str | None = None,
    scan_id: str | None = None,
    now: datetime | None = None,
    guardrail_events: list[str] | None = None,
) -> ScanRecord:
    return ScanRecord(
        scan_id=scan_id or str(uuid.uuid4()),
        owner=owner,
        url=url,
        batch_id=batch_id,
        status=ScanStatus.PENDING,
        queued_at=now or utcnow(),
        guardrail_events=list(guardrail_events or []),
    )


def _body(record: ScanRecord) -> str:
    return json.dumps(
        {
            "scan_id": record.scan_id,
            "owner": record.owner,
            "url": record.url,
            "batch_id": record.batch_id,
        }
    )


def send(records: list[ScanRecord]) -> list[ScanRecord]:
    """Queue records; return the ones that could not be queued (never raises for SQS).

    Every queued row gets enqueued_at, so worker.requeue_stuck can tell a row whose
    message was never sent (no enqueued_at) from one that is waiting in the queue.
    """
    sqs = clients.sqs()
    queue_url = settings().scan_queue_url
    unsent: list[ScanRecord] = []
    sent: list[ScanRecord] = []
    for start in range(0, len(records), 10):
        chunk = records[start : start + 10]
        entries = [{"Id": str(i), "MessageBody": _body(r)} for i, r in enumerate(chunk)]
        try:
            response = sqs.send_message_batch(QueueUrl=queue_url, Entries=entries)
            failed_ids = {f["Id"] for f in response.get("Failed", [])}
            if failed_ids:
                retry = [e for e in entries if e["Id"] in failed_ids]
                again = sqs.send_message_batch(QueueUrl=queue_url, Entries=retry)
                failed_ids = {f["Id"] for f in again.get("Failed", [])}
        except (ClientError, BotoCoreError) as exc:
            logger.warning("send_message_batch failed (%s)", type(exc).__name__)
            failed_ids = {e["Id"] for e in entries}
        for i, record in enumerate(chunk):
            (unsent if str(i) in failed_ids else sent).append(record)
    if sent:
        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(store.mark_enqueued, [r.scan_id for r in sent]))
    if unsent:
        logger.warning("%d of %d scan messages could not be queued", len(unsent), len(records))
    return unsent


def enqueue(records: list[ScanRecord]) -> None:
    unsent = send(records)
    if unsent:
        raise EnqueueError(f"{len(unsent)} scan messages could not be queued")


def create_and_enqueue(records: list[ScanRecord]) -> int:
    """Write rows (idempotent) and queue every row that is still PENDING.

    Re-running for the same records is safe: rows already RUNNING or finished are not
    re-queued, and a duplicate message for a PENDING row is discarded by the worker claim.
    """
    with ThreadPoolExecutor(max_workers=16) as pool:
        created = list(pool.map(store.put_scan_if_absent, records))
    pending: list[ScanRecord] = []
    for record, was_created in zip(records, created, strict=True):
        if was_created:
            pending.append(record)
            continue
        existing = store.get_scan(record.scan_id)
        if existing is not None and existing.status == ScanStatus.PENDING:
            pending.append(existing)
    enqueue(pending)
    logger.info("queued %d of %d scans", len(pending), len(records))
    return len(pending)


# POST /scan dedup reuses the owner's scan of the same URL completed within this window.
DEDUP_WINDOW = timedelta(hours=24)
DEDUP_PAGE_SIZE = 25
# Bounds a lookup at 8 index pages (200 entries) and 3 consistent re-reads, so a URL
# submitted thousands of times cannot make POST /scan slow; past that it is a miss.
DEDUP_MAX_PAGES = 8
DEDUP_MAX_REREADS = 3
_IN_PROGRESS = {ScanStatus.PENDING.value, ScanStatus.RUNNING.value}
# pydantic's ValidationError is a ValueError; the others cover attributes of the wrong type.
_BAD_ROW = (ValueError, TypeError, KeyError, AttributeError)


def _aware(value: object) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _reusable(status: object, completed_at: object, cutoff: datetime) -> bool:
    if status in _IN_PROGRESS:
        return True
    completed = _aware(completed_at)
    return status == ScanStatus.COMPLETE.value and completed is not None and completed >= cutoff


def confirmed_scans_by_url(
    owner: str, url: str, nominate: Callable[[dict], bool]
) -> Iterator[ScanRecord]:
    """The owner's scans of the same normalised URL, newest first, each re-read consistently.

    The index only nominates: entries `nominate` accepts are re-read from the table and only
    rows that still exist and belong to `owner` are yielded, so callers re-check status. A
    malformed entry or row is logged by scan id (never the URL) and skipped, so one bad row
    cannot fail the request. Raises ClientError/BotoCoreError from the index or the table.
    """
    rereads = 0
    for entry in store.iter_scans_by_dedup_key(
        dedup_key(owner, url), DEDUP_PAGE_SIZE, DEDUP_MAX_PAGES
    ):
        scan_id = entry.get("scan_id") if isinstance(entry, dict) else None
        if not scan_id:
            continue
        try:
            if not nominate(entry):
                continue
            if rereads >= DEDUP_MAX_REREADS:
                return
            rereads += 1
            record = store.get_scan(str(scan_id), consistent=True)
        except _BAD_ROW as exc:
            logger.warning("skipping unreadable scan row %.64s (%s)", scan_id, type(exc).__name__)
            continue
        if record is not None and record.owner == owner:
            yield record


def find_reusable(owner: str, url: str, now: datetime | None = None) -> ScanRecord | None:
    """The owner's newest scan of the same URL that may answer a new POST /scan, or None.

    Off unless SCAN_DEDUP_ENABLED is set. A PENDING or RUNNING scan matches at any age, a
    COMPLETE one while completed_at is within DEDUP_WINDOW, a FAILED one never. Any lookup
    failure (the index missing or still backfilling, a throttle) is logged and is a miss, so
    dedup can only ever save a scan, never block one. Two concurrent first submissions of
    the same URL can both create a scan; a lock is not worth an extra write per scan.
    """
    if not settings().scan_dedup_enabled:
        return None
    cutoff = (now or utcnow()) - DEDUP_WINDOW

    def nominate(entry: dict) -> bool:
        return _reusable(entry.get("status"), entry.get("completed_at"), cutoff)

    try:
        for record in confirmed_scans_by_url(owner, url, nominate):
            if _reusable(record.status.value, record.completed_at, cutoff):
                return record
    except (ClientError, BotoCoreError) as exc:
        logger.warning("scan dedup lookup skipped (%s)", type(exc).__name__)
    return None


def latest_scan(owner: str, url: str, *, include_failed: bool = False) -> ScanRecord | None:
    """The owner's newest scan of the same URL, for GET /scans/lookup (dedup flag or not).

    FAILED scans are skipped unless include_failed. While the index is missing or still
    backfilling this logs and answers not-found; any other DynamoDB error propagates.
    """
    failed = ScanStatus.FAILED.value
    try:
        for record in confirmed_scans_by_url(
            owner, url, lambda entry: include_failed or entry.get("status") != failed
        ):
            if include_failed or record.status.value != failed:
                return record
    except ClientError as exc:
        if not store.index_unavailable(exc):
            raise
        logger.warning("scan lookup answered not-found: the dedup index is not readable yet")
    return None
