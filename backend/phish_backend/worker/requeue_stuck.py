# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Scheduled sweep (every 5 minutes): nothing stays PENDING or awaiting upload forever.

1. A PENDING scan whose message was never sent (no enqueued_at) or went quiet
   (enqueued_at older than 20 minutes) is queued again. Duplicates are safe: the worker's
   claim discards a message for a scan that is already RUNNING or finished, and a
   successful send restamps enqueued_at, so each scan is re-sent at most every 20 minutes.
2. An upload batch still awaiting its CSV 15 minutes after the presigned POST expired is
   closed as failed with "CSV was never uploaded".
"""

import logging
from datetime import datetime, timedelta

from botocore.exceptions import ClientError

from phish_backend.api.routes.batches import UPLOAD_SECONDS
from phish_backend.common import log, scans, store
from phish_backend.common.timeutil import utcnow
from phish_contracts.models import ScanRecord

logger = logging.getLogger(__name__)

STUCK_AFTER_SECONDS = 20 * 60
# A row with no enqueued_at may still be mid-send in the API or split_csv.
SEND_GRACE_SECONDS = 120
UPLOAD_GRACE_SECONDS = 15 * 60
NEVER_UPLOADED = "CSV was never uploaded"


def _parse(stamp: str | None) -> datetime | None:
    return datetime.fromisoformat(stamp) if stamp else None


def _is_stuck(item: dict, now: datetime) -> bool:
    if item.get("status") != "PENDING":
        return False
    enqueued = item.get("enqueued_at")
    if enqueued is not None:
        return int(enqueued) < int(now.timestamp()) - STUCK_AFTER_SECONDS
    touched = max(t for t in (_parse(item.get("queued_at")), _parse(item.get("retried_at"))) if t)
    return touched < now - timedelta(seconds=SEND_GRACE_SECONDS)


def sweep(now: datetime) -> dict:
    try:
        stuck = [
            ScanRecord.model_validate(store.from_dynamo(item))
            for item in store.pending_scan_items()
            if _is_stuck(item, now)
        ]
        index_ready = True
    except ClientError as exc:
        if not store.index_not_ready(exc):
            raise
        # Expected for a while after the deploy that adds the index; the next sweep retries.
        logger.warning(
            "status index %s not readable yet (backfilling); skipped requeue this sweep",
            store.PENDING_INDEX,
        )
        stuck, index_ready = [], False
    unsent = {r.scan_id for r in scans.send(stuck)} if stuck else set()
    for record in stuck:
        if record.scan_id not in unsent:
            logger.warning("scan %s was stuck PENDING; queued again", record.scan_id)
    cutoff = now - timedelta(seconds=UPLOAD_SECONDS + UPLOAD_GRACE_SECONDS)
    abandoned = [
        batch_id
        for batch_id in store.awaiting_upload_batch_ids(cutoff)
        if store.mark_batch_error(batch_id, NEVER_UPLOADED, now, only_if_awaiting_upload=True)
    ]
    for batch_id in abandoned:
        logger.warning("batch %s: CSV was never uploaded; marked failed", batch_id)
    result = {
        "requeued": len(stuck) - len(unsent),
        "not_queued": len(unsent),
        "abandoned_uploads": len(abandoned),
        "index_ready": index_ready,
    }
    logger.info("requeue sweep done", extra=result)
    return result


def handler(event, context) -> dict:
    log.configure()
    return sweep(utcnow())
