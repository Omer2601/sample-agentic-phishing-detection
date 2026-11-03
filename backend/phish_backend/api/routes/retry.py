# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""POST /scans/{id}/retry and POST /batches/{id}/retry-failed."""

import logging

from phish_backend.api.http import ApiError, Request, json_response
from phish_backend.common import scans, store
from phish_contracts.models import ScanRecord

logger = logging.getLogger(__name__)
NOT_QUEUED = "the retry could not be queued; try again"


def _reopen_and_send(failed: list[ScanRecord], owner: str) -> tuple[int, int]:
    """Reopen FAILED scans and queue them. Returns (queued, reopened).

    A scan whose message could not be sent goes back to FAILED with its prior reason,
    so a retry never leaves a PENDING row that nothing will pick up.
    """
    stamp = store.retry_stamp()
    prior = {r.scan_id: r for r in failed}
    reopened = [
        r
        for r in (store.reopen_failed_scan(s.scan_id, owner, retried_at=stamp) for s in failed)
        if r is not None
    ]
    if not reopened:
        return 0, 0
    unsent = scans.send(reopened)
    for record in unsent:
        if not store.revert_reopen(prior[record.scan_id], stamp):
            logger.warning("scan %s changed before its retry could be reverted", record.scan_id)
    return len(reopened) - len(unsent), len(reopened)


def retry_scan(req: Request) -> dict:
    scan_id = req.path_id()
    current = store.get_scan(scan_id)
    if current is None or current.owner != req.owner:
        raise ApiError(404, "scan not found")
    queued, reopened = _reopen_and_send([current], req.owner)
    if not reopened:
        raise ApiError(409, "only FAILED scans can be retried")
    if not queued:
        raise ApiError(503, NOT_QUEUED)
    return json_response(202, {"scan_id": scan_id, "status": "PENDING"})


def retry_failed_in_batch(req: Request) -> dict:
    batch_id = req.path_id()
    item = store.get_batch_item(batch_id)
    if not item or item.get("owner") != req.owner:
        raise ApiError(404, "batch not found")
    queued, reopened = _reopen_and_send(store.failed_scans_for_batch(batch_id), req.owner)
    if reopened and not queued:
        raise ApiError(503, NOT_QUEUED)
    return json_response(202, {"batch_id": batch_id, "retried": queued})
