# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""GET /scans/{id}/report and GET /batches/{id}/report: HTML reports as presigned links.

Each request renders the report from the stored records, writes it to the artifacts
bucket and answers with a short-lived link. Rendering on request keeps a batch report
current while its scans finish, and the owner check always runs before anything is
written or signed.
"""

from phish_backend.api.http import ApiError, Request, json_response
from phish_backend.common import clients, store
from phish_backend.common.config import settings
from phish_backend.reports.html import render_batch_report, render_scan_report
from phish_contracts.models import ScanStatus

PRESIGN_SECONDS = 900
CONTENT_TYPE = "text/html; charset=utf-8"
_PAGE = 200


def _publish(key: str, page: str, filename: str) -> dict:
    """Store the page and return a download link that expires in PRESIGN_SECONDS."""
    s3 = clients.s3()
    bucket = settings().artifacts_bucket
    disposition = f'attachment; filename="{filename}"'
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=page.encode("utf-8"),
        ContentType=CONTENT_TYPE,
        ContentDisposition=disposition,
    )
    url = s3.generate_presigned_url(
        "get_object",
        Params={
            "Bucket": bucket,
            "Key": key,
            # Always a download, never rendered on the bucket's origin.
            "ResponseContentDisposition": disposition,
            "ResponseContentType": CONTENT_TYPE,
        },
        ExpiresIn=PRESIGN_SECONDS,
    )
    return json_response(200, {"url": url, "expires_in": PRESIGN_SECONDS})


def scan_report(req: Request) -> dict:
    record = store.get_scan(req.path_id())
    if record is None or record.owner != req.owner:
        raise ApiError(404, "scan not found")
    if record.status != ScanStatus.COMPLETE or record.verdict is None:
        raise ApiError(409, "a report is available once the scan is COMPLETE")
    return _publish(
        f"scans/{record.scan_id}/report.html",
        render_scan_report(record),
        f"phish-report-{record.scan_id[:8]}.html",
    )


def batch_report(req: Request) -> dict:
    batch_id = req.path_id()
    item = store.get_batch_item(batch_id)
    if not item or item.get("owner") != req.owner:
        raise ApiError(404, "batch not found")
    scans, cursor = [], None
    while True:
        page, cursor = store.scans_for_batch(batch_id, _PAGE, cursor)
        # Belt and braces: a batch only ever holds its owner's scans, and a row that
        # claims otherwise is left out rather than shown to this caller.
        scans += [s for s in page if s.owner == req.owner]
        if not cursor:
            break
    return _publish(
        f"batches/{batch_id}/report.html",
        render_batch_report(store.batch_from_item(item), scans, console_url=settings().console_url),
        f"phish-batch-report-{batch_id[:8]}.html",
    )
