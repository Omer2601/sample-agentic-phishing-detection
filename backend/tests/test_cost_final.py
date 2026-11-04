# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""cost_final on GET /scans/{id}, /history and batch items; cost_usd keeps its string type."""

import json

import pytest
from backend_testkit import OWNER_A, api_event, put_batch_for_tests, utcnow

from phish_backend.api import app
from phish_backend.common import store
from phish_contracts.models import ReportStatus, ScanRecord, ScanStatus


def call(event):
    response = app.handler(event, None)
    return response["statusCode"], json.loads(response["body"])


def put(scan_id, status, report_status=ReportStatus.READY, batch_id=None):
    store.put_scan_if_absent(
        ScanRecord(
            scan_id=scan_id,
            owner=OWNER_A,
            url="https://a.example/",
            batch_id=batch_id,
            status=status,
            queued_at=utcnow(),
            report_status=report_status,
            cost_usd="0.0125",
        )
    )


CASES = [
    (ScanStatus.PENDING, ReportStatus.READY, False),
    (ScanStatus.RUNNING, ReportStatus.READY, False),
    (ScanStatus.COMPLETE, ReportStatus.PENDING, False),
    (ScanStatus.COMPLETE, ReportStatus.READY, True),
    (ScanStatus.COMPLETE, ReportStatus.FAILED, True),
    (ScanStatus.FAILED, ReportStatus.READY, True),
]


@pytest.mark.parametrize(("status", "report", "final"), CASES)
def test_cost_final_on_the_scan_record(aws, status, report, final):
    put("s1", status, report)
    code, body = call(api_event("GET", "/scans/{id}", path={"id": "s1"}))
    assert code == 200
    assert body["cost_final"] is final
    # Backward compatible: the web UI parses cost_usd as a decimal string.
    assert body["cost_usd"] == "0.0125"


def test_cost_final_on_history_and_batch_items(aws):
    put("s1", ScanStatus.COMPLETE, ReportStatus.PENDING, batch_id="b1")
    put("s2", ScanStatus.COMPLETE, ReportStatus.READY, batch_id="b1")
    put_batch_for_tests("b1", OWNER_A, total=2)
    _, history = call(api_event("GET", "/history"))
    _, batch = call(api_event("GET", "/batches/{id}", path={"id": "b1"}))
    for items in (history["items"], batch["items"]):
        assert {i["scan_id"]: i["cost_final"] for i in items} == {"s1": False, "s2": True}
        assert all(isinstance(i["cost_usd"], str) for i in items)
