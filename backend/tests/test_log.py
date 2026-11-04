# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
import logging

from phish_backend.common import log


def test_json_formatter_emits_one_json_object_with_extras():
    record = logging.makeLogRecord(
        {"name": "t", "levelname": "INFO", "msg": "hello %s", "args": ("x",)}
    )
    record.scan_id = "s1"
    out = json.loads(log.JsonFormatter().format(record))
    assert out["message"] == "hello x"
    assert out["scan_id"] == "s1"
    assert out["level"] == "INFO"


def test_emit_metrics_is_valid_emf(caplog):
    caplog.set_level(logging.INFO, logger="phish.metrics")
    log.emit_metrics({"Service": "worker"}, {"ScanDurationMs": 1234.0})
    record = caplog.records[-1]
    emf = record._aws
    assert emf["CloudWatchMetrics"][0]["Namespace"] == "PhishTriage"
    assert emf["CloudWatchMetrics"][0]["Dimensions"] == [["Service"]]
    assert emf["CloudWatchMetrics"][0]["Metrics"] == [
        {"Name": "ScanDurationMs", "Unit": "Milliseconds"}
    ]
    assert record.ScanDurationMs == 1234.0
    assert record.Service == "worker"


def test_correlation_ref_is_short_and_logged(caplog):
    caplog.set_level(logging.ERROR)
    ref = log.correlation_ref("thing", RuntimeError("secret arn:aws:iam::1:role/x"))
    assert len(ref) == 12
    assert ref in caplog.text
