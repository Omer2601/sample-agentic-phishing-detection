# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Structured JSON logging and CloudWatch Embedded Metric Format."""

import json
import logging
import os
import sys
import time
import uuid

METRICS_NAMESPACE = "PhishTriage"
_RESERVED = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """One JSON object per line, so CloudWatch parses fields and EMF is detected."""

    def format(self, record: logging.LogRecord) -> str:
        out = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "timestamp": int(record.created * 1000),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED:
                out[key] = value
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


def configure() -> None:
    root = logging.getLogger()
    if not root.handlers:
        root.addHandler(logging.StreamHandler(sys.stdout))
    for handler in root.handlers:
        handler.setFormatter(JsonFormatter())
    root.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def correlation_ref(what: str, exc: BaseException) -> str:
    """Log the full exception server side and return a short id that is safe to show callers."""
    ref = uuid.uuid4().hex[:12]
    logging.getLogger("phish.errors").error("%s failed (ref %s)", what, ref, exc_info=exc)
    return ref


def emit_metrics(
    dimensions: dict[str, str], metrics: dict[str, float], unit: str = "Milliseconds"
) -> None:
    emf = {
        "Timestamp": int(time.time() * 1000),
        "CloudWatchMetrics": [
            {
                "Namespace": METRICS_NAMESPACE,
                "Dimensions": [list(dimensions)],
                "Metrics": [{"Name": name, "Unit": unit} for name in metrics],
            }
        ],
    }
    logging.getLogger("phish.metrics").info("metrics", extra={"_aws": emf, **dimensions, **metrics})
