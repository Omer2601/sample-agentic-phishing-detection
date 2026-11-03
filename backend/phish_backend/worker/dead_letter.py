# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Scan DLQ consumer.

A message that exhausted SQS redelivery still ends as a visible FAILED scan.
"""

import json
import logging

from phish_backend.common import log, store
from phish_backend.common.timeutil import utcnow

logger = logging.getLogger(__name__)
REASON = (
    "The scan could not be processed after repeated delivery failures. Use Retry to run it again."
)


def handler(event, context):
    log.configure()
    for record in event.get("Records", []):
        try:
            scan_id = str(json.loads(record["body"]).get("scan_id", ""))
        except (json.JSONDecodeError, AttributeError):
            logger.error("dead-letter message %s is not a scan message", record.get("messageId"))
            continue
        if scan_id and store.fail_scan(scan_id, None, error=REASON, completed_at=utcnow()):
            logger.warning("scan %s marked FAILED from the dead-letter queue", scan_id)
