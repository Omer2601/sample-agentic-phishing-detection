# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""GET /feed/phishing (v1 behaviour, moved)."""

import logging

from phish_backend.api import feed
from phish_backend.api.http import Request, json_response
from phish_backend.common import clients
from phish_backend.common.config import settings
from phish_backend.common.url_input import error_or_none

logger = logging.getLogger(__name__)


def get(req: Request) -> dict:
    try:
        limit = int(req.query.get("limit", "10"))
    except ValueError:
        limit = 10
    try:
        payload = feed.get_live_phishing_urls(
            limit, error_or_none, s3=clients.s3(), bucket=settings().artifacts_bucket
        )
    except (OSError, ValueError) as exc:
        logger.warning("live feed unavailable: %s", type(exc).__name__)
        return json_response(503, {"error": "Live feed temporarily unavailable"})
    return json_response(200, payload)
