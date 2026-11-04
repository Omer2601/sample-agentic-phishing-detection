# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""GET /stats and GET /stats/export."""

from phish_backend.api.http import ApiError, Request, csv_response, json_response
from phish_backend.stats import read


def _range(req: Request) -> str:
    value = req.query.get("range", "7d")
    if value not in read.RANGES:
        raise ApiError(400, f"range must be one of {', '.join(read.RANGES)}")
    return value


def get(req: Request) -> dict:
    return json_response(200, read.build_stats(req.owner, _range(req)))


def export(req: Request) -> dict:
    range_ = _range(req)
    return csv_response(read.export_csv(req.owner, range_), f"phish-triage-{range_}.csv")
