# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""GET /history."""

from phish_backend.api.http import Request, json_response, scan_dump
from phish_backend.common import store

SUMMARY_EXCLUDE = {"findings", "calls"}


def list_history(req: Request) -> dict:
    items, nxt = store.scans_for_owner(req.owner, req.limit(), req.query.get("next"))
    return json_response(
        200,
        {"items": [scan_dump(s, SUMMARY_EXCLUDE) for s in items], "next": nxt},
    )
