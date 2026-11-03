# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from phish_backend.api.http import Request, json_response


def get(req: Request) -> dict:
    # Deliberately minimal: no region, ARNs or versions (v1 security test 1).
    return json_response(200, {"ok": True}, disclaimer=False)
