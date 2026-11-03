# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Request parsing and response helpers for API Gateway REST proxy events."""

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any

from phish_contracts.disclaimer import DISCLAIMER_TEXT
from phish_contracts.models import ReportStatus, ScanRecord, ScanStatus

MAX_BODY_BYTES = 256 * 1024
# interfaces.md: every scan and batch id matches this.
_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_BASE_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class Request:
    method: str
    resource: str
    owner: str
    path: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    raw_body: str | None = None
    # Lower-cased header names.
    headers: dict[str, str] = field(default_factory=dict)
    # True when the web console proxy signed the request for a signed-in user.
    console: bool = False

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def json(self) -> dict[str, Any]:
        if not self.raw_body:
            raise ApiError(400, "request body must be a JSON object")
        if len(self.raw_body.encode()) > MAX_BODY_BYTES:
            raise ApiError(400, "request body is too large")
        try:
            data = json.loads(self.raw_body)
        except json.JSONDecodeError as exc:
            raise ApiError(400, "request body must be valid JSON") from exc
        if not isinstance(data, dict):
            raise ApiError(400, "request body must be a JSON object")
        return data

    def path_id(self) -> str:
        """The {id} path parameter; anything malformed is simply not found."""
        value = self.path.get("id") or ""
        if not _ID_RE.match(value):
            raise ApiError(404, "not found")
        return value

    def limit(self, default: int = 25, maximum: int = 200) -> int:
        raw = self.query.get("limit")
        if raw is None:
            return default
        try:
            value = int(raw)
        except ValueError as exc:
            raise ApiError(400, "limit must be an integer") from exc
        if not 1 <= value <= maximum:
            raise ApiError(400, f"limit must be between 1 and {maximum}")
        return value


def request_from_event(event: dict, owner: str, *, console: bool = False) -> Request:
    body = event.get("body")
    if body and event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8", errors="replace")
    return Request(
        method=event.get("httpMethod", ""),
        resource=event.get("resource", ""),
        owner=owner,
        path=event.get("pathParameters") or {},
        query=event.get("queryStringParameters") or {},
        raw_body=body,
        headers={
            k.lower(): v
            for k, v in (event.get("headers") or {}).items()
            if isinstance(k, str) and isinstance(v, str)
        },
        console=console,
    )


def public_dump(model: Any, exclude: set[str] | None = None) -> dict:
    """A record as the API returns it: the caller's identity (`owner`) is never in a body."""
    return model.model_dump(mode="json", exclude={"owner", *(exclude or ())})


def scan_dump(record: ScanRecord, exclude: set[str] | None = None) -> dict:
    """A scan as the API returns it, plus cost_final: True once no step will add to cost_usd.

    That is a FAILED scan, or a COMPLETE one whose report step has ended. A COMPLETE scan
    whose report is still PENDING has the report turn's cost to come, and a retry reopens a
    FAILED scan, so finality is read from the current row every time.
    """
    body = public_dump(record, exclude)
    body["cost_final"] = record.status == ScanStatus.FAILED or (
        record.status == ScanStatus.COMPLETE and record.report_status != ReportStatus.PENDING
    )
    return body


def json_response(
    status: int, body: Any, *, disclaimer: bool = True, headers: dict[str, str] | None = None
) -> dict:
    """Every JSON object carries the human-review disclaimer; only /health opts out."""
    if disclaimer and isinstance(body, dict):
        body = {**body, "disclaimer": DISCLAIMER_TEXT}
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", **_BASE_HEADERS, **(headers or {})},
        "body": json.dumps(body, default=str),
    }


def csv_response(body: str, filename: str) -> dict:
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": f'attachment; filename="{filename}"',
            **_BASE_HEADERS,
        },
        "body": body,
    }
