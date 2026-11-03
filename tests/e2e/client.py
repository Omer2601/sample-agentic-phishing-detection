# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""SigV4 client for the deployed API, plus polling helpers."""

import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

TERMINAL = {"COMPLETE", "FAILED"}
# API Gateway throttles the stage (50 rps, burst 100); bulk scan fetches must back off.
RETRY_STATUSES = {429, 503}
MAX_ATTEMPTS = 6
_sleep = time.sleep


def require_https(url: str) -> str:
    """Reject anything but an https URL, so file:, ftp: or data: values never get opened."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"refusing non-https URL: {url!r}")
    return url


def _https_opener() -> urllib.request.OpenerDirector:
    # Only the HTTPS handler is installed (no file, ftp, data or redirect handlers), so even
    # a URL that slipped past require_https could not be read from disk or redirected.
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.HTTPSHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
    ):
        opener.add_handler(handler)
    return opener


_OPENER = _https_opener()


def open_https(req: urllib.request.Request, timeout: float = 60):
    require_https(req.full_url)
    return _OPENER.open(req, timeout=timeout)


class ApiClient:
    def __init__(self, base_url: str, region: str, session: boto3.Session | None = None) -> None:
        self.base_url = require_https(base_url).rstrip("/")
        self.region = region
        self.session = session or boto3.Session(region_name=region)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        query: dict | None = None,
        headers: dict | None = None,
        signed: bool = True,
    ) -> tuple[int, Any]:
        for attempt in range(MAX_ATTEMPTS):
            status, parsed = self._request_once(method, path, body, query, headers, signed)
            if status not in RETRY_STATUSES or attempt == MAX_ATTEMPTS - 1:
                return status, parsed
            # Full jitter on top of the exponential step spreads retries from parallel workers.
            _sleep(min(0.5 * 2**attempt, 16.0) * (1 + random.random() / 2))  # noqa: S311 - jitter, not crypto
        return status, parsed

    def _request_once(
        self,
        method: str,
        path: str,
        body: Any,
        query: dict | None,
        headers: dict | None,
        signed: bool,
    ) -> tuple[int, Any]:
        url = self.base_url + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = json.dumps(body).encode() if body is not None else None
        hdrs = {"Content-Type": "application/json", **(headers or {})}
        if signed:
            aws_request = AWSRequest(method=method, url=url, data=data, headers=hdrs)
            SigV4Auth(
                self.session.get_credentials().get_frozen_credentials(), "execute-api", self.region
            ).add_auth(aws_request)
            hdrs = dict(aws_request.headers)
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)  # noqa: S310 - https only, checked by open_https
        try:
            with open_https(req, timeout=60) as resp:
                raw, status, ctype = (
                    resp.read().decode(),
                    resp.status,
                    resp.headers.get("Content-Type", ""),
                )
        except urllib.error.HTTPError as exc:
            raw, status, ctype = exc.read().decode(), exc.code, exc.headers.get("Content-Type", "")
        return status, (json.loads(raw) if "json" in ctype and raw else raw)

    def post_scan(self, url: str) -> dict:
        status, body = self.request("POST", "/scan", body={"url": url})
        assert status == 202, body
        return body

    def get_scan(self, scan_id: str) -> dict:
        status, body = self.request("GET", f"/scans/{scan_id}")
        assert status == 200, body
        return body

    def wait_scan(self, scan_id: str, timeout_s: float = 300) -> dict:
        deadline = time.monotonic() + timeout_s
        while True:
            scan = self.get_scan(scan_id)
            if scan["status"] in TERMINAL or time.monotonic() > deadline:
                return scan
            time.sleep(2)

    def create_json_batch(self, urls: list[str]) -> str:
        status, body = self.request("POST", "/batches", body={"urls": urls})
        assert status == 202, body
        return body["batch_id"]

    def create_upload_batch(self, csv_bytes: bytes, count: int, source: str) -> str:
        status, body = self.request(
            "POST", "/batches", body={"upload": True, "count": count, "source": source}
        )
        assert status == 202, body
        boundary = "phishboundary"
        parts = []
        for name, value in body["upload_fields"].items():
            disposition = f'Content-Disposition: form-data; name="{name}"'
            parts.append(f"--{boundary}\r\n{disposition}\r\n\r\n{value}\r\n".encode())
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="u.csv"\r\n'
            f"Content-Type: text/csv\r\n\r\n".encode()
            + csv_bytes
            + f"\r\n--{boundary}--\r\n".encode()
        )
        req = urllib.request.Request(  # noqa: S310 - https only, checked by open_https
            body["upload_url"],
            data=b"".join(parts),
            method="POST",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        with open_https(req, timeout=60) as resp:
            assert resp.status in (200, 201, 204), resp.status
        return body["batch_id"]

    def batch_detail_all(self, batch_id: str) -> dict:
        status, detail = self.request("GET", f"/batches/{batch_id}", query={"limit": 200})
        assert status == 200, detail
        items, nxt = list(detail["items"]), detail["next"]
        while nxt:
            _, page = self.request("GET", f"/batches/{batch_id}", query={"limit": 200, "next": nxt})
            items += page["items"]
            nxt = page["next"]
        detail["items"] = items
        return detail

    def wait_batch(self, batch_id: str, timeout_s: float, poll_s: float = 5.0) -> dict:
        deadline = time.monotonic() + timeout_s
        while True:
            _, detail = self.request("GET", f"/batches/{batch_id}", query={"limit": 1})
            batch = detail["batch"]
            if detail.get("error") or batch.get("completed_at") or time.monotonic() > deadline:
                return self.batch_detail_all(batch_id)
            time.sleep(poll_s)

    def stats(self, range_: str) -> dict:
        status, body = self.request("GET", "/stats", query={"range": range_})
        assert status == 200, body
        return body
