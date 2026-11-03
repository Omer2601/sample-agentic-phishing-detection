# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Parse an uploaded URL list: header optional, CRLF or LF, first column is the URL."""

import csv
import io
from dataclasses import dataclass, field

from phish_backend.common.url_input import InvalidUrl, validate_submitted_url

MAX_UPLOAD_BYTES = 1_048_576
UNREADABLE = "CSV is not a readable CSV file (malformed quoting or a field over 128 KB)"
_HEADER_NAMES = {"url", "urls", "link", "links", "website", "site", "domain"}
_MAX_REPORTED_INVALID = 100


@dataclass
class ParsedCsv:
    urls: list[str] = field(default_factory=list)
    invalid: list[dict] = field(default_factory=list)
    invalid_count: int = 0
    duplicates: int = 0
    over_cap: bool = False
    total_rows: int = 0


def parse_url_csv(data: bytes, max_urls: int) -> ParsedCsv:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("CSV must be UTF-8 text") from exc
    parsed = ParsedCsv()
    try:
        _collect(text, max_urls, parsed)
    except csv.Error as exc:
        raise ValueError(UNREADABLE) from exc
    return parsed


def _collect(text: str, max_urls: int, parsed: ParsedCsv) -> None:
    seen: set[str] = set()
    first_value_seen = False
    for row_number, row in enumerate(csv.reader(io.StringIO(text, newline="")), start=1):
        cell = row[0].strip() if row else ""
        if not cell:
            continue
        if not first_value_seen:
            first_value_seen = True
            if cell.lower() in _HEADER_NAMES:
                continue
        parsed.total_rows += 1
        try:
            url = validate_submitted_url(cell)
        except InvalidUrl as exc:
            parsed.invalid_count += 1
            if len(parsed.invalid) < _MAX_REPORTED_INVALID:
                parsed.invalid.append({"row": row_number, "value": cell[:200], "reason": str(exc)})
            continue
        if url in seen:
            parsed.duplicates += 1
            continue
        seen.add(url)
        if len(parsed.urls) >= max_urls:
            parsed.over_cap = True
            continue
        parsed.urls.append(url)
