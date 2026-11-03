# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Locate the operator's URL lists. Live phishing URLs are never committed to the repo."""

import os
from pathlib import Path

from phish_backend.batch.csv_parse import parse_url_csv


def data_dir() -> Path:
    return Path(os.environ.get("PHISH_E2E_DATA_DIR", Path(__file__).parent / "data")).expanduser()


def load(name: str) -> bytes:
    return (data_dir() / name).read_bytes()


def count_urls(data: bytes, cap: int = 5000) -> int:
    return len(parse_url_csv(data, cap).urls)


def unique_urls(n: int, base_file: str = "Book1-clean-nohdr.csv") -> list[str]:
    base = parse_url_csv(load(base_file), 5000).urls
    out = []
    for i in range(n):
        url = base[i % len(base)]
        if i >= len(base):
            url += ("&" if "?" in url else "?") + f"e2e={i}"
        out.append(url)
    return out
