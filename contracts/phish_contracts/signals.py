# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Plain-English titles for signal names.

signal_catalog.json maps a signal name to {"title", "explain"}. web/src/lib/signalCatalog.json
is a byte-identical copy (tests/test_signal_catalog_copy.py); change both together.
"""

import json
import re
from pathlib import Path

CATALOG: dict[str, dict[str, str]] = json.loads(
    Path(__file__).with_name("signal_catalog.json").read_text(encoding="utf-8")
)

_SEPARATORS = re.compile(r"[\s_\-]+")


def _entry(name: str) -> dict[str, str] | None:
    return CATALOG.get(name) or CATALOG.get(name.strip().lower())


def humanize(name: str) -> str:
    """'brand_in_subdomain' -> 'Brand in subdomain'."""
    words = _SEPARATORS.sub(" ", name).strip().lower()
    return words[:1].upper() + words[1:]


def title_for(name: str) -> str:
    """The catalog title, or the humanized name for a signal the catalog does not know."""
    entry = _entry(name)
    return entry["title"] if entry else humanize(name)


def explain_for(name: str) -> str:
    """The catalog explanation, or "" for a signal the catalog does not know."""
    entry = _entry(name)
    return entry["explain"] if entry else ""
