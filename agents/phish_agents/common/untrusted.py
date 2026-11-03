# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Fencing for attacker-controlled page content before it reaches a model."""

from __future__ import annotations

import re
from typing import Any

START_MARKER = "<<<UNTRUSTED_PAGE_CONTENT>>>"
END_MARKER = "<<<END_UNTRUSTED_PAGE_CONTENT>>>"

_STRING_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`', re.S)
_WHITESPACE = re.compile(r"\s+")


def wrap_untrusted(label: str, content: str, limit: int) -> str:
    # A page could close the fence early by including the end marker itself.
    cleaned = (
        (content or "")
        .replace(START_MARKER, "[marker removed]")
        .replace(END_MARKER, "[marker removed]")
    )
    body = cleaned[:limit] + ("\n[truncated]" if len(cleaned) > limit else "")
    return f"{START_MARKER}\n[{label}]\n{body}\n{END_MARKER}\n"


def sanitize_for_retry(text: str, limit: int = 4000) -> str:
    """Second-attempt content after a guardrail block: literals emptied, whitespace collapsed."""
    stripped = _STRING_LITERAL.sub(lambda m: m.group(0)[0] * 2, text or "")
    return _WHITESPACE.sub(" ", stripped).strip()[:limit]


def sanitize_values(obj: Any, limit: int = 4000) -> Any:
    """sanitize_for_retry applied to string values only, so keys and structure survive.

    Running sanitize_for_retry over a serialized JSON document empties every key too,
    leaving the model a document of blank strings.
    """
    if isinstance(obj, str):
        return sanitize_for_retry(obj, limit)
    if isinstance(obj, dict):
        return {k: sanitize_values(v, limit) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_values(v, limit) for v in obj]
    return obj
