# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Tests for the dev signing proxy's path-traversal defense.

The proxy re-signs and forwards the browser's request path to API Gateway, so a
smuggled "../" would be signed and forwarded verbatim. These assert that
normalize_request_path rejects traversal in its raw, encoded and mixed forms
before anything is signed, while leaving legitimate /api/* paths (and their
query strings) intact.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sign_proxy  # noqa: E402


class TestRejectsTraversal:
    @pytest.mark.parametrize(
        "raw",
        [
            "/api/../admin",
            "/api/../../etc/passwd",
            "/api/scan/../../secret",
            "/../api/scan",
            "/api/..",
            "..",
            "/..",
        ],
    )
    def test_literal_dotdot_segment_is_rejected(self, raw: str) -> None:
        with pytest.raises(ValueError):
            sign_proxy.normalize_request_path(raw)

    @pytest.mark.parametrize(
        "raw",
        [
            "/api/%2e%2e/admin",
            "/api/%2E%2E/admin",
            "/api/scan%2f..%2fsecret",
            "/api/%2f%2f",
            "/api/foo%5c..%5cbar",
        ],
    )
    def test_percent_encoded_traversal_is_rejected(self, raw: str) -> None:
        with pytest.raises(ValueError):
            sign_proxy.normalize_request_path(raw)

    @pytest.mark.parametrize(
        "raw",
        [
            "/api/scan\\..\\secret",
            "/api\\admin",
        ],
    )
    def test_backslash_is_rejected(self, raw: str) -> None:
        with pytest.raises(ValueError):
            sign_proxy.normalize_request_path(raw)


class TestAllowsLegitimatePaths:
    def test_simple_api_path_passes_through(self) -> None:
        assert sign_proxy.normalize_request_path("/api/scan") == "/api/scan"

    def test_nested_api_path_passes_through(self) -> None:
        assert sign_proxy.normalize_request_path("/api/scan/123") == "/api/scan/123"

    def test_query_string_is_preserved_untouched(self) -> None:
        # The query is not normalized, so encoded values there must survive.
        out = sign_proxy.normalize_request_path("/api/scan?url=https%3a%2f%2fx.example")
        assert out == "/api/scan?url=https%3a%2f%2fx.example"

    def test_redundant_slashes_and_dot_are_collapsed(self) -> None:
        # Single-dot and doubled slashes are harmless; normpath tidies them so the
        # forwarded path is canonical, without rejecting the request.
        assert sign_proxy.normalize_request_path("/api/./scan") == "/api/scan"
        assert sign_proxy.normalize_request_path("/api//scan") == "/api/scan"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


class TestResponseHeaders:
    """The dev proxy relays CSV exports the same way the production tier does."""

    def test_csv_keeps_its_type_and_attachment_filename(self):
        headers = sign_proxy.response_headers(
            {
                "Content-Type": "text/csv; charset=utf-8",
                "Content-Disposition": 'attachment; filename="phish-triage-7d.csv"',
            },
            12,
        )
        assert headers == [
            ("Content-Type", "text/csv"),
            ("Content-Disposition", 'attachment; filename="phish-triage-7d.csv"'),
            ("Content-Length", "12"),
        ]

    def test_other_types_are_labelled_json_without_a_disposition(self):
        headers = sign_proxy.response_headers(
            {"Content-Type": "text/html", "Content-Disposition": "attachment; filename=x"},
            2,
        )
        assert headers == [("Content-Type", "application/json"), ("Content-Length", "2")]

    def test_missing_headers_default_to_json(self):
        assert sign_proxy.response_headers(None, 0) == [
            ("Content-Type", "application/json"),
            ("Content-Length", "0"),
        ]
