# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Specialists must report a certificate error under the browser's own signal name."""

from pathlib import Path

import pytest

AGENTS = Path(__file__).resolve().parents[1] / "phish_agents"


@pytest.mark.parametrize("agent", ["brand_visual", "code_analyst"])
def test_prompt_reports_tls_error_by_its_exact_name(agent):
    prompt = " ".join((AGENTS / agent / "prompt.md").read_text().split())
    # Models invented `tls_error_capture_gap` next to the browser's `tls_error` (2026-10-18).
    assert "report it as the signal `tls_error`, exactly that name" in prompt
    assert "no variants such as `tls_error_capture_gap`" in prompt
