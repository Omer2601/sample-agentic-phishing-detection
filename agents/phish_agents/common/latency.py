# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Opt-in latency settings, read once from the Runtime environment (the stack sets them).

LATENCY_BUDGETS=1 (-c latencyBudgets=true): the capture budgets, client timeouts and page
deadline sized for the tools Runtime's session start lag. CODE_TEXT_BUDGET=half
(-c codeTextBudget=half): code_analyst's capture keeps half the script text and a shorter DOM.
Unset keeps the earlier values everywhere. Ported from a fork of this sample.
"""

from __future__ import annotations

import os

TIGHT_BUDGETS = os.environ.get("LATENCY_BUDGETS", "").strip() == "1"
HALF_CODE_TEXT = os.environ.get("CODE_TEXT_BUDGET", "").strip().lower() == "half"
