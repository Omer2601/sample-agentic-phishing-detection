# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The disclaimer and the API auth statement must stay documented where users look."""

import json
import re
from pathlib import Path

import pytest

from phish_contracts.disclaimer import DISCLAIMER_TEXT

ROOT = Path(__file__).resolve().parents[2]


def read(name: str) -> str:
    return (ROOT / name).read_text()


def test_api_sample_json_shows_the_disclaimer_field():
    api = read("docs/api.md")
    assert f'"disclaimer": "{DISCLAIMER_TEXT}"' in api
    assert "`disclaimer`" in api and "last column" in api


@pytest.mark.parametrize("name", ["docs/api.md", "README.md", "docs/threat-model.md"])
def test_api_auth_is_stated_plainly(name):
    text = read(name)
    assert re.search(r"SigV4", text)
    assert re.search(r"Cognito gates only the web console", text)
    assert re.search(r"except `(GET )?/health`", text)


@pytest.mark.parametrize("name", ["docs/api.md", "README.md"])
def test_cli_usage_is_shown(name):
    assert "awscurl --service execute-api" in read(name)


def test_api_md_documents_the_python_sigv4_example():
    assert "SigV4Auth" in read("docs/api.md")


def test_api_sample_blocks_are_valid_json_where_they_claim_to_be():
    for block in re.findall(r"```json\n(.*?)```", read("docs/api.md"), re.S):
        if '"...' in block or "..." in block.replace("\\n...", ""):
            continue
        json.loads(block)


def test_responsible_ai_lists_every_place_the_notice_appears():
    text = read("docs/responsible-ai.md")
    for place in ("JSON response", "report_markdown", "HTML reports", "CSV"):
        assert place in text
