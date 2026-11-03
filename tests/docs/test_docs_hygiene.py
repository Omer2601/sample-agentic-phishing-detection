# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
ONE_PAGE = ["security.md", "threat-model.md", "responsible-ai.md"]
# A 12-digit literal is an AWS account id; only the documentation placeholder is allowed.
ACCOUNT_ID = re.compile(r"(?<![0-9])(?!123456789012)[0-9]{12}(?![0-9])")
STALE = re.compile(
    r"(LiteLLM|judge agent|moderator agent|search_agents|registry-tools|ALB tier|Fargate)", re.I
)
# Legal review prohibits promising outcomes in customer-facing docs.
PROHIBITED = re.compile(r"\bguarantee[ds]?\b", re.I)
LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")


@pytest.mark.parametrize("path", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_dashes(path):
    assert not re.search("[\u2014\u2013]", path.read_text()), f"em or en dash in {path}"


@pytest.mark.parametrize("path", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_account_ids(path):
    hits = ACCOUNT_ID.findall(path.read_text())
    assert not hits, f"account id {hits} in {path}"


@pytest.mark.parametrize("path", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_stale_v1_terms(path):
    assert not STALE.findall(path.read_text()), f"stale v1 term in {path}"


@pytest.mark.parametrize("path", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_prohibited_legal_terms(path):
    assert not PROHIBITED.findall(path.read_text()), f"prohibited legal term in {path}"


@pytest.mark.parametrize("path", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_resolve(path):
    for target in LINK.findall(path.read_text()):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        assert (path.parent / target).exists(), f"{path}: broken link {target}"


@pytest.mark.parametrize("name", ONE_PAGE)
def test_one_page_docs_are_short(name):
    lines = (ROOT / "docs" / name).read_text().count("\n")
    assert lines < 120, f"docs/{name} has {lines} lines"
