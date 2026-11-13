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
# A live phishing URL in a doc is one click from harm; anything off this list must be defanged.
SAFE_HOSTS = (
    "example.com",
    "example.org",
    "example.net",
    "example",
    "invalid",
    "test",
    "localhost",
    "iana.org",
    "github.com",
    "amazon.com",
    "amazonaws.com",
    "shields.io",
    "astral.sh",
    "badssl.com",
)
URL_HOST = re.compile(r"https?://([^/\s)\"'`<>|\]]+)")
# Feed hosts the docs or screenshots once showed, kept defanged so this file stays clean.
FEED_HOSTS = (
    "outlook-ashy[.]vercel[.]app",
    "hetvishah697-alt[.]github[.]io",
    "auth-autoscout24[.]ch-77c435fn7d[.]icu",
    "ch-77c435fn7d[.]icu",
    "info-ledgr-live[.]pages[.]dev",
    "mydpd[.]ftzgv[.]cc",
    "raza014[.]github[.]io",
    "dashboard[.]adobeexperience[.]com[.]br",
    "d18390wdgenrs6[.]cloudfront[.]net",
    "community-policy-info[.]vercel[.]app",
    "exoduslarp[.]vercel[.]app",
    "netflix-ui-clone-vikas[.]vercel[.]app",
    "lyloauckland[.]hostel[.]town",
    "dhl[.]smarthub[.]vuelogix[.]ai",
    "g5[.]lu",
    "likpaklix[.]com",
    "vf4933[.]craftum[.]io",
    "blockbook[.]b1tcore[.]org",
    "metamask-docs-fbv47wj26-consensys-ddffed67[.]vercel[.]app",
)


def _unsafe_hosts(text):
    hosts = []
    for raw in URL_HOST.findall(text):
        host = raw.lower().split("@")[-1].split(":")[0].rstrip(".")
        if host.startswith("...") or not host:
            continue
        if not any(host == s or host.endswith("." + s) for s in SAFE_HOSTS):
            hosts.append(host)
    return hosts


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


@pytest.mark.parametrize("path", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_live_urls(path):
    hosts = _unsafe_hosts(path.read_text())
    assert not hosts, f"un-defanged URL host {hosts} in {path}; defang it (hxxps://, [.])"


@pytest.mark.parametrize("path", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_known_feed_hosts(path):
    text = path.read_text().lower()
    hits = [h for h in FEED_HOSTS if h.replace("[.]", ".") in text]
    assert not hits, f"un-defanged feed host {hits} in {path}"


def test_live_url_rules_catch_a_feed_url():
    live = "see https://" + FEED_HOSTS[0].replace("[.]", ".") + "/"
    assert _unsafe_hosts(live) == [FEED_HOSTS[0].replace("[.]", ".")]
    assert _unsafe_hosts("hxxps://outlook-ashy[.]vercel[.]app/ and https://example.com/") == []


@pytest.mark.parametrize("name", ONE_PAGE)
def test_one_page_docs_are_short(name):
    lines = (ROOT / "docs" / name).read_text().count("\n")
    assert lines < 120, f"docs/{name} has {lines} lines"
