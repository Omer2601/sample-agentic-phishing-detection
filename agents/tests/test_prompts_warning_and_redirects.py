# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Prompt rules for provider warnings and redirect chains (the code side is in
test_warning_bypass.py, test_redirect_chain.py and phish_contracts.observation)."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
AGENTS = ROOT / "agents" / "phish_agents"


def flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


ORCHESTRATOR = flat(ROOT / "agents" / "orchestrator" / "prompt.md")


def test_orchestrator_judges_the_real_page_and_caps_an_unseen_one():
    # The 2026-10-16 rule ("weigh it like a confirmed report") made a warning alone phishing.
    assert "like a confirmed report" not in ORCHESTRATOR
    assert "strong supporting third-party evidence, not proof" in ORCHESTRATOR
    assert "judge the verdict from that real page" in ORCHESTRATOR
    assert "`warning_bypass_blocked`" in ORCHESTRATOR
    assert "`risk_score` at most 69" in ORCHESTRATOR and '`"action":"warn"`' in ORCHESTRATOR
    assert "never `phishing` from the warning alone" in ORCHESTRATOR
    assert 'start `summary` with "Page not observed:"' in ORCHESTRATOR


def test_orchestrator_reads_redirects_and_keeps_dead_redirects_site_down():
    assert "Redirect chains are `url_analyst` evidence" in ORCHESTRATOR
    assert "A redirect to a host that does not resolve means the site is down" in ORCHESTRATOR
    assert "a redirect to a host that does not resolve, or a `site_down` verdict" in ORCHESTRATOR


@pytest.mark.parametrize("agent", ["brand_visual", "code_analyst"])
def test_browser_specialists_judge_the_real_page_behind_a_warning(agent):
    prompt = flat(AGENTS / agent / "prompt.md")
    assert "The browser tried once to proceed past it" in prompt
    assert "`warning_bypass_blocked`" in prompt and "use `suspicious` at most" in prompt
    assert "Never call a page phishing from the warning alone" in prompt
    assert "`redirect_chain`" in prompt


def test_url_analyst_calls_check_redirects_once():
    prompt = flat(AGENTS / "url_analyst" / "prompt.md")
    assert "Call `check_redirects` exactly once" in prompt
    for name in ("`redirect_cross_domain`", "`redirect_to_free_hosting`", "`site_unreachable`"):
        assert name in prompt


def test_new_signal_names_are_in_the_catalog():
    catalog = json.loads(
        (ROOT / "contracts" / "phish_contracts" / "signal_catalog.json").read_text("utf-8")
    )
    for name in ("warning_bypass_blocked", "redirect_to_free_hosting", "redirect_cross_domain"):
        assert name in catalog
    assert "like a confirmed report" not in json.dumps(catalog)
    assert "at most suspicious" in catalog["cloudflare_malware_warning"]["explain"]


def test_cross_domain_redirect_entry_fits_any_cross_domain_hop_and_copies_match():
    # Repro acebce58: httpbin.org to example.com (neither free hosting nor a shortener) was
    # shown as "Redirects from a free host or shortener to another site".
    source = ROOT / "contracts" / "phish_contracts" / "signal_catalog.json"
    web_copy = ROOT / "web" / "src" / "lib" / "signalCatalog.json"
    assert source.read_bytes() == web_copy.read_bytes()
    entry = json.loads(source.read_text("utf-8"))["redirect_cross_domain"]
    assert "free host" not in entry["title"] and "shortener" not in entry["title"]
    assert not entry["explain"].startswith("The link starts on a free hosting")


def test_orchestrator_caps_a_www_sibling_capture_like_an_unseen_page():
    rule = ORCHESTRATOR[ORCHESTRATOR.index("- `www_sibling_capture`") :]
    rule = rule[: rule.index(" - ")]
    assert "same tenant or registrant" in rule and "visitors see a certificate warning" in rule
    assert 'at most `suspicious`, `risk_score` 50 to 69 and `"action":"warn"`' in rule
    assert 'start `summary` with "Page not observed:"' in rule
    assert "never makes the verdict `legitimate` on its own" in rule
    assert "Code enforces this cap whatever you answer" in rule


@pytest.mark.parametrize("agent", ["brand_visual", "code_analyst"])
def test_browser_specialists_hold_a_www_sibling_at_suspicious(agent):
    prompt = flat(AGENTS / agent / "prompt.md")
    lead = "`www_sibling_capture` means the certificate does not cover the submitted `www.` name"
    assert lead in prompt
    assert "report both `tls_error` and `www_sibling_capture`" in prompt
    assert "use `suspicious` at most even when the sibling looks like phishing" in prompt
    assert "A clean sibling is never `legitimate` on its own" in prompt
