# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""verdict_detail: what state the captured page was in (taken down, parked, S3 AccessDenied).

Additive only. The browser specialists' code (phish_agents.common.page_state) records the
recognised page state on Finding.page_state, a code-only field the model never sees or writes;
this module turns those into the structured VerdictDetail that code sets on the stored Verdict.
Verdict labels and risk are never changed here: in the
2026-10-31 evaluation the same takedown page was judged `suspicious` or `unknown` depending only
on the lure in its hostname, and this field reports the page state consistently either way.
"""

from collections.abc import Sequence

from phish_contracts.models import Finding, PageState, VerdictDetail

BROWSER_AGENTS = frozenset({"brand_visual", "code_analyst"})

S3_ALL_ACCESS_DISABLED = "s3_all_access_disabled"
VERCEL_451_DEPLOYMENT_UNAVAILABLE = "vercel_451_deployment_unavailable"
PROVIDER_SUSPENDED_PAGE = "provider_suspended_page"
GODADDY_LANDER = "godaddy_lander"
FOR_SALE_LANDER = "for_sale_lander"
S3_ACCESS_DENIED = "s3_access_denied"

# When two captures disagree, the most definitive state wins.
_PRIORITY = (PageState.TAKEN_DOWN, PageState.S3_ACCESS_DENIED, PageState.PARKED)


def verdict_detail(findings: Sequence[Finding]) -> VerdictDetail | None:
    """The page state the browser findings' code recorded, or None when none did."""
    seen: dict[tuple[PageState, str], list[str]] = {}
    for finding in findings:
        if finding.agent not in BROWSER_AGENTS or finding.page_state is None:
            continue
        match = (finding.page_state.page_state, finding.page_state.reason)
        agents = seen.setdefault(match, [])
        if finding.agent not in agents:
            agents.append(finding.agent)
    if not seen:
        return None
    state, reason = min(seen, key=lambda key: (_PRIORITY.index(key[0]), key[1]))
    return VerdictDetail(page_state=state, reason=reason, agents=seen[(state, reason)])
