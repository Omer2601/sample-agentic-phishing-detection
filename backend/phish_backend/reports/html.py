# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Self-contained HTML reports for one scan and for one batch, styled after v1's report.

Every value that reaches the page comes from a URL, a hostile page or a model, so every
value is HTML-escaped at the point it is written, URLs are defanged (in model and page prose
too, with defang_text, so records stored before the worker defanged them are safe), and the
page loads nothing: the Content-Security-Policy allows only the one inline stylesheet (by
hash), so even a value that slipped past escaping could not run script or fetch anything.
"""

import base64
import hashlib
from collections.abc import Iterable
from decimal import Decimal
from html import escape
from urllib.parse import quote, urlparse

from phish_contracts.disclaimer import DISCLAIMER_MARKDOWN, DISCLAIMER_TEXT, DISCLAIMER_TITLE
from phish_contracts.models import (
    SPECIALISTS,
    BatchRecord,
    CallKind,
    CodeInsights,
    Finding,
    FindingStatus,
    RedirectHop,
    ReportStatus,
    ScanRecord,
    Severity,
    Usage,
    Verdict,
    defang,
    defang_text,
)
from phish_contracts.signals import explain_for, title_for

SPECIALIST_LABELS = {
    "url_analyst": "URL analyst",
    "brand_visual": "Brand and visual",
    "code_analyst": "Code analyst",
}
_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
_ACTION_LABELS = {"block": "Block", "warn": "Warn", "allow": "Allow"}
# Display labels keyed on the raw string so a verdict value added to the contract later
# (error_404) renders correctly here before and after the enum knows about it.
_VERDICT_LABELS = {"error_404": "Error 404", "site_down": "Site down"}


def verdict_label(value: str) -> str:
    """Human label for a verdict value: "Error 404", "Site down", else capitalised."""
    return _VERDICT_LABELS.get(value, value.capitalize())


# The console's verdict palette (web/src/lib/verdictStyle.ts): phishing red, suspicious
# amber, legitimate blue. Amber text uses a darker step so it keeps contrast on white.
REPORT_CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
@page { margin: 14mm 12mm; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', sans-serif;
  background: #f1f5f9; color: #1e293b; line-height: 1.55; padding: 2rem 1rem;
  font-size: 15px; }
.container { max-width: 960px; margin: 0 auto; }
.header { background: #0f172a; border-radius: 14px; padding: 2rem 2.25rem; color: #fff;
  margin-bottom: 1.25rem; }
.header h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.01em;
  margin-bottom: 0.25rem; }
.header .meta { color: #94a3b8; font-size: 0.8rem; }
.header .url { margin-top: 1rem; padding: 0.6rem 0.9rem; background: rgba(255,255,255,0.08);
  border-radius: 8px; font-family: ui-monospace, 'SF Mono', monospace; font-size: 0.85rem;
  color: #e2e8f0; word-break: break-all; }
.verdict-box { background: #f8fafc; border: 1px solid #cbd5e1; border-left-width: 6px;
  border-radius: 12px; padding: 1.5rem 1.75rem; margin: 1.25rem 0; }
.verdict-box h2 { color: #475569; font-size: 1.9rem; font-weight: 800;
  letter-spacing: 0.02em; line-height: 1.1; }
.verdict-box .sub { color: #475569; font-size: 0.85rem; margin-top: 0.4rem;
  font-weight: 600; }
.verdict-box .summary { color: #334155; font-size: 0.95rem; margin-top: 0.9rem;
  max-width: 70ch; }
.v-phishing { background: #fdf0f0; border-color: #d03b3b; }
.v-phishing h2, .v-phishing .sub { color: #b42f2f; }
.v-suspicious { background: #fff8e6; border-color: #eda100; }
.v-suspicious h2, .v-suspicious .sub { color: #8a5d00; }
.v-legitimate { background: #eef5fd; border-color: #2a78d6; }
.v-legitimate h2, .v-legitimate .sub { color: #1f5fae; }
.v-error_404 { background: #fff8e6; border-color: #eda100; }
.v-error_404 h2, .v-error_404 .sub { color: #8a5d00; }
.v-site_down { background: #f1f5f9; border-color: #64748b; }
.v-site_down h2, .v-site_down .sub { color: #475569; }
.disclaimer { background: #fffbeb; border: 3px solid #78350f; border-radius: 10px;
  color: #451a03; padding: 0.9rem 1.2rem; margin-bottom: 1.25rem; font-weight: 700;
  font-size: 1rem; line-height: 1.45; }
.disclaimer .title { display: block; font-size: 1.1rem; font-weight: 800;
  text-transform: uppercase; letter-spacing: 0.02em; }
.disclaimer.footer-notice { margin: 1.75rem 0 0; }
.disclaimer-note { border-left: 4px solid #78350f; background: #fffbeb; color: #451a03;
  font-weight: 700; font-size: 0.82rem; padding: 0.4rem 0.75rem; margin-top: 0.9rem;
  border-radius: 4px; }
caption.disclaimer-note { display: table-caption; caption-side: top; text-align: left;
  margin: 0 0 0.6rem; }
.metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem;
  margin: 1.25rem 0; }
.metric { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px;
  padding: 0.9rem 1rem; }
.metric .label { font-size: 0.75rem; color: #64748b; font-weight: 500; }
.metric .value { font-size: 1.3rem; font-weight: 700; color: #0f172a; margin-top: 0.15rem;
  font-variant-numeric: tabular-nums; }
.section { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
  padding: 1.4rem 1.6rem; margin-bottom: 0.9rem; }
.section h3 { font-size: 1rem; color: #0f172a; margin-bottom: 0.9rem; font-weight: 700;
  padding-bottom: 0.5rem; border-bottom: 1px solid #e2e8f0; }
.section p, .section li { font-size: 0.9rem; color: #334155; }
.section ul { padding-left: 1.2rem; }
.section li + li { margin-top: 0.25rem; }
.facts { display: flex; flex-wrap: wrap; gap: 0.4rem 1.5rem; margin-bottom: 1rem;
  font-size: 0.85rem; color: #475569; }
.facts strong { color: #0f172a; }
.signal { margin-bottom: 0.85rem; }
.signal .name { font-weight: 600; color: #0f172a; font-size: 0.9rem; }
.signal .explain { font-size: 0.84rem; color: #64748b; margin-top: 0.1rem; }
.capture-note { font-size: 0.86rem; color: #475569; margin-bottom: 0.9rem; }
.not-observed { margin-top: 0.6rem; font-size: 0.9rem; font-weight: 600; color: #8a5d00; }
.capped-from { margin-top: 0.3rem; font-size: 0.85rem; color: #5f6b7a; }
.insights { margin-top: 1rem; }
.insights h4 { font-size: 0.9rem; color: #0f172a; margin: 0.6rem 0 0.4rem; }
.signal .evidence { white-space: pre-wrap; word-break: break-word; font-size: 0.86rem;
  color: #475569; margin-top: 0.1rem; }
.sev { display: inline-block; border-radius: 4px; padding: 0.05rem 0.4rem;
  margin-right: 0.45rem; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.03em;
  vertical-align: 0.08em; }
.sev-critical { background: #b42f2f; color: #fff; }
.sev-high { background: #fdf0f0; color: #b42f2f; }
.sev-medium { background: #fff8e6; color: #8a5d00; }
.sev-low { background: #f1f5f9; color: #475569; }
.pill { display: inline-block; border-radius: 999px; padding: 0.05rem 0.55rem;
  font-size: 0.78rem; font-weight: 600; border: 1px solid #cbd5e1; color: #475569; }
.pill.v-phishing { color: #b42f2f; }
.pill.v-suspicious { color: #8a5d00; }
.pill.v-legitimate { color: #1f5fae; }
.pill.v-error_404 { color: #8a5d00; }
.pill.v-site_down { color: #475569; }
.muted { color: #64748b; }
table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
th { text-align: left; color: #64748b; font-size: 0.75rem; font-weight: 600;
  padding: 0.5rem; border-bottom: 1px solid #e2e8f0; }
td { padding: 0.5rem; border-bottom: 1px solid #f1f5f9; color: #334155; vertical-align: top; }
tr:last-child td { border-bottom: 0; }
td.url { font-family: ui-monospace, 'SF Mono', monospace; font-size: 0.8rem;
  word-break: break-all; }
td.num { font-variant-numeric: tabular-nums; }
a { color: #4f46e5; }
pre { white-space: pre-wrap; word-break: break-word; font-size: 0.82rem; color: #334155;
  font-family: ui-monospace, 'SF Mono', 'Fira Code', monospace; line-height: 1.6; }
.footer { text-align: center; color: #64748b; font-size: 0.75rem; margin-top: 1.75rem; }
@media (max-width: 640px) { .metrics { grid-template-columns: repeat(2, 1fr); }
  .header, .section, .verdict-box { padding: 1.1rem 1.2rem; } }
@media print {
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { background: #fff; padding: 0; font-size: 11pt; }
  .container { max-width: none; }
  .header { background: #fff; color: #0f172a; border: 1px solid #cbd5e1; padding: 1rem 1.2rem; }
  .header .meta { color: #475569; }
  .header .url { background: #f1f5f9; color: #0f172a; }
  .section, .metric, .verdict-box, .header { box-shadow: none; }
  .section, .metric, .verdict-box, .signal, tr, .disclaimer { break-inside: avoid; }
  .disclaimer, .disclaimer-note { border-color: #000; color: #000; background: #fff; }
  .section h3 { break-after: avoid; }
  .metrics { grid-template-columns: repeat(4, 1fr); }
  a { color: #0f172a; text-decoration: none; }
}
"""
REPORT_CSS_HASH = (
    "sha256-" + base64.b64encode(hashlib.sha256(REPORT_CSS.encode()).digest()).decode()
)
_CSP = f"default-src 'none'; style-src '{REPORT_CSS_HASH}'; base-uri 'none'; form-action 'none'"


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _seconds(ms: int | None) -> str:
    return "n/a" if ms is None else f"{ms / 1000:.1f} s"


def _cost(usd: Decimal) -> str:
    return f"${Decimal(usd):.4f}"


def _scan_cost(record: ScanRecord) -> str:
    # A model with no price is not free: its tokens are missing from cost_usd.
    return "unknown" if record.unpriced_models else _cost(record.cost_usd)


def _when(value) -> str:
    return "n/a" if value is None else value.strftime("%Y-%m-%d %H:%M:%S UTC")


def _without_leading_disclaimer(markdown: str) -> str:
    """The page opens with its own banner, so drop the report's leading disclaimer line."""
    body = markdown.lstrip()
    if not body.startswith(DISCLAIMER_MARKDOWN):
        return markdown
    return body[len(DISCLAIMER_MARKDOWN) :].lstrip().removeprefix("---").lstrip()


def _page(title: str, body: str) -> str:
    return (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">\n'
        '<meta name="referrer" content="no-referrer">\n'
        f"<title>{_e(title)}</title>\n<style>{REPORT_CSS}</style>\n</head>\n<body>\n"
        f'<div class="container">\n{_banner()}\n{body}\n{_banner(footer=True)}\n'
        '<div class="footer">Phishing triage with Amazon Bedrock AgentCore.</div>\n'
        "</div>\n</body>\n</html>\n"
    )


def _banner(*, footer: bool = False) -> str:
    """The bold human-review notice: at the top of every report and again at the bottom."""
    extra = " footer-notice" if footer else ""
    return (
        f'<div class="disclaimer{extra}" role="note"><span class="title">'
        f"{_e(DISCLAIMER_TITLE)}</span>{_e(DISCLAIMER_TEXT)}</div>"
    )


def _note() -> str:
    return f'<div class="disclaimer-note">{_e(DISCLAIMER_TITLE)}. {_e(DISCLAIMER_TEXT)}</div>'


def _header(title: str, meta: str, url: str | None = None) -> str:
    line = f'<div class="url">{_e(defang(url))}</div>' if url is not None else ""
    return f'<div class="header"><h1>{_e(title)}</h1><div class="meta">{_e(meta)}</div>{line}</div>'


def _metrics(items: Iterable[tuple[str, str]]) -> str:
    cells = "".join(
        f'<div class="metric"><div class="label">{_e(label)}</div>'
        f'<div class="value">{_e(value)}</div></div>'
        for label, value in items
    )
    return f'<div class="metrics">{cells}</div>'


def _list(items: list[str]) -> str:
    if not items:
        return '<p class="muted">None</p>'
    return "<ul>" + "".join(f"<li>{_e(defang_text(i))}</li>" for i in items) + "</ul>"


def _finding_state(finding: Finding | None) -> str:
    if finding is None:
        return "No report"
    if finding.status == FindingStatus.BLOCKED:
        return "Blocked by guardrail"
    if finding.status == FindingStatus.ERROR:
        return "Specialist error"
    return finding.verdict.value.capitalize()


def _defanged(url: str) -> str:
    """Defang a URL unless the producer already did (defanging twice garbles "[.]")."""
    return url if "[.]" in url else defang(url)


def _insights_html(insights: CodeInsights) -> str:
    """A compact view of what the page's code does. Every value is producer data: escaped."""
    facts = [f"{insights.script_count} scripts", f"{insights.script_kb} KB of script"]
    parts = [
        f'<div class="insights"><h4>{_e("What the page's code does")}</h4><div class="facts">',
        "".join(f"<span>{_e(f)}</span>" for f in facts),
        "</div>",
    ]
    if insights.endpoints:
        parts.append(
            "<table><tr><th>Request</th><th>URL (defanged)</th><th>Off-domain</th></tr>"
            + "".join(
                f'<tr><td>{_e(x.kind)}</td><td class="url">{_e(_defanged(x.url))}</td>'
                f"<td>{'yes' if x.off_domain else 'no'}</td></tr>"
                for x in insights.endpoints
            )
            + "</table>"
        )
    if insights.forms:
        parts.append(
            "<table><tr><th>Form action (defanged)</th><th>Fields</th><th>Sent by script</th></tr>"
            + "".join(
                f'<tr><td class="url">{_e(_defanged(f.action)) if f.action else "none"}</td>'
                f"<td>{_e(', '.join(f.fields)) or 'none'}</td>"
                f"<td>{'yes' if f.submits_via_js else 'no'}</td></tr>"
                for f in insights.forms
            )
            + "</table>"
        )
    if insights.external_script_hosts:
        hosts = ", ".join(_defanged(h) for h in insights.external_script_hosts)
        parts.append(f"<p>Scripts loaded from: {_e(hosts)}</p>")
    parts.append("</div>")
    return "".join(parts)


_HOP_VIA = {
    "start": "Submitted URL",
    "http": "HTTP redirect",
    "client": "Script or meta refresh",
    "warning_bypass": "Proceeded past the warning",
}


def _chain_html(chain: list[RedirectHop]) -> str:
    """The redirect chain, every URL defanged and escaped; empty when there is only one hop."""
    if len(chain) < 2:
        return ""
    rows = []
    for hop in chain:
        marks = [
            m
            for m, on in (
                ("new site", hop.cross_domain),
                ("free hosting", hop.free_hosting),
                ("shortener", hop.shortener),
            )
            if on
        ]
        if hop.error:
            marks.append(f"failed: {hop.error}")
        rows.append(
            f"<tr><td>{_e(_HOP_VIA.get(hop.via, hop.via))}</td>"
            f'<td class="url">{_e(defang(hop.url))}</td>'
            f'<td class="num">{_e(hop.status if hop.status is not None else "")}</td>'
            f"<td>{_e(defang_text(', '.join(marks)))}</td></tr>"
        )
    return (
        f'<div class="insights"><h4>{_e("Redirect chain")}</h4>'
        "<table><tr><th>How</th><th>URL (defanged)</th><th>Status</th><th>Marks</th></tr>"
        + "".join(rows)
        + "</table></div>"
    )


def _signal_html(s) -> str:
    explain = explain_for(s.name)
    return (
        f'<div class="signal"><div class="name"><span class="sev sev-{_e(s.severity.value)}">'
        f"{_e(s.severity.value)}</span>{_e(title_for(s.name))}</div>"
        + (f'<div class="explain">{_e(explain)}</div>' if explain else "")
        + f'<div class="evidence">{_e(defang_text(s.evidence))}</div></div>'
    )


def _specialist_section(agent: str, finding: Finding | None) -> str:
    label = SPECIALIST_LABELS[agent]
    if finding is None:
        return f'<div class="section"><h3>{_e(label)}</h3><p class="muted">No report</p></div>'
    facts = [("Verdict", _finding_state(finding))]
    if finding.status == FindingStatus.OK:
        facts.append(("Confidence", f"{finding.confidence}%"))
    facts += [
        ("Latency", _seconds(finding.latency_ms)),
        ("Tokens", f"{finding.usage.input_tokens} in, {finding.usage.output_tokens} out"),
    ]
    fact_html = "".join(f"<span>{_e(k)}: <strong>{_e(v)}</strong></span>" for k, v in facts)
    signals = sorted(finding.signals, key=lambda s: _SEVERITY_ORDER.index(s.severity))
    if signals:
        signal_html = "".join(_signal_html(s) for s in signals)
    else:
        signal_html = '<p class="muted">No signals recorded.</p>'
    note = f'<p class="capture-note">{_e(finding.capture_note)}</p>' if finding.capture_note else ""
    insights = _insights_html(finding.insights) if finding.insights else ""
    chain = _chain_html(finding.redirect_chain)
    return (
        f'<div class="section"><h3>{_e(label)}</h3><div class="facts">{fact_html}</div>'
        f"{note}{signal_html}{chain}{insights}</div>"
    )


def _usage_by_model(record: ScanRecord) -> dict[str, tuple[int, int]]:
    # The same usages the worker prices: the harness call plus each specialist's Finding.
    usages: list[Usage] = [c.usage for c in record.calls if c.kind == CallKind.HARNESS and c.usage]
    usages += [f.usage for f in record.findings]
    totals: dict[str, tuple[int, int]] = {}
    for u in usages:
        seen_in, seen_out = totals.get(u.model_id, (0, 0))
        totals[u.model_id] = (seen_in + u.input_tokens, seen_out + u.output_tokens)
    return totals


def _unpriced_note(record: ScanRecord) -> str:
    if not record.unpriced_models:
        return ""
    return (
        f'<p class="muted">No price is known for {_e(", ".join(record.unpriced_models))}, so '
        f"the total is unknown. The priced models cost {_e(_cost(record.cost_usd))}.</p>"
    )


def render_scan_report(record: ScanRecord) -> str:
    """The report for one COMPLETE scan: verdict, report, one section per specialist."""
    verdict = record.verdict
    if verdict is None:
        raise ValueError("a scan report needs a verdict")
    label = verdict.verdict.value
    # total_ms ends when the verdict is stored; the report turn runs after it, so it is
    # shown on its own row and never added to the orchestrator's time.
    harness = [c for c in record.calls if c.kind == CallKind.HARNESS]
    orchestrator_ms = sum(c.duration_ms for c in harness if c.name != "report")
    report_ms = sum(c.duration_ms for c in harness if c.name == "report")
    findings = {f.agent: f for f in record.findings}
    body = [
        _header(
            "Phishing analysis report",
            f"Scan {record.scan_id}  ·  completed {_when(record.completed_at)}",
            record.url,
        ),
        f'<div class="verdict-box v-{_e(label)}"><h2>{_e(verdict_label(label).upper())}</h2>'
        f'<div class="sub">Risk {verdict.risk_score}/100  ·  {_e(verdict.confidence.value)} '
        f"confidence  ·  Recommended action: {_e(_ACTION_LABELS[verdict.action.value])}</div>"
        f'<div class="summary">{_e(defang_text(verdict.summary))}</div>'
        + (
            f'<p class="not-observed">{_e(NOT_OBSERVED_NOTICE)}</p>'
            if verdict.page_observed is False
            else ""
        )
        + _capped_note(verdict)
        + f"{_note()}</div>",
        _metrics(
            [
                ("Risk score", f"{verdict.risk_score}/100"),
                ("Total time", _seconds(record.total_ms)),
                ("Token cost", _scan_cost(record)),
                ("Action", _ACTION_LABELS[verdict.action.value]),
            ]
        ),
        '<div class="section"><h3>Timings</h3><table>'
        + "".join(
            f'<tr><td>{_e(k)}</td><td class="num">{_e(v)}</td></tr>'
            for k, v in [
                ("Queued at", _when(record.queued_at)),
                ("Started at", _when(record.started_at)),
                ("Completed at", _when(record.completed_at)),
                ("Waiting in the queue", _seconds(record.queue_wait_ms)),
                ("Orchestrator (harness)", _seconds(orchestrator_ms or None)),
                ("Total, to the verdict", _seconds(record.total_ms)),
            ]
            + (
                [("Report writing (harness, after the verdict)", _seconds(report_ms))]
                if report_ms
                else []
            )
            + [
                (f"{SPECIALIST_LABELS[a]} latency", _seconds(findings[a].latency_ms))
                for a in SPECIALISTS
                if a in findings
            ]
        )
        + "</table></div>",
        '<div class="section"><h3>Cost</h3><table><tr><th>Model</th><th>Input tokens</th>'
        "<th>Output tokens</th></tr>"
        + "".join(
            f'<tr><td>{_e(model)}</td><td class="num">{i}</td><td class="num">{o}</td></tr>'
            for model, (i, o) in sorted(_usage_by_model(record).items())
        )
        + f"</table><p>Total token cost: <strong>{_e(_scan_cost(record))}</strong></p>"
        + _unpriced_note(record)
        + "</div>",
        *(_specialist_section(a, findings.get(a)) for a in SPECIALISTS),
        '<div class="section"><h3>Disagreements resolved</h3>'
        + _list(verdict.disagreements)
        + "</div>",
        '<div class="section"><h3>Missed by the specialists</h3>'
        + _list(verdict.missed_by_specialists)
        + "</div>",
    ]
    if record.guardrail_events:
        body.append(
            '<div class="section"><h3>Guardrail events</h3>'
            + _list(record.guardrail_events)
            + "</div>"
        )
    body.append(_report_section(record))
    return _page(f"Phishing analysis report: {defang(record.url)}", "\n".join(body))


def _capped_note(verdict: Verdict) -> str:
    """One line when the page-not-observed cap changed what the model answered, else ""."""
    model = verdict.capped_from
    if model is None:
        return ""
    return (
        f'<p class="capped-from">Before the page-not-observed cap the model answered '
        f"{_e(verdict_label(model.verdict.value))}, risk {model.risk_score}/100, "
        f"action {_e(_ACTION_LABELS[model.action.value])}.</p>"
    )


NOT_OBSERVED_NOTICE = (
    "Page not observed: the browser never saw the site's real page (a provider warning, bot "
    "check or failed capture stood in front of it), so this verdict rests on the URL and on what "
    "the browser did see."
)
PENDING_NOTICE = (
    "The full report is still being written. The verdict and specialist findings above are "
    "final; reload this page in a minute to see the report."
)
FAILED_NOTICE = (
    "The full report could not be written. The verdict and specialist findings above are "
    "still valid."
)


def _report_section(record: ScanRecord) -> str:
    """The orchestrator report, or a notice while it is PENDING or after it FAILED."""
    if record.report_status == ReportStatus.PENDING:
        return (
            '<div class="section"><h3>Orchestrator report</h3>'
            f'<p class="muted">{PENDING_NOTICE}</p></div>'
        )
    if record.report_status == ReportStatus.FAILED:
        reason = f" Reason: {_e(record.report_error)}" if record.report_error else ""
        return (
            '<div class="section"><h3>Orchestrator report</h3>'
            f'<p class="muted">{FAILED_NOTICE}{reason}</p></div>'
        )
    return (
        '<div class="section"><h3>Orchestrator report</h3>'
        f"<pre>{_e(defang_text(_without_leading_disclaimer(record.verdict.report_markdown)))}"
        "</pre></div>"
    )


def _safe_console(console_url: str) -> str:
    """The console origin for scan links, or "" when it is not a plain https origin."""
    parsed = urlparse(console_url or "")
    if parsed.scheme != "https" or not parsed.netloc or parsed.path not in ("", "/"):
        return ""
    return f"https://{parsed.netloc}"


def render_batch_report(batch: BatchRecord, scans: list[ScanRecord], *, console_url: str) -> str:
    """One row per scan: defanged URL, status, verdict, risk, confidence, cost, scan link."""
    console = _safe_console(console_url)
    rows = []
    for index, scan in enumerate(scans, start=1):
        v = scan.verdict
        scan_cell = _e(scan.scan_id)
        if console:
            href = f"{console}/results/{quote(scan.scan_id, safe='')}"
            scan_cell = f'<a href="{_e(href)}" rel="noopener noreferrer">{scan_cell}</a>'
        rows.append(
            f'<tr><td class="num">{index}</td><td class="url">{_e(defang(scan.url))}</td>'
            f"<td>{_e(scan.status.value)}</td>"
            + (
                f'<td><span class="pill v-{_e(v.verdict.value)}">'
                f"{_e(verdict_label(v.verdict.value))}</span></td>"
                if v
                else '<td class="muted">n/a</td>'
            )
            + f'<td class="num">{v.risk_score if v else "n/a"}</td>'
            f"<td>{_e(v.confidence.value) if v else 'n/a'}</td>"
            f'<td class="num">{_e(_scan_cost(scan))}</td><td>{scan_cell}</td></tr>'
        )
    counts = {k.value: n for k, n in batch.verdict_counts.items()}
    body = [
        _header(
            "Batch phishing report",
            f"Batch {batch.batch_id}  ·  created {_when(batch.created_at)}  ·  "
            f"{len(scans)} of {batch.total} URLs",
        ),
        _metrics(
            [
                ("URLs", str(batch.total)),
                ("Phishing", str(counts.get("phishing", 0))),
                ("Wall clock", _seconds(batch.wall_clock_ms)),
                (
                    "Token cost",
                    ("at least " if any(s.unpriced_models for s in scans) else "")
                    + _cost(batch.cost_usd),
                ),
            ]
        ),
        '<div class="section"><h3>Scans</h3><table><caption class="disclaimer-note">'
        f"{_e(DISCLAIMER_TITLE)}. {_e(DISCLAIMER_TEXT)}</caption>"
        "<tr><th>#</th><th>URL (defanged)</th>"
        "<th>Status</th><th>Verdict</th><th>Risk</th><th>Confidence</th><th>Cost</th>"
        "<th>Scan</th></tr>" + "".join(rows) + "</table></div>",
    ]
    return _page(f"Batch phishing report: {batch.batch_id}", "\n".join(body))
