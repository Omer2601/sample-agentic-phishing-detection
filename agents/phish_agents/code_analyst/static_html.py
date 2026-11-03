# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""code_analyst's fallback when the browser cannot load the page: a bounded excerpt of the
raw HTML that the guarded HTTP probe (common/http_probe.py) read.

The bytes are tokenized with the standard library's html.parser, which only splits text
into tags and attributes: no script runs, no subresource is fetched, nothing is rendered.
The excerpt is untrusted page content and reaches the model fenced like the browser capture.
It is never built from a Cloudflare warning or a bot challenge: that HTML is the block
page, not the site.
"""

from __future__ import annotations

import codecs
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from phish_agents.code_analyst.heuristics import derive_signals
from phish_agents.common.browser import site_block_signal
from phish_agents.common.http_probe import http_probe

SOURCE = "raw HTML, not rendered, scripts not run"
MAX_FORMS = 20
MAX_INPUTS = 30
MAX_SCRIPT_SRCS = 60
MAX_INLINE_SCRIPTS = 20
INLINE_SCRIPT_LIMIT = 2_000
INLINE_TOTAL_LIMIT = 12_000
MAX_IFRAMES = 20
MAX_HOSTS = 30
URL_LIMIT = 300
TITLE_LIMIT = 200
_HTML_TYPES = ("text/html", "application/xhtml+xml")
_CHARSET = re.compile(r"charset=[\"']?([A-Za-z0-9._-]+)", re.I)


class _Excerpt(HTMLParser):
    """Everything in the page, uncapped: the body is at most 64 KB (http_probe), so the full
    parse is bounded, and signals are derived from all of it before the excerpt is cut."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title, self.meta_refresh, self.base_href = "", None, None
        self.forms: list[dict] = []
        self.loose_inputs: list[str] = []
        self.script_srcs: list[str] = []
        self.inline_scripts: list[str] = []
        self.iframes: list[str] = []
        self._form: dict | None = None
        self._in_title = self._in_script = False
        self._script = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        form = self._form
        if tag == "form":
            self._form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower()[:10],
                "fields": [],
                "formactions": [],
            }
            self.forms.append(self._form)
        elif tag == "input":
            kind = (a.get("type") or "text").lower()[:20]
            if form is not None:
                form["fields"].append((kind, a.get("name", "")[:80]))
            else:
                self.loose_inputs.append(kind)
        elif tag == "script":
            src = a.get("src", "")
            if src:
                self.script_srcs.append(src)
            else:
                self._in_script, self._script = True, ""
        elif tag == "iframe":
            self.iframes.append(a.get("src", ""))
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh = a.get("content", "")[:URL_LIMIT]
        elif tag == "base" and self.base_href is None and a.get("href"):
            self.base_href = a["href"]
        elif tag == "title":
            self._in_title = True
        # A submit button's formaction overrides its form's action.
        if tag in ("input", "button") and form is not None and a.get("formaction"):
            form["formactions"].append(a["formaction"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
        elif tag == "title":
            self._in_title = False
        elif tag == "script" and self._in_script:
            self._in_script = False
            if text := self._script.strip():
                self.inline_scripts.append(text)

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script += data
        elif self._in_title and len(self.title) < TITLE_LIMIT:
            self.title = (self.title + data)[:TITLE_LIMIT]


def _decode(body: bytes, content_type: str) -> str:
    match = _CHARSET.search(content_type or "")
    encoding = "utf-8"
    if match:
        try:
            encoding = codecs.lookup(match.group(1)).name
        except LookupError:
            pass
    return body.decode(encoding, errors="replace")


def _resolve(base: str, url: str) -> str:
    if not url:
        return ""
    try:
        return urljoin(base, url)
    except ValueError:
        return url


def _external_hosts(final_url: str, urls: list[str]) -> list[str]:
    home = (urlparse(final_url).hostname or "").lower()
    hosts: set[str] = set()
    for url in urls:
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            continue
        if host and host != home:
            hosts.add(host)
    return sorted(hosts)


def _form(form: dict, base: str) -> dict:
    # Hidden inputs last, so padding a form with them cannot push its password field out.
    fields = sorted(form["fields"], key=lambda field: field[0] == "hidden")
    return {
        "action": _resolve(base, form["action"]),
        "method": form["method"],
        "inputs": [kind for kind, _ in fields],
        "names": [name for _, name in fields],
        "formactions": [_resolve(base, url) for url in form["formactions"]],
    }


def _cut_form(form: dict) -> dict:
    out = {
        "action": form["action"][:URL_LIMIT],
        "method": form["method"],
        "inputs": form["inputs"][:MAX_INPUTS],
        "names": form["names"][:MAX_INPUTS],
    }
    if form["formactions"]:
        out["formactions"] = [u[:URL_LIMIT] for u in form["formactions"][:MAX_INPUTS]]
    if len(form["inputs"]) > MAX_INPUTS:
        out["inputs_dropped"] = len(form["inputs"]) - MAX_INPUTS
    return out


def _cut_scripts(texts: list[str]) -> list[str]:
    out, left = [], INLINE_TOTAL_LIMIT
    for text in texts[:MAX_INLINE_SCRIPTS]:
        chunk = text[: min(INLINE_SCRIPT_LIMIT, left)]
        if not chunk:
            break
        out.append(chunk)
        left -= len(chunk)
    return out


def excerpt(probe: dict) -> dict | None:
    """The bounded excerpt of a probe result, or None when there is no site HTML to show:
    the probe did not end on a page, the page is not HTML, or it is a block page.

    derived_signals and external_hosts come from the whole page and lead the excerpt, so
    padding (many decoy forms, scripts or inputs) cannot push the evidence past the caps or
    the model's 30,000 character fence; what the caps dropped is counted in `dropped`.
    """
    status, body = probe.get("final_status"), probe.get("body") or b""
    if probe.get("outcome") != "ok" or not isinstance(status, int) or not 200 <= status < 400:
        return None
    # A page without a declared HTML type is not parsed as one (missing type included).
    content_type = (probe.get("content_type") or "").lower()
    if not content_type.startswith(_HTML_TYPES):
        return None
    if probe.get("cf_mitigated") or not body:
        return None
    parser = _Excerpt()
    parser.feed(_decode(body, content_type))
    parser.close()
    title = parser.title.strip()
    # A Cloudflare warning, bot check, cloaking filter or block page is not the site's code.
    if site_block_signal({"status": status, "title": title}) is not None:
        return None
    final_url = probe.get("final_url") or ""
    # Relative URLs resolve against <base href> when the page sets one, as a browser would.
    base = _resolve(final_url, parser.base_href) if parser.base_href else final_url
    # Forms with a password input first, so decoy forms cannot crowd them out.
    forms = sorted(
        (_form(f, base) for f in parser.forms), key=lambda f: "password" not in f["inputs"]
    )
    script_srcs = [_resolve(base, u) for u in parser.script_srcs]
    iframes = [_resolve(base, u) for u in parser.iframes]
    actions = [f["action"] for f in forms] + [u for f in forms for u in f["formactions"]]
    hosts = _external_hosts(final_url, script_srcs + actions + iframes)
    # Each formaction is a destination its form can post to, judged like the action.
    signal_forms = forms + [{**f, "action": u} for f in forms for u in f["formactions"]]
    signals = derive_signals(
        {
            "forms": signal_forms,
            "scripts": [{"src": None, "text": t} for t in parser.inline_scripts],
        },
        urlparse(final_url).hostname or "",
    )
    inline = _cut_scripts(parser.inline_scripts)
    dropped = {
        "forms": len(forms) - MAX_FORMS,
        "inputs_outside_forms": len(parser.loose_inputs) - MAX_INPUTS,
        "script_srcs": len(script_srcs) - MAX_SCRIPT_SRCS,
        "inline_scripts": len(parser.inline_scripts) - len(inline),
        "iframes": len(iframes) - MAX_IFRAMES,
        "external_hosts": len(hosts) - MAX_HOSTS,
    }
    return {
        "derived_signals": signals,
        "external_hosts": hosts[:MAX_HOSTS],
        "dropped": {k: n for k, n in dropped.items() if n > 0},
        "source": SOURCE,
        "final_url": final_url[:URL_LIMIT],
        "status": status,
        "hops": [h[:URL_LIMIT] for h in probe.get("hops") or []],
        "bytes_read": len(body),
        "title": title,
        "base_href": (parser.base_href or "")[:URL_LIMIT] or None,
        "forms": [_cut_form(f) for f in forms[:MAX_FORMS]],
        "inputs_outside_forms": parser.loose_inputs[:MAX_INPUTS],
        "script_srcs": [u[:URL_LIMIT] for u in script_srcs[:MAX_SCRIPT_SRCS]],
        "inline_scripts": inline,
        "iframes": [u[:URL_LIMIT] for u in iframes[:MAX_IFRAMES]],
        "meta_refresh": parser.meta_refresh,
    }


async def read_static_html(url: str, total_s: float, probe_fn=http_probe) -> dict | None:
    """One guarded GET walk of url (redirects by hand, every hop checked, 64 KB at most)."""
    return excerpt(await probe_fn(url, total_s=total_s, keep_body=True))
