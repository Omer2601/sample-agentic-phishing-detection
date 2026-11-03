# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Ranked, budgeted view of a page code capture for the code_analyst model.

The full capture (scripts, DOM, network log) is ~32k tokens on a typical page and most of
it is library code, styling and image requests. This view keeps every security-relevant
fact verbatim (forms, iframes, redirects, listeners, sinks, derived signals, POST targets)
and spends a token budget on the script and DOM text most likely to carry evidence:
credential handling, exfiltration, dynamic code execution, redirects and obfuscation.
Heuristics still run on the full capture; only what the model reads is trimmed.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from urllib.parse import urlparse

MODE_ENV = "CODE_MODEL_VIEW"
TOKENS_ENV = "CODE_MODEL_VIEW_TOKENS"
COMPACT = "compact"
DEFAULT_TOKENS = 15_000
MIN_TOKENS = 2_000
# The view is wrapped in a 70k-char untrusted fence; stay well inside it.
MAX_TOKENS = 30_000
# Measured on 207 dev captures: the JSON-serialised capture averages ~1.95 chars per token.
CHARS_PER_TOKEN = 2

SMALL_SCRIPT = 2_000
WINDOW_BEFORE = 200
WINDOW_AFTER = 350
SCRIPT_EXCERPT_LIMIT = 3_000
MAX_NOTABLE_REQUESTS = 40
MAX_HOSTS = 30
MAX_ATTR = 160
MAX_TEXT = 240
MAX_HITS_PER_MARKER = 6
BEACON_QUERY = 20

NOTE = (
    "This capture is a compact view: forms, iframes, redirects, listeners, sinks and derived "
    "signals are complete; `network.notable_requests` lists non-GET, XHR, fetch, WebSocket, "
    "beacon and document requests, POSTs first, up to a size cap (`network.notable_omitted`, "
    "when present, counts the ones left out, so then the list is not complete); `network` "
    "summarises requests by host; `scripts` lists every script, with library and "
    "analytics bundles named but not shown and other scripts shown whole when they fit or as "
    "excerpts around security-relevant code (`markers` names what each matched, `urls` lists "
    "the URL literals each contains); `dom_html` "
    "has style, svg, template, comment and script bodies and non-hiding style attributes "
    "removed and long "
    "text shortened; scripts injected by the capture browser's own extension are counted in "
    "`capture_browser_extension_scripts`, not listed. Text left out "
    "for size is not evidence either way."
)


# A script is a library by its host only when that host is the vendor's own (matched as a
# domain suffix, so googletagmanager.com.evil.ru is not one), and by its file name only
# when served from a curated public CDN (jsdelivr and unpkg serve anyone's files): a
# first-party "jquery.min.js" is shown like any other script.
_LIBRARY_HOSTS = {
    "googletagmanager.com": "gtm",
    "google-analytics.com": "google-analytics",
    "doubleclick.net": "google-ads",
    "googlesyndication.com": "google-ads",
    "googleadservices.com": "google-ads",
    "connect.facebook.net": "facebook-pixel",
    "hotjar.com": "hotjar",
    "clarity.ms": "clarity",
    "analytics.tiktok.com": "tiktok-pixel",
    "cloudflareinsights.com": "cloudflare-insights",
    "hcaptcha.com": "captcha",
    "challenges.cloudflare.com": "captcha",
    "cdn.shopify.com": "shopify",
    "amazon-adsystem.com": "ads",
    "criteo.net": "ads",
    "taboola.com": "ads",
    "outbrain.com": "ads",
    "adnxs.com": "ads",
    "segment.com": "telemetry",
    "mixpanel.com": "telemetry",
    "nr-data.net": "telemetry",
    "sentry-cdn.com": "telemetry",
    "browser-intake-datadoghq.com": "telemetry",
}
_CDN_HOSTS = (
    "code.jquery.com",
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "www.gstatic.com",
    "www.google.com",
)
_LIBRARY_FILES = [
    (name, re.compile(pattern, re.I))
    for name, pattern in [
        ("jquery", r"^jquery"),
        ("react", r"^react(-dom)?[.-]"),
        ("vue", r"^vue[.\w-]*\.js"),
        ("angular", r"^angular[.\w-]*\.js"),
        ("bootstrap", r"^bootstrap[.\w-]*\.js"),
        ("lodash", r"^(lodash|underscore)[.\w-]*\.js"),
        ("polyfill", r"^(polyfill|core-js)"),
        ("carousel", r"^(swiper|slick|owl\.carousel|splide|flickity)"),
        ("captcha", r"recaptcha"),
    ]
]

_LIBRARY_TEXT = [
    (name, re.compile(pattern))
    for name, pattern in [
        ("jquery", r"jQuery (JavaScript Library )?v\d|/\*! jQuery"),
        ("react", r"@license React|react\.production\.min\.js"),
        ("vue", r"Vue\.js v\d"),
        ("bootstrap", r"Bootstrap v\d"),
        ("lodash", r"@license\s+Lodash|lodash\.com"),
        ("core-js", r"core-js"),
        ("gtm", r"googletagmanager\.com/gt[am]|gtag\('config'|'gtm\.start'"),
        ("facebook-pixel", r"fbq\('init'|fbevents\.js"),
        ("hotjar", r"static\.hotjar\.com"),
        ("clarity", r"clarity\.ms/tag"),
    ]
]

# (name, weight, also searched in library text, pattern). Weights rank excerpts.
_MARKER_SPECS = [
    ("telegram_exfil", 40, True, r"api\.telegram\.org|/bot\d{6,}:|chat_id"),
    ("discord_webhook", 40, True, r"discord(app)?\.com/api/webhooks"),
    ("wallet_drainer", 30, True, r"eth_requestAccounts|setApprovalForAll|ethereum\.request"),
    ("obfuscation", 25, True, r"_0x[0-9a-f]{4,}|(\\x[0-9a-f]{2}){6}|while\s*\(!!\[\]\)"),
    ("base64_blob", 15, True, r"[A-Za-z0-9+/]{300,}={0,2}"),
    (
        "decode",
        20,
        True,
        r"\batob\s*\(|fromCharCode|\bunescape\s*\(|decodeURIComponent\s*\(\s*escape",
    ),
    ("dynamic_exec", 20, False, r"\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['\"]"),
    (
        "doc_write",
        15,
        False,
        r"document\.write(ln)?\s*\(|insertAdjacentHTML|\.innerHTML\s*=|outerHTML\s*=",
    ),
    ("card_data", 25, False, r"\bcvv\b|\bcvc\b|card.?number|cc.?num|expir(y|ation)|\biban\b"),
    (
        "credentials",
        20,
        False,
        r"passw(or)?d|\bpass\b|\botp\b|one.?time|verification.?code|\b2fa\b|\bpin\b",
    ),
    ("secrets", 25, False, r"seed.?phrase|mnemonic|private.?key|recovery.?phrase|\bssn\b"),
    ("identity", 8, False, r"\bemail\b|user.?name|login|sign.?in|phone"),
    ("exfil_php", 15, True, r"\.php['\"?/]"),
    (
        "network_send",
        12,
        False,
        r"\bfetch\s*\(|XMLHttpRequest|\.ajax\s*\(|\$\.post\s*\(|axios|sendBeacon|FormData",
    ),
    ("websocket", 15, False, r"WebSocket\s*\(|EventSource\s*\("),
    (
        "redirect",
        12,
        False,
        r"location(\.href)?\s*=[^=]|location\.(replace|assign)\s*\(|window\.open\s*\(|top\.location",
    ),
    (
        "visitor_check",
        15,
        True,
        r"ipapi|ipinfo|ip-api|geoip|ipify|navigator\.webdriver|headless|devtools|debugger",
    ),
    (
        "submit_hook",
        10,
        False,
        r"preventDefault|onsubmit|addEventListener\s*\(\s*['\"](submit|keydown|keyup|input|paste)",
    ),
]
_MARKERS = [(n, w, lib, re.compile(p, re.I)) for n, w, lib, p in _MARKER_SPECS]


def enabled() -> bool:
    return os.environ.get(MODE_ENV, "").strip().lower() == COMPACT


def budget_tokens() -> int:
    try:
        tokens = int(os.environ.get(TOKENS_ENV, "") or DEFAULT_TOKENS)
    except ValueError:
        return DEFAULT_TOKENS
    return min(max(tokens, MIN_TOKENS), MAX_TOKENS)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def library_name(src: str | None, text: str) -> str | None:
    """The vendor library a script is served as, judged by where it comes from only: page
    text can claim any banner, so `library_banner` is a hint, never a reason to hide code."""
    if not src:
        return None
    try:
        parsed = urlparse(src)
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    for suffix, name in _LIBRARY_HOSTS.items():
        if host == suffix or host.endswith("." + suffix):
            return name
    if host in _CDN_HOSTS:
        basename = parsed.path.rsplit("/", 1)[-1]
        for name, pattern in _LIBRARY_FILES:
            if pattern.search(parsed.path if name == "captcha" else basename):
                return name
    return None


def library_banner(text: str) -> str | None:
    head = text[:3_000]
    for name, pattern in _LIBRARY_TEXT:
        if pattern.search(head):
            return name
    return None


_URL_LITERAL = re.compile(
    r"""(?:https?:)?//[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+[^\s"'`<>()\\]{0,150}"""
)
MAX_SCRIPT_URLS = 8


def script_urls(text: str) -> list[str]:
    """The first distinct URL literals in a script (redirect and exfil targets are often
    constants defined far from the code that uses them)."""
    out: list[str] = []
    for match in _URL_LITERAL.finditer(text):
        url = match.group(0)
        if url not in out:
            out.append(url)
            if len(out) >= MAX_SCRIPT_URLS:
                break
    return out


def _hits(text: str, library: bool) -> list[tuple[int, int, str, int]]:
    """Every marker match as (start, end, name, weight), capped per marker."""
    out = []
    for name, weight, in_library, pattern in _MARKERS:
        if library and not in_library:
            continue
        for i, match in enumerate(pattern.finditer(text)):
            if i >= MAX_HITS_PER_MARKER:
                break
            out.append((match.start(), match.end(), name, weight))
    return out


def _windows(text: str, hits: list[tuple[int, int, str, int]], limit: int) -> str:
    """Context windows around the heaviest hits, merged and in source order. A window that
    would take the total past `limit` is skipped, so a lighter hit never pushes out a
    heavier one; the heaviest window alone is clipped to `limit`."""
    spans: list[tuple[int, int]] = []
    for start, end, _, _ in sorted(hits, key=lambda h: -h[3]):
        lo, hi = max(start - WINDOW_BEFORE, 0), min(end + WINDOW_AFTER, len(text))
        if not spans:
            spans = [(lo, min(hi, lo + limit))]
            continue
        for a, b in spans:
            if lo < b and hi > a:
                lo, hi = min(a, lo), max(b, hi)
        merged = [(a, b) for a, b in spans if not (lo < b and hi > a)] + [(lo, hi)]
        if sum(b - a for a, b in merged) <= limit:
            spans = merged
    return " … ".join(text[a:b] for a, b in sorted(spans))


def _script_entries(scripts: list[dict], host: str) -> tuple[list[dict], int]:
    """Index every script with its markers and a candidate excerpt; drop browser-extension
    scripts injected by the capture browser itself (they carry no page text)."""
    entries, extension = [], 0
    for index, script in enumerate(scripts):
        if not isinstance(script, dict):
            continue
        src = script.get("src") if isinstance(script.get("src"), str) else None
        if src and src.startswith("chrome-extension://"):
            extension += 1
            continue
        text = script.get("text") if isinstance(script.get("text"), str) else ""
        library = library_name(src, text)
        banner = None if library else library_banner(text)
        hits = _hits(text, bool(library))
        markers = sorted({name for _, _, name, _ in hits})
        entry: dict = {"i": index, "src": src, "chars": len(text)}
        if script.get("in_dom") is False:
            entry["in_dom"] = False
        if library:
            entry["library"] = library
        if banner:
            entry["library_banner"] = banner
        if markers:
            entry["markers"] = markers
        urls = [] if library else script_urls(text)
        if urls:
            entry["urls"] = urls
        score = sum(w for _, w in {(n, w) for _, _, n, w in hits})
        first_party = not src or _host(src) == host
        if library:
            excerpt = _windows(text, hits, SCRIPT_EXCERPT_LIMIT // 2) if hits else ""
        elif len(text) <= SMALL_SCRIPT:
            excerpt = text
            score += 5
        else:
            excerpt = _windows(text, hits, SCRIPT_EXCERPT_LIMIT) if hits else text[:400]
        score += 4 if first_party else 0
        score += 6 if script.get("in_dom") is False else 0
        entries.append(
            {
                "entry": entry,
                "excerpt": excerpt,
                "full": None if library else text,
                "score": score,
                "whole": excerpt == text,
            }
        )
    return entries, extension


_NOTABLE_TYPES = {"xhr", "fetch", "websocket", "eventsource", "ping", "document", "other"}


def _vendor_host(host: str) -> bool:
    return any(host == suffix or host.endswith("." + suffix) for suffix in _LIBRARY_HOSTS)


def _network(requests: list[dict], host: str) -> tuple[dict, list[dict]]:
    """Per-host summary of every request, plus the requests worth reading one by one:
    non-GET or body-carrying requests, XHR/fetch/socket/beacon/document requests, and
    third-party GETs with a long query string (image and script beacons)."""
    hosts: dict[str, Counter] = {}
    flagged: set[str] = set()
    notable, seen = [], set()
    for req in requests:
        if not isinstance(req, dict):
            continue
        url = req.get("url") if isinstance(req.get("url"), str) else ""
        req_host = _host(url)
        rtype = req.get("resource_type") or "other"
        counts = hosts.setdefault(req_host, Counter())
        counts[rtype] += 1
        method = req.get("method") or "GET"
        if method != "GET":
            counts[f"method:{method}"] += 1
        sends = method not in ("GET", "HEAD", "OPTIONS") or bool(req.get("has_body"))
        beacon = (
            req_host != host
            and not _vendor_host(req_host)
            and len(url.partition("?")[2]) > BEACON_QUERY
        )
        if not (sends or rtype in _NOTABLE_TYPES or beacon):
            continue
        flagged.add(req_host)
        if (method, url) in seen:
            continue
        seen.add((method, url))
        rank = 0 if sends else 1 if rtype != "document" or req_host != host else 2
        rank = rank if rtype in _NOTABLE_TYPES or sends else 3
        notable.append((rank, len(notable), req))
    ordered = sorted(hosts.items(), key=lambda kv: (kv[0] not in flagged, -sum(kv[1].values())))
    summary = {
        "total_requests": len(requests),
        "hosts": [
            {"host": h, "first_party": h == host, "counts": dict(c.most_common())}
            for h, c in ordered[:MAX_HOSTS]
        ],
    }
    if len(ordered) > MAX_HOSTS:
        summary["other_hosts"] = len(ordered) - MAX_HOSTS
    return summary, [req for _, _, req in sorted(notable, key=lambda n: n[:2])]


_DROP_BLOCKS = re.compile(r"<(style|svg|template)\b[^>]*>.*?</\1\s*>", re.I | re.S)
_SCRIPT_BODY = re.compile(r"(<script\b[^>]*>).*?(</script\s*>)", re.I | re.S)
_COMMENT = re.compile(r"<!--.*?-->", re.S)
_LONG_ATTR = re.compile(rf"(\s[\w:-]+=)(\"[^\"]{{{MAX_ATTR},}}\"|'[^']{{{MAX_ATTR},}}')")
_LONG_TEXT = re.compile(rf">([^<]{{{MAX_TEXT},}})<")
_SPACE = re.compile(r"\s{2,}")
_STYLE_ATTR = re.compile(r"\sstyle=(\"[^\"]*\"|'[^']*')", re.I)
_HIDING_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?![.\d]*[1-9])", re.I
)


def compact_dom(html: str) -> str:
    """Markup with the bulk that carries no security evidence removed: style, svg, template
    and comment blocks, script bodies (their text is in `scripts`), style attributes that
    do not hide anything,
    and the middle of long attribute values and text runs."""
    html = _COMMENT.sub("", html)
    html = _DROP_BLOCKS.sub(lambda m: f"<{m.group(1)}/>", html)
    html = _SCRIPT_BODY.sub(r"\1\2", html)
    html = _STYLE_ATTR.sub(lambda m: m.group(0) if _HIDING_STYLE.search(m.group(1)) else "", html)
    html = _LONG_ATTR.sub(
        lambda m: f"{m.group(1)}{m.group(2)[: MAX_ATTR - 20]}…{m.group(2)[0]}", html
    )
    html = _LONG_TEXT.sub(lambda m: f">{m.group(1)[: MAX_TEXT - 40]}…<", html)
    return _SPACE.sub(" ", html)


_BULKY = ("scripts", "requests", "dom_html")


def _size(value) -> int:
    return len(json.dumps(value, separators=(",", ":")))


def compact_capture(data: dict, tokens: int) -> dict:
    """The capture with every fact kept and scripts, DOM and requests fitted to `tokens`."""
    budget = tokens * CHARS_PER_TOKEN
    host = _host(data.get("final_url") if isinstance(data.get("final_url"), str) else "")
    facts = {k: v for k, v in data.items() if k not in _BULKY}
    requests, scripts, dom_html = data.get("requests"), data.get("scripts"), data.get("dom_html")
    network, notable = _network(requests if isinstance(requests, list) else [], host)
    entries, extension = _script_entries(scripts if isinstance(scripts, list) else [], host)
    dom = compact_dom(dom_html if isinstance(dom_html, str) else "")

    left = budget - _size(facts) - _size(network) - _size([e["entry"] for e in entries])
    notable_cap = max(int(left * 0.15), 0)
    kept_notable, used = [], 0
    for req in notable[:MAX_NOTABLE_REQUESTS]:
        cost = _size(req)
        if used + cost > notable_cap:
            break
        kept_notable.append(req)
        used += cost
    left -= used
    dom_cap = max(int(left * 0.35), 0)
    script_left = left - min(len(dom), dom_cap)
    for item in sorted(entries, key=lambda e: -e["score"]):
        excerpt = item["excerpt"]
        if not excerpt:
            continue
        if script_left <= 200:
            item["entry"]["text_omitted"] = True
            continue
        piece = excerpt[:script_left]
        item["entry"]["text" if item["whole"] and len(piece) == len(excerpt) else "excerpt"] = piece
        script_left -= _size(piece) + 12
    for item in sorted(entries, key=lambda e: -e["score"]):
        entry, full = item["entry"], item["full"]
        if not full or "excerpt" not in entry:
            continue
        extra = _size(full) - _size(entry["excerpt"])
        if extra <= script_left:
            del entry["excerpt"]
            entry["text"] = full
            script_left -= extra
    dom_cap += max(script_left, 0)

    view = dict(facts)
    view["dom_html"] = dom[:dom_cap] + ("…" if len(dom) > dom_cap else "")
    view["network"] = {**network, "notable_requests": kept_notable}
    if len(kept_notable) < len(notable):
        view["network"]["notable_omitted"] = len(notable) - len(kept_notable)
    view["scripts"] = [e["entry"] for e in entries]
    if extension:
        view["capture_browser_extension_scripts"] = extension
    return view
