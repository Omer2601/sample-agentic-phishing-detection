# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Deterministic code signals handed to the model as leads, not verdicts.

Tuned on the 2026-10-11 live probe: github, discord, paypal and microsoftonline sign-in
pages must raise no high or critical signal, while the kits seen that day (relative
/api/telegram endpoints, duckdns receivers on odd ports, ipify fingerprinting, forms
submitted only by script) still do.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from phish_agents.url_analyst.whois import registered_domain
from phish_contracts.models import defang

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_TELEGRAM_TEXT = re.compile(r"api\.telegram\.org/bot|[\"'`]/api/telegram\b", re.I)
# Endpoint URLs only: "sendMessage" in free script text is also chrome.runtime.sendMessage.
_TELEGRAM_URL = re.compile(r"api\.telegram\.org/bot|/api/telegram\b|/sendMessage\b", re.I)
_DYN_DNS = (
    r"duckdns\.org|ngrok\.io|ngrok-free\.app|ngrok\.app|no-ip\.(?:org|biz|com)|ddns\.net|"
    r"hopto\.org|zapto\.org|sytes\.net|serveo\.net|serveousercontent\.com|loca\.lt|"
    r"dynu\.net|mooo\.com|trycloudflare\.com"
)
_DYN_DNS_HOST = re.compile(rf"(?:^|\.)(?:{_DYN_DNS})$", re.I)
_DYN_DNS_TEXT = re.compile(rf"(?<![a-z0-9.-])[a-z0-9.-]+\.(?:{_DYN_DNS})(?::\d+)?", re.I)
_GEO_IP = (
    r"api(?:64)?\.ipify\.org|ipapi\.co|ip-api\.com|ipinfo\.io|ipwho\.is|ipgeolocation\.io|"
    r"geolocation-db\.com|freeipapi\.com|extreme-ip-lookup\.com|ipdata\.co|api\.db-ip\.com|"
    r"api\.myip\.com|wtfismyip\.com|ip\.sb|ipapi\.is"
)
_GEO_IP_TEXT = re.compile(rf"\b(?:{_GEO_IP})\b", re.I)

_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("eval_or_function_constructor", "medium", re.compile(r"\beval\s*\(|new\s+Function\s*\(")),
    ("base64_decode", "low", re.compile(r"\batob\s*\(")),
    ("char_code_obfuscation", "medium", re.compile(r"String\.fromCharCode\s*\(|\bunescape\s*\(")),
    ("long_encoded_blob", "medium", re.compile(r"[A-Za-z0-9+/]{400,}={0,2}")),
    ("telegram_bot_exfil", "critical", _TELEGRAM_TEXT),
    ("discord_webhook_exfil", "critical", re.compile(r"discord(?:app)?\.com/api/webhooks", re.I)),
    # Wallet calls are the hijack; a clipboard READ is suspicious but copy-to-clipboard
    # polyfills read too (github), and clipboard WRITE is every copy button.
    (
        "wallet_or_clipboard_hijack",
        "high",
        re.compile(r"ethereum\.request|eth_requestAccounts|solana\.connect\s*\("),
    ),
    ("wallet_or_clipboard_hijack", "medium", re.compile(r"navigator\.clipboard\.read")),
    # Anti-debugging is `debugger` re-armed by a timer or loop; the word "devtools" is in
    # every React build (__REACT_DEVTOOLS_GLOBAL_HOOK__).
    (
        "devtools_evasion",
        "medium",
        re.compile(
            r"(?:setInterval|setTimeout|while\s*\(|for\s*\()[^;{}]{0,120}[{\s]*\bdebugger\b"
        ),
    ),
    ("ip_geolocation_lookup", "medium", _GEO_IP_TEXT),
)
_KEY_EVENTS = frozenset({"keydown", "keyup", "keypress"})
_SENSITIVE_INPUT = re.compile(r"input\[(password|email|tel|number)\]")
_SCRIPT_SUBMIT = re.compile(r"preventDefault\s*\(|\.submit\s*\(")
# Analytics and error-reporting collectors that legitimate sign-in pages beacon to.
_TELEMETRY = frozenset(
    {
        "data.microsoft.com",
        "google-analytics.com",
        "googletagmanager.com",
        "doubleclick.net",
        "sentry.io",
        "datadoghq.com",
        "browser-intake-datadoghq.com",
        "newrelic.com",
        "nr-data.net",
        "segment.io",
        "segment.com",
        "hotjar.com",
        "cloudflareinsights.com",
    }
)
# Registered domains one organisation serves its own pages and APIs from.
_SAME_ORG = (
    frozenset({"microsoft.com", "microsoftonline.com", "live.com", "office.com", "msftauth.net"}),
    frozenset({"github.com", "githubassets.com", "githubusercontent.com"}),
    frozenset({"paypal.com", "paypalobjects.com"}),
    frozenset({"discord.com", "discordapp.com", "discord.gg"}),
    frozenset({"google.com", "gstatic.com", "googleapis.com", "youtube.com"}),
)


def _host(url: str, base_host: str) -> str:
    return (urlparse(urljoin(f"https://{base_host}/", url)).hostname or base_host).lower()


def _site(url: str, base_host: str) -> str:
    return registered_domain(_host(url, base_host))


def _same_org(site: str, home: str) -> bool:
    return site == home or any(site in group and home in group for group in _SAME_ORG)


def _telemetry(host: str) -> bool:
    return any(host == t or host.endswith("." + t) for t in _TELEMETRY)


def _endpoints(capture: dict) -> list[tuple[str, str]]:
    """(kind, url) for every recorded sink and network request."""
    out = [(s.get("kind") or "sink", s.get("url") or "") for s in capture.get("sinks", [])]
    out += [
        (r.get("resource_type") or "request", r.get("url") or "")
        for r in capture.get("requests", [])
    ]
    return [(kind, url) for kind, url in out if url]


def derive_signals(capture: dict, page_host: str) -> list[dict]:
    home = registered_domain(page_host)
    out: list[dict] = []

    def add(name: str, severity: str, detail: str) -> None:
        for entry in out:
            if entry["name"] == name:
                # One entry per name, at the strongest severity seen.
                if _SEVERITY_RANK[severity] > _SEVERITY_RANK[entry["severity"]]:
                    entry.update(severity=severity, detail=detail[:200])
                return
        out.append({"name": name, "severity": severity, "detail": detail[:200]})

    scripts = capture.get("scripts", [])
    texts = [script.get("text") or "" for script in scripts]
    endpoints = _endpoints(capture)
    off_domain = [
        (kind, url)
        for kind, url in ((s.get("kind"), s.get("url", "")) for s in capture.get("sinks", []))
        if not _same_org(_site(url, page_host), home) and not _telemetry(_host(url, page_host))
    ]

    script_submit = any(_SCRIPT_SUBMIT.search(t) for t in texts) or any(
        listener.get("type") == "submit" and listener.get("target") in {"form", "document"}
        for listener in capture.get("listeners", [])
    )
    for form in capture.get("forms", []):
        if "password" not in form.get("inputs", []):
            continue
        action = (form.get("action") or "").strip()
        if _site(action, page_host) != home:
            add("credential_form_off_domain", "critical", f"password form posts to {action}")
        if action.lower().startswith("javascript:") or (not action and script_submit):
            add(
                "js_only_credential_submit",
                "high",
                f"password form has action {action or '(empty)'!r} and is sent by script",
            )
    for script, text in zip(scripts, texts, strict=True):
        for name, severity, pattern in _PATTERNS:
            match = pattern.search(text)
            if match:
                add(name, severity, f"{script.get('src') or 'inline'}: {match.group(0)[:80]}")
        match = _DYN_DNS_TEXT.search(text)
        if match:
            add(
                "dynamic_dns_receiver", "high", f"{script.get('src') or 'inline'}: {match.group(0)}"
            )
    for kind, url in endpoints:
        host = _host(url, page_host)
        if _TELEGRAM_URL.search(url):
            add("telegram_bot_exfil", "critical", f"{kind} to {url}")
        if _DYN_DNS_HOST.search(host):
            add("dynamic_dns_receiver", "high", f"{kind} to {url}")
        if _GEO_IP_TEXT.search(host):
            add("ip_geolocation_lookup", "medium", f"{kind} to {url}")
    for listener in capture.get("listeners", []):
        if listener.get("type") in {
            "keydown",
            "keyup",
            "keypress",
            "input",
        } and _SENSITIVE_INPUT.search(listener.get("target", "")):
            # Sign-in pages validate as you type; only a key listener plus an off-domain
            # sink looks like a keylogger.
            add(
                "key_listener_on_sensitive_input",
                "high" if off_domain else "medium",
                f"{listener['type']} on {listener['target']}",
            )
        if listener.get("type") in _KEY_EVENTS and listener.get("target") in {"document", "window"}:
            add(
                "global_key_listener",
                "medium",
                f"{listener['type']} on {listener['target']} ({listener.get('via', 'listener')})",
            )
    for kind, url in off_domain:
        add("data_sent_off_domain", "medium", f"{kind} to {url}")
    return out


# Requests that carry data somewhere; images, styles and fonts are page furniture.
_DATA_REQUESTS = frozenset({"fetch", "xhr", "websocket", "ping", "eventsource"})
MAX_ENDPOINTS = 20


def code_insights(capture: dict, page_host: str) -> dict:
    """What the page's code does, for the console: endpoints, forms, scripts (no model)."""
    home = registered_domain(page_host)
    scripts = capture.get("scripts", [])
    texts = [script.get("text") or "" for script in scripts]
    script_submit = any(_SCRIPT_SUBMIT.search(t) for t in texts) or any(
        listener.get("type") == "submit" for listener in capture.get("listeners", [])
    )
    seen: set[str] = set()
    endpoints = []
    for kind, url in _endpoints(capture):
        if kind not in _DATA_REQUESTS or url in seen:
            continue
        host = _host(url, page_host)
        if _telemetry(host):
            continue
        seen.add(url)
        off = not _same_org(registered_domain(host), home)
        endpoints.append({"url": defang(url[:300]), "kind": kind, "off_domain": off})
    endpoints.sort(key=lambda e: not e["off_domain"])
    forms = []
    for form in capture.get("forms", [])[:10]:
        action = (form.get("action") or "").strip()
        js = action.lower().startswith("javascript:") or (not action and script_submit)
        forms.append(
            {
                "action": action if action.lower().startswith("javascript:") else defang(action),
                "fields": list(form.get("inputs", [])),
                "submits_via_js": js,
            }
        )
    hosts: list[str] = []
    for script in scripts:
        src = script.get("src")
        # The managed browser injects its own chrome-extension:// scripts; they are not the page's.
        if src and urlparse(urljoin(f"https://{page_host}/", src)).scheme in ("http", "https"):
            site = registered_domain(_host(src, page_host))
            if not _same_org(site, home) and site not in hosts:
                hosts.append(site)
    return {
        "endpoints": endpoints[:MAX_ENDPOINTS],
        "forms": forms,
        "script_count": len(scripts),
        "script_kb": sum(len(t) for t in texts) // 1024,
        "external_script_hosts": hosts[:15],
    }
