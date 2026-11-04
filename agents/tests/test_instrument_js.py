# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Runs instrument.js and DOM_PROBE in a local headless Chromium on a data: URL.

No network is used. Skipped when the Playwright Chromium build is not installed.
"""

from urllib.parse import quote

import pytest
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from phish_agents.code_analyst.capture import DOM_PROBE, INSTRUMENT_JS

PAGE = """<!doctype html><html><body>
<form action="/p"><input type="hidden" name="victim_id" value="7">
<input type="password" name="pw" onkeyup="x()"></form>
<script>
document.onkeydown = function (e) {};
document.querySelector('input[name=pw]').oninput = function () {};
window.addEventListener('keypress', function () {});
</script></body></html>"""


@pytest.fixture
async def probe():
    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"local Chromium unavailable: {exc.message.splitlines()[0]}")
        try:
            context = await browser.new_context()
            await context.add_init_script(INSTRUMENT_JS)
            page = await context.new_page()
            await page.goto("data:text/html," + quote(PAGE))
            yield await page.evaluate(DOM_PROBE)
        finally:
            await browser.close()


async def test_records_property_handlers(probe):
    listeners = probe["log"]["listeners"]
    assert {"type": "keydown", "target": "document", "via": "property"} in listeners
    assert {"type": "input", "target": "input[password]", "via": "property"} in listeners


async def test_records_inline_attribute_handlers(probe):
    listeners = probe["log"]["listeners"]
    assert {"type": "keyup", "target": "input[password]", "via": "attribute"} in listeners


async def test_names_window_and_document_targets(probe):
    listeners = probe["log"]["listeners"]
    assert {"type": "keypress", "target": "window", "via": "listener"} in listeners


async def test_form_inputs_include_names_and_hidden_fields(probe):
    form = probe["forms"][0]
    assert form["inputs"] == ["hidden", "password"]
    assert form["names"] == ["victim_id", "pw"]


WEBSOCKET_PROBE = """() => {
  const ws = window.WebSocket;
  const sock = new WebSocket("ws://127.0.0.1:9/feed");
  const result = {
    constants: [ws.CONNECTING, ws.OPEN, ws.CLOSING, ws.CLOSED],
    instance: sock instanceof WebSocket,
    sharedPrototype: Object.getPrototypeOf(sock) === ws.prototype,
    readyStateMatches: sock.readyState === WebSocket.CONNECTING,
    name: ws.name,
    sinks: window.__phishLog.sinks.filter((s) => s.kind === "websocket"),
  };
  sock.close();
  return result;
}"""


async def test_websocket_wrapper_keeps_constants_and_prototype():
    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"local Chromium unavailable: {exc.message.splitlines()[0]}")
        try:
            context = await browser.new_context()
            await context.add_init_script(INSTRUMENT_JS)
            page = await context.new_page()
            await page.goto("data:text/html," + quote("<!doctype html><p>ws</p>"))
            out = await page.evaluate(WEBSOCKET_PROBE)
        finally:
            await browser.close()
    assert out["constants"] == [0, 1, 2, 3]
    assert out["instance"] and out["sharedPrototype"] and out["readyStateMatches"]
    assert out["name"] == "WebSocket"
    assert out["sinks"] == [{"kind": "websocket", "url": "ws://127.0.0.1:9/feed"}]
