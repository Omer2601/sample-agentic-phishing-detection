# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Test doubles for S3, Strands agents, AgentCore Browser and Playwright."""

from __future__ import annotations

import asyncio
import base64
import contextlib
from dataclasses import dataclass, field
from typing import Any


class FakeS3:
    def __init__(self) -> None:
        self.objects: dict[str, dict[str, Any]] = {}

    def put_object(self, **kwargs: Any) -> dict:
        self.objects[kwargs["Key"]] = kwargs
        return {}


@dataclass
class FakeMetrics:
    accumulated_usage: dict[str, int]


@dataclass
class FakeResult:
    structured_output: Any
    stop_reason: str = "end_turn"
    metrics: FakeMetrics = field(
        default_factory=lambda: FakeMetrics({"inputTokens": 100, "outputTokens": 20})
    )


class FakeAgentFactory:
    """Callable standing in for strands.Agent. Each call pops the next scripted outcome.

    An outcome is a FakeResult to return or an Exception to raise. Before returning, the
    fake runs every tool it was given once, the way the model is instructed to, with the
    arguments in tool_args (by tool name) or none.
    """

    def __init__(self, outcomes: list[Any], tool_args: dict[str, dict] | None = None) -> None:
        self.outcomes = list(outcomes)
        self.tool_args = tool_args or {}
        self.prompts: list[str] = []
        self.kwargs: list[dict] = []
        self.tool_outputs: list[Any] = []

    def __call__(self, **kwargs: Any) -> FakeAgentFactory:
        self.kwargs.append(kwargs)
        self._tools = kwargs.get("tools", [])
        return self

    async def invoke_async(self, prompt: str, structured_output_model: Any = None) -> FakeResult:
        self.prompts.append(prompt)
        for tool in self._tools:
            args = self.tool_args.get(getattr(tool, "tool_name", ""), {})
            self.tool_outputs.append(await tool(**args))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    @property
    def event_loop_metrics(self) -> FakeMetrics:
        return FakeMetrics({"inputTokens": 50, "outputTokens": 0})


class FakeResponse:
    def __init__(
        self, status: int = 200, url: str = "", resource_type: str = "document", body: str = ""
    ) -> None:
        self.status = status
        self.url = url
        self.request = FakeRequest(url, resource_type)
        self._body = body

    async def text(self) -> str:
        return self._body


@dataclass
class FakeRequest:
    url: str
    resource_type: str = "document"
    method: str = "GET"
    post_data: str | None = None
    post_data_buffer: bytes | None = None
    redirected_from: FakeRequest | None = None


class FakePage:
    def __init__(
        self,
        *,
        final_url: str = "https://example.com/",
        title: str = "Example",
        body_text: str = "Welcome",
        evaluate_result: Any = None,
        goto_error: Exception | None = None,
        responses: list[FakeResponse] | None = None,
        redirect_chain: list[str] | None = None,
        content: str = "<html><body>Welcome</body></html>",
        status: int = 200,
        hang: frozenset[str] = frozenset(),
        screenshot_error: Exception | None = None,
        inner_text_error: Exception | None = None,
        cdp_unavailable: bool = False,
        cdp_hang: bool = False,
        slow: dict[str, float] | None = None,
    ) -> None:
        self.url = final_url
        self._status = status
        self._title = title
        self._body_text = body_text
        self._evaluate_result = evaluate_result or {}
        self._goto_error = goto_error
        self._responses = responses or []
        # URLs the navigation passed through before final_url, oldest first.
        self._redirect_chain = redirect_chain or []
        self.handlers: dict[str, list] = {}
        self._content = content
        self.goto_calls: list[str] = []
        self.goto_kwargs: list[dict] = []
        self.load_states: list[tuple[str, Any]] = []
        self.screenshot_kwargs: list[dict] = []
        self.inner_text_kwargs: list[dict] = []
        # Methods named here never return, the way a stuck page behaves in Playwright.
        self._hang = hang
        self._screenshot_error = screenshot_error
        self._inner_text_error = inner_text_error
        # Called at the start of inner_text, so a test can see what was done before it.
        self.before_inner_text = None
        # CDP methods sent through context.new_cdp_session(page), in order.
        self.cdp_calls: list[str] = []
        self.cdp_detached = False
        self._cdp_unavailable = cdp_unavailable
        # CDP captureScreenshot never returns, while page.screenshot still works.
        self._cdp_hang = cdp_hang
        # Methods named here take this many seconds, honouring a timeout= kwarg the way
        # Playwright does: past the timeout they raise Playwright's TimeoutError.
        self._slow = slow or {}
        self.context: FakeContext | None = None

    async def _maybe_hang(self, method: str, timeout_ms: float | None = None) -> None:
        if method in self._hang:
            await asyncio.Event().wait()
        delay = self._slow.get(method)
        if delay is None:
            return
        if timeout_ms is not None and timeout_ms / 1000 < delay:
            from playwright.async_api import TimeoutError as PlaywrightTimeout

            await asyncio.sleep(timeout_ms / 1000)
            raise PlaywrightTimeout(f"{method}: Timeout {timeout_ms}ms exceeded.")
        await asyncio.sleep(delay)

    def on(self, event: str, handler) -> None:
        self.handlers.setdefault(event, []).append(handler)

    async def goto(self, url: str, **kwargs: Any) -> FakeResponse:
        self.goto_calls.append(url)
        self.goto_kwargs.append(kwargs)
        await self._maybe_hang("goto", kwargs.get("timeout"))
        if self._goto_error:
            raise self._goto_error
        for response in self._responses:
            for handler in self.handlers.get("request", []):
                handler(response.request)
            for handler in self.handlers.get("response", []):
                handler(response)
        response = FakeResponse(self._status, self.url)
        previous = None
        for hop in self._redirect_chain:
            previous = FakeRequest(hop, redirected_from=previous)
        response.request.redirected_from = previous
        return response

    async def wait_for_load_state(self, state: str = "load", **kwargs: Any) -> None:
        self.load_states.append((state, kwargs.get("timeout")))
        await self._maybe_hang("wait_for_load_state", kwargs.get("timeout"))

    async def content(self) -> str:
        return self._content

    async def title(self) -> str:
        await self._maybe_hang("title")
        return self._title

    async def inner_text(self, _selector: str, **kwargs: Any) -> str:
        self.inner_text_kwargs.append(kwargs)
        if self.before_inner_text:
            self.before_inner_text()
        await self._maybe_hang("inner_text")
        if self._inner_text_error:
            raise self._inner_text_error
        return self._body_text

    async def screenshot(self, **kwargs: Any) -> bytes:
        self.screenshot_kwargs.append(kwargs)
        await self._maybe_hang("screenshot", kwargs.get("timeout"))
        if self._screenshot_error:
            raise self._screenshot_error
        return b"\x89PNG fake"

    async def evaluate(self, _script: str) -> Any:
        await self._maybe_hang("evaluate")
        return self._evaluate_result


class FakeCDPSession:
    """CDP session on a FakePage. A captureScreenshot shares the page's screenshot
    behaviour (hang, error), so a stuck page is stuck on either path."""

    def __init__(self, page: FakePage) -> None:
        self.page = page

    async def send(self, method: str, params: dict | None = None) -> dict:
        self.page.cdp_calls.append(method)
        if method == "Page.captureScreenshot":
            self.page.screenshot_kwargs.append({"cdp": True, **(params or {})})
            if self.page._cdp_hang:
                await asyncio.Event().wait()
            await self.page._maybe_hang("screenshot")
            if self.page._screenshot_error:
                raise self.page._screenshot_error
            return {"data": base64.b64encode(b"\x89PNG fake").decode()}
        return {}

    async def detach(self) -> None:
        self.page.cdp_detached = True


class FakeContext:
    def __init__(self, page: FakePage) -> None:
        self.pages = [page]
        self.routes: list = []
        self.init_scripts: list[str] = []
        page.context = self

    async def new_cdp_session(self, page: FakePage) -> FakeCDPSession:
        if page._cdp_unavailable:
            from playwright.async_api import Error

            raise Error("BrowserContext.new_cdp_session: CDP session is not available")
        return FakeCDPSession(page)

    async def route(self, pattern: str, handler) -> None:
        self.routes.append((pattern, handler))

    async def add_init_script(self, script: str) -> None:
        self.init_scripts.append(script)


class FakeBrowser:
    def __init__(self, page: FakePage) -> None:
        self.contexts = [FakeContext(page)]
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class FakePlaywright:
    def __init__(self, page: FakePage) -> None:
        self.browser = FakeBrowser(page)
        self.chromium = self

    async def connect_over_cdp(self, ws_url: str, headers: dict) -> FakeBrowser:
        assert ws_url.startswith("wss://") and headers
        return self.browser

    async def __aenter__(self) -> FakePlaywright:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None


class FakeBrowserClient:
    instances: list[FakeBrowserClient] = []

    def __init__(self, region: str) -> None:
        self.region = region
        self.started = False
        self.stopped = False
        FakeBrowserClient.instances.append(self)

    def start(self, **_: Any) -> str:
        self.started = True
        return "session-1"

    def generate_ws_headers(self) -> tuple[str, dict]:
        return "wss://browser.example/automation", {"Authorization": "sig"}

    def stop(self) -> None:
        self.stopped = True


@contextlib.asynccontextmanager
async def local_playwright():
    """async_playwright() that skips when the bundled Node driver cannot start.

    Some packaged Python-playwright drivers need glibc 2.27+, so they cannot start on an AL2
    build host (glibc 2.26); the AgentCore image (AL2023) runs it normally. Setting
    PLAYWRIGHT_NODEJS_PATH to a newer Node lets a developer run these tests on such a host.
    """
    import os
    import platform

    import pytest
    from playwright.async_api import async_playwright

    libc, version = platform.libc_ver()
    old_glibc = libc == "glibc" and tuple(int(p) for p in version.split(".")[:2]) < (2, 27)
    if old_glibc and not os.environ.get("PLAYWRIGHT_NODEJS_PATH"):
        pytest.skip(f"Playwright's Node driver needs glibc 2.27+, this host has {version}")
    manager = async_playwright()
    pw = await manager.__aenter__()
    try:
        yield pw
    finally:
        await manager.__aexit__(None, None, None)
