# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Look up a brand's official website through Amazon Bedrock AgentCore Web Search.

The Web Search connector sits behind a small AgentCore Gateway in us-east-1 (the edge stack).
The runtime reaches it over MCP (JSON-RPC over HTTPS) with SigV4 from its own role. Everything
here fails soft: when the gateway is not configured, slow or refusing, the tool says so in one
line and brand_visual judges the page exactly as it does without web search.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import uuid
from collections.abc import Callable, Mapping
from datetime import timedelta
from typing import Any, Protocol
from urllib.parse import urlsplit

from phish_agents.common import cache
from phish_agents.common.gateway_mcp import GatewayMcpClient
from phish_agents.common.timing import CallRecorder
from phish_agents.common.untrusted import wrap_untrusted
from phish_contracts.models import CallKind

logger = logging.getLogger(__name__)

# The Gateway names a target's tools {target name}___{tool}; infra sets WEB_SEARCH_TOOL_NAME
# from the same target name, this is the fallback.
DEFAULT_TOOL_NAME = "web-search___WebSearch"
# The whole analysis has a 30 s deadline (common/server.py), so one lookup gets a small slice:
# connect plus one search round trip.
START_TIMEOUT_S = 4
CALL_TIMEOUT_S = 6
MAX_RESULTS = 5
MAX_LOOKUPS = 2
BRAND_LIMIT = 80
TITLE_LIMIT = 120
SNIPPET_LIMIT = 200
RESULTS_LIMIT = 3000
_NOT_QUERY = re.compile(r"[^\w .&'+-]", re.UNICODE)
_SPACES = re.compile(r"\s+")
_REGION_IN_HOST = re.compile(r"\.bedrock-agentcore\.([a-z0-9-]+)\.")


class McpClientLike(Protocol):
    def start(self) -> Any: ...

    def stop(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None: ...

    async def call_tool_async(
        self,
        tool_use_id: str,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
    ) -> Mapping[str, Any]: ...


def _mcp_client(url: str, region: str) -> McpClientLike:
    # Not the Strands MCPClient: its mcp 2.2.0 handshake uses a protocol version the Gateway
    # refuses (see common/gateway_mcp.py).
    return GatewayMcpClient(url, region, timeout_s=CALL_TIMEOUT_S)


def _clean_brand(brand: str) -> str:
    return _SPACES.sub(" ", _NOT_QUERY.sub(" ", brand or "")).strip()[:BRAND_LIMIT].strip()


def build_query(brand: str) -> str:
    """A plain search phrase: the brand (letters, digits and a few joiners) plus a fixed suffix.

    The brand comes from the model, which read it off an untrusted page, so it is reduced to a
    short plain phrase before it leaves the runtime.
    """
    cleaned = _clean_brand(brand)
    return f"{cleaned} official website" if cleaned else ""


def _host(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def _same_site(host: str, scan_host: str) -> bool:
    return bool(host and scan_host) and (
        host == scan_host or host.endswith("." + scan_host) or scan_host.endswith("." + host)
    )


def _one_line(text: object, limit: int) -> str:
    return _SPACES.sub(" ", str(text or "")).strip()[:limit]


def _results(payload: Mapping[str, Any]) -> list[dict]:
    structured = payload.get("structuredContent")
    if isinstance(structured, dict) and isinstance(structured.get("results"), list):
        return structured["results"]
    for block in payload.get("content") or []:
        text = block.get("text") if isinstance(block, dict) else None
        if text:
            parsed = json.loads(text)
            if isinstance(parsed, dict) and isinstance(parsed.get("results"), list):
                return parsed["results"]
    raise ValueError("web search result has no results list")


def _slim(results: list[dict]) -> list[dict]:
    """The fields _render uses, capped, for the cache. Empty when nothing is worth keeping."""
    return [
        {
            "url": _one_line(item.get("url"), 300),
            "title": _one_line(item.get("title"), TITLE_LIMIT),
            "text": _one_line(item.get("text"), SNIPPET_LIMIT),
        }
        for item in results[:MAX_RESULTS]
        if isinstance(item, dict) and _one_line(item.get("url"), 300)
    ]


class WebSearch:
    def __init__(
        self,
        url: str,
        region: str,
        scan_url: str,
        recorder: CallRecorder,
        *,
        tool_name: str = DEFAULT_TOOL_NAME,
        max_lookups: int = MAX_LOOKUPS,
        client_factory: Callable[[str, str], McpClientLike] = _mcp_client,
    ) -> None:
        self.url, self.region, self.tool_name = url, region, tool_name
        self.scan_host = _host(scan_url)
        self.recorder = recorder
        self.max_lookups = max_lookups
        self._client_factory = client_factory
        self._client: McpClientLike | None = None
        self._lookups = 0

    @classmethod
    def from_env(
        cls, scan_url: str, recorder: CallRecorder, env: Mapping[str, str] = os.environ
    ) -> WebSearch | None:
        url = (env.get("WEB_SEARCH_GATEWAY_URL") or "").strip()
        if not url:
            return None
        if not url.startswith("https://"):
            logger.warning("web search disabled: WEB_SEARCH_GATEWAY_URL is not an https URL")
            return None
        match = _REGION_IN_HOST.search(urlsplit(url).netloc)
        region = env.get("WEB_SEARCH_REGION") or (
            match.group(1) if match else env.get("AWS_REGION", "")
        )
        if not region:
            logger.warning("web search disabled: no region configured")
            return None
        return cls(
            url,
            region,
            scan_url,
            recorder,
            tool_name=env.get("WEB_SEARCH_TOOL_NAME") or DEFAULT_TOOL_NAME,
        )

    async def lookup(self, brand: str) -> str:
        query = build_query(brand)
        if not query:
            return "web_search_skipped: no brand name to search for"
        cache_key = cache.websearch_key(_clean_brand(brand))
        cached = await asyncio.to_thread(self._cache_get, cache_key) if cache.enabled() else None
        if cached is not None:
            # No gateway call happened, so no web_search Call row and no lookup budget used.
            return self._render(query, cached)
        if self._lookups >= self.max_lookups:
            return f"web_search_limit: at most {self.max_lookups} lookups per scan"
        self._lookups += 1
        try:
            with self.recorder.record(CallKind.WEB_SEARCH, "brand_visual") as handle:
                payload = await self._search(query)
                if payload.get("status") != "success" or payload.get("isError"):
                    handle.status = "error"
                    logger.warning("web search returned an error result")
                    return "web_search_unavailable: the search returned an error"
                results = _results(payload)
        except Exception as exc:  # noqa: BLE001 - web search is optional evidence, never fatal
            logger.warning(
                "web search failed error=%s detail=%s",
                type(exc).__name__,
                str(exc).splitlines()[0][:200] if str(exc) else "",
            )
            return f"web_search_unavailable: {type(exc).__name__}"
        logger.info("web search ok results=%d", len(results))
        slim = _slim(results)
        if slim and cache.enabled():
            await asyncio.to_thread(
                cache.put, cache_key, {"results": slim}, cache.websearch_ttl_s()
            )
        return self._render(query, results)

    @staticmethod
    def _cache_get(key: str) -> list[dict] | None:
        stored = cache.get(key)
        results = stored.get("results") if stored else None
        if isinstance(results, list) and results and all(isinstance(r, dict) for r in results):
            return results
        return None

    async def _search(self, query: str) -> Mapping[str, Any]:
        if self._client is None:
            client = self._client_factory(self.url, self.region)
            # start() blocks while it connects, so it runs off the event loop.
            try:
                await asyncio.wait_for(asyncio.to_thread(client.start), START_TIMEOUT_S + 1)
            except BaseException:
                # close() only stops self._client, so a client that never started is stopped
                # here. A timed-out start() thread keeps running; stop() closes its HTTP pool,
                # which fails that thread's request rather than leaving the pool open.
                await self._stop(client)
                raise
            self._client = client
        return await asyncio.wait_for(
            self._client.call_tool_async(
                uuid.uuid4().hex,
                self.tool_name,
                {"query": query, "maxResults": MAX_RESULTS},
                read_timeout_seconds=timedelta(seconds=CALL_TIMEOUT_S),
            ),
            CALL_TIMEOUT_S + 1,
        )

    def _render(self, query: str, results: list[dict]) -> str:
        lines = [f"query: {query}"]
        for i, item in enumerate(results[:MAX_RESULTS], 1):
            if not isinstance(item, dict):
                continue
            url = _one_line(item.get("url"), 300)
            host = _host(url)
            marker = " [scanned site]" if _same_site(host, self.scan_host) else ""
            title = _one_line(item.get("title"), TITLE_LIMIT)
            snippet = _one_line(item.get("text"), SNIPPET_LIMIT)
            lines.append(f"{i}. {host or 'unknown host'}{marker} | {title} | {url} | {snippet}")
        if len(lines) == 1:
            lines.append("no results")
        return wrap_untrusted("web search results", "\n".join(lines), RESULTS_LIMIT)

    async def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            await self._stop(client)

    @staticmethod
    async def _stop(client: McpClientLike) -> None:
        try:
            await asyncio.to_thread(client.stop, None, None, None)
        except Exception as exc:  # noqa: BLE001 - cleanup must not replace the Finding
            logger.warning("web search client stop failed error=%s", type(exc).__name__)
