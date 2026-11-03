# brand_visual

Answers one question: does the page pretend to be a brand, and is its look and copy built to deceive?

|           |                                                                                                                               |
| --------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Runs on   | Amazon Bedrock AgentCore Runtime (`phish_brand_visual`), as an MCP server                                                     |
| Model     | `global.anthropic.claude-sonnet-5-5` (context flag `specialistModel`; Bedrock prompt caching on by default)                                                         |
| Called by | The [dispatcher](dispatcher.md) in the first round (`dispatcher___analyze_all`, concurrently with the other two specialists), and at most once more in an optional second round by the orchestrator, through AgentCore Gateway `phish-specialists` as `brand-visual___analyze`. |
| Tools     | The tool runs in the shared tools MCP server (`phish_tools_server`); this agent calls it through the `phish-tools` Gateway as `tools___capture_page`. Local runs without `TOOLS_GATEWAY_URL` run it in process. |
| Tools (detail) | `capture_page`: opens the URL in AgentCore Browser, takes a viewport screenshot, reads the title, final URL and visible text. `lookup_official_domain(brand)` (with `-c webSearch=true`, the default): searches AgentCore Web Search for the brand's official website |
| Prompt    | [`agents/phish_agents/brand_visual/prompt.md`](../../agents/phish_agents/brand_visual/prompt.md)                              |
| Code      | [`agents/phish_agents/brand_visual/`](../../agents/phish_agents/brand_visual/)                                                |

It uses one AgentCore Browser session per URL and always closes it. The screenshot is saved to `scans/{scan_id}/screenshot.png` and shown on the result page.

## Web search

`lookup_official_domain` takes only a brand name. The code reduces it to a plain phrase of at most 80 characters, searches for `<brand> official website` and returns up to 5 results (host, title, URL, snippet) fenced as untrusted content. A result served from the scanned site is marked `[scanned site]`, so the page cannot confirm itself. The prompt has the model call it once whenever a brand is claimed and the serving domain is not clearly that brand's own (an earlier wording, "only when the official domain is not already known", led to no lookups at all in 64 test scans), and to treat the domain as confirmed only when independent results agree. When it confirms a domain, the evidence quotes that host, so the source stays cited in the report. The runtime talks to the Gateway with a small SigV4 JSON-RPC client (`common/gateway_mcp.py`) pinned to MCP protocol `2025-06-18`, because the Gateway refuses the `mcp` 2.1.1 handshake version.

The call goes over MCP to a small AgentCore Gateway in `us-east-1` (the `PhishTriageAgenticEdge` stack; when the stack is in `us-east-1`, `eu-west-1` or `ap-northeast-1` it is a regional Web Search Gateway in the main stack instead, separate from the tools Gateway), signed with SigV4 by the runtime role, which may invoke that gateway only. The gateway calls the AWS-owned Web Search connector with its own role. The runtime reads `WEB_SEARCH_GATEWAY_URL`, `WEB_SEARCH_REGION` and `WEB_SEARCH_TOOL_NAME`; without the URL (`-c webSearch=false`) the tool is not offered.

At most 2 lookups per scan, with 4 seconds to connect and 6 seconds per search, because the whole analysis has a 35 second deadline. A failure, time-out or refusal returns one line (`web_search_unavailable`, `web_search_limit` or `web_search_skipped`) and the agent judges as it would without web search. It is never an error Finding.

**Result cache.** When `PHISH_CACHE_TABLE` is set, a successful, non-empty search result is cached per normalized brand (`websearch#<brand>`, lowercase with spaces collapsed) for `PHISH_WEBSEARCH_CACHE_TTL_S` seconds (default 24 hours). Only the fields the tool renders are stored (URL, title and snippet, capped), and the `[scanned site]` marker is applied at read time against the current scan's host. Errors, time-outs, refusals and empty results are never cached. A hit makes no Gateway call, uses none of the 2-lookup budget and writes no `web_search` call row; it is logged as `cache hit type=websearch`. Any cache error is a miss and the Gateway path runs as before. Page capture and the model call are never cached.

## What it looks for

| Signal                         | What it means                                         | Example                                      |
| ------------------------------ | ----------------------------------------------------- | -------------------------------------------- |
| Impersonated brand             | A brand is named in the text, title or logo           | "Sign in with your Microsoft account"        |
| Login form that mimics a brand | A known sign-in page layout, colors and logo          | a copy of the Google sign-in card            |
| Brand and domain do not match  | The brand on the page does not own the serving domain | PayPal logo on `secure-pay-check[.]top`      |
| Urgency or scare copy          | Pressure to act now                                   | "Your account will be suspended in 24 hours" |
| Copied footer or legal text    | Legal text or links lifted from the real brand's site | "© Apple Inc." footer on an unrelated host   |

A copy of a known brand's sign-in or landing page with a sign-in, sign-up, account, payment or wallet action, on a domain the brand does not own, is reported as `brand_domain_mismatch` and at least `suspicious`, even when it calls itself a clone or demo or its buttons go nowhere; whether it sends data is the code analyst's call. Brand documentation or content with no such action is not covered.

A blank, parked or error page is not phishing on that basis alone. The agent returns `unknown` or `suspicious` with low confidence. An HTTP 404 is reported as a fact instead: a `low` `page_not_found` signal and verdict `error_404`.

## Input and output

Input: `analyze(url, scan_id)`. Output: one `Finding`, also saved to `scans/{scan_id}/findings/brand_visual.json`.

```json
{
  "agent": "brand_visual",
  "status": "ok",
  "verdict": "phishing",
  "confidence": 88,
  "signals": [
    {
      "name": "brand_domain_mismatch",
      "severity": "high",
      "evidence": "Google logo and sign-in card served from g00gle-mobile-verif[.]com."
    },
    {
      "name": "urgency_lure",
      "severity": "medium",
      "evidence": "Page text: 'Verify now or your account will be locked.'"
    }
  ],
  "artifacts": ["scans/3f2a9c1e-7b4d-4e0a-9d61-0c8e5b2f7a10/screenshot.png"],
  "usage": {
    "input_tokens": 8800,
    "output_tokens": 230,
    "model_id": "global.anthropic.claude-sonnet-5-5"
  },
  "latency_ms": 19400,
  "calls": []
}
```

## How it is timed

It records `kind=browser` for the browser session (`name=capture_page`, because the tools server captures), `kind=model`, `name=brand_visual` for the model call, and `kind=web_search`, `name=brand_visual` for each web search lookup.

## When it fails

| `status`               | Cause                                                              | What the orchestrator does                   |
| ---------------------- | ------------------------------------------------------------------ | -------------------------------------------- |
| `ok`                   | Normal result                                                      | Weighs it with the others                    |
| `blocked_by_guardrail` | The model refused the page, then refused a retry with trimmed text | Treats it as suspicious evidence             |
| `error`                | Analysis passed its 35 second deadline, or a model error        | Not a vote; lowers confidence, notes the gap |

When the page itself cannot be captured, the finding is still `ok` and the model judges from the URL. The capture reports one category, which is also logged with the exception class and the first line of its message (never page content):

| Category             | Cause                                                                                  |
| -------------------- | -------------------------------------------------------------------------------------- |
| `site_unreachable`   | The host does not resolve (checked before a browser session starts), or refused or reset the connection. Adds a deterministic `site_unreachable` signal: a dead phishing host is evidence, not an error. |
| `tls_error`          | The host answered, but its certificate or TLS setup was rejected (any `net::ERR_CERT_*` or `net::ERR_SSL_*`, for example `ERR_CERT_COMMON_NAME_INVALID`, `ERR_CERT_AUTHORITY_INVALID`, `ERR_CERT_DATE_INVALID`). Adds a `low` `tls_error` signal. It is a capture gap: the site is not down (something answered), and a bad certificate alone is not evidence of phishing (neglected legitimate sites have them, most phishing kits have valid free certificates). |
| `navigation_timeout` | The page did not reach DOMContentLoaded within its navigation share of the 14 second capture budget (at most 12 seconds). |
| `blocked_by_guard`   | Our URL safety (SSRF) guard refused the URL, a redirect hop or the final URL, for example an internal address or a host that could not be resolved right now. Adds a `low` `blocked_by_guard` signal with the reason: our policy, not evidence. The guard aborts with `net::ERR_ACCESS_DENIED` so it cannot be confused with the browser's own refusal. |
| `blocked_by_browser` | The browser, or the AgentCore Browser service, refused the navigation (`net::ERR_BLOCKED_BY_CLIENT`, `ERR_BLOCKED_BY_ADMINISTRATOR`, or a `chrome-error://` page) and our guard did not. Adds a `low` `blocked_by_browser` signal. It is a capture gap, not evidence: the managed browser refuses some URLs before sending any request (its own blocklists also cover ads and trackers), so it says nothing about the page. |
| `blocked_by_site`    | The site refused the browser during navigation (`net::ERR_BLOCKED_BY_RESPONSE`). Adds a `low` `blocked_by_site` signal. |
| `browser_error`      | AgentCore Browser session or CDP failure, for example a throttled session start.       |
| `internal_error`     | A bug in the capture code.                                                             |

A page that loads but is a block page is still captured, and the signal names the kind of block: Cloudflare's own "Suspected Phishing" or "Suspected Misleading Website" warning adds a `high` `cloudflare_phishing_warning` signal and its "Suspected Malware" warning a `high` `cloudflare_malware_warning` signal (third-party evidence; see the click-through below); a bot filter such as EggyWall adds a `medium` `cloaking_bot_filter` signal; an interactive bot check ("Just a moment...", a captcha, "unusual traffic") adds a `low` `bot_challenge` signal; any other block (HTTP 401, 403, 406, 429 or 451, or a title such as "Access denied") adds a `low` `blocked_by_site` signal. Every incomplete capture also sets `capture_note`, one plain sentence shown under the screenshot in the console.

**The click past a provider warning.** On a Cloudflare warning page the capture tries once to reach the real page, inside the same capture budget (at most 8 s, and never past the screenshot's reserved time). It clicks only the warning's own proceed control (`#bypass-button` inside the same-origin `form[action="/cdn-cgi/phish-bypass"]`), and only when that control is enabled. Cloudflare keeps the button disabled until its Turnstile widget calls back: the capture never touches the widget and never solves a captcha or bot check; it waits at most 3 s for the button to enable on its own, then stops. Every interstitial saved so far (2026-10-16 and 2026-10-21) had a Turnstile-gated button or no button at all, so expect most warnings to end there. A stopped click adds a `low` `warning_bypass_blocked` signal (the reason: `turnstile`, `proceed_disabled`, `no_proceed_control`, `no_navigation`, `still_on_warning` or `no_time`), the warning signal's evidence says the real page was not observed, and the screenshot is the warning. A click that gets through captures the real page (screenshot, text, DOM, forms and scripts) and the warning signal says so. Nothing else on either page is clicked, typed or submitted. Every hop of the click's navigation and the final URL pass the same URL guard as the first navigation.

**Redirect chain and page_observed.** The Finding's `redirect_chain` lists how the browser reached the captured page, oldest first: `via` is `start`, `http` (a 3xx), `client` (a script or meta refresh navigation, including one during the settle) or `warning_bypass` (the click above), with the hop's status, any `net::ERR_*` error and `cross_domain`, `free_hosting` and `shortener` flags. Every hop is checked by the URL guard; a script redirect to a host that does not resolve fails the capture as `site_unreachable`. `page_observed` is `true` when the capture saw the site's real page and `false` when a provider warning, bot check, block page or failed capture stood in front of it.

**The www. sibling.** When the capture fails with `tls_error` and the code is `net::ERR_CERT_COMMON_NAME_INVALID`, and the submitted host starts with `www.` with at least two labels after it, the certificate does not cover the `www.` name (a free host's wildcard covers `*.vercel.app`, not `www.*.vercel.app`). The capture then tries once, in the same browser session and inside navigation's share of the same budget (no deadline is extended; with less than 1 second left it is skipped), to open the same site without `www.`: `https://` plus the bare host, with the same port, path and query (`www_sibling_url` in [`common/browser.py`](../../agents/phish_agents/common/browser.py)). It goes through the same `preflight()` and `navigate()` as the first URL, so the URL guard checks the sibling host, every hop and the final URL. It is never recursive, and if the sibling fails too the original `tls_error` is the reported failure. On success it takes the screenshot (uploaded under the usual `screenshot.png` key, since it is evidence) and the visible text of that page, and the capture data carries `sibling_capture` (`submitted_url`, `captured_url`, `reason`). The Finding keeps the `low` `tls_error` signal for the submitted URL and adds a `low` `www_sibling_capture` signal naming both URLs. The tool text says plainly that the page shown is the same site without `www.`, captured because the certificate does not cover `www.`, and that the submitted URL shows a certificate warning to visitors. `page_observed` stays `false`: the submitted page was not seen, so the [page-not-observed cap](orchestrator.md#page-not-observed) applies.

A final response of HTTP 404 is also captured and gets a `low` `page_not_found` signal (the tool text carries a `page_not_found` field). The agent reports the 404 and does not call the page phishing on that basis; other 4xx and 5xx statuses behave as before.

## Try it on its own

```bash
uv run --package phish-agents python eval/evaluate_agents.py --agent brand_visual --limit 5 --region <your-region>
```
