# code_analyst

Answers one question: does the page's code steal, hide or send away what you type?

|           |                                                                                                                                                                                        |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Runs on   | Amazon Bedrock AgentCore Runtime (`phish_code_analyst`), as an MCP server                                                                                                              |
| Model     | `global.anthropic.claude-sonnet-5-5` (context flag `specialistModel`; Bedrock prompt caching on by default)                                                                                                                  |
| Called by | By default the worker, directly with `InvokeAgentRuntime`, at the same time as the other two specialists and the pre-check (`-c directSpecialists=false`: through the [dispatcher](dispatcher.md)). Harness path (`-c directOrchestration=false`): the [dispatcher](dispatcher.md) in the first round (`dispatcher___analyze_all`, concurrently with the other two specialists), and at most once more in an optional second round by the orchestrator, through AgentCore Gateway `phish-specialists` as `code-analyst___analyze`. |
| Tools     | By default this agent calls its own copy of the tools runtime (`<appName>_tools_code`) directly with `InvokeAgentRuntime`, as `capture_page_code`, on the scan's tools session (`-c splitToolsRuntimes=false`: the shared `phish_tools_server` runtime). With `-c directTools=false` it calls the shared tools server through the `phish-tools` Gateway as `tools___capture_page_code`. Local runs without `TOOLS_RUNTIME_ARN` or `TOOLS_GATEWAY_URL` run it in process. |
| Tools (detail) | `capture_page_code`: opens the URL in its own AgentCore Browser session and captures the rendered DOM, inline and external scripts, network requests, form actions and event listeners. When the browser cannot load the page, it returns a bounded excerpt of the page's raw HTML instead (see [Raw HTML fallback](#raw-html-fallback)) |
| Prompt    | [`agents/phish_agents/code_analyst/prompt.md`](../../agents/phish_agents/code_analyst/prompt.md)                                                                                       |
| Code      | [`agents/phish_agents/code_analyst/`](../../agents/phish_agents/code_analyst/)                                                                                                         |

It opens its own browser session, separate from `brand_visual`, so the two captures do not share state. It runs concurrently with the other two specialists: by default the worker invokes all three at once, and on the Harness path the dispatcher does (see [orchestrator.md](orchestrator.md#why-a-dispatcher)). The capture is saved to `scans/{scan_id}/capture.json`. Page code is data: it runs only inside the AgentCore Browser sandbox and is never executed anywhere else; the raw HTML fallback only reads it.

## What it looks for

| Signal                        | What it means                                          | Example                                            |
| ----------------------------- | ------------------------------------------------------ | -------------------------------------------------- |
| Off-origin credential form    | A password form posts to another host                  | `<form action="hxxps://collect.drop[.]xyz/p">`     |
| Keylogger                     | `keydown` or `input` listeners that send what you type | a listener that calls `fetch` on every key         |
| Obfuscation                   | Code hidden from a reader                              | `eval(atob("..."))`, packed or hex strings         |
| Exfiltration endpoint         | Data sent to a collection service                      | Telegram bot API, webhook services, raw IP hosts   |
| Injected or remote scripts    | Scripts loaded from unrelated domains                  | a script from `cdn-js-update[.]top`                |
| Clipboard or wallet hijacking | Code that rewrites copied text or wallet addresses     | a `copy` listener that swaps a crypto address      |
| Anti-analysis                 | Content hidden from tools or researchers               | devtools detection, bot checks that blank the page |

## Input and output

Input: `analyze(url, scan_id)`. Output: one `Finding`, also saved to `scans/{scan_id}/findings/code_analyst.json`.

```json
{
  "agent": "code_analyst",
  "status": "ok",
  "verdict": "phishing",
  "confidence": 93,
  "signals": [
    {
      "name": "credential_form_off_domain",
      "severity": "critical",
      "evidence": "Password form action posts to collect[.]example-drop[.]xyz."
    },
    {
      "name": "key_listener_on_sensitive_input",
      "severity": "high",
      "evidence": "keydown listener on the password field sends each key with fetch."
    }
  ],
  "artifacts": ["scans/3f2a9c1e-7b4d-4e0a-9d61-0c8e5b2f7a10/capture.json"],
  "usage": {
    "input_tokens": 7400,
    "output_tokens": 260,
    "model_id": "global.anthropic.claude-sonnet-5-5"
  },
  "latency_ms": 21800,
  "calls": []
}
```

The values are an example. Signals that code derives from the capture have fixed names, such as `credential_form_off_domain` and `key_listener_on_sensitive_input` above (see `agents/phish_agents/code_analyst/heuristics.py`); the model may add signals under names it chooses.

## How it is timed

It records `kind=browser` for the browser session (`name=capture_page_code`, because the tools server captures) and `kind=model`, `name=code_analyst` for the model call.

The 42 second deadline has to hold a model turn that calls the tool, the capture and the answer turn, so the capture has its own hard budget of 18 seconds, session start included (`CAPTURE_BUDGET_S` in `code_analyst/capture.py`). The browser gets the first 15 seconds: navigation (at most 15 seconds, and never past 13 seconds into the capture), the networkidle settle and the click past a provider warning come out of the first 13, and the DOM probe, rendered DOM and script bodies must finish by 15, or the capture fails as `navigation_timeout` with code `capture_budget`. Closing the CDP connection and stopping the browser session get at most 2 seconds each. The last 3 seconds are kept for the raw HTML fallback. The tools server stops a capture that still runs at 20 seconds and the specialist's call to the tools runtime gives up at 30 seconds; both are backstops. With `-c latencyBudgets=false` the earlier values apply: a 35 second deadline, a 20 second budget (browser 16 seconds, navigation never past 14, fallback 4), and backstops at 22 and 25 seconds. Before 2026-10-26 the capture could run to 25 seconds (28 on the client) and nothing after navigation had a bound, so a page that never loaded plus both model turns passed the deadline: 12 of 103 scans in one feed batch (11 on `www.roblox.rw`) ended as `error` with reason `timeout` and no code was seen.

## When it fails

| `status`               | Cause                                                                         | What the orchestrator does                   |
| ---------------------- | ----------------------------------------------------------------------------- | -------------------------------------------- |
| `ok`                   | Normal result                                                                 | Weighs it with the others                    |
| `blocked_by_guardrail` | The model refused the code, then refused a retry with string literals removed | Treats it as suspicious evidence             |
| `error`                | Analysis passed its 42 second deadline (35 with `-c latencyBudgets=false`), or a model error | Not a vote; lowers confidence, notes the gap |

When the page itself cannot be captured, the finding is still `ok` and the model judges from the URL. The capture reports one category, which is also logged with the exception class and the first line of its message (never page content):

| Category             | Cause                                                                                  |
| -------------------- | -------------------------------------------------------------------------------------- |
| `site_unreachable`   | The host does not resolve (checked before a browser session starts), or refused or reset the connection. Adds a deterministic `site_unreachable` signal: a dead phishing host is evidence, not an error. |
| `tls_error`          | The host answered, but its certificate or TLS setup was rejected (any `net::ERR_CERT_*` or `net::ERR_SSL_*`, for example `ERR_CERT_COMMON_NAME_INVALID`, `ERR_CERT_AUTHORITY_INVALID`, `ERR_CERT_DATE_INVALID`). Adds a `low` `tls_error` signal. It is a capture gap: the site is not down (something answered), and a bad certificate alone is not evidence of phishing (neglected legitimate sites have them, most phishing kits have valid free certificates). |
| `navigation_timeout` | The page did not reach DOMContentLoaded in time (at most 15 seconds, and never past 13 seconds into the capture, 14 with `-c latencyBudgets=false`), or the capture used up its browser budget (code `capture_budget`). |
| `blocked_by_guard`   | Our URL safety (SSRF) guard refused the URL, a redirect hop or the final URL, for example an internal address or a host that could not be resolved right now. Adds a `low` `blocked_by_guard` signal with the reason: our policy, not evidence. The guard aborts with `net::ERR_ACCESS_DENIED` so it cannot be confused with the browser's own refusal. |
| `blocked_by_browser` | The browser, or the AgentCore Browser service, refused the navigation (`net::ERR_BLOCKED_BY_CLIENT`, `ERR_BLOCKED_BY_ADMINISTRATOR`, or a `chrome-error://` page) and our guard did not. Adds a `low` `blocked_by_browser` signal. It is a capture gap, not evidence: the managed browser refuses some URLs before sending any request (its own blocklists also cover ads and trackers), so it says nothing about the page. |
| `blocked_by_site`    | The site refused the browser during navigation (`net::ERR_BLOCKED_BY_RESPONSE`). Adds a `low` `blocked_by_site` signal. |
| `browser_error`      | AgentCore Browser session or CDP failure, for example a throttled session start.       |
| `internal_error`     | A bug in the capture code.                                                             |

A page that loads but is a block page is still captured, and the signal names the kind of block: Cloudflare's own "Suspected Phishing" or "Suspected Misleading Website" warning adds a `high` `cloudflare_phishing_warning` signal and its "Suspected Malware" warning a `high` `cloudflare_malware_warning` signal (third-party evidence; see the click-through below); a bot filter such as EggyWall adds a `medium` `cloaking_bot_filter` signal; an interactive bot check ("Just a moment...", a captcha, "unusual traffic") adds a `low` `bot_challenge` signal; any other block (HTTP 401, 403, 406, 429 or 451, or a title such as "Access denied") adds a `low` `blocked_by_site` signal. Every incomplete capture also sets `capture_note`, one plain sentence shown under the screenshot in the console.

**The click past a provider warning.** On a Cloudflare warning page the capture tries once to reach the real page, inside the same capture budget (at most 8 s, and never past the screenshot's reserved time). It clicks only the warning's own proceed control (`#bypass-button` inside the same-origin `form[action="/cdn-cgi/phish-bypass"]`), and only when that control is enabled. Cloudflare keeps the button disabled until its Turnstile widget calls back: the capture never touches the widget and never solves a captcha or bot check; it waits at most 3 s for the button to enable on its own, then stops. Every interstitial saved so far (2026-10-16 and 2026-10-21) had a Turnstile-gated button or no button at all, so expect most warnings to end there. A stopped click adds a `low` `warning_bypass_blocked` signal (the reason: `turnstile`, `proceed_disabled`, `no_proceed_control`, `no_navigation`, `still_on_warning` or `no_time`), the warning signal's evidence says the real page was not observed, and the screenshot is the warning. A click that gets through captures the real page (screenshot, text, DOM, forms and scripts) and the warning signal says so. Nothing else on either page is clicked, typed or submitted. Every hop of the click's navigation and the final URL pass the same URL guard as the first navigation.

**Redirect chain and page_observed.** The Finding's `redirect_chain` lists how the browser reached the captured page, oldest first: `via` is `start`, `http` (a 3xx), `client` (a script or meta refresh navigation, including one during the settle) or `warning_bypass` (the click above), with the hop's status, any `net::ERR_*` error and `cross_domain`, `free_hosting` and `shortener` flags. Every hop is checked by the URL guard; a script redirect to a host that does not resolve fails the capture as `site_unreachable`. `page_observed` is `true` when the capture saw the site's real page and `false` when a provider warning, bot check, block page or failed capture stood in front of it.

**The www. sibling.** When the capture fails with `tls_error` and the code is `net::ERR_CERT_COMMON_NAME_INVALID`, and the submitted host starts with `www.` with at least two labels after it, the certificate does not cover the `www.` name (a free host's wildcard covers `*.vercel.app`, not `www.*.vercel.app`). The capture then tries once, in the same browser session and inside navigation's share of the same budget (no deadline is extended; with less than 1 second left it is skipped), to open the same site without `www.`: `https://` plus the bare host, with the same port, path and query (`www_sibling_url` in [`common/browser.py`](../../agents/phish_agents/common/browser.py)). It goes through the same `preflight()` and `navigate()` as the first URL, so the URL guard checks the sibling host, every hop and the final URL. It is never recursive, and if the sibling fails too the original `tls_error` is the reported failure. On success it analyses that page's DOM, scripts and requests as usual (the requests of the failed attempt are dropped), and the capture data carries `sibling_capture` (`submitted_url`, `captured_url`, `reason`). The Finding keeps the `low` `tls_error` signal for the submitted URL and adds a `low` `www_sibling_capture` signal naming both URLs. The tool text says plainly that the page shown is the same site without `www.`, captured because the certificate does not cover `www.`, and that the submitted URL shows a certificate warning to visitors. `page_observed` stays `false`: the submitted page was not seen, so the [page-not-observed cap](orchestrator.md#page-not-observed) applies.

### Raw HTML fallback

When the browser capture fails as `navigation_timeout`, `blocked_by_browser` or a `browser_error` raised inside the capture, the tools server (in process for local runs) reads the page's raw HTML with the same guarded HTTP probe the pre-check and `url_analyst` use (GET, redirects followed by hand, at most 5, every hop through the URL safety guard and connected only to the address it approved, at most 64 KB read on the wire, never decompressed), within what is left of the 18 second budget (20 with `-c latencyBudgets=false`). It is not tried after `tls_error` (the GET would meet the same certificate), `site_unreachable`, `blocked_by_guard` or `blocked_by_site`, nor when the call to the tools server itself fails (`browser_error: tools_gateway`): the fallback runs inside the tools server, so that Finding has no `static_html_only` signal. The HTML is never executed and nothing it links to is fetched: Python's `html.parser` splits it into tags, and the tool keeps a bounded excerpt (`static_html`). It leads with `derived_signals` (the same heuristics as a rendered capture) and `external_hosts`, both computed from the whole page before anything is cut, and `dropped`, the number of forms, inputs, script sources, inline scripts, iframes and hosts the caps left out; then title, `base_href`, forms (those with a password input first; per form the action, method, input types and names with hidden inputs last, any button or input `formaction`, and `inputs_dropped`), inputs outside forms, script sources, inline script snippets (2,000 characters each, 12,000 in total), iframes, meta refresh, the final URL and hops. Form actions, formactions, script sources and iframes are resolved against `<base href>` when the page sets one, as a browser would, and a formaction is judged like the form action (an off-domain one on a password form is `credential_form_off_domain`). Padding a page with decoy forms, scripts or hidden inputs therefore cannot push the evidence out of the excerpt. The model sees it fenced as untrusted content under the label "raw HTML excerpt, not rendered, scripts not run". No excerpt is made from a Cloudflare warning, a bot challenge (by title, or Cloudflare's `cf-mitigated` header), a cloaking filter or any other block page, from a final status outside 200 to 399, or from a body that is not declared `text/html` or `application/xhtml+xml` (a missing type included) or is served compressed: that HTML is the block page, not the site, or not a page at all. The capture still counts as failed: `page_observed` stays `false`, the Finding gets a `low` `static_html_only` signal (next to any gap signal such as `blocked_by_browser`), `capture_note` says the raw HTML was read instead of the rendered page, and `insights` stay empty. The verdict can be `phishing`, `suspicious` or `unknown`, never `legitimate`: finding nothing in raw HTML is not evidence that the page is safe (a kit can serve a clean page to a plain GET and build its form by script), so the prompt says so and code turns a `legitimate` answer into `unknown`, keeping the model's signals and confidence. The excerpt is saved in `capture.json` (a failed upload is logged and the result kept).

A final response of HTTP 404 is also captured and gets a `low` `page_not_found` signal (the tool text carries a `page_not_found` field). The agent reports the 404 and does not call the page phishing on that basis; other 4xx and 5xx statuses behave as before.

## Try it on its own

```bash
uv run --package phish-agents python eval/evaluate_agents.py --agent code_analyst --limit 5 --region <your-region>
```

## Code insights

Every complete capture also fills `insights`, measured by code and never by the model: the endpoints the page sends data to (fetch, XHR, beacons and websockets, defanged, off-domain first, known analytics left out), its forms and whether a script submits them, the number and size of its scripts, and the external hosts its scripts load from. The console shows it as "What the page's code does".
