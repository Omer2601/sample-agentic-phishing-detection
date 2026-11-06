# url_analyst

Answers one question: does the URL itself, and the domain behind it, look like phishing?

|           |                                                                                                |
| --------- | ---------------------------------------------------------------------------------------------- |
| Runs on   | Amazon Bedrock AgentCore Runtime (`phish_url_analyst`), as an MCP server                       |
| Model     | `global.anthropic.claude-sonnet-5-5` (context flag `specialistModel`; Bedrock prompt caching on by default)                          |
| Called by | By default the worker, directly with `InvokeAgentRuntime`, at the same time as the other two specialists and the pre-check (`-c directSpecialists=false`: through the [dispatcher](dispatcher.md)). Harness path (`-c directOrchestration=false`): the [dispatcher](dispatcher.md) in the first round (`dispatcher___analyze_all`, concurrently with the other two specialists), and at most once more in an optional second round by the orchestrator, through AgentCore Gateway `phish-specialists` as `url-analyst___analyze`. |
| Tools     | By default `whois_lookup` runs in this agent's own process (`localRdap` or `directTools`, both on by default), with the same SSRF-guarded client and result cache. Only with `-c localRdap=false -c directTools=false` does it run in the shared tools server (`phish_tools_server`), called through the `phish-tools` Gateway as `tools___whois_lookup`. |
| Tools (detail) | `whois_lookup`: an RDAP lookup over HTTPS for the scan's registered domain. `check_redirects`: the URL's HTTP redirect chain, always in process |
| Prompt    | [`agents/phish_agents/url_analyst/prompt.md`](../../agents/phish_agents/url_analyst/prompt.md) |
| Code      | [`agents/phish_agents/url_analyst/`](../../agents/phish_agents/url_analyst/)                   |

It never renders the page. `whois_lookup` takes no arguments, so text in the URL cannot point it at another host. Every RDAP request passes the same SSRF guard as the browser. A failed lookup is not evidence either way; it only lowers confidence.

**Redirect chain.** `check_redirects` (no arguments) returns the URL's HTTP redirect chain from the same plain HTTP probe the pre-check uses (`common/http_probe.py`): GET requests, up to 5 redirects followed by hand, every hop through the SSRF guard, at most 64 KB read per hop, nothing parsed or executed, 6 s in total. The probe starts with the analysis and runs while the model reads the URL. The tool gives the model each hop with `cross_domain` (the hop moved to another site: a new registered domain, or a new subdomain of a free hosting service), `free_hosting` and `shortener` flags, plus `cross_domain_hops` and `final_host_differs`. A start host on free hosting or a shortener that hops to another site is `redirect_cross_domain`; a hop onto free hosting or a shortener is `redirect_to_free_hosting`. The chain is stored in the Finding's `redirect_chain` whether or not the model called the tool. When the chain ends at a host that does not resolve (or refuses the connection, or answers HTTP 410), code adds a `medium` `site_unreachable` signal: the orchestrator reads a redirect to a dead host as Site down. Script and meta refresh hops are not seen here (nothing runs); the browser specialists record those.

**Result cache.** When `PHISH_CACHE_TABLE` is set, the RDAP answer is cached per registered domain (`rdap#<domain>`, so `a.example.com` and `b.example.com` share one row) for `PHISH_RDAP_CACHE_TTL_S` seconds (default 7 days). The cache holds the raw fields (creation, expiry and last-changed dates, registrar, status, name servers), never the domain age: `age_days` is recomputed from the stored creation date on every read. Failures, 404s, rate limits and answers with neither a creation date nor a registrar are never stored. A cache error is logged and treated as a miss, so the lookup goes live exactly as without a cache; live lookups keep the SSRF check on every redirect hop. The cache sits inside `rdap_lookup`, so it serves both the in-process tool and the tools server `whois_lookup`. Hits are logged (`cache hit type=rdap`); the `Call` record format is unchanged.

## What it looks for

| Signal                             | What it means                                               | Example                                 |
| ---------------------------------- | ----------------------------------------------------------- | --------------------------------------- |
| Typosquatting                      | A brand name with swapped or look-alike characters          | `g00gle`, `paypa1`, `rn` for `m`        |
| Homoglyph or punycode              | Characters from another alphabet that look Latin            | `xn--pypal-4ve[.]com`                   |
| Suspicious TLD                     | A TLD often used for throwaway domains                      | `.xyz`, `.top` with a brand in the host |
| Deep or brand-bearing subdomain    | The brand sits left of an unrelated registered domain       | `paypal.com.verify-account[.]xyz`       |
| Free hosting or site builder abuse | A free host plus a brand or lure word                       | weebly, pages.dev, github.io, blogspot  |
| IP literal host                    | No domain at all                                            | `hxxp://203.0.113[.]7/login`            |
| Credential words in path or query  | Lure tokens stacked into the URL                            | `/secure/verify/login?update=wallet`    |
| Very new domain                    | RDAP creation date under 30 days (strong) or 180 (moderate) | registered 4 days ago                   |
| Redirect to another site           | A free host or shortener that hops to a different site      | `bit[.]ly/x` to `kit[.]pages[.]dev`     |
| Registrar or privacy-proxy pattern | Privacy-only registrant plus a brand look-alike             | registrant "REDACTED FOR PRIVACY"       |

## Input and output

Input: `analyze(url, scan_id)` with the URL and scan id from the orchestrator. Output: one `Finding`, also saved to `scans/{scan_id}/findings/url_analyst.json` in the artifacts bucket.

```json
{
  "agent": "url_analyst",
  "status": "ok",
  "verdict": "phishing",
  "confidence": 90,
  "signals": [
    {
      "name": "typosquatting",
      "severity": "high",
      "evidence": "g00gle-mobile-verif[.]com replaces o with 0 in google."
    },
    {
      "name": "new_domain",
      "severity": "high",
      "evidence": "RDAP creation date 2026-09-25, 4 days before the scan."
    }
  ],
  "artifacts": [],
  "usage": {
    "input_tokens": 1900,
    "output_tokens": 210,
    "model_id": "global.anthropic.claude-sonnet-5-5"
  },
  "latency_ms": 6200,
  "calls": []
}
```

The values are an example. Signal names such as `typosquatting` and `new_domain` are chosen by the model, so expect other names for the same evidence.

## How it is timed

It records two kinds of `Call`: `kind=whois`, `name=whois_lookup` and `kind=model`, `name=url_analyst`. The redirect probe overlaps the model call and records no `Call` of its own.

## When it fails

| `status`               | Cause                                                         | What the orchestrator does                   |
| ---------------------- | ------------------------------------------------------------- | -------------------------------------------- |
| `ok`                   | Normal result                                                 | Weighs it with the others                    |
| `blocked_by_guardrail` | The model refused the content, then refused a sanitized retry | Treats it as suspicious evidence             |
| `error`                | Timeout, model error or invalid output                        | Not a vote; lowers confidence, notes the gap |

## Try it on its own

```bash
uv run --package phish-agents python eval/evaluate_agents.py --agent url_analyst --limit 5 --region <your-region>
```
