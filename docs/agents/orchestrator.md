# orchestrator

Answers the final question: is this URL phishing, and what should you do about it?

|           |                                                                                                                                                                |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Runs on   | By default, no runtime of its own: the worker Lambda calls the model with the Amazon Bedrock Converse API. Harness path (`-c directOrchestration=false`): Amazon Bedrock AgentCore Harness (`phish_orchestrator`) |
| Model     | `us.anthropic.claude-opus-5-5` (context flag `orchestratorModel`)                                                                                              |
| Called by | The worker Lambda, twice per scan: the scan input with the three Findings, then `Write the full report now.` By default these are two Converse calls on one conversation; on the Harness path, two `InvokeHarness` calls on the same harness session |
| Tools | None by default: the worker has already run the specialists and puts their Findings in the message. Harness path: one tool, AgentCore Gateway `phish-specialists`, which fronts several targets: [`dispatcher___analyze_all`](dispatcher.md) for round one, the three specialist tools `url-analyst___analyze`, `brand-visual___analyze`, `code-analyst___analyze` for the optional second round, and, only with `-c agentRegistry=true`, the `registry` target (search of AWS Agent Registry, part of Amazon Bedrock AgentCore) |
| Prompt    | Default: [`backend/phish_backend/worker/orchestrator_direct.md`](../../backend/phish_backend/worker/orchestrator_direct.md). Harness path: [`agents/orchestrator/prompt.md`](../../agents/orchestrator/prompt.md) |
| Memory | None. On the Harness path the harness has no managed memory, the two turns of a scan share one runtime session, and the worker passes `actorId` = the scan id. Similar past scans come from the app's own AgentCore Memory, read by the worker |
| Code | Default: [`backend/phish_backend/worker/direct.py`](../../backend/phish_backend/worker/direct.py) and [`run_scan.py`](../../backend/phish_backend/worker/run_scan.py). Harness path: no Python for the agent itself, infra loads the prompt into the harness |

## What it does

Every model-backed scan ends here. The conversation has two turns: the verdict, then the report.

**Default path.** The worker invokes the three specialists itself, at the same time as the pre-check, reads their Findings from S3, and sends them to the orchestrator model in one Converse call (turn 1). The model calls no tools and there is no second round. When all three specialists answer `legitimate` at confidence 80 or more and nothing else needs weighing, the worker skips turn 1 (the unanimous fast path, see [configuration.md](../configuration.md)). The report is a second Converse call on the same conversation (turn 2). The rules below for judging, the compact turn 1 JSON and the report are the same on both paths.

**Harness path (`-c directOrchestration=false`).** The two turns run on one harness session. Turn 1 (the scan input) produces the verdict, fast:

0. Only with `-c agentRegistry=true` (off by default): searches Agent Registry once through the `registry` target on the same Gateway (the step in [`registry_step.md`](../../agents/orchestrator/registry_step.md), which infra inserts into the prompt). The lookup is informational: round one is still the dispatcher call, and the second round may use only a specialist tool whose record the search returned. If the lookup fails, the orchestrator notes `Registry lookup failed; used the known tools.` in `missed_by_specialists` and `## Gaps`, and goes on.
1. Calls [`dispatcher___analyze_all`](dispatcher.md) once with `url` and `scan_id`. The dispatcher runs the three specialists concurrently and returns their three Findings in a fixed order; each specialist saves its own Finding to S3.
2. Holds each `Finding` to a quality bar: well-formed, concrete evidence, `status` is `ok`.
3. Lists anything a specialist missed in `missed_by_specialists`, for example an off-domain password form that the brand check called legitimate, and records each pair of conflicting specialists in `disagreements`.
4. Judges with fixed rules, among them: a brand sign-in on a domain the brand does not own is phishing even when its form posts to its own host or its code looks clean; a captured copy of a known brand's sign-in or landing page with a sign-in, sign-up, account, payment or wallet action, on a domain the brand does not own, is at least `suspicious` with risk at least 50 even when nothing is wired up yet (this is a pre-publish gate), and it is phishing when the copy sits on a look-alike domain built from the brand or claims to be official and offers a sign-in, account or wallet action; a throwaway host (free hosting subdomain, shortener or new domain) that only bounces the visitor to a brand's real sign-in page is phishing; a Cloudflare "Suspected Phishing", "Suspected Misleading Website" or "Suspected Malware" warning is strong supporting evidence, the verdict is judged from the real page when a specialist captured it, and it is at most `suspicious` when none did (see [Page not observed](#page-not-observed)); redirect chains (from `url_analyst` and the browser captures) are evidence for the throwaway host rule, and a redirect to a host that does not resolve is Site down. Measured effect of the 2026-10-16 rules, before the warning rule changed: [evaluation.md](../evaluation.md#accuracy-on-live-phishing-2026-10-16).
5. Treats a `blocked_by_guardrail` finding as suspicious evidence about the page, not as a failure.
6. Optionally runs one second round, only when the first round leaves the verdict open (two findings conflict and neither has concrete evidence, or a failed finding is what the verdict depends on). The second round is bounded: one specialist tool (`url-analyst___analyze`, `brand-visual___analyze` or `code-analyst___analyze`, never the dispatcher again), called once more, for the conflicting or failed specialist only. A `blocked_by_guardrail` finding or an `error_404` or `site_down` page never triggers a second round. Most scans need none.
7. Replies with only a compact JSON object: `verdict`, `risk_score`, `confidence`, `action`, `summary`, `disagreements`, `missed_by_specialists`. No `report_markdown`, no tags, no code fence.

Turn 2 (the follow-up message `Write the full report now.`) produces the report, with no tool calls, from the findings already in the conversation:

8. Replies with only `{"report_markdown": "..."}`, with the same verdict as turn 1.

The split lets the worker store and show the verdict as soon as turn 1 ends, while the longer report (the slow part of Opus output) is written afterwards. The prompt sets a hard length budget. In turn 1 the short fields stay short (summary 2 sentences and 50 words, at most 3 disagreements and 3 missed points) because the result page shows them first. The worker enforces the summary's 50 words: a longer summary is cut to its first 50 words and ends in "...". It also defangs every URL and host name in the summary, `disagreements`, `missed_by_specialists` and `report_markdown` (`hxxps://evil[.]example`) before it stores them, so a report never holds a clickable phishing link; the scan's `url` field is stored exactly as submitted. The report is at most 450 words: a `## Reasoning` section of 150 to 250 words that explains how the judge weighed each specialist finding and resolved any disagreement, one decisive signal per specialist under `## Evidence`, and `## Recommended actions` with a list for the recipient and a list for the security team. With a 250 to 450 word reasoning section, 50 URLs measured p50 52.4 s per scan; with 150 to 250 words, p50 44.0 s (5 URLs: 38.4 s), and the orchestrator was about 70% of each scan (2026-09-30, `us-west-2`), measured when the report was part of the single answer. The `harnessMaxTokens` default of 8192 (the Converse `maxTokens` by default, the harness `MaxTokens` on the Harness path) lets thinking plus the report fit in either turn.

## Why a dispatcher

This section is about the Harness path. On the default path the worker invokes the three specialists concurrently itself, so neither the Harness nor the dispatcher is in the scan path.

The Harness runs same-turn Gateway tool calls one after another. Measured on 2026-10-16 in a separate test stack, the model asked for all three specialist tools in its first assistant message in 16 of 16 scans, but the harness ran them strictly one after another, in the order the model emitted them, with 0.1 to 1.9 s between one call ending and the next starting. A stronger "parallel tool use" prompt changed nothing, and the Harness APIs (CreateHarness, UpdateHarness, InvokeHarness) have no parallel tool execution setting. So round one is one tool, [`dispatcher___analyze_all`](dispatcher.md), whose Runtime calls the three specialists concurrently: the first round costs about the slowest specialist instead of the sum. The orchestrator still decides, judges every finding, and runs the optional second round itself with a single specialist tool. Median time to the verdict (turn 1, 5 URLs each):

| Shape (2026-10-16) | Median to the verdict | Range |
| --- | --- | --- |
| The orchestrator calls the three specialist tools itself (serial) | 40.1 s | 32.6 to 47.8 s |
| The same with a "parallel tool use" prompt | 40.7 s | 32.1 to 65.1 s |
| Earlier dispatcher design, effort `low` | 27.4 s | 20.1 to 40.2 s |
| No dispatcher, registry lookup first, effort `medium` (the default from 2026-10-16 to 2026-10-21) | 43.0 s | 38.3 to 55.5 s |

In the dispatcher run, the one scan where the model skipped the dispatcher and called the three specialist tools took 40.2 s, the same as the serial runs. The same serial behaviour was seen on 2026-09-29 and 2026-10-11. The dispatcher design (no registry, effort `medium`) measured on 2026-10-21, before orchestrator prompt caching: a median of 24.5 s and 35.0 s to the verdict in two runs of 7 single scans on an idle stack, and p50 42.5 s, p95 77.8 s in a 50-URL batch (68.8 s and 114.5 s without the dispatcher on 2026-10-18). In the test-suite run every model-backed scan made exactly one dispatcher call, and the three specialists were busy at the same time. Batch measurements of every design are in [evaluation.md](../evaluation.md#latency-history). With orchestrator prompt caching (the default since 2026-10-24): median 33.1 s and 33.9 s to the verdict in two runs of 7 single scans, p50 48.5 s in a rerun of the same 50-URL batch on a heavily loaded test machine ([evaluation.md](../evaluation.md#prompt-caching-rerun-2026-10-25)).

## Effort

Opus 5.5 always thinks, and `output_config.effort` is the only depth control. The worker passes `medium` (context flag `orchestratorEffort`) inside `additionalModelRequestFields.output_config.effort` on each call: each Converse call by default, each `InvokeHarness` call on the Harness path (verified live on Opus 5.5). That fits the job: in turn 1 the orchestrator reads three findings and decides, and in turn 2 it writes up a decision already made. `cdk.json` ships `medium`, the model default, because `low` broke the verdict JSON in 2 of 5 scans in the design without a dispatcher (2026-10-16). `-c orchestratorEffort=low` was faster by about 2.3 s at the median in that test (40.7 s against 43.0 s to the verdict on the same 5 URLs, Harness path, recorded in [`infra/phish_infra/config.py`](../../infra/phish_infra/config.py)); check verdict quality with scans on a test stack before using it (the evaluation script calls the Harness without the worker's effort setting, so it cannot measure this).

Prompt caching (context flag `orchestratorPromptCache`, on by default): by default the worker puts a Converse `cachePoint` after the system prompt, so the report turn reads it back from the Bedrock prompt cache. On the Harness path it sends `cache_control: {"type": "ephemeral"}` in `additionalModelRequestFields` instead, so each later model call of the scan reads the earlier prompt (system prompt, tools, and the turns so far) from the cache.

## Input and output

Input (the one user message the worker sends):

```text
Analyse this URL.
url: hxxp://g00gle-mobile-verif[.]com/
scan_id: 3f2a9c1e-7b4d-4e0a-9d61-0c8e5b2f7a10
```

The worker sends the real URL; it is defanged here so the example is not a live link.

With episodic memory on (`-c episodicMemory=true`, the default) and similar past scans found, up to three lines follow, for example:

```text
Context from earlier scans (similar past verdicts, not evidence for this URL; judge this URL only on the findings for it):
- hxxp://g00gle-verify[.]com/ | verdict=phishing | risk=93 | reason: Google sign-in clone posts credentials off-domain.
```

The past URLs are always defanged. A failed memory read sends the three-line message unchanged.

Output of turn 1 (compact JSON, no `report_markdown`):

```json
{"verdict":"phishing","risk_score":95,"confidence":"high","action":"block","summary":"A Google look-alike domain registered 4 days ago serves a Google sign-in copy that posts the password to another host.","disagreements":[],"missed_by_specialists":[]}
```

Second user message, on the same session:

```text
Write the full report now.
```

Output of turn 2 (JSON, no tool calls):

```json
{
  "report_markdown": "## Verdict\nPhishing, risk 95, block.\n## Reasoning\nAll three specialists called the page phishing, and their evidence is independent. url_analyst found a g00gle typosquat registered 4 days ago... (150 to 250 words in a real report)\n## Evidence\n- url_analyst: g00gle typosquat, domain age 4 days.\n- brand_visual: Google sign-in page on g00gle-mobile-verif[.]com.\n- code_analyst: password form posts to collect[.]example-drop[.]xyz.\n## Recommended actions\n### For the recipient\n- Do not sign in.\n- If you already entered your password, change it now.\n### For the security team\n- Block g00gle-mobile-verif[.]com.\n- Search mail logs for other recipients of the URL.\n## Gaps\nNone."
}
```

The worker stores the turn 1 object as the `Verdict` (scan `COMPLETE`, `report_status` `PENDING`), then screens the turn 2 text with the output guardrail, appends the human-review disclaimer and stores it as `report_markdown` (`report_status` `READY`). That code lives in [`backend/phish_backend/worker/run_scan.py`](../../backend/phish_backend/worker/run_scan.py).

## The `error_404` verdict

When the final navigated response for the submitted URL is HTTP 404, the orchestrator emits verdict `error_404` (displayed as "Error 404") instead of `unknown`. The values come from the existing enums:

- `risk_score` 10: the page does not exist, so there is nothing to harm the recipient, but the score is not 0 because a dead URL is not proof the sender was benign.
- `confidence` `high`: the status code is a fact observed by the browser, not a judgment.
- `action` `allow`: there is nothing to block, and `warn` would raise an alert for every dead link. `## Gaps` says the page was not available to judge.

`unknown` is kept for genuine no-evidence cases, such as no specialist answering.

## Page not observed

A provider warning is a third party's opinion, not the page. Until 2026-10-21 the prompt weighed a Cloudflare warning "like a confirmed report", so a pages.dev URL whose real page was never seen (Cloudflare's "Suspected Malware" page, Turnstile-gated) came out `phishing`, risk 80. Now the browser specialists try once to proceed past the warning ([brand_visual](brand_visual.md#when-it-fails)), and:

- When a specialist captured the real page, the verdict is judged from that page, with the warning as strong supporting evidence.
- When none did, the verdict is at most `suspicious`, `risk_score` at most 69 and `action` `warn`, and `summary` starts with "Page not observed:". The prompt asks for this, and the worker enforces it after turn 1 whatever the model answered ([`contracts/phish_contracts/observation.py`](../../contracts/phish_contracts/observation.py)): a `phishing` verdict becomes `suspicious`, the risk is capped at 69, `block` becomes `warn`, and the report gets a "Page not observed" note at its top. When the cap changed the verdict, risk or action, the model's own answer is kept in `verdict.capped_from` (`verdict`, `risk_score`, `action`), logged at INFO and shown as a line in the HTML report. The rule applies when a `cloudflare_phishing_warning` or `cloudflare_malware_warning` signal is present, or a `www_sibling_capture` signal is (see below), and no browser finding has `page_observed: true`; other capture gaps (`blocked_by_browser`, `tls_error`, `static_html_only`, bot checks) keep their existing rules.
- `www_sibling_capture`: the certificate does not cover the submitted `www.` name (`ERR_CERT_COMMON_NAME_INVALID`), so a browser specialist captured the same site without `www.` instead ([brand_visual](brand_visual.md#when-it-fails)). The `www.` and bare host belong to the same tenant or registrant, so that page is evidence about the same site operator; but the submitted page was not observed and a visitor following the link gets a certificate warning. A phishing-looking sibling therefore makes the scan at most `suspicious`, risk 50 to 69, `action` `warn`, under the same cap and the same "Page not observed" summary lead-in (the report note says the bare host was captured instead). A clean sibling never makes the verdict `legitimate` on its own: the URL evidence still stands.
- `Verdict.page_observed` records the outcome for every scan (`false` when no browser capture saw the real page, `true` when one did, absent when unknown).

A pre-publish gate that holds only at risk 70 or `action` `block` would let these URLs through, because they are capped at risk 69 and `warn`. Send `action` `warn` and `page_observed: false` to human review as well, as in the [API gate table](../api.md#use-it-as-a-pre-publish-gate) and the [gate in Getting started](../getting-started.md#test-the-api-a-pre-publish-gate). In the 2026-10-21 accuracy rerun this rule held 18 phishing URLs at `warn` ([evaluation](../evaluation.md#accuracy-rerun-2026-10-21)).

## How it is timed

The worker records `Call` rows with `kind=harness`, `name=orchestrator` around each orchestrator turn (the Converse call by default, the harness invocation on the Harness path; the report turn is named `report`), one `kind=specialist` row per Finding that starts when the specialists were invoked and lasts the Finding's `latency_ms` (there is no dispatcher row), and, with `-c agentRegistry=true`, one `kind=registry` row for the lookup. The specialists add their own calls inside each `Finding`.

## When it fails

| What happened                          | What you see                                                                           |
| -------------------------------------- | -------------------------------------------------------------------------------------- |
| One specialist returns `error`         | Not counted as a vote. Confidence drops and the report names the gap.                  |
| Two or more findings failed or blocked | Confidence is at most `medium`.                                                        |
| No specialist answered                 | Verdict `unknown`, risk score 50, confidence `low`, action `warn`.                     |
| The submitted URL returned HTTP 404    | Verdict `error_404` (shown as "Error 404"), risk score 10, confidence `high`, action `allow`. |
| A specialist reports the site could not be reached at all | Verdict `site_down` (shown as "Site down"), risk score 10, confidence `high`, action `allow`. |
| Turn 1 writes an enum value without its quotes (`"confidence":high`) | The worker quotes a bare or half-quoted `verdict`, `confidence` or `action` value before parsing, so the verdict is read as usual. Valid JSON is left unchanged, and the result is still validated. |
| Turn 1 is not valid verdict JSON       | The worker logs only the shape of the answer (length, brace and quote counts, the JSON decoder error and offset, and a class such as `truncated` or `unquoted_enum_value`), never its text, retries the scan (3 attempts in total), then marks it FAILED with a reason. In a 50-URL batch on 2026-10-18, 1 scan needed one retry; on 2026-10-16 some attempts failed this way, every visible case a bare `confidence` value (two real answers are kept as test cases in `contracts/tests/test_models.py`). |
| Turn 2 fails, is not valid JSON, or there is not enough time left | `report_status` becomes `FAILED` with a short reason; the verdict stands and the scan stays `COMPLETE`. A redelivered message resumes only the report. |
| A specialist hangs in the first round  | The specialist returns an `error` finding at its own deadline; the other two are unaffected. |
| The Agent Registry lookup fails (`-c agentRegistry=true` only) | The orchestrator notes it in `missed_by_specialists` and `## Gaps` and calls the dispatcher as usual; the scan goes on. |

## Try it on its own

```bash
uv run --package phish-agents python eval/evaluate_agents.py --agent orchestrator --limit 5 --region <your-region>
```
