# Evaluation

You can measure how well each agent, and the whole team, labels a set of URLs you already know the answer to. This page also keeps the measured latency and cost of the current design and of every earlier design, so the README can stay short.

**On this page:** [Run it](#run-it) · [The dataset](#the-dataset) · [Metrics](#metrics) · [Compare with hosted scanners](#compare-with-hosted-scanners) · [Accuracy on live phishing](#accuracy-on-live-phishing-2026-10-16) · [Accuracy rerun, 2026-10-21](#accuracy-rerun-2026-10-21) · [Harness path design](#harness-path-design-default-2026-10-21-to-2026-11-02) · [Prompt caching rerun](#prompt-caching-rerun-2026-10-25) · [Accuracy rerun, 2026-10-26](#accuracy-rerun-2026-10-26) · [Accuracy rerun, 2026-10-27](#accuracy-rerun-2026-10-27) · [Each latency flag on its own](#each-latency-flag-on-its-own-2026-11-03) · [Latency history](#latency-history) · [Cost history](#cost-history) · [Limitations](#limitations)

> [!WARNING]
> Every URL is a paid call to Amazon Bedrock and AgentCore, and each one opens real web pages. Start with `--limit 5`. A full run of the committed sample can take 20 minutes or more: the script calls each of the 4 agents for each of the 21 URLs one at a time (84 calls), and one call takes about 6 to 35 s.

## Run it

```bash
export AWS_REGION=<your-region>
uv run --package phish-agents python eval/evaluate_agents.py --agent all --limit 10
```

| Flag              | Values                                                               | Default                          |
| ----------------- | -------------------------------------------------------------------- | -------------------------------- |
| `--agent`         | `all`, `orchestrator`, `url_analyst`, `brand_visual`, `code_analyst` | `all`                            |
| `--limit`         | How many rows of the dataset to use                                  | every row                        |
| `--dataset`       | Path to a CSV of `url,label`                                         | `eval/data/committed_sample.csv` |
| `--stack`         | The stack whose outputs name the agents                              | `PhishTriageAgentic`             |
| `--region`        | Region of the stack                                                  | the session Region (`AWS_REGION` or your profile's Region) |
| `--suspicious-as` | Count a `suspicious` verdict as `phishing` or `legitimate`           | `phishing`                       |

Each specialist is called on its own AgentCore Runtime, and `orchestrator` runs the full team through the harness, so you can see which agent helps and which one misses. The `orchestrator` run is one verdict turn on the Harness, without the worker's effort and prompt-caching settings, the report turn or the worker's page-not-observed cap, so its verdicts can differ from a scan through the API. Raw results go to `eval/results/<utc-time>.json`.

## The dataset

`eval/data/committed_sample.csv` has 21 labelled URLs: 16 legitimate domains and 5 phishing test pages published for security testing. It is safe to commit and stable over time.

To use your own data, write a CSV with a header `url,label` where `label` is `phishing` or `legitimate`, and pass it with `--dataset`. Keep live phishing feeds out of the repository.

## Metrics

- **Precision**: of the URLs called phishing, how many were phishing. Low precision means false alarms.
- **Recall**: of the phishing URLs, how many were caught. Low recall means misses.
- **F1**: one number that balances the two.
- **False positive rate**: of the legitimate URLs, how many were called phishing.
- **`--suspicious-as`**: a `suspicious` verdict is not a yes or a no. Scoring it both ways shows how much your result depends on that choice.

## Compare with hosted scanners

`eval/benchmark_vendors.py` sends the same labelled URLs to two hosted URL scanners and scores them with the same metrics as `evaluate_agents.py`, next to this sample's own rows from a results file. The output names the scanners only as Vendor 1 and Vendor 2.

```bash
export VT_API_KEY=<key> URLSCAN_API_KEY=<key>   # Vendor 1, Vendor 2; a missing key skips that vendor
uv run --package phish-agents python eval/benchmark_vendors.py \
  --ours eval/results/<utc-time>.json --limit 5
```

| Flag                    | Values                                                                     | Default                          |
| ----------------------- | -------------------------------------------------------------------------- | -------------------------------- |
| `--dataset`, `--limit`  | As for `evaluate_agents.py`                                                | `eval/data/committed_sample.csv` |
| `--ours`                | An `evaluate_agents.py` results file, scored on the same URLs              | no row for this sample           |
| `--ours-agent`          | Which agent's rows to use from that file                                   | `orchestrator`                   |
| `--vt-min-detections`   | Vendor 1 calls a URL phishing at this many detections or more              | `1`                              |
| `--vt-count-suspicious` | Count Vendor 1 `suspicious` detections as well as `malicious`              | off                              |
| `--out-dir`             | Where the CSV, the summary and the cache go                                | `eval/results/vendors`           |

- **Output.** `<utc-time>.csv` has one row per scanner and URL (prediction and the vendor's raw counts or error). `<utc-time>.md` is a table of recall, false positive rate and unscored URLs per scanner, with the run date, the URL count and the Vendor 1 threshold. A URL with no verdict (an error or a time-out) is unscored and left out of recall and false positive rate. Our row uses the `evaluate_agents.py` scoring (`--suspicious-as`), not the risk-50 "caught" rule of the runs below.
- **Resumable.** Each finished vendor response is cached under `eval/results/vendors/cache/` (gitignored), so a rerun skips URLs already done. Rate-limited and network failures are not cached and are retried on the next run.
- **Rate limits.** Vendor 1's public API allows 4 requests a minute and 500 a day, so the script waits at least 15 s between calls and needs at least two calls per URL (about 250 URLs a day at most). When it is still rate limited after its retries it stops that vendor for the run; rerun the next day to resume. Every 429 is retried with backoff, honoring `Retry-After`.
- **Scans are unlisted.** Vendor 2 scans are always submitted with visibility `unlisted`, never `public`. This is hard-coded, not a flag.
- **Submitted URLs leave your account.** Both vendors keep what you submit, and unlisted scans are still visible to the vendor and its vetted users. Do not submit private or customer URLs.
- **Check the terms before you publish.** Read each vendor's terms of service before publishing results. The VirusTotal public API is for non-commercial use only, and some terms limit publishing comparisons. Get permission, or a commercial key, where the terms require it.

## Accuracy on live phishing, 2026-10-16

Measured on a test stack in `us-west-2` with a private labelled set that is not in this repository: 104 URLs, 58 phishing and 46 legitimate. Phishing URLs came from a public feed and were kept only when a fresh capture in AgentCore Browser clearly showed phishing (a brand sign-in, payment or wallet page on a domain the brand does not own, a lure, a bounce from a throwaway host to a brand sign-in, or a Cloudflare phishing or malware warning). Stale and false-positive feed entries were dropped. Legitimate URLs are real sign-in pages of large brands and banks, popular sites, brand-owned shorteners (for example `aka[.]ms`), GitHub Pages, Vercel and Netlify projects, and feed false positives such as static UI clones with no credential capture. Each URL was labelled by a person from its screenshot and capture.

Caught means the verdict is phishing, or suspicious with risk 50 or more (`warn` or `block` in a gate). A false positive is a legitimate URL that is caught. URLs whose page was gone by scan time (Error 404, Site down) or whose scan failed are left out; 100 URLs were live in every run.

> [!NOTE]
> How the accuracy numbers on this page were made: every run below used a private labelled URL set that is not in this repository, and was scored with a separate scoring script, not in this repository, that applies the rule above (caught = phishing, or suspicious at risk 50 or more) to scans on a test stack. `eval/evaluate_agents.py` has no risk threshold (it counts every `suspicious` verdict by `--suspicious-as`), so it does not reproduce these numbers. You can reproduce the method with your own labelled set and this scoring rule, but not the exact set.

| Run (100 URLs live in every run) | Recall, caught | Recall, phishing verdict only | False positive rate |
| --- | --- | --- | --- |
| Before the changes below | 0.963 (52 of 54) | 0.759 (41 of 54) | 0.022 (1 of 46) |
| + Cloudflare "Suspected Malware" page recognised (`cloudflare_malware_warning`) | 0.962 (50 of 52, 2 scans failed) | 0.808 (42 of 52) | 0.022 |
| + a throwaway host that only bounces to a brand's real sign-in page is phishing | 0.963 | 0.870 (47 of 54) | 0.022 |
| + a same-site form or clean code does not clear a brand sign-in on a domain the brand does not own | 0.963 (52 of 54) | 0.889 (48 of 54) | 0.0 (0 of 46) |

The two URLs still missed were a page the browser could not open (HTTP error behind a provider warning) and a brand lure whose browser capture was refused, both capture gaps. Phishing scored suspicious at 55 to 75 include brand lure pages on documentation hosts with no form (the next step is an outbound link), and a sign-in copy whose code showed a security-awareness simulation.

Caveats: the set is small and recent, so one URL is about 2 points of recall. Live pages change between runs. The orchestrator harness keeps no memory between scans (its managed memory is off in this release, so no harness state carries from one scan to the next). The app's own episodic memory (`episodicMemory`, on by default) is separate: it still passes up to three similar past scans to the orchestrator, labelled as context and not evidence, so a rescan of the same URL can lean toward its earlier verdict and the gains above may be understated. Deploy with `-c episodicMemory=false` to measure without it. A run costs about $32 (about $0.31 per URL).

## Accuracy rerun, 2026-10-21

The same 104-URL labelled set, scanned again on the current default (dispatcher, no registry, the page-not-observed rule below) on a test stack in `us-west-2`. All 104 scans completed. 18 URLs had gone dead since 2026-10-16 (10 Error 404, 8 Site down), so the comparison uses the 86 URLs that were live in both runs: 41 phishing and 45 legitimate.

| Same 86 live URLs | 2026-10-16 | 2026-10-21 |
| --- | --- | --- |
| Recall, caught (phishing, or suspicious at risk 50 or more) | 0.976 (40 of 41) | 0.878 (36 of 41) |
| Recall, phishing verdict only | 0.902 (37 of 41) | 0.390 (16 of 41) |
| False positive rate | 0.0 (0 of 45) | 0.022 (1 of 45) |

What changed, in plain terms:

- **Most of the drop in phishing verdicts is the new rule, by design.** When a provider warning (for example Cloudflare's "Suspected Malware" page) stands in front of a site and the browser cannot get past it, nobody has seen the real page, so the verdict is held at Suspicious, risk at most 69, action `warn`, and `page_observed` is `false` (see [Page not observed](agents/orchestrator.md#page-not-observed)). 18 phishing URLs were held this way. 16 of them were `phishing` on 2026-10-16, so the rule moved 16 phishing verdicts to suspicious (`warn`). Counted as phishing, phishing-verdict recall would be 0.780 (32 of 41). None of them fell below the warn line, so a gate that holds `warn` for a person still catches them.
- **The rest is live sites changing, not the release.** Two Vercel projects now answer HTTP 451 "Deployment Unavailable", one host shows a hosting "Account Suspended" page, one page is blank, one site now fails its certificate check, and one capture timed out twice. These pages no longer show phishing, so their scores fell, and four of them fell below the warn line: that is the whole drop in caught recall. The fifth miss was already missed on 2026-10-16.
- **One new false positive:** a static Facebook look-alike on GitHub Pages whose login button sends nothing. Its risk moved from 45 to 50, which crosses the warn line; the verdict is the same as before.

Click-through on Cloudflare warnings: in a browser-only screen (no model) of pages.dev hosts from the public feed on 2026-10-21, 54 hosts behind a Cloudflare warning had a recorded outcome, and 0 of 54 got past it. 52 showed the "Suspected Malware" page, whose proceed button sits behind a Cloudflare Turnstile check, and 2 showed the "Suspected Phishing" page, which has no proceed button. So for these hosts the page-not-observed rule, not the page, decides the verdict. With Web Bot Auth signing on (`-c browserSigning=true`, 2026-10-26, a separate test stack), 30 such URLs gave the same result: 0 of 30 got past the warning (25 Turnstile-gated proceed buttons, 5 without one), and no verdict changed.

Caveats: episodic memory was on, so these rescans saw earlier verdicts for the same URLs, as on 2026-10-16. The scan record keeps only the verdict after the rule, so the 16 is inferred by comparing with the 2026-10-16 verdicts; a later fix will also record the verdict before the rule so the effect can be measured directly. The run cost $18.71 in tokens, a median of $0.205 per model-backed URL.

## Harness path design (default 2026-10-21 to 2026-11-02)

The default from 2026-10-21 until the latency flags became the default on 2026-11-03 ([below](#latency-flags-on-by-default-2026-11-03)). `-c directOrchestration=false` brings back its Harness path and turns `unanimousFastPath` and `directSpecialists` off with it; `localRdap`, `directTools`, `splitToolsRuntimes`, `latencyBudgets` and `codeTextBudget=half` stay on unless you turn them off. It had orchestrator prompt caching added on 2026-10-24 and, on 2026-10-26, the brand-copy rule, code_analyst's capture budget with its raw HTML fallback and the 35 s page-specialist deadline (see [Accuracy rerun, 2026-10-26](#accuracy-rerun-2026-10-26)): one `dispatcher___analyze_all` call runs the three specialists at the same time, no Agent Registry lookup unless `-c agentRegistry=true`, orchestrator effort `medium`, verdict first.

| Measure (test account, `us-west-2`) | Value |
| --- | --- |
| One scan on an idle stack, median to the verdict | 24.5 s and 35.0 s in two runs of 7 scans each (5 model-backed scans per run, 18.2 to 45.6 s; 2 on the pre-check) |
| One scan on an idle stack, median to the full report | Not timed on its own; in the batch below the report came about 11 s after the verdict at the median |
| 50-URL API batch at `scanConcurrency` 25, p50 / p95 to the verdict | 42.5 s / 77.8 s once picked up; 88.8 s / 149.1 s including queue wait (queue wait p50 13.4 s, p95 98.6 s) |
| 50-URL API batch, p50 / p95 to the full report | 53.8 s / 88.7 s once picked up; 100.7 s / 160.9 s including queue wait |
| 50-URL API batch, wall clock and token cost | 162 s to the last verdict, 172 s to the last report; $10.34 for 47 model-backed scans (3 dead URLs ended on the pre-check at $0) |
| Token cost per URL, mean / p90 | $0.153 / $0.194 (median $0.142) with orchestrator prompt caching, 2026-10-25, 43 model-backed scans of the same 50 URLs (see [Prompt caching rerun](#prompt-caching-rerun-2026-10-25)); $0.220 / $0.275 before caching, 2026-10-21; $0.157 / $0.207 (median $0.145) on 291 model-backed scans of a different 317-URL set, 2026-10-26 |
| Recall on live feed phishing, caught (phishing, or suspicious at risk 50 or more) | 0.983 (235 of 239), 1 false positive of 32 legitimate, 2026-10-27, episodic memory off, private labelled set (see [Accuracy rerun, 2026-10-27](#accuracy-rerun-2026-10-27)) |
| Dead or HTTP 404 URL (pre-check, unchanged; 2026-10-18) | 1.0 to 6.7 s, no model call, $0 |

Where a scan has two timings, time to the verdict (`total_ms`, scan `COMPLETE`) is reported separately from time to the full report (`report_ready_at`).

## Prompt caching rerun, 2026-10-25

The same 50 URLs as the 2026-10-21 batch, on a test stack with orchestrator prompt caching on (`orchestratorPromptCache`, the default) and code_analyst caching only its tools and system prompt. Everything else unchanged.

| Measure | 2026-10-21 | 2026-10-25 |
| --- | --- | --- |
| Model-backed scans | 47 | 43 (7 URLs were dead by then) |
| Token cost per URL, mean / median / p90 | $0.220 / $0.216 / $0.275 | $0.153 / $0.142 / $0.194 |
| Per 100 URLs | Opus $14.21, Sonnet $7.79, total $22.00 | Opus $8.54, Sonnet $6.72, total $15.26 |
| Orchestrator prompt tokens read from cache | 0% | 62% |
| Time to verdict, median | 42.5 s | 48.5 s |
| Recall (phishing, or suspicious at risk 50 or more) | 0.929 (26 of 28) | 0.92 (23 of 25) |
| False positives | 0 of 18 | 0 of 18 |

Strict recall (a `phishing` verdict only) fell from 11 of 28 to 4 of 25 because the pages changed, not the model: of the 7 URLs judged `phishing` on 2026-10-21 and not on 2026-10-25, 5 now sit behind a Cloudflare "Suspected Phishing" warning or a Vercel takedown (HTTP 451), which the page-not-observed rule holds at `suspicious`, and 1 answers HTTP 404. The median time to verdict is 6 s slower on this run; the test machine was under heavy load, and prompt caching does not add work, so read it as noise until a second run says otherwise.

## Accuracy rerun, 2026-10-26

Measured on a test stack in `us-west-2` with the changes described below: the brand-copy rule and code_analyst's 20 s capture budget with its raw HTML fallback (code_analyst's 35 s deadline, from 2026-10-25, was in both runs). brand_visual still had its 30 s deadline in this run; it got 35 s afterwards (see below), re-measured on 2026-10-27.

The set has 317 URLs: 299 from a public phishing feed and 18 real sign-in or home pages of large brands (Google, Microsoft, Apple, PayPal, Chase, Coinbase and others, plus the brand-owned shortener `aka[.]ms`). The feed's labels are not ground truth: 14 of its URLs are preview builds of the MetaMask documentation on the Consensys team's Vercel account (their canonical links and analytics go to MetaMask's own domains), so after review they were relabelled legitimate. That leaves 285 phishing and 32 legitimate. All 317 scans completed; 27 phishing URLs were dead by scan time (18 Error 404, 9 Site down) and are left out. Caught means the verdict is phishing, or suspicious with risk 50 or more; the set and the scoring script are not published, as in the note above.

Two baselines, both on the earlier code: the same day, 196 of the feed URLs (14 of them the MetaMask previews) on a test stack running the code before these changes, and a 103-URL feed batch scanned earlier on another deployment of that code. Every URL of both is in the 317.

| Run | Recall, caught | Recall, phishing verdict only | False positives |
| --- | --- | --- | --- |
| Before, earlier code, 196 feed URLs (177 live), MetaMask previews counted as legitimate | 0.945 (154 of 163) | 0.417 (68 of 163) | 0 of 14 |
| After, with these changes, 317 URLs (290 live) | 0.961 (248 of 258) | 0.372 (96 of 258) | 1 of 32 (0.031) |
| Same 163 feed URLs live in both runs, before then after | 154 then 155 of 163 | 68 then 69 | |
| Same 95 feed URLs live in both, 103-URL earlier batch then after | 88 then 93 of 95 | 25 then 27 | |

Scored against the feed's own labels, the before run is 0.870 (154 of 177): 14 of its 16 legitimate verdicts were the MetaMask previews. Over both comparisons 7 URLs moved into caught and 1 moved out. The 7 are brand copies the old code scored below 50 or called legitimate: five copies of Netflix pages and one of a Facebook page on GitHub Pages and Vercel (for example `hxxps://raza014[.]github[.]io/netflix-clone/`, legitimate 20 then suspicious 55), and `hxxp://dashboard[.]adobeexperience[.]com[.]br/` (45 then 55). The one out is `hxxps://d18390wdgenrs6[.]cloudfront[.]net/` (65 then 45): its script redirect now ends at an Error 404, so the page changed.

| Measure | Before | After |
| --- | --- | --- |
| code_analyst error Findings | 12 of 103 scans in the 103-URL earlier batch | 0 of 317 |
| brand_visual model ran out of time (30 s deadline) | 1 of 196 | 5 of 317 |
| `static_html_only` (code_analyst read the raw HTML) | not in this code | 7 Findings: 4 phishing URLs, all still caught (one phishing 91, three suspicious 62 to 69), and 3 brand pages, still legitimate |
| Token cost, mean / median / p90 per model-backed URL | $0.158 / $0.143 / $0.206 (178 scans, $28.14 in total) | $0.157 / $0.145 / $0.207 (291 scans, $45.77 in total for 317 URLs) |

The 10 phishing URLs still missed:

- **Four certificate errors on a `www.` name the certificate does not cover**, so no page was seen and the verdict rests on the URL: `hxxps://www[.]community-policy-info[.]vercel[.]app/` (suspicious 45), `hxxps://www[.]exoduslarp[.]vercel[.]app/` (40), `hxxps://www[.]netflix-ui-clone-vikas[.]vercel[.]app/` (40; the same project without `www.` was caught at 55) and `hxxps://www[.]lyloauckland[.]hostel[.]town/` (unknown 25).
- **Three where no capture loaded**: `hxxps://www[.]dhl[.]smarthub[.]vuelogix[.]ai/` (40, certificate mismatch and an aborted navigation), `hxxps://g5[.]lu/avzxd` (40, a short link whose navigation timed out) and `hxxp://likpaklix[.]com/` (45, a 3-day-old domain the browser refused).
- **Three pages that show no phishing now**: `hxxps://vf4933[.]craftum[.]io/` (legitimate 15, the site builder's "subscription expired" page), `hxxp://blockbook[.]b1tcore[.]org/` (legitimate 25, a stock open-source Blockbook explorer with no sign-in or seed prompt, which may be a feed false positive) and the CloudFront host above.

The false positive is a MetaMask documentation preview, `hxxps://metamask-docs-fbv47wj26-consensys-ddffed67[.]vercel[.]app/developer-tools/faucet/`, held at suspicious 50 (action `warn`): its "Connect MetaMask" wallet button is a wallet action on a `vercel[.]app` host MetaMask does not own, which the brand-copy rule holds for review by design. The other 13 previews, documentation pages with no such action, were legitimate at risk 15 to 18.

What changed and why:

- **The brand-copy rule.** This is a pre-publish gate, and phishing kits are often wired up after the page is published. So a captured copy of a known brand's sign-in or landing page with a sign-in, sign-up, account, payment or wallet action, on a domain the brand does not own, is at least suspicious with risk 50 or more even when nothing sends data yet; a "clone" or "demo" label does not lower it. It is phishing when the copy sits on a look-alike domain built from the brand, or claims to be the official site, and offers a sign-in, account or wallet action. Brand documentation or other content with no such action is judged on the evidence. See [orchestrator.md](agents/orchestrator.md#what-it-does) and [brand_visual.md](agents/brand_visual.md#what-it-looks-for).
- **code_analyst capture budget and raw HTML fallback.** On the old code a page that never loaded could use up the whole deadline: 12 of the 103 earlier-batch scans ended with a code_analyst error and no code seen. The capture now has a hard 20 s budget, and when the browser cannot load the page the tool reads the raw HTML through the guarded probe instead (signal `static_html_only`, `page_observed` `false`). No code_analyst error in 317 scans. See [code_analyst.md](agents/code_analyst.md#raw-html-fallback).
- **Deadlines.** brand_visual's model ran out of time on 5 of 317 scans at 30 s, so both page specialists, brand_visual and code_analyst, now have 35 s (`PAGE_DEADLINE_S`); url_analyst keeps 30 s (1 time-out in 317). Re-measured on 2026-10-27: 0 of 317 (see below). See [dispatcher.md](agents/dispatcher.md#timeouts).

Caveats: episodic memory was on, so most scans saw up to three similar past scans, as in the earlier runs. The before and after sets differ in size and mix, so compare the same-URL rows, not the headline recall. Strict recall stays low by design: of the 159 live phishing URLs judged suspicious, 117 were "Page not observed": 97 behind a Cloudflare warning, which the [page-not-observed rule](agents/orchestrator.md#page-not-observed) holds at suspicious, and 20 capture gaps judged from the URL.

## Accuracy rerun, 2026-10-27

The same 317 URLs and labels as 2026-10-26, on a test stack in `us-west-2` deployed with `-c episodicMemory=false`, so no earlier verdict reached the orchestrator as context (every run before this one had episodic memory on). Two runs a day after the previous one: the code from 2026-10-26 with brand_visual's 35 s page deadline, then the same code plus the `www.` sibling capture (see [code_analyst](agents/code_analyst.md) and [brand_visual](agents/brand_visual.md)). Live pages keep changing: 44 URLs were dead in the first run and 46 in the second, so the live counts differ slightly. Caught means the verdict is phishing, or suspicious with risk 50 or more; the set and the scoring script are not published, as in the note above.

| Run, 317 URLs | Recall, caught | Recall, phishing verdict only | False positives | Token cost |
| --- | --- | --- | --- | --- |
| Base code, episodic memory off | 0.979 (236 of 241) | 0.320 (77 of 241) | 1 of 32 (0.031) | $41.60 |
| + `www.` sibling capture | 0.983 (235 of 239) | 0.397 (95 of 239) | 1 of 32 (0.031) | $43.23 |

- **brand_visual's 35 s page deadline:** its model ran out of time in 0 of 317 scans in both runs, against 5 of 317 with the 30 s deadline on 2026-10-26.
- **`www.` sibling capture:** when the certificate does not cover the submitted `www.` name, both page specialists now capture the same path on the host without `www.`, inside the same capture budget and through the same guard. The page is still not observed (visitors to the `www.` link get a certificate warning), so the verdict is held at suspicious, risk at most 69. `hxxps://www[.]netflix-ui-clone-vikas[.]vercel[.]app/` moved from suspicious 45 (missed) to 60 (caught). On the first live try every sibling failed: the failed `www.` navigation commits Chromium's error page a moment later and interrupts the next navigation, so the capture now retries the sibling once on exactly that error.
- **The false positive** is the same MetaMask documentation preview with a "Connect MetaMask" wallet button, held at suspicious 50 for review by design (see 2026-10-26).

The 4 phishing URLs missed in the second run:

- `hxxps://vf4933[.]craftum[.]io/` (legitimate 15): the site builder's "temporarily unavailable" page; no phishing is shown any more.
- `hxxp://blockbook[.]b1tcore[.]org/` (legitimate 25): a stock open-source Blockbook explorer with no sign-in or seed prompt, which may be a feed false positive.
- `hxxps://www[.]lyloauckland[.]hostel[.]town/` (suspicious 35): the sibling without `www.` was captured and does not look like phishing now.
- `hxxps://www[.]exoduslarp[.]vercel[.]app/` (suspicious 45): neither the `www.` page nor its sibling was captured.

## Capture, compact view and latency flags, 2026-11-02

`-c codeModelView=compact`, `-c captureRecovery=true`, `-c directOrchestration=true` and `-c localRdap=true` (see [configuration.md](configuration.md)) were measured together on one test stack in a test account (`us-west-2`), first with all four on and then, about 35 minutes later, after redeploying the same stack with all four off. Both runs scanned the same 448 URLs: 224 from a public phishing feed pulled that day and 224 legitimate sign-in, brand, SaaS, government and free-hosting pages. Episodic memory was off and `scanConcurrency` was 10 in both runs. 39 URLs were dead (Error 404, Site down) in both runs, so 409 are scored: 190 phishing, 219 legitimate. Caught means the verdict is phishing, or suspicious with risk 50 or more; the set and the scoring script are not published, as in the note above.

| Measure (409 URLs live in both runs) | Flags on | Flags off |
| --- | --- | --- |
| Recall, caught | 0.911 (173 of 190) | 0.889 (169 of 190) |
| Recall, phishing verdict only | 0.321 (61 of 190) | 0.295 (56 of 190) |
| False positive rate | 0.050 (11 of 219) | 0.046 (10 of 219) |
| Page observed (the specialists saw the real page) | 0.738 | 0.699 |
| Scan time, median (worker start to verdict) | 19.0 s | 26.8 s |
| Scan time, p90 | 27.7 s | 37.8 s |
| Model cost per scan, mean (`cost_usd`, model tokens only) | $0.092 | $0.160 |

- **Cost fell 43% and scan time 29% at the median** with no measurable change in accuracy: 16 of 409 outcomes changed between the runs, in both directions, and the recall and false-positive differences (4 and 1 URLs) are within run-to-run variation on live sites.
- The four flags were measured as one bundle, so the split of the gain between them is not known from this run. A later leave-one-out run ([2026-11-03](#each-latency-flag-on-its-own-2026-11-03)) found `directOrchestration` the only latency flag with a clear effect on its own; `codeModelView` and `captureRecovery` were not part of that run.
- Queueing is not in the scan times: every URL was submitted at once, so scans waited in the queue for minutes in both runs.
- After this measurement `codeModelView=compact` and `captureRecovery=true` became the default; that pair was not measured on its own. `directOrchestration` and `localRdap` stayed off until the [2026-11-03 run](#latency-flags-on-by-default-2026-11-03). With `directOrchestration` the optional second round and the Harness trace are gone, and a URL the pre-check finds dead still pays for the specialists.

## Latency flags on by default, 2026-11-03

The remaining latency flags (`directOrchestration`, `localRdap`, `unanimousFastPath`, `directSpecialists`, `directTools`, `splitToolsRuntimes`, `latencyBudgets`, `codeTextBudget=half`) were measured together on one test stack in a test account (`us-west-2`): arm A with all eight on, then, about 27 minutes later, arm B on the 2026-11-02 default (`codeModelView=compact` and `captureRecovery=true`, the eight off). Both arms scanned the same 448 URLs with episodic memory off and `scanConcurrency` 25; 407 were live in both (188 phishing, 219 legitimate). Caught is scored as above.

| Measure (407 URLs live in both arms) | All eight on | 2026-11-02 default |
| --- | --- | --- |
| Recall, caught | 0.883 (166 of 188) | 0.867 (163 of 188) |
| Recall, phishing verdict only | 0.309 | 0.287 |
| False positive rate | 0.046 (10 of 219) | 0.050 (11 of 219) |
| Page observed | 0.713 | 0.717 |
| Scan time, median and p90 (worker start to verdict) | 18.6 s and 31.2 s | 37.8 s and 71.9 s |
| Submit to `COMPLETE`, median and p90 (includes queueing) | 325 s and 520 s | 583 s and 927 s |
| Model cost per scan, mean | $0.090 | $0.134 |

- **Scan time roughly halved and cost fell about 33%**; accuracy held, and the 3 to 4 URL differences are within run-to-run variation on live sites.
- All 448 URLs were submitted at once, so most of the submit-to-`COMPLETE` time is queue wait at 25 scans in flight.
- 129 arm A scans had the fast-path shape (three specialists legitimate at 80 or more, stored at risk 5); none was labelled phishing.
- The eight flags were measured as one bundle here; each one on its own is in [the next section](#each-latency-flag-on-its-own-2026-11-03). They became the default after this run; `-c directOrchestration=false` restores the Harness path with its second round and trace.

## Each latency flag on its own, 2026-11-03

To see which of the eight latency flags matters, each one was turned off on its own (leave one out) on one test stack in a test account (`us-west-2`), with episodic memory off and `scanConcurrency` 25. Every arm scanned the same 110 URLs (60 phishing from a public feed, 50 legitimate), one arm after another over about five and a half hours; 8 phishing URLs were dead in every arm but one and are left out (7 were dead in the `directSpecialists` off arm, so it scores 53 phishing URLs). The all-on default ran first and last to measure run-to-run noise. Caught is scored as above.

| Arm | Caught | False positives | Scan time, median / p90 | Model cost per scan, mean |
| --- | --- | --- | --- | --- |
| All eight on (the default) | 47 of 52 | 2 of 50 | 20.1 s / 32.4 s | $0.092 |
| All eight on, repeated last | 47 of 52 | 2 of 50 | 23.4 s / 34.7 s | $0.089 |
| All eight off | 47 of 52 | 2 of 50 | 41.5 s / 82.7 s | $0.132 |
| `directOrchestration` off (also turns off `unanimousFastPath` and `directSpecialists`) | 46 of 52 | 2 of 50 | 31.0 s / 64.1 s | $0.135 |
| `unanimousFastPath` off | 46 of 52 | 2 of 50 | 17.7 s / 29.3 s | $0.091 |
| `directSpecialists` off | 46 of 53 | 2 of 50 | 17.1 s / 26.8 s | $0.088 |
| `localRdap` off | 46 of 52 | 2 of 50 | 16.6 s / 26.5 s | $0.091 |
| `directTools` off (also turns off `splitToolsRuntimes`) | 47 of 52 | 2 of 50 | 23.9 s / 35.3 s | $0.091 |
| `splitToolsRuntimes` off | 47 of 52 | 2 of 50 | 22.5 s / 33.3 s | $0.091 |
| `latencyBudgets` off | 47 of 52 | 2 of 50 | 22.9 s / 32.7 s | $0.091 |
| `codeTextBudget=full` | 47 of 52 | 2 of 50 | 22.8 s / 34.1 s | $0.090 |

- **Noise band.** The two all-on runs differ by about 3 s at the median, so smaller differences are inside the noise, and one URL of recall is too.
- **`directOrchestration` is the only flag with a clear effect.** Turning it off added about 8 to 11 s at the median and about 30 s at p90, and cost about 47% more per scan. Most of the gap between all on and all off is this flag. It is also the only flag that moved cost.
- **The other flags were not measurably faster or cheaper on their own.** `directTools` showed a small signal (about 4 s slower median on phishing scans with it off) that one run cannot confirm. `unanimousFastPath`, `localRdap`, `directSpecialists`, `splitToolsRuntimes`, `latencyBudgets` and `codeTextBudget` are inside the noise; three arms that ran in the same hour were faster than all on, which points to time of day, not to the flags.
- **No flag measurably hurt accuracy**: 46 or 47 caught phishing URLs (of 52, or of 53 in the `directSpecialists` off arm) and the same 2 of 50 false positives in every arm.
- **Reliability.** With `directSpecialists` off, 2 of 110 scans had all three specialist findings fail (verdict unknown); no other arm had this. With `directTools` off, 1 scan was unknown because the target site rate-limited the capture.

## Latency history

Each design below was measured on a test stack in `us-west-2` with Claude Opus 5.5 as orchestrator and Claude Sonnet 5.5 specialists, at the default `scanConcurrency` of 25 unless noted.

| Design | Round one | Measured |
| --- | --- | --- |
| Lambda fan-out (removed) | A Lambda ran the three specialists in parallel | 2026-09-30 |
| `registry` design | The orchestrator called three specialist tools, one after another | 2026-10-05 |
| Earlier dispatcher | A dispatcher ran the three in parallel, effort `low` | 2026-10-05 |
| Revised dispatcher | Same, after later prompt and pipeline changes | 2026-10-11 |
| No dispatcher (default 2026-10-16 to 2026-10-21) | Registry lookup, then three specialist tools one after another, effort `medium` | 2026-10-16, 2026-10-18 |
| Harness path: dispatcher, no registry (default 2026-10-21 to 2026-11-02) | One dispatcher call, three in parallel, effort `medium` | 2026-10-21 |
| **Current: direct orchestration (latency flags on, default since 2026-11-03)** | The worker invokes the three specialists in parallel, then one Converse call for the verdict | [2026-11-03](#latency-flags-on-by-default-2026-11-03) |

<details>
<summary>Why the dispatcher came back (2026-10-16 spike)</summary>

A spike on 2026-10-16 (test stack, 5 live URLs per row, turn 1 only) measured the median time to the verdict for each shape. In 16 of 16 scans that called the three specialist tools, the model asked for all three in one message and the Harness ran them strictly one after another.

| Shape (2026-10-16) | Specialists overlapped | Median to the verdict | Range |
| --- | --- | --- | --- |
| Orchestrator calls the three specialist tools (no registry, no tools server) | 0 of 5 | 40.1 s | 32.6 to 47.8 s |
| The same with a "parallel tool use" prompt | 0 of 5 | 40.7 s | 32.1 to 65.1 s |
| Earlier dispatcher design, with registry, effort `low` | 4 of 4 through the dispatcher | 27.4 s | 20.1 to 40.2 s |
| No dispatcher: orchestrator calls the specialists after the registry lookup, effort `medium` (default from 2026-10-16 to 2026-10-21) | 5 of 5 after the registry lookup | 43.0 s | 38.3 to 55.5 s |


</details>

<details>
<summary>Dispatcher, no registry, 50-URL batch (2026-10-21)</summary>

The same shape as the 2026-10-18 batch: 50 URLs submitted at once through the API, 32 live phishing URLs from a public feed (12 on pages.dev, 11 hosts also in the 2026-10-18 batch) and 18 real brand sign-in pages. Test stack in `us-west-2`, `scanConcurrency` 25, on-demand prices from `pricing.json`.

| Measure | 2026-10-18, no dispatcher | 2026-10-21, dispatcher |
| --- | --- | --- |
| Model-backed scans | 50 | 47 (3 dead URLs ended on the pre-check) |
| Token cost per URL, median / p90 | $0.307 / $0.376 | $0.216 / $0.275 |
| Token cost per URL, mean / min / max | $0.312 / $0.232 / $0.391 | $0.220 / $0.134 / $0.325 |
| Batch token cost | $15.62 | $10.34 |
| Processing to the verdict, p50 / p95 | 68.8 s / 114.5 s | 42.5 s / 77.8 s |
| Processing to the full report, p50 / p95 | 82.0 s / 126.4 s | 53.8 s / 88.7 s |
| To the verdict including queue wait, p50 / p95 | 150.1 s / 231.9 s | 88.8 s / 149.1 s |
| To the full report including queue wait, p50 / p95 | 161.4 s / 243.2 s | 100.7 s / 160.9 s |
| Queue wait, p50 / p95 | 76.2 s / 158.6 s | 13.4 s / 98.6 s |
| Wall clock, to the last verdict / report | 241 s / 254 s | 162 s / 172 s |
| Retries | 1 of 50 | 0 of 50 |
| COMPLETE / reports READY | 50 / 50 | 50 / 50 |

Mean token cost per model-backed URL, by call:

| Call | Model | 2026-10-18 | 2026-10-21 |
| --- | --- | --- | --- |
| Orchestrator, verdict turn | Opus 5.5 | $0.154 | $0.079 (16,048 input tokens, was 31,099) |
| Orchestrator, report turn | Opus 5.5 | $0.082 | $0.063 (9,734 input tokens, was 13,921) |
| `code_analyst` | Sonnet 5.5 | $0.059 | $0.060 |
| `brand_visual` | Sonnet 5.5 | $0.011 | $0.010 |
| `url_analyst` | Sonnet 5.5 | $0.006 | $0.007 |
| Per 100 URLs | | Opus $23.59, Sonnet $7.65, total $31.24 | Opus $14.21, Sonnet $7.79, total $22.00 |

The saving is fewer orchestrator input tokens: one dispatcher result replaces three tool rounds and the registry lookup. It is not the lower cache-read price: the orchestrator was not prompt-cached in this run (orchestrator caching came later, see `orchestratorPromptCache` in [deploy.md](deploy.md)). Recorded `cost_usd` matched a recomputation from the stored token counts on 47 of 47 scans. On the feed labels, 26 of 28 live phishing URLs were caught (0.929) and 0 of 18 brand sign-in pages were flagged; 11 of the 50 scans were held by the page-not-observed rule, which is why only 11 of 28 got a `phishing` verdict (see [Accuracy rerun, 2026-10-21](#accuracy-rerun-2026-10-21)).

</details>

<details>
<summary>No dispatcher, 50-URL batch (2026-10-18)</summary>

50-URL API batch, all submitted at once, 32 live phishing URLs from a public feed and 18 real brand sign-in pages:

| Measure | Value |
| --- | --- |
| Processing to the verdict, p50 / p95 | 68.8 s / 114.5 s |
| Processing to the full report, p50 / p95 | 82.0 s / 126.4 s |
| To the verdict including queue wait, p50 / p95 | 150.1 s / 231.9 s |
| To the full report including queue wait, p50 / p95 | 161.4 s / 243.2 s |
| Wall clock | 241 s to the last verdict, 254 s to the last report |
| Result | 50 COMPLETE (1 retried once), 50 reports READY, 0 FAILED |
| Token cost | $15.62 (median $0.307, p90 $0.376, mean $0.312 per URL) |

Three dead URLs (two HTTP 404, one host that does not resolve) ended on the pre-check in 1.0 to 6.7 s with no model call and $0. The registry lookup added 0.5 to 0.8 s per scan. The orchestrator's two turns were about 75% of the token cost (on average $0.154 for the verdict turn and $0.082 for the report turn).

</details>

<details>
<summary>Earlier dispatcher against the registry design (2026-10-05, 200 URLs)</summary>

Dispatcher, pre-check, verdict first, effort `low`, result cache; 200 URLs through the web app, the same URLs as the registry design's 200-URL run:

| Measure | Previous registry design | Earlier dispatcher design |
| --- | --- | --- |
| Time to the verdict, p50 / p95 | 65.3 s / 134.8 s (verdict and report arrived together) | 33.7 s / 98.2 s |
| Time to the full report, p50 / p95 | 65.3 s / 134.8 s | 48.3 s / 113.4 s |
| Model path only (165 scans): verdict, report | not split | 37.9 s / 98.3 s, 52.1 s / 118.1 s |
| Pages that answered HTTP 404 (35 scans) | 32 scans, full model path | 3.8 s / 12.6 s, no model call, report ready at once |
| Batch wall clock | 764.8 s | 549 s |
| Cost | $41.33 | $35.02 |
| Reports READY / FAILED / `unknown` verdicts | not applicable | 200 / 0 / 0 |

Quality against the previous design on the same URLs: 193 of 200 verdicts identical (96.5%), mean absolute risk change 2.1 points. Seven changed: three suspicious became Error 404 (the sites went offline), three phishing became suspicious (risk 72, 75 and 75 became 68, 65 and 65), one suspicious became phishing (74 became 78).


The revised dispatcher design measured a median of 41 s of processing to the verdict (57 s including queue wait, p95 113 s) on 54 URLs on 2026-10-11 (40 live phishing URLs, 10 dead ones and 4 legitimate sign-in pages).

</details>

<details>
<summary>Lambda fan-out and registry designs (2026-09-30 and 2026-10-05)</summary>

In the registry design the Harness ran same-turn Gateway calls one after another (seen 2026-09-29 and 2026-10-11), and verdict and report arrived together.

| Measure | Lambda fan-out, removed (2026-09-30) | `registry` mode, previous design (2026-10-05) |
| ------- | ------------- | ------------------------- |
| Single scan | p50 about 27 to 31 s | about 50 to 60 s (49 to 59 s for a legitimate site on the final code; one 404 scan took 119 s on an earlier run, 54 s on the next) |
| 50-URL API batch p50 | 44.0 s (about 46 s in another batch) | 91.7 s (cold run right after a deploy) |
| 50-URL API batch p95 | 110.0 s | 163.5 s |
| 50-URL batch wall clock and cost | not recorded | 333 s, $9.87, 50 of 50 complete |
| 200-URL web app batch p50 / p95 | not recorded | 65.3 s / 134.8 s |
| 200-URL web app batch wall clock and cost | 10 min 44 s, $30.02 | 764.8 s (12 min 45 s), $41.33, 200 of 200 complete |
| 1,000-URL API batch p50 / p95 | 27.3 s / 80.6 s | 55.2 s / 106.7 s (mean 60.5 s) |
| 1,000-URL API batch wall clock and cost | 30 min 41 s, $144.58 | 2,797.9 s (46.6 min, about 21 scans per minute at `scanConcurrency` 25), $229.17 (about $0.23 per URL), 1,000 of 1,000 complete |

The cold 50-URL run was slower than the 1,000-URL run (91.7 s against 55.2 s at p50), so expect a first batch right after a deploy to be slower than steady state.

Verdicts and per-call latency from the registry design runs:

| Run | phishing | suspicious | legitimate | `error_404` | `unknown` |
| --- | --- | --- | --- | --- | --- |
| 1,000 URLs, API | 411 | 383 | 30 | 172 (17.2%) | 4 (0.4%) |
| 200 URLs, web app | 86 | 76 | 6 | 32 (16.0%) | 0 |
| 50 URLs, API (cold) | 20 | 16 | 2 | 11 | 1 |

The sample is real phishing URLs, so many were already dead; that is why `error_404` is 17.2% of the 1,000-URL sample. These are verdict counts, not accuracy: no labels were applied to this feed.

| Call (1,000-URL API run) | p50 | p95 |
| ------------------------ | --- | --- |
| Orchestrator harness | 54.7 s | 106.2 s |
| `url_analyst` specialist | 5.4 s | 8.0 s |
| `brand_visual` specialist | 9.5 s | 19.8 s |
| `code_analyst` specialist | 10.8 s | 22.4 s |
| Browser `capture_page` | 4.5 s | 12.8 s |
| Browser `capture_page_code` | 5.0 s | 18.1 s |
| `whois` lookup | 1.1 s | 2.1 s |
| Web search | 0.9 s | 1.0 s |

With the fuller orchestrator report (a 150 to 250 word reasoning section), episodic memory and web search all on, the Lambda fan-out design measured (2026-09-30, API batches) 5 URLs p50 38.4 s / p95 58.2 s and 50 URLs p50 44.0 s / p95 110.0 s; an earlier 250 to 450 word reasoning budget measured p50 52.4 s on the same 50 URLs. In that design the orchestrator was about 70% of each scan, which is why the verdict now comes in turn 1 and the report in turn 2. In our runs on 2026-09-29 the orchestrator overhead (Harness time minus the slowest specialist) had a p95 of 29 s with 5 or fewer scans in flight and 82 s with 16 to 30, which is the trade-off `scanConcurrency` controls.

</details>

## Cost history

Token cost only, as recorded on each scan (`cost_usd`).

| Design | Run | Token cost | Per URL |
| --- | --- | --- | --- |
| Lambda fan-out (removed) | 1,000-URL API batch, 2026-09-30 | $144.58 | about $0.145 |
| Lambda fan-out (removed) | 200-URL web app batch, 2026-09-30 | $30.02 | about $0.15 |
| `registry` design | 1,000-URL API batch, 2026-10-05 | $229.17 | about $0.23 |
| `registry` design | 200-URL web app batch, 2026-10-05 | $41.33 | about $0.21 |
| `registry` design | 50-URL cold run, 2026-10-05 | $9.87 | about $0.197 |
| Earlier dispatcher | 200-URL web app batch, 2026-10-05 | $35.02 | about $0.175 |
| No dispatcher | 50-URL API batch, 2026-10-18 | $15.62 | $0.312 |
| Dispatcher, no registry | 50-URL API batch, 2026-10-21 | $10.34 | $0.220 |
| Dispatcher, orchestrator prompt caching | 50-URL API batch, 2026-10-25 (same URLs) | $6.56 | $0.153 |
| Harness path: dispatcher, orchestrator prompt caching, 2026-10-26 rules (default 2026-10-21 to 2026-11-02) | 317-URL accuracy set, 2026-10-26 | $45.77 | $0.157 (291 model-backed scans) |
| Four flags on, including direct orchestration (A/B arm) | 448-URL A/B, 2026-11-02 ([details](#capture-compact-view-and-latency-flags-2026-11-02)) | Not totalled here | $0.092 mean (409 live URLs) |
| Current: latency flags on (default since 2026-11-03) | 448-URL A/B, 2026-11-03 ([details](#latency-flags-on-by-default-2026-11-03)) | Not totalled here | $0.090 mean (407 live URLs) |

> [!NOTE]
> Runs before 2026-10-16 counted specialist prompt-cache reads and writes as zero (fixed on 2026-10-16), so they leave out most specialist input tokens: on a test stack the same 200-URL batch recorded about $0.25 per URL once they were counted. Runs before 2026-10-21 priced cache reads at 0.1 times the input price; the current `pricing.json` uses the published 0.05 times.

## First design baseline (2026-08-27)

These numbers are from the first design of this sample (a different agent design), measured on 2026-08-27 on the committed sample. They are a reference point, not a result of the current design.

| Metric        | First design value                            |
| ------------- | --------------------------------------------- |
| URLs          | 21 (5 phishing, 16 legitimate), all completed |
| Precision     | 1.00                                          |
| Recall        | 1.00                                          |
| F1            | 1.00                                          |
| Time per scan | 96 to 250 seconds, mean 128                   |

## Limitations

- **The sample is small.** Five phishing URLs cannot support an accuracy claim. A perfect score here only shows the wiring works and the obvious cases are caught.
- **Live pages change.** A page can be taken down, cloaked or changed between runs.
- **Model output varies.** The same URL can get a different score on another run, most often near the line between suspicious and phishing.
- For a claim you can defend, run a larger, private, recent feed and report how many URLs could not be reached.
