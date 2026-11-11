# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Run a labelled URL set through two hosted URL scanners and compare them with this sample.

Output names the scanners only as "Vendor 1" and "Vendor 2". Keys come from VT_API_KEY and
URLSCAN_API_KEY; a scanner whose key is not set is skipped. Raw vendor responses are cached
per URL, so a rerun skips URLs already done (Vendor 1's free quota spans several days).

Usage:
  VT_API_KEY=... URLSCAN_API_KEY=... uv run --package phish-agents \
    python eval/benchmark_vendors.py --ours eval/results/<utc-time>.json --limit 5
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import io
import json
import logging
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request
from urllib.response import addinfourl

import urllib3

logger = logging.getLogger("benchmark_vendors")

HERE = Path(__file__).resolve().parent

# Metrics and dataset parsing are shared with the agent evaluation, not reimplemented.
_spec = importlib.util.spec_from_file_location("evaluate_agents", HERE / "evaluate_agents.py")
_ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ev)
load_dataset, score = _ev.load_dataset, _ev.score

VT_BASE = "https://www.virustotal.com/api/v3"
URLSCAN_BASE = "https://urlscan.io/api/v1"
# Never "public": a public urlscan scan publishes the URL and its screenshot to everyone.
# Deliberately not a CLI flag.
URLSCAN_VISIBILITY = "unlisted"
# The only hosts this script talks to. The scanned URL is sent as data, never fetched here.
ALLOWED_HOSTS = frozenset({"www.virustotal.com", "urlscan.io"})
HTTP_TIMEOUT_S = 30
_HTTP = urllib3.PoolManager()  # urllib3 2.x: CERT_REQUIRED and system CA bundle
RETRIES_ON_429 = 3
BACKOFF_S = 15.0
MAX_BACKOFF_S = 300.0


class ScanError(Exception):
    """A scan that produced no verdict. Terminal errors are cached; others are retried."""

    def __init__(self, message: str, *, terminal: bool):
        super().__init__(message)
        self.terminal = terminal


class QuotaExhausted(ScanError):
    """Still rate limited after every retry: stop this scanner for the run."""

    def __init__(self, message: str):
        super().__init__(message, terminal=False)


def _error_message(body: dict) -> str:
    err = body.get("error")
    if isinstance(err, dict):
        return str(err.get("message") or err.get("code") or "")
    return str(body.get("message") or body.get("description") or err or "")


def urlopen(request: Request, timeout: float) -> addinfourl:
    """HTTPS-only stand-in for urllib's urlopen: no file:// or other schemes, fixed hosts.

    Raises HTTPError for non-2xx answers, like urllib, so callers handle both the same way.
    """
    parts = urlsplit(request.full_url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"refusing to call {parts.scheme}://{parts.hostname}")
    try:
        # urllib3 verifies certificates by default; no redirects or retries (handled above).
        response = _HTTP.request(
            request.get_method(),
            request.full_url,
            body=request.data,
            headers=dict(request.header_items()),
            timeout=timeout,
            retries=False,
            redirect=False,
        )
    except urllib3.exceptions.HTTPError as exc:
        raise URLError(exc) from exc
    body = response.data
    if not 200 <= response.status < 300:
        raise HTTPError(
            request.full_url, response.status, response.reason, response.headers, io.BytesIO(body)
        )
    return addinfourl(io.BytesIO(body), response.headers, request.full_url, response.status)


def _retry_after(exc: HTTPError) -> float | None:
    for header in ("Retry-After", "X-Rate-Limit-Reset-After"):
        value = exc.headers.get(header) if exc.headers else None
        if value is None:
            continue
        try:
            return min(float(value), MAX_BACKOFF_S)
        except ValueError:
            # ponytail: an HTTP-date Retry-After falls back to exponential backoff.
            return None
    return None


class _Client:
    """Throttled JSON over HTTPS with backoff on 429. The key goes only into a header."""

    name = ""
    label = ""
    env_var = ""
    min_interval_s = 0.0

    def __init__(
        self,
        api_key: str,
        *,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._key = api_key
        self.sleep = sleep
        self.clock = clock
        self._last_call: float | None = None

    def _auth_headers(self) -> dict[str, str]:
        raise NotImplementedError

    def _throttle(self) -> None:
        if self._last_call is not None:
            wait = self.min_interval_s - (self.clock() - self._last_call)
            if wait > 0:
                self.sleep(wait)
        self._last_call = self.clock()

    def _call(
        self, method: str, url: str, *, data: bytes | None = None, headers: dict | None = None
    ) -> tuple[int, dict]:
        """Return (status, JSON body). HTTP errors come back as a status, not an exception."""
        all_headers = {"Accept": "application/json", **(headers or {}), **self._auth_headers()}
        for attempt in range(RETRIES_ON_429 + 1):
            self._throttle()
            # urlopen above is HTTPS-only and limited to ALLOWED_HOSTS.
            request = Request(url, data=data, headers=all_headers, method=method)  # noqa: S310
            try:
                with urlopen(request, timeout=HTTP_TIMEOUT_S) as response:
                    return response.status, json.loads(response.read() or b"{}")
            except HTTPError as exc:
                if exc.code == 429 and attempt < RETRIES_ON_429:
                    delay = _retry_after(exc) or BACKOFF_S * 2**attempt
                    logger.info("%s rate limited, retrying in %.0f s", self.label, delay)
                    self.sleep(delay)
                    continue
                raw = exc.read()
                try:
                    body = json.loads(raw) if raw else {}
                except ValueError:
                    body = {}
                return exc.code, body if isinstance(body, dict) else {}
        raise AssertionError("unreachable")  # pragma: no cover

    def _check(self, status: int, body: dict) -> None:
        if status == 200:
            return
        detail = f"HTTP {status} {_error_message(body)}".strip()
        if status == 429:
            raise QuotaExhausted(detail)
        raise ScanError(detail, terminal=400 <= status < 500)

    def scan(self, url: str) -> dict:
        raise NotImplementedError

    def predict(self, raw: dict) -> tuple[str | None, str]:
        raise NotImplementedError


class VirusTotalClient(_Client):
    name = "virustotal"
    label = "Vendor 1"
    env_var = "VT_API_KEY"
    # Public API: 4 requests a minute, 500 a day.
    min_interval_s = 15.0
    max_polls = 20

    def __init__(
        self, api_key: str, *, min_detections: int = 1, count_suspicious: bool = False, **kw
    ):
        super().__init__(api_key, **kw)
        self.min_detections = min_detections
        self.count_suspicious = count_suspicious

    def _auth_headers(self) -> dict[str, str]:
        return {"x-apikey": self._key}

    def scan(self, url: str) -> dict:
        status, body = self._call(
            "POST",
            f"{VT_BASE}/urls",
            data=urlencode({"url": url}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self._check(status, body)
        analysis_id = body.get("data", {}).get("id")
        if not analysis_id:
            raise ScanError("submit returned no analysis id", terminal=True)
        for _ in range(self.max_polls):
            # The 15 s throttle spaces these polls.
            status, body = self._call("GET", f"{VT_BASE}/analyses/{quote(analysis_id, safe='')}")
            self._check(status, body)
            if body.get("data", {}).get("attributes", {}).get("status") == "completed":
                return body
        raise ScanError(f"analysis not completed after {self.max_polls} polls", terminal=False)

    def predict(self, raw: dict) -> tuple[str | None, str]:
        stats = raw.get("data", {}).get("attributes", {}).get("stats")
        if not isinstance(stats, dict):
            return None, "no stats"
        malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
        hits = malicious + (suspicious if self.count_suspicious else 0)
        detail = f"malicious={malicious} suspicious={suspicious}"
        return ("phishing" if hits >= self.min_detections else "legitimate"), detail


class UrlscanClient(_Client):
    name = "urlscan"
    label = "Vendor 2"
    env_var = "URLSCAN_API_KEY"
    min_interval_s = 2.0
    first_poll_s = 10.0
    poll_s = 5.0
    max_polls = 36

    def _auth_headers(self) -> dict[str, str]:
        return {"API-Key": self._key}

    def scan(self, url: str) -> dict:
        payload = {"url": url, "visibility": URLSCAN_VISIBILITY}
        status, body = self._call(
            "POST",
            f"{URLSCAN_BASE}/scan/",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        self._check(status, body)
        uuid = body.get("uuid")
        if not uuid:
            raise ScanError("submit returned no uuid", terminal=True)
        self.sleep(self.first_poll_s)
        for _ in range(self.max_polls):
            status, body = self._call("GET", f"{URLSCAN_BASE}/result/{quote(uuid, safe='')}/")
            if status == 404:  # the scan is still running
                self.sleep(self.poll_s)
                continue
            self._check(status, body)
            return body
        raise ScanError(f"result not ready after {self.max_polls} polls", terminal=False)

    def predict(self, raw: dict) -> tuple[str | None, str]:
        malicious = raw.get("verdicts", {}).get("overall", {}).get("malicious")
        if not isinstance(malicious, bool):
            return None, "no verdict"
        return ("phishing" if malicious else "legitimate"), f"malicious={malicious}"


def _cache_path(cache_dir: Path, client: _Client, url: str) -> Path:
    return cache_dir / client.name / f"{hashlib.sha256(url.encode()).hexdigest()}.json"


def run_scanner(client: _Client, dataset: list[tuple[str, str]], cache_dir: Path) -> list[dict]:
    """One row per URL in the evaluate_agents row shape; cached URLs are not resubmitted."""
    rows = []
    stopped = ""
    for url, label in dataset:
        path = _cache_path(cache_dir, client, url)
        entry = json.loads(path.read_text()) if path.exists() else None
        if entry is None and not stopped:
            t0 = time.monotonic()
            try:
                entry = {"response": client.scan(url), "error": None}
            except QuotaExhausted as exc:
                stopped = f"not scanned: {exc}"
                logger.warning("%s still rate limited; rerun later to resume", client.label)
            except ScanError as exc:
                logger.info("%s %s failed: %s", client.label, url, exc)
                if exc.terminal:
                    entry = {"response": None, "error": str(exc)}
                else:
                    rows.append(_row(url, label, None, str(exc), 0))
                    continue
            except (URLError, OSError, ValueError) as exc:
                logger.info("%s %s failed: %s", client.label, url, type(exc).__name__)
                rows.append(_row(url, label, None, type(exc).__name__, 0))
                continue
            if entry is not None:
                entry |= {
                    "url": url,
                    "fetched_at": datetime.now(UTC).isoformat(),
                    "elapsed_ms": int((time.monotonic() - t0) * 1000),
                }
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(entry, indent=2))
        if entry is None:
            rows.append(_row(url, label, None, stopped, 0))
        elif entry.get("response") is None:
            rows.append(_row(url, label, None, entry.get("error") or "", entry["elapsed_ms"]))
        else:
            prediction, detail = client.predict(entry["response"])
            rows.append(_row(url, label, prediction, detail, entry["elapsed_ms"]))
    # ponytail: a crash between submit and the verdict resubmits that one URL on rerun;
    # cache the pending scan id if quota gets that tight.
    return rows


def _row(url, label, prediction, detail, latency_ms) -> dict:
    return {
        "url": url,
        "label": label,
        "prediction": prediction,
        "detail": detail,
        "latency_ms": latency_ms,
    }


def load_ours(path: Path, agent: str, dataset: list[tuple[str, str]]) -> list[dict]:
    """This sample's rows from an evaluate_agents.py results file, limited to the dataset."""
    by_url = {r["url"]: r for r in json.loads(path.read_text())["rows"][agent]}
    missing = [url for url, _ in dataset if url not in by_url]
    if missing:
        logger.warning("%d dataset URLs are not in %s; scored as unscored", len(missing), path)
    rows = []
    for url, label in dataset:
        r = by_url.get(url)
        if r is None:
            rows.append(_row(url, label, None, "not in results file", 0))
        else:
            rows.append(_row(url, label, r["prediction"], r.get("verdict", ""), r["latency_ms"]))
    return rows


def _cell(value: float | None, hits: int, total: int) -> str:
    return "n/a" if value is None else f"{value} ({hits} of {total})"


def summarize(results: dict[str, list[dict]], *, run_date: str, notes: list[str]) -> str:
    """Markdown table of recall and false positive rate per scanner, scored by score()."""
    any_rows = next(iter(results.values()), [])
    phishing = sum(r["label"] == "phishing" for r in any_rows)
    lines = [
        f"Run {run_date}, {len(any_rows)} URLs ({phishing} phishing, "
        f"{len(any_rows) - phishing} legitimate).",
        "",
        *notes,
        "",
        "| Scanner | Recall | False positive rate | Unscored (errors/no verdict) |",
        "| --- | --- | --- | --- |",
    ]
    for scanner, rows in results.items():
        s = score(rows)
        recall = _cell(s["recall"], s["tp"], s["tp"] + s["fn"])
        fpr = _cell(s["fpr"], s["fp"], s["fp"] + s["tn"])
        lines.append(f"| {scanner} | {recall} | {fpr} | {s['errors']} |")
    return "\n".join(lines) + "\n"


def write_csv(path: Path, results: dict[str, list[dict]]) -> None:
    with path.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["scanner", "url", "label", "prediction", "detail"])
        for scanner, rows in results.items():
            for r in rows:
                writer.writerow([scanner, r["url"], r["label"], r["prediction"] or "", r["detail"]])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", type=Path, default=HERE / "data" / "committed_sample.csv")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--ours", type=Path, help="an evaluate_agents.py results JSON file")
    parser.add_argument("--ours-agent", default="orchestrator")
    parser.add_argument(
        "--vt-min-detections",
        type=int,
        default=1,
        help="Vendor 1 calls a URL phishing at this many detections or more",
    )
    parser.add_argument(
        "--vt-count-suspicious",
        action="store_true",
        help="count Vendor 1 'suspicious' detections as well as 'malicious'",
    )
    parser.add_argument("--out-dir", type=Path, default=HERE / "results" / "vendors")
    args = parser.parse_args(argv)
    if args.vt_min_detections < 1:
        parser.error("--vt-min-detections must be 1 or more")
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    dataset = load_dataset(args.dataset)[: args.limit]
    results: dict[str, list[dict]] = {}
    if args.ours:
        results[f"This sample ({args.ours_agent})"] = load_ours(args.ours, args.ours_agent, dataset)
    vt_opts = {
        "count_suspicious": args.vt_count_suspicious,
        "min_detections": args.vt_min_detections,
    }
    for cls, extra in ((VirusTotalClient, vt_opts), (UrlscanClient, {})):
        key = os.environ.get(cls.env_var)
        if not key:
            logger.warning("%s not set: skipping %s (%s)", cls.env_var, cls.label, cls.name)
            continue
        client = cls(key, **extra)
        results[client.label] = run_scanner(client, dataset, args.out_dir / "cache")
    if not results:
        logger.error("nothing to compare: set a vendor API key or pass --ours")
        return 1

    counted = "malicious and suspicious" if args.vt_count_suspicious else "malicious only"
    notes = [
        f"Vendor 1 counts a URL as phishing at {args.vt_min_detections} or more detections "
        f"({counted}). Vendor 2 counts it as phishing when its overall verdict is malicious.",
        "Unscored URLs are left out of recall and false positive rate.",
    ]
    if args.ours:
        notes.append(f"This sample: `{args.ours_agent}` rows from `{args.ours.name}`.")
    now = datetime.now(UTC)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    write_csv(args.out_dir / f"{stamp}.csv", results)
    summary = summarize(results, run_date=now.date().isoformat(), notes=notes)
    (args.out_dir / f"{stamp}.md").write_text(summary)
    logger.info("%s\nwrote %s.csv and %s.md in %s", summary, stamp, stamp, args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
