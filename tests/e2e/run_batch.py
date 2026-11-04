# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Run one batch end to end and write a report.

uv run --package phish-backend python -m tests.e2e.run_batch --csv Book1-chunk1.csv --source api
"""

import argparse
import logging
from concurrent.futures import ThreadPoolExecutor

from tests.e2e import datasets, report
from tests.e2e.client import ApiClient
from tests.e2e.stack import REGION, outputs

logger = logging.getLogger("e2e")


def run(label: str, csv_bytes: bytes, source: str, timeout_s: float) -> dict:
    api = ApiClient(outputs()["ApiUrl"], REGION)
    count = datasets.count_urls(csv_bytes)
    batch_id = api.create_upload_batch(csv_bytes, count, source)
    detail = api.wait_batch(batch_id, timeout_s)
    with ThreadPoolExecutor(max_workers=8) as pool:
        full = list(pool.map(lambda s: api.get_scan(s["scan_id"]), detail["items"]))
    summary = report.summarize(label, full, detail["batch"].get("wall_clock_ms"))
    summary.update(
        batch_id=batch_id,
        expected=count,
        error=detail.get("error"),
        invalid_rows=len(detail.get("invalid_rows", [])),
    )
    logger.info("report written to %s", report.write(summary))
    return summary


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, help="file name inside PHISH_E2E_DATA_DIR")
    parser.add_argument("--source", choices=["ui", "api"], default="api")
    parser.add_argument(
        "--unique", type=int, default=0, help="build N unique URLs from Book1 instead of --csv"
    )
    parser.add_argument("--timeout", type=float, default=3600)
    args = parser.parse_args()
    data = (
        ("\n".join(datasets.unique_urls(args.unique)) + "\n").encode()
        if args.unique
        else datasets.load(args.csv)
    )
    run(f"{args.source}-{args.unique or args.csv}", data, args.source, args.timeout)


if __name__ == "__main__":
    main()
