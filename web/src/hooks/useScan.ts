// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { isReportPending, isTerminal } from "@/lib/scanProgress";
import type { ScanDetail } from "@/lib/types";
import { usePolling } from "./usePolling";

export const SCAN_POLL_MS = 1500;
/** First wait between report polls; it grows by REPORT_BACKOFF up to the max. */
export const REPORT_POLL_MS = 3000;
export const REPORT_POLL_MAX_MS = 10000;
const REPORT_BACKOFF = 1.5;
/** Stop waiting for the report after this long; the verdict stays valid. */
export const REPORT_POLL_CAP_MS = 5 * 60 * 1000;

export function nextReportDelay(delayMs: number): number {
  return Math.min(REPORT_POLL_MAX_MS, Math.round(delayMs * REPORT_BACKOFF));
}

/**
 * Load one scan and keep it fresh until it is COMPLETE or FAILED. The scan id is
 * in the URL, so reloading or coming back from another page resumes here.
 *
 * COMPLETE means the verdict exists, not that the report does. While the report
 * is PENDING a second, slower poll (backing off, capped) keeps fetching the
 * record so the report appears without a refresh. A failed report poll never
 * replaces the verdict with an error; the next attempt just tries again.
 */
export function useScanRecord(scanId: string) {
  const [record, setRecord] = useState<ScanDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reportTimedOut, setReportTimedOut] = useState(false);
  // Stop from inside the loader too: a poll can be scheduled between the terminal
  // response and the re-render that disables polling, and it must not fetch again.
  const stopped = useRef(false);

  useEffect(() => {
    stopped.current = false;
    setRecord(null);
    setError(null);
    setReportTimedOut(false);
  }, [scanId]);

  const poll = useCallback(async () => {
    if (stopped.current) return;
    try {
      const next = await api.getScan(scanId);
      if (isTerminal(next.status)) stopped.current = true;
      setRecord(next);
      setError(null);
    } catch (err) {
      stopped.current = true;
      setError(
        err instanceof Error ? err.message : "Could not load this scan.",
      );
    }
  }, [scanId]);

  const retry = useCallback(async () => {
    stopped.current = false;
    await poll();
  }, [poll]);

  const done = record !== null && isTerminal(record.status);
  usePolling(poll, SCAN_POLL_MS, !done && error === null);

  const reportPending = record !== null && isReportPending(record);
  useEffect(() => {
    if (!reportPending || reportTimedOut) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const startedAt = Date.now();
    let delay = REPORT_POLL_MS;
    const tick = async () => {
      if (cancelled) return;
      if (Date.now() - startedAt >= REPORT_POLL_CAP_MS) {
        setReportTimedOut(true);
        return;
      }
      try {
        const next = await api.getScan(scanId);
        if (cancelled) return;
        setRecord(next);
        // Leaving PENDING flips reportPending, which tears this effect down.
      } catch {
        // Transient: the verdict on screen stays; try again after the backoff.
      }
      if (cancelled) return;
      delay = nextReportDelay(delay);
      timer = setTimeout(() => void tick(), delay);
    };
    timer = setTimeout(() => void tick(), delay);
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [reportPending, reportTimedOut, scanId]);

  /** After the cap, let the user ask for another round of report polling. */
  const checkReportAgain = useCallback(() => setReportTimedOut(false), []);

  return { record, error, retry, reportTimedOut, checkReportAgain };
}
