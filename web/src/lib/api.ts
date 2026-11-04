// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
/**
 * The typed client for the phishing detection API.
 *
 * Every call goes to same-origin /api/*. The web tier (web/server/wsgi.py) checks
 * the Cognito session, adds the caller's verified subject, signs with SigV4 and
 * forwards to API Gateway, so the browser never holds an AWS credential or learns
 * the API endpoint.
 */
import type {
  BatchDetail,
  BatchRecord,
  FeedItem,
  FeedResponse,
  Page,
  RiskTier,
  ScanDetail,
  ScanRecord,
  ScanStatus,
  Stats,
  StatsRange,
} from "./types";
import { fetchWithRetry } from "./http";

const API_PREFIX = "/api";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/**
 * A short message for an error body that did not come from our API (CloudFront or
 * WAF HTML). Keyed on status alone, because parsing an intermediary's page would
 * trust a shape AWS is free to change.
 */
export function edgeRejectionMessage(status: number): string {
  if (status === 403) {
    return "This request was blocked before it reached the scanner, usually because the URL matched an edge security rule. Try a different URL.";
  }
  if (status === 429)
    return "Too many requests right now. Wait a moment and try again.";
  if (status >= 500)
    return "The service is temporarily unavailable. Try again shortly.";
  return `The request was rejected (HTTP ${status}).`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  // Throttled (429) and briefly unavailable (503) calls are retried with backoff:
  // a throttled request never ran, so sending it again is always safe. A 502 on a
  // read (a dropped web-adapter connection mid-poll) is retried the same way.
  const res = await fetchWithRetry(`${API_PREFIX}${path}`, {
    ...init,
    credentials: "same-origin",
  });
  if (res.status === 401) {
    // An expired session: send the browser through login and come back here.
    const target = window.location.pathname + window.location.search;
    window.location.assign(`/auth/login?next=${encodeURIComponent(target)}`);
    return new Promise<T>(() => {});
  }
  if (res.status >= 400) {
    let message: string;
    try {
      const body = (await res.clone().json()) as { error?: unknown };
      message = typeof body.error === "string" ? body.error : "";
    } catch {
      // Not our API talking: show a short message, never an HTML page.
      message = edgeRejectionMessage(res.status);
    }
    throw new ApiError(
      message || `Request to ${path} failed with ${res.status}`,
      res.status,
    );
  }
  return (await res.json()) as T;
}

function postJson(body: unknown): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

function withPaging(
  path: string,
  next: string | null | undefined,
  limit: number,
): string {
  const query = new URLSearchParams({ limit: String(limit) });
  if (next) query.set("next", next);
  return `${path}?${query.toString()}`;
}

/** GET /scans/{id}/report and GET /batches/{id}/report. */
export interface ReportLink {
  url: string;
  expires_in: number;
}

export interface UploadTicket {
  batch_id: string;
  upload_url: string;
  upload_fields: Record<string, string>;
}

function mapFeed(body: Record<string, unknown>): FeedResponse {
  const mapItem = (i: Record<string, unknown>): FeedItem => ({
    url: String(i.url ?? ""),
    host: String(i.host ?? ""),
    risk: (i.risk as RiskTier) ?? "high",
    label: String(i.label ?? i.host ?? ""),
    source: String(i.source ?? body.attribution ?? ""),
  });
  const groups = Array.isArray(body.groups)
    ? (body.groups as Record<string, unknown>[])
    : [];
  const items = Array.isArray(body.items)
    ? (body.items as Record<string, unknown>[])
    : [];
  return {
    items: items.map(mapItem),
    groups: groups.map((g) => ({
      risk: g.risk as RiskTier,
      title: String(g.title ?? ""),
      description: String(g.description ?? ""),
      items: (Array.isArray(g.items)
        ? (g.items as Record<string, unknown>[])
        : []
      ).map(mapItem),
    })),
    attribution: String(body.attribution ?? ""),
    liveCount: Number(body.live_count ?? 0),
    cached: Boolean(body.cached),
    warning: String(body.warning ?? ""),
    message: typeof body.message === "string" ? body.message : undefined,
  };
}

export const api = {
  health: () => request<{ ok: boolean }>("/health"),

  startScan: (url: string) =>
    request<{ scan_id: string }>("/scan", postJson({ url })),

  getScan: (scanId: string) =>
    request<ScanDetail>(`/scans/${encodeURIComponent(scanId)}`),

  retryScan: (scanId: string) =>
    request<{ scan_id: string; status: ScanStatus }>(
      `/scans/${encodeURIComponent(scanId)}/retry`,
      { method: "POST" },
    ),

  /** A short-lived presigned link to the scan's HTML report (COMPLETE scans only). */
  getScanReport: (scanId: string) =>
    request<ReportLink>(`/scans/${encodeURIComponent(scanId)}/report`),

  /** A short-lived presigned link to the batch's HTML report. */
  getBatchReport: (batchId: string) =>
    request<ReportLink>(`/batches/${encodeURIComponent(batchId)}/report`),

  retryFailed: (batchId: string) =>
    request<{ batch_id: string; retried: number }>(
      `/batches/${encodeURIComponent(batchId)}/retry-failed`,
      { method: "POST" },
    ),

  /** Up to 50 URLs inline. Larger lists use requestUpload. */
  startBatch: (urls: string[]) =>
    request<{ batch_id: string }>("/batches", postJson({ urls })),

  requestUpload: (count: number) =>
    request<UploadTicket>(
      "/batches",
      postJson({ upload: true, count, source: "ui" }),
    ),

  listBatches: (next?: string | null, limit = 20) =>
    request<Page<BatchRecord>>(withPaging("/batches", next, limit)),

  getBatch: (batchId: string, next?: string | null) =>
    request<BatchDetail>(
      withPaging(`/batches/${encodeURIComponent(batchId)}`, next, 200),
    ),

  getHistory: (next?: string | null) =>
    request<Page<ScanRecord>>(withPaging("/history", next, 25)),

  getStats: (range: StatsRange) => request<Stats>(`/stats?range=${range}`),

  /** A plain link: the browser downloads the CSV through the proxy with its cookie. */
  statsExportUrl: (range: StatsRange) =>
    `${API_PREFIX}/stats/export?range=${range}`,

  getSuggestions: async (limit = 10): Promise<FeedResponse> =>
    mapFeed(
      await request<Record<string, unknown>>(
        `/feed/phishing?limit=${encodeURIComponent(limit)}`,
      ),
    ),
};
