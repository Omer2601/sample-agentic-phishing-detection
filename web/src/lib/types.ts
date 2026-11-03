// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
/**
 * Wire types for the phishing detection API.
 *
 * These mirror contracts/phish_contracts/models.py field for field. JSON field
 * names stay snake_case on purpose: renaming at the boundary would need a mapping
 * layer that can drift from the Python models. Change both files together.
 */

/**
 * `error_404` is the target page returning HTTP 404 (nothing to analyse). It is
 * distinct from "unknown", which means the analysis could not decide.
 * `site_down` is a dead target (DNS gone, connection refused, HTTP 410, or a
 * redirect to a dead host), answered without a model like `error_404`.
 */
export type VerdictLabel =
  | "phishing"
  | "suspicious"
  | "legitimate"
  | "unknown"
  | "error_404"
  | "site_down";
export type FindingStatus = "ok" | "blocked_by_guardrail" | "error";
export type Severity = "low" | "medium" | "high" | "critical";
export type CallKind =
  | "harness"
  | "specialist"
  | "model"
  | "browser"
  | "whois"
  | "web_search"
  | "registry";
export type Action = "block" | "warn" | "allow";
export type ConfidenceBand = "low" | "medium" | "high";
export type ScanStatus = "PENDING" | "RUNNING" | "COMPLETE" | "FAILED";
/**
 * The full report is written after the verdict. A missing field on a record
 * means READY (records stored before the verdict-first split).
 */
export type ReportStatus = "PENDING" | "READY" | "FAILED";
export type BatchSource = "ui" | "api";
export type SpecialistName = "url_analyst" | "brand_visual" | "code_analyst";

export const SPECIALISTS: readonly SpecialistName[] = [
  "url_analyst",
  "brand_visual",
  "code_analyst",
];

export interface Usage {
  input_tokens: number;
  output_tokens: number;
  model_id: string;
}

export interface Call {
  kind: CallKind;
  name: string;
  started_at: string;
  duration_ms: number;
  status: "ok" | "error" | "blocked_by_guardrail";
  usage?: Usage | null;
}

export interface Signal {
  name: string;
  severity: Severity;
  evidence: string;
}

/** One request or form target the page's code can send data to (code_analyst). */
export interface EndpointInsight {
  /** Defanged by the backend; render as text, never as a link. */
  url: string;
  /** fetch, xhr, beacon, form, websocket or image. */
  kind: string;
  off_domain: boolean;
}

export interface FormInsight {
  /** Defanged form action, "" when the form has none. */
  action: string;
  /** Input types in page order. */
  fields?: string[];
  submits_via_js: boolean;
}

/** What the page's code does, measured by code_analyst. Mirrors phish_contracts CodeInsights. */
export interface CodeInsights {
  /** At most 20, off-domain first. */
  endpoints?: EndpointInsight[];
  /** At most 10. */
  forms?: FormInsight[];
  script_count?: number;
  script_kb?: number;
  /** At most 15 registered domains. */
  external_script_hosts?: string[];
}

/** How a hop was reached. Mirrors phish_contracts RedirectHop.via. */
export type HopVia = "start" | "http" | "client" | "warning_bypass";

/** One step from the submitted URL to the page finally shown, measured by code. */
export interface RedirectHop {
  /** Exact URL (a machine field): render it defanged, never as a link. */
  url: string;
  via?: HopVia | string;
  status?: number | null;
  /** net::ERR_* when this hop did not load. */
  error?: string | null;
  /** The hop moved to another site. */
  cross_domain?: boolean;
  free_hosting?: boolean;
  shortener?: boolean;
}

export interface Finding {
  agent: SpecialistName;
  status: FindingStatus;
  verdict: VerdictLabel;
  confidence: number;
  signals: Signal[];
  artifacts: string[];
  usage: Usage;
  latency_ms: number;
  calls: Call[];
  // brand_visual only: how far the page capture got (complete, partial, failed (...)).
  capture_status?: string | null;
  /** One plain sentence on how the capture went, written by code, never by the model. */
  capture_note?: string | null;
  /** code_analyst only. Absent on older records. */
  insights?: CodeInsights | null;
  /** At most 10 hops; empty or absent on older records. */
  redirect_chain?: RedirectHop[];
  /** brand_visual and code_analyst: did the capture see the real page. */
  page_observed?: boolean | null;
}

export interface Verdict {
  verdict: VerdictLabel;
  risk_score: number;
  confidence: ConfidenceBand;
  action: Action;
  summary: string;
  disagreements: string[];
  missed_by_specialists: string[];
  report_markdown: string;
  /**
   * Set by code, not the model: false when no browser capture saw the real page. A
   * provider warning that hid the page also caps the verdict at suspicious (risk 69).
   */
  page_observed?: boolean | null;
  /** Set by code when that cap changed the answer: what the model said before it. */
  capped_from?: { verdict: VerdictLabel; risk_score: number; action: Action } | null;
}

/** Mirrors phish_contracts.models.SimilarScan. */
export interface SimilarScan {
  scan_id: string;
  summary: string;
}

export interface ScanRecord {
  scan_id: string;
  url: string;
  batch_id: string | null;
  status: ScanStatus;
  queued_at: string;
  started_at: string | null;
  completed_at: string | null;
  queue_wait_ms: number | null;
  total_ms: number | null;
  verdict: Verdict | null;
  findings: Finding[];
  calls: Call[];
  /** Decimal serialised as a string by Pydantic, e.g. "0.1432". */
  cost_usd: string;
  /**
   * Models with no price: their tokens are not in cost_usd, so the cost is unknown.
   * Absent in records written before the field existed.
   */
  unpriced_models?: string[];
  error: string | null;
  /** Worker attempts so far; a scan is FAILED only after 3. */
  attempts: number;
  /** Guardrail interventions, shown to the user; they never stop a scan. */
  guardrail_events: string[];
  /**
   * Your own earlier scans that episodic memory matched to this one (GET /scans/{id} only).
   * Context the orchestrator saw, never evidence; other owners' scans are never listed.
   */
  similar_scans?: SimilarScan[];
  /** Epoch seconds of the last successful SQS send; absent until queued. */
  enqueued_at?: number | null;
  /** Worker claims over the scan's whole life (never reset by a retry). */
  claims?: number;
  /**
   * Progress of the full report, separate from `status`: COMPLETE means the
   * verdict is available, even while this is PENDING. Absent means READY.
   */
  report_status?: ReportStatus;
  /** ISO time the report started being written. */
  report_started_at?: string | null;
  /** ISO time the report became READY. */
  report_ready_at?: string | null;
  /** Short reason, set when report_status is FAILED. */
  report_error?: string | null;
}

/** GET /scans/{id}: the record plus short-lived presigned artifact links. */
export interface ScanDetail extends ScanRecord {
  /** Server-side copy of the AI disclaimer. Optional; the console uses lib/disclaimer.ts. */
  disclaimer?: string;
  artifacts: { screenshot: string | null };
}

export interface BatchRecord {
  batch_id: string;
  source: BatchSource;
  total: number;
  status_counts: Partial<Record<ScanStatus, number>>;
  verdict_counts: Partial<Record<VerdictLabel, number>>;
  created_at: string;
  first_started_at: string | null;
  completed_at: string | null;
  wall_clock_ms: number | null;
  sum_scan_ms: number;
  cost_usd: string;
  // Upload lifecycle (phish_contracts BatchRecord, sent on GET /batches and
  // GET /batches/{id}).
  /** True while a presigned CSV upload has been requested but not yet split. */
  awaiting_upload: boolean;
  /** When split_csv or the sweeper handled the upload. */
  split_at: string | null;
  /** Why the batch cannot proceed, e.g. "CSV was never uploaded". An errored
   * batch also has completed_at, so it is closed. */
  error: string | null;
}

export interface Page<T> {
  items: T[];
  next: string | null;
}

/** One CSV row the splitter skipped (not a URL, a duplicate, over the cap). */
export interface InvalidRow {
  row: number;
  value: string;
  reason: string;
}

/**
 * GET /batches/{id} (interfaces.md, backend api/routes/batches.py). The
 * BatchRecord sits under `batch`; the detail-only fields sit beside it at the
 * top level, next to the scan page.
 */
export interface BatchDetail {
  /** Optional server-side disclaimer; see ScanDetail. */
  disclaimer?: string;
  batch: BatchRecord;
  /** Skipped CSV rows, at most the first 100. */
  invalid_rows: InvalidRow[];
  /** Why the upload could not be split, when it could not. */
  error: string | null;
  p50_ms: number | null;
  p95_ms: number | null;
  /** p95 is past the top latency bucket; p95_ms is then the 120000 bound. */
  p95_over_max: boolean;
  /** The same for p50. Absent from older backends. */
  p50_over_max?: boolean;
  /** The value is a latency bucket upper edge, not a measured duration. */
  p50_bound?: boolean;
  p95_bound?: boolean;
  items: ScanRecord[];
  next: string | null;
}

export type StatsRange = "24h" | "7d" | "30d" | "all";

export interface StatsTotals {
  scanned: number;
  phishing: number;
  suspicious: number;
  legitimate: number;
  unknown: number;
  /** Scans whose target returned HTTP 404. Absent in data written before the label existed. */
  error_404?: number;
  /** Scans whose target was down. Absent in data written before the label existed. */
  site_down?: number;
  failed: number;
  cost_usd: string;
  /** Scans with a model that has no price; cost_usd is then a lower bound. */
  unpriced_scans?: number;
  input_tokens: number;
  output_tokens: number;
  avg_ms: number;
  p95_ms: number;
  /** p95 is past the top latency bucket; p95_ms is then the 120000 bound. */
  p95_over_max: boolean;
  /** p95_ms is a latency bucket edge, so only an upper bound. */
  p95_bound?: boolean;
}

export interface DailyStats {
  day: string;
  phishing: number;
  suspicious: number;
  legitimate: number;
  unknown: number;
  /** Scans whose target returned HTTP 404. Absent in data written before the label existed. */
  error_404?: number;
  /** Scans whose target was down. Absent in data written before the label existed. */
  site_down?: number;
  failed: number;
  cost_usd: string;
  input_tokens: number;
  output_tokens: number;
}

export interface LatencyBucket {
  upper_ms: number;
  count: number;
}

export interface ModelUsage {
  model_id: string;
  input_tokens: number;
  output_tokens: number;
  cost_usd: string;
  /** false when some of this model's calls had no price; absent in older responses. */
  cost_known?: boolean;
}

export interface AgentCoreStat {
  kind: CallKind;
  name: string;
  count: number;
  avg_ms: number;
  p95_ms: number;
  /** p95 is past the top latency bucket; p95_ms is then the 120000 bound. */
  p95_over_max: boolean;
  /** p95_ms is a latency bucket edge, so only an upper bound. */
  p95_bound?: boolean;
  errors: number;
  blocked: number;
}

export interface Stats {
  /** Optional server-side disclaimer; see ScanDetail. */
  disclaimer?: string;
  range: StatsRange;
  totals: StatsTotals;
  daily: DailyStats[];
  latency_histogram: LatencyBucket[];
  by_model: ModelUsage[];
  agentcore: AgentCoreStat[];
  recent_batches: BatchRecord[];
}

/** Presentational progress for a scan that is still running (derived client side). */
export type ScanStage = "QUEUED" | "SPECIALISTS" | "VERDICT" | "DONE";

export interface ScanProgress {
  scanId: string;
  status: ScanStatus;
  stage: ScanStage;
  /** 0..1, capped below 1 until the API reports COMPLETE. */
  progress: number;
  elapsedSeconds: number;
}

/** Risk tier of a suggested target from GET /feed/phishing (unchanged from v1). */
export type RiskTier = "high" | "medium" | "low";

export interface FeedItem {
  url: string;
  host: string;
  risk: RiskTier;
  label: string;
  source: string;
}

export interface FeedGroup {
  risk: RiskTier;
  title: string;
  description: string;
  items: FeedItem[];
}

export interface FeedResponse {
  items: FeedItem[];
  groups: FeedGroup[];
  attribution: string;
  liveCount: number;
  cached: boolean;
  warning: string;
  message?: string;
}
