// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
/**
 * THE ONE PLACE THIS APP CALLS fetch(). Three exports: fetchWithPayloadHash for
 * same-origin calls through CloudFront, fetchWithRetry (the same, with 429 and
 * 503 backoff, and 502 backoff for reads) for API calls, and
 * uploadToPresignedPost for the one request that goes straight to S3.
 * =============================================================================
 * Every request the SPA makes goes through `fetchWithPayloadHash`, which exists
 * for a single reason: the app is served through CloudFront with Origin Access
 * Control (OAC) in front of a Lambda function URL, and with OAC the CALLER must
 * supply the SHA-256 of the request body in `x-amz-content-sha256`. Without it
 * CloudFront cannot sign the origin request and answers every POST with an opaque
 * 403. See lib/payloadHash.ts for the AWS documentation link and the full
 * explanation.
 *
 * The header is attached in exactly one place on purpose. Scattered across call
 * sites it is guaranteed to be forgotten by whoever adds the next POST, and the
 * symptom of forgetting it (a bodyless 403 in production only) is expensive to
 * diagnose. If you are adding a request, add it here, not next to your feature.
 *
 * This wrapper is deliberately thin: it adds one header and changes nothing else.
 * The URL, method, body, credentials mode, and every caller-supplied header are
 * passed through untouched, and the Response is returned as-is so each caller
 * keeps its own status handling.
 * =============================================================================
 */
import { PAYLOAD_HASH_HEADER, hashRequestBody } from "./payloadHash";

/**
 * Methods that can never carry a payload, and so must not carry the header.
 *
 * A denylist rather than an allowlist of POST/PUT/PATCH: the failure mode of
 * missing a body-bearing method is a 403 nobody can read, while the cost of
 * hashing an empty body on some future DELETE is a digest CloudFront would have
 * arrived at anyway. GET, which is everything the read side of this app does, is
 * left exactly as the caller wrote it.
 */
const METHODS_WITHOUT_PAYLOAD = new Set(["GET", "HEAD"]);

/**
 * fetch, plus the CloudFront OAC payload hash on anything that can carry a body.
 *
 * Throws `PayloadHashUnavailableError` (from lib/payloadHash.ts) when the digest
 * cannot be computed, before any request is made. That is intentional: a caller
 * that swallows the throw and proceeds would send a request CloudFront rejects
 * without explanation.
 */
export async function fetchWithPayloadHash(
  input: string,
  init?: RequestInit,
): Promise<Response> {
  // fetch defaults to GET when no method is given.
  const method = (init?.method ?? "GET").toUpperCase();
  if (METHODS_WITHOUT_PAYLOAD.has(method)) {
    return fetch(input, init);
  }

  // Headers are normalised through the Headers constructor so a record, an array
  // of pairs, or an existing Headers instance all survive with their entries
  // intact. Content-Type in particular must not be dropped.
  const headers = new Headers(init?.headers);
  if (!headers.has(PAYLOAD_HASH_HEADER)) {
    headers.set(PAYLOAD_HASH_HEADER, await hashRequestBody(init?.body));
  }
  return fetch(input, { ...init, headers });
}

/**
 * Upload a CSV straight to S3 with a presigned POST from POST /batches.
 *
 * Deliberately not routed through fetchWithPayloadHash. The request goes to S3,
 * not CloudFront, so there is no OAC signature to satisfy, and S3 rejects a
 * presigned POST that carries headers its policy did not list. Going direct is
 * also what keeps a 200-URL body away from the edge WAF body-size rule, which
 * caused the v1 limit of 50 URLs.
 */
export async function uploadToPresignedPost(
  url: string,
  fields: Record<string, string>,
  file: Blob,
  filename: string,
): Promise<void> {
  const form = new FormData();
  for (const [name, value] of Object.entries(fields)) form.append(name, value);
  // S3 ignores every form field after "file", so it must be appended last.
  form.append("file", file, filename);
  const res = await fetch(url, { method: "POST", body: form });
  if (!res.ok) throw new Error(`Upload was rejected (HTTP ${res.status}).`);
}

export interface RetryOptions {
  retries?: number;
  baseMs?: number;
  capMs?: number;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
}

const RETRYABLE = new Set([429, 503]);

/**
 * A 502 from the web tier means the Lambda Web Adapter lost its pooled
 * connection to gunicorn (ConnectionReset), which a poll hits now and then.
 * The request may have reached the app, so only reads, which are safe to send
 * twice, are retried, and only twice: one blip stays silent, a real outage
 * still surfaces within a second or two.
 */
const GATEWAY_RETRIES = 2;

/**
 * API Gateway answers 429 when its stage throttle is exceeded; the request never ran, so it is
 * always safe to send again. A 502 on a GET or HEAD is retried too (see GATEWAY_RETRIES).
 * Exponential backoff with full jitter, Retry-After wins when present.
 */
export async function fetchWithRetry(
  input: string,
  init?: RequestInit,
  { retries = 4, baseMs = 500, capMs = 8000, sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
    random = Math.random }: RetryOptions = {},
): Promise<Response> {
  const idempotent = METHODS_WITHOUT_PAYLOAD.has((init?.method ?? "GET").toUpperCase());
  for (let attempt = 0; ; attempt += 1) {
    const res = await fetchWithPayloadHash(input, init);
    const gatewayBlip = res.status === 502 && idempotent && attempt < GATEWAY_RETRIES;
    if (!gatewayBlip && (!RETRYABLE.has(res.status) || attempt === retries)) return res;
    const retryAfter = Number(res.headers.get("Retry-After"));
    const backoff = Math.min(capMs, baseMs * 2 ** attempt);
    await sleep(Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : Math.round(backoff * random()));
  }
}
