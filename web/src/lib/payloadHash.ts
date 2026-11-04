// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
/**
 * REQUEST PAYLOAD HASHING FOR CLOUDFRONT ORIGIN ACCESS CONTROL (OAC).
 * =============================================================================
 * WHY THIS EXISTS. Do not delete it as mysterious plumbing.
 *
 * The app is served through CloudFront with Origin Access Control in front of a
 * Lambda function URL. With OAC, CloudFront signs the origin request with SigV4
 * on our behalf, and SigV4 covers the request body. CloudFront does not read the
 * body to hash it: AWS puts that on the caller.
 *
 *   "If you use PUT or POST methods with your Lambda function URL, your users
 *    must compute the SHA256 of the body and include the payload hash value of
 *    the request body in the x-amz-content-sha256 header when sending the
 *    request to CloudFront."
 *
 *   https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/
 *   private-content-restricting-access-to-lambda.html
 *
 * Omit the header and CloudFront cannot produce a signature the origin accepts,
 * so every POST comes back as an opaque 403 with no body and no clue: the scan
 * flow, the batch flow and registration all die in the deployed app while
 * working perfectly against a local dev server. GET requests are unaffected,
 * which is what makes the failure so confusing to diagnose.
 *
 * The digest is computed with the browser's own Web Crypto API. No dependency is
 * added for this: `crypto.subtle` is native everywhere this app runs.
 * =============================================================================
 */

/**
 * The header CloudFront reads the caller-computed payload digest from. Lowercase
 * because that is how it is spelled in the AWS documentation and how SigV4
 * canonicalises header names.
 */
export const PAYLOAD_HASH_HEADER = "x-amz-content-sha256";

/**
 * Raised when the digest cannot be produced, so the request is abandoned instead
 * of being sent without the header.
 *
 * Sending an unhashed POST is strictly worse than failing here: CloudFront
 * answers it with a bare 403 that names no cause, and the user is left with a
 * scan that silently never starts. A thrown error with this name at least points
 * the next reader at the payload hash.
 */
export class PayloadHashUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PayloadHashUnavailableError";
  }
}

/** Reused across calls; a TextEncoder is stateless and always UTF-8. */
const TEXT_ENCODER = new TextEncoder();

/**
 * `crypto.subtle` is exposed only in a secure context. That covers everywhere
 * this app is meant to run: https:// (the CloudFront distribution) and
 * http://localhost or http://127.0.0.1 (`npm run dev`, which binds loopback by
 * design). It is absent over plain http:// on a LAN address or a bare IP.
 *
 * If it is genuinely missing we fail loudly rather than fall back to an unsigned
 * request, because the fallback would be a 403 with no explanation. There is no
 * hand-rolled SHA-256 fallback on purpose: shipping our own hash implementation
 * to paper over a misconfigured origin would hide the real problem.
 */
function requireSubtleCrypto(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new PayloadHashUnavailableError(
      "Web Crypto (crypto.subtle) is unavailable, so the CloudFront OAC payload " +
        "hash cannot be computed. This API is restricted to secure contexts: " +
        "serve the app over https, or over http://localhost during development.",
    );
  }
  return subtle;
}

/**
 * The exact bytes fetch will put on the wire, for every body shape this app can
 * produce. Hashing anything else (the whole backing buffer of a view, say) yields
 * a digest that does not describe the request, which fails identically to sending
 * no digest at all.
 */
async function toPayloadBytes(body: BodyInit | null | undefined): Promise<Uint8Array> {
  // No body. The digest is then the SHA-256 of a zero-length input, the value
  // SigV4 calls the hash of the empty string. It is computed here rather than
  // pasted in as a constant so it cannot be a mistyped 64 character literal.
  if (body === null || body === undefined) return new Uint8Array(0);

  if (typeof body === "string") return TEXT_ENCODER.encode(body);

  if (body instanceof ArrayBuffer) return new Uint8Array(body);

  // Uint8Array, DataView and friends. The view window matters: a typed array can
  // be a slice of a larger buffer, and only its own bytes are sent.
  if (ArrayBuffer.isView(body)) {
    return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  }

  // fetch sends this as its percent-encoded string form, so hash exactly that.
  if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
    return TEXT_ENCODER.encode(body.toString());
  }

  if (typeof Blob !== "undefined" && body instanceof Blob) {
    return new Uint8Array(await body.arrayBuffer());
  }

  // FormData and ReadableStream are refused, not guessed at. A FormData body is
  // serialised into a multipart document by fetch itself, using a boundary token
  // fetch chooses after this point, so any digest computed here would describe
  // different bytes than the ones sent. A stream can only be read once, and
  // reading it to hash it would leave nothing to send.
  //
  // Nothing in this app sends either shape today. If an upload is ever added,
  // serialise it here into a string, a Blob, or a Uint8Array and set
  // Content-Type (including your own multipart boundary) explicitly, then this
  // helper can hash it faithfully.
  throw new PayloadHashUnavailableError(
    "This request body shape cannot be hashed for the CloudFront OAC payload " +
      "header, because the bytes sent are decided after this point. Serialise it " +
      "to a string, a Blob, or a Uint8Array and set Content-Type explicitly.",
  );
}

/** Lowercase hex, the encoding SigV4 expects for the payload hash. */
function toLowerHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

/**
 * Lowercase hex SHA-256 of a request body, for the `x-amz-content-sha256`
 * header. An absent body hashes as the empty string.
 *
 * Never log the return value alongside the body it describes: the digest of a
 * small, guessable body is not a secret, but it is one more thing that does not
 * belong in a console for a request that carries a password.
 */
export async function hashRequestBody(body?: BodyInit | null): Promise<string> {
  const bytes = await toPayloadBytes(body);
  const digest = await requireSubtleCrypto().digest("SHA-256", bytes);
  return toLowerHex(new Uint8Array(digest));
}
