// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
/**
 * WHY THIS SUITE EXISTS
 *
 * The digest this helper produces is the difference between a working POST and an
 * opaque 403 from CloudFront, because Origin Access Control makes the caller
 * responsible for the `x-amz-content-sha256` body hash. A wrong digest fails
 * exactly like a missing one, with no message and no way to tell them apart from
 * the browser, so correctness is pinned here rather than discovered in a deploy.
 *
 * What is protected:
 *  - Known answers. The vectors below are independently computed values
 *    (`printf 'abc' | shasum -a 256`), not values read back out of this code.
 *  - The empty body. Its digest is the well-known SHA-256 of the empty string,
 *    asserted against the literal so a future refactor cannot quietly start
 *    hashing something else, while the implementation itself computes it.
 *  - Every body shape the wrapper can be handed must agree with its string
 *    equivalent, since a typed-array view over a larger buffer is the easy way to
 *    hash bytes the request never sends.
 *  - Refusal, loudly, when the digest cannot be produced. Silently sending an
 *    unhashed POST is the failure this whole file exists to prevent.
 *
 * Environment note: vitest runs these in the `node` environment, with no DOM. The
 * helper uses `globalThis.crypto.subtle`, which Node exposes as a global from
 * Node 20 onwards (this repo builds on Node 22), so the same code path the
 * browser takes is the one exercised here. The first test asserts that outright,
 * so an older runtime fails with a clear reason instead of a confusing digest
 * error.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  PAYLOAD_HASH_HEADER,
  PayloadHashUnavailableError,
  hashRequestBody,
} from "./payloadHash";

/** SHA-256 of the empty string. `printf '' | shasum -a 256`. */
const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/** SHA-256 of "abc", the canonical FIPS 180-4 vector. `printf 'abc' | shasum -a 256`. */
const ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/** SHA-256 of a realistic scan body. `printf '{"url":"https://example.com"}' | shasum -a 256`. */
const SCAN_BODY = '{"url":"https://example.com"}';
const SCAN_BODY_SHA256 = "5dc5c505a79bfc2eb22d0e45eff415c6ecf0c965c3d53d6e3e02c1bda74b0927";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("runtime support", () => {
  it("has Web Crypto available in the node test environment", () => {
    // Node 20+ exposes crypto as a global, so no polyfill or jsdom is needed to
    // exercise the browser code path.
    expect(typeof globalThis.crypto?.subtle?.digest).toBe("function");
  });
});

describe("known answers", () => {
  it("matches the published vector for a short ASCII string", async () => {
    expect(await hashRequestBody("abc")).toBe(ABC_SHA256);
  });

  it("matches the vector for a JSON body of the shape the app posts", async () => {
    expect(await hashRequestBody(SCAN_BODY)).toBe(SCAN_BODY_SHA256);
  });

  it("hashes an empty body as the SHA-256 of the empty string", async () => {
    // Computed by the helper from a zero-length input, compared here against the
    // independently known constant.
    expect(await hashRequestBody("")).toBe(EMPTY_SHA256);
  });

  it("treats a missing body the same as an empty one", async () => {
    expect(await hashRequestBody()).toBe(EMPTY_SHA256);
    expect(await hashRequestBody(undefined)).toBe(EMPTY_SHA256);
    expect(await hashRequestBody(null)).toBe(EMPTY_SHA256);
  });

  it("returns 64 lowercase hex characters, the encoding SigV4 expects", async () => {
    for (const body of ["", "abc", SCAN_BODY, "\u{1F600} unicode"]) {
      expect(await hashRequestBody(body)).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("encodes text as UTF-8, so multibyte bodies are not mangled", async () => {
    // The digest of the bytes, not of the UTF-16 code units: a wrong encoding
    // here would only fail for non-ASCII URLs, which is the worst way to find out.
    const utf8 = new TextEncoder().encode("café \u{1F600}");
    expect(await hashRequestBody("café \u{1F600}")).toBe(await hashRequestBody(utf8));
  });
});

describe("body shapes agree with their string equivalent", () => {
  const encoder = new TextEncoder();

  it("hashes a Uint8Array like the string it encodes", async () => {
    expect(await hashRequestBody(encoder.encode("abc"))).toBe(ABC_SHA256);
  });

  it("hashes an ArrayBuffer like the string it encodes", async () => {
    const bytes = encoder.encode(SCAN_BODY);
    // A standalone ArrayBuffer holding exactly these bytes.
    const buffer = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(buffer).set(bytes);
    expect(await hashRequestBody(buffer)).toBe(SCAN_BODY_SHA256);
  });

  it("hashes only a typed array's own window, not its whole backing buffer", async () => {
    // "xxabcxx" with a view over the middle three bytes. Hashing the backing
    // buffer would produce the digest of the padded string instead.
    const padded = Uint8Array.from(encoder.encode("xxabcxx"));
    const view = padded.subarray(2, 5);
    expect(view.byteOffset).toBe(2);
    expect(await hashRequestBody(view)).toBe(ABC_SHA256);
  });

  it("hashes a DataView the same way", async () => {
    const padded = Uint8Array.from(encoder.encode("xxabcxx"));
    const view = new DataView(padded.buffer, 2, 3);
    expect(await hashRequestBody(view)).toBe(ABC_SHA256);
  });

  it("hashes a Blob by its bytes", async () => {
    expect(await hashRequestBody(new Blob([SCAN_BODY]))).toBe(SCAN_BODY_SHA256);
  });

  it("hashes URLSearchParams as the percent-encoded string fetch would send", async () => {
    const params = new URLSearchParams({ url: "https://example.com/a b" });
    expect(await hashRequestBody(params)).toBe(await hashRequestBody(params.toString()));
  });
});

describe("refusing rather than guessing", () => {
  it("rejects a FormData body, whose wire bytes are not knowable here", async () => {
    // fetch picks the multipart boundary after this point, so any digest computed
    // here would describe different bytes than the ones sent. Nothing in the app
    // posts FormData; if that changes, the failure must be this loud.
    const form = new FormData();
    form.set("url", "https://example.com");
    await expect(hashRequestBody(form)).rejects.toThrow(PayloadHashUnavailableError);
  });

  it("fails loudly when Web Crypto is unavailable instead of returning a placeholder", async () => {
    // What an insecure context looks like: crypto present, subtle missing.
    vi.stubGlobal("crypto", {});
    await expect(hashRequestBody("abc")).rejects.toThrow(PayloadHashUnavailableError);
    await expect(hashRequestBody("abc")).rejects.toThrow(/https/i);
  });
});

describe("header name", () => {
  it("is the header CloudFront OAC reads, spelled in lowercase", () => {
    expect(PAYLOAD_HASH_HEADER).toBe("x-amz-content-sha256");
  });
});
