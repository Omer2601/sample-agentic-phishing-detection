// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
/**
 * WHY THIS SUITE EXISTS
 *
 * This is the single wrapper every request in the app goes through, and its whole
 * job is to attach the `x-amz-content-sha256` digest CloudFront Origin Access
 * Control requires on a body-carrying request. Two failures matter, and neither
 * one shows up in local development:
 *
 *  - the header is missing on a POST, so the deployed app answers every scan with
 *    a bodyless 403;
 *  - the wrapper is not transparent, so normalising headers quietly drops
 *    Content-Type or the credentials mode and breaks the session or the parse.
 *
 * Both are pinned below, along with the rule that a GET is passed through exactly
 * as written and never gains the header.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  fetchWithPayloadHash,
  fetchWithRetry,
  uploadToPresignedPost,
} from "./http";
import { PAYLOAD_HASH_HEADER, PayloadHashUnavailableError, hashRequestBody } from "./payloadHash";

const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/** Records what reached fetch, so the outgoing request can be inspected. */
function stubFetch() {
  const fn = vi.fn(async (_input: string, _init?: RequestInit) => {
    return { status: 200, ok: true } as Response;
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

/** The init fetch was actually called with. */
function sentInit(fn: ReturnType<typeof stubFetch>): RequestInit {
  return (fn.mock.calls[0]?.[1] ?? {}) as RequestInit;
}

function sentHeaders(fn: ReturnType<typeof stubFetch>): Headers {
  return new Headers(sentInit(fn).headers);
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("payload hash header", () => {
  it("sets the digest of the body on a POST", async () => {
    const fetchMock = stubFetch();
    await fetchWithPayloadHash("/api/scan", { method: "POST", body: "abc" });
    expect(sentHeaders(fetchMock).get(PAYLOAD_HASH_HEADER)).toBe(ABC_SHA256);
  });

  it("sets the empty-string digest on a POST that carries no body", async () => {
    const fetchMock = stubFetch();
    await fetchWithPayloadHash("/api/scan", { method: "POST" });
    expect(sentHeaders(fetchMock).get(PAYLOAD_HASH_HEADER)).toBe(EMPTY_SHA256);
  });

  it("accepts a lowercase method name, as fetch does", async () => {
    const fetchMock = stubFetch();
    await fetchWithPayloadHash("/api/scan", { method: "post", body: "abc" });
    expect(sentHeaders(fetchMock).get(PAYLOAD_HASH_HEADER)).toBe(ABC_SHA256);
  });

  it("covers the other body-carrying methods too", async () => {
    for (const method of ["PUT", "PATCH", "DELETE"]) {
      const fetchMock = stubFetch();
      await fetchWithPayloadHash("/api/thing", { method, body: "abc" });
      expect(sentHeaders(fetchMock).get(PAYLOAD_HASH_HEADER)).toBe(ABC_SHA256);
      vi.unstubAllGlobals();
    }
  });

  it("hashes a JSON body byte for byte, matching the helper", async () => {
    const body = JSON.stringify({ url: "https://example.com" });
    const fetchMock = stubFetch();
    await fetchWithPayloadHash("/api/scan", { method: "POST", body });
    expect(sentHeaders(fetchMock).get(PAYLOAD_HASH_HEADER)).toBe(await hashRequestBody(body));
  });

  it("does not overwrite a digest the caller already supplied", async () => {
    const fetchMock = stubFetch();
    await fetchWithPayloadHash("/api/scan", {
      method: "POST",
      body: "abc",
      headers: { [PAYLOAD_HASH_HEADER]: "UNSIGNED-PAYLOAD" },
    });
    expect(sentHeaders(fetchMock).get(PAYLOAD_HASH_HEADER)).toBe("UNSIGNED-PAYLOAD");
  });
});

describe("GET requests", () => {
  it("adds no payload hash to a GET", async () => {
    const fetchMock = stubFetch();
    await fetchWithPayloadHash("/api/scans/j1");
    expect(sentHeaders(fetchMock).has(PAYLOAD_HASH_HEADER)).toBe(false);
  });

  it("adds no payload hash to an explicit GET or HEAD", async () => {
    for (const method of ["GET", "HEAD", "get"]) {
      const fetchMock = stubFetch();
      await fetchWithPayloadHash("/api/health", { method });
      expect(sentHeaders(fetchMock).has(PAYLOAD_HASH_HEADER)).toBe(false);
      vi.unstubAllGlobals();
    }
  });

  it("passes a GET init through untouched", async () => {
    const fetchMock = stubFetch();
    const init: RequestInit = { credentials: "same-origin" };
    await fetchWithPayloadHash("/api/health", init);
    // Same object, so nothing about a read request can be altered here.
    expect(fetchMock.mock.calls[0]?.[1]).toBe(init);
  });
});

describe("transparency", () => {
  it("keeps the url, method, body and credentials mode", async () => {
    const fetchMock = stubFetch();
    await fetchWithPayloadHash("/api/batches", {
      method: "POST",
      body: "abc",
      credentials: "same-origin",
      cache: "no-store",
    });
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/batches");
    const init = sentInit(fetchMock);
    expect(init.method).toBe("POST");
    expect(init.body).toBe("abc");
    expect(init.credentials).toBe("same-origin");
    expect(init.cache).toBe("no-store");
  });

  it("preserves caller headers given as a record", async () => {
    const fetchMock = stubFetch();
    await fetchWithPayloadHash("/api/scan", {
      method: "POST",
      body: "abc",
      headers: { "Content-Type": "application/json", "X-Trace": "t1" },
    });
    const headers = sentHeaders(fetchMock);
    expect(headers.get("content-type")).toBe("application/json");
    expect(headers.get("x-trace")).toBe("t1");
    expect(headers.get(PAYLOAD_HASH_HEADER)).toBe(ABC_SHA256);
  });

  it("preserves caller headers given as a Headers instance", async () => {
    const fetchMock = stubFetch();
    const headers = new Headers({ "Content-Type": "application/json" });
    await fetchWithPayloadHash("/api/scan", { method: "POST", body: "abc", headers });
    expect(sentHeaders(fetchMock).get("content-type")).toBe("application/json");
    expect(sentHeaders(fetchMock).get(PAYLOAD_HASH_HEADER)).toBe(ABC_SHA256);
    // The caller's own object is not mutated.
    expect(headers.has(PAYLOAD_HASH_HEADER)).toBe(false);
  });

  it("preserves caller headers given as an array of pairs", async () => {
    const fetchMock = stubFetch();
    await fetchWithPayloadHash("/api/scan", {
      method: "POST",
      body: "abc",
      headers: [["Content-Type", "application/json"]],
    });
    expect(sentHeaders(fetchMock).get("content-type")).toBe("application/json");
  });

  it("returns the response the caller's own status handling expects", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ status: 202, ok: true }) as Response));
    const res = await fetchWithPayloadHash("/api/scan", { method: "POST", body: "abc" });
    expect(res.status).toBe(202);
  });
});

describe("when the digest cannot be computed", () => {
  it("throws and sends nothing, rather than a request CloudFront will 403", async () => {
    const fetchMock = stubFetch();
    // An insecure context: crypto exists, crypto.subtle does not.
    vi.stubGlobal("crypto", {});
    await expect(
      fetchWithPayloadHash("/api/scan", { method: "POST", body: "abc" }),
    ).rejects.toThrow(PayloadHashUnavailableError);
    // The important half of the assertion: no unsigned POST left the browser.
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("uploadToPresignedPost", () => {
  it("posts the policy fields first and the file last", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return new Response(null, { status: 204 });
    });
    await uploadToPresignedPost(
      "https://bucket.s3.us-west-2.amazonaws.com/",
      { key: "uploads/o/b.csv", policy: "p" },
      new Blob(["url\nhttps://a.example\n"], { type: "text/csv" }),
      "b.csv",
    );
    const form = calls[0].init.body as FormData;
    expect([...form.keys()]).toEqual(["key", "policy", "file"]);
    expect(calls[0].init.method).toBe("POST");
    // S3 rejects unknown headers on presigned POST, so no payload hash is added.
    expect(new Headers(calls[0].init.headers).has("x-amz-content-sha256")).toBe(
      false,
    );
    vi.unstubAllGlobals();
  });

  it("throws with the status when S3 refuses", async () => {
    vi.stubGlobal(
      "fetch",
      async () => new Response("<Error/>", { status: 403 }),
    );
    await expect(
      uploadToPresignedPost("https://b.example/", {}, new Blob(["x"]), "x.csv"),
    ).rejects.toThrow(/HTTP 403/);
    vi.unstubAllGlobals();
  });
});

describe("fetchWithRetry", () => {
  it("retries 429 with backoff and returns the first success", async () => {
    const statuses = [429, 429, 200];
    const fetchMock = vi.fn(async () => new Response("{}", { status: statuses.shift() }));
    vi.stubGlobal("fetch", fetchMock);
    const sleeps: number[] = [];
    const res = await fetchWithRetry("/api/scan", { method: "POST" }, {
      sleep: async (ms) => { sleeps.push(ms); },
      random: () => 1,
    });
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(sleeps).toEqual([500, 1000]);
  });

  it("honours Retry-After seconds", async () => {
    const responses = [new Response("", { status: 429, headers: { "Retry-After": "3" } }), new Response("{}")];
    vi.stubGlobal("fetch", vi.fn(async () => responses.shift()));
    const sleeps: number[] = [];
    await fetchWithRetry("/api/stats", undefined, { sleep: async (ms) => { sleeps.push(ms); }, random: () => 1 });
    expect(sleeps).toEqual([3000]);
  });

  it("gives up after four retries and returns the last 429", async () => {
    const fetchMock = vi.fn(async () => new Response("", { status: 429 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await fetchWithRetry("/api/scan", undefined, { sleep: async () => {}, random: () => 0 });
    expect(res.status).toBe(429);
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });

  it("retries a single 502 on a GET silently with backoff (UI e2e run 2, D4)", async () => {
    const statuses = [502, 200];
    const fetchMock = vi.fn(async () => new Response("{}", { status: statuses.shift() }));
    vi.stubGlobal("fetch", fetchMock);
    const sleeps: number[] = [];
    const res = await fetchWithRetry("/api/batches?limit=20", undefined, {
      sleep: async (ms) => { sleeps.push(ms); },
      random: () => 1,
    });
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(sleeps).toEqual([500]);
  });

  it("retries a 502 on a GET at most twice, then returns it", async () => {
    const fetchMock = vi.fn(async () => new Response("", { status: 502 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await fetchWithRetry("/api/batches", { method: "GET" }, { sleep: async () => {}, random: () => 0 });
    expect(res.status).toBe(502);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("never retries a 502 on a POST, which may already have run", async () => {
    const fetchMock = vi.fn(async () => new Response("", { status: 502 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await fetchWithRetry("/api/scan", { method: "POST", body: "{}" }, { sleep: async () => {}, random: () => 0 });
    expect(res.status).toBe(502);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("never retries a 400", async () => {
    const fetchMock = vi.fn(async () => new Response("", { status: 400 }));
    vi.stubGlobal("fetch", fetchMock);
    await fetchWithRetry("/api/scan", undefined, { sleep: async () => {}, random: () => 0 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
