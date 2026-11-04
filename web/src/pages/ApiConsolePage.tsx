// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useState } from "react";
import { Terminal, Play, Copy, Check } from "lucide-react";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  Input,
  Spinner,
} from "@/components/ui";
import { fetchWithPayloadHash } from "@/lib/http";

/**
 * Same-origin prefix the server-side signing tier is mounted on. Defined here
 * rather than imported because the transport module is owned by another agent
 * and does not export it; the value must stay in step with real.ts. Calls go to
 * `/api/*` so a first-party tier can attach AWS SigV4, keeping every AWS
 * credential out of the browser.
 */
const API_PROXY_PREFIX = "/api";

/** A clearly fake stand-in so the copyable commands never leak a real API id. */
const PLACEHOLDER_BASE = "https://<api-id>.execute-api.<region>.amazonaws.com/<stage>";

interface PathParam {
  name: string;
  label: string;
  placeholder: string;
}

interface EndpointDef {
  id: string;
  method: "GET" | "POST";
  /** Path template; a path parameter is written as `{name}`. */
  pathTemplate: string;
  description: string;
  pathParam?: PathParam;
  /** Pre-filled request body for POST endpoints. */
  defaultBody?: string;
}

/**
 * Which endpoints feed a follow-up lookup. A scan is asynchronous, so the id it
 * returns must land in the matching GET input; wiring it here lets the page do
 * that automatically after a successful call.
 */
const AUTO_FILL: Record<string, { targetId: string; sourceKey: string }> = {
  scan: { targetId: "result", sourceKey: "scan_id" },
  batches: { targetId: "batch", sourceKey: "batch_id" },
};

const ENDPOINTS: EndpointDef[] = [
  {
    id: "health",
    method: "GET",
    pathTemplate: "/health",
    description: "Liveness probe, the only endpoint that needs no auth.",
  },
  {
    id: "scan",
    method: "POST",
    pathTemplate: "/scan",
    description:
      "Queue one URL. Returns a scan_id; the verdict takes about 30 to 40 seconds.",
    defaultBody: JSON.stringify({ url: "https://example.com" }, null, 2),
  },
  {
    id: "result",
    method: "GET",
    pathTemplate: "/scans/{scanId}",
    description:
      "Status, verdict, findings, call timings and cost for one scan.",
    pathParam: {
      name: "scanId",
      label: "Scan id",
      placeholder: "scan id from POST /scan",
    },
  },
  {
    id: "batches",
    method: "POST",
    pathTemplate: "/batches",
    description:
      'Up to 50 URLs inline. For up to 1,000, send {"upload": true, "count": n, "source": "api"} and POST the CSV to the returned upload_url.',
    defaultBody: JSON.stringify(
      { urls: ["https://a.example", "https://b.example"] },
      null,
      2,
    ),
  },
  {
    id: "batch",
    method: "GET",
    pathTemplate: "/batches/{batchId}",
    description:
      "Counters, verdict mix, timings, cost and per-URL rows for a batch.",
    pathParam: {
      name: "batchId",
      label: "Batch id",
      placeholder: "batch id from POST /batches",
    },
  },
  {
    id: "listBatches",
    method: "GET",
    pathTemplate: "/batches",
    description: "Your batches, newest first.",
  },
  {
    id: "history",
    method: "GET",
    pathTemplate: "/history",
    description: "Your scans, newest first.",
  },
  {
    id: "stats",
    method: "GET",
    pathTemplate: "/stats?range=7d",
    description: "Totals, daily series, latency, model and AgentCore stats.",
  },
  {
    id: "feed",
    method: "GET",
    pathTemplate: "/feed/phishing?limit=5",
    description: "Live, pre-screened phishing URLs safe to scan.",
  },
];

/** The rendered result of one execution, including failures. */
interface RunOutcome {
  /** HTTP status, or null when the request never reached the server. */
  status: number | null;
  ok: boolean;
  ms: number;
  body: string;
}

/** Read a string field off an unknown JSON value without asserting `any`. */
function readString(value: unknown, key: string): string | undefined {
  if (value && typeof value === "object" && key in value) {
    const field = (value as Record<string, unknown>)[key];
    return typeof field === "string" ? field : undefined;
  }
  return undefined;
}

/** Path actually requested: the parameter is substituted and URL-encoded. */
function toRequestPath(ep: EndpointDef, paramValue: string): string {
  if (!ep.pathParam) return ep.pathTemplate;
  return ep.pathTemplate.replace(
    `{${ep.pathParam.name}}`,
    encodeURIComponent(paramValue.trim()),
  );
}

/** Path shown in the copyable command: readable, with a hint when empty. */
function toDisplayPath(ep: EndpointDef, paramValue: string): string {
  if (!ep.pathParam) return ep.pathTemplate;
  const shown = paramValue.trim() || `<${ep.pathParam.name}>`;
  return ep.pathTemplate.replace(`{${ep.pathParam.name}}`, shown);
}

/**
 * A reproducible command for outside the browser. IAM endpoints use awscurl so
 * the reader signs with their own credentials; /health is plain curl since it
 * is unauthenticated.
 */
function buildCommand(ep: EndpointDef, paramValue: string, bodyValue: string): string {
  const url = `${PLACEHOLDER_BASE}${toDisplayPath(ep, paramValue)}`;
  if (ep.id === "health") return `curl ${url}`;

  const parts = ["awscurl --service execute-api --region <region>"];
  if (ep.method === "POST") {
    parts.push("-X POST");
    parts.push("-H 'Content-Type: application/json'");
    // Collapse the pretty-printed body to a single line for a runnable command.
    const inline = bodyValue.replace(/\s*\n\s*/g, " ").trim();
    parts.push(`-d '${inline}'`);
  }
  parts.push(url);
  return parts.join(" \\\n  ");
}

interface EndpointCardProps {
  ep: EndpointDef;
  paramValue: string;
  bodyValue: string;
  outcome: RunOutcome | undefined;
  running: boolean;
  onParamChange: (value: string) => void;
  onBodyChange: (value: string) => void;
  onRun: () => void;
}

function EndpointCard({
  ep,
  paramValue,
  bodyValue,
  outcome,
  running,
  onParamChange,
  onBodyChange,
  onRun,
}: EndpointCardProps) {
  const [copied, setCopied] = useState(false);
  const command = buildCommand(ep, paramValue, bodyValue);
  const paramId = `${ep.id}-param`;
  const bodyId = `${ep.id}-body`;

  async function copyCommand() {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      // Revert the confirmation so the control is ready for the next copy.
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access can be blocked (permissions, insecure context); the
      // command stays visible for manual selection, so there is nothing to do.
      setCopied(false);
    }
  }

  return (
    <Card>
      <CardHeader className="flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <Badge tone={ep.method === "GET" ? "accent" : "warn"}>{ep.method}</Badge>
          <CardTitle className="truncate font-mono text-sm">{ep.pathTemplate}</CardTitle>
        </div>
        <Button
          size="sm"
          variant="primary"
          onClick={onRun}
          disabled={running}
          aria-label={`Run ${ep.method} ${ep.pathTemplate}`}
        >
          {running ? <Spinner className="h-4 w-4" /> : <Play className="h-4 w-4" />}
          {running ? "Running" : "Run"}
        </Button>
      </CardHeader>

      <CardBody className="space-y-4">
        <p className="text-sm text-fg-subtle">{ep.description}</p>

        {ep.pathParam && (
          <div className="space-y-1.5">
            <label htmlFor={paramId} className="text-xs font-medium text-fg-subtle">
              {ep.pathParam.label}
            </label>
            <Input
              id={paramId}
              value={paramValue}
              placeholder={ep.pathParam.placeholder}
              onChange={(e) => onParamChange(e.target.value)}
            />
          </div>
        )}

        {ep.method === "POST" && (
          <div className="space-y-1.5">
            <label htmlFor={bodyId} className="text-xs font-medium text-fg-subtle">
              Request body (JSON)
            </label>
            <textarea
              id={bodyId}
              value={bodyValue}
              spellCheck={false}
              onChange={(e) => onBodyChange(e.target.value)}
              className="h-28 w-full rounded-xl border border-border bg-surface px-3.5 py-2.5 font-mono text-xs text-fg placeholder:text-muted transition-colors focus-visible:border-accent"
            />
          </div>
        )}

        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-fg-subtle">Reproduce it</span>
            <Button
              size="sm"
              variant="ghost"
              onClick={copyCommand}
              aria-label={`Copy command for ${ep.method} ${ep.pathTemplate}`}
            >
              {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <pre className="max-h-32 overflow-auto rounded-xl border border-border bg-surface-2/50 p-3 font-mono text-xs leading-relaxed text-fg-subtle">
            {command}
          </pre>
        </div>

        {/* Announced politely so the outcome reaches assistive tech after a run
            without stealing focus from the button that triggered it. */}
        <div aria-live="polite">
          {outcome && (
            <div className="space-y-1.5">
              <div className="flex items-center gap-2 text-xs">
                <Badge tone={outcome.ok ? "safe" : "danger"}>
                  {outcome.status === null ? "no response" : `HTTP ${outcome.status}`}
                </Badge>
                <span className="text-muted">{outcome.ms} ms</span>
              </div>
              <pre className="max-h-72 overflow-auto rounded-xl border border-border bg-surface-2/50 p-3 font-mono text-xs leading-relaxed text-fg">
                {outcome.body}
              </pre>
            </div>
          )}
        </div>
      </CardBody>
    </Card>
  );
}

/** Build the initial per-endpoint body map from each POST endpoint's sample. */
function initialBodies(): Record<string, string> {
  const map: Record<string, string> = {};
  for (const ep of ENDPOINTS) {
    if (ep.defaultBody) map[ep.id] = ep.defaultBody;
  }
  return map;
}

export function ApiConsolePage() {
  const [params, setParams] = useState<Record<string, string>>({});
  const [bodies, setBodies] = useState<Record<string, string>>(initialBodies);
  const [outcomes, setOutcomes] = useState<Record<string, RunOutcome>>({});
  const [running, setRunning] = useState<Record<string, boolean>>({});

  async function runEndpoint(ep: EndpointDef) {
    setRunning((prev) => ({ ...prev, [ep.id]: true }));

    const init: RequestInit = { credentials: "same-origin" };
    if (ep.method === "POST") {
      init.method = "POST";
      init.headers = { "Content-Type": "application/json" };
      init.body = bodies[ep.id] ?? "";
    }

    const path = toRequestPath(ep, params[ep.id] ?? "");
    const started = performance.now();

    try {
      // Through the shared wrapper, not bare fetch: the POST endpoints below need
      // the x-amz-content-sha256 body digest that CloudFront Origin Access
      // Control requires, or they come back as an unexplained 403. See
      // lib/http.ts. GET endpoints are unaffected.
      const res = await fetchWithPayloadHash(`${API_PROXY_PREFIX}${path}`, init);
      const ms = Math.round(performance.now() - started);
      const text = await res.text();

      // Pretty-print when the body is JSON, otherwise show it verbatim so a
      // non-JSON error page or empty response is still readable rather than
      // throwing on parse.
      let parsed: unknown;
      let display = text;
      try {
        parsed = JSON.parse(text);
        display = JSON.stringify(parsed, null, 2);
      } catch {
        display = text || "(empty response body)";
      }

      setOutcomes((prev) => ({
        ...prev,
        [ep.id]: { status: res.status, ok: res.ok, ms, body: display },
      }));

      // On a successful async submit, carry the returned id into its poll input
      // so the flow can be demoed end to end without copy-paste.
      const rule = AUTO_FILL[ep.id];
      if (res.ok && rule) {
        const id = readString(parsed, rule.sourceKey);
        if (id) setParams((prev) => ({ ...prev, [rule.targetId]: id }));
      }
    } catch (err) {
      const ms = Math.round(performance.now() - started);
      const message = err instanceof Error ? err.message : String(err);
      setOutcomes((prev) => ({
        ...prev,
        [ep.id]: {
          status: null,
          ok: false,
          ms,
          body: `Network error, the request did not complete: ${message}`,
        },
      }));
    } finally {
      setRunning((prev) => ({ ...prev, [ep.id]: false }));
    }
  }

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <div className="flex items-center gap-2.5">
          <span className="inline-flex h-9 w-9 items-center justify-center rounded-xl bg-accent/15 text-accent">
            <Terminal className="h-5 w-5" />
          </span>
          <h1 className="text-2xl font-extrabold tracking-tight text-fg">API console</h1>
        </div>
        <p className="max-w-3xl text-sm text-fg-subtle">
          Requests are signed with AWS SigV4 server-side, so the browser never holds AWS
          credentials. A scan takes about 30 to 40 seconds, so POST /scan returns a scan_id to poll
          rather than a verdict.
        </p>
      </header>

      <div className="grid gap-4 lg:grid-cols-2">
        {ENDPOINTS.map((ep) => (
          <EndpointCard
            key={ep.id}
            ep={ep}
            paramValue={params[ep.id] ?? ""}
            bodyValue={bodies[ep.id] ?? ""}
            outcome={outcomes[ep.id]}
            running={Boolean(running[ep.id])}
            onParamChange={(value) => setParams((prev) => ({ ...prev, [ep.id]: value }))}
            onBodyChange={(value) => setBodies((prev) => ({ ...prev, [ep.id]: value }))}
            onRun={() => void runEndpoint(ep)}
          />
        ))}
      </div>
    </div>
  );
}
