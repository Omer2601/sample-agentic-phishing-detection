// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useState, type FormEvent } from "react";
import { Search, ArrowRight } from "lucide-react";
import { validateUrl, normalizeUrl, cn } from "@/lib/utils";
import { Button, Card, CardBody, Input } from "./ui";
import { LiveTargetPicker } from "./LiveTargetPicker";

export function ScanForm({ onSubmit, disabled }: { onSubmit: (url: string) => void; disabled?: boolean }) {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);

  const submit = (raw: string) => {
    const err = validateUrl(raw);
    setTouched(true);
    setError(err);
    if (!err) onSubmit(normalizeUrl(raw));
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    submit(value);
  };

  return (
    <Card>
      <CardBody>
        <form onSubmit={handleSubmit} noValidate>
          <label htmlFor="scan-url" className="text-sm font-semibold text-fg">
            Analyse a URL
          </label>
          <p className="mt-1 text-sm text-fg-subtle">
            Submit a suspicious link. It is rendered in an isolated browser and checked by three specialist agents in parallel.
          </p>

          <div className="mt-4 flex flex-col gap-2 sm:flex-row">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <Input
                id="scan-url"
                type="url"
                inputMode="url"
                autoComplete="off"
                placeholder="paypal-secure-login.example/verify"
                className={cn("pl-10", touched && error && "border-danger focus-visible:border-danger")}
                value={value}
                disabled={disabled}
                aria-invalid={Boolean(touched && error)}
                aria-describedby={error ? "scan-url-error" : undefined}
                onChange={(e) => {
                  setValue(e.target.value);
                  if (touched) setError(validateUrl(e.target.value));
                }}
              />
            </div>
            <Button type="submit" size="lg" disabled={disabled} className="sm:w-auto">
              Scan
              <ArrowRight className="h-4 w-4" />
            </Button>
          </div>

          {touched && error ? (
            <p id="scan-url-error" className="mt-2 text-xs text-danger" role="alert">
              {error}
            </p>
          ) : (
            <p className="mt-2 text-xs text-muted">
              A full scan takes about 30 to 40 seconds. https:// is added automatically if omitted.
            </p>
          )}
        </form>

        {/* Two ways to pick a target without typing: a dropdown and a suggestions
            strip, both backed by the live threat feed. See LiveTargetPicker. */}
        <LiveTargetPicker
          disabled={disabled}
          onPick={(url) => {
            setValue(url);
            setError(null);
            setTouched(false);
            onSubmit(normalizeUrl(url));
          }}
        />
      </CardBody>
    </Card>
  );
}
