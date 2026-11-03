// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import type { InputHTMLAttributes } from "react";
import { Input } from "@/components/ui";
import { cn } from "@/lib/utils";
import { fieldElementId } from "./fieldIds";

/**
 * The labelled input the registration form is built from.
 *
 * They exist so the accessibility wiring is written once and cannot drift
 * between fields: a real <label htmlFor>, aria-invalid while the field is in
 * error, and an aria-describedby that stitches together the error text and any
 * extra description instead of one overwriting the other. The visible focus ring comes from the global :focus-visible rule in
 * index.css, so it matches the rest of the app.
 *
 * The element ids come from fieldIds.ts, which the page also uses to move focus
 * to the first field in error after a failed submit.
 */

type NativeProps = Omit<
  InputHTMLAttributes<HTMLInputElement>,
  "id" | "aria-invalid" | "aria-describedby" | "className"
>;

interface FieldProps extends NativeProps {
  /** Field name; also the source of the element id. */
  name: string;
  label: string;
  /** Message rendered under the input; also flips the field into the error style. */
  error?: string | null;
  /** Id of an extra element describing the field. */
  describedBy?: string;
}

function ErrorText({ id, children }: { id: string; children: string }) {
  // No role="alert" here. On submit the page moves focus to the first field in
  // error, which makes the screen reader read this text as that field's
  // description, and the form's single aria-live region announces the result.
  // An alert role as well would announce the same failure twice.
  return (
    <p id={id} className="mt-1.5 text-xs font-medium text-danger">
      {children}
    </p>
  );
}

const labelClass = "mb-1.5 block text-sm font-medium text-fg";
const errorInputClass = "border-danger focus-visible:border-danger";

export function TextField({ label, error, describedBy, name, ...props }: FieldProps) {
  const id = fieldElementId(name);
  const errorId = `${id}-error`;
  const described = [error ? errorId : null, describedBy].filter(Boolean).join(" ");
  return (
    <div>
      <label htmlFor={id} className={labelClass}>
        {label}
      </label>
      <Input
        id={id}
        name={name}
        aria-invalid={Boolean(error)}
        aria-describedby={described || undefined}
        className={cn(error && errorInputClass)}
        {...props}
      />
      {error ? <ErrorText id={errorId}>{error}</ErrorText> : null}
    </div>
  );
}
