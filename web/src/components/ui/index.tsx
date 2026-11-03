// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import {
  forwardRef,
  useEffect,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type CSSProperties,
  type HTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
} from "react";
import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

/* ---- Button -------------------------------------------------------------- */

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "outline";
type ButtonSize = "sm" | "md" | "lg" | "icon";

const buttonVariants: Record<ButtonVariant, string> = {
  primary:
    "bg-accent text-white hover:brightness-110 shadow-xs shadow-accent/30 border border-transparent",
  secondary: "bg-surface-2 text-fg hover:bg-surface-2/70 border border-border",
  ghost:
    "bg-transparent text-fg-subtle hover:bg-surface-2 hover:text-fg border border-transparent",
  danger: "bg-danger text-white hover:brightness-110 border border-transparent",
  outline: "bg-transparent text-fg border border-border hover:bg-surface-2",
};

const buttonSizes: Record<ButtonSize, string> = {
  sm: "h-8 px-3 text-xs gap-1.5",
  md: "h-10 px-4 text-sm gap-2",
  lg: "h-12 px-6 text-base gap-2",
  icon: "h-10 w-10 justify-center",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "primary", size = "md", ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        "inline-flex items-center rounded-xl font-medium transition-all duration-150",
        "disabled:pointer-events-none disabled:opacity-50 select-none",
        buttonVariants[variant],
        buttonSizes[size],
        className,
      )}
      {...props}
    />
  ),
);
Button.displayName = "Button";

/* ---- Card ---------------------------------------------------------------- */

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("card", className)} {...props} />;
}

export function CardHeader({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-5 pb-0", className)} {...props} />;
}

export function CardTitle({
  className,
  ...props
}: HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3
      className={cn("text-sm font-semibold tracking-tight text-fg", className)}
      {...props}
    />
  );
}

export function CardBody({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-4 sm:p-5", className)} {...props} />;
}

/* ---- Badge --------------------------------------------------------------- */

type BadgeTone = "neutral" | "danger" | "warn" | "safe" | "accent";

const badgeTones: Record<BadgeTone, string> = {
  neutral: "bg-surface-2 text-fg-subtle border-border",
  danger: "bg-danger/15 text-danger border-danger/30",
  warn: "bg-warn/15 text-warn border-warn/30",
  safe: "bg-safe/15 text-safe border-safe/30",
  accent: "bg-accent/15 text-accent border-accent/30",
};

export function Badge({
  tone = "neutral",
  className,
  children,
}: {
  tone?: BadgeTone;
  className?: string;
  children: ReactNode;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        badgeTones[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

/* ---- Input --------------------------------------------------------------- */

export const Input = forwardRef<
  HTMLInputElement,
  InputHTMLAttributes<HTMLInputElement>
>(({ className, ...props }, ref) => (
  <input
    ref={ref}
    className={cn(
      "h-11 w-full rounded-xl border border-border bg-surface px-3.5 text-sm text-fg",
      "placeholder:text-muted transition-colors",
      "focus-visible:border-accent",
      "disabled:cursor-not-allowed disabled:opacity-50",
      className,
    )}
    {...props}
  />
));
Input.displayName = "Input";

/* ---- Progress ------------------------------------------------------------ */

export function Progress({
  value,
  tone = "accent",
  className,
}: {
  value: number; // 0..1
  tone?: BadgeTone;
  className?: string;
}) {
  const fill: Record<BadgeTone, string> = {
    neutral: "bg-muted",
    danger: "bg-danger",
    warn: "bg-warn",
    safe: "bg-safe",
    accent: "bg-accent",
  };
  return (
    <div
      className={cn(
        "h-2 w-full overflow-hidden rounded-full bg-surface-2",
        className,
      )}
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(value * 100)}
    >
      <div
        className={cn(
          "h-full rounded-full transition-[width] duration-500 ease-out",
          fill[tone],
        )}
        style={{ width: `${Math.min(100, Math.max(0, value * 100))}%` }}
      />
    </div>
  );
}

/* ---- Spinner & Skeleton -------------------------------------------------- */

export function Spinner({ className }: { className?: string }) {
  return (
    <svg
      className={cn("animate-spin text-accent", className)}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle
        className="opacity-20"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-90"
        fill="currentColor"
        d="M4 12a8 8 0 0 1 8-8v4a4 4 0 0 0-4 4H4z"
      />
    </svg>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("skeleton", className)} />;
}

/* ---- Collapsible --------------------------------------------------------- */

/**
 * Disclosure section built on native <details>/<summary>. Native is chosen over
 * a hand-rolled ARIA widget because the browser already gives correct keyboard
 * toggling and screen-reader semantics for free. The verbose parts of a scan
 * report default to closed so the analysis, not the prose, leads the page.
 *
 * The chevron rotates via the `[open]` state of the parent details element, so
 * the icon tracks the real disclosure state rather than a React mirror of it.
 */
export function Collapsible({
  title,
  subtitle,
  defaultOpen = false,
  badge,
  children,
}: {
  title: string;
  subtitle?: string;
  defaultOpen?: boolean;
  badge?: ReactNode;
  children: ReactNode;
}) {
  return (
    <details
      open={defaultOpen}
      className="rounded-xl border border-border bg-surface-2/40 [&[open]>summary_svg]:rotate-90"
    >
      <summary
        className={cn(
          "flex cursor-pointer select-none items-center gap-3 rounded-xl px-4 py-3",
          "focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-accent/40",
          // Strip the platform disclosure triangle so the custom chevron is the
          // only affordance shown.
          "list-none [&::-webkit-details-marker]:hidden",
        )}
      >
        <ChevronRight
          className="h-4 w-4 shrink-0 text-fg-subtle transition-transform duration-150"
          aria-hidden="true"
        />
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-semibold text-fg">{title}</span>
          {subtitle ? (
            <span className="mt-0.5 block text-xs text-fg-subtle">
              {subtitle}
            </span>
          ) : null}
        </span>
        {badge ? <span className="ml-auto shrink-0">{badge}</span> : null}
      </summary>
      <div className="px-3 pb-3 pt-1 sm:px-4 sm:pb-4">{children}</div>
    </details>
  );
}

/* ---- Clamp --------------------------------------------------------------- */

/**
 * Clamps text to `lines` and reveals a Show more/less toggle ONLY when the
 * content actually overflows, so a short finding never gets a pointless toggle.
 * Overflow is measured (scrollHeight vs clientHeight) under a ResizeObserver
 * because the wrapped line count depends on the available width, which changes
 * with layout and viewport.
 *
 * The clamp is applied as an inline style rather than a Tailwind line-clamp
 * class because `lines` is a runtime prop and Tailwind only emits classes it can
 * discover statically in the source; the inline rule is the same mechanism the
 * utility compiles to.
 */
export function Clamp({
  lines = 6,
  children,
}: {
  lines?: number;
  children: ReactNode;
}) {
  const [expanded, setExpanded] = useState(false);
  const [overflows, setOverflows] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const measure = () => {
      // Overflow is only measurable while clamped. Once expanded the element
      // grows to fit its content, so skip measuring and keep the last known
      // result rather than clearing it and hiding the "Show less" control.
      if (expanded) return;
      setOverflows(el.scrollHeight > el.clientHeight + 1);
    };
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    measure();
    return () => observer.disconnect();
  }, [children, expanded, lines]);

  const clampStyle: CSSProperties | undefined = expanded
    ? undefined
    : {
        display: "-webkit-box",
        WebkitBoxOrient: "vertical",
        WebkitLineClamp: lines,
        overflow: "hidden",
      };

  return (
    <div>
      <div ref={ref} style={clampStyle}>
        {children}
      </div>
      {overflows ? (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="mt-1.5 text-xs font-medium text-accent hover:underline"
          aria-expanded={expanded}
        >
          {expanded ? "Show less" : "Show more"}
        </button>
      ) : null}
    </div>
  );
}
