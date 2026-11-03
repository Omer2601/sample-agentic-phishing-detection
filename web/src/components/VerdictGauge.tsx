// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { useEffect, useState } from "react";
import { scoreBand } from "@/lib/utils";

/**
 * A colour-banded radial gauge that makes the risk score readable at a glance.
 * The arc sweeps 240 degrees; the marker and the numeric read-out animate up
 * from zero on mount. Colour follows the risk band (safe/warn/danger).
 */
export function VerdictGauge({ score, size = 220 }: { score: number; size?: number }) {
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    let raf = 0;
    const start = performance.now();
    const duration = 900;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      // easeOutCubic
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(Math.round(eased * score));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [score]);

  const band = scoreBand(score);
  const bandColor = `rgb(var(--${band}))`;

  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2 - 18;
  const startAngle = 150; // degrees
  const sweep = 240;
  const valueAngle = startAngle + (sweep * display) / 100;

  const arcPath = (from: number, to: number) => describeArc(cx, cy, r, from, to);
  // A marker on the arc, not a needle from the centre: a needle ran straight
  // through the score read-out at most values.
  const marker = polar(cx, cy, r, valueAngle);

  return (
    <div className="relative inline-flex flex-col items-center" role="img" aria-label={`Risk score ${score} out of 100`}>
      <svg width={size} height={size * 0.78} viewBox={`0 0 ${size} ${size * 0.78}`}>
        {/* Track */}
        <path
          d={arcPath(startAngle, startAngle + sweep)}
          fill="none"
          stroke="rgb(var(--surface-2))"
          strokeWidth={14}
          strokeLinecap="round"
        />
        {/* Band segments: safe 0-35, warn 35-70, danger 70-100 */}
        <path d={arcPath(startAngle, startAngle + sweep * 0.35)} fill="none" stroke="rgb(var(--safe))" strokeWidth={14} strokeLinecap="round" opacity={0.28} />
        <path d={arcPath(startAngle + sweep * 0.35, startAngle + sweep * 0.7)} fill="none" stroke="rgb(var(--warn))" strokeWidth={14} strokeLinecap="round" opacity={0.28} />
        <path d={arcPath(startAngle + sweep * 0.7, startAngle + sweep)} fill="none" stroke="rgb(var(--danger))" strokeWidth={14} strokeLinecap="round" opacity={0.28} />
        {/* Value arc */}
        <path
          d={arcPath(startAngle, valueAngle)}
          fill="none"
          stroke={bandColor}
          strokeWidth={14}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 6px ${bandColor})` }}
        />
        <circle cx={marker.x} cy={marker.y} r={9} fill={bandColor} stroke="rgb(var(--surface))" strokeWidth={3} />
      </svg>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center" style={{ top: "18%" }}>
        <span className="text-5xl font-extrabold tabular-nums text-fg" style={{ color: bandColor }}>
          {display}
        </span>
        <span className="text-xs font-medium uppercase tracking-widest text-muted">/ 100 risk</span>
      </div>
    </div>
  );
}

function polar(cx: number, cy: number, r: number, angleDeg: number) {
  const a = (angleDeg * Math.PI) / 180;
  return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
}

function describeArc(cx: number, cy: number, r: number, startDeg: number, endDeg: number) {
  const start = polar(cx, cy, r, startDeg);
  const end = polar(cx, cy, r, endDeg);
  const largeArc = endDeg - startDeg <= 180 ? 0 : 1;
  return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 1 ${end.x} ${end.y}`;
}
