# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Reject a diagram with a diagonal line, a crossing, an overlap, a line through an icon or a
long label (a line label over 3 words plus a step number, an icon label over 2 lines).

Edges must use edgeStyle=none with explicit exit and entry ports and explicit waypoints,
so the geometry checked here is exactly the geometry draw.io renders.
"""

import sys
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path

# defusedxml: the diagram is a repo file, but a stdlib parser would also expand external entities.
import defusedxml.ElementTree as ET

TOL = 0.5
Point = tuple[float, float]
PORTS = ("exitX", "exitY", "entryX", "entryY")
MAX_EDGE_WORDS, MAX_ICON_LINES = 3, 2


@dataclass(frozen=True)
class Rect:
    x: float
    y: float
    w: float
    h: float


@dataclass(frozen=True)
class Segment:
    edge: str
    a: Point
    b: Point

    @property
    def horizontal(self) -> bool:
        return abs(self.a[1] - self.b[1]) <= TOL

    @property
    def vertical(self) -> bool:
        return abs(self.a[0] - self.b[0]) <= TOL


def _style(raw: str | None) -> dict[str, str]:
    return dict(kv.split("=", 1) for kv in (raw or "").split(";") if "=" in kv)


def _between(value: float, lo: float, hi: float) -> bool:
    lo, hi = min(lo, hi), max(lo, hi)
    return lo + TOL < value < hi - TOL


def _overlap(a1: float, a2: float, b1: float, b2: float) -> float:
    return min(max(a1, a2), max(b1, b2)) - max(min(a1, a2), min(b1, b2))


def _is_icon(style: dict[str, str]) -> bool:
    # obstacle=1 marks non-AWS shapes (step markers, external boxes) that lines must avoid.
    if style.get("obstacle") == "1":
        return True
    return any(k in style for k in ("resIcon", "image")) or style.get("shape", "").startswith(
        "mxgraph.aws4"
    )


def _crossings(segments: list[Segment]) -> list[str]:
    errors: list[str] = []
    for s1, s2 in combinations(segments, 2):
        if s1.edge == s2.edge:
            continue
        if (s1.horizontal and s2.vertical) or (s1.vertical and s2.horizontal):
            h, vv = (s1, s2) if s1.horizontal else (s2, s1)
            x, y = vv.a[0], h.a[1]
            if _between(x, h.a[0], h.b[0]) and _between(y, vv.a[1], vv.b[1]):
                errors.append(f"edges {s1.edge} and {s2.edge} cross at ({x:.0f}, {y:.0f})")
        elif s1.horizontal and s2.horizontal and abs(s1.a[1] - s2.a[1]) <= TOL:
            if _overlap(s1.a[0], s1.b[0], s2.a[0], s2.b[0]) > TOL:
                errors.append(f"edges {s1.edge} and {s2.edge} overlap on y={s1.a[1]:.0f}")
        elif s1.vertical and s2.vertical and abs(s1.a[0] - s2.a[0]) <= TOL:
            if _overlap(s1.a[1], s1.b[1], s2.a[1], s2.b[1]) > TOL:
                errors.append(f"edges {s1.edge} and {s2.edge} overlap on x={s1.a[0]:.0f}")
    return errors


def _labels(cells: list, icons: set[str]) -> list[str]:
    """Line labels: one line, a step number plus at most 3 words. Icon labels: 2 lines at most."""
    errors: list[str] = []
    for c in cells:
        cid, value = c.get("id"), c.get("value") or ""
        if c.get("edge") == "1":
            words = value.split()
            if words and words[0][0].isdigit():
                words = words[1:]
            if "\n" in value or len(words) > MAX_EDGE_WORDS:
                errors.append(f"edge {cid}: label {value!r} is longer than {MAX_EDGE_WORDS} words")
        elif cid in icons and value.count("\n") >= MAX_ICON_LINES:
            errors.append(f"icon {cid}: label has more than {MAX_ICON_LINES} lines")
    return errors


def _through_icons(
    segments: list[Segment],
    rects: dict[str, Rect],
    icons: set[str],
    endpoints: dict[str, tuple[str, str]],
) -> list[str]:
    errors: list[str] = []
    for seg in segments:
        for icon in sorted(icons - set(endpoints[seg.edge])):
            r = rects[icon]
            if seg.horizontal and _between(seg.a[1], r.y, r.y + r.h):
                hit = _overlap(seg.a[0], seg.b[0], r.x, r.x + r.w) > TOL
            elif seg.vertical and _between(seg.a[0], r.x, r.x + r.w):
                hit = _overlap(seg.a[1], seg.b[1], r.y, r.y + r.h) > TOL
            else:
                hit = False
            if hit:
                errors.append(f"edge {seg.edge}: passes through icon {icon}")
    return errors


def validate(path: Path) -> list[str]:
    root = ET.parse(path).getroot()
    cells = list(root.iter("mxCell"))
    if not cells:
        return [f"{path}: no mxCell elements; save the file uncompressed"]
    by_id = {c.get("id"): c for c in cells}

    rects: dict[str, Rect] = {}
    icons: set[str] = set()
    for c in cells:
        if c.get("vertex") != "1":
            continue
        parent = by_id.get(c.get("parent"))
        if parent is not None and parent.get("vertex") == "1":
            return [
                f"vertex {c.get('id')}: nested vertices are not supported; use absolute coordinates"
            ]
        g = c.find("mxGeometry")
        rects[c.get("id")] = Rect(*(float(g.get(k, 0)) for k in ("x", "y", "width", "height")))
        if _is_icon(_style(c.get("style"))):
            icons.add(c.get("id"))

    errors: list[str] = []
    segments: list[Segment] = []
    endpoints: dict[str, tuple[str, str]] = {}
    for c in cells:
        if c.get("edge") != "1":
            continue
        cid, style = c.get("id"), _style(c.get("style"))
        if style.get("edgeStyle", "none") != "none":
            errors.append(f"edge {cid}: edgeStyle must be none so waypoints are the rendered route")
            continue
        src, tgt = c.get("source"), c.get("target")
        if src not in rects or tgt not in rects or any(p not in style for p in PORTS):
            errors.append(f"edge {cid}: needs a source, a target and explicit {', '.join(PORTS)}")
            continue
        s, t = rects[src], rects[tgt]
        pts: list[Point] = [(s.x + s.w * float(style["exitX"]), s.y + s.h * float(style["exitY"]))]
        pts += [
            (float(p.get("x", 0)), float(p.get("y", 0)))
            for p in c.findall("mxGeometry/Array/mxPoint")
        ]
        pts.append((t.x + t.w * float(style["entryX"]), t.y + t.h * float(style["entryY"])))
        endpoints[cid] = (src, tgt)
        for a, b in zip(pts, pts[1:], strict=False):
            seg = Segment(cid, a, b)
            if not (seg.horizontal or seg.vertical):
                errors.append(f"edge {cid}: segment {a} -> {b} is not orthogonal")
            segments.append(seg)

    errors += _labels(cells, icons)
    errors += _crossings(segments)
    errors += _through_icons(segments, rects, icons, endpoints)
    return errors


if __name__ == "__main__":
    problems = validate(Path(sys.argv[1]))
    for p in problems:
        print(p)
    print(f"{len(problems)} problem(s)")
    sys.exit(1 if problems else 0)
