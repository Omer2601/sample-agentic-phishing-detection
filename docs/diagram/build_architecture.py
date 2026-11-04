# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Generate docs/architecture.drawio from a layout spec.

Coordinates are absolute and on a strict grid. Every edge has explicit ports and waypoints and
edgeStyle=none, so validate_diagram.py checks exactly what draw.io draws. Labels sit under icons
(above for LABEL_TOP), so edges leave icons from the other sides. Edit the tables, then run:
  uv run python docs/diagram/build_architecture.py
  uv run --with defusedxml==0.7.1 python docs/diagram/validate_diagram.py docs/architecture.drawio
"""

from pathlib import Path

# The diagram is written by the small serializer below rather than xml.etree: this script
# only emits XML built from the tables in this file and never parses any, and keeping the
# stdlib XML package out entirely means no parser that could expand entities is even
# importable here. validate_diagram.py reads the file back with defusedxml.
ATTR_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "\n": "&#10;"}
ATTR_ESCAPES |= {"\r": "&#13;", "\t": "&#09;"}


class Element:
    """An XML element with attributes and children, serialized like ElementTree does."""

    def __init__(self, tag: str, /, **attrib: str) -> None:
        self.tag, self.attrib, self.children = tag, attrib, []

    def to_xml(self, depth: int = 0) -> str:
        pad = "  " * depth
        attrs = "".join(
            f' {k}="{"".join(ATTR_ESCAPES.get(c, c) for c in v)}"' for k, v in self.attrib.items()
        )
        if not self.children:
            return f"{pad}<{self.tag}{attrs} />"
        inner = "\n".join(child.to_xml(depth + 1) for child in self.children)
        return f"{pad}<{self.tag}{attrs}>\n{inner}\n{pad}</{self.tag}>"


def SubElement(parent: Element, tag: str, /, **attrib: str) -> Element:  # noqa: N802 - ET name
    child = Element(tag, **attrib)
    parent.children.append(child)
    return child


OUT = Path(__file__).resolve().parents[1] / "architecture.drawio"
ICON = 64
INK = "#232F3E"
# The README shows the PNG about 900 px wide, so text is large on this canvas.
FONT, EDGE_FONT, GROUP_FONT = 16, 15, 18

# AWS Architecture Icons 07312026 category colors.
COLOR = {
    "compute": "#ED7100",
    "storage": "#7AA116",
    "database": "#C925D1",
    "integration": "#E7157B",
    "networking": "#8C4FFF",
    "ml": "#01A88D",
}

# Default deploy only (all latency flags on, agentRegistry=false, webSearch=true,
# browserSigning=false, episodicMemory=true). Strict grid: one column pitch, icons centered on
# column lines. Row 1 is the request path. The worker sits above the pre-check tools server, so
# the pre-check drops straight down; its two other lines leave downwards into their own lanes:
# one to the specialists box, one to the orchestrator model. Every explanation lives in the
# numbered steps in docs/architecture.md, so line labels stay at three words or fewer.
PITCH = 220
COL = [120 + i * PITCH for i in range(7)]  # icon centers
ROW1 = 80  # request path icon tops
SPEC_PITCH = 140  # vertical pitch of the three specialists
ROWM = 470  # middle specialist icon top
ROW_UP, ROW_DOWN = ROWM - SPEC_PITCH, ROWM + SPEC_PITCH  # url_analyst, code_analyst
SUPPORT = 850
LANE_TOP = ROW1 - 35  # the direct API client line
LANE_MODEL = 210  # the worker to orchestrator model line
LANE_SPEC = 268  # the worker to specialists line
BROWSER_X = COL[6] - 60  # the three capture lines turn down or up here
PAGE_W, PAGE_H = 1560, 1070
GROUP_W = PAGE_W - 40
SUP_PITCH = 190  # eight supporting services share the row
SUP = [120 + i * SUP_PITCH for i in range(8)]


def at(col: int) -> int:
    """Icon left edge for a column."""
    return COL[col] - ICON // 2


def sup(i: int) -> int:
    """Icon left edge for a supporting services slot."""
    return SUP[i] - ICON // 2


# (label, x, y, w, h, border color, label align). Labels sit at the bottom.
GROUPS = [
    ("The scan: Amazon Bedrock and AgentCore", 20, 245, GROUP_W, 530, "#01A88D", "right"),
    ("Supporting services (no lines)", 20, 820, GROUP_W, 190, "#7D8998", "left"),
]

# Plain box drawn behind the specialist icons: (id, label, x, y, w, h).
BOX_W = 190
BOX = (COL[2] - BOX_W // 2, ROW_UP - 38, BOX_W, 2 * SPEC_PITCH + ICON + 38 + 34)
BOXES = [("specialists", "3 specialists (Sonnet)", *BOX)]

# id: (label, resIcon, category, x, y). "user" is the general user shape. Two lines at most.
NODES = {
    "client": ("Users and\nAPI clients", "user", "", at(0), ROW1),
    "cf": ("CloudFront\n+ AWS WAF", "cloudfront", "networking", at(1), ROW1),
    "api": ("API Gateway\n+ Lambda (API)", "api_gateway", "integration", at(2), ROW1),
    "sqs": ("Amazon SQS\nscan queue", "sqs", "integration", at(4), ROW1),
    "worker": ("AWS Lambda\nworker", "lambda", "compute", at(5), ROW1),
    "model": ("Amazon Bedrock\norchestrator (Opus)", "bedrock", "ml", at(0), ROWM),
    "rt_url": ("url_analyst\n(RDAP in process)", "bedrock_agentcore", "ml", at(2), ROW_UP),
    "rt_brand": ("brand_visual", "bedrock_agentcore", "ml", at(2), ROWM),
    "rt_code": ("code_analyst", "bedrock_agentcore", "ml", at(2), ROW_DOWN),
    "tools_pre": ("tools server\n(pre-check)", "bedrock_agentcore", "ml", at(5), ROW_UP),
    "tools_brand": ("tools server\n(brand copy)", "bedrock_agentcore", "ml", at(4), ROWM),
    "tools_code": ("tools server\n(code copy)", "bedrock_agentcore", "ml", at(4), ROW_DOWN),
    "browser": ("AgentCore\nBrowser", "bedrock_agentcore", "ml", at(6), ROWM),
    # Supporting services: no lines; the steps in docs/architecture.md say who uses each.
    "ddb": ("DynamoDB\nscans", "dynamodb", "database", sup(0), SUPPORT),
    "artifacts": ("Amazon S3\nartifacts", "s3", "storage", sup(1), SUPPORT),
    "cache": ("DynamoDB\nresult cache", "dynamodb", "database", sup(2), SUPPORT),
    "memory": ("AgentCore\nMemory", "bedrock_agentcore", "ml", sup(3), SUPPORT),
    "guardrails": ("Bedrock\nGuardrails", "bedrock", "ml", sup(4), SUPPORT),
    "websearch": ("AgentCore\nWeb Search", "bedrock_agentcore", "ml", sup(5), SUPPORT),
    "harness": ("Harness path\n(standby)", "bedrock_agentcore", "ml", sup(6), SUPPORT),
    "registry": ("Agent Registry\n(opt-in, off)", "bedrock_agentcore", "ml", sup(7), SUPPORT),
}
# Lines leave these icons downwards, so their labels sit above.
LABEL_TOP = {"worker"}

# Plain text, no border, not an obstacle: (id, text, x, y, w, h). The legend.
TEXTS = [
    (
        "footer",
        "Solid lines: the scan path, numbered in order (docs/architecture.md explains each "
        "step). Bottom row: off the path, no lines. Harness path: AgentCore Harness, the "
        "dispatcher and both Gateways, used with -c directOrchestration=false.\n"
        "Agent Registry is deployed only with -c agentRegistry=true. Every AWS call is signed "
        "with SigV4.",
        20,
        1018,
        GROUP_W,
        44,
    ),
]

# id: (source, target, exit (x, y), entry (x, y), waypoints, label[, "dashed"][, label position])
# The label position runs from -1 (source) to 1 (target); the default 0 is the middle.
EDGES = {
    "client_cf": ("client", "cf", (1, 0.5), (0, 0.5), [], "1 HTTPS"),
    "client_api": (
        "client",
        "api",
        (0.5, 0),
        (0.5, 0),
        [(COL[0], LANE_TOP), (COL[2], LANE_TOP)],
        "1 SigV4",
    ),
    "cf_api": ("cf", "api", (1, 0.5), (0, 0.5), [], "SigV4"),
    "api_sqs": ("api", "sqs", (1, 0.5), (0, 0.5), [], "2 enqueue"),
    "sqs_worker": ("sqs", "worker", (1, 0.5), (0, 0.5), [], "2 trigger"),
    "worker_precheck": ("worker", "tools_pre", (0.75, 1), (0.75, 0), [], "3 pre-check", 0.6),
    "worker_specs": (
        "worker",
        "specialists",
        (0.5, 1),
        (0.5, 0),
        [(COL[5], LANE_SPEC), (COL[2], LANE_SPEC)],
        "3 in parallel",
    ),
    "brand_tools": ("rt_brand", "tools_brand", (1, 0.5), (0, 0.5), [], "4 capture"),
    "code_tools": ("rt_code", "tools_code", (1, 0.5), (0, 0.5), [], "4 capture"),
    "pre_browser": (
        "tools_pre",
        "browser",
        (1, 0.5),
        (0, 0.25),
        [(BROWSER_X, ROW_UP + ICON / 2), (BROWSER_X, ROWM + ICON / 4)],
        "",
    ),
    "brand_browser": ("tools_brand", "browser", (1, 0.5), (0, 0.5), [], "5 browse", -0.4),
    "code_browser": (
        "tools_code",
        "browser",
        (1, 0.5),
        (0, 0.75),
        [(BROWSER_X + 20, ROW_DOWN + ICON / 2), (BROWSER_X + 20, ROWM + 3 * ICON / 4)],
        "",
    ),
    "worker_model": (
        "worker",
        "model",
        (0.25, 1),
        (0.5, 0),
        [(COL[5] - ICON / 4, LANE_MODEL), (COL[0], LANE_MODEL)],
        "6 verdict, report",
    ),
}

LABEL = f"align=center;html=0;fontSize={FONT};fontColor={INK};whiteSpace=nowrap;"
LABEL_BELOW = "verticalLabelPosition=bottom;verticalAlign=top;" + LABEL
LABEL_ABOVE = "verticalLabelPosition=top;verticalAlign=bottom;" + LABEL


def icon_style(cid: str, icon: str, category: str) -> str:
    label = LABEL_ABOVE if cid in LABEL_TOP else LABEL_BELOW
    if icon == "user":
        return f"shape=mxgraph.aws4.user;fillColor={INK};strokeColor=none;aspect=fixed;" + label
    return (
        f"shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.{icon};fillColor={COLOR[category]};"
        "strokeColor=#ffffff;outlineConnect=0;aspect=fixed;" + label
    )


def _cell(root: Element, cid: str, value: str, style: str, x: int, y: int, w: int, h: int) -> None:
    cell = SubElement(root, "mxCell", id=cid, value=value, vertex="1", parent="1", style=style)
    SubElement(
        cell, "mxGeometry", x=str(x), y=str(y), width=str(w), height=str(h), **{"as": "geometry"}
    )


def _edge(root: Element, cid: str, spec: tuple) -> None:
    src, tgt, (ex, ey), (nx, ny), points, label, *extra = spec
    style = (
        "edgeStyle=none;rounded=0;html=0;endArrow=block;endFill=1;strokeColor=#545B64;"
        f"strokeWidth=2;exitX={ex};exitY={ey};exitDx=0;exitDy=0;"
        f"entryX={nx};entryY={ny};entryDx=0;entryDy=0;"
        f"fontSize={EDGE_FONT};fontColor={INK};labelBackgroundColor=#ffffff;"
        + ("dashed=1;dashPattern=6 4;" if "dashed" in extra else "")
    )
    cell = SubElement(
        root,
        "mxCell",
        id=cid,
        value=label,
        edge="1",
        parent="1",
        source=src,
        target=tgt,
        style=style,
    )
    pos = [str(e) for e in extra if isinstance(e, float)]
    geo = SubElement(
        cell, "mxGeometry", relative="1", **({"x": pos[0]} if pos else {}), **{"as": "geometry"}
    )
    if points:
        arr = SubElement(geo, "Array", **{"as": "points"})
        for x, y in points:
            SubElement(arr, "mxPoint", x=str(x), y=str(y))


def build() -> Element:
    mxfile = Element("mxfile", host="drawio", compressed="false")
    diagram = SubElement(mxfile, "diagram", id="architecture", name="Architecture")
    model = SubElement(
        diagram,
        "mxGraphModel",
        dx=str(PAGE_W),
        dy=str(PAGE_H),
        grid="1",
        gridSize="10",
        page="1",
        pageWidth=str(PAGE_W),
        pageHeight=str(PAGE_H),
        background="#FFFFFF",
    )
    root = SubElement(model, "root")
    SubElement(root, "mxCell", id="0")
    SubElement(root, "mxCell", id="1", parent="0")

    for i, (label, x, y, w, h, color, *opt) in enumerate(GROUPS):
        _cell(
            root,
            f"group{i}",
            label,
            (
                "rounded=0;dashed=1;dashPattern=4 4;fillColor=none;"
                f"strokeColor={color};strokeWidth=2;verticalAlign=bottom;"
                f"align={opt[0] if opt else 'left'};fontSize={GROUP_FONT};fontStyle=1;"
                f"fontColor={color};spacingLeft=10;spacingRight=10;spacingBottom=4;"
            ),
            x,
            y,
            w,
            h,
        )

    for cid, label, x, y, w, h in BOXES:
        _cell(
            root,
            cid,
            label,
            (
                "rounded=1;arcSize=4;fillColor=#F2FBF9;strokeColor=#01A88D;strokeWidth=1;"
                f"verticalAlign=top;align=center;fontSize={FONT};fontStyle=1;fontColor=#01A88D;"
                "spacingTop=4;"
            ),
            x,
            y,
            w,
            h,
        )

    for cid, (label, icon, category, x, y) in NODES.items():
        _cell(root, cid, label, icon_style(cid, icon, category), x, y, ICON, ICON)

    for cid, text, x, y, w, h in TEXTS:
        _cell(
            root,
            cid,
            text,
            (
                f"text;html=0;fillColor=none;strokeColor=none;fontSize={FONT - 2};"
                f"fontColor={INK};align=left;verticalAlign=top;whiteSpace=wrap;"
            ),
            x,
            y,
            w,
            h,
        )

    for cid, spec in EDGES.items():
        _edge(root, cid, spec)
    return mxfile


if __name__ == "__main__":
    OUT.write_text(build().to_xml(), encoding="utf-8")
    print(f"wrote {OUT}")
