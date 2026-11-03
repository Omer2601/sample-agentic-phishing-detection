# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from pathlib import Path

import pytest

from docs.diagram.validate_diagram import validate

ICON = "shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.lambda;"


def diagram(tmp_path: Path, vertices: str, edges: str) -> Path:
    path = tmp_path / "d.drawio"
    path.write_text(
        '<mxfile><diagram><mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
        f"{vertices}{edges}</root></mxGraphModel></diagram></mxfile>"
    )
    return path


def v(cid: str, x: int, y: int) -> str:
    return (
        f'<mxCell id="{cid}" value="{cid}" style="{ICON}" vertex="1" parent="1">'
        f'<mxGeometry x="{x}" y="{y}" width="64" height="64" as="geometry"/></mxCell>'
    )


def e(cid: str, src: str, tgt: str, ports: str, points: tuple[tuple[int, int], ...] = ()) -> str:
    pts = "".join(f'<mxPoint x="{x}" y="{y}"/>' for x, y in points)
    arr = f'<Array as="points">{pts}</Array>' if points else ""
    return (
        f'<mxCell id="{cid}" style="edgeStyle=none;{ports}" edge="1" parent="1" '
        f'source="{src}" target="{tgt}">'
        f'<mxGeometry relative="1" as="geometry">{arr}</mxGeometry></mxCell>'
    )


RIGHT_TO_LEFT = "exitX=1;exitY=0.5;entryX=0;entryY=0.5;"


def test_straight_horizontal_edge_is_valid(tmp_path):
    path = diagram(tmp_path, v("a", 0, 0) + v("b", 200, 0), e("e1", "a", "b", RIGHT_TO_LEFT))
    assert validate(path) == []


def test_diagonal_edge_fails(tmp_path):
    path = diagram(tmp_path, v("a", 0, 0) + v("b", 200, 100), e("e1", "a", "b", RIGHT_TO_LEFT))
    assert any("not orthogonal" in m for m in validate(path))


def test_elbow_with_waypoint_is_valid(tmp_path):
    ports = "exitX=1;exitY=0.5;entryX=0.5;entryY=0;"
    edge = e("e1", "a", "b", ports, ((232, 32),))
    path = diagram(tmp_path, v("a", 0, 0) + v("b", 200, 200), edge)
    assert validate(path) == []


def test_crossing_edges_fail(tmp_path):
    verts = v("a", 0, 100) + v("b", 300, 100) + v("c", 150, 0) + v("d", 150, 300)
    down = "exitX=0.5;exitY=1;entryX=0.5;entryY=0;"
    edges = e("h", "a", "b", RIGHT_TO_LEFT) + e("vert", "c", "d", down)
    assert any("cross" in m for m in validate(diagram(tmp_path, verts, edges)))


def test_overlapping_collinear_edges_fail(tmp_path):
    verts = v("a", 0, 0) + v("b", 400, 0) + v("c", 100, 0)
    edges = e("e1", "a", "b", RIGHT_TO_LEFT) + e("e2", "a", "c", RIGHT_TO_LEFT)
    problems = validate(diagram(tmp_path, verts, edges))
    assert any("overlap" in m or "through icon" in m for m in problems)


def test_edge_through_unrelated_icon_fails(tmp_path):
    verts = v("a", 0, 0) + v("b", 400, 0) + v("blocker", 200, 0)
    problems = validate(diagram(tmp_path, verts, e("e1", "a", "b", RIGHT_TO_LEFT)))
    assert any("through icon blocker" in m for m in problems)


def test_edge_through_marker_fails(tmp_path):
    marker = (
        '<mxCell id="m1" value="1" style="ellipse;obstacle=1;" vertex="1" parent="1">'
        '<mxGeometry x="190" y="20" width="26" height="26" as="geometry"/></mxCell>'
    )
    verts = v("a", 0, 0) + v("b", 400, 0) + marker
    problems = validate(diagram(tmp_path, verts, e("e1", "a", "b", RIGHT_TO_LEFT)))
    assert any("through icon m1" in m for m in problems)


def test_edge_through_plain_box_is_allowed(tmp_path):
    box = (
        '<mxCell id="g" value="group" style="rounded=0;" vertex="1" parent="1">'
        '<mxGeometry x="-20" y="-20" width="500" height="100" as="geometry"/></mxCell>'
    )
    verts = v("a", 0, 0) + v("b", 400, 0) + box
    assert validate(diagram(tmp_path, verts, e("e1", "a", "b", RIGHT_TO_LEFT))) == []


def test_edge_without_explicit_ports_fails(tmp_path):
    path = diagram(tmp_path, v("a", 0, 0) + v("b", 200, 0), e("e1", "a", "b", ""))
    assert any("explicit" in m for m in validate(path))


def test_auto_routed_edge_style_fails(tmp_path):
    edge = e("e1", "a", "b", RIGHT_TO_LEFT).replace(
        "edgeStyle=none", "edgeStyle=orthogonalEdgeStyle"
    )
    path = diagram(tmp_path, v("a", 0, 0) + v("b", 200, 0), edge)
    assert any("edgeStyle" in m for m in validate(path))


def test_real_architecture_diagram_is_valid():
    real = Path(__file__).resolve().parents[2] / "docs" / "architecture.drawio"
    if not real.exists():
        pytest.skip("diagram not generated yet")
    assert validate(real) == []


def test_builder_escapes_attributes_and_matches_the_committed_diagram():
    from docs.diagram import build_architecture as ba

    node = ba.Element("a", v='<&"\n>')
    ba.SubElement(node, "b")
    assert node.to_xml() == '<a v="&lt;&amp;&quot;&#10;&gt;">\n  <b />\n</a>'
    assert ba.build().to_xml() == ba.OUT.read_text(encoding="utf-8")
