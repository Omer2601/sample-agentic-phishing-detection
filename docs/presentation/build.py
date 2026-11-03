# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Render slides.html to one PNG per slide, a PDF and a PPTX (slide images plus speaker notes).

Run from this folder:
  uv run --no-project --with playwright==1.63.0 --with python-pptx==1.0.2 python build.py
"""

import logging
from pathlib import Path

from playwright.sync_api import Route, sync_playwright
from pptx import Presentation
from pptx.util import Emu

HERE = Path(__file__).resolve().parent
SRC = HERE / "slides.html"
PNG_DIR = HERE / "png"
PDF = HERE / "agentic-phishing-detection.pdf"
PPTX = HERE / "agentic-phishing-detection.pptx"

log = logging.getLogger("build")


def local_only(route: Route) -> None:
    # The deck is self-contained; refuse anything that is not a local file.
    if route.request.url.startswith(("file:", "data:")):
        route.continue_()
    else:
        log.warning("blocked %s", route.request.url)
        route.abort()


def render() -> list[str]:
    PNG_DIR.mkdir(exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1920, "height": 1080}, device_scale_factor=1)
        page.route("**/*", local_only)
        page.goto(SRC.as_uri())
        page.evaluate("document.fonts.ready")
        slides = page.locator("section.slide")
        notes = []
        for i in range(slides.count()):
            slide = slides.nth(i)
            slide.screenshot(path=str(PNG_DIR / f"slide-{i + 1:02d}.png"))
            notes.append(slide.get_attribute("data-notes") or "")
        page.pdf(path=str(PDF), width="1920px", height="1080px", print_background=True)
        browser.close()
    log.info("rendered %d slides", len(notes))
    return notes


def build_pptx(notes: list[str]) -> None:
    prs = Presentation()
    prs.slide_width, prs.slide_height = Emu(12192000), Emu(6858000)  # 16:9
    blank = prs.slide_layouts[6]
    for i, text in enumerate(notes, start=1):
        slide = prs.slides.add_slide(blank)
        slide.shapes.add_picture(
            str(PNG_DIR / f"slide-{i:02d}.png"), 0, 0, prs.slide_width, prs.slide_height
        )
        slide.notes_slide.notes_text_frame.text = text
    prs.save(PPTX)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    build_pptx(render())
