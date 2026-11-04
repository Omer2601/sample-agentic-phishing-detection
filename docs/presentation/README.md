# Customer deck: Agentic phishing URL detection

A 16-slide, 16:9 dark-theme deck for the sample. The source is one HTML file; the PDF, the PPTX and the per-slide PNGs are built from it.

| File | What it is |
| --- | --- |
| `slides.html` | Editable source. One `<section class="slide">` per slide (1920x1080), speaker notes in `data-notes` |
| `assets/` | Console screenshots (dark theme, phishing URLs defanged) and the Inter and JetBrains Mono fonts (SIL Open Font License) |
| `build.py` | Renders `png/`, the PDF and the PPTX |
| `agentic-phishing-detection.pdf` | The deck, one page per slide |
| `agentic-phishing-detection.pptx` | The deck as full-slide images with speaker notes. Edit the HTML, then rebuild |
| `png/` | One PNG per slide |

## View

Open `agentic-phishing-detection.pdf`, or open `slides.html` in a browser and scroll. Everything is local; the page loads no network resources.

## Rebuild

Needs [uv](https://docs.astral.sh/uv/) and a Playwright Chromium (`uv run --no-project --with playwright==1.63.0 playwright install chromium` once).

```bash
uv run --no-project --with playwright==1.63.0 --with python-pptx==1.0.2 python build.py
```

## Rules for edits

- Every number comes from `README.md`, `docs/evaluation.md` or `docs/cost.md` of the sample, with its date and test conditions on the slide. Do not add numbers that were not measured.
- Defang phishing URLs in slide text and screenshots (`hxxp`, `[.]`).
- No em or en dashes: `perl -CSD -ne 'print if /[\x{2013}\x{2014}]/' slides.html README.md` must print nothing.
