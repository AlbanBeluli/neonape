from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from textwrap import wrap
from typing import Sequence


PAGE_SIZE = "letter"
BACKGROUND = "#0A0A0A"
PRIMARY = "#FF4D00"
SECONDARY = "#9F00FF"
TEXT = "#F2F2F2"
MUTED = "#CFCFCF"
PANEL = "#141414"
ROW_ALT = "#1B1B1B"
ROW_BASE = "#111111"
BORDER = "#5A1A7A"


@dataclass(frozen=True)
class Block:
    kind: str
    title: str
    rows: tuple[tuple[str, ...], ...]
    height: float


def generate_pdf_report(
    output_path: Path,
    *,
    title: str,
    subtitle: str,
    summary_rows: Sequence[tuple[str, str]],
    sections: Sequence[tuple[str, str]],
    oracle_rows: Sequence[tuple[str, str, str]] | None = None,
    objective_history: Sequence[float] | None = None,
    subjective_history: Sequence[float] | None = None,
    sparkline_text: str | None = None,
) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise RuntimeError("PDF generation requires `reportlab` to be installed.") from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    width, height = letter
    margin = 0.6 * inch
    header_height = 0.7 * inch
    footer_height = 0.45 * inch
    content_top = height - margin - header_height
    content_bottom = margin + footer_height
    usable_height = content_top - content_bottom

    blocks = _build_blocks(
        summary_rows=summary_rows,
        oracle_rows=oracle_rows or (),
        sections=sections,
        objective_history=objective_history or (),
        subjective_history=subjective_history or (),
        sparkline_text=sparkline_text or "",
        usable_width=width - (margin * 2),
    )
    pages = _paginate_blocks(blocks, usable_height=usable_height)

    pdf = canvas.Canvas(str(output_path), pagesize=letter)
    today = datetime.now(UTC).date().isoformat()
    total_pages = max(len(pages), 1)

    for page_number, page_blocks in enumerate(pages or [[]], start=1):
        _draw_page_theme(
            pdf,
            width=width,
            height=height,
            margin=margin,
            title=title,
            subtitle=subtitle,
            date_text=today,
            page_number=page_number,
            total_pages=total_pages,
            colors=colors,
        )
        cursor_y = content_top
        for block in page_blocks:
            cursor_y = _draw_block(
                pdf,
                block,
                x=margin,
                y=cursor_y,
                width=width - (margin * 2),
                colors=colors,
            )
        pdf.showPage()

    pdf.save()
    return output_path


def _build_blocks(
    *,
    summary_rows: Sequence[tuple[str, str]],
    oracle_rows: Sequence[tuple[str, str, str]],
    sections: Sequence[tuple[str, str]],
    objective_history: Sequence[float],
    subjective_history: Sequence[float],
    sparkline_text: str,
    usable_width: float,
) -> list[Block]:
    blocks: list[Block] = []
    blocks.append(
        Block(
            kind="key_value",
            title="Executive Summary",
            rows=tuple((label, value) for label, value in summary_rows),
            height=_table_height(len(summary_rows), base=52),
        )
    )
    if oracle_rows:
        oracle_height = 58
        for _, _, reason in oracle_rows:
            oracle_height += 18 + (max(len(wrap(reason, width=50)), 1) - 1) * 10
        blocks.append(
            Block(
                kind="oracle_table",
                title="Objective Oracles",
                rows=tuple(oracle_rows),
                height=oracle_height,
            )
        )
    if objective_history or subjective_history or sparkline_text:
        spark_lines = tuple((line,) for line in sparkline_text.splitlines() if line.strip())
        blocks.append(
            Block(
                kind="chart",
                title="Score Chart",
                rows=spark_lines,
                height=170 + (len(spark_lines) * 12),
            )
        )
    for title, body in sections:
        wrapped_lines: list[tuple[str, ...]] = []
        for paragraph in (body or "").split("\n"):
            lines = wrap(paragraph, width=92) or [""]
            for line in lines:
                wrapped_lines.append((line,))
        blocks.append(
            Block(
                kind="text_panel",
                title=title,
                rows=tuple(wrapped_lines),
                height=44 + (len(wrapped_lines) * 12),
            )
        )
    return blocks


def _paginate_blocks(blocks: Sequence[Block], *, usable_height: float) -> list[list[Block]]:
    pages: list[list[Block]] = []
    current: list[Block] = []
    used = 0.0
    for block in blocks:
        block_total = block.height + 10
        if current and used + block_total > usable_height:
            pages.append(current)
            current = [block]
            used = block_total
        else:
            current.append(block)
            used += block_total
    if current:
        pages.append(current)
    return pages


def _draw_page_theme(pdf, *, width: float, height: float, margin: float, title: str, subtitle: str, date_text: str, page_number: int, total_pages: int, colors) -> None:
    pdf.setFillColor(colors.HexColor(BACKGROUND))
    pdf.rect(0, 0, width, height, fill=1, stroke=0)

    pdf.setFont("Helvetica-Bold", 18)
    pdf.setFillColor(colors.HexColor(PRIMARY))
    pdf.drawString(margin, height - margin - 8, title)
    pdf.setFont("Helvetica", 9)
    pdf.setFillColor(colors.HexColor(MUTED))
    pdf.drawRightString(width - margin, height - margin - 8, subtitle)

    pdf.setStrokeColor(colors.HexColor(SECONDARY))
    pdf.setLineWidth(1.3)
    pdf.line(margin, height - margin - 16, width - margin, height - margin - 16)

    footer_y = margin - 4
    pdf.setStrokeColor(colors.HexColor(BORDER))
    pdf.setLineWidth(0.9)
    pdf.line(margin, footer_y + 18, width - margin, footer_y + 18)
    pdf.setFont("Helvetica", 8)
    pdf.setFillColor(colors.HexColor(MUTED))
    pdf.drawString(margin, footer_y + 5, f"{title} | {date_text}")
    pdf.drawRightString(width - margin, footer_y + 5, f"Page {page_number}/{total_pages}")


def _draw_block(pdf, block: Block, *, x: float, y: float, width: float, colors) -> float:
    block_height = block.height
    top = y
    bottom = y - block_height

    pdf.setFillColor(colors.HexColor(PANEL))
    pdf.setStrokeColor(colors.HexColor(BORDER))
    pdf.setLineWidth(1.0)
    pdf.roundRect(x, bottom, width, block_height, 8, fill=1, stroke=1)

    pdf.setFillColor(colors.HexColor(SECONDARY))
    pdf.rect(x, top - 24, width, 24, fill=1, stroke=0)
    pdf.setFont("Helvetica-Bold", 10)
    pdf.setFillColor(colors.white)
    pdf.drawString(x + 10, top - 16, block.title)

    cursor_y = top - 38
    if block.kind == "key_value":
        for index, (label, value) in enumerate(block.rows):
            _draw_row_background(pdf, x, width, cursor_y, 16, index, colors)
            pdf.setFont("Helvetica-Bold", 9)
            pdf.setFillColor(colors.HexColor(PRIMARY))
            pdf.drawString(x + 10, cursor_y, str(label))
            pdf.setFont("Helvetica", 9)
            pdf.setFillColor(colors.HexColor(TEXT))
            pdf.drawString(x + 130, cursor_y, str(value))
            cursor_y -= 16
    elif block.kind == "oracle_table":
        pdf.setFont("Helvetica-Bold", 8)
        pdf.setFillColor(colors.HexColor(PRIMARY))
        pdf.drawString(x + 10, cursor_y, "Oracle")
        pdf.drawString(x + 150, cursor_y, "Score")
        pdf.drawString(x + 200, cursor_y, "Reason")
        cursor_y -= 14
        for index, (oracle, score, reason) in enumerate(block.rows):
            reason_lines = wrap(reason, width=50) or [""]
            row_height = 16 + ((len(reason_lines) - 1) * 10)
            _draw_row_background(pdf, x, width, cursor_y, row_height, index, colors)
            pdf.setFont("Helvetica", 8)
            pdf.setFillColor(colors.HexColor(TEXT))
            pdf.drawString(x + 10, cursor_y, str(oracle)[:26])
            pdf.drawString(x + 150, cursor_y, str(score))
            pdf.drawString(x + 200, cursor_y, reason_lines[0])
            extra_y = cursor_y - 10
            for extra in reason_lines[1:]:
                pdf.drawString(x + 200, extra_y, extra)
                extra_y -= 10
            cursor_y -= row_height + 2
    elif block.kind == "chart":
        chart_height = 90
        chart_width = width - 20
        chart_bottom = cursor_y - chart_height + 6
        pdf.setStrokeColor(colors.HexColor(BORDER))
        pdf.rect(x + 10, chart_bottom, chart_width, chart_height, fill=0, stroke=1)
        objective = _extract_series(block.rows, prefix="Objective:")
        subjective = _extract_series(block.rows, prefix="Subjective:")
        # no-op series are rendered by caller via sparkline text; chart uses passed histories through labels
        pdf.setFont("Helvetica", 9)
        pdf.setFillColor(colors.HexColor(TEXT))
        pdf.drawString(x + 12, chart_bottom - 12, "Orange: objective score")
        pdf.drawString(x + 170, chart_bottom - 12, "Purple: subjective score")
        cursor_y = chart_bottom - 28
        for index, (line,) in enumerate(block.rows):
            _draw_row_background(pdf, x, width, cursor_y, 14, index, colors)
            pdf.setFont("Helvetica", 8)
            pdf.setFillColor(colors.HexColor(MUTED))
            pdf.drawString(x + 10, cursor_y, line)
            cursor_y -= 14
    else:
        for index, (line,) in enumerate(block.rows):
            _draw_row_background(pdf, x, width, cursor_y, 14, index, colors)
            pdf.setFont("Helvetica", 8.5)
            pdf.setFillColor(colors.HexColor(TEXT))
            pdf.drawString(x + 10, cursor_y, line)
            cursor_y -= 14

    return bottom - 10


def _draw_row_background(pdf, x: float, width: float, y: float, row_height: float, index: int, colors) -> None:
    fill = ROW_BASE if index % 2 == 0 else ROW_ALT
    pdf.setFillColor(colors.HexColor(fill))
    pdf.rect(x + 4, y - row_height + 4, width - 8, row_height, fill=1, stroke=0)


def _table_height(rows: int, *, base: float = 48) -> float:
    return base + (rows * 16)


def _extract_series(rows: Sequence[tuple[str, ...]], *, prefix: str) -> list[float]:
    values: list[float] = []
    for row in rows:
        if not row:
            continue
        text = row[0]
        if text.startswith(prefix):
            for char in text.removeprefix(prefix).strip():
                values.append(float(ord(char)))
    return values
