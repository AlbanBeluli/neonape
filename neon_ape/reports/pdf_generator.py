from __future__ import annotations

from pathlib import Path
from textwrap import wrap
from typing import Sequence


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
    pdf = canvas.Canvas(str(output_path), pagesize=letter)
    width, height = letter
    margin = 0.65 * inch
    y = height - margin

    def ensure_space(lines: int = 1) -> None:
        nonlocal y
        if y < margin + (lines * 14):
            pdf.showPage()
            y = height - margin

    def draw_line(text: str, *, x: float = margin, font: str = "Helvetica", size: int = 10, color=colors.whitesmoke, leading: int = 13) -> None:
        nonlocal y
        ensure_space(1)
        pdf.setFont(font, size)
        pdf.setFillColor(color)
        pdf.drawString(x, y, text)
        y -= leading

    def draw_section_header(text: str) -> None:
        nonlocal y
        ensure_space(2)
        pdf.setFillColor(colors.HexColor("#ff9f1a"))
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(margin, y, text)
        y -= 14

    pdf.setFillColor(colors.HexColor("#120c16"))
    pdf.rect(0, 0, width, height, fill=1, stroke=0)

    pdf.setFillColor(colors.HexColor("#ff6a00"))
    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(margin, y, title)
    y -= 22
    pdf.setFillColor(colors.HexColor("#ffb347"))
    pdf.setFont("Helvetica", 11)
    pdf.drawString(margin, y, subtitle)
    y -= 20

    pdf.setStrokeColor(colors.HexColor("#8a2be2"))
    pdf.setLineWidth(1.2)
    pdf.line(margin, y, width - margin, y)
    y -= 16

    draw_section_header("Executive Summary")
    for label, value in summary_rows:
        draw_line(f"{label}: {value}", font="Helvetica", size=10)

    if oracle_rows:
        ensure_space(10)
        draw_section_header("Objective Oracles")
        table_top = y
        col_widths = (145, 55, width - (margin * 2) - 200)
        row_height = 18
        pdf.setFillColor(colors.HexColor("#2b1a36"))
        pdf.rect(margin, table_top - row_height, width - (margin * 2), row_height, fill=1, stroke=0)
        header_x = margin + 6
        pdf.setFillColor(colors.whitesmoke)
        pdf.setFont("Helvetica-Bold", 9)
        pdf.drawString(header_x, table_top - 12, "Oracle")
        pdf.drawString(header_x + col_widths[0], table_top - 12, "Score")
        pdf.drawString(header_x + col_widths[0] + col_widths[1], table_top - 12, "Reason")
        y = table_top - row_height - 6
        for index, (oracle, score, reason) in enumerate(oracle_rows):
            ensure_space(2)
            fill = colors.HexColor("#16101c") if index % 2 == 0 else colors.HexColor("#211628")
            pdf.setFillColor(fill)
            pdf.rect(margin, y - 10, width - (margin * 2), row_height, fill=1, stroke=0)
            pdf.setFillColor(colors.whitesmoke)
            pdf.setFont("Helvetica", 8)
            pdf.drawString(header_x, y, oracle[:28])
            pdf.drawString(header_x + col_widths[0], y, score)
            reason_lines = wrap(reason, width=52) or [""]
            pdf.drawString(header_x + col_widths[0] + col_widths[1], y, reason_lines[0])
            row_extra = 0
            for extra in reason_lines[1:2]:
                row_extra += 10
                draw_line(extra, x=header_x + col_widths[0] + col_widths[1], size=8, leading=10)
            y -= row_height + row_extra
        y -= 8

    if objective_history or subjective_history:
        ensure_space(12)
        draw_section_header("Score Chart")
        chart_height = 90
        chart_width = width - (margin * 2)
        chart_bottom = y - chart_height
        pdf.setStrokeColor(colors.HexColor("#5c4a72"))
        pdf.rect(margin, chart_bottom, chart_width, chart_height, stroke=1, fill=0)
        _draw_series(
            pdf,
            series=list(objective_history or []),
            x=margin,
            y=chart_bottom,
            width=chart_width,
            height=chart_height,
            stroke_color=colors.HexColor("#ff6a00"),
        )
        _draw_series(
            pdf,
            series=list(subjective_history or []),
            x=margin,
            y=chart_bottom,
            width=chart_width,
            height=chart_height,
            stroke_color=colors.HexColor("#8a2be2"),
        )
        y = chart_bottom - 16
        draw_line("Orange: objective score   Purple: subjective score", size=9, color=colors.HexColor("#dddddd"))
        if sparkline_text:
            for line in sparkline_text.splitlines():
                draw_line(line, size=9, color=colors.HexColor("#dddddd"))

    for section_title, body in sections:
        ensure_space(4)
        draw_section_header(section_title)
        for paragraph in (body or "").split("\n"):
            lines = wrap(paragraph, width=100) or [""]
            for line in lines:
                draw_line(line, font="Helvetica", size=10, color=colors.whitesmoke)
            y -= 4

    pdf.save()
    return output_path


def _draw_series(pdf, *, series: list[float], x: float, y: float, width: float, height: float, stroke_color) -> None:
    if len(series) < 2:
        return
    minimum = min(series)
    maximum = max(series)
    span = maximum - minimum or 1.0
    points: list[tuple[float, float]] = []
    for index, value in enumerate(series):
        px = x + (width * index / (len(series) - 1))
        py = y + ((value - minimum) / span) * (height - 4) + 2
        points.append((px, py))
    pdf.setStrokeColor(stroke_color)
    pdf.setLineWidth(1.5)
    for start, end in zip(points, points[1:]):
        pdf.line(start[0], start[1], end[0], end[1])
