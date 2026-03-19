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
    headers: tuple[str, ...] = ()


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
    workflow_data: dict[str, object] | None = None,
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
        workflow_data=workflow_data or {},
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
    workflow_data: dict[str, object],
) -> list[Block]:
    if workflow_data:
        return _build_workflow_blocks(
            summary_rows=summary_rows,
            oracle_rows=oracle_rows,
            workflow_data=workflow_data,
        )
    blocks: list[Block] = []
    blocks.append(
        Block(
            kind="key_value",
            title="Executive Summary",
            rows=tuple((label, value) for label, value in summary_rows),
            height=_table_height(len(summary_rows), base=52),
            headers=(),
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
                headers=("Oracle", "Score", "Reason"),
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
                headers=(),
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
                headers=(),
            )
        )
    return blocks


def _build_workflow_blocks(
    *,
    summary_rows: Sequence[tuple[str, str]],
    oracle_rows: Sequence[tuple[str, str, str]],
    workflow_data: dict[str, object],
) -> list[Block]:
    blocks: list[Block] = [
        Block(
            kind="key_value",
            title="Executive Summary",
            rows=tuple((label, value) for label, value in summary_rows),
            height=_table_height(len(summary_rows), base=56),
        )
    ]
    if oracle_rows:
        blocks.append(
            Block(
                kind="table",
                title="Objective Oracles",
                headers=("Oracle", "Score", "Reason"),
                rows=tuple(oracle_rows),
                height=_generic_table_height(("Oracle", "Score", "Reason"), oracle_rows),
            )
        )

    blocks.extend(
        _chunk_table_blocks(
            "Service Inventory",
            ("Host", "Port", "Proto", "Service", "Product", "Version", "Source"),
            [
                (
                    _cell(item.get("host")),
                    _cell(item.get("port")),
                    _cell(item.get("protocol")),
                    _cell(item.get("service_name")),
                    _cell(item.get("product")),
                    _cell(item.get("version")),
                    _cell(item.get("source_tool")),
                )
                for item in _as_dict_rows(workflow_data.get("service_inventory"))
            ],
            chunk_size=18,
        )
    )
    blocks.extend(
        _chunk_table_blocks(
            "Nmap Results",
            ("Host", "Port", "Proto", "Service", "Product", "Version", "Banner", "Summary"),
            [
                (
                    _cell(item.get("host")),
                    _cell(item.get("port")),
                    _cell(item.get("protocol")),
                    _cell(item.get("service_name")),
                    _cell(item.get("product")),
                    _cell(item.get("version")),
                    _cell(item.get("banner")),
                    _cell(item.get("summary")),
                )
                for item in _as_dict_rows(workflow_data.get("nmap_results"))
            ],
            chunk_size=12,
        )
    )
    blocks.extend(
        _chunk_table_blocks(
            "Nuclei Findings",
            ("Severity", "Template", "Name", "Matched At", "Matcher", "Summary"),
            [
                (
                    _cell(item.get("severity")),
                    _cell(item.get("template_id")),
                    _cell(item.get("name")),
                    _cell(item.get("matched_at")),
                    _cell(item.get("matcher_name")),
                    _cell(item.get("summary")),
                )
                for item in _as_dict_rows(workflow_data.get("nuclei_findings"))
            ],
            chunk_size=12,
        )
    )
    blocks.extend(
        _chunk_table_blocks(
            "Sensitive Paths",
            ("Host", "Path", "Category", "Risk", "Status", "Length", "Source"),
            [
                (
                    _cell(item.get("host")),
                    _cell(item.get("path")),
                    _cell(item.get("category")),
                    _cell(item.get("risk_score")),
                    _cell(item.get("status_code")),
                    _cell(item.get("content_length")),
                    _cell(item.get("source_tool")),
                )
                for item in _as_dict_rows(workflow_data.get("sensitive_paths"))
            ],
            chunk_size=14,
        )
    )
    blocks.extend(
        _chunk_table_blocks(
            "MAGI Checklist Status",
            ("Step", "Section", "Title", "Status", "Tool", "Profile"),
            [
                (
                    _cell(item.get("step_order")),
                    _cell(item.get("section_name")),
                    _cell(item.get("title")),
                    _cell(item.get("status")),
                    _cell(item.get("action_tool")),
                    _cell(item.get("action_profile")),
                )
                for item in _as_dict_rows(workflow_data.get("magi_checklist"))
            ],
            chunk_size=14,
        )
    )
    blocks.extend(
        _chunk_table_blocks(
            "ffuf Summary",
            ("Host", "Path", "Category", "Risk", "Status", "Length"),
            [
                (
                    _cell(item.get("host")),
                    _cell(item.get("key") or item.get("path")),
                    _cell(item.get("category")),
                    _cell(item.get("risk_score")),
                    _cell(item.get("status_code")),
                    _cell(item.get("content_length")),
                )
                for item in _as_dict_rows(workflow_data.get("ffuf_summary"))
            ],
            chunk_size=18,
        )
    )
    blocks.extend(
        _chunk_table_blocks(
            "Passive Recon",
            ("Type", "Key", "Value"),
            [
                (
                    _cell(item.get("finding_type")),
                    _cell(item.get("key")),
                    _cell(item.get("value")),
                )
                for item in _as_dict_rows(workflow_data.get("passive_recon"))
            ],
            chunk_size=18,
        )
    )
    blocks.extend(
        _chunk_table_blocks(
            "Raw Findings",
            ("Tool", "Type", "Key", "Value", "Category", "Risk"),
            [
                (
                    _cell(item.get("tool_name")),
                    _cell(item.get("finding_type")),
                    _cell(item.get("key")),
                    _cell(item.get("value")),
                    _cell(item.get("category")),
                    _cell(item.get("risk_score")),
                )
                for item in _as_dict_rows(workflow_data.get("raw_findings"))
            ],
            chunk_size=12,
        )
    )
    recommendations = tuple((_cell(line),) for line in _as_string_rows(workflow_data.get("recommendations")))
    if recommendations:
        blocks.append(
            Block(
                kind="text_panel",
                title="Recommendations / Next Steps",
                rows=recommendations,
                height=44 + (len(recommendations) * 14),
            )
        )
    return blocks


def _chunk_table_blocks(
    title: str,
    headers: tuple[str, ...],
    rows: list[tuple[str, ...]],
    *,
    chunk_size: int,
) -> list[Block]:
    if not rows:
        rows = [tuple("-" for _ in headers)]
    blocks: list[Block] = []
    for index in range(0, len(rows), chunk_size):
        chunk = tuple(rows[index:index + chunk_size])
        chunk_title = title if index == 0 else f"{title} (cont.)"
        blocks.append(
            Block(
                kind="table",
                title=chunk_title,
                headers=headers,
                rows=chunk,
                height=_generic_table_height(headers, chunk),
            )
        )
    return blocks


def _generic_table_height(headers: tuple[str, ...], rows: Sequence[tuple[str, ...]]) -> float:
    total = 62.0
    widths = _column_wrap_widths(headers)
    for row in rows:
        max_lines = 1
        for index, cell in enumerate(row):
            wrap_width = widths[index] if index < len(widths) else 16
            max_lines = max(max_lines, len(wrap(str(cell), width=wrap_width)) or 1)
        total += 8 + (max_lines * 10)
    return total


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
    elif block.kind == "table":
        cursor_y = _draw_generic_table(pdf, block, x=x, width=width, cursor_y=cursor_y, colors=colors)
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


def _draw_generic_table(pdf, block: Block, *, x: float, width: float, cursor_y: float, colors) -> float:
    widths = _column_width_points(width - 20, len(block.headers))
    pdf.setFont("Helvetica-Bold", 8)
    pdf.setFillColor(colors.HexColor(PRIMARY))
    current_x = x + 10
    for index, header in enumerate(block.headers):
        pdf.drawString(current_x, cursor_y, header)
        current_x += widths[index]
    cursor_y -= 14
    wraps = _column_wrap_widths(block.headers)
    for row_index, row in enumerate(block.rows):
        wrapped_cells = []
        row_height = 14
        for index, cell in enumerate(row):
            cell_lines = wrap(str(cell), width=wraps[index] if index < len(wraps) else 16) or [str(cell)]
            wrapped_cells.append(cell_lines)
            row_height = max(row_height, 8 + (len(cell_lines) * 10))
        _draw_row_background(pdf, x, width, cursor_y, row_height, row_index, colors)
        current_x = x + 10
        for index, cell_lines in enumerate(wrapped_cells):
            text_y = cursor_y
            pdf.setFont("Helvetica", 7.5)
            pdf.setFillColor(colors.HexColor(TEXT))
            for line in cell_lines:
                pdf.drawString(current_x, text_y, line)
                text_y -= 10
            current_x += widths[index]
        cursor_y -= row_height + 2
    return cursor_y


def _column_width_points(total_width: float, columns: int) -> list[float]:
    ratios_map = {
        3: [0.18, 0.22, 0.60],
        6: [0.14, 0.12, 0.16, 0.28, 0.14, 0.16],
        7: [0.18, 0.08, 0.08, 0.14, 0.20, 0.16, 0.16],
        8: [0.14, 0.07, 0.07, 0.12, 0.14, 0.12, 0.12, 0.22],
    }
    ratios = ratios_map.get(columns, [1 / columns] * columns)
    return [total_width * ratio for ratio in ratios]


def _column_wrap_widths(headers: tuple[str, ...]) -> list[int]:
    columns = len(headers)
    widths_map = {
        3: [14, 18, 52],
        6: [12, 12, 16, 28, 12, 12],
        7: [14, 8, 8, 12, 18, 14, 12],
        8: [12, 8, 8, 10, 12, 10, 10, 26],
    }
    return widths_map.get(columns, [18] * columns)


def _as_dict_rows(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _as_string_rows(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _cell(value: object) -> str:
    if value is None or value == "":
        return "-"
    return str(value)
