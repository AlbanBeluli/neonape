from __future__ import annotations

import json

from rich.console import Console

from neon_ape.db.repository import review_overview
from neon_ape.ui.views import build_inventory_table, build_review_findings_table, build_review_summary_panel, build_web_path_table


def run_review(
    console: Console,
    connection,
    *,
    target: str,
    limit: int = 50,
    as_json: bool = False,
) -> None:
    overview = review_overview(connection, target, limit=limit)
    if as_json:
        console.print_json(json.dumps({"target": target, **overview}))
        return
    console.print(build_review_summary_panel(target, overview))
    console.print(build_web_path_table(overview["web_paths"]["katana"], "katana"))
    console.print(build_web_path_table(overview["web_paths"]["gobuster"], "gobuster"))
    console.print(build_inventory_table(overview["inventory"]))
    console.print(build_review_findings_table(overview["reviews"]))
