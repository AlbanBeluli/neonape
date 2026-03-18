from pathlib import Path

from neon_ape.reports.pdf_generator import generate_pdf_report


def test_generate_pdf_report_writes_file(tmp_path: Path) -> None:
    output_path = tmp_path / "report.pdf"
    generated = generate_pdf_report(
        output_path,
        title="Neon Ape Test Report",
        subtitle="Target: fixture.local",
        summary_rows=(("Target", "fixture.local"), ("Score", "95%")),
        sections=(("Findings", "Sample findings body"), ("Oracles", "host discovery: 100%"),),
        oracle_rows=(("host discovery", "100%", "Live hosts found: 2"),),
        objective_history=[50.0, 75.0, 95.0],
        subjective_history=[40.0, 60.0, 70.0],
        sparkline_text="Objective: ▁▅█",
    )
    assert generated.exists()
    assert generated.stat().st_size > 0
