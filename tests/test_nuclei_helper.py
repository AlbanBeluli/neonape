from pathlib import Path

from neon_ape.tools.nuclei_helper import download_templates
from neon_ape.tools.projectdiscovery import _nuclei_base_command


def test_download_templates_uses_existing_local_templates(tmp_path, monkeypatch) -> None:
    source = tmp_path / "source-templates"
    source.mkdir()
    (source / "template.yaml").write_text("id: test\n", encoding="utf-8")
    target = tmp_path / ".neonape" / "nuclei-templates"

    monkeypatch.setattr("neon_ape.tools.nuclei_helper.nuclei_templates_path", lambda: target)
    monkeypatch.setattr("neon_ape.tools.nuclei_helper._candidate_template_dirs", lambda: [source])

    path, message, ready = download_templates()
    assert path == target
    assert ready is True
    assert "Templates already present" in message
    assert target.exists()


def test_nuclei_base_command_uses_managed_templates_path(tmp_path, monkeypatch) -> None:
    target = tmp_path / ".neonape" / "nuclei-templates"
    monkeypatch.setattr("neon_ape.tools.projectdiscovery.nuclei_templates_path", lambda: target)
    command = _nuclei_base_command()
    assert "-t" in command
    assert str(target) in command
