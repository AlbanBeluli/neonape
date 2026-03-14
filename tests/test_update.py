from pathlib import Path

from neon_ape.commands.update import run_update
from neon_ape.config import AppConfig


class StubConsole:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def print(self, message) -> None:
        self.messages.append(str(message))


def test_update_warns_when_script_is_missing(tmp_path) -> None:
    config = AppConfig(
        app_name="Neon Ape",
        config_path=tmp_path / "config.toml",
        install_root=tmp_path / "install",
        bin_dir=tmp_path / "bin",
        launcher_path=tmp_path / "bin" / "neonape",
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "neon_ape.db",
        log_path=tmp_path / "data" / "neon_ape.log",
        checklist_path=tmp_path / "seed.json",
        schema_path=tmp_path / "schema.sql",
        scan_dir=tmp_path / "data" / "scans",
        privacy_mode=True,
        theme_name="eva",
    )
    console = StubConsole()

    run_update(console, config, assume_yes=True)

    assert any("update script was not found" in message for message in console.messages)


def test_update_runs_script_when_present(tmp_path, monkeypatch) -> None:
    install_root = tmp_path / "install"
    install_root.mkdir(parents=True)
    update_script = install_root / "update.sh"
    update_script.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    update_script.chmod(0o755)

    config = AppConfig(
        app_name="Neon Ape",
        config_path=tmp_path / "config.toml",
        install_root=install_root,
        bin_dir=tmp_path / "bin",
        launcher_path=tmp_path / "bin" / "neonape",
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "neon_ape.db",
        log_path=tmp_path / "data" / "neon_ape.log",
        checklist_path=tmp_path / "seed.json",
        schema_path=tmp_path / "schema.sql",
        scan_dir=tmp_path / "data" / "scans",
        privacy_mode=True,
        theme_name="eva",
    )
    console = StubConsole()

    class Result:
        returncode = 0
        stdout = "updated"
        stderr = ""

    def fake_run(*args, **kwargs):
        return Result()

    monkeypatch.setattr("neon_ape.commands.update.subprocess.run", fake_run)

    run_update(console, config, assume_yes=True)

    assert any("updated" in message for message in console.messages)
    assert any("update completed" in message.lower() for message in console.messages)
