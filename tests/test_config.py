from pathlib import Path

from rich.console import Console

from neon_ape.commands.config import run_config_command
from neon_ape.config import AppConfig, load_user_config, save_user_config, update_user_config


def test_default_config_uses_home_and_env(monkeypatch) -> None:
    monkeypatch.setenv("HOME", "/tmp/neon-home")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/neon-config")
    monkeypatch.setenv("NEONAPE_INSTALL_ROOT", "/tmp/neon-install")
    monkeypatch.setenv("NEONAPE_BIN_DIR", "/tmp/neon-bin")

    config = AppConfig.default()

    assert config.config_path == Path("/tmp/neon-config/neonape/config.toml")
    assert config.install_root == Path("/tmp/neon-install")
    assert config.bin_dir == Path("/tmp/neon-bin")
    assert config.launcher_path == Path("/tmp/neon-bin/neonape")
    assert config.data_dir == Path("/tmp/neon-home/.neon_ape")
    assert config.db_path == Path("/tmp/neon-home/.neon_ape/neon_ape.db")
    assert config.schema_path.name == "schema.sql"
    assert config.checklist_path.name == "neon_ape_checklist.json"
    assert config.llm_provider == "cline"
    assert config.llm_model == "qwen3.5:4b"


def test_ensure_directories_creates_runtime_dirs(tmp_path) -> None:
    config = AppConfig(
        app_name="Neon Ape",
        install_root=tmp_path / "install",
        bin_dir=tmp_path / "bin",
        launcher_path=tmp_path / "bin" / "neonape",
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "neon_ape.db",
        log_path=tmp_path / "data" / "neon_ape.log",
        checklist_path=tmp_path / "seed.json",
        schema_path=tmp_path / "schema.sql",
        scan_dir=tmp_path / "data" / "scans",
        config_path=tmp_path / "config.toml",
        privacy_mode=True,
        theme_name="eva",
        obsidian_vault_path=None,
        llm_provider="cline",
    )

    config.ensure_directories()

    assert config.data_dir.is_dir()
    assert config.scan_dir.is_dir()


def test_default_config_reads_toml_file(monkeypatch, tmp_path) -> None:
    config_home = tmp_path / "config"
    config_dir = config_home / "neonape"
    config_dir.mkdir(parents=True)
    (config_dir / "config.toml").write_text(
        """
[neonape]
install_root = "~/apps/neonape"
bin_dir = "~/bin"
data_dir = "~/secure/neonape"
privacy_mode = false
obsidian_vault_path = "~/vaults/neon"
llm_model = "llama3.2:3b"
llm_provider = "ollama"
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

    config = AppConfig.default()

    assert config.install_root == Path(tmp_path / "home/apps/neonape")
    assert config.bin_dir == Path(tmp_path / "home/bin")
    assert config.data_dir == Path(tmp_path / "home/secure/neonape")
    assert config.privacy_mode is False
    assert config.theme_name == "eva"
    assert config.obsidian_vault_path == Path(tmp_path / "home/vaults/neon")
    assert config.llm_provider == "ollama"
    assert config.llm_model == "llama3.2:3b"


def test_save_and_update_user_config(tmp_path) -> None:
    config_path = tmp_path / "config.toml"
    save_user_config({"privacy_mode": True, "theme_name": "eva"}, config_path)
    assert load_user_config(config_path)["privacy_mode"] is True

    update_user_config("privacy_mode", "false", config_path)
    update_user_config("theme_name", "seele", config_path)
    update_user_config("obsidian_vault_path", "~/vault", config_path)
    update_user_config("llm_provider", "cline", config_path)
    update_user_config("llm_model", "qwen3.5:4b", config_path)
    loaded = load_user_config(config_path)
    assert loaded["privacy_mode"] is False
    assert loaded["theme_name"] == "seele"
    assert loaded["obsidian_vault_path"] == "~/vault"
    assert loaded["llm_provider"] == "cline"
    assert loaded["llm_model"] == "qwen3.5:4b"


def test_config_show_marks_llm_model_inactive_for_cline(tmp_path) -> None:
    console = Console(record=True, width=120)

    config = AppConfig(
        app_name="Neon Ape",
        install_root=tmp_path / "install",
        bin_dir=tmp_path / "bin",
        launcher_path=tmp_path / "bin" / "neonape",
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "neon_ape.db",
        log_path=tmp_path / "data" / "neon_ape.log",
        checklist_path=tmp_path / "seed.json",
        schema_path=tmp_path / "schema.sql",
        scan_dir=tmp_path / "data" / "scans",
        config_path=tmp_path / "config.toml",
        privacy_mode=True,
        theme_name="eva",
        obsidian_vault_path=None,
        llm_provider="cline",
        llm_model="qwen3.5:4b",
    )

    run_config_command(console, config, action="show")

    rendered = console.export_text()
    assert "ollama only; inactive with cline" in rendered
