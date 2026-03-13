from pathlib import Path

from neon_ape.app import NeonApeApp
from neon_ape.config import AppConfig


def test_uninstall_removes_install_root_launcher_and_data(tmp_path) -> None:
    install_root = tmp_path / "install"
    bin_dir = tmp_path / "bin"
    data_dir = tmp_path / "data"
    launcher = bin_dir / "neonape"
    install_root.mkdir(parents=True)
    bin_dir.mkdir(parents=True)
    data_dir.mkdir(parents=True)
    launcher.write_text("", encoding="utf-8")
    (data_dir / "neon_ape.db").write_text("", encoding="utf-8")

    config = AppConfig(
        app_name="Neon Ape",
        config_path=tmp_path / "config.toml",
        install_root=install_root,
        bin_dir=bin_dir,
        launcher_path=launcher,
        data_dir=data_dir,
        db_path=data_dir / "neon_ape.db",
        log_path=data_dir / "neon_ape.log",
        checklist_path=tmp_path / "seed.json",
        schema_path=tmp_path / "schema.sql",
        scan_dir=data_dir / "scans",
        privacy_mode=True,
    )
    app = NeonApeApp(config=config)
    app.command = "uninstall"
    app.uninstall_yes = True
    app.uninstall_purge_data = True

    app.run()

    assert not install_root.exists()
    assert not launcher.exists()
    assert not data_dir.exists()
