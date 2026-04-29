from __future__ import annotations

from src.core.config import load_config
from src.gui.main_window import MainWindow
from src.gui.setup_wizard import SetupWizard


def test_load_config_integration():
    cfg = load_config()
    assert cfg is not None
    assert cfg.db_path is not None
    assert cfg.clipboard_timeout_sec >= 0


def test_main_window_creation():
    app = MainWindow()
    try:
        assert app is not None
        assert app.title() != ""
    finally:
        app.destroy()


def test_setup_wizard_creation():
    app = MainWindow()
    try:
        wizard = SetupWizard(app)
        assert wizard is not None
        assert wizard.title() != ""
        wizard.destroy()
    finally:
        app.destroy()