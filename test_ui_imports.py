"""Smoke tests for the Qt UI imports and configuration."""

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu --no-sandbox")

SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

import hercules
import hercules_qt
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QMainWindow


def main() -> int:
    assert issubclass(hercules_qt.QtDashboard, QMainWindow)
    assert issubclass(hercules_qt.WorkspaceWebPage, hercules_qt.QWebEnginePage)
    assert hercules_qt.SettingsDialog is not None
    assert QWebEngineView is not None

    config = hercules.CONFIG
    for name in (
        "ui_font_family",
        "ui_font_size",
        "ui_fullscreen",
        "ui_frame_bg",
        "ui_fg_color",
        "ui_card_bg",
        "ui_card_border_color",
        "ui_prompt_bg",
        "ui_prompt_fg",
        "ui_accent_color",
        "ui_window_alpha",
    ):
        assert hasattr(config, name), f"Falta la opción Qt UI {name}"

    assert 0.5 <= config.ui_window_alpha <= 1.0
    assert config.ui_titlebar_style in {"system", "dark", "accent", "custom"}
    print("OK: Qt dashboard, Chromium WebEngine y configuración importados")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"FAIL: {exc}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
