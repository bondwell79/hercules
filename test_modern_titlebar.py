"""Tests for title-bar settings exposed by the migrated Qt settings dialog."""

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu --no-sandbox")

import hercules
from hercules_qt import SettingsDialog
from PySide6.QtWidgets import QApplication


class TitlebarSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_settings_dialog_offers_supported_titlebar_styles(self):
        dialog = SettingsDialog(hercules, None)
        self.addCleanup(dialog.close)

        self.assertNotIn(("UI", "titlebar_style"), dialog._fields)
        self.assertEqual(
            [
                dialog._fields[("UI", "theme")].itemData(index)
                for index in range(dialog._fields[("UI", "theme")].count())
            ],
            list(dialog.THEMES),
        )
        self.assertEqual(dialog._fields[("UI", "theme")].count(), 7)


if __name__ == "__main__":
    unittest.main()
