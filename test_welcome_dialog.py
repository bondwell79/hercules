"""Tests for the Qt welcome dialog shown during application startup."""

import os
import types
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu --no-sandbox")

from PySide6.QtWidgets import QApplication, QCheckBox, QDialog, QWidget

import hercules_qt


class WelcomeDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def _run_startup(self, accepted, disable_welcome):
        core = types.SimpleNamespace(
            VERSION="test",
            CONFIG=types.SimpleNamespace(
                ui_mono_font_family="Consolas",
                ui_mono_font_size=12,
            ),
            WelcomeDialog=types.SimpleNamespace(ASCII_ART="HERCULES"),
            _load_welcome_pref=Mock(return_value=True),
            _save_welcome_pref=Mock(),
        )
        dialog_seen = []

        def execute_dialog(dialog):
            dialog_seen.append(dialog)
            checkbox = next(
                item
                for item in dialog.findChildren(QCheckBox)
                if item.text() == "No mostrar este mensaje al iniciar"
            )
            checkbox.setChecked(disable_welcome)
            return (
                QDialog.DialogCode.Accepted
                if accepted
                else QDialog.DialogCode.Rejected
            )

        with (
            patch.object(hercules_qt, "QtDashboard", return_value=QWidget()),
            patch.object(QDialog, "exec", execute_dialog),
            patch.object(QApplication, "exec", return_value=0),
        ):
            self.assertEqual(hercules_qt.main(core), 0)

        self.assertEqual(len(dialog_seen), 1)
        return core, dialog_seen[0]

    def test_welcome_dialog_contents_and_opt_out_are_shown(self):
        core, dialog = self._run_startup(accepted=True, disable_welcome=True)

        self.assertEqual(dialog.windowTitle(), "Bienvenido a Hercules test")
        labels = [label.text() for label in dialog.findChildren(hercules_qt.QLabel)]
        self.assertIn("HERCULES", labels)
        core._save_welcome_pref.assert_called_once_with(False)

    def test_dismissing_dialog_does_not_save_opt_out(self):
        core, _dialog = self._run_startup(accepted=False, disable_welcome=True)
        core._save_welcome_pref.assert_not_called()


if __name__ == "__main__":
    unittest.main()
