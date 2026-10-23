"""Headless smoke tests for the migrated Qt dashboard widgets."""

import os
import sys
import tempfile
import types
from pathlib import Path
from unittest import TestCase, main

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu --no-sandbox")

SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

import hercules
from hercules_qt import QtDashboard
from PySide6.QtWidgets import (
    QApplication,
    QPlainTextEdit,
    QPushButton,
    QTreeWidget,
)
from PySide6.QtWebEngineWidgets import QWebEngineView


class _EmptyDatabase:
    def delete_tasks_by_status(self, _statuses):
        return 0

    def list_tasks(self, _statuses):
        return []

    def get_task(self, _task_id):
        return None


class DashboardWidgetTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        workspace = Path(self.temp_dir.name)
        self.core = types.SimpleNamespace(
            CONFIG=hercules.CONFIG,
            CONFIG_PATH=hercules.CONFIG_PATH,
            WORKSPACE_DIR=workspace,
            SCRIPT_DIR=hercules.SCRIPT_DIR,
            VERSION=hercules.VERSION,
            LLM_MODE=hercules.LLM_MODE,
            LLM_MODEL=hercules.LLM_MODEL,
            LLM_BASE_URL=hercules.LLM_BASE_URL,
            TaskStatus=hercules.TaskStatus,
            EventType=hercules.EventType,
            EVENT_LABELS=hercules.EVENT_LABELS,
            Database=_EmptyDatabase,
            ToolsRegistry=lambda: object(),
            LLMConnector=lambda: object(),
            PermissionManager=lambda _queue: object(),
            Agent=lambda *_args: types.SimpleNamespace(
                parallel=types.SimpleNamespace(
                    cancel_all=lambda: None, wait_all=lambda _timeout=None: True
                )
            ),
            TaskOrchestrator=lambda *_args, **_kwargs: object(),
        )
        self.window = QtDashboard(self.core)

    def tearDown(self):
        self.window.close()
        self.temp_dir.cleanup()

    def test_dashboard_exposes_native_qt_controls(self):
        self.assertIsInstance(self.window.prompt_edit, QPlainTextEdit)
        self.assertIsInstance(self.window.execute_button, QPushButton)
        self.assertIsInstance(self.window.abort_button, QPushButton)
        self.assertIsInstance(self.window.active_tasks, QTreeWidget)
        self.assertFalse(hasattr(self.window, "file_tree"))
        self.assertIsInstance(self.window.web_view, QWebEngineView)
        self.assertEqual(self.window.windowTitle(), f"Hercules {hercules.VERSION}")


if __name__ == "__main__":
    main()
