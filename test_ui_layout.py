"""Headless Qt dashboard layout and JavaScript smoke tests."""

import os
import tempfile
import threading
import types
import unittest
from unittest.mock import patch
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu --no-sandbox")

import hercules
from hercules_qt import BrowserToolBridge, QtDashboard, SettingsDialog, _is_within_workspace
from PySide6.QtCore import QEvent, QEventLoop, QTimer, QUrl, Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineSettings
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QSplitter,
    QTabWidget,
)


class _EmptyDatabase:
    def delete_tasks_by_status(self, _statuses):
        return 0

    def list_tasks(self, _statuses):
        return []

    def get_task(self, _task_id):
        return None


class QtDashboardLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.workspace_dir = tempfile.TemporaryDirectory()
        workspace = Path(self.workspace_dir.name)
        self.core = types.SimpleNamespace(
            CONFIG=hercules.CONFIG,
            CONFIG_PATH=hercules.CONFIG_PATH,
            ToolDefinition=hercules.ToolDefinition,
            RiskLevel=hercules.RiskLevel,
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
            Agent=lambda *_args: object(),
            TaskOrchestrator=lambda *_args, **_kwargs: object(),
        )
        self.window = QtDashboard(self.core)

    def tearDown(self):
        self.window.close()
        self.workspace_dir.cleanup()

    def test_dashboard_uses_requested_two_column_layout(self):
        columns = self.window.centralWidget()
        self.assertIsInstance(columns, QSplitter)
        left, right = columns.widget(0), columns.widget(1)
        self.assertIsInstance(left, QSplitter)

        self.assertEqual(
            [left.widget(i).title() for i in range(left.count())],
            [
                "Nueva instrucción para el agente",
                "Tareas",
                "Historial de tarea",
            ],
        )
        self.assertEqual(right.title(), "Terminal, navegador y explorador")
        self.assertIsInstance(self.window.workspace_tabs, QTabWidget)
        self.assertEqual(
            [
                self.window.workspace_tabs.tabText(i)
                for i in range(self.window.workspace_tabs.count())
            ],
            ["Terminal de sistema", "Navegador web", "Explorador"],
        )
        self.assertIsInstance(self.window.terminal_view, QPlainTextEdit)
        self.assertTrue(self.window.terminal_view.isReadOnly())
        self.assertTrue(
            self.window.web_view.settings().testAttribute(
                QWebEngineSettings.WebAttribute.JavascriptEnabled
            )
        )

    def test_browser_tools_are_registered_without_replacing_existing_tools(self):
        self.assertIsNone(self.window._browser_tool_bridge)

        class Registry:
            def __init__(self):
                self.tools = {}

            def register(self, tool):
                self.tools[tool.name] = tool

        registry = Registry()
        existing_tool = object()
        registry.tools["read_file"] = existing_tool
        self.window.tools = registry
        self.window._register_browser_tools()

        expected = {
            "browser_navigate", "browser_snapshot", "browser_click", "browser_fill",
            "browser_scroll", "browser_press_key", "browser_screenshot", "browser_back",
            "browser_forward", "browser_reload",
        }
        self.assertEqual(set(registry.tools) - {"read_file"}, expected)
        self.assertIs(registry.tools["read_file"], existing_tool)
        self.assertIsNotNone(self.window._browser_tool_bridge)
        for name in expected:
            self.assertEqual(registry.tools[name].risk, hercules.RiskLevel.SAFE)

    def test_browser_snapshot_assigns_interactive_refs(self):
        bridge = BrowserToolBridge(self.window)
        completed = threading.Event()
        response = {}
        callbacks = []
        with patch.object(
            self.window.web_view.page(), "runJavaScript",
            side_effect=lambda script, callback: callbacks.append((script, callback)),
        ):
            bridge._execute(("snapshot", {}, completed, response))
        self.assertEqual(len(callbacks), 1)
        script = callbacks[0][0]
        self.assertIn("data-hercules-ref", script)
        self.assertIn("const ref = 'e'", script)
        callbacks[0][1]({
            "url": "https://example.test", "title": "Example", "text": "Contenido",
            "controls": [
                {"ref": "e1", "details": "button", "label": "Enviar"},
                {"ref": "e2", "details": "input text", "label": "Correo"},
            ],
        })
        self.assertTrue(completed.is_set())
        self.assertIn("@e1 button Enviar", response["result"])
        self.assertIn("@e2 input text Correo", response["result"])
        self.assertEqual(bridge._active_refs, {"e1", "e2"})

    def test_browser_snapshot_parses_serialized_javascript_result(self):
        bridge = BrowserToolBridge(self.window)
        completed = threading.Event()
        response = {}
        callbacks = []
        with patch.object(
            self.window.web_view.page(), "runJavaScript",
            side_effect=lambda script, callback: callbacks.append((script, callback)),
        ):
            bridge._execute(("snapshot", {}, completed, response))
        self.assertIn("JSON.stringify", callbacks[0][0])
        callbacks[0][1](
            '{"url":"https://example.test","title":"Example",'
            '"text":"Contenido","controls":[]}'
        )
        self.assertTrue(completed.is_set())
        self.assertIn("URL: https://example.test", response["result"])
        self.assertIn("Título: Example", response["result"])
        self.assertIn("Contenido", response["result"])

    def test_browser_click_and_fill_accept_snapshot_refs(self):
        bridge = BrowserToolBridge(self.window)
        bridge._active_refs = {"e1", "e2"}
        for action, arguments, expected in (
            ("click", {"ref": "@e1"}, '[data-hercules-ref="e1"]'),
            ("fill", {"ref": "e2", "text": "hola"}, '[data-hercules-ref="e2"]'),
        ):
            with self.subTest(action=action):
                bridge._active_refs = {"e1", "e2"}
                callbacks = []
                completed = threading.Event()
                response = {}
                with patch.object(
                    self.window.web_view.page(), "runJavaScript",
                    side_effect=lambda script, callback: callbacks.append((script, callback)),
                ):
                    bridge._interact(action, arguments, completed, response)
                self.assertIn("data-hercules-ref=", callbacks[0][0])
                self.assertIn(action and arguments["ref"].lstrip("@"), callbacks[0][0])
                callbacks[0][1]("OK: control (@e1)")
                self.assertTrue(completed.is_set())
                self.assertEqual(bridge._active_refs, set())

    def test_browser_ref_must_be_current_and_css_selector_stays_supported(self):
        bridge = BrowserToolBridge(self.window)
        with self.assertRaisesRegex(ValueError, "caducada"):
            bridge._interact("click", {"ref": "e9"}, threading.Event(), {})
        callbacks = []
        with patch.object(
            self.window.web_view.page(), "runJavaScript",
            side_effect=lambda script, callback: callbacks.append((script, callback)),
        ):
            bridge._interact("click", {"selector": "#submit"}, threading.Event(), {})
        self.assertIn('document.querySelector("#submit")', callbacks[0][0])

    def test_browser_tool_execution_selects_browser_tab(self):
        bridge = BrowserToolBridge(self.window)
        browser_index = self.window.workspace_tabs.indexOf(
            self.window.web_view.parentWidget()
        )
        self.window.workspace_tabs.setCurrentIndex(0)
        completed = threading.Event()
        response = {}

        bridge._execute(("back", {}, completed, response))

        self.assertEqual(self.window.workspace_tabs.currentIndex(), browser_index)
        self.assertTrue(completed.is_set())
        self.assertIn("back", response["result"])

    def test_browser_scroll_moves_page_by_requested_amount(self):
        bridge = BrowserToolBridge(self.window)
        completed = threading.Event()
        response = {}
        callbacks = []

        with patch.object(
            self.window.web_view.page(), "runJavaScript",
            side_effect=lambda script, callback: callbacks.append((script, callback)),
        ) as run_js:
            bridge._execute(
                ("scroll", {"direction": "down", "amount": 450}, completed, response)
            )

        self.assertEqual(len(callbacks), 1)
        self.assertIn("window.scrollBy(0, 450)", callbacks[0][0])
        callbacks[0][1](900)
        run_js.assert_called_once()
        self.assertTrue(completed.is_set())
        self.assertEqual(
            response["result"],
            "Página desplazada hacia abajo 450 px; posición vertical: 900 px",
        )

    def test_browser_scroll_rejects_invalid_direction_and_amount(self):
        bridge = BrowserToolBridge(self.window)
        with self.assertRaisesRegex(ValueError, "direction"):
            bridge._scroll({"direction": "left"}, threading.Event(), {})
        with self.assertRaisesRegex(ValueError, "amount"):
            bridge._scroll(
                {"direction": "up", "amount": -1}, threading.Event(), {}
            )

    def test_browser_press_key_sends_native_qt_key_events(self):
        bridge = BrowserToolBridge(self.window)
        completed = threading.Event()
        response = {}

        with (
            patch.object(self.window.web_view, "setFocus") as set_focus,
            patch("hercules_qt.QApplication.sendEvent") as send_event,
            patch.object(self.window.web_view.page(), "runJavaScript") as run_js,
        ):
            bridge._interact(
                "press_key", {"key": "[ArrowDown]"}, completed, response
            )

        set_focus.assert_called_once_with(Qt.FocusReason.OtherFocusReason)
        run_js.assert_not_called()
        self.assertEqual(send_event.call_count, 2)
        events = [call.args[1] for call in send_event.call_args_list]
        self.assertTrue(all(isinstance(event, QKeyEvent) for event in events))
        self.assertEqual(
            [event.type() for event in events],
            [QEvent.Type.KeyPress, QEvent.Type.KeyRelease],
        )
        self.assertTrue(all(event.key() == Qt.Key.Key_Down for event in events))
        self.assertTrue(all(event.text() == "" for event in events))
        self.assertTrue(completed.is_set())
        self.assertEqual(response["result"], "Tecla enviada: ArrowDown")

    def test_browser_press_key_resolves_bracketed_names_and_rejects_unknown_keys(self):
        key, text, name = BrowserToolBridge._resolve_qt_key("[Enter]")
        self.assertEqual((key, text, name), (Qt.Key.Key_Return, "\r", "Enter"))

        key, text, name = BrowserToolBridge._resolve_qt_key("a")
        self.assertEqual((key, text, name), (Qt.Key.Key_A, "a", "a"))

        with self.assertRaisesRegex(ValueError, "tecla no reconocida"):
            BrowserToolBridge._resolve_qt_key("[NotAKey]")

    def test_browser_tool_bridge_validates_navigation_and_screenshot_paths(self):
        bridge = BrowserToolBridge(self.window)
        completed = threading.Event()
        response = {}

        with self.assertRaisesRegex(ValueError, r"HTTP\(S\)"):
            bridge._navigate("javascript:alert(1)", completed, response)
        with self.assertRaisesRegex(ValueError, "workspace"):
            bridge._screenshot("..\\outside.png")

        local_page = self.window.workspace / "page.html"
        local_page.write_text("<title>local</title>", encoding="utf-8")
        bridge._navigate(
            local_page.as_uri(),
            threading.Event(),
            {},
        )
        self.assertEqual(self.window.web_view.url(), QUrl.fromLocalFile(str(local_page)))
        self.assertEqual(self.window.address_bar.text(), local_page.as_uri())

    def test_browser_screenshot_is_saved_inside_workspace(self):
        bridge = BrowserToolBridge(self.window)
        with patch.object(self.window.web_view, "grab") as grab:
            image = types.SimpleNamespace(
                width=lambda: 800,
                height=lambda: 600,
                save=lambda path, _format: Path(path).write_bytes(b"png") > 0,
            )
            grab.return_value = image
            result = bridge._screenshot("captures\\page.png")
        screenshot = self.window.workspace / "captures" / "page.png"
        self.assertTrue(screenshot.is_file())
        self.assertIn(str(screenshot), result)
        self.assertIn("(800x600)", result)

    def test_command_tool_output_is_shown_without_rerunning_command(self):
        calls = []
        tool = types.SimpleNamespace(
            runner=lambda arguments: calls.append(arguments) or "salida del comando\n"
        )
        self.window.tools = types.SimpleNamespace(get=lambda _name: tool)
        self.window._monitor_command_tool()

        arguments = {"command": "echo prueba"}
        result = tool.runner(arguments)
        self.window.workspace_tabs.setCurrentIndex(1)
        self.window._poll_queue()

        self.assertEqual(
            self.window.workspace_tabs.currentIndex(),
            self.window.workspace_tabs.indexOf(self.window.terminal_view.parentWidget()),
        )
        self.assertEqual(result, "salida del comando\n")
        self.assertEqual(calls, [arguments])
        terminal_path = str(self.window.workspace).replace("\\", "/")
        if len(terminal_path) > 1 and terminal_path[1] == ":":
            terminal_path = terminal_path[2:]
        self.assertEqual(
            self.window.terminal_view.toPlainText(),
            f"{terminal_path}> echo prueba\nsalida del comando\n",
        )

    def test_double_clicking_explorer_file_shows_browser_tab(self):
        target = self.window.workspace / "opened.txt"
        target.write_text("contenido", encoding="utf-8")
        self.window.workspace_tabs.setCurrentIndex(0)
        index = self.window.file_model.index(str(target))

        self.window._open_file_from_tree(index)

        browser_index = self.window.workspace_tabs.indexOf(
            self.window.web_view.parentWidget()
        )
        self.assertEqual(self.window.workspace_tabs.currentIndex(), browser_index)
        self.assertEqual(
            self.window.web_view.url(), QUrl.fromLocalFile(str(target.resolve()))
        )

    def test_written_file_is_shown_in_browser_tab(self):
        target = self.window.workspace / "salida.txt"
        target.write_text("hola", encoding="utf-8")
        self.window.workspace_tabs.setCurrentIndex(0)

        self.window.ui_queue.put(
            {"type": "show_file", "task_id": 1, "path": "salida.txt"}
        )
        self.window._poll_queue()

        browser_index = self.window.workspace_tabs.indexOf(
            self.window.web_view.parentWidget()
        )
        self.assertEqual(self.window.workspace_tabs.currentIndex(), browser_index)
        self.assertEqual(
            self.window.web_view.url(), QUrl.fromLocalFile(str(target.resolve()))
        )

    def test_history_entries_keep_configured_event_colors(self):
        event = types.SimpleNamespace(
            event_type=hercules.EventType.FINAL_ANSWER,
            timestamp="2026-10-15 12:00:00",
            content="Respuesta final de prueba",
        )
        task = types.SimpleNamespace(
            id=1,
            title="Tarea de prueba",
            status=types.SimpleNamespace(value="COMPLETED"),
            parent_task_id=None,
        )
        self.window.db.get_task = lambda _task_id: task
        self.window.db.get_history = lambda _task_id: [event]

        self.window._select_task(1)

        answer = self.window.history_view.document().find("Respuesta final de prueba")
        self.assertTrue(answer.isNull() is False)
        self.assertEqual(
            answer.charFormat().foreground().color().name(),
            self.window.config.ui_final_answer_fg,
        )

    def test_command_execution_history_is_filtered(self):
        command_call = types.SimpleNamespace(
            event_type=hercules.EventType.TOOL_CALL,
            content='Llamada a herramienta: execute_command\\nArgumentos: {"command": "echo prueba"}',
        )
        command_result = types.SimpleNamespace(
            event_type=hercules.EventType.TOOL_RESULT,
            content="[execute_command] OK\\nsalida del comando",
        )
        command_error = types.SimpleNamespace(
            event_type=hercules.EventType.INFO,
            content="[execute_command] AVISO\\ncomando bloqueado",
        )
        other_tool = types.SimpleNamespace(
            event_type=hercules.EventType.TOOL_RESULT,
            content="[read_file] OK\\ncontenido",
        )

        self.assertTrue(self.window._is_command_execution_history_entry(command_call))
        self.assertTrue(self.window._is_command_execution_history_entry(command_result))
        self.assertTrue(self.window._is_command_execution_history_entry(command_error))
        self.assertFalse(self.window._is_command_execution_history_entry(other_tool))

    def test_webengine_executes_javascript(self):
        loop = QEventLoop()
        result = []
        timer = QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        page_path = Path(self.workspace_dir.name) / "page with spaces.html"
        page_path.write_text(
            "<html><head><title>pending</title></head>"
            "<body><script>document.title = 'qt-webengine-js-ok';</script></body></html>",
            encoding="utf-8",
        )

        def on_loaded(success):
            if success:
                self.window.web_view.page().runJavaScript(
                    "document.title",
                    lambda title: (result.append(title), loop.quit()),
                )
            else:
                loop.quit()

        self.window.web_view.loadFinished.connect(on_loaded)
        self.window.web_view.setUrl(QUrl.fromLocalFile(str(page_path)))
        timer.start(15000)
        loop.exec()
        self.window.web_view.loadFinished.disconnect(on_loaded)
        self.assertEqual(result, ["qt-webengine-js-ok"])

    def test_local_document_policy_confines_files_to_workspace(self):
        workspace = Path(self.workspace_dir.name)
        inside = workspace / "document.html"
        outside = workspace.parent / "outside.html"
        self.assertTrue(_is_within_workspace(inside, workspace))
        self.assertFalse(_is_within_workspace(outside, workspace))
        page = self.window.web_view.page()
        self.assertTrue(
            page.acceptNavigationRequest(
                QUrl.fromLocalFile(str(inside)),
                QWebEnginePage.NavigationType.NavigationTypeOther,
                True,
            )
        )
        self.assertFalse(
            page.acceptNavigationRequest(
                QUrl.fromLocalFile(str(outside)),
                QWebEnginePage.NavigationType.NavigationTypeOther,
                True,
            )
        )

        class RequestInfo:
            def __init__(self, requested_url, first_party_url):
                self._requested_url = requested_url
                self._first_party_url = first_party_url
                self.blocked = False

            def requestUrl(self):
                return self._requested_url

            def firstPartyUrl(self):
                return self._first_party_url

            def block(self, blocked):
                self.blocked = blocked

        interceptor = self.window._request_interceptor
        outside_request = RequestInfo(
            QUrl.fromLocalFile(str(outside)),
            QUrl.fromLocalFile(str(inside)),
        )
        interceptor.interceptRequest(outside_request)
        self.assertTrue(outside_request.blocked)

        remote_page_request = RequestInfo(
            QUrl.fromLocalFile(str(inside)),
            QUrl("https://example.com/"),
        )
        interceptor.interceptRequest(remote_page_request)
        self.assertTrue(remote_page_request.blocked)

    def test_settings_dialog_uses_typed_controls_and_preserves_comments(self):
        config_path = Path(self.workspace_dir.name) / "config.ini"
        config_path.write_text(
            "[LLM]\n"
            "; Select local or HTTP mode\n"
            "mode = http\n\n"
            "[UI]\n"
            "; Start maximized\n"
            "fullscreen = true\n",
            encoding="utf-8",
        )
        config = hercules.Config(str(config_path))
        subtasks_path = Path(self.workspace_dir.name) / "subtareas.ini"
        subtasks_path.write_text("[ANALIZAR]\\nprompt = Analiza\\n", encoding="utf-8")
        core = types.SimpleNamespace(
            CONFIG=config,
            SUBTAREAS_INI_PATH=str(subtasks_path),
            Config=hercules.Config,
            _scan_config_file=hercules._scan_config_file,
            _update_config_file=hercules._update_config_file,
            _HEX_COLOR_RE=hercules._HEX_COLOR_RE,
            re=hercules.re,
        )
        dialog = SettingsDialog(core, self.window)
        self.addCleanup(dialog.close)

        self.assertEqual(dialog.tabs.count(), len(config._parser.sections()) + 1)
        self.assertNotIn("Workspace", dialog.SECTION_TITLES)
        self.assertNotIn("Database", dialog.SECTION_TITLES)
        self.assertNotIn("Database", [dialog.tabs.tabText(i) for i in range(dialog.tabs.count())])
        self.assertIsInstance(dialog._fields[("Agent", "workspace_path")], QLineEdit)
        self.assertIsInstance(dialog._fields[("LLM", "database_path")], QLineEdit)
        self.assertEqual(dialog._fields[("LLM", "database_path")].text(), "hercules.db")
        self.assertEqual(
            sum(1 for key in dialog._fields if key == ("LLM", "database_path")), 1
        )
        theme = dialog._fields[("UI", "theme")]
        self.assertIsInstance(theme, QComboBox)
        self.assertEqual(theme.count(), 7)
        self.assertEqual(theme.currentData(), "dark")
        ui_tab_index = next(
            index
            for index in range(dialog.tabs.count())
            if dialog.tabs.tabText(index) == dialog.SECTION_TITLES["UI"]
        )
        ui_form = dialog.tabs.widget(ui_tab_index).widget().layout()
        ui_labels = [
            ui_form.itemAt(row, QFormLayout.ItemRole.LabelRole).widget().text()
            for row in range(ui_form.rowCount())
            if ui_form.itemAt(row, QFormLayout.ItemRole.LabelRole) is not None
        ]
        self.assertEqual(
            ui_labels,
            ["Tema", "Iniciar en pantalla completa", "Tipografía", "Tamaño de fuente"],
        )
        self.assertIsNotNone(dialog._theme_preview)
        self.assertIn("Vista previa", dialog._theme_preview.title())
        self.assertEqual(dialog._theme_preview_label.text(), "Así se verá el texto con el tema y la tipografía seleccionados.")
        self.assertEqual(dialog._theme_preview_button.text(), "Botón de ejemplo")
        self.assertNotIn("bg_color", ui_labels)
        self.assertEqual(
            dialog.tabs.tabText(dialog.tabs.count() - 1),
            dialog.SUBTASKS_TAB_TITLE,
        )
        self.assertEqual(
            dialog.subtasks_edit.toPlainText(), "[ANALIZAR]\\nprompt = Analiza\\n"
        )
        self.assertIsInstance(dialog._fields[("LLM", "mode")], QComboBox)
        self.assertIsInstance(dialog._fields[("UI", "fullscreen")], QComboBox)
        api_key = dialog._fields[("LLM", "api_key")]
        self.assertIsInstance(api_key, QLineEdit)
        self.assertEqual(api_key.echoMode(), QLineEdit.EchoMode.Password)
        retries = dialog._fields[("LLM", "retries")]
        self.assertIsInstance(retries, QLineEdit)
        self.assertEqual(retries.text(), "3")
        self.assertIsNotNone(dialog._validate("LLM", "retries", "0"))
        self.assertIsNotNone(dialog._validate("LLM", "retries", "no"))
        self.assertEqual(
            dialog._fields[("LLM", "mode")].toolTip(),
            "Select local or HTTP mode",
        )
        form = dialog.tabs.widget(0).widget().layout()
        self.assertIsInstance(form, QFormLayout)
        description_row = next(
            row
            for row in range(form.rowCount())
            if form.itemAt(row, QFormLayout.ItemRole.SpanningRole) is not None
            and isinstance(
                form.itemAt(row, QFormLayout.ItemRole.SpanningRole).widget(), QLabel
            )
            and form.itemAt(row, QFormLayout.ItemRole.SpanningRole).widget().text()
            == "Select local or HTTP mode"
        )
        description = form.itemAt(
            description_row, QFormLayout.ItemRole.SpanningRole
        ).widget()
        self.assertEqual(
            description.alignment(),
            Qt.AlignmentFlag.AlignJustify | Qt.AlignmentFlag.AlignTop,
        )

        dialog._fields[("UI", "fullscreen")].setCurrentText("false")
        retries.setText("4")
        theme.setCurrentIndex(theme.findData("ocean"))
        dialog.subtasks_edit.setPlainText(
            "[ANALIZAR]\\nprompt = Analiza la petición\\n\\n[IMPLEMENTAR]\\n"
            "prompt = Ejecuta el plan\\n"
        )
        with patch("hercules_qt.QMessageBox.information"):
            dialog._save()
        saved_config = hercules.Config(str(config_path))
        self.assertEqual(saved_config._parser.get("UI", "theme"), "ocean")
        self.assertEqual(saved_config.llm_retries, 4)
        self.assertEqual(saved_config._parser.get("UI", "bg_color"), "#081521")
        self.assertEqual(
            subtasks_path.read_text(encoding="utf-8"),
            "[ANALIZAR]\\nprompt = Analiza la petición\\n\\n[IMPLEMENTAR]\\n"
            "prompt = Ejecuta el plan\\n",
        )
        saved = config_path.read_text(encoding="utf-8")
        self.assertIn("; Start maximized", saved)
        self.assertIn("fullscreen = false", saved)
        self.assertIn("; Select local or HTTP mode", saved)
        self.assertIn("mode = http", saved)

    def test_configuration_sections_are_not_migrated(self):
        config_path = Path(self.workspace_dir.name) / "old-config.ini"
        config_path.write_text(
            "[Workspace]\npath = ./old-workspace\n"
            "[Database]\npath = old.db\n",
            encoding="utf-8",
        )
        config = hercules.Config(str(config_path))
        self.assertEqual(config.workspace_path, "./workspace")
        self.assertEqual(config.db_path, "hercules.db")
        self.assertEqual(config._parser.get("Agent", "workspace_path"), "./workspace")
        self.assertEqual(config._parser.get("LLM", "database_path"), "hercules.db")


if __name__ == "__main__":
    unittest.main()
