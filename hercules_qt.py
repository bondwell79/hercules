"""Qt dashboard and Chromium-based workspace browser."""

from __future__ import annotations

import queue
import threading
import traceback
from collections import deque
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from PySide6.QtCore import QTimer, QUrl, Qt
from PySide6.QtGui import (
    QAction,
    QColor,
    QDesktopServices,
    QFont,
    QKeySequence,
    QShortcut,
    QTextCharFormat,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QColorDialog,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileSystemModel,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTreeView,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtWebEngineCore import (
    QWebEnginePage,
    QWebEngineProfile,
    QWebEngineSettings,
    QWebEngineUrlRequestInterceptor,
)
from PySide6.QtWebEngineWidgets import QWebEngineView


def _is_within_workspace(path: Path, workspace: Path) -> bool:
    try:
        path.resolve().relative_to(workspace.resolve())
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _file_url_path(url: QUrl) -> Optional[Path]:
    if url.scheme().lower() != "file":
        return None
    local_path = url.toLocalFile()
    if not local_path:
        return None
    return Path(local_path)


class WorkspaceRequestInterceptor(QWebEngineUrlRequestInterceptor):
    """Restrict local-file requests to pages and resources in the workspace."""

    def __init__(self, workspace: Path) -> None:
        super().__init__()
        self.workspace = workspace.resolve()

    def interceptRequest(self, info: Any) -> None:
        requested_url = info.requestUrl()
        path = _file_url_path(requested_url)
        if path is None:
            return
        first_party = info.firstPartyUrl()
        first_party_path = _file_url_path(first_party)
        if (
            not _is_within_workspace(path, self.workspace)
            or first_party_path is None
            or not _is_within_workspace(first_party_path, self.workspace)
        ):
            info.block(True)


class WorkspaceWebPage(QWebEnginePage):
    """Allow normal web browsing while confining local documents to the workspace."""

    def __init__(self, workspace: Path, parent: QWidget) -> None:
        super().__init__(QWebEngineProfile.defaultProfile(), parent)
        self.workspace = workspace.resolve()

    def acceptNavigationRequest(
        self,
        url: QUrl,
        navigation_type: QWebEnginePage.NavigationType,
        is_main_frame: bool,
    ) -> bool:
        scheme = url.scheme().lower()
        if scheme in {"http", "https", "about", "data", "blob"}:
            return True
        path = _file_url_path(url)
        return path is not None and _is_within_workspace(path, self.workspace)


class SettingsDialog(QDialog):
    SECTION_TITLES = {
        "LLM": "🧠 LLM",
        "Workspace": "📁 Workspace",
        "Database": "🗄 Base de datos",
        "Agent": "🤖 Agente",
        "UI": "🎨 Interfaz",
    }
    CHOICES = {
        ("LLM", "mode"): ("local", "http"),
        ("UI", "titlebar_style"): ("system", "dark", "accent", "custom"),
    }

    def __init__(self, core_module: Any, parent: QWidget) -> None:
        super().__init__(parent)
        self.core = core_module
        self.config = core_module.CONFIG
        self.config_path = Path(self.config.path)
        self._fields: Dict[tuple[str, str], QWidget] = {}
        self._initial: Dict[tuple[str, str], str] = {}
        self.setWindowTitle("Configuración de Hercules")
        self.resize(820, 680)
        self.setMinimumSize(600, 420)
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget(self)
        layout.addWidget(self.tabs, 1)
        try:
            self._build_tabs()
        except OSError as exc:
            raise OSError(f"No se pudo leer {self.config_path}: {exc}") from exc

        footer = QHBoxLayout()
        footer.addWidget(
            QLabel(
                "Los cambios se guardan en config.ini y se aplican al reiniciar Hercules.",
                self,
            ),
            1,
        )
        layout.addLayout(footer)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel,
            self,
        )
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Guardar")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancelar")
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        save_shortcut = QShortcut(QKeySequence.StandardKey.Save, self)
        save_shortcut.activated.connect(self._save)

    def _build_tabs(self) -> None:
        scanned = self.core._scan_config_file(str(self.config_path))
        parser = self.config._parser
        sections = [section for section in self.SECTION_TITLES if parser.has_section(section)]
        sections.extend(section for section in parser.sections() if section not in sections)

        for section in sections:
            descriptions: Dict[str, str] = {}
            for key, description in scanned.get(section, []):
                descriptions.setdefault(key, description)
            keys = list(descriptions)
            keys.extend(key for key in parser.options(section) if key not in descriptions)

            form = QFormLayout()
            form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
            form.setLabelAlignment(Qt.AlignmentFlag.AlignTop)
            for key in keys:
                self._add_setting(form, section, key, descriptions.get(key, ""))

            body = QWidget(self.tabs)
            body.setLayout(form)
            scroll = QScrollArea(self.tabs)
            scroll.setWidgetResizable(True)
            scroll.setWidget(body)
            self.tabs.addTab(scroll, self.SECTION_TITLES.get(section, section))

    def _add_setting(
        self,
        form: QFormLayout,
        section: str,
        key: str,
        description: str,
    ) -> None:
        value = self.config._parser.get(section, key, raw=True)
        field_key = (section, key)
        self._initial[field_key] = value
        default = self.core.Config.DEFAULTS.get(section, {}).get(key, "")

        label = QLabel(key)
        label.setToolTip(description)
        choices = self.CHOICES.get(field_key)
        if choices is None and (
            default.lower() in {"true", "false"}
            or value.lower() in {"true", "false"}
        ):
            choices = ("true", "false")

        if choices:
            field = QComboBox()
            field.addItems(choices)
            current_index = field.findText(value, Qt.MatchFlag.MatchFixedString)
            if current_index >= 0:
                field.setCurrentIndex(current_index)
            else:
                field.setCurrentText(value)
        else:
            field = QLineEdit(value)
            if key == "api_key":
                field.setEchoMode(QLineEdit.EchoMode.Password)
        field.setToolTip(description)

        self._fields[field_key] = field
        if isinstance(field, QLineEdit) and (
            self.core._HEX_COLOR_RE.fullmatch(value)
            or self.core._HEX_COLOR_RE.fullmatch(default)
        ):
            value_widget = self._color_field(field)
        else:
            value_widget = field

        if description:
            help_label = QLabel(description)
            help_label.setWordWrap(True)
            help_label.setAlignment(
                Qt.AlignmentFlag.AlignJustify | Qt.AlignmentFlag.AlignTop
            )
            help_label.setStyleSheet(f"color: {self.config.ui_tab_fg};")
            form.addRow(label, value_widget)
            form.addRow(help_label)
        else:
            form.addRow(label, value_widget)

    def _color_field(self, field: QLineEdit) -> QWidget:
        row = QWidget(self)
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(field, 1)
        color_button = QPushButton("Elegir…", row)
        color_button.clicked.connect(lambda: self._choose_color(field))
        layout.addWidget(color_button)

        def update_swatch(value: str) -> None:
            color = QColor(value)
            if color.isValid():
                color_button.setStyleSheet(
                    f"background-color: {color.name()}; "
                    f"color: {'#000000' if color.lightness() > 128 else '#ffffff'};"
                )
            else:
                color_button.setStyleSheet("")

        field.textChanged.connect(update_swatch)
        update_swatch(field.text())
        return row

    def _choose_color(self, field: QLineEdit) -> None:
        current = QColor(field.text())
        color = QColorDialog.getColor(
            current if current.isValid() else QColor(self.config.ui_accent_color),
            self,
            "Seleccionar color",
        )
        if color.isValid():
            field.setText(color.name())

    def _field_value(self, field: QWidget) -> str:
        if isinstance(field, QComboBox):
            return field.currentText().strip()
        if isinstance(field, QLineEdit):
            return field.text().strip()
        raise TypeError(f"Unsupported settings field: {type(field).__name__}")

    def _validate(self, section: str, key: str, value: str) -> Optional[str]:
        if "%" in value:
            return "no puede contener '%'"
        default = self.core.Config.DEFAULTS.get(section, {}).get(key)
        if default is None:
            return None
        try:
            if self.core.re.fullmatch(r"-?\d+", default):
                int(value)
            elif self.core.re.fullmatch(r"-?\d+\.\d+", default):
                float(value)
            elif default.lower() in {"true", "false"}:
                if value.lower() not in {"true", "false"}:
                    return "debe ser true o false"
            elif self.core._HEX_COLOR_RE.fullmatch(default):
                if not (key.startswith("titlebar") and value.lower() == "system"):
                    if not QColor(value).isValid():
                        return "color no válido (use nombre CSS o #RRGGBB)"
        except ValueError:
            return (
                "debe ser un número"
                if not self.core._HEX_COLOR_RE.fullmatch(default)
                else "color no válido"
            )
        return None

    def _save(self) -> None:
        updates: Dict[str, Dict[str, str]] = {}
        for (section, key), field in self._fields.items():
            value = self._field_value(field)
            if value == self._initial[(section, key)]:
                continue
            error = self._validate(section, key, value)
            if error:
                QMessageBox.critical(
                    self,
                    "Valor no válido",
                    f"[{section}] {key}: {error}",
                )
                return
            updates.setdefault(section, {})[key] = value

        if not updates:
            self.accept()
            return
        try:
            self.core._update_config_file(str(self.config_path), updates)
        except OSError as exc:
            QMessageBox.critical(
                self,
                "Error al guardar",
                f"No se pudo escribir {self.config_path}:\n{exc}",
            )
            return
        QMessageBox.information(
            self,
            "Ajustes guardados",
            "Reinicia Hercules para aplicar los cambios.",
        )
        self.accept()


class QtDashboard(QMainWindow):
    POLL_INTERVAL_MS = 200
    TASK_REFRESH_INTERVAL_MS = 1000

    def __init__(self, core_module: Any) -> None:
        super().__init__()
        self.core = core_module
        self.config = core_module.CONFIG
        self.workspace = Path(core_module.WORKSPACE_DIR).resolve()
        self.db = core_module.Database()
        self.tools = core_module.ToolsRegistry()
        self.llm = core_module.LLMConnector()
        self.ui_queue: queue.Queue[Dict[str, Any]] = queue.Queue()
        self._monitor_command_tool()
        self.permissions = core_module.PermissionManager(self.ui_queue)
        self.agent = core_module.Agent(
            self.db,
            self.llm,
            self.tools,
            self.permissions,
            self.ui_queue,
        )
        self.orchestrator = core_module.TaskOrchestrator(
            self.db,
            self.agent,
            self.ui_queue,
            max_retries=core_module.MAX_RECTIFICATION_RETRIES,
        )
        self.selected_task_id: Optional[int] = None
        self._follow_active_task = True
        self._active_task_cancel_event: Optional[threading.Event] = None
        self._active_task_thread: Optional[threading.Thread] = None
        self._context_usage: Dict[int, Dict[str, int]] = {}
        self._approval_queue: deque[Dict[str, Any]] = deque()
        self._approval_dialog_open = False
        self._preauthorized_requests: set[str] = set()
        self._browser_current_dir = self.workspace

        self._clear_unfinished_tasks()
        self._configure_window()
        self._build_layout()
        self._setup_browser()
        self._refresh_file_browser()
        self._refresh_task_lists()
        self._select_task(None)

        self._event_timer = QTimer(self)
        self._event_timer.timeout.connect(self._poll_queue)
        self._event_timer.start(self.POLL_INTERVAL_MS)
        self._task_timer = QTimer(self)
        self._task_timer.timeout.connect(self._refresh_task_lists)
        self._task_timer.start(self.TASK_REFRESH_INTERVAL_MS)

    def _clear_unfinished_tasks(self) -> None:
        try:
            unfinished = self.core.TaskStatus.unfinished()
            removed = self.db.delete_tasks_by_status(unfinished)
        except Exception as exc:
            print(f"[init] Aviso: no se pudo limpiar el historial de tareas: {exc}")
            return
        if removed:
            states = ", ".join(status.value for status in unfinished)
            print(
                f"[init] Se eliminaron {removed} tarea(s) no terminada(s) "
                f"en estado {states} al arrancar la aplicación."
            )

    def _configure_window(self) -> None:
        self.setWindowTitle(f"Hercules {self.core.VERSION}")
        self.resize(1600, 950)
        self.setMinimumSize(1050, 650)
        icon_path = self.core.SCRIPT_DIR / "hercules.ico"
        if icon_path.is_file():
            from PySide6.QtGui import QIcon

            self.setWindowIcon(QIcon(str(icon_path)))
        font = QFont(self.config.ui_font_family, self.config.ui_font_size)
        self.setFont(font)
        self.setStyleSheet(
            f"""
            QMainWindow, QWidget {{ background: {self.config.ui_frame_bg}; color: {self.config.ui_fg_color}; }}
            QGroupBox {{ background: {self.config.ui_card_bg}; border: 1px solid {self.config.ui_card_border_color}; border-radius: 6px; margin-top: 10px; padding: 8px; }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; }}
            QPlainTextEdit, QLineEdit, QTreeView, QTreeWidget, QTabWidget::pane {{
                background: {self.config.ui_prompt_bg}; color: {self.config.ui_prompt_fg};
                border: 1px solid {self.config.ui_card_border_color}; border-radius: 4px;
                selection-background-color: {self.config.ui_browser_selected_bg};
                selection-color: {self.config.ui_browser_selected_fg};
            }}
            QPushButton {{ background: {self.config.ui_button_bg}; color: {self.config.ui_button_fg}; border: 0; border-radius: 4px; padding: 6px 12px; }}
            QPushButton:hover {{ background: {self.config.ui_button_hover_bg}; }}
            QPushButton:disabled {{ color: {self.config.ui_tab_fg}; }}
            QTabBar::tab {{ background: {self.config.ui_tab_bg}; color: {self.config.ui_tab_fg}; padding: 7px 12px; }}
            QTabBar::tab:selected {{ background: {self.config.ui_tab_selected_bg}; color: {self.config.ui_tab_selected_fg}; }}
            QHeaderView::section {{ background: {self.config.ui_browser_header_bg}; color: {self.config.ui_browser_fg}; border: 0; padding: 4px; }}
            QProgressBar {{ background: {self.config.ui_context_bar_bg}; border: 0; border-radius: 4px; text-align: center; }}
            QProgressBar::chunk {{ background: {self.config.ui_accent_color}; border-radius: 4px; }}
            QSplitter::handle {{ background: {self.config.ui_separator_color}; }}
            """
        )
        if hasattr(self, "setWindowOpacity"):
            self.setWindowOpacity(float(self.config.ui_window_alpha))

    def _build_layout(self) -> None:
        menu = self.menuBar().addMenu("(≡)")
        settings_action = QAction("Configuración…", self)
        settings_action.triggered.connect(self._open_settings)
        menu.addAction(settings_action)
        workspace_action = QAction("Abrir workspace en el explorador", self)
        workspace_action.triggered.connect(self._open_workspace)
        menu.addAction(workspace_action)

        columns = QSplitter(Qt.Orientation.Horizontal, self)
        columns.setChildrenCollapsible(False)
        self.setCentralWidget(columns)

        left = QSplitter(Qt.Orientation.Vertical, columns)
        left.setChildrenCollapsible(False)
        columns.addWidget(left)
        self._build_prompt_panel(left)
        self._build_tasks_panel(left)
        self._build_history_panel(left)
        left.setSizes([205, 275, 480])

        right = QSplitter(Qt.Orientation.Vertical, columns)
        right.setChildrenCollapsible(False)
        columns.addWidget(right)
        self._build_explorer_panel(right)
        self._build_workspace_tools_panel(right)
        right.setSizes([330, 620])
        columns.setSizes([650, 950])

        status = QWidget(self)
        status_layout = QHBoxLayout(status)
        status_layout.setContentsMargins(10, 4, 10, 6)
        status_layout.addWidget(QLabel("Contexto:", status))
        self.context_bar = QProgressBar(status)
        self.context_bar.setRange(0, 100)
        self.context_bar.setValue(0)
        self.context_bar.setFormat("0% (0/0 tokens)")
        status_layout.addWidget(self.context_bar, 1)
        self.statusBar().addPermanentWidget(status, 1)
        self.statusBar().showMessage(self._config_summary())

    def _build_prompt_panel(self, parent: QWidget) -> None:
        panel = QGroupBox("Nueva instrucción para el agente", parent)
        layout = QVBoxLayout(panel)
        self.prompt_edit = QPlainTextEdit(panel)
        self.prompt_edit.setPlaceholderText("Describe la tarea que debe realizar el agente…")
        self.prompt_edit.setMaximumBlockCount(1000)
        layout.addWidget(self.prompt_edit, 1)

        controls = QHBoxLayout()
        self.execute_button = QPushButton("▶ Ejecutar", panel)
        self.execute_button.clicked.connect(self._execute_task)
        controls.addWidget(self.execute_button)
        self.abort_button = QPushButton("■ Abortar", panel)
        self.abort_button.setEnabled(False)
        self.abort_button.clicked.connect(self._abort_task)
        controls.addWidget(self.abort_button)
        clear_button = QPushButton("Limpiar", panel)
        clear_button.clicked.connect(self.prompt_edit.clear)
        controls.addWidget(clear_button)
        self.delete_finished_button = QPushButton("Borrar terminadas", panel)
        self.delete_finished_button.clicked.connect(self._delete_finished_tasks)
        controls.addWidget(self.delete_finished_button)
        self.preauth_checkbox = QCheckBox("Preautorizar con el LLM", panel)
        controls.addWidget(self.preauth_checkbox)
        layout.addLayout(controls)
        parent.addWidget(panel)

    def _build_tasks_panel(self, parent: QWidget) -> None:
        panel = QGroupBox("Tareas", parent)
        layout = QVBoxLayout(panel)
        self.task_tabs = QTabWidget(panel)
        self.active_tasks = self._new_task_tree(self.task_tabs)
        self.finished_tasks = self._new_task_tree(self.task_tabs)
        self.task_tabs.addTab(self.active_tasks, "En curso")
        self.task_tabs.addTab(self.finished_tasks, "Terminadas")
        layout.addWidget(self.task_tabs)
        parent.addWidget(panel)

    def _new_task_tree(self, parent: QWidget) -> QTreeWidget:
        tree = QTreeWidget(parent)
        tree.setHeaderLabels(["Tarea", "Estado"])
        tree.setColumnWidth(0, 390)
        tree.currentItemChanged.connect(self._on_task_selected)
        tree.itemDoubleClicked.connect(self._on_task_double_clicked)
        return tree

    def _build_history_panel(self, parent: QWidget) -> None:
        panel = QGroupBox("Historial de tarea", parent)
        layout = QVBoxLayout(panel)
        self.history_title = QLabel("Historial de tarea (ninguna seleccionada)", panel)
        layout.addWidget(self.history_title)
        self.history_view = QPlainTextEdit(panel)
        self.history_view.setReadOnly(True)
        self.history_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.history_view.setStyleSheet(
            f"background: {self.config.ui_history_bg}; color: {self.config.ui_history_fg};"
        )
        layout.addWidget(self.history_view, 1)
        parent.addWidget(panel)

    def _build_explorer_panel(self, parent: QWidget) -> None:
        panel = QGroupBox("Explorador del workspace", parent)
        layout = QVBoxLayout(panel)
        toolbar = QHBoxLayout()
        self.path_label = QLabel(str(self.workspace), panel)
        self.path_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        toolbar.addWidget(self.path_label, 1)
        up_button = QPushButton("↑", panel)
        up_button.setToolTip("Subir al directorio padre")
        up_button.clicked.connect(self._go_parent_directory)
        toolbar.addWidget(up_button)
        refresh_button = QPushButton("↻", panel)
        refresh_button.setToolTip("Actualizar")
        refresh_button.clicked.connect(self._refresh_file_browser)
        toolbar.addWidget(refresh_button)
        layout.addLayout(toolbar)

        self.file_model = QFileSystemModel(panel)
        self.file_model.setRootPath(str(self.workspace))
        self.file_tree = QTreeView(panel)
        self.file_tree.setModel(self.file_model)
        self.file_tree.setRootIndex(self.file_model.index(str(self.workspace)))
        self.file_tree.setColumnWidth(0, 280)
        self.file_tree.setColumnHidden(2, True)
        self.file_tree.setColumnHidden(3, True)
        self.file_tree.doubleClicked.connect(self._open_file_from_tree)
        layout.addWidget(self.file_tree, 1)
        parent.addWidget(panel)

    def _build_workspace_tools_panel(self, parent: QWidget) -> None:
        panel = QGroupBox("Terminal y navegador", parent)
        layout = QVBoxLayout(panel)

        self.workspace_tabs = QTabWidget(panel)
        terminal_page = QWidget(self.workspace_tabs)
        terminal_layout = QVBoxLayout(terminal_page)
        self.terminal_view = QPlainTextEdit(terminal_page)
        self.terminal_view.setReadOnly(True)
        self.terminal_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.terminal_view.setMaximumBlockCount(5000)
        self.terminal_view.setPlaceholderText(
            "Aquí aparecerán los comandos del agente y la salida real de su ejecución."
        )
        terminal_toolbar = QHBoxLayout()
        terminal_toolbar.addWidget(
            QLabel(
                "Comandos ejecutados por el agente y su salida",
                terminal_page,
            ),
            1,
        )
        clear_terminal_button = QPushButton("Limpiar", terminal_page)
        clear_terminal_button.clicked.connect(self.terminal_view.clear)
        terminal_toolbar.addWidget(clear_terminal_button)
        terminal_layout.addLayout(terminal_toolbar)
        terminal_layout.addWidget(self.terminal_view, 1)
        self.workspace_tabs.addTab(terminal_page, "Terminal de sistema")

        browser_page = QWidget(self.workspace_tabs)
        browser_layout = QVBoxLayout(browser_page)
        toolbar = QHBoxLayout()
        self.back_button = QPushButton("←", browser_page)
        self.back_button.clicked.connect(self._browser_back)
        toolbar.addWidget(self.back_button)
        self.forward_button = QPushButton("→", browser_page)
        self.forward_button.clicked.connect(self._browser_forward)
        toolbar.addWidget(self.forward_button)
        reload_button = QPushButton("↻", browser_page)
        reload_button.clicked.connect(self._browser_reload)
        toolbar.addWidget(reload_button)
        self.address_bar = QLineEdit(browser_page)
        self.address_bar.setPlaceholderText("https://… o ruta local del workspace")
        self.address_bar.returnPressed.connect(self._navigate_to_address)
        toolbar.addWidget(self.address_bar, 1)
        go_button = QPushButton("Ir", browser_page)
        go_button.clicked.connect(self._navigate_to_address)
        toolbar.addWidget(go_button)
        browser_layout.addLayout(toolbar)
        self.web_view = QWebEngineView(browser_page)
        browser_layout.addWidget(self.web_view, 1)
        self.workspace_tabs.addTab(browser_page, "Navegador web")
        layout.addWidget(self.workspace_tabs, 1)
        parent.addWidget(panel)

    def _monitor_command_tool(self) -> None:
        get_tool = getattr(self.tools, "get", None)
        if not callable(get_tool):
            return
        command_tool = get_tool("execute_command")
        if command_tool is None:
            return

        original_runner = command_tool.runner

        def monitored_runner(arguments: Dict[str, Any]) -> str:
            command = str(arguments.get("command", ""))
            self.ui_queue.put({"type": "terminal_command", "command": command})
            try:
                output = original_runner(arguments)
            except Exception as exc:
                self.ui_queue.put(
                    {"type": "terminal_output", "output": f"ERROR: {exc}"}
                )
                raise
            self.ui_queue.put({"type": "terminal_output", "output": output})
            return output

        command_tool.runner = monitored_runner

    def _setup_browser(self) -> None:
        profile = QWebEngineProfile.defaultProfile()
        self._request_interceptor = WorkspaceRequestInterceptor(self.workspace)
        profile.setUrlRequestInterceptor(self._request_interceptor)
        settings = self.web_view.settings()
        settings.setAttribute(
            QWebEngineSettings.WebAttribute.JavascriptEnabled,
            True,
        )
        settings.setAttribute(
            QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls,
            True,
        )
        self.web_view.setPage(WorkspaceWebPage(self.workspace, self.web_view))
        self.web_view.urlChanged.connect(self._update_address_bar)
        self.web_view.loadFinished.connect(self._update_browser_actions)
        self.web_view.page().profile().downloadRequested.connect(
            self._reject_browser_download
        )
        self._update_browser_actions()

    def _config_summary(self) -> str:
        if self.core.LLM_MODE == "local":
            return (
                f"LLM local: {self.core.LLM_MODEL} · Workspace: {self.workspace}"
            )
        return (
            f"LLM HTTP: {self.core.LLM_MODEL} · {self.core.LLM_BASE_URL} "
            f"· Workspace: {self.workspace}"
        )

    def _refresh_task_lists(self) -> None:
        active = self.db.list_tasks(
            [
                self.core.TaskStatus.PENDING,
                self.core.TaskStatus.IN_PROGRESS,
                self.core.TaskStatus.AWAITING_APPROVAL,
            ]
        )
        finished = self.db.list_tasks(self.core.TaskStatus.finished())
        self._populate_task_tree(
            self.active_tasks,
            [task for task in active if task.parent_task_id is None],
        )
        self._populate_task_tree(
            self.finished_tasks,
            [task for task in finished if task.parent_task_id is None],
        )
        if self.selected_task_id is not None and self.db.get_task(self.selected_task_id) is None:
            self._select_task(None)

    def _populate_task_tree(self, tree: QTreeWidget, tasks: list[Any]) -> None:
        selected_id = self.selected_task_id
        tree.blockSignals(True)
        tree.clear()
        for task in tasks:
            item = self._task_item(task)
            tree.addTopLevelItem(item)
            if task.id is not None:
                for subtask in self.db.list_subtasks(task.id):
                    item.addChild(self._task_item(subtask))
            item.setExpanded(True)
            if task.id == selected_id:
                tree.setCurrentItem(item)
            for index in range(item.childCount()):
                child = item.child(index)
                if child.data(0, Qt.ItemDataRole.UserRole) == selected_id:
                    tree.setCurrentItem(child)
        tree.blockSignals(False)

    def _task_item(self, task: Any) -> QTreeWidgetItem:
        item = QTreeWidgetItem([f"#{task.id}  {task.title}", task.status.value])
        item.setData(0, Qt.ItemDataRole.UserRole, task.id)
        item.setToolTip(0, task.prompt)
        item.setForeground(1, self._status_color(task.status.value))
        return item

    def _status_color(self, status: str) -> Any:
        from PySide6.QtGui import QColor

        color_key = {
            "PENDING": "ui_status_pending",
            "IN_PROGRESS": "ui_status_in_progress",
            "AWAITING_APPROVAL": "ui_status_awaiting_approval",
            "COMPLETED": "ui_status_completed",
            "FAILED": "ui_status_failed",
            "CANCELLED": "ui_status_cancelled",
        }.get(status)
        return QColor(getattr(self.config, color_key, self.config.ui_accent_color))

    def _on_task_selected(
        self,
        current: Optional[QTreeWidgetItem],
        _previous: Optional[QTreeWidgetItem],
    ) -> None:
        if current is None:
            return
        task_id = current.data(0, Qt.ItemDataRole.UserRole)
        if task_id is not None:
            self._follow_active_task = False
            self._select_task(int(task_id))

    def _on_task_double_clicked(
        self,
        item: QTreeWidgetItem,
        _column: int,
    ) -> None:
        task_id = item.data(0, Qt.ItemDataRole.UserRole)
        if task_id is not None:
            self._follow_active_task = False
            self._select_task(int(task_id))

    def _select_task(self, task_id: Optional[int]) -> None:
        self.selected_task_id = task_id
        if task_id is None:
            self.history_title.setText("Historial de tarea (ninguna seleccionada)")
            self.history_view.clear()
            self._refresh_context_bar()
            return
        task = self.db.get_task(task_id)
        if task is None:
            self.history_title.setText(f"Tarea #{task_id} (no encontrada)")
            self.history_view.clear()
            return
        parent_suffix = (
            f" · subtarea de #{task.parent_task_id}"
            if task.parent_task_id is not None
            else ""
        )
        self.history_title.setText(
            f"Tarea #{task.id} — {task.title} [{task.status.value}]{parent_suffix}"
        )
        cursor = self.history_view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        cursor.select(QTextCursor.SelectionType.Document)
        cursor.removeSelectedText()
        colors = {
            self.core.EventType.THOUGHT.value: ("ui_thought_fg", True),
            self.core.EventType.TOOL_CALL.value: ("ui_tool_call_fg", False),
            self.core.EventType.TOOL_RESULT.value: ("ui_tool_result_fg", False),
            self.core.EventType.FINAL_ANSWER.value: ("ui_final_answer_fg", True),
            self.core.EventType.ERROR.value: ("ui_error_fg", False),
            self.core.EventType.STATUS_CHANGE.value: ("ui_status_change_fg", False),
            self.core.EventType.INFO.value: ("ui_info_fg", False),
            self.core.EventType.LOOP_DETECTED.value: ("ui_loop_detected_fg", False),
            self.core.EventType.CONTEXT_COMPACTED.value: ("ui_context_compacted_fg", False),
            self.core.EventType.CONTEXT_OVERFLOW.value: ("ui_context_overflow_fg", False),
        }
        for entry in self.db.get_history(task_id):
            if self._is_command_execution_history_entry(entry):
                continue
            event_type = getattr(entry.event_type, "value", entry.event_type)
            label = self.core.EVENT_LABELS.get(event_type, event_type)
            color_key, bold = colors.get(event_type, ("ui_history_fg", False))
            text_format = QTextCharFormat()
            text_format.setForeground(QColor(getattr(self.config, color_key)))
            text_format.setFontWeight(
                QFont.Weight.Bold if bold else QFont.Weight.Normal
            )
            cursor.insertText(
                f"[{entry.timestamp}] {label}\n{entry.content}\n{'─' * 60}\n",
                text_format,
            )
        self.history_view.setTextCursor(cursor)
        self.history_view.moveCursor(QTextCursor.MoveOperation.End)
        self._refresh_context_bar()

    def _is_command_execution_history_entry(self, entry: Any) -> bool:
        event_type = getattr(entry.event_type, "value", entry.event_type)
        if event_type == self.core.EventType.TOOL_CALL.value:
            return "execute_command" in str(entry.content)
        if event_type not in {
            self.core.EventType.TOOL_RESULT.value,
            self.core.EventType.INFO.value,
        }:
            return False
        content = str(entry.content)
        return content.startswith("[execute_command]") or "[execute_command] " in content

    def _refresh_context_bar(self) -> None:
        usage = self._context_usage.get(self.selected_task_id or -1)
        if usage is None:
            self.context_bar.setValue(0)
            self.context_bar.setFormat("0% (0/0 tokens)")
            return
        percent = max(0, min(100, usage["percent"]))
        self.context_bar.setValue(percent)
        self.context_bar.setFormat(
            f"{percent}% ({usage['tokens_used']}/{usage['max_tokens']} tokens)"
        )

    def _execute_task(self) -> None:
        if self._active_task_thread is not None and self._active_task_thread.is_alive():
            return
        prompt = self.prompt_edit.toPlainText().strip()
        if not prompt:
            self.statusBar().showMessage("Escribe una instrucción antes de ejecutar.", 4000)
            return
        title = prompt.splitlines()[0][:80]
        task = self.db.create_task(title=title, prompt=prompt)
        self.prompt_edit.clear()
        self._follow_active_task = True
        self._refresh_task_lists()
        self._select_task(task.id)
        cancel_event = threading.Event()
        self._active_task_cancel_event = cancel_event
        self.execute_button.setEnabled(False)
        self.abort_button.setEnabled(True)

        def run_task() -> None:
            try:
                self.orchestrator.run(task, cancel_event=cancel_event)
            except Exception:
                traceback.print_exc()
                self.ui_queue.put({"type": "orchestrator_error"})
            finally:
                self.ui_queue.put({"type": "orchestrator_finished"})

        self._active_task_thread = threading.Thread(
            target=run_task,
            daemon=True,
            name=f"orchestrator-task-{task.id}",
        )
        self._active_task_thread.start()

    def _abort_task(self) -> None:
        if self._active_task_cancel_event is not None:
            self._active_task_cancel_event.set()
            self.abort_button.setEnabled(False)
            self.statusBar().showMessage("Cancelación solicitada…")

    def _finish_task_thread(self) -> None:
        self._active_task_cancel_event = None
        self._active_task_thread = None
        self.execute_button.setEnabled(True)
        self.abort_button.setEnabled(False)
        self._refresh_task_lists()

    def _delete_finished_tasks(self) -> None:
        answer = QMessageBox.question(
            self,
            "Borrar tareas terminadas",
            "¿Quieres eliminar todas las tareas terminadas y sus historiales?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            deleted = self.db.delete_tasks_by_status(self.core.TaskStatus.finished())
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Error al borrar tareas",
                f"No se pudieron eliminar las tareas terminadas:\n{exc}",
            )
            return
        self._refresh_task_lists()
        if self.selected_task_id is not None and self.db.get_task(self.selected_task_id) is None:
            self._select_task(None)
        self.statusBar().showMessage(
            f"{deleted} tarea(s) terminada(s) eliminada(s).",
            5000,
        )

    def _poll_queue(self) -> None:
        while True:
            try:
                event = self.ui_queue.get_nowait()
            except queue.Empty:
                break
            self._handle_event(event)

    def _handle_event(self, event: Dict[str, Any]) -> None:
        event_type = event.get("type")
        if event_type == "status_change":
            self._refresh_task_lists()
            if self._follow_active_task:
                in_progress = self.db.list_tasks([self.core.TaskStatus.IN_PROGRESS])
                if in_progress:
                    latest = max(in_progress, key=lambda task: task.id or 0)
                    if latest.id is not None and latest.id != self.selected_task_id:
                        self._select_task(latest.id)
        elif event_type == "history_update":
            if event.get("task_id") == self.selected_task_id:
                self._select_task(self.selected_task_id)
        elif event_type == "context_usage":
            task_id = event.get("task_id")
            if task_id is not None:
                self._context_usage[int(task_id)] = {
                    "tokens_used": int(event.get("tokens_used", 0)),
                    "max_tokens": int(event.get("max_tokens", 0)),
                    "percent": int(event.get("percent", 0)),
                }
                if task_id == self.selected_task_id:
                    self._refresh_context_bar()
        elif event_type == "approval_request":
            self._show_approval(event)
        elif event_type == "preauth_result":
            self._finish_preauthorization(event)
        elif event_type == "refresh_file_browser":
            self._refresh_file_browser()
        elif event_type == "terminal_command":
            terminal_path = str(self.workspace).replace("\\", "/")
            if len(terminal_path) > 1 and terminal_path[1] == ":":
                terminal_path = terminal_path[2:]
            self._append_terminal_text(
                f"{terminal_path}> {event.get('command', '')}\n"
            )
        elif event_type == "terminal_output":
            output = str(event.get("output", "")).rstrip("\r\n")
            self._append_terminal_text(f"{output}\n")
        elif event_type == "orchestrator_finished":
            self._finish_task_thread()
        elif event_type == "orchestrator_error":
            self.statusBar().showMessage(
                "Se produjo un error inesperado al ejecutar la tarea; consulta la consola.",
                10000,
            )
        else:
            print(f"[ui] Evento desconocido: {event_type!r}")

    def _append_terminal_text(self, text: str) -> None:
        self.terminal_view.moveCursor(QTextCursor.MoveOperation.End)
        self.terminal_view.insertPlainText(text)
        self.terminal_view.moveCursor(QTextCursor.MoveOperation.End)

    def _show_approval(self, event: Dict[str, Any]) -> None:
        if self.config.no_authorization:
            self.permissions.resolve(
                event["request_id"],
                True,
                reason="autorización omitida por configuración (no_authorization=true)",
            )
            self.core.Dashboard._log_event(
                self,
                event["task_id"],
                self.core.EventType.APPROVAL_GRANTED,
                f"⚠ Autorización omitida por configuración: '{event['tool_name']}'",
            )
            return
        if self.preauth_checkbox.isChecked():
            self._preauthorized_requests.add(event["request_id"])

            def preauthorize() -> None:
                try:
                    approved, reason = self.core.Dashboard._query_llm_for_preauth(
                        self, event
                    )
                except Exception as exc:
                    approved, reason = False, f"error en la consulta al LLM: {exc}"
                self.ui_queue.put(
                    {
                        "type": "preauth_result",
                        "event": event,
                        "approved": approved,
                        "reason": reason,
                    }
                )

            threading.Thread(
                target=preauthorize,
                daemon=True,
                name=f"preauth-{event['request_id'][:8]}",
            ).start()
            return
        self._approval_queue.append(event)
        self._show_next_approval()

    def _finish_preauthorization(self, result: Dict[str, Any]) -> None:
        event = result["event"]
        self._preauthorized_requests.discard(event["request_id"])
        if result["approved"]:
            reason = str(result.get("reason", "preautorizado por el LLM"))
            self.permissions.resolve(event["request_id"], True, reason=reason)
            self.core.Dashboard._log_event(
                self,
                event["task_id"],
                self.core.EventType.PREAUTHORIZATION_GRANTED,
                f"🤖 Preautorización concedida para '{event['tool_name']}': {reason}",
            )
            return
        reason = str(result.get("reason", "sin motivo"))
        self.core.Dashboard._log_event(
            self,
            event["task_id"],
            self.core.EventType.PREAUTHORIZATION_DENIED,
            f"🤖 No se pudo preautorizar '{event['tool_name']}': {reason}",
        )
        if self.config.preauth_fallback_to_human:
            self._approval_queue.append(event)
            self._show_next_approval()
        else:
            self.permissions.resolve(
                event["request_id"],
                False,
                reason=f"preautorización denegada o fallida: {reason}",
            )

    def _show_next_approval(self) -> None:
        if self._approval_dialog_open or not self._approval_queue:
            return
        event = self._approval_queue.popleft()
        self._approval_dialog_open = True
        description = (
            f"Tarea #{event['task_id']}\n"
            f"Herramienta: {event['tool_name']}\n"
            f"Riesgo: {event.get('risk', '?')}\n\n"
            f"{event.get('tool_description', '')}\n\n"
            f"Argumentos:\n"
            f"{self.core._format_approval_args(event['tool_name'], event.get('arguments', {}))}"
        )
        answer = QMessageBox(self)
        answer.setWindowTitle("Aprobación requerida")
        answer.setIcon(QMessageBox.Icon.Warning)
        answer.setText("El agente solicita permiso para realizar una acción.")
        answer.setInformativeText(description)
        allow_button = answer.addButton(
            "Permitir", QMessageBox.ButtonRole.AcceptRole
        )
        answer.addButton("Denegar", QMessageBox.ButtonRole.RejectRole)
        answer.exec()
        granted = answer.clickedButton() is allow_button
        self.permissions.resolve(
            event["request_id"],
            granted,
            reason="permitido por el usuario" if granted else "denegado por el usuario",
        )
        self._approval_dialog_open = False
        QTimer.singleShot(0, self._show_next_approval)

    def _refresh_file_browser(self) -> None:
        if not _is_within_workspace(self._browser_current_dir, self.workspace):
            self._browser_current_dir = self.workspace
        if not self._browser_current_dir.is_dir():
            self._browser_current_dir = self.workspace
        self.file_model.setRootPath(str(self.workspace))
        self.file_tree.setRootIndex(
            self.file_model.index(str(self._browser_current_dir))
        )
        self.path_label.setText(str(self._browser_current_dir))

    def _go_parent_directory(self) -> None:
        current = self._browser_current_dir.resolve()
        if current == self.workspace or not _is_within_workspace(current.parent, self.workspace):
            return
        self._browser_current_dir = current.parent
        self._refresh_file_browser()

    def _open_file_from_tree(self, index: Any) -> None:
        if not index.isValid():
            return
        path = Path(self.file_model.filePath(index)).resolve()
        if not _is_within_workspace(path, self.workspace):
            QMessageBox.warning(
                self,
                "Ruta fuera del workspace",
                "Solo se pueden abrir documentos del workspace.",
            )
            return
        if path.is_dir():
            self._browser_current_dir = path
            self._refresh_file_browser()
            return
        self._load_local_document(path)

    def _load_local_document(self, path: Path) -> None:
        if not path.is_file():
            return
        self.web_view.setUrl(QUrl.fromLocalFile(str(path)))

    def _navigate_to_address(self) -> None:
        address = self.address_bar.text().strip()
        if not address:
            return
        parsed = urlparse(address)
        if parsed.scheme.lower() == "file":
            local_path = Path(QUrl(address).toLocalFile())
            if not _is_within_workspace(local_path, self.workspace):
                QMessageBox.warning(
                    self,
                    "Ruta fuera del workspace",
                    "El navegador solo puede abrir archivos locales del workspace.",
                )
                return
            url = QUrl.fromLocalFile(str(local_path.resolve()))
        elif parsed.scheme.lower() in {"http", "https"}:
            url = QUrl(address)
        elif Path(address).is_absolute() or (
            not parsed.scheme and (self.workspace / address).exists()
        ):
            local_path = Path(address)
            if not local_path.is_absolute():
                local_path = self.workspace / local_path
            if not _is_within_workspace(local_path, self.workspace):
                QMessageBox.warning(
                    self,
                    "Ruta fuera del workspace",
                    "El navegador solo puede abrir archivos locales del workspace.",
                )
                return
            url = QUrl.fromLocalFile(str(local_path.resolve()))
        elif not parsed.scheme:
            url = QUrl("https://www.google.com/search")
            url.setQuery(f"q={address}")
        else:
            QMessageBox.warning(
                self,
                "Esquema no permitido",
                "Solo se permiten URLs HTTP(S) y documentos locales del workspace.",
            )
            return
        self.web_view.setUrl(url)

    def _update_address_bar(self, url: QUrl) -> None:
        self.address_bar.setText(url.toString())

    def _update_browser_actions(self, _loaded: Optional[bool] = None) -> None:
        history = self.web_view.history()
        self.back_button.setEnabled(history.canGoBack())
        self.forward_button.setEnabled(history.canGoForward())

    def _browser_back(self) -> None:
        self.web_view.back()

    def _browser_forward(self) -> None:
        self.web_view.forward()

    def _browser_reload(self) -> None:
        self.web_view.reload()

    def _reject_browser_download(self, download: Any) -> None:
        download.cancel()
        self.statusBar().showMessage(
            "Descargas deshabilitadas en el navegador embebido.",
            5000,
        )

    def _open_settings(self) -> None:
        try:
            dialog = SettingsDialog(self.core, self)
        except OSError as exc:
            QMessageBox.critical(self, "Error de configuración", str(exc))
            return
        if dialog.exec() == QDialog.DialogCode.Accepted:
            QMessageBox.information(
                self,
                "Configuración guardada",
                "Reinicia Hercules para aplicar los cambios.",
            )

    def _open_workspace(self) -> None:
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.workspace))):
            QMessageBox.critical(
                self,
                "No se pudo abrir el workspace",
                f"No se pudo abrir {self.workspace} en el explorador del sistema.",
            )

    def closeEvent(self, event: Any) -> None:
        if self._active_task_cancel_event is not None:
            self._active_task_cancel_event.set()
        for request_id in list(self._preauthorized_requests):
            self.permissions.resolve(
                request_id,
                False,
                reason="aplicación cerrada durante la preautorización",
            )
        while self._approval_queue:
            request = self._approval_queue.popleft()
            self.permissions.resolve(
                request["request_id"],
                False,
                reason="aplicación cerrada antes de la aprobación",
            )
        super().closeEvent(event)


def main(core_module: Any) -> int:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    app.setApplicationName("Hercules")
    window = QtDashboard(core_module)
    if core_module.CONFIG.ui_fullscreen:
        window.showMaximized()
    else:
        window.show()
    app.processEvents()
    try:
        if core_module._load_welcome_pref():
            dialog = QDialog(window)
            dialog.setWindowTitle(f"Bienvenido a Hercules {core_module.VERSION}")
            layout = QVBoxLayout(dialog)
            ascii_title = QLabel(core_module.WelcomeDialog.ASCII_ART.strip(), dialog)
            ascii_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ascii_title.setFont(
                QFont(
                    core_module.CONFIG.ui_mono_font_family,
                    core_module.CONFIG.ui_mono_font_size + 4,
                    QFont.Weight.Bold,
                )
            )
            ascii_title.setStyleSheet("color: #4fc3f7;")
            layout.addWidget(ascii_title)
            title = QLabel(f"Hercules {core_module.VERSION}", dialog)
            title.setStyleSheet("font-size: 22px; font-weight: bold;")
            layout.addWidget(title)
            layout.addWidget(
                QLabel(
                    "Agente LLM con herramientas, control de permisos humano-en-el-bucle "
                    "y navegador Chromium integrado.",
                    dialog,
                )
            )
            link = QPushButton("Abrir repositorio de Hercules", dialog)
            link.clicked.connect(
                lambda: QDesktopServices.openUrl(
                    QUrl("https://github.com/bondwell79/hercules")
                )
            )
            layout.addWidget(link)
            dont_show = QCheckBox("No mostrar este mensaje al iniciar", dialog)
            layout.addWidget(dont_show)
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok, parent=dialog)
            buttons.accepted.connect(dialog.accept)
            layout.addWidget(buttons)
            dialog.adjustSize()

            def center_welcome_dialog() -> None:
                offset = window.frameGeometry().center() - dialog.frameGeometry().center()
                dialog.move(dialog.pos() + offset)

            QTimer.singleShot(0, center_welcome_dialog)
            if dialog.exec() == QDialog.DialogCode.Accepted and dont_show.isChecked():
                try:
                    core_module._save_welcome_pref(False)
                except OSError as exc:
                    print(f"[welcome] No se pudo guardar la preferencia: {exc}")
    except Exception as exc:
        print(f"[welcome] No se pudo mostrar el popup de bienvenida: {exc}")
    return app.exec()
