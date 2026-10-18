"""Qt dashboard and Chromium-based workspace browser."""

from __future__ import annotations

import configparser
import json
import logging
import queue
import threading
import time
import traceback
from collections import deque
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from PySide6.QtCore import QEvent, QObject, QTimer, QUrl, Qt, Signal, Slot
from PySide6.QtGui import (
    QAction,
    QColor,
    QConicalGradient,
    QDesktopServices,
    QFont,
    QFontDatabase,
    QKeyEvent,
    QKeySequence,
    QPainter,
    QPainterPath,
    QPen,
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


APPROVAL_DISPLAY_MAX_CHARS = 255


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


class BrowserToolBridge(QObject):
    """Runs browser tool requests on the Qt GUI thread and returns their results."""

    request = Signal(object)

    def __init__(self, dashboard: "QtDashboard") -> None:
        super().__init__(dashboard)
        self.dashboard = dashboard
        self.request.connect(self._execute)

    def run(self, action: str, arguments: Dict[str, Any]) -> str:
        completed = threading.Event()
        response: Dict[str, str] = {}
        self.request.emit((action, arguments, completed, response))
        if not completed.wait(30):
            return "ERROR: el navegador no respondió dentro de 30 segundos"
        return response.get("result", "ERROR: el navegador no devolvió resultado")

    @Slot(object)
    def _execute(self, request: Any) -> None:
        action, arguments, completed, response = request
        browser_index = self.dashboard.workspace_tabs.indexOf(
            self.dashboard.web_view.parentWidget()
        )
        if browser_index >= 0:
            self.dashboard.workspace_tabs.setCurrentIndex(browser_index)
        try:
            if action == "navigate":
                address = str(arguments.get("url", ""))
                self._navigate(address, completed, response)
                return
            elif action in {"back", "forward", "reload"}:
                getattr(self.dashboard.web_view, action)()
                response["result"] = f"Acción del navegador ejecutada: {action}"
            elif action == "screenshot":
                response["result"] = self._screenshot(arguments.get("path"))
            elif action == "scroll":
                self._scroll(arguments, completed, response)
                return
            elif action == "snapshot":
                self.dashboard.web_view.page().runJavaScript(
                    """(() => {
                      const visible = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
                      const nodes = [...document.querySelectorAll('a,button,input,textarea,select,[role],h1,h2,h3')]
                        .filter(visible).slice(0, 250);
                      const lines = nodes.map(e => {
                        const label = e.getAttribute('aria-label') || e.innerText || e.value || e.placeholder || '';
                        return `${e.tagName.toLowerCase()}${e.id ? '#'+e.id : ''}${e.getAttribute('role') ? '[role='+e.getAttribute('role')+']' : ''} ${label.trim().replace(/\\s+/g,' ').slice(0,180)}`;
                      }).filter(line => line.trim());
                      return `URL: ${location.href}\\nTítulo: ${document.title}\\n${document.body.innerText.slice(0,12000)}\\nControles:\\n${lines.join('\\n')}`;
                    })()""",
                    lambda result: self._finish(completed, response, str(result or "(página vacía)")),
                )
                return
            elif action in {"click", "fill", "press_key"}:
                self._interact(action, arguments, completed, response)
                return
            else:
                raise ValueError(f"Acción de navegador desconocida: {action}")
        except Exception as exc:
            response["result"] = f"ERROR: {exc}"
        completed.set()

    def _navigate(
        self,
        address: str,
        completed: threading.Event,
        response: Dict[str, str],
    ) -> None:
        address = address.strip()
        parsed = urlparse(address)
        if parsed.scheme.lower() in {"http", "https"}:
            url = QUrl(address)
        elif parsed.scheme.lower() == "file":
            path = Path(QUrl(address).toLocalFile()).resolve()
            if not _is_within_workspace(path, self.dashboard.workspace):
                raise ValueError("solo se permiten archivos locales del workspace")
            url = QUrl.fromLocalFile(str(path))
        else:
            raise ValueError("url debe usar HTTP(S) o ser un file:// del workspace")
        if not url.isValid() or not url.host() and url.scheme() in {"http", "https"}:
            raise ValueError("URL no válida")
        self.dashboard.address_bar.setText(url.toString())
        self.dashboard.workspace_tabs.setCurrentIndex(
            self.dashboard.workspace_tabs.indexOf(self.dashboard.web_view.parentWidget())
        )
        self.dashboard.web_view.loadFinished.connect(
            lambda _success: self._finish(
                completed,
                response,
                f"Página cargada: {self.dashboard.web_view.url().toString()}",
            ),
            Qt.ConnectionType.SingleShotConnection,
        )
        self.dashboard.web_view.setUrl(url)

    def _interact(
        self,
        action: str,
        arguments: Dict[str, Any],
        completed: threading.Event,
        response: Dict[str, str],
    ) -> None:
        if action == "press_key":
            raw_key = str(arguments.get("key", "")).strip()
            key, text, key_name = self._resolve_qt_key(raw_key)
            web_view = self.dashboard.web_view
            web_view.setFocus(Qt.FocusReason.OtherFocusReason)
            for event_type in (QEvent.Type.KeyPress, QEvent.Type.KeyRelease):
                QApplication.sendEvent(
                    web_view,
                    QKeyEvent(
                        event_type,
                        key,
                        Qt.KeyboardModifier.NoModifier,
                        text,
                    ),
                )
            self._finish(completed, response, f"Tecla enviada: {key_name}")
            return

        raw_selector = str(arguments.get("selector", ""))
        selector = json.dumps(raw_selector)
        selector_label = json.dumps(raw_selector)
        if not arguments.get("selector"):
            raise ValueError("selector es obligatorio")
        value = json.dumps(str(arguments.get("text", "")))
        if action == "click":
            operation = "e.click();"
        else:
            operation = f"""const setter=Object.getOwnPropertyDescriptor(
              e instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype,'value').set;
              if (!setter) return 'ERROR: el elemento no admite texto'; setter.call(e,{value});
              e.dispatchEvent(new Event('input',{{bubbles:true}})); e.dispatchEvent(new Event('change',{{bubbles:true}}));"""
        script = f"""(() => {{ let e; try {{ e=document.querySelector({selector}); }} catch (error) {{ return 'ERROR: selector CSS inválido'; }}
          if (!e) return 'ERROR: no se encontró el elemento'; e.scrollIntoView({{block:'center'}}); {operation}
          return 'OK: '+e.tagName.toLowerCase()+' ('+{selector_label}+ ')'; }})()"""
        self.dashboard.web_view.page().runJavaScript(
            script,
            lambda result: self._finish(completed, response, str(result or "OK")),
        )

    def _scroll(
        self,
        arguments: Dict[str, Any],
        completed: threading.Event,
        response: Dict[str, str],
    ) -> None:
        direction = str(arguments.get("direction", "")).strip().casefold()
        if direction not in {"up", "down"}:
            raise ValueError("direction debe ser 'up' o 'down'")

        amount = arguments.get("amount", 600)
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            raise ValueError("amount debe ser un entero positivo en píxeles")

        delta = amount if direction == "down" else -amount
        direction_label = "abajo" if direction == "down" else "arriba"
        self.dashboard.web_view.page().runJavaScript(
            f"(() => {{ window.scrollBy(0, {delta}); return Math.round(window.scrollY); }})()",
            lambda scroll_y: self._finish(
                completed,
                response,
                f"Página desplazada hacia {direction_label} {amount} px; posición vertical: {scroll_y} px",
            ),
        )

    @staticmethod
    def _resolve_qt_key(raw_key: str) -> tuple[Qt.Key, str, str]:
        key_name = raw_key.strip()
        if key_name.startswith("[") and key_name.endswith("]"):
            key_name = key_name[1:-1].strip()
        if not key_name:
            raise ValueError("key debe ser un nombre de tecla no vacío")

        normalized = key_name.casefold()
        named_keys = {
            "enter": (Qt.Key.Key_Return, "\r"),
            "return": (Qt.Key.Key_Return, "\r"),
            "escape": (Qt.Key.Key_Escape, ""),
            "esc": (Qt.Key.Key_Escape, ""),
            "tab": (Qt.Key.Key_Tab, "\t"),
            "backspace": (Qt.Key.Key_Backspace, ""),
            "delete": (Qt.Key.Key_Delete, ""),
            "insert": (Qt.Key.Key_Insert, ""),
            "home": (Qt.Key.Key_Home, ""),
            "end": (Qt.Key.Key_End, ""),
            "pageup": (Qt.Key.Key_PageUp, ""),
            "pagedown": (Qt.Key.Key_PageDown, ""),
            "arrowup": (Qt.Key.Key_Up, ""),
            "up": (Qt.Key.Key_Up, ""),
            "arrowdown": (Qt.Key.Key_Down, ""),
            "down": (Qt.Key.Key_Down, ""),
            "arrowleft": (Qt.Key.Key_Left, ""),
            "left": (Qt.Key.Key_Left, ""),
            "arrowright": (Qt.Key.Key_Right, ""),
            "right": (Qt.Key.Key_Right, ""),
            "space": (Qt.Key.Key_Space, " "),
        }
        if normalized in named_keys:
            key, text = named_keys[normalized]
        elif len(key_name) == 1 and key_name.isascii() and key_name.isprintable():
            text = key_name
            key = Qt.Key(ord(key_name.upper()))
        else:
            raise ValueError(f"tecla no reconocida: {raw_key}")

        return key, text, key_name

    def _screenshot(self, raw_path: Any) -> str:
        if raw_path:
            path = Path(str(raw_path)).expanduser()
            if not path.is_absolute():
                path = self.dashboard.workspace / path
            path = path.resolve()
        else:
            path = self.dashboard.workspace / "browser_screenshot.png"
        if not _is_within_workspace(path, self.dashboard.workspace):
            raise ValueError("la captura debe guardarse dentro del workspace")
        path.parent.mkdir(parents=True, exist_ok=True)
        image = self.dashboard.web_view.grab()
        if not image.save(str(path), "PNG"):
            raise OSError(f"no se pudo guardar la captura: {path}")
        return f"Captura de pantalla guardada en: {path} ({image.width()}x{image.height()})"

    @staticmethod
    def _finish(completed: threading.Event, response: Dict[str, str], result: str) -> None:
        response["result"] = result[:20000]
        completed.set()


class SettingsDialog(QDialog):
    SECTION_TITLES = {
        "LLM": "🧠 LLM",
        "Agent": "🤖 Agente",
        "UI": "🎨 Interfaz",
    }
    SUBTASKS_TAB_TITLE = "🔀 Subtareas"
    THEMES = {
        "dark": "Modo dark",
        "ocean": "Modo ocean",
        "green": "Modo green",
        "retro": "Modo retro",
        "windows": "Modo windows",
        "mac": "Modo mac",
        "black&white": "Modo black&white",
    }
    THEME_ROLES = {
        "background": ("bg_color", "frame_bg", "prompt_bg", "history_bg", "approval_bg", "approval_request_bg", "approval_granted_bg", "approval_denied_bg", "browser_header_bg", "scrollbar_trough", "tab_bg", "context_bar_bg"),
        "surface": ("card_bg", "browser_bg", "checkbox_bg", "tab_selected_bg"),
        "raised": ("button_bg",),
        "text": ("fg_color", "prompt_fg", "browser_fg", "button_fg", "checkbox_fg", "tab_selected_fg", "approval_request_fg"),
        "soft_text": ("history_fg", "tab_fg", "scrollbar_arrow", "status_change_fg", "status_pending"),
        "border": ("browser_border", "separator_color", "card_border_color"),
        "selection": ("browser_selected_bg",),
        "selection_text": ("browser_selected_fg",),
        "accent": ("accent_color", "button_accent_bg", "tab_hover_bg", "status_in_progress", "tool_call_fg", "loop_detected_fg", "context_compacted_fg"),
        "accent_text": ("button_accent_fg",),
        "accent_hover": ("button_accent_hover_bg",),
        "accent_pressed": ("button_accent_pressed_bg", "button_pressed_bg"),
        "success": ("approval_fg", "approval_granted_fg", "final_answer_fg", "status_completed", "context_bar_low"),
        "warning": ("approval_denied_fg", "info_fg", "thought_fg", "status_awaiting_approval", "context_bar_medium"),
        "danger": ("error_fg", "context_overflow_fg", "status_failed", "button_danger_bg"),
        "danger_text": ("button_danger_fg",),
        "danger_hover": ("button_danger_hover_bg",),
        "danger_pressed": ("button_danger_pressed_bg",),
        "secondary": ("tool_result_fg", "status_cancelled", "context_bar_high"),
        "hover": ("button_hover_bg", "scrollbar_thumb_hover"),
        "scrollbar": ("scrollbar_thumb",),
        "titlebar": ("titlebar_color",),
        "titlebar_text": ("titlebar_text_color",),
    }
    THEME_PALETTES = {
        "dark": {"background": "#0f1115", "surface": "#1a1d23", "raised": "#272b33", "text": "#e6e8eb", "soft_text": "#9ca3af", "border": "#2a2e37", "selection": "#1e3a5f", "selection_text": "#ffffff", "accent": "#60a5fa", "accent_text": "#ffffff", "accent_hover": "#60a5fa", "accent_pressed": "#2563eb", "success": "#4ade80", "warning": "#fbbf24", "danger": "#f87171", "danger_text": "#ffffff", "danger_hover": "#ef4444", "danger_pressed": "#b91c1c", "secondary": "#5eead4", "hover": "#343944", "scrollbar": "#3a3f4b", "titlebar": "#0f1115", "titlebar_text": "#e6e8eb"},
        "ocean": {"background": "#081521", "surface": "#102536", "raised": "#18384d", "text": "#e4f4fb", "soft_text": "#9bb9c8", "border": "#25485d", "selection": "#155e75", "selection_text": "#f0fdff", "accent": "#38bdf8", "accent_text": "#062033", "accent_hover": "#7dd3fc", "accent_pressed": "#0284c7", "success": "#5eead4", "warning": "#fbbf24", "danger": "#fb7185", "danger_text": "#ffffff", "danger_hover": "#fda4af", "danger_pressed": "#be123c", "secondary": "#a5f3fc", "hover": "#24516a", "scrollbar": "#326078", "titlebar": "#081521", "titlebar_text": "#e4f4fb"},
        "green": {"background": "#17231e", "surface": "#22332b", "raised": "#34483d", "text": "#e8f2eb", "soft_text": "#b1c5b7", "border": "#42594a", "selection": "#547b63", "selection_text": "#ffffff", "accent": "#9ac7a7", "accent_text": "#183123", "accent_hover": "#b9d9c2", "accent_pressed": "#6fa982", "success": "#a8d5a2", "warning": "#e8c98a", "danger": "#d98e8e", "danger_text": "#ffffff", "danger_hover": "#e9aaaa", "danger_pressed": "#a85f66", "secondary": "#a7c9bd", "hover": "#40574a", "scrollbar": "#60796a", "titlebar": "#17231e", "titlebar_text": "#e8f2eb"},
        "retro": {"background": "#160d26", "surface": "#24143b", "raised": "#351c50", "text": "#fff1fa", "soft_text": "#c4a8d8", "border": "#56336d", "selection": "#5b1b75", "selection_text": "#ffffff", "accent": "#00f5d4", "accent_text": "#120d27", "accent_hover": "#7bffeb", "accent_pressed": "#00bfa5", "success": "#a8ff60", "warning": "#ffe347", "danger": "#ff4fa3", "danger_text": "#ffffff", "danger_hover": "#ff83bd", "danger_pressed": "#c21870", "secondary": "#ff79c6", "hover": "#482461", "scrollbar": "#70428a", "titlebar": "#160d26", "titlebar_text": "#fff1fa"},
        "windows": {"background": "#c0c0c0", "surface": "#d4d0c8", "raised": "#c0c0c0", "text": "#000000", "soft_text": "#404040", "border": "#808080", "selection": "#000080", "selection_text": "#ffffff", "accent": "#000080", "accent_text": "#ffffff", "accent_hover": "#0000a0", "accent_pressed": "#000060", "success": "#008000", "warning": "#808000", "danger": "#800000", "danger_text": "#ffffff", "danger_hover": "#a00000", "danger_pressed": "#600000", "secondary": "#008080", "hover": "#d4d0c8", "scrollbar": "#808080", "titlebar": "#000080", "titlebar_text": "#ffffff"},
        "mac": {"background": "#d8d8d8", "surface": "#eeeeee", "raised": "#d0d0d0", "text": "#222222", "soft_text": "#666666", "border": "#a0a0a0", "selection": "#3875d7", "selection_text": "#ffffff", "accent": "#6b8fc9", "accent_text": "#ffffff", "accent_hover": "#8eacd9", "accent_pressed": "#4e70aa", "success": "#5a9b68", "warning": "#d19a45", "danger": "#c65d5d", "danger_text": "#ffffff", "danger_hover": "#dc7777", "danger_pressed": "#a94343", "secondary": "#7a9d9b", "hover": "#e4e4e4", "scrollbar": "#aaaaaa", "titlebar": "#c8c8c8", "titlebar_text": "#222222"},
        "black&white": {"background": "#101010", "surface": "#202020", "raised": "#303030", "text": "#f2f2f2", "soft_text": "#b0b0b0", "border": "#505050", "selection": "#707070", "selection_text": "#ffffff", "accent": "#b8b8b8", "accent_text": "#101010", "accent_hover": "#d0d0d0", "accent_pressed": "#888888", "success": "#d0d0d0", "warning": "#aaaaaa", "danger": "#888888", "danger_text": "#ffffff", "danger_hover": "#a0a0a0", "danger_pressed": "#606060", "secondary": "#c0c0c0", "hover": "#404040", "scrollbar": "#686868", "titlebar": "#101010", "titlebar_text": "#f2f2f2"},
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
        self.subtasks_path = Path(
            getattr(core_module, "SUBTAREAS_INI_PATH", "subtareas.ini")
        )
        self._fields: Dict[tuple[str, str], QWidget] = {}
        self._initial: Dict[tuple[str, str], str] = {}
        self._theme_preview: Optional[QGroupBox] = None
        self._theme_preview_label: Optional[QLabel] = None
        self._theme_preview_button: Optional[QPushButton] = None
        self.setWindowTitle("Configuración de Hercules")
        self.resize(820, 680)
        self.setMinimumSize(600, 420)
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget(self)
        layout.addWidget(self.tabs, 1)
        try:
            self._build_tabs()
            self._build_subtasks_tab()
        except OSError as exc:
            raise OSError(f"No se pudo leer la configuración: {exc}") from exc

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
        sections = [
            section for section in self.SECTION_TITLES if parser.has_section(section)
        ]
        sections.extend(
            section
            for section in parser.sections()
            if section not in sections and section not in {"Database", "Workspace"}
        )

        for section in sections:
            descriptions: Dict[str, str] = {}
            for key, description in scanned.get(section, []):
                descriptions.setdefault(key, description)
            keys = list(descriptions)
            keys.extend(key for key in parser.options(section) if key not in descriptions)
            if section == "LLM" and "database_path" not in keys:
                keys.insert(0, "database_path")
            elif section == "UI":
                keys = [
                    "theme",
                    "fullscreen",
                    "font_family",
                    "font_size",
                ]

            form = QFormLayout()
            form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
            form.setLabelAlignment(Qt.AlignmentFlag.AlignTop)
            for key in keys:
                self._add_setting(form, section, key, descriptions.get(key, ""))
                if section == "UI" and key == "font_family":
                    field = self._fields[("UI", "font_family")]
                    signal = (
                        field.currentTextChanged
                        if isinstance(field, QComboBox)
                        else field.textChanged
                    )
                    signal.connect(self._update_preview_font)
                elif section == "UI" and key == "font_size":
                    field = self._fields[("UI", "font_size")]
                    signal = (
                        field.currentTextChanged
                        if isinstance(field, QComboBox)
                        else field.textChanged
                    )
                    signal.connect(self._update_preview_font)

            if section == "UI":
                preview = self._build_theme_preview()
                form.addRow(preview)

            body = QWidget(self.tabs)
            body.setLayout(form)
            scroll = QScrollArea(self.tabs)
            scroll.setWidgetResizable(True)
            scroll.setWidget(body)
            self.tabs.addTab(scroll, self.SECTION_TITLES.get(section, section))

    def _build_theme_preview(self) -> QGroupBox:
        preview = QGroupBox("Vista previa", self.tabs)
        layout = QVBoxLayout(preview)
        self._theme_preview = preview
        self._theme_preview_label = QLabel(
            "Así se verá el texto con el tema y la tipografía seleccionados.", preview
        )
        self._theme_preview_label.setWordWrap(True)
        layout.addWidget(self._theme_preview_label)
        self._theme_preview_button = QPushButton("Botón de ejemplo", preview)
        layout.addWidget(self._theme_preview_button)

        self._fields[("UI", "theme")].currentIndexChanged.connect(
            self._update_theme_preview
        )
        self._update_theme_preview()
        self._update_preview_font()
        return preview

    def _update_theme_preview(self) -> None:
        if not self._theme_preview:
            return
        theme = self._field_value(self._fields[("UI", "theme")])
        palette = self.THEME_PALETTES.get(theme, self.THEME_PALETTES["dark"])
        self._theme_preview.setStyleSheet(
            f"QGroupBox {{ background: {palette['surface']}; color: {palette['text']}; "
            f"border: 1px solid {palette['border']}; border-radius: 6px; margin-top: 8px; }} "
            f"QLabel {{ background: transparent; color: {palette['text']}; }} "
            f"QPushButton {{ background: {palette['accent']}; color: {palette['accent_text']}; "
            "border: 0; border-radius: 4px; padding: 6px 12px; }"
        )

    def _update_preview_font(self, *_args: Any) -> None:
        if not self._theme_preview_label:
            return
        family = self._field_value(self._fields[("UI", "font_family")])
        try:
            size = int(self._field_value(self._fields[("UI", "font_size")]))
        except ValueError:
            size = self.config.ui_font_size
        font = QFont(family, size)
        self._theme_preview_label.setFont(font)
        self._theme_preview_button.setFont(font)

    def _build_subtasks_tab(self) -> None:
        try:
            self._initial_subtasks = self.subtasks_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            self._initial_subtasks = ""
        tab = QWidget(self.tabs)
        layout = QVBoxLayout(tab)
        help_label = QLabel(
            "Edita las etapas del plan en formato INI. Cada sección con una clave "
            "'prompt' define una subtarea; el orden de las secciones determina "
            "el orden de ejecución. Puedes usar {user_prompt} y los nombres de "
            "etapas anteriores como placeholders.",
            tab,
        )
        help_label.setWordWrap(True)
        layout.addWidget(help_label)
        self.subtasks_edit = QPlainTextEdit(tab)
        self.subtasks_edit.setPlainText(self._initial_subtasks)
        self.subtasks_edit.setTabStopDistance(
            4 * self.subtasks_edit.fontMetrics().horizontalAdvance(" ")
        )
        self.subtasks_edit.setPlaceholderText("[ANALIZAR]\\nprompt = ...")
        layout.addWidget(self.subtasks_edit, 1)
        self.tabs.addTab(tab, self.SUBTASKS_TAB_TITLE)

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

        setting_labels = {
            ("LLM", "database_path"): "Base de datos",
            ("UI", "theme"): "Tema",
            ("UI", "fullscreen"): "Iniciar en pantalla completa",
            ("UI", "font_family"): "Tipografía",
            ("UI", "font_size"): "Tamaño de fuente",
        }
        label = QLabel(setting_labels.get(field_key, key))
        label.setToolTip(description)
        choices = self.CHOICES.get(field_key)
        if field_key == ("UI", "theme"):
            choices = tuple(self.THEMES)
        elif field_key == ("UI", "font_family"):
            choices = tuple(QFontDatabase.families())
        elif field_key == ("UI", "font_size"):
            choices = tuple(str(size) for size in range(8, 25))
        elif field_key == ("LLM", "database_path"):
            choices = None
        if choices is None and (
            default.lower() in {"true", "false"}
            or value.lower() in {"true", "false"}
        ):
            choices = ("true", "false")

        if choices:
            field = QComboBox()
            if field_key == ("UI", "theme"):
                for theme, title in self.THEMES.items():
                    field.addItem(title, theme)
                current_index = field.findData(value)
            else:
                field.addItems(choices)
                current_index = field.findText(value, Qt.MatchFlag.MatchFixedString)
            if current_index >= 0:
                field.setCurrentIndex(current_index)
            elif field_key != ("UI", "theme"):
                field.setCurrentText(value)
        else:
            field = QLineEdit(value)
            if key == "api_key":
                field.setEchoMode(QLineEdit.EchoMode.Password)
        field.setToolTip(description)
        if field_key == ("UI", "theme"):
            field.setProperty("setting_key", "theme")

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
            if field.property("setting_key") == "theme":
                return str(field.currentData())
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
            if (section, key) == ("UI", "theme"):
                palette = self.THEME_PALETTES.get(value)
                if palette:
                    ui_defaults = self.core.Config.DEFAULTS.get("UI", {})
                    for role, keys in self.THEME_ROLES.items():
                        color = palette[role]
                        for color_key in keys:
                            if color_key in ui_defaults:
                                updates.setdefault("UI", {})[color_key] = color

        subtasks_text = self.subtasks_edit.toPlainText()
        subtasks_changed = subtasks_text != self._initial_subtasks
        if subtasks_changed:
            try:
                configparser.ConfigParser(interpolation=None).read_string(subtasks_text)
            except configparser.Error as exc:
                QMessageBox.critical(
                    self,
                    "Plan de subtareas no válido",
                    f"Corrige el formato INI antes de guardar:\n{exc}",
                )
                return

        if not updates and not subtasks_changed:
            self.accept()
            return
        try:
            if updates:
                self.core._update_config_file(str(self.config_path), updates)
            if subtasks_changed:
                self.subtasks_path.write_text(subtasks_text, encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(
                self,
                "Error al guardar",
                f"No se pudo escribir la configuración:\n{exc}",
            )
            return
        QMessageBox.information(
            self,
            "Ajustes guardados",
            "Reinicia Hercules para aplicar los cambios.",
        )
        self.accept()


class AnimatedProgressBar(QProgressBar):
    """Progress bar with a moving gradient border while a task is running."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._generating = False
        self._gradient_offset = 0.0
        self._gradient_timer = QTimer(self)
        self._gradient_timer.setInterval(35)
        self._gradient_timer.timeout.connect(self._advance_gradient)

    def set_generating(self, generating: bool) -> None:
        if self._generating == generating:
            return
        self._generating = generating
        if generating:
            self._gradient_timer.start()
        else:
            self._gradient_timer.stop()
        self.update()

    def _advance_gradient(self) -> None:
        self._gradient_offset = (self._gradient_offset + 0.015) % 1.0
        self.update()

    def paintEvent(self, event: Any) -> None:
        super().paintEvent(event)
        if not self._generating:
            return

        rect = self.rect().adjusted(1, 1, -1, -1)
        path = QPainterPath()
        path.addRoundedRect(rect, 5, 5)
        gradient = QConicalGradient(rect.center(), self._gradient_offset * 360)
        gradient.setColorAt(0.0, QColor("#00d4ff"))
        gradient.setColorAt(0.5, QColor("#b44cff"))
        gradient.setColorAt(1.0, QColor("#00d4ff"))
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(gradient, 3))
        painter.drawPath(path)


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
        self._browser_tool_bridge: Optional[BrowserToolBridge] = None
        self._register_browser_tools()
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
        self._tree_signatures: Dict[int, Any] = {}
        self._history_last_id = 0

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

    def _register_browser_tools(self) -> None:
        register = getattr(self.tools, "register", None)
        if not callable(register):
            return
        self._browser_tool_bridge = BrowserToolBridge(self)
        definitions = [
            ("browser_navigate", "Navega en el navegador integrado a una URL HTTP(S) o documento local del workspace.", {"url": {"type": "string", "description": "URL HTTP(S) o file:// dentro del workspace."}}, ["url"], "navigate"),
            ("browser_snapshot", "Devuelve título, texto y controles visibles de la página abierta en el navegador integrado.", {}, [], "snapshot"),
            ("browser_click", "Hace clic en un elemento de la página seleccionándolo con un selector CSS.", {"selector": {"type": "string", "description": "Selector CSS del elemento."}}, ["selector"], "click"),
            ("browser_fill", "Rellena un campo de formulario seleccionado con un selector CSS.", {"selector": {"type": "string", "description": "Selector CSS del campo."}, "text": {"type": "string", "description": "Texto que se escribirá."}}, ["selector", "text"], "fill"),
            (
                "browser_scroll",
                "Desplaza la página del navegador integrado hacia arriba o abajo.",
                {
                    "direction": {
                        "type": "string",
                        "enum": ["up", "down"],
                        "description": "Dirección del desplazamiento.",
                    },
                    "amount": {
                        "type": "integer",
                        "description": "Distancia en píxeles; por defecto 600.",
                    },
                },
                ["direction"],
                "scroll",
            ),
            (
                "browser_press_key",
                "Envía una tecla nativa al navegador integrado. Las teclas especiales "
                "pueden indicarse entre corchetes, por ejemplo [Enter] o [ArrowDown].",
                {
                    "key": {
                        "type": "string",
                        "description": (
                            "Nombre de la tecla, por ejemplo Enter, Escape o [ArrowDown]."
                        ),
                    }
                },
                ["key"],
                "press_key",
            ),
            ("browser_screenshot", "Captura el navegador integrado y adjunta la imagen para que el modelo pueda analizarla.", {"path": {"type": "string", "description": "Ruta de salida opcional, relativa al workspace."}}, [], "screenshot"),
            ("browser_back", "Retrocede en el historial del navegador integrado.", {}, [], "back"),
            ("browser_forward", "Avanza en el historial del navegador integrado.", {}, [], "forward"),
            ("browser_reload", "Recarga la página del navegador integrado.", {}, [], "reload"),
        ]
        for name, description, properties, required, action in definitions:
            register(self.core.ToolDefinition(
                name=name,
                description=description,
                risk=self.core.RiskLevel.SAFE,
                parameters={"type": "object", "properties": properties, "required": required},
                runner=lambda arguments, browser_action=action: self._browser_tool_bridge.run(browser_action, arguments),
            ))

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
        self._application_font = QFont(
            self.config.ui_font_family, self.config.ui_font_size
        )
        self.setFont(self._application_font)
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

        self._build_workspace_tools_panel(columns)
        columns.setSizes([650, 950])

        status = QWidget(self)
        status_layout = QHBoxLayout(status)
        status_layout.setContentsMargins(10, 4, 10, 6)
        status_layout.addWidget(QLabel("Contexto:", status))
        self.context_bar = AnimatedProgressBar(status)
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

    def _build_explorer_panel(self, parent: QTabWidget) -> None:
        panel = QWidget(parent)
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
        parent.addTab(panel, "Explorador")

    def _build_workspace_tools_panel(self, parent: QWidget) -> None:
        panel = QGroupBox("Terminal, navegador y explorador", parent)
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
        self._build_explorer_panel(self.workspace_tabs)
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

    def _subtasks_by_parent(self, tasks: list[Any]) -> Dict[int, list[Any]]:
        """Obtiene las subtareas de todos los padres con una sola consulta."""
        parent_ids = [task.id for task in tasks if task.id is not None]
        many = getattr(self.db, "list_subtasks_many", None)
        if callable(many):
            return many(parent_ids)
        return {pid: self.db.list_subtasks(pid) for pid in parent_ids}

    def _populate_task_tree(self, tree: QTreeWidget, tasks: list[Any]) -> None:
        selected_id = self.selected_task_id
        subtasks_by_parent = self._subtasks_by_parent(tasks)
        # Reconstruir el árbol cada segundo reinicia el scroll y la selección;
        # solo se rehace si algo ha cambiado desde la última vez.
        signature = (
            selected_id,
            tuple(
                (
                    task.id,
                    task.title,
                    task.status.value,
                    tuple(
                        (sub.id, sub.title, sub.status.value)
                        for sub in subtasks_by_parent.get(task.id, [])
                    ),
                )
                for task in tasks
            ),
        )
        if self._tree_signatures.get(id(tree)) == signature:
            return
        self._tree_signatures[id(tree)] = signature
        tree.setUpdatesEnabled(False)
        tree.blockSignals(True)
        try:
            scroll_bar = tree.verticalScrollBar()
            scroll_value = scroll_bar.value()
            tree.clear()
            for task in tasks:
                item = self._task_item(task)
                tree.addTopLevelItem(item)
                for subtask in subtasks_by_parent.get(task.id, []):
                    item.addChild(self._task_item(subtask))
                item.setExpanded(True)
                if task.id == selected_id:
                    tree.setCurrentItem(item)
                for index in range(item.childCount()):
                    child = item.child(index)
                    if child.data(0, Qt.ItemDataRole.UserRole) == selected_id:
                        tree.setCurrentItem(child)
            scroll_bar.setValue(scroll_value)
        finally:
            tree.blockSignals(False)
            tree.setUpdatesEnabled(True)

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
        """Muestra el historial completo de una tarea (render desde cero)."""
        self.selected_task_id = task_id
        self._history_last_id = 0
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
        self._update_history_title(task)
        self.history_view.setUpdatesEnabled(False)
        try:
            self.history_view.clear()
            self._append_history_entries(task_id, self.db.get_history(task_id))
        finally:
            self.history_view.setUpdatesEnabled(True)
        self.history_view.moveCursor(QTextCursor.MoveOperation.End)
        self._refresh_context_bar()

    def _update_history_title(self, task: Any) -> None:
        parent_suffix = (
            f" · subtarea de #{task.parent_task_id}"
            if task.parent_task_id is not None
            else ""
        )
        self.history_title.setText(
            f"Tarea #{task.id} — {task.title} [{task.status.value}]{parent_suffix}"
        )

    def _refresh_history_incremental(self, task_id: int) -> None:
        """
        Añade solo las entradas nuevas al historial de la tarea seleccionada.

        Repintar todo el historial en cada evento es O(n²) y congela la GUI en
        tareas largas. Si la BD no admite lectura incremental se hace el render
        completo.
        """
        fetch_after = getattr(self.db, "get_history_after", None)
        if not callable(fetch_after):
            self._select_task(task_id)
            return
        entries = fetch_after(task_id, self._history_last_id)
        if not entries:
            return
        scroll_bar = self.history_view.verticalScrollBar()
        follow_tail = scroll_bar.value() >= scroll_bar.maximum() - 4
        self._append_history_entries(task_id, entries)
        if follow_tail:
            self.history_view.moveCursor(QTextCursor.MoveOperation.End)

    def _history_colors(self) -> Dict[str, tuple[str, bool]]:
        et = self.core.EventType
        return {
            et.THOUGHT.value: ("ui_thought_fg", True),
            et.TOOL_CALL.value: ("ui_tool_call_fg", False),
            et.TOOL_RESULT.value: ("ui_tool_result_fg", False),
            et.FINAL_ANSWER.value: ("ui_final_answer_fg", True),
            et.ERROR.value: ("ui_error_fg", False),
            et.STATUS_CHANGE.value: ("ui_status_change_fg", False),
            et.INFO.value: ("ui_info_fg", False),
            et.LOOP_DETECTED.value: ("ui_loop_detected_fg", False),
            et.CONTEXT_COMPACTED.value: ("ui_context_compacted_fg", False),
            et.CONTEXT_OVERFLOW.value: ("ui_context_overflow_fg", False),
        }

    def _append_history_entries(self, task_id: int, entries: Any) -> None:
        colors = self._history_colors()
        cursor = QTextCursor(self.history_view.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        for entry in entries:
            entry_id = getattr(entry, "id", None)
            if isinstance(entry_id, int):
                self._history_last_id = max(self._history_last_id, entry_id)
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
                f"[{entry.timestamp}] {label}\n{entry.content}\n\n",
                text_format,
            )

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
        self.context_bar.set_generating(True)

        def run_task() -> None:
            try:
                self.orchestrator.run(task, cancel_event=cancel_event)
            except Exception:
                # Sin consola (build Nuitka) print_exc no deja rastro: se
                # registra también en el log de aplicación.
                logging.getLogger("hercules").exception("Fallo en la tarea %s", task.id)
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
        self.context_bar.set_generating(False)
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

    # Máximo de tiempo que un tick del temporizador dedica a vaciar la cola.
    POLL_BUDGET_SECONDS = 0.05

    def _poll_queue(self) -> None:
        """
        Procesa los eventos pendientes sin monopolizar el hilo de la GUI.

        - Presupuesto de tiempo por tick: una ráfaga de eventos no congela la
          ventana; el resto se atiende en el siguiente tick.
        - Los eventos repetidos de refresco (historial, estado, explorador) se
          agrupan: basta un refresco por tick.
        - Un fallo al tratar un evento se registra y no impide procesar los
          demás ni mata el temporizador.
        """
        deadline = time.monotonic() + self.POLL_BUDGET_SECONDS
        refresh_history_for: set[int] = set()
        refresh_tasks = False
        refresh_files = False
        while time.monotonic() < deadline:
            try:
                event = self.ui_queue.get_nowait()
            except queue.Empty:
                break
            event_type = event.get("type")
            if event_type == "history_update":
                task_id = event.get("task_id")
                if task_id is not None and task_id == self.selected_task_id:
                    refresh_history_for.add(task_id)
                continue
            if event_type == "status_change":
                refresh_tasks = True
                continue
            if event_type == "refresh_file_browser":
                refresh_files = True
                continue
            self._safe_handle_event(event)
        if refresh_tasks:
            self._safe_handle_event({"type": "status_change"})
        for task_id in refresh_history_for:
            try:
                if task_id == self.selected_task_id:
                    self._refresh_history_incremental(task_id)
            except Exception:  # noqa: BLE001
                logging.getLogger("hercules").exception("Error actualizando el historial")
        if refresh_files:
            self._safe_handle_event({"type": "refresh_file_browser"})

    def _safe_handle_event(self, event: Dict[str, Any]) -> None:
        try:
            self._handle_event(event)
        except Exception:  # noqa: BLE001
            logging.getLogger("hercules").exception(
                "Error al procesar el evento de interfaz %r", event.get("type")
            )

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
            elif self.selected_task_id is not None:
                task = self.db.get_task(self.selected_task_id)
                if task is not None:
                    self._update_history_title(task)
        elif event_type == "history_update":
            if event.get("task_id") == self.selected_task_id:
                self._refresh_history_incremental(self.selected_task_id)
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
        elif event_type == "show_file":
            self._show_changed_file(str(event.get("path", "")))
        elif event_type == "terminal_command":
            self._activate_terminal()
            terminal_path = str(self.workspace).replace("\\", "/")
            if len(terminal_path) > 1 and terminal_path[1] == ":":
                terminal_path = terminal_path[2:]
            self._append_terminal_text(
                f"{terminal_path}> {event.get('command', '')}\n"
            )
        elif event_type == "terminal_output":
            self._activate_terminal()
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

    def _activate_terminal(self) -> None:
        terminal_index = self.workspace_tabs.indexOf(self.terminal_view.parentWidget())
        if terminal_index >= 0:
            self.workspace_tabs.setCurrentIndex(terminal_index)

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
        if len(description) > APPROVAL_DISPLAY_MAX_CHARS:
            description = description[: APPROVAL_DISPLAY_MAX_CHARS - 1] + "…"
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

    def _show_changed_file(self, raw_path: str) -> None:
        if not raw_path:
            return
        path = Path(raw_path)
        if not path.is_absolute():
            path = self.workspace / path
        path = path.resolve()
        if not _is_within_workspace(path, self.workspace) or not path.is_file():
            return
        self.workspace_tabs.setCurrentIndex(
            self.workspace_tabs.indexOf(self.web_view.parentWidget())
        )
        url = QUrl.fromLocalFile(str(path))
        if self.web_view.url() == url:
            self.web_view.reload()
        else:
            self.web_view.setUrl(url)

    def _load_local_document(self, path: Path) -> None:
        if not path.is_file():
            return
        browser_index = self.workspace_tabs.indexOf(self.web_view.parentWidget())
        if browser_index >= 0:
            self.workspace_tabs.setCurrentIndex(browser_index)
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
