#!/usr/bin/env python3
"""
hercules.py

Agente LLM Autónomo con Control de Permisos (HITL - Human-in-the-Loop).

Desarrollado exclusivamente con la biblioteca estándar de Python (cero dependencias externas).

Características:
    - Gestión del ciclo de vida de tareas (PENDING, IN_PROGRESS, AWAITING_APPROVAL,
      COMPLETED, FAILED, CANCELLED).
    - Control de seguridad humano: validación manual de acciones sensibles.
    - Trazabilidad completa: historial estructurado y auditable por tarea.
    - Dashboard interactivo (tkinter) con 4 zonas:
        1. Entrada de prompt + botón Ejecutar.
        2. Tablero de tareas en 2 columnas (pendientes vs ejecutadas).
        3. Registro de trazabilidad por tarea seleccionada.
        4. Aviso emergente de aprobación (Permitir / Cancelar).
    - Persistencia local en SQLite.
    - Conector HTTP para LLMs compatibles con OpenAI / Ollama.

Configuración mediante variables de entorno:
    LLM_BASE_URL   - URL base del endpoint (por defecto: http://localhost:11434/v1)
    LLM_API_KEY    - Clave de API (opcional para Ollama)
    LLM_MODEL      - Modelo a utilizar (por defecto: llama3.2)
    LLM_TIMEOUT    - Timeout en segundos (por defecto: 120)
"""

from __future__ import annotations

import collections
import configparser
import json
import os
import queue
import shlex
import sqlite3
import subprocess
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
import webbrowser
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from tkinter import BooleanVar, Canvas, Tk, StringVar, Text, Toplevel, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any, Callable, Dict, List, Optional, Tuple


# ============================================================================
# CONFIGURACIÓN (config.ini + variables de entorno)
# ============================================================================

CONFIG_PATH = os.environ.get("HERCULES_CONFIG", "config.ini")
SUBTAREAS_INI_PATH = os.environ.get("HERCULES_SUBTAREAS_INI", "subtareas.ini")


def _str_to_bool(value: str) -> bool:
    """Convierte una cadena a booleano (true/1/yes -> True)."""
    return value.strip().lower() in ("true", "1", "yes", "si", "sí", "on")


class Config:
    """
    Carga la configuración desde config.ini con fallback a variables de entorno.

    Prioridad (de mayor a menor):
        1. Variables de entorno (HERCULES_* y LLM_*)
        2. Fichero config.ini
        3. Valores por defecto
    """

    DEFAULTS: Dict[str, Dict[str, str]] = {
        "LLM": {
            "mode": "local",
            "base_url": "http://localhost:8080/v1",
            "api_key": "",
            "model": "Qwen3-4B-Instruct-2507-Q4_K_M.gguf",
            "model_path": "modelos",
            "timeout": "120",
            "n_ctx": "8192",
            "n_threads": "8",
            "n_gpu_layers": "0",
        },
        "Workspace": {
            "path": "./workspace",
        },
        "Database": {
            "path": "hercules.db",
        },
        "Agent": {
            "max_iterations": "10",
            "loop_threshold": "5",
            "max_rectification_retries": "3",
            "context_compact_threshold": "80",
        },
        "UI": {
            "fullscreen": "false",
            "bg_color": "#1e1e1e",
            "fg_color": "#e0e0e0",
            "frame_bg": "#252526",
            "card_bg": "#2d2d30",
            "prompt_bg": "#1e1e1e",
            "prompt_fg": "#e0e0e0",
            "history_bg": "#1e1e1e",
            "history_fg": "#d4d4d4",
            "approval_bg": "#1e1e1e",
            "approval_fg": "#b6eea8",
            "approval_request_bg": "#1e1e1e",
            "approval_request_fg": "#a88647",
            "approval_granted_bg": "#1e1e1e",
            "approval_granted_fg": "#388e3c",
            "approval_denied_bg": "#1e1e1e",
            "approval_denied_fg": "#d32f2f",
            "final_answer_fg": "#4caf50",
            "thought_fg": "#e65100",
            "info_fg": "#fbc02d",
            "tool_call_fg": "#4fc3f7",
            "tool_result_fg": "#80cbc4",
            "approval_request_fg": "#ffb74d",
            "approval_granted_fg": "#66bb6a",
            "approval_denied_fg": "#ef5350",
            "error_fg": "#ef5350",
            "status_change_fg": "#b0bec5",
            "loop_detected_fg": "#ce93d8",
            "context_compacted_fg": "#ce93d8",
            "status_pending": "#9e9e9e",
            "status_in_progress": "#4fc3f7",
            "status_awaiting_approval": "#ffb74d",
            "status_completed": "#66bb6a",
            "status_failed": "#ef5350",
            "status_cancelled": "#9e9e9e",
            "font_family": "Segoe UI",
            "font_size": "10",
            "mono_font_family": "Consolas",
            "mono_font_size": "10",
            "context_bar_bg": "#e0e0e0",
            "context_bar_low": "#4caf50",
            "context_bar_medium": "#ff9800",
            "context_bar_high": "#f44336",
            "browser_bg": "#2d2d30",
            "browser_fg": "#e0e0e0",
            "browser_header_bg": "#252526",
            "browser_selected_bg": "#264f78",
            "browser_selected_fg": "#ffffff",
            "button_bg": "#3c3c3c",
            "button_fg": "#e0e0e0",
            "checkbox_bg": "#2d2d30",
            "checkbox_fg": "#e0e0e0",
        },
    }

    def __init__(self, path: str = CONFIG_PATH) -> None:
        self._path = path
        self._parser = configparser.ConfigParser()
        # Cargar valores por defecto primero.
        self._parser.read_dict(self.DEFAULTS)
        # Sobrescribir con config.ini si existe.
        if os.path.exists(path):
            try:
                self._parser.read(path, encoding="utf-8")
            except configparser.Error as e:
                print(f"[AVISO] Error leyendo {path}: {e}. Usando valores por defecto.")

    # --- LLM ---

    @property
    def llm_base_url(self) -> str:
        return os.environ.get(
            "LLM_BASE_URL", self._parser.get("LLM", "base_url")
        ).rstrip("/")

    @property
    def llm_api_key(self) -> str:
        return os.environ.get("LLM_API_KEY", self._parser.get("LLM", "api_key"))

    @property
    def llm_model(self) -> str:
        return os.environ.get("LLM_MODEL", self._parser.get("LLM", "model"))

    @property
    def llm_timeout(self) -> float:
        env_val = os.environ.get("LLM_TIMEOUT")
        if env_val:
            return float(env_val)
        return self._parser.getfloat("LLM", "timeout")

    @property
    def llm_mode(self) -> str:
        env_val = os.environ.get("LLM_MODE")
        if env_val:
            return env_val.strip().lower()
        return self._parser.get("LLM", "mode").strip().lower()

    @property
    def llm_model_path(self) -> str:
        return os.environ.get("LLM_MODEL_PATH", self._parser.get("LLM", "model_path"))

    @property
    def llm_n_ctx(self) -> int:
        env_val = os.environ.get("LLM_N_CTX")
        if env_val:
            return int(env_val)
        return self._parser.getint("LLM", "n_ctx")

    @property
    def llm_n_threads(self) -> int:
        env_val = os.environ.get("LLM_N_THREADS")
        if env_val:
            return int(env_val)
        return self._parser.getint("LLM", "n_threads")

    @property
    def llm_n_gpu_layers(self) -> int:
        env_val = os.environ.get("LLM_N_GPU_LAYERS")
        if env_val:
            return int(env_val)
        return self._parser.getint("LLM", "n_gpu_layers")

    # --- Workspace ---

    @property
    def workspace_path(self) -> str:
        return os.environ.get(
            "HERCULES_WORKSPACE", self._parser.get("Workspace", "path")
        )

    # --- Database ---

    @property
    def db_path(self) -> str:
        return os.environ.get("HERCULES_DB", self._parser.get("Database", "path"))

    # --- Agent ---

    @property
    def max_iterations(self) -> int:
        env_val = os.environ.get("HERCULES_MAX_ITER")
        if env_val:
            return int(env_val)
        return self._parser.getint("Agent", "max_iterations")

    @property
    def loop_threshold(self) -> int:
        env_val = os.environ.get("HERCULES_LOOP_THRESHOLD")
        if env_val:
            return int(env_val)
        return self._parser.getint("Agent", "loop_threshold")

    @property
    def max_rectification_retries(self) -> int:
        env_val = os.environ.get("HERCULES_MAX_RECTIFICATION_RETRIES")
        if env_val:
            return int(env_val)
        return self._parser.getint("Agent", "max_rectification_retries")

    @property
    def context_compact_threshold(self) -> int:
        """
        Umbral (en porcentaje, 1-100) del contexto a partir del cual
        se compacta automáticamente antes de enviar al modelo.

        Si el valor está fuera del rango válido, se limita a [1, 100].
        """
        env_val = os.environ.get("HERCULES_CONTEXT_COMPACT_THRESHOLD")
        if env_val:
            try:
                value = int(env_val)
            except ValueError:
                value = self._parser.getint("Agent", "context_compact_threshold")
        else:
            value = self._parser.getint("Agent", "context_compact_threshold")
        return max(1, min(100, value))

    # --- UI ---

    @property
    def ui_fullscreen(self) -> bool:
        env_val = os.environ.get("HERCULES_FULLSCREEN")
        if env_val is not None:
            return _str_to_bool(env_val)
        return self._parser.getboolean("UI", "fullscreen")

    @property
    def ui_bg_color(self) -> str:
        return self._parser.get("UI", "bg_color")

    @property
    def ui_fg_color(self) -> str:
        return self._parser.get("UI", "fg_color")

    @property
    def ui_frame_bg(self) -> str:
        return self._parser.get("UI", "frame_bg")

    @property
    def ui_card_bg(self) -> str:
        return self._parser.get("UI", "card_bg")

    @property
    def ui_browser_bg(self) -> str:
        return self._parser.get("UI", "browser_bg")

    @property
    def ui_browser_fg(self) -> str:
        return self._parser.get("UI", "browser_fg")

    @property
    def ui_browser_header_bg(self) -> str:
        return self._parser.get("UI", "browser_header_bg")

    @property
    def ui_browser_selected_bg(self) -> str:
        return self._parser.get("UI", "browser_selected_bg")

    @property
    def ui_browser_selected_fg(self) -> str:
        return self._parser.get("UI", "browser_selected_fg")

    @property
    def ui_prompt_bg(self) -> str:
        return self._parser.get("UI", "prompt_bg")

    @property
    def ui_prompt_fg(self) -> str:
        return self._parser.get("UI", "prompt_fg")

    @property
    def ui_history_bg(self) -> str:
        return self._parser.get("UI", "history_bg")

    @property
    def ui_history_fg(self) -> str:
        return self._parser.get("UI", "history_fg")

    @property
    def ui_approval_bg(self) -> str:
        return self._parser.get("UI", "approval_bg")

    @property
    def ui_approval_fg(self) -> str:
        return self._parser.get("UI", "approval_fg")

    @property
    def ui_approval_request_bg(self) -> str:
        return self._parser.get("UI", "approval_request_bg")

    @property
    def ui_approval_request_fg(self) -> str:
        return self._parser.get("UI", "approval_request_fg")

    @property
    def ui_approval_granted_bg(self) -> str:
        return self._parser.get("UI", "approval_granted_bg")

    @property
    def ui_approval_granted_fg(self) -> str:
        return self._parser.get("UI", "approval_granted_fg")

    @property
    def ui_approval_denied_bg(self) -> str:
        return self._parser.get("UI", "approval_denied_bg")

    @property
    def ui_approval_denied_fg(self) -> str:
        return self._parser.get("UI", "approval_denied_fg")

    @property
    def ui_final_answer_fg(self) -> str:
        return self._parser.get("UI", "final_answer_fg")

    @property
    def ui_thought_fg(self) -> str:
        return self._parser.get("UI", "thought_fg")

    @property
    def ui_info_fg(self) -> str:
        return self._parser.get("UI", "info_fg")

    @property
    def ui_tool_call_fg(self) -> str:
        return self._parser.get("UI", "tool_call_fg")

    @property
    def ui_tool_result_fg(self) -> str:
        return self._parser.get("UI", "tool_result_fg")

    @property
    def ui_approval_request_fg(self) -> str:
        return self._parser.get("UI", "approval_request_fg")

    @property
    def ui_approval_granted_fg(self) -> str:
        return self._parser.get("UI", "approval_granted_fg")

    @property
    def ui_approval_denied_fg(self) -> str:
        return self._parser.get("UI", "approval_denied_fg")

    @property
    def ui_error_fg(self) -> str:
        return self._parser.get("UI", "error_fg")

    @property
    def ui_status_change_fg(self) -> str:
        return self._parser.get("UI", "status_change_fg")

    @property
    def ui_loop_detected_fg(self) -> str:
        return self._parser.get("UI", "loop_detected_fg")

    @property
    def ui_context_compacted_fg(self) -> str:
        return self._parser.get("UI", "context_compacted_fg")

    @property
    def ui_status_pending(self) -> str:
        return self._parser.get("UI", "status_pending")

    @property
    def ui_status_in_progress(self) -> str:
        return self._parser.get("UI", "status_in_progress")

    @property
    def ui_status_awaiting_approval(self) -> str:
        return self._parser.get("UI", "status_awaiting_approval")

    @property
    def ui_status_completed(self) -> str:
        return self._parser.get("UI", "status_completed")

    @property
    def ui_status_failed(self) -> str:
        return self._parser.get("UI", "status_failed")

    @property
    def ui_status_cancelled(self) -> str:
        return self._parser.get("UI", "status_cancelled")

    @property
    def ui_font_family(self) -> str:
        return self._parser.get("UI", "font_family")

    @property
    def ui_font_size(self) -> int:
        return self._parser.getint("UI", "font_size")

    @property
    def ui_mono_font_family(self) -> str:
        return self._parser.get("UI", "mono_font_family")

    @property
    def ui_mono_font_size(self) -> int:
        return self._parser.getint("UI", "mono_font_size")

    @property
    def ui_context_bar_bg(self) -> str:
        return self._parser.get("UI", "context_bar_bg")

    @property
    def ui_context_bar_low(self) -> str:
        return self._parser.get("UI", "context_bar_low")

    @property
    def ui_context_bar_medium(self) -> str:
        return self._parser.get("UI", "context_bar_medium")

    @property
    def ui_context_bar_high(self) -> str:
        return self._parser.get("UI", "context_bar_high")

    @property
    def ui_button_bg(self) -> str:
        return self._parser.get("UI", "button_bg")

    @property
    def ui_button_fg(self) -> str:
        return self._parser.get("UI", "button_fg")

    @property
    def ui_checkbox_bg(self) -> str:
        return self._parser.get("UI", "checkbox_bg")

    @property
    def ui_checkbox_fg(self) -> str:
        return self._parser.get("UI", "checkbox_fg")


# Instancia global de configuración.
CONFIG = Config()

# Aliases para compatibilidad con el resto del código.
DB_PATH = CONFIG.db_path
MAX_ITERATIONS = CONFIG.max_iterations
LOOP_THRESHOLD = CONFIG.loop_threshold
MAX_RECTIFICATION_RETRIES = CONFIG.max_rectification_retries
CONTEXT_COMPACT_THRESHOLD = CONFIG.context_compact_threshold
LLM_MODE = CONFIG.llm_mode
LLM_BASE_URL = CONFIG.llm_base_url
LLM_API_KEY = CONFIG.llm_api_key
LLM_MODEL = CONFIG.llm_model
LLM_MODEL_PATH = CONFIG.llm_model_path
LLM_TIMEOUT = CONFIG.llm_timeout
LLM_N_CTX = CONFIG.llm_n_ctx
LLM_N_THREADS = CONFIG.llm_n_threads
LLM_N_GPU_LAYERS = CONFIG.llm_n_gpu_layers

# Directorio del script (para resolver rutas relativas como modelos/).
SCRIPT_DIR = Path(__file__).parent.resolve()

# Directorio de trabajo restringido para operaciones de archivos
WORKSPACE_DIR = Path(CONFIG.workspace_path).resolve()
WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================================
# ENUMERACIONES
# ============================================================================

class TaskStatus(str, Enum):
    """Estados posibles de una tarea."""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    # Estados terminales: la tarea ya terminó (con éxito, fallo o cancelación)
    # y NO deben borrarse en la limpieza de arranque.
    TERMINAL_STATUSES = frozenset({COMPLETED, FAILED, CANCELLED})

    @classmethod
    def unfinished(cls) -> List["TaskStatus"]:
        """Estados de tareas que NO han terminado y deben limpiarse al iniciar."""
        return [s for s in cls if s not in cls.TERMINAL_STATUSES]  # type: ignore[attr-defined]  # noqa: F821


class RiskLevel(str, Enum):
    """Niveles de riesgo de una herramienta."""
    SAFE = "SAFE"          # Lectura / consulta: ejecución automática.
    CRITICAL = "CRITICAL"  # Escritura / comandos: requiere aprobación humana.


class EventType(str, Enum):
    """Tipos de evento registrados en el historial."""
    THOUGHT = "thought"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    APPROVAL_REQUEST = "approval_request"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    FINAL_ANSWER = "final_answer"
    ERROR = "error"
    STATUS_CHANGE = "status_change"
    INFO = "info"
    LOOP_DETECTED = "loop_detected"
    CONTEXT_COMPACTED = "context_compacted"
    SUBTASK_CREATED = "subtask_created"
    SUBTASK_STARTED = "subtask_started"
    SUBTASK_COMPLETED = "subtask_completed"
    SUBTASK_FAILED = "subtask_failed"
    ORCHESTRATION_DECISION = "orchestration_decision"
    PREAUTHORIZATION_REQUEST = "preauthorization_request"
    PREAUTHORIZATION_GRANTED = "preauthorization_granted"
    PREAUTHORIZATION_DENIED = "preauthorization_denied"


class SubtaskType(str, Enum):
    """
    Tipos de subtarea dentro del flujo de descomposición.

    Flujo normal:
        REQUIREMENTS -> DEVELOPMENT -> EXECUTION_VERIFICATION

    Si EXECUTION_VERIFICATION falla, se inserta:
        RECTIFICATION -> EXECUTION_VERIFICATION (reintento)

    El ciclo se repite hasta que la verificación sea exitosa o se
    alcance ``max_rectification_retries``.
    """
    REQUIREMENTS = "REQUIREMENTS"
    DEVELOPMENT = "DEVELOPMENT"
    EXECUTION_VERIFICATION = "EXECUTION_VERIFICATION"
    RECTIFICATION = "RECTIFICATION"

    @property
    def label(self) -> str:
        """Etiqueta legible para mostrar en la UI."""
        return _SUBTASK_LABELS.get(self, self.value)

    @property
    def icon(self) -> str:
        """Icono representativo para el tablero."""
        return _SUBTASK_ICONS.get(self, "•")


_SUBTASK_LABELS: Dict[SubtaskType, str] = {
    SubtaskType.REQUIREMENTS: "Requisitos técnicos",
    SubtaskType.DEVELOPMENT: "Desarrollo de la solución",
    SubtaskType.EXECUTION_VERIFICATION: "Ejecución y comprobación",
    SubtaskType.RECTIFICATION: "Rectificación de la solución",
}

_SUBTASK_ICONS: Dict[SubtaskType, str] = {
    SubtaskType.REQUIREMENTS: "📋",
    SubtaskType.DEVELOPMENT: "🛠",
    SubtaskType.EXECUTION_VERIFICATION: "✅",
    SubtaskType.RECTIFICATION: "🔧",
}


# ============================================================================
# MODELOS DE DATOS
# ============================================================================

@dataclass
class Task:
    """Representa una tarea del agente."""
    id: Optional[int]
    title: str
    prompt: str
    status: TaskStatus
    created_at: str
    updated_at: str
    final_answer: Optional[str] = None
    # --- Descomposición en subtareas ---
    parent_task_id: Optional[int] = None
    subtask_type: Optional[SubtaskType] = None
    attempt_number: int = 0


@dataclass
class HistoryEntry:
    """Entrada del historial de una tarea."""
    id: Optional[int]
    task_id: int
    timestamp: str
    event_type: EventType
    content: str


@dataclass
class ToolCall:
    """Llamada a una herramienta solicitada por el LLM."""
    id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class ToolResult:
    """Resultado de la ejecución de una herramienta."""
    tool_call_id: str
    name: str
    success: bool
    output: str


# ============================================================================
# EXCEPCIONES DEL LLM
# ============================================================================

class LLMError(Exception):
    """Error genérico del conector LLM (modo local o HTTP)."""


# ============================================================================
# CAPA DE PERSISTENCIA (SQLite)
# ============================================================================

class Database:
    """Capa de persistencia SQLite para tareas e historial."""

    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    title           TEXT    NOT NULL,
                    prompt          TEXT    NOT NULL,
                    status          TEXT    NOT NULL,
                    created_at      TEXT    NOT NULL,
                    updated_at      TEXT    NOT NULL,
                    final_answer    TEXT,
                    parent_task_id  INTEGER,
                    subtask_type    TEXT,
                    attempt_number  INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY (parent_task_id) REFERENCES tasks(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS history (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id    INTEGER NOT NULL,
                    timestamp  TEXT    NOT NULL,
                    event_type TEXT    NOT NULL,
                    content    TEXT    NOT NULL,
                    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_history_task_id ON history(task_id);
                CREATE INDEX IF NOT EXISTS idx_tasks_status    ON tasks(status);
                CREATE INDEX IF NOT EXISTS idx_tasks_parent    ON tasks(parent_task_id);
                """
            )
            # Migración ligera: si la tabla existía sin las columnas nuevas,
            # las añadimos ahora. SQLite no soporta IF NOT EXISTS en ALTER TABLE
            # para columnas, así que comprobamos antes con PRAGMA.
            self._migrate_add_column_if_missing(conn, "tasks", "parent_task_id", "INTEGER")
            self._migrate_add_column_if_missing(conn, "tasks", "subtask_type", "TEXT")
            self._migrate_add_column_if_missing(
                conn, "tasks", "attempt_number", "INTEGER NOT NULL DEFAULT 0"
            )

    @staticmethod
    def _migrate_add_column_if_missing(
        conn: sqlite3.Connection,
        table: str,
        column: str,
        definition: str,
    ) -> None:
        """Añade una columna a una tabla si no existe ya (migración ligera)."""
        cur = conn.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in cur.fetchall()}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    # --- Tareas ---

    def create_task(
        self,
        title: str,
        prompt: str,
        parent_task_id: Optional[int] = None,
        subtask_type: Optional[SubtaskType] = None,
        attempt_number: int = 0,
    ) -> Task:
        #now = datetime.utcnow().isoformat(timespec="seconds")
        now = datetime.now(UTC).isoformat(timespec="seconds")
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO tasks "
                "(title, prompt, status, created_at, updated_at, "
                " parent_task_id, subtask_type, attempt_number) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    title,
                    prompt,
                    TaskStatus.PENDING.value,
                    now,
                    now,
                    parent_task_id,
                    subtask_type.value if subtask_type is not None else None,
                    attempt_number,
                ),
            )
            task_id = cur.lastrowid
        return Task(
            id=task_id,
            title=title,
            prompt=prompt,
            status=TaskStatus.PENDING,
            created_at=now,
            updated_at=now,
            parent_task_id=parent_task_id,
            subtask_type=subtask_type,
            attempt_number=attempt_number,
        )

    def update_task_status(
        self,
        task_id: int,
        status: TaskStatus,
        final_answer: Optional[str] = None,
    ) -> None:
        now = datetime.now(UTC).isoformat(timespec="seconds")
        with self._lock, self._connect() as conn:
            if final_answer is not None:
                conn.execute(
                    "UPDATE tasks SET status = ?, updated_at = ?, final_answer = ? "
                    "WHERE id = ?",
                    (status.value, now, final_answer, task_id),
                )
            else:
                conn.execute(
                    "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                    (status.value, now, task_id),
                )

    def get_task(self, task_id: int) -> Optional[Task]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_task(row)

    def list_tasks(self, statuses: List[TaskStatus]) -> List[Task]:
        if not statuses:
            return []
        placeholders = ",".join("?" for _ in statuses)
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM tasks WHERE status IN ({placeholders}) "
                f"ORDER BY updated_at DESC",
                [s.value for s in statuses],
            ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def list_subtasks(self, parent_task_id: int) -> List[Task]:
        """Devuelve las subtareas de una tarea padre, ordenadas por creación."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tasks WHERE parent_task_id = ? "
                "ORDER BY id ASC",
                (parent_task_id,),
            ).fetchall()
        return [self._row_to_task(r) for r in rows]

    @staticmethod
    def _row_to_task(row: sqlite3.Row) -> Task:
        """Convierte una fila de la tabla ``tasks`` en un ``Task``."""
        subtask_type_raw = row["subtask_type"]
        subtask_type: Optional[SubtaskType] = None
        if subtask_type_raw:
            try:
                subtask_type = SubtaskType(subtask_type_raw)
            except ValueError:
                subtask_type = None
        return Task(
            id=row["id"],
            title=row["title"],
            prompt=row["prompt"],
            status=TaskStatus(row["status"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            final_answer=row["final_answer"],
            parent_task_id=row["parent_task_id"],
            subtask_type=subtask_type,
            attempt_number=row["attempt_number"] or 0,
        )

    def delete_tasks_by_status(self, statuses: List[TaskStatus]) -> int:
        """
        Elimina las tareas que se encuentren en cualquiera de los estados indicados.

        El historial asociado se borra en cascada por la FK de la tabla ``history``.
        Retorna el número de filas eliminadas.
        """
        if not statuses:
            return 0
        placeholders = ",".join("?" for _ in statuses)
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                f"DELETE FROM tasks WHERE status IN ({placeholders})",
                [s.value for s in statuses],
            )
            return cur.rowcount

    # --- Historial ---

    def add_history(
        self,
        task_id: int,
        event_type: EventType,
        content: str,
    ) -> HistoryEntry:
        now = datetime.utcnow().isoformat(timespec="seconds")
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO history (task_id, timestamp, event_type, content) "
                "VALUES (?, ?, ?, ?)",
                (task_id, now, event_type.value, content),
            )
            entry_id = cur.lastrowid
        return HistoryEntry(
            id=entry_id,
            task_id=task_id,
            timestamp=now,
            event_type=event_type,
            content=content,
        )

    def get_history(self, task_id: int) -> List[HistoryEntry]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM history WHERE task_id = ? ORDER BY id ASC",
                (task_id,),
            ).fetchall()
        return [
            HistoryEntry(
                id=r["id"],
                task_id=r["task_id"],
                timestamp=r["timestamp"],
                event_type=EventType(r["event_type"]),
                content=r["content"],
            )
            for r in rows
        ]


# ============================================================================
# CONECTOR LLM (HTTP + local con llama-cpp-python)
# ============================================================================

class LLMConnector:
    """
    Cliente para LLMs con dos modos de operación:

    - "local": carga un modelo GGUF directamente con llama-cpp-python
      (sin endpoint HTTP, inferencia en proceso).
    - "http": envía solicitudes a un endpoint compatible con
      /v1/chat/completions (OpenAI / Ollama / llama.cpp server).

    El modo se selecciona con el parámetro `mode` (o la clave
    `mode` en la sección [LLM] de config.ini).
    En ambos casos la respuesta es compatible con OpenAI
    (choices[0].message.content / tool_calls), por lo que
    `parse_assistant_message` funciona sin cambios.
    """

    _VALID_MODES = ("local", "http")

    def __init__(
        self,
        mode: str = LLM_MODE,
        base_url: str = LLM_BASE_URL,
        api_key: str = LLM_API_KEY,
        model: str = LLM_MODEL,
        model_path: str = LLM_MODEL_PATH,
        timeout: float = LLM_TIMEOUT,
        n_ctx: int = LLM_N_CTX,
        n_threads: int = LLM_N_THREADS,
        n_gpu_layers: int = LLM_N_GPU_LAYERS,
    ) -> None:
        self.mode = mode.strip().lower()
        if self.mode not in self._VALID_MODES:
            raise LLMError(
                f"Modo LLM inválido: '{mode}'. Válidos: {self._VALID_MODES}"
            )
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.model_path = model_path
        self.timeout = timeout
        self.n_ctx = n_ctx
        self.n_threads = n_threads
        self.n_gpu_layers = n_gpu_layers
        self._local_llm = None
        # Lock para serializar llamadas al LLM. llama-cpp-python NO es
        # thread-safe: su contexto interno se corrompe si dos hilos llaman
        # a create_chat_completion() a la vez (provoca el error
        # "GGML_ASSERT(i1 >= 0 && i1 < ne1) failed"). Con este lock,
        # las llamadas al LLM se ejecutan una tras otra, aunque las
        # tareas sigan corriendo en paralelo en otros aspectos
        # (ejecución de herramientas, escritura en BD, etc.).
        self._lock = threading.Lock()

        if self.mode == "local":
            self._init_local()

    # --- Backend local (llama-cpp-python) ---

    def _resolve_model_file(self) -> Path:
        """
        Resuelve la ruta del modelo .gguf (absoluta).

        Acepta dos formas de configurar ``model_path`` en config.ini:
            - Directorio: se le concatena el nombre del modelo (``model``).
            - Ruta completa al archivo: se respeta tal cual.

        Si la ruta resuelta no existe, lanza ``LLMError`` con un mensaje
        claro que indica qué campos revisar.
        """
        p = Path(self.model_path)
        if not p.is_absolute():
            p = SCRIPT_DIR / p
        resolved = p.resolve()
        # Si model_path apunta a un directorio, añadir el nombre del modelo.
        if resolved.is_dir():
            resolved = resolved / self.model
        if not resolved.exists():
            raise LLMError(
                f"Archivo de modelo no encontrado: {resolved}. "
                f"Verifica que 'model' y 'model_path' en config.ini "
                f"apuntan a un .gguf existente."
            )
        return resolved

    def _init_local(self) -> None:
        """Carga el modelo GGUF en memoria con llama-cpp-python."""
        try:
            from llama_cpp import Llama  # type: ignore
        except ImportError as e:
            raise LLMError(
                "llama-cpp-python no está instalado. "
                "Instálalo con: pip install llama-cpp-python"
            ) from e

        model_file = self._resolve_model_file()
        if not model_file.exists():
            raise LLMError(
                f"Archivo de modelo no encontrado: {model_file}. "
                f"Colócalo en la ruta indicada por 'model_path' en config.ini."
            )

        try:
            self._local_llm = Llama(
                model_path=str(model_file),
                n_ctx=self.n_ctx,
                n_threads=self.n_threads,
                n_gpu_layers=self.n_gpu_layers,
                verbose=False,
            )
        except Exception as e:  # noqa: BLE001
            raise LLMError(f"Error cargando modelo {model_file}: {e}") from e

    def _chat_local(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]],
        tool_choice: Optional[str],
    ) -> Dict[str, Any]:
        """Inferencia local usando llama-cpp-python."""
        if self._local_llm is None:
            self._init_local()
        kwargs: Dict[str, Any] = {"messages": messages}
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = tool_choice or "auto"
        try:
            result = self._local_llm.create_chat_completion(**kwargs)
        except Exception as e:  # noqa: BLE001
            raise LLMError(f"Error en inferencia local: {e}") from e
        # llama-cpp-python devuelve un dict estilo OpenAI.
        if isinstance(result, dict):
            return result
        try:
            return dict(result)
        except Exception as e:  # noqa: BLE001
            raise LLMError(f"Respuesta local en formato inesperado: {e}") from e

    # --- Backend HTTP (OpenAI / Ollama / llama.cpp server) ---

    def _chat_http(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]],
        tool_choice: Optional[str],
    ) -> Dict[str, Any]:
        """Envía una solicitud HTTP al endpoint y devuelve la respuesta cruda."""
        url = f"{self.base_url}/chat/completions"
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
            # Forzar al modelo a usar herramientas cuando estén disponibles.
            # "auto" deja al modelo decidir; "required" fuerza al menos una.
            payload["tool_choice"] = tool_choice or "auto"

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            raise LLMError(f"HTTP {e.code} desde {url}: {detail}") from e
        except urllib.error.URLError as e:
            raise LLMError(f"No se pudo conectar con {url}: {e.reason}") from e
        except json.JSONDecodeError as e:
            raise LLMError(f"Respuesta JSON inválida del LLM: {e}") from e

    # --- Dispatcher ---

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Envía una solicitud de chat y devuelve la respuesta cruda.

        Delega al backend local o HTTP según `self.mode`. En ambos casos
        el formato de respuesta es compatible con OpenAI
        (choices[0].message.content / tool_calls).

        Las llamadas se serializan con un lock porque llama-cpp-python
        no es thread-safe (ver nota en __init__).
        """
        with self._lock:
            if self.mode == "local":
                return self._chat_local(messages, tools, tool_choice)
            return self._chat_http(messages, tools, tool_choice)

    @staticmethod
    def _extract_tool_calls_from_text(
        content: str,
    ) -> Tuple[str, List[ToolCall]]:
        """
        Extrae tool_calls del texto cuando el modelo los emite como
        bloques ``<tool_call>{...}</tool_call>`` en lugar del campo
        estructurado ``tool_calls`` (común en Qwen3-Instruct y otros
        modelos que no usan el formato OpenAI nativo).

        Devuelve (contenido_limpio, tool_calls). Los bloques que no se
        puedan parsear como JSON se conservan en el contenido.
        """
        tool_calls: List[ToolCall] = []
        cleaned_parts: List[str] = []
        pos = 0
        open_tag = "<tool_call>"
        close_tag = "</tool_call>"

        while True:
            start = content.find(open_tag, pos)
            if start == -1:
                cleaned_parts.append(content[pos:])
                break
            # Texto previo al bloque: se conserva tal cual.
            cleaned_parts.append(content[pos:start])
            end = content.find(close_tag, start)
            if end == -1:
                # Sin cierre: dejar el resto intacto y abortar.
                cleaned_parts.append(content[start:])
                break
            inner = content[start + len(open_tag):end].strip()
            try:
                payload = json.loads(inner)
            except json.JSONDecodeError:
                # No es JSON válido: conservar el bloque en el contenido.
                cleaned_parts.append(content[start:end + len(close_tag)])
                pos = end + len(close_tag)
                continue
            name = payload.get("name", "") if isinstance(payload, dict) else ""
            args = payload.get("arguments", {}) if isinstance(payload, dict) else {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"_raw": args}
            elif not isinstance(args, dict):
                args = {}
            tool_calls.append(
                ToolCall(
                    id=f"call_{uuid.uuid4().hex[:8]}",
                    name=name,
                    arguments=args,
                )
            )
            pos = end + len(close_tag)

        cleaned = "".join(cleaned_parts).strip()
        return cleaned, tool_calls

    @staticmethod
    def _extract_tool_calls_from_xml(
        content: str,
    ) -> Tuple[str, List[ToolCall]]:
        """
        Extrae tool_calls del texto cuando el modelo los emite como bloques
        XML en lugar de JSON o del campo estructurado ``tool_calls``.

        Algunos modelos (Hermes/Mistral en modo XML,某些 fine-tunes, etc.)
        responden con etiquetas XML en lugar de JSON. Esta función
        compatibiliza esos formatos convirtiéndolos a la misma estructura
        ``ToolCall`` que el parser JSON.

        Formatos XML soportados:
            - ``<tool_call><name>func</name><arguments>...</arguments></tool_call>``
            - ``<invoke name="func">...</invoke>`` (Hermes/Mistral)
            - ``<function_call><function name="func">...</function></function_call>``
            - ``<tool_use><name>func</name><input>...</input></tool_use>``
            - ``<tool name="func">...</tool>`` (cuando tiene atributo/hijo ``name``)

        El nombre de la función puede estar en un atributo ``name`` o en un
        elemento hijo ``<name>``. Los argumentos se buscan en ``<arguments>``,
        ``<input>`` o, en su defecto, en los hijos directos del bloque.

        Devuelve (contenido_limpio, tool_calls). Los bloques que no se
        puedan parsear como XML válido o que no contengan un nombre de
        función se conservan en el contenido.
        """
        tool_calls: List[ToolCall] = []
        cleaned_parts: List[str] = []
        pos = 0

        # Etiquetas raíz que pueden contener tool calls.
        # ``tool`` se incluye pero solo se acepta si tiene ``name`` (atributo
        # o hijo) para no capturar HTML u otros ``<tool>`` genéricos.
        root_tags = (
            "tool_call", "invoke", "function_call", "tool_use", "tool",
        )

        while pos < len(content):
            # Encontrar la siguiente etiqueta raíz candidata más cercana.
            next_start = -1
            next_tag: Optional[str] = None
            for tag in root_tags:
                open_tag = f"<{tag}"
                idx = content.find(open_tag, pos)
                if idx == -1:
                    continue
                # Verificar que sea una etiqueta de apertura válida
                # (seguida de espacio, >, / o whitespace).
                after_idx = idx + len(open_tag)
                if after_idx >= len(content):
                    continue
                after_char = content[after_idx]
                if after_char in (" ", ">", "/", "\n", "\t", "\r"):
                    if next_start == -1 or idx < next_start:
                        next_start = idx
                        next_tag = tag

            if next_start == -1 or next_tag is None:
                cleaned_parts.append(content[pos:])
                break

            # Texto previo al bloque: se conserva tal cual.
            cleaned_parts.append(content[pos:next_start])

            # Buscar la etiqueta de cierre correspondiente.
            close_tag = f"</{next_tag}>"
            end = content.find(close_tag, next_start)
            if end == -1:
                # Sin cierre: dejar el resto intacto y abortar.
                cleaned_parts.append(content[next_start:])
                break

            block_end = end + len(close_tag)
            block = content[next_start:block_end]

            try:
                # Envolver en un root sintético para que ElementTree
                # acepte el bloque aunque contenga texto mixto o múltiples
                # elementos hermanos.
                wrapped = f"<root>{block}</root>"
                root = ET.fromstring(wrapped)

                tc_elem = root[0] if len(root) else None
                if tc_elem is None:
                    cleaned_parts.append(block)
                    pos = block_end
                    continue

                # Extraer nombre: atributo ``name`` o elemento hijo ``<name>``.
                name = (tc_elem.get("name") or "").strip()
                name_source = tc_elem

                if not name:
                    name_elem = tc_elem.find("name")
                    if name_elem is not None and name_elem.text:
                        name = name_elem.text.strip()

                # Si no hay nombre en el root, buscar en hijos directos.
                # Esto cubre el caso ``<function_call><function name="...">``
                # donde la definición de la función está anidada.
                if not name:
                    for child in tc_elem:
                        child_name = (child.get("name") or "").strip()
                        if not child_name:
                            child_name_elem = child.find("name")
                            if child_name_elem is not None and child_name_elem.text:
                                child_name = child_name_elem.text.strip()
                        if child_name:
                            name = child_name
                            name_source = child
                            break

                if not name:
                    # Sin nombre no es un tool_call válido: conservar bloque.
                    cleaned_parts.append(block)
                    pos = block_end
                    continue

                # Usar el elemento que contiene el nombre como tc_elem
                # para que los argumentos se extraigan del lugar correcto.
                tc_elem = name_source

                # Localizar contenedor de argumentos.
                args_elem = tc_elem.find("arguments")
                if args_elem is None:
                    args_elem = tc_elem.find("input")
                if args_elem is None:
                    # Si no hay contenedor, usar el propio bloque como args
                    # y filtrar ``name`` después.
                    args_elem = tc_elem

                arguments = LLMConnector._xml_element_to_dict(args_elem)
                # Si args_elem era el propio tc_elem, eliminar ``name`` y
                # cualquier atributo ``name`` que se haya colado.
                if args_elem is tc_elem:
                    arguments.pop("name", None)

                tool_calls.append(
                    ToolCall(
                        id=f"call_{uuid.uuid4().hex[:8]}",
                        name=name,
                        arguments=arguments,
                    )
                )
                pos = block_end
            except ET.ParseError:
                # XML inválido: conservar el bloque en el contenido.
                cleaned_parts.append(block)
                pos = block_end

        cleaned = "".join(cleaned_parts).strip()
        return cleaned, tool_calls

    @staticmethod
    def _xml_element_to_dict(elem: ET.Element) -> Dict[str, Any]:
        """
        Convierte un elemento XML en un diccionario, intentando preservar
        tipos simples (int, float, bool, None) y arrays cuando hay varios
        hijos con el mismo tag.

        Reglas:
            - Atributos del elemento → claves del diccionario.
            - Hijos con texto plano y sin atributos → valor escalar coerced.
            - Hijos con hijos o atributos → recursión a dict.
            - Varios hijos con el mismo tag → lista (array).
            - Texto que parece JSON (``{`` o ``[`` al inicio) → se intenta
              parsear como JSON antes de coercing.
        """
        result: Dict[str, Any] = {}

        # Atributos del elemento.
        for attr_name, attr_value in elem.attrib.items():
            result[attr_name] = LLMConnector._coerce_xml_value(attr_value)

        # Agrupar hijos por tag para detectar arrays.
        children_by_tag: Dict[str, List[ET.Element]] = {}
        for child in elem:
            children_by_tag.setdefault(child.tag, []).append(child)

        for tag, children in children_by_tag.items():
            if len(children) == 1:
                child = children[0]
                if len(child) == 0 and not child.attrib:
                    text = (child.text or "").strip()
                    # Si el texto parece JSON, intentar parsearlo.
                    if text.startswith(("{", "[")):
                        try:
                            result[tag] = json.loads(text)
                            continue
                        except json.JSONDecodeError:
                            pass
                    result[tag] = LLMConnector._coerce_xml_value(text)
                else:
                    result[tag] = LLMConnector._xml_element_to_dict(child)
            else:
                # Múltiples hijos con el mismo tag → array.
                result[tag] = [
                    LLMConnector._xml_element_to_dict(child)
                    if (len(child) or child.attrib)
                    else LLMConnector._coerce_xml_value(
                        (child.text or "").strip()
                    )
                    for child in children
                ]

        return result

    @staticmethod
    def _coerce_xml_value(text: str) -> Any:
        """Intenta convertir una cadena a un tipo Python nativo."""
        if not text:
            return text
        lower = text.lower()
        if lower in ("true", "false"):
            return lower == "true"
        if lower in ("null", "none"):
            return None
        # Número (int o float).
        try:
            if "." in text or "e" in text.lower():
                return float(text)
            return int(text)
        except ValueError:
            pass
        return text

    @staticmethod
    def parse_assistant_message(raw: Dict[str, Any]) -> Tuple[str, List[ToolCall]]:
        """
        Extrae contenido textual y tool_calls del mensaje del asistente.

        Soporta tres formatos de tool_calls:
            1. Estructurado OpenAI: ``message.tool_calls`` (lista de objetos).
            2. Texto plano JSON: bloques ``<tool_call>{...}</tool_call>``
               dentro de ``message.content`` (Qwen3-Instruct y similares).
            3. Texto plano XML: bloques ``<tool_call>...</tool_call>``,
               ``<invoke name="...">...</invoke>``, ``<function_call>...``,
               ``<tool_use>...</tool_use>`` o ``<tool name="...">...</tool>``
               (Hermes/Mistral en modo XML y otros modelos que emiten XML
               en lugar de JSON).

        Devuelve (content, tool_calls). Si el LLM no devuelve tool_calls
        en ninguno de los formatos, se devuelve una lista vacía.
        """
        try:
            choice = raw["choices"][0]
            message = choice.get("message", {})
        except (KeyError, IndexError) as e:
            raise LLMError(f"Respuesta LLM sin 'choices[0].message': {raw}") from e

        # Validar que el mensaje no esté vacío: si el LLM devuelve
        # {"choices": [{}]} sin message, es una respuesta estructuralmente
        # inválida que debe tratarse como error, no como respuesta vacía.
        if not message:
            raise LLMError(f"Respuesta LLM con 'message' vacío: {raw}")

        content = message.get("content") or ""
        raw_calls = message.get("tool_calls") or []
        tool_calls: List[ToolCall] = []
        for tc in raw_calls:
            try:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                args_raw = fn.get("arguments", "{}")
                if isinstance(args_raw, str):
                    try:
                        args = json.loads(args_raw)
                    except json.JSONDecodeError:
                        args = {"_raw": args_raw}
                else:
                    # Normalizar tipos incorrectos (lista, int, bool, None)
                    # a dict vacío para evitar pasar valores no-dict al tool.
                    args = args_raw if isinstance(args_raw, dict) else {}
                tool_calls.append(
                    ToolCall(
                        id=tc.get("id", f"call_{uuid.uuid4().hex[:8]}"),
                        name=name,
                        arguments=args,
                    )
                )
            except Exception as e:  # noqa: BLE001
                raise LLMError(f"Tool call malformado: {tc} ({e})") from e

        # Fallback: si no hay tool_calls estructurados, buscar en el texto.
        if not tool_calls and content:
            content, text_calls = LLMConnector._extract_tool_calls_from_text(content)
            tool_calls = text_calls

            # Segundo fallback: algunos modelos responden con etiquetas XML
            # en lugar de JSON (Hermes/Mistral en modo XML, etc.). Si el
            # parser JSON no encontró nada (o conservó bloques no parseables),
            # intentar extraer tool_calls del XML.
            if not tool_calls and content:
                content, xml_calls = LLMConnector._extract_tool_calls_from_xml(content)
                tool_calls = xml_calls

        return content, tool_calls


# ============================================================================
# HERRAMIENTAS (TOOLS)
# ============================================================================

@dataclass
class ToolDefinition:
    """Definición de una herramienta: esquema, riesgo y ejecutor."""
    name: str
    description: str
    risk: RiskLevel
    parameters: Dict[str, Any]
    runner: Callable[[Dict[str, Any]], str]


def _resolve_workspace_path(path: str) -> Path:
    """
    Resuelve una ruta restringiéndola al directorio de trabajo.
    Lanza ValueError si se intenta escapar del workspace.
    """
    p = Path(path)
    if not p.is_absolute():
        p = WORKSPACE_DIR / p
    resolved = p.resolve()
    try:
        resolved.relative_to(WORKSPACE_DIR)
    except ValueError as e:
        raise ValueError(
            f"Ruta fuera del workspace permitido ({WORKSPACE_DIR}): {resolved}"
        ) from e
    return resolved


def tool_read_file(args: Dict[str, Any]) -> str:
    path = _resolve_workspace_path(args.get("path", ""))
    if not path.exists():
        return f"ERROR: el archivo no existe: {path}"
    if not path.is_file():
        return f"ERROR: no es un archivo: {path}"
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        return f"ERROR al leer {path}: {e}"
    if len(content) > 50_000:
        content = content[:50_000] + "\n... [truncado]"
    return content


def tool_list_directory(args: Dict[str, Any]) -> str:
    path = _resolve_workspace_path(args.get("path", "."))
    if not path.exists():
        return f"ERROR: el directorio no existe: {path}"
    if not path.is_dir():
        return f"ERROR: no es un directorio: {path}"
    try:
        entries = sorted(path.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
    except Exception as e:  # noqa: BLE001
        return f"ERROR al listar {path}: {e}"
    lines = []
    for entry in entries:
        kind = "DIR " if entry.is_dir() else "FILE"
        try:
            size = entry.stat().st_size if entry.is_file() else "-"
        except OSError:
            size = "-"
        lines.append(f"{kind}  {size:>8}  {entry.name}")
    return "\n".join(lines) if lines else "(directorio vacío)"


def tool_search_files(args: Dict[str, Any]) -> str:
    pattern = args.get("pattern", "")
    base = _resolve_workspace_path(args.get("path", "."))
    if not pattern:
        return "ERROR: 'pattern' es obligatorio"
    if not base.exists() or not base.is_dir():
        return f"ERROR: directorio inválido: {base}"
    matches: List[str] = []
    try:
        for p in base.rglob(pattern):
            try:
                rel = p.relative_to(WORKSPACE_DIR)
            except ValueError:
                rel = p
            matches.append(str(rel))
            if len(matches) >= 200:
                matches.append("... [truncado, más de 200 coincidencias]")
                break
    except Exception as e:  # noqa: BLE001
        return f"ERROR al buscar: {e}"
    return "\n".join(matches) if matches else "(sin coincidencias)"


def tool_get_current_time(_args: Dict[str, Any]) -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def tool_write_file(args: Dict[str, Any]) -> str:
    path = _resolve_workspace_path(args.get("path", ""))
    content = args.get("content", "")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        return f"ERROR al escribir {path}: {e}"
    return f"OK: escrito {len(content)} caracteres en {path}"


def tool_execute_command(args: Dict[str, Any]) -> str:
    """
    Ejecuta un comando del sistema de forma restringida al workspace.
    Se aplica una lista de denegación para comandos peligrosos.
    """
    command = args.get("command", "")
    if not command:
        return "ERROR: 'command' es obligatorio"

    # Lista de denegación básica de comandos destructivos.
    denied = ["rm -rf /", "format", "del /f /s /q", "shutdown", "reboot"]
    lowered = command.lower()
    for d in denied:
        if d in lowered:
            return f"ERROR: comando bloqueado por política de seguridad: '{d}'"

    try:
        # cwd restringido al workspace.
        result = subprocess.run(
            command,
            shell=True,
            cwd=str(WORKSPACE_DIR),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return "ERROR: timeout (30s) ejecutando el comando"
    except Exception as e:  # noqa: BLE001
        return f"ERROR al ejecutar comando: {e}"

    out = (result.stdout or "") + (result.stderr or "")
    if not out:
        out = f"(sin salida) código={result.returncode}"
    if len(out) > 20_000:
        out = out[:20_000] + "\n... [truncado]"
    return out


def tool_delete_file(args: Dict[str, Any]) -> str:
    path = _resolve_workspace_path(args.get("path", ""))
    if not path.exists():
        return f"ERROR: no existe: {path}"
    try:
        if path.is_dir():
            import shutil
            shutil.rmtree(path)
        else:
            path.unlink()
    except Exception as e:  # noqa: BLE001
        return f"ERROR al eliminar {path}: {e}"
    return f"OK: eliminado {path}"


class ToolsRegistry:
    """Registro central de herramientas disponibles para el agente."""

    def __init__(self) -> None:
        self._tools: Dict[str, ToolDefinition] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.register(
            ToolDefinition(
                name="read_file",
                description=(
                    "Lee el contenido de un archivo de texto dentro del workspace. "
                    "Argumentos: path (ruta relativa al workspace o absoluta)."
                ),
                risk=RiskLevel.SAFE,
                parameters={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Ruta del archivo a leer.",
                        }
                    },
                    "required": ["path"],
                },
                runner=tool_read_file,
            )
        )
        self.register(
            ToolDefinition(
                name="list_directory",
                description=(
                    "Lista el contenido de un directorio del workspace. "
                    "Argumentos: path (directorio, por defecto el workspace raíz)."
                ),
                risk=RiskLevel.SAFE,
                parameters={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Ruta del directorio a listar.",
                        }
                    },
                },
                runner=tool_list_directory,
            )
        )
        self.register(
            ToolDefinition(
                name="search_files",
                description=(
                    "Busca archivos por patrón (glob) dentro de un directorio. "
                    "Argumentos: pattern (obligatorio), path (opcional)."
                ),
                risk=RiskLevel.SAFE,
                parameters={
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Patrón glob, p. ej. '*.txt'.",
                        },
                        "path": {
                            "type": "string",
                            "description": "Directorio base de búsqueda.",
                        },
                    },
                    "required": ["pattern"],
                },
                runner=tool_search_files,
            )
        )
        self.register(
            ToolDefinition(
                name="get_current_time",
                description="Devuelve la fecha y hora UTC actuales en formato ISO 8601.",
                risk=RiskLevel.SAFE,
                parameters={"type": "object", "properties": {}},
                runner=tool_get_current_time,
            )
        )
        self.register(
            ToolDefinition(
                name="write_file",
                description=(
                    "Escribe contenido en un archivo del workspace (crea "
                    "directorios si no existen). Argumentos: path, content."
                ),
                risk=RiskLevel.CRITICAL,
                parameters={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Ruta del archivo a escribir.",
                        },
                        "content": {
                            "type": "string",
                            "description": "Contenido a escribir.",
                        },
                    },
                    "required": ["path", "content"],
                },
                runner=tool_write_file,
            )
        )
        self.register(
            ToolDefinition(
                name="execute_command",
                description=(
                    "Ejecuta un comando del sistema dentro del workspace. "
                    "Argumentos: command (cadena con el comando)."
                ),
                risk=RiskLevel.CRITICAL,
                parameters={
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Comando a ejecutar.",
                        }
                    },
                    "required": ["command"],
                },
                runner=tool_execute_command,
            )
        )
        self.register(
            ToolDefinition(
                name="delete_file",
                description=(
                    "Elimina un archivo o directorio del workspace. "
                    "Argumentos: path."
                ),
                risk=RiskLevel.CRITICAL,
                parameters={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Ruta a eliminar.",
                        }
                    },
                    "required": ["path"],
                },
                runner=tool_delete_file,
            )
        )

    def register(self, tool: ToolDefinition) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def all(self) -> List[ToolDefinition]:
        return list(self._tools.values())

    def to_openai_tools(self) -> List[Dict[str, Any]]:
        """Convierte el registro al formato OpenAI/Ollama de tools."""
        out: List[Dict[str, Any]] = []
        for t in self.all():
            out.append(
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                }
            )
        return out


# ============================================================================
# GESTOR DE PERMISOS (HITL)
# ============================================================================

class PermissionDecision:
    """Resultado de una solicitud de permiso."""

    def __init__(self, granted: bool, reason: str = "") -> None:
        self.granted = granted
        self.reason = reason


class PermissionManager:
    """
    Gestor de aprobaciones humanas.

    Las herramientas SAFE se ejecutan automáticamente.
    Las herramientas CRITICAL bloquean la tarea hasta que el usuario
    autorice o deniegue la operación.
    """

    def __init__(self, ui_queue: "queue.Queue[Dict[str, Any]]") -> None:
        self._ui_queue = ui_queue
        self._events: Dict[str, "threading.Event"] = {}
        self._decisions: Dict[str, PermissionDecision] = {}
        self._lock = threading.Lock()

    def request(
        self,
        task_id: int,
        tool: ToolDefinition,
        arguments: Dict[str, Any],
    ) -> PermissionDecision:
        """
        Solicita aprobación humana para una herramienta CRITICAL.

        Publica un evento en la cola de la UI y espera la decisión.
        """
        request_id = uuid.uuid4().hex
        event = threading.Event()
        with self._lock:
            self._events[request_id] = event
            self._decisions[request_id] = PermissionDecision(False, "pendiente")

        self._ui_queue.put(
            {
                "type": "approval_request",
                "request_id": request_id,
                "task_id": task_id,
                "tool_name": tool.name,
                "tool_description": tool.description,
                "risk": tool.risk.value,
                "arguments": arguments,
            }
        )

        # Espera síncrona hasta que la UI resuelva la aprobación.
        event.wait(timeout=600)  # 10 minutos máximo.

        with self._lock:
            decision = self._decisions.pop(request_id, PermissionDecision(False, "timeout"))
            self._events.pop(request_id, None)
        return decision

    def resolve(self, request_id: str, granted: bool, reason: str = "") -> None:
        """Resuelve una solicitud de permiso (invocado por la UI)."""
        with self._lock:
            event = self._events.get(request_id)
            decision = self._decisions.get(request_id)
        if event is None or decision is None:
            return
        decision.granted = granted
        decision.reason = reason
        event.set()


# ============================================================================
# DETECTOR DE BUCLES
# ============================================================================

class LoopDetector:
    """
    Detecta cuando el modelo estÃ¡ repitiendo la misma respuesta.

    Genera una huella estable (fingerprint) de cada mensaje del asistente
    combinando el contenido textual normalizado y la firma de las
    tool_calls (nombre + argumentos ordenados). Cuando la misma huella
    aparece un número de veces igual o superior al umbral, se considera
    que el modelo está atrapado en un bucle y se debe compactar el
    contexto para permitirle replantear la estrategia.
    """

    def __init__(self, threshold: int = LOOP_THRESHOLD) -> None:
        self.threshold = max(1, int(threshold))
        self._counts: Dict[str, int] = {}

    @staticmethod
    def fingerprint(content: str, tool_calls: List[ToolCall]) -> str:
        """
        Genera una huella estable para una respuesta del asistente.

        - Normaliza el contenido (strip).
        - Ordena los argumentos de cada tool_call para que el orden
          de las claves no afecte a la huella.
        - Incluye el nombre de la herramienta.
        """
        norm_content = (content or "").strip()
        tc_parts: List[str] = []
        for tc in tool_calls:
            try:
                args_repr = json.dumps(
                    tc.arguments, sort_keys=True, ensure_ascii=False
                )
            except (TypeError, ValueError):
                args_repr = repr(tc.arguments)
            tc_parts.append(f"{tc.name}|{args_repr}")
        return f"C:{norm_content}|TC:{','.join(tc_parts)}"

    def record(self, content: str, tool_calls: List[ToolCall]) -> int:
        """
        Registra una respuesta y devuelve el contador actual para su huella.

        Un contador >= self.threshold indica que la respuesta se ha
        repetido suficientes veces como para considerarla un bucle.
        """
        fp = self.fingerprint(content, tool_calls)
        self._counts[fp] = self._counts.get(fp, 0) + 1
        return self._counts[fp]

    def is_looping(self, content: str, tool_calls: List[ToolCall]) -> bool:
        """
        Devuelve True si la respuesta actual forma parte de un bucle
        (contador >= umbral) sin incrementarlo.
        """
        fp = self.fingerprint(content, tool_calls)
        return self._counts.get(fp, 0) >= self.threshold

    def reset(self) -> None:
        """Reinicia el detector (p.ej. tras una compactaciÃ³n de contexto)."""
        self._counts.clear()


# ============================================================================
# MOTOR DEL AGENTE (ReAct)
# ============================================================================

SYSTEM_PROMPT = """Eres un agente autónomo con acceso a HERRAMIENTAS (tools/functions). Tienes permiso y DEBES usarlas cuando la tarea lo requiera.

HERRAMIENTAS DISPONIBLES:
- read_file(path): Lee el contenido de un archivo del workspace.
- write_file(path, content): Escribe contenido en un archivo del workspace.
- list_directory(path): Lista el contenido de un directorio del workspace.
- search_files(pattern, path): Busca archivos por patrón glob.
- execute_command(command): Ejecuta un comando del sistema dentro del workspace.
- delete_file(path): Elimina un archivo o directorio del workspace.
- get_current_time(): Devuelve la fecha y hora UTC actuales.

REGLAS OBLIGATORIAS:
1. SIEMPRE que el usuario pida crear, escribir, modificar, leer o buscar archivos, DEBES llamar a la herramienta correspondiente. NO respondas con texto diciendo que no puedes hacerlo.
2. NO inventes código en tu respuesta. USA write_file para guardar código en archivos.
3. NO digas "no tengo acceso" o "no puedo crear archivos". TIENES ACCESO a través de las herramientas.
4. Cuando llames a una herramienta, el sistema te devolverá el resultado automáticamente.
5. Después de obtener los resultados de las herramientas, proporciona una respuesta final concisa SIN tool_calls.
6. Si una herramienta falla, intenta otra estrategia o explica el problema brevemente.
7. Sé claro y breve en tus razonamientos.

FORMATO DE RESPUESTA:
- Si necesitas actuar: emite una o más tool_calls.
- Si ya tienes la respuesta final: responde solo con texto, sin tool_calls.
"""


class Agent:
    """
    Bucle de razonamiento del agente (estilo ReAct).

    Mantiene el historial de mensajes por tarea, llama al LLM,
    ejecuta herramientas (con control HITL) y registra cada paso.
    """

    def __init__(
        self,
        db: Database,
        llm: LLMConnector,
        tools: ToolsRegistry,
        permissions: PermissionManager,
        ui_queue: "queue.Queue[Dict[str, Any]]",
    ) -> None:
        self.db = db
        self.llm = llm
        self.tools = tools
        self.permissions = permissions
        self.ui_queue = ui_queue

    # --- Helpers de logging ---

    def _log(
        self,
        task_id: int,
        event_type: EventType,
        content: str,
    ) -> None:
        self.db.add_history(task_id, event_type, content)
        self.ui_queue.put(
            {
                "type": "history_update",
                "task_id": task_id,
                "event_type": event_type.value,
                "content": content,
            }
        )

    def _set_status(
        self,
        task_id: int,
        status: TaskStatus,
        final_answer: Optional[str] = None,
    ) -> None:
        self.db.update_task_status(task_id, status, final_answer=final_answer)
        self.ui_queue.put(
            {"type": "status_change", "task_id": task_id, "status": status.value}
        )
        self._log(
            task_id,
            EventType.STATUS_CHANGE,
            f"Estado de la tarea → {status.value}",
        )

    # --- Compactación de contexto ---

    def _compact_context(
        self,
        task_id: int,
        messages: List[Dict[str, Any]],
        reason: str = "bucle",
    ) -> List[Dict[str, Any]]:
        """
        Compacta el historial de mensajes.

        Conserva el system prompt y el prompt original del usuario, y
        reemplaza todos los mensajes intermedios por un único mensaje
        de resumen que incluye las últimas llamadas a herramientas y
        sus resultados. Esto le da al modelo un contexto reducido pero
        con la información esencial para replantear su estrategia y
        salir del bucle.
        """
        if len(messages) <= 2:
            return messages

        system_msg = messages[0]
        user_msg = messages[1]
        middle = messages[2:]

        summary_lines: List[str] = [
            "CONTEXTO COMPACTADO: Se han eliminado los mensajes intermedios.",
            "A continuación se resume el progreso realizado hasta ahora:",
            "",
        ]

        # Extraer las últimas interacciones (pensamientos, tools, resultados).
        recent_thoughts: List[str] = []
        recent_tool_calls: List[str] = []
        recent_results: List[str] = []
        for msg in middle:
            role = msg.get("role", "")
            if role == "assistant":
                content = (msg.get("content") or "").strip()
                if content:
                    recent_thoughts.append(content[:200])
                for tc in msg.get("tool_calls", []) or []:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    name = fn.get("name", "?")
                    args = fn.get("arguments", "{}")
                    if isinstance(args, str) and len(args) > 120:
                        args = args[:120] + "..."
                    recent_tool_calls.append(f"  - {name}({args})")
            elif role == "tool":
                content = (msg.get("content") or "").strip()
                if content:
                    recent_results.append(content[:200])

        if recent_thoughts:
            summary_lines.append("Últimos pensamientos:")
            summary_lines.extend(f"  - {t}" for t in recent_thoughts[-3:])
            summary_lines.append("")
        if recent_tool_calls:
            summary_lines.append("Últimas herramientas llamadas:")
            summary_lines.extend(recent_tool_calls[-5:])
            summary_lines.append("")
        if recent_results:
            summary_lines.append("Últimos resultados:")
            summary_lines.extend(f"  - {r}" for r in recent_results[-5:])
            summary_lines.append("")

        if reason == "bucle":
            summary_lines.append(
                "IMPORTANTE: Estás atrapado en un bucle. Cambia tu estrategia "
                "completamente. Si una herramienta falla, prueba con otra "
                "diferente o con argumentos distintos. Si no puedes avanzar, "
                "proporciona una respuesta final explicando qué has logrado "
                "y qué no has podido completar."
            )

        summary_msg = {
            "role": "user",
            "content": "\n".join(summary_lines),
        }

        if reason == "bucle":
            self._log(
                task_id,
                EventType.LOOP_DETECTED,
                (
                    f"♻ Bucle detectado: la misma respuesta se ha repetido "
                    f"{LOOP_THRESHOLD} o más veces. Iniciando compactación "
                    f"del contexto."
                ),
            )
        if reason == "exceso_contexto":
            self._log(
                task_id,
                EventType.CONTEXT_OVERFLOW,
                (
                    f"⚠ Contexto demasiado grande: {len(messages)} mensajes. "
                    f"Iniciando compactación del contexto."
                ),
            )
        self._log(
            task_id,
            EventType.CONTEXT_COMPACTED,
            (
                f"Contexto compactado: {len(messages)} mensajes → "
                f"3 mensajes (system + user + resumen)."
            ),
        )

        return [system_msg, user_msg, summary_msg]

    # --- Ejecución de tool calls ---

    def _execute_tool_call(
        self,
        task_id: int,
        call: ToolCall,
    ) -> ToolResult:
        tool = self.tools.get(call.name)
        if tool is None:
            msg = f"ERROR: herramienta desconocida '{call.name}'"
            self._log(task_id, EventType.ERROR, msg)
            return ToolResult(call.id, call.name, False, msg)

        # Permiso humano si es crítica.
        if tool.risk == RiskLevel.CRITICAL:
            self._set_status(task_id, TaskStatus.AWAITING_APPROVAL)
            self._log(
                task_id,
                EventType.APPROVAL_REQUEST,
                (
                    f"Solicitud de aprobación para herramienta CRITICAL "
                    f"'{tool.name}' con argumentos: {json.dumps(call.arguments, ensure_ascii=False)}"
                ),
            )
            decision = self.permissions.request(task_id, tool, call.arguments)
            if not decision.granted:
                self._log(
                    task_id,
                    EventType.APPROVAL_DENIED,
                    f"Acción denegada por el usuario: {tool.name}. "
                    f"Motivo: {decision.reason or 'no especificado'}",
                )
                self._set_status(task_id, TaskStatus.IN_PROGRESS)
                return ToolResult(
                    call.id,
                    call.name,
                    False,
                    f"DENEGADO por el usuario. {decision.reason or ''}".strip(),
                )
            self._log(
                task_id,
                EventType.APPROVAL_GRANTED,
                f"Acción aprobada por el usuario: {tool.name}",
            )
            self._set_status(task_id, TaskStatus.IN_PROGRESS)

        # Ejecución.
        try:
            output = tool.runner(call.arguments)
            success = not output.startswith("ERROR")
        except ValueError as e:
            # Aviso de validación (p.ej. ruta fuera del workspace).
            # Se envía al modelo como información, no como error de ejecución,
            # para que reformule la petición con una ruta válida.
            output = (
                f"AVISO: {e}. "
                f"Solo puedes acceder a rutas dentro del workspace permitido: "
                f"{WORKSPACE_DIR}. "
                f"Por favor, reformula tu petición usando una ruta válida "
                f"relativa al workspace (por ejemplo, 'mi_archivo.txt' o "
                f"'subdirectorio/mi_archivo.txt') y vuelve a intentarlo."
            )
            success = False
        except Exception as e:  # noqa: BLE001
            # Cualquier otro error de ejecución se convierte en aviso limpio
            # para el modelo, sin traceback en la UI, con guía correctiva.
            error_type = type(e).__name__
            output = (
                f"AVISO: la herramienta '{tool.name}' no pudo completarse "
                f"({error_type}: {e}). "
                f"Revisa los argumentos proporcionados y reformula tu petición. "
                f"Si el problema persiste, prueba con una estrategia alternativa "
                f"o con argumentos diferentes."
            )
            success = False

        # En la UI, cualquier resultado no exitoso se muestra como aviso limpio,
        # sin traceback ni mensajes de error técnicos. El modelo recibe el
        # mensaje completo (sea AVISO: o ERROR:) para poder reaccionar.
        if success:
            log_event = EventType.TOOL_RESULT
            log_prefix = "OK"
        else:
            log_event = EventType.INFO
            log_prefix = "AVISO"

        self._log(
            task_id,
            log_event,
            f"[{tool.name}] {log_prefix}\n{output}",
        )
        return ToolResult(call.id, call.name, success, output)

    # --- Estimación de uso de contexto ---

    @staticmethod
    def _estimate_context_usage(
        messages: List[Dict[str, Any]],
    ) -> Tuple[int, int, int]:
        """
        Estima el uso de contexto en tokens a partir de los mensajes.

        Aproximación: 1 token ≈ 4 caracteres (estimación conservadora
        para modelos BPE como LLaMA / Qwen). Se cuentan los caracteres
        de ``content`` y de los argumentos serializados de ``tool_calls``.

        Devuelve ``(tokens_estimados, max_tokens, porcentaje)``.
        El porcentaje se limita a ``[0, 100]``.
        """
        total_chars = 0
        for msg in messages:
            content = msg.get("content") or ""
            if isinstance(content, str):
                total_chars += len(content)
            # Contar también los argumentos de tool_calls.
            for tc in msg.get("tool_calls", []) or []:
                if isinstance(tc, dict):
                    fn = tc.get("function", {})
                    if isinstance(fn, dict):
                        args = fn.get("arguments", "")
                        if isinstance(args, str):
                            total_chars += len(args)
                        name = fn.get("name", "")
                        if isinstance(name, str):
                            total_chars += len(name)
        estimated_tokens = total_chars // 4
        max_tokens = max(1, LLM_N_CTX)
        percent = min(100, int(estimated_tokens * 100 / max_tokens))
        return estimated_tokens, LLM_N_CTX, percent

    def _publish_context_usage(
        self,
        task_id: int,
        messages: List[Dict[str, Any]],
    ) -> None:
        """Publica el uso de contexto estimado en la cola de la UI."""
        tokens_used, max_tokens, percent = self._estimate_context_usage(messages)
        self.ui_queue.put(
            {
                "type": "context_usage",
                "task_id": task_id,
                "tokens_used": tokens_used,
                "max_tokens": max_tokens,
                "percent": percent,
            }
        )

    # --- Bucle principal ---

    def run(self, task: Task) -> None:
        """Ejecuta el bucle de razonamiento para una tarea."""
        if task.id is None:
            return

        task_id = task.id
        self._set_status(task_id, TaskStatus.IN_PROGRESS)
        self._log(
            task_id,
            EventType.INFO,
            f"Tarea creada. Prompt: {task.prompt}",
        )

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": task.prompt},
        ]

        final_answer: Optional[str] = None
        # Contador de iteraciones sin tool_calls para detectar modelos que ignoran tools.
        no_tool_streak = 0
        # Flag: indica si el modelo ya usó herramientas en esta tarea.
        # Una vez que las usa, las respuestas sin tools se aceptan como finales.
        tools_were_used = False
        # Detector de bucles: si el modelo repite la misma respuesta
        # LOOP_THRESHOLD veces, se compacta el contexto.
        loop_detector = LoopDetector(LOOP_THRESHOLD)
        try:
            for iteration in range(1, MAX_ITERATIONS + 1):
                self._log(
                    task_id,
                    EventType.INFO,
                    f"--- Iteración {iteration}/{MAX_ITERATIONS} ---",
                )

                # Compactación preventiva por tamaño de contexto: antes de
                # enviar el historial al modelo, se estima el uso de tokens.
                # Si supera el porcentaje configurado (CONTEXT_COMPACT_THRESHOLD)
                # del límite n_ctx, se compacta el contexto para evitar que
                # el modelo se quede sin espacio o degrade la respuesta.
                # Esto es independiente de la detección de bucles.
                _, _, current_percent = self._estimate_context_usage(messages)
                if current_percent >= CONTEXT_COMPACT_THRESHOLD and len(messages) > 2:
                    self._log(
                        task_id,
                        EventType.INFO,
                        (
                            f"⚠ Contexto al {current_percent}% del límite "
                            f"(umbral {CONTEXT_COMPACT_THRESHOLD}%). "
                            f"Compactando preventivamente antes de enviar al modelo."
                        ),
                    )
                    messages = self._compact_context(task_id, messages, reason="exceso_contexto")
                    loop_detector.reset()
                    no_tool_streak = 0
                    self._publish_context_usage(task_id, messages)
                    continue

                # Forzar uso de herramientas solo si el modelo aún no las ha usado.
                tool_choice = "required" if no_tool_streak >= 1 else "auto"

                try:
                    raw = self.llm.chat(
                        messages,
                        tools=self.tools.to_openai_tools(),
                        tool_choice=tool_choice,
                    )
                except LLMError as e:
                    self._log(task_id, EventType.ERROR, f"Error LLM: {e}")
                    self._set_status(task_id, TaskStatus.FAILED)
                    return

                content, tool_calls = LLMConnector.parse_assistant_message(raw)

                # Detección de bucles: si la misma respuesta (contenido +
                # tool_calls) se repite LOOP_THRESHOLD veces, se compacta
                # el contexto para permitir al modelo replantear su estrategia.
                repeat_count = loop_detector.record(content, tool_calls)
                if repeat_count >= LOOP_THRESHOLD:
                    messages = self._compact_context(task_id, messages, reason="bucle")
                    loop_detector.reset()
                    # Tras compactar, reiniciamos también el contador de
                    # "no tool_calls" para dar margen al modelo a responder
                    # de nuevo con herramientas.
                    no_tool_streak = 0
                    # Publicar uso de contexto tras la compactación.
                    self._publish_context_usage(task_id, messages)
                    continue

                if content:
                    self._log(task_id, EventType.THOUGHT, content)

                # Registrar la respuesta del asistente en el historial ANTES
                # de cualquier otra decisión. Esto es imprescindible para que
                # la API acepte el historial en la siguiente iteración: si el
                # modelo responde solo con texto (sin tool_calls), el mensaje
                # assistant debe estar presente antes de inyectar cualquier
                # mensaje user (recordatorio). De lo contrario, el historial
                # queda como [system, user, user] y la API lo rechaza con
                # "conversation roles must alternate".
                assistant_msg: Dict[str, Any] = {
                    "role": "assistant",
                    "content": content or None,
                }
                if tool_calls:
                    assistant_msg["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": json.dumps(tc.arguments, ensure_ascii=False),
                            },
                        }
                        for tc in tool_calls
                    ]
                messages.append(assistant_msg)

                # Si hay tool_calls, ejecutarlos.
                if tool_calls:
                    tools_were_used = True
                    no_tool_streak = 0
                else:
                    # Sin tool_calls: decidir si es respuesta final válida
                    # o si hay que forzar el uso de herramientas.
                    #
                    # Las subtareas REQUIREMENTS y EXECUTION_VERIFICATION
                    # están diseñadas para terminar con una respuesta en
                    # texto puro (documento de requisitos o veredicto de
                    # verificación). En estos casos, el texto ES la respuesta
                    # final y NO debemos inyectar recordatorios ni seguir
                    # iterando.
                    text_only_subtask_types = {
                        SubtaskType.REQUIREMENTS,
                        SubtaskType.EXECUTION_VERIFICATION,
                    }
                    allows_text_only_answer = (
                        task.subtask_type in text_only_subtask_types
                    )

                    if tools_were_used or allows_text_only_answer:
                        final_answer = content or "(sin contenido)"
                        self._log(task_id, EventType.FINAL_ANSWER, final_answer)
                        self._set_status(
                            task_id,
                            TaskStatus.COMPLETED,
                            final_answer=final_answer,
                        )
                        return
                    no_tool_streak += 1
                    if no_tool_streak >= 3:
                        # Tras 3 intentos sin tools, aceptar como final.
                        final_answer = content or "(sin contenido)"
                        self._log(task_id, EventType.FINAL_ANSWER, final_answer)
                        self._set_status(
                            task_id,
                            TaskStatus.COMPLETED,
                            final_answer=final_answer,
                        )
                        return
                    self._log(
                        task_id,
                        EventType.INFO,
                        "El modelo no usó herramientas. Inyectando recordatorio.",
                    )
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "RECORDATORIO OBLIGATORIO: Debes usar las herramientas "
                                "disponibles (write_file, read_file, execute_command, etc.) "
                                "para completar la tarea. NO respondas solo con texto. "
                                "Llama a la herramienta apropiada AHORA con los argumentos "
                                "correctos en formato JSON."
                            ),
                        }
                    )
                    continue

                for tc in tool_calls:
                    self._log(
                        task_id,
                        EventType.TOOL_CALL,
                        (
                            f"Llamada a herramienta: {tc.name}\n"
                            f"Argumentos: {json.dumps(tc.arguments, ensure_ascii=False, indent=2)}"
                        ),
                    )
                    result = self._execute_tool_call(task_id, tc)
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": result.tool_call_id,
                            "content": result.output,
                        }
                    )
                    if tc.name in {"write_file", "execute_command", "delete_file"} and result.success:
                        # refrescamos explorador de ficheros
                        self.ui_queue.put({"type": "refresh_file_browser", "task_id": task_id})

                # Publicar uso de contexto tras procesar las herramientas
                # de esta iteración para que la UI actualice la barra.
                self._publish_context_usage(task_id, messages)

            # Agotó iteraciones.
            self._log(
                task_id,
                EventType.ERROR,
                f"Se alcanzó el máximo de iteraciones ({MAX_ITERATIONS}) sin respuesta final.",
            )
            self._set_status(task_id, TaskStatus.FAILED)

        except Exception as e:  # noqa: BLE001
            self._log(
                task_id,
                EventType.ERROR,
                f"Error inesperado en el agente: {e}\n{traceback.format_exc(limit=3)}",
            )
            self._set_status(task_id, TaskStatus.FAILED)


# ============================================================================
# ORQUESTADOR DE SUBTAREAS
# ============================================================================

# Prompts fijos que el sistema inyecta para cada tipo de subtarea.
# El LLM solo recibe el contexto del paso anterior; no decide la
# descomposición (esa decisión la toma el orquestador).
#
# Estas son las plantillas POR DEFECTO. Si existe el fichero
# ``subtareas.ini`` junto al ejecutable, las plantillas definidas allí
# tienen prioridad y sobrescriben las correspondientes aquí.
_DEFAULT_SUBTASK_PROMPTS: Dict[SubtaskType, str] = {
    SubtaskType.REQUIREMENTS: (
        "Eres un analista técnico. Tu única misión en esta subtarea es "
        "producir un documento de REQUISITOS TÉCNICOS para la tarea del "
        "usuario indicada más abajo.\n\n"
        "REGLAS:\n"
        "1. NO ejecutes ninguna acción (no llames a write_file, "
        "execute_command, delete_file, etc.).\n"
        "2. NO modifiques archivos. Solo analiza y documenta.\n"
        "3. Tu respuesta final debe ser un documento estructurado con:\n"
        "   - Objetivo principal\n"
        "   - Restricciones y dependencias\n"
        "   - Archivos a crear o modificar (con rutas relativas al workspace)\n"
        "   - Comandos a ejecutar (si aplica)\n"
        "   - Criterios de aceptación verificables\n"
        "4. Sé conciso pero completo. Usa listas y secciones claras.\n\n"
        "TAREA DEL USUARIO:\n{user_prompt}"
    ),
    SubtaskType.DEVELOPMENT: (
        "Eres un desarrollador. Tu misión es implementar la solución "
        "basándote en los REQUISITOS TÉCNICOS proporcionados más abajo.\n\n"
        "REGLAS:\n"
        "1. USA las herramientas disponibles (write_file, execute_command, "
        "read_file, etc.) para implementar la solución.\n"
        "2. Sigue los requisitos al pie de la letra.\n"
        "3. Cuando termines la implementación, proporciona una respuesta "
        "final concisa describiendo qué has creado/modificado y dónde.\n"
        "4. NO verifiques la solución (eso lo hará la siguiente subtarea).\n\n"
        "REQUISITOS TÉCNICOS:\n{requirements}\n\n"
        "TAREA ORIGINAL DEL USUARIO:\n{user_prompt}"
    ),
    SubtaskType.EXECUTION_VERIFICATION: (
        "Eres un verificador. Tu misión es EJECUTAR y COMPROBAR que la "
        "solución implementada cumple los requisitos.\n\n"
        "REGLAS:\n"
        "1. USA las herramientas disponibles (execute_command, read_file, "
        "list_directory, etc.) para ejecutar y verificar la solución.\n"
        "2. Compara el resultado con los criterios de aceptación de los "
        "requisitos.\n"
        "3. Tu respuesta final debe comenzar EXACTAMENTE con una de estas "
        "dos líneas (sin preámbulo):\n"
        "   - 'VERIFICACIÓN EXITOSA: ...' (seguido de un resumen breve)\n"
        "   - 'VERIFICACIÓN FALLIDA: ...' (seguido de la lista detallada "
        "de errores o problemas encontrados)\n"
        "4. Sé objetivo: si hay cualquier error, fallo de comando, archivo "
        "faltante o comportamiento inesperado, marca como FALLIDA.\n\n"
        "SOLUCIÓN IMPLEMENTADA:\n{solution}\n\n"
        "REQUISITOS TÉCNICOS:\n{requirements}\n\n"
        "TAREA ORIGINAL DEL USUARIO:\n{user_prompt}"
    ),
    SubtaskType.RECTIFICATION: (
        "Eres un desarrollador en modo corrección. La solución anterior "
        "ha FALLADO la verificación. Tu misión es producir una versión "
        "CORREGIDA de la solución.\n\n"
        "REGLAS:\n"
        "1. Analiza cuidadosamente los errores reportados.\n"
        "2. USA las herramientas disponibles (write_file, execute_command, "
        "read_file, etc.) para corregir los problemas.\n"
        "3. NO repitas los mismos errores: cambia la estrategia si es "
        "necesario.\n"
        "4. Cuando termines, proporciona una respuesta final concisa "
        "describiendo qué has corregido y por qué.\n\n"
        "ERRORES REPORTADOS EN LA VERIFICACIÓN:\n{verification_errors}\n\n"
        "SOLUCIÓN ANTERIOR (que falló):\n{previous_solution}\n\n"
        "REQUISITOS TÉCNICOS:\n{requirements}\n\n"
        "TAREA ORIGINAL DEL USUARIO:\n{user_prompt}"
    ),
}


def _load_subtask_prompts_from_ini(
    path: str = SUBTAREAS_INI_PATH,
) -> Optional[Dict[SubtaskType, str]]:
    """
    Carga las plantillas de subtareas desde ``subtareas.ini``.

    El fichero debe tener una sección por cada ``SubtaskType`` (usando el
    ``value`` del enum como nombre de sección: ``requirements``,
    ``development``, ``execution_verification``, ``rectification``) y una
    clave ``prompt`` con la plantilla.

    Retorna ``None`` si el fichero no existe. Si existe pero está vacío o
    no contiene ninguna sección válida, retorna un diccionario vacío.
    """
    if not os.path.exists(path):
        return None

    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except configparser.Error as e:
        print(
            f"[AVISO] Error leyendo {path}: {e}. "
            "Usando plantillas por defecto."
        )
        return {}

    loaded: Dict[SubtaskType, str] = {}
    for subtask_type in SubtaskType:
        section = subtask_type.value
        if parser.has_section(section) and parser.has_option(section, "prompt"):
            template = parser.get(section, "prompt").strip()
            if template:
                loaded[subtask_type] = template
    return loaded


def _build_subtask_prompts() -> Dict[SubtaskType, str]:
    """
    Construye el diccionario final de plantillas de subtareas.

    Prioridad (de mayor a menor):
        1. Plantillas definidas en ``subtareas.ini`` (si el fichero existe).
        2. Plantillas por defecto definidas en ``_DEFAULT_SUBTASK_PROMPTS``.
    """
    prompts: Dict[SubtaskType, str] = dict(_DEFAULT_SUBTASK_PROMPTS)
    overrides = _load_subtask_prompts_from_ini()
    if overrides:
        prompts.update(overrides)
    return prompts


# Plantillas activas que el orquestador utiliza en tiempo de ejecución.
# Se inicializan al cargar el módulo combinando ``subtareas.ini`` (si
# existe) con los valores por defecto.
_SUBTASK_PROMPTS: Dict[SubtaskType, str] = _build_subtask_prompts()

# Marcadores que la subtarea de verificación debe producir.
_VERIFICATION_SUCCESS_PREFIX = "VERIFICACIÓN EXITOSA:"
_VERIFICATION_FAILURE_PREFIX = "VERIFICACIÓN FALLIDA:"


class TaskOrchestrator:
    """
    Orquesta la descomposición de una tarea del usuario en subtareas.

    Flujo normal:
        1. REQUIREMENTS       → produce el documento de requisitos.
        2. DEVELOPMENT        → implementa la solución.
        3. EXECUTION_VERIFICATION → ejecuta y verifica.

    Si la verificación falla, se inserta un ciclo de rectificación:
        4. RECTIFICATION      → corrige la solución.
        5. EXECUTION_VERIFICATION → vuelve a verificar.

    El ciclo se repite hasta que la verificación sea exitosa o se
    alcance ``MAX_RECTIFICATION_RETRIES``. En ese caso, la tarea
    padre se marca como FAILED.

    Cada subtarea es una ``Task`` independiente en la base de datos,
    con ``parent_task_id`` apuntando a la tarea padre. Esto permite
    trazabilidad completa y visualización jerárquica en el dashboard.
    """

    def __init__(
        self,
        db: Database,
        agent: Agent,
        ui_queue: "queue.Queue[Dict[str, Any]]",
        max_retries: int = MAX_RECTIFICATION_RETRIES,
    ) -> None:
        self.db = db
        self.agent = agent
        self.ui_queue = ui_queue
        self.max_retries = max_retries

    # --- API pública ---

    def run(self, parent_task: Task) -> None:
        """
        Ejecuta el flujo completo de descomposición para una tarea padre.

        La tarea padre ya debe existir en la BD (creada por el dashboard).
        Este método crea las subtareas, las ejecuta secuencialmente y
        actualiza el estado de la tarea padre al final.
        """
        if parent_task.id is None:
            return
        parent_id = parent_task.id

        self._log_parent(
            parent_id,
            EventType.ORCHESTRATION_DECISION,
            (
                f"🎼 Orquestación iniciada. Se crearán 3 subtareas: "
                f"Requisitos → Desarrollo → Ejecución/Verificación. "
                f"Máx. reintentos de rectificación: {self.max_retries}."
            ),
        )

        # --- Subtarea 1: Requisitos ---
        requirements_task = self._create_subtask(
            parent_id,
            SubtaskType.REQUIREMENTS,
            attempt=0,
            prompt=_SUBTASK_PROMPTS[SubtaskType.REQUIREMENTS].format(
                user_prompt=parent_task.prompt,
            ),
        )
        requirements_output = self._run_subtask(requirements_task)
        if requirements_output is None:
            self._fail_parent(parent_id, "La subtarea de requisitos no produjo resultado.")
            return

        # --- Subtarea 2: Desarrollo ---
        development_task = self._create_subtask(
            parent_id,
            SubtaskType.DEVELOPMENT,
            attempt=0,
            prompt=_SUBTASK_PROMPTS[SubtaskType.DEVELOPMENT].format(
                requirements=requirements_output,
                user_prompt=parent_task.prompt,
            ),
        )
        solution_output = self._run_subtask(development_task)
        if solution_output is None:
            self._fail_parent(parent_id, "La subtarea de desarrollo no produjo resultado.")
            return

        # --- Subtarea 3: Ejecución y verificación (con ciclo de rectificación) ---
        attempt = 0
        verification_output: Optional[str] = None
        previous_solution = solution_output

        while True:
            verification_task = self._create_subtask(
                parent_id,
                SubtaskType.EXECUTION_VERIFICATION,
                attempt=attempt,
                prompt=_SUBTASK_PROMPTS[SubtaskType.EXECUTION_VERIFICATION].format(
                    solution=previous_solution,
                    requirements=requirements_output,
                    user_prompt=parent_task.prompt,
                ),
            )
            verification_output = self._run_subtask(verification_task)

            if verification_output is None:
                self._fail_parent(
                    parent_id,
                    f"La subtarea de verificación (intento {attempt + 1}) "
                    f"no produjo resultado.",
                )
                return

            if self._is_verification_successful(verification_output):
                # Éxito: terminamos el flujo.
                self._log_parent(
                    parent_id,
                    EventType.ORCHESTRATION_DECISION,
                    (
                        f"✅ Verificación exitosa en el intento {attempt + 1}. "
                        f"Tarea padre completada."
                    ),
                )
                self._complete_parent(parent_id, verification_output)
                return

            # Verificación fallida: decidir si reintentamos.
            if attempt >= self.max_retries:
                self._log_parent(
                    parent_id,
                    EventType.ORCHESTRATION_DECISION,
                    (
                        f"⛔ Se agotaron los reintentos de rectificación "
                        f"({self.max_retries}). Tarea padre marcada como FAILED."
                    ),
                )
                self._fail_parent(
                    parent_id,
                    f"Verificación fallida tras {self.max_retries} reintentos. "
                    f"Último error: {verification_output[:200]}",
                )
                return

            # Crear subtarea de rectificación y volver a verificar.
            self._log_parent(
                parent_id,
                EventType.ORCHESTRATION_DECISION,
                (
                    f"🔧 Verificación fallida (intento {attempt + 1}). "
                    f"Creando subtarea de rectificación "
                    f"({attempt + 1}/{self.max_retries})."
                ),
            )
            rectification_task = self._create_subtask(
                parent_id,
                SubtaskType.RECTIFICATION,
                attempt=attempt,
                prompt=_SUBTASK_PROMPTS[SubtaskType.RECTIFICATION].format(
                    verification_errors=verification_output,
                    previous_solution=previous_solution,
                    requirements=requirements_output,
                    user_prompt=parent_task.prompt,
                ),
            )
            rectified_solution = self._run_subtask(rectification_task)
            if rectified_solution is None:
                self._fail_parent(
                    parent_id,
                    f"La subtarea de rectificación (intento {attempt + 1}) "
                    f"no produjo resultado.",
                )
                return

            previous_solution = rectified_solution
            attempt += 1

    # --- Helpers internos ---

    def _create_subtask(
        self,
        parent_id: int,
        subtask_type: SubtaskType,
        attempt: int,
        prompt: str,
    ) -> Task:
        """Crea una subtarea en la BD y la registra en el historial del padre."""
        title_prefix = f"[{subtask_type.icon} {subtask_type.label}]"
        if attempt > 0:
            title_prefix += f" (intento {attempt + 1})"
        title = f"{title_prefix} #{parent_id}"

        task = self.db.create_task(
            title=title,
            prompt=prompt,
            parent_task_id=parent_id,
            subtask_type=subtask_type,
            attempt_number=attempt,
        )
        self._log_parent(
            parent_id,
            EventType.SUBTASK_CREATED,
            (
                f"➕ Subtarea creada: #{task.id} — {subtask_type.label} "
                f"(intento {attempt + 1})"
            ),
        )
        # Notificar a la UI para que refresque el tablero.
        self.ui_queue.put({"type": "status_change", "task_id": task.id, "status": TaskStatus.PENDING.value})
        return task

    def _run_subtask(self, task: Task) -> Optional[str]:
        """
        Ejecuta una subtarea usando el Agent y devuelve su ``final_answer``.

        Retorna ``None`` si la subtarea falla (estado FAILED).
        """
        if task.id is None:
            return None
        self._log_parent(
            task.parent_task_id or task.id,
            EventType.SUBTASK_STARTED,
            f"▶ Iniciando subtarea #{task.id} — {task.subtask_type.label if task.subtask_type else '?'}",
        )
        # El Agent.run() se ejecuta en el hilo del orquestador (que ya es
        # un hilo separado lanzado por el dashboard). Bloqueamos aquí
        # hasta que la subtarea termine.
        self.agent.run(task)
        # Releer la tarea para obtener el estado y respuesta final.
        updated = self.db.get_task(task.id)
        if updated is None:
            return None
        if updated.status == TaskStatus.COMPLETED:
            self._log_parent(
                task.parent_task_id or task.id,
                EventType.SUBTASK_COMPLETED,
                f"✔ Subtarea #{task.id} completada.",
            )
            return updated.final_answer
        # Cualquier estado no terminal se considera fallo.
        self._log_parent(
            task.parent_task_id or task.id,
            EventType.SUBTASK_FAILED,
            (
                f"✘ Subtarea #{task.id} finalizada con estado "
                f"{updated.status.value}."
            ),
        )
        return None

    @staticmethod
    def _is_verification_successful(verification_output: str) -> bool:
        """
        Determina si la salida de la subtarea de verificación indica éxito.

        La subtarea de verificación debe comenzar su respuesta final con
        ``VERIFICACIÓN EXITOSA:`` o ``VERIFICACIÓN FALLIDA:``. Cualquier
        otro contenido se considera fallo (por seguridad).
        """
        text = verification_output.strip()
        return text.startswith(_VERIFICATION_SUCCESS_PREFIX)

    def _complete_parent(self, parent_id: int, final_answer: str) -> None:
        """Marca la tarea padre como COMPLETED con la respuesta final."""
        self.db.update_task_status(
            parent_id,
            TaskStatus.COMPLETED,
            final_answer=final_answer,
        )
        self.ui_queue.put(
            {"type": "status_change", "task_id": parent_id, "status": TaskStatus.COMPLETED.value}
        )
        self._log_parent(
            parent_id,
            EventType.STATUS_CHANGE,
            f"🏁 Tarea padre #{parent_id} → COMPLETED.",
        )

    def _fail_parent(self, parent_id: int, reason: str) -> None:
        """Marca la tarea padre como FAILED con un motivo."""
        self.db.update_task_status(
            parent_id,
            TaskStatus.FAILED,
            final_answer=f"FAILED: {reason}",
        )
        self.ui_queue.put(
            {"type": "status_change", "task_id": parent_id, "status": TaskStatus.FAILED.value}
        )
        self._log_parent(
            parent_id,
            EventType.STATUS_CHANGE,
            f"⛔ Tarea padre #{parent_id} → FAILED. Motivo: {reason}",
        )

    def _log_parent(
        self,
        parent_id: int,
        event_type: EventType,
        content: str,
    ) -> None:
        """Registra un evento en el historial de la tarea padre."""
        self.db.add_history(parent_id, event_type, content)
        self.ui_queue.put(
            {
                "type": "history_update",
                "task_id": parent_id,
                "event_type": event_type.value,
                "content": content,
            }
        )


# ============================================================================
# INTERFAZ DE USUARIO (Dashboard tkinter)
# ============================================================================

EVENT_STATUS_COLORS = {
    TaskStatus.PENDING.value: CONFIG.ui_status_pending,
    TaskStatus.IN_PROGRESS.value: CONFIG.ui_status_in_progress,
    TaskStatus.AWAITING_APPROVAL.value: CONFIG.ui_status_awaiting_approval,
    TaskStatus.COMPLETED.value: CONFIG.ui_status_completed,
    TaskStatus.FAILED.value: CONFIG.ui_status_failed,
    TaskStatus.CANCELLED.value: CONFIG.ui_status_cancelled,
}

EVENT_LABELS = {
    EventType.THOUGHT.value: "💭 Pensamiento",
    EventType.TOOL_CALL.value: "🔧 Tool Call",
    EventType.TOOL_RESULT.value: "📥 Tool Result",
    EventType.APPROVAL_REQUEST.value: "⚠ Solicitud de aprobación",
    EventType.APPROVAL_GRANTED.value: "✅ Aprobado",
    EventType.APPROVAL_DENIED.value: "❌ Denegado",
    EventType.FINAL_ANSWER.value: "🏁 Respuesta final",
    EventType.ERROR.value: "⛔ Error",
    EventType.STATUS_CHANGE.value: "🔄 Estado",
    EventType.INFO.value: "ℹ Info",
    EventType.LOOP_DETECTED.value: "🔁 Bucle detectado",
    EventType.CONTEXT_COMPACTED.value: "🗜 Contexto compactado",
    EventType.SUBTASK_CREATED.value: "➕ Subtarea creada",
    EventType.SUBTASK_STARTED.value: "▶ Subtarea iniciada",
    EventType.SUBTASK_COMPLETED.value: "✔ Subtarea completada",
    EventType.SUBTASK_FAILED.value: "✘ Subtarea fallida",
    EventType.ORCHESTRATION_DECISION.value: "🎼 Decisión de orquestación",
}


def _format_approval_args(tool_name: str, args: Dict[str, Any]) -> str:
    """
    Formatea los argumentos de una solicitud de aprobación como texto legible.

    En lugar de mostrar el JSON crudo, presenta cada argumento en una línea
    con etiqueta clara. Para write_file, muestra también una vista previa del
    contenido (limitada a 500 caracteres) para que el usuario pueda revisarlo.
    """
    if not args:
        return "(sin argumentos)"

    lines: List[str] = []

    if tool_name == "write_file":
        path = args.get("path", "")
        content = args.get("content", "")
        preview = content if len(content) <= 500 else content[:500] + "\n... [contenido truncado, total: {} caracteres]".format(len(content))
        lines.append(f"📄 Archivo a escribir: {path}")
        lines.append(f"📏 Tamaño: {len(content)} caracteres")
        lines.append("")
        lines.append("── Vista previa del contenido ──")
        lines.append(preview)
    elif tool_name == "execute_command":
        cmd = args.get("command", "")
        lines.append(f"💻 Comando a ejecutar:")
        lines.append(f"   {cmd}")
    elif tool_name == "delete_file":
        path = args.get("path", "")
        lines.append(f"🗑️  Ruta a eliminar: {path}")
    elif tool_name == "read_file":
        path = args.get("path", "")
        lines.append(f"📖 Archivo a leer: {path}")
    elif tool_name == "list_directory":
        path = args.get("path", ".")
        lines.append(f"📁 Directorio a listar: {path}")
    elif tool_name == "search_files":
        pattern = args.get("pattern", "")
        path = args.get("path", ".")
        lines.append(f"🔍 Patrón de búsqueda: {pattern}")
        lines.append(f"📁 En directorio: {path}")
    elif tool_name == "get_current_time":
        lines.append("🕐 Solicitar fecha/hora actual (sin argumentos)")
    else:
        # Herramienta desconocida: mostrar como lista clave-valor.
        for key, value in args.items():
            lines.append(f"• {key}: {value}")

    return "\n".join(lines)


def _format_size(num_bytes: int) -> str:
    """Formatea un tamaño en bytes como cadena legible (B/KB/MB/GB)."""
    try:
        n = int(num_bytes)
    except (TypeError, ValueError):
        return "?"
    if n < 0:
        return "?"
    if n < 1024:
        return f"{n} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if n < 1024.0:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"


class Dashboard:
    """Dashboard interactivo con las 4 zonas de la especificación."""

    POLL_INTERVAL_MS = 200

    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title("Gestor de Agentes LLM — HITL")
        self.root.geometry("1280x820")
        # Tamaño mínimo: ancho suficiente para el tablero en 2 columnas y
        # alto suficiente para que el prompt (Zona 1) y el panel de
        # aprobación (Zona 4) queden siempre visibles aunque la ventana
        # se reduzca verticalmente.
        self.root.minsize(1000, 560)

        # Aplicar configuración de UI desde config.ini.
        self._apply_ui_config()

        self.db = Database()
        # Limpieza de arranque: elimina cualquier tarea que NO haya terminado
        # (PENDING, IN_PROGRESS, AWAITING_APPROVAL). Esto cubre cierres
        # bruscos del programa o fallos del agente en sesiones anteriores
        # que dejaron tareas a medias o esperando aprobación humana.
        try:
            unfinished = TaskStatus.unfinished()
            removed = self.db.delete_tasks_by_status(unfinished)
            if removed > 0:
                states = ", ".join(s.value for s in unfinished)
                print(
                    f"[init] Se eliminaron {removed} tarea(s) no terminada(s) "
                    f"en estado {states} al arrancar la aplicación."
                )
        except Exception as exc:  # noqa: BLE001
            print(f"[init] Aviso: no se pudo limpiar el historial de tareas: {exc}")
        self.tools = ToolsRegistry()
        self.llm = LLMConnector()
        self.ui_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.permissions = PermissionManager(self.ui_queue)
        self.agent = Agent(self.db, self.llm, self.tools, self.permissions, self.ui_queue)
        self.orchestrator = TaskOrchestrator(
            db=self.db,
            agent=self.agent,
            ui_queue=self.ui_queue,
            max_retries=MAX_RECTIFICATION_RETRIES,
        )

        self.selected_task_id: Optional[int] = None
        self._build_styles()
        self._build_layout()
        self._refresh_task_lists()
        self._poll_queue()

    def _apply_ui_config(self) -> None:
        """Aplica colores, fuente y modo fullscreen desde la configuración."""
        try:
            self.root.configure(bg=CONFIG.ui_bg_color)
        except Exception:  # noqa: BLE001
            pass
        # Fuente base para widgets que no usen estilos ttk.
        try:
            default_font = (CONFIG.ui_font_family, CONFIG.ui_font_size)
            self.root.option_add("*Font", default_font)
        except Exception:  # noqa: BLE001
            pass
        # Fullscreen si está habilitado en config.ini.
        if CONFIG.ui_fullscreen:
            try:
                self.root.state("zoomed")
            except Exception:  # noqa: BLE001
                self.root.attributes("-fullscreen", True)

    def _build_config_label_text(self) -> str:
        """Genera el texto de la barra de estado según el modo LLM."""
        if LLM_MODE == "local":
            return (
                f"LLM: {LLM_MODEL}  ·  Modo: Local (llama-cpp-python, sin endpoint HTTP)  ·  "
                f"Workspace: {WORKSPACE_DIR}"
            )
        return (
            f"LLM: {LLM_MODEL}  ·  Modo: HTTP  ·  "
            f"Endpoint: {LLM_BASE_URL}  ·  Workspace: {WORKSPACE_DIR}"
        )

    # --- Estilos ---

    def _build_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:  # noqa: BLE001
            pass
        # Sin bordes: los objetos se diferencian únicamente por color de fondo.
        style.configure("TFrame", background=CONFIG.ui_frame_bg, borderwidth=0, relief="flat")
        style.configure("Card.TFrame", background=CONFIG.ui_card_bg, borderwidth=0, relief="flat")
        # Estilos del explorador de ficheros (Treeview).
        style.configure(
            "Treeview",
            background=CONFIG.ui_browser_bg,
            foreground=CONFIG.ui_browser_fg,
            fieldbackground=CONFIG.ui_browser_bg,
            borderwidth=0,
            rowheight=22,
        )
        style.map(
            "Treeview",
            background=[("selected", CONFIG.ui_browser_selected_bg)],
            foreground=[("selected", CONFIG.ui_browser_selected_fg)],
        )
        style.configure(
            "Treeview.Heading",
            background=CONFIG.ui_browser_header_bg,
            foreground=CONFIG.ui_browser_fg,
            relief="flat",
        )
        style.map(
            "Treeview.Heading",
            background=[("active", CONFIG.ui_browser_header_bg)],
        )
        style.configure(
            "TLabel",
            background=CONFIG.ui_frame_bg,
            foreground=CONFIG.ui_fg_color,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size),
        )
        style.configure(
            "Card.TLabel",
            background=CONFIG.ui_card_bg,
            foreground=CONFIG.ui_fg_color,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size),
        )
        style.configure(
            "Title.TLabel",
            background=CONFIG.ui_frame_bg,
            foreground=CONFIG.ui_fg_color,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size + 2, "bold"),
        )
        style.configure(
            "Header.TLabel",
            background=CONFIG.ui_card_bg,
            foreground=CONFIG.ui_fg_color,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size + 1, "bold"),
        )
        style.configure("Status.PENDING.TLabel", foreground=EVENT_STATUS_COLORS[TaskStatus.PENDING.value])
        style.configure("Status.IN_PROGRESS.TLabel", foreground=EVENT_STATUS_COLORS[TaskStatus.IN_PROGRESS.value])
        style.configure("Status.AWAITING_APPROVAL.TLabel", foreground=EVENT_STATUS_COLORS[TaskStatus.AWAITING_APPROVAL.value])
        style.configure("Status.COMPLETED.TLabel", foreground=EVENT_STATUS_COLORS[TaskStatus.COMPLETED.value])
        style.configure("Status.FAILED.TLabel", foreground=EVENT_STATUS_COLORS[TaskStatus.FAILED.value])
        style.configure("Status.CANCELLED.TLabel", foreground=EVENT_STATUS_COLORS[TaskStatus.CANCELLED.value])
        # Estilo base de todos los botones (los específicos heredan de aquí).
        style.configure(
            "TButton",
            background=CONFIG.ui_button_bg,
            foreground=CONFIG.ui_button_fg,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size),
            borderwidth=0,
        )
        style.map(
            "TButton",
            background=[
                ("active", CONFIG.ui_button_bg),
                ("disabled", CONFIG.ui_card_bg),
            ],
            foreground=[
                ("disabled", CONFIG.ui_status_cancelled),
            ],
        )
        style.configure(
            "Execute.TButton",
            background=CONFIG.ui_button_bg,
            foreground=CONFIG.ui_button_fg,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size, "bold"),
            borderwidth=0,
        )
        style.configure(
            "Allow.TButton",
            background=CONFIG.ui_button_bg,
            foreground=CONFIG.ui_button_fg,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size, "bold"),
            borderwidth=0,
        )
        style.configure(
            "Deny.TButton",
            background=CONFIG.ui_button_bg,
            foreground=CONFIG.ui_button_fg,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size, "bold"),
            borderwidth=0,
        )
        # Casillas de verificación (antes no estaban configuradas).
        style.configure(
            "Card.TCheckbutton",
            background=CONFIG.ui_card_bg,
            foreground=CONFIG.ui_checkbox_fg,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size),
        )
        style.map(
            "Card.TCheckbutton",
            background=[("active", CONFIG.ui_card_bg)],
            foreground=[("disabled", CONFIG.ui_status_cancelled)],
        )

    # --- Layout ---

    def _make_scrollable_frame(self, parent: ttk.Frame) -> ttk.Frame:
        """
        Crea un contenedor con scroll vertical (Canvas + Scrollbar + Frame interno).

        Empaqueta el contenedor en `parent` (fill="both", expand=True) y devuelve
        el Frame interno donde se añadirán los widgets hijos. El contenedor ocupa
        el espacio disponible en `parent` sin crecer indefinidamente, evitando que
        desplace otros elementos de la interfaz.
        """
        container = ttk.Frame(parent, style="Card.TFrame")
        container.pack(fill="both", expand=True)

        canvas = Canvas(
            container,
            bg=CONFIG.ui_card_bg,
            highlightthickness=0,
            borderwidth=0,
        )
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        inner = ttk.Frame(canvas, style="Card.TFrame")
        window_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_inner_configure(_event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _on_canvas_configure(event):
            canvas.itemconfig(window_id, width=event.width)

        inner.bind("<Configure>", _on_inner_configure)
        canvas.bind("<Configure>", _on_canvas_configure)

        # Scroll con rueda del ratón.
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind("<Enter>", lambda _e: canvas.bind_all("<MouseWheel>", _on_mousewheel))
        canvas.bind("<Leave>", lambda _e: canvas.unbind_all("<MouseWheel>"))

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        return inner

    def _build_layout(self) -> None:
        # ------------------------------------------------------------------
        # Distribución vertical del dashboard:
        #
        #   ┌──────────────────────────────────────────────┐
        #   │  Zona 1: Prompt + Ejecutar   (top, fijo)     │  ← SIEMPRE visible
        #   ├──────────────────────────────────────────────┤
        #   │                                              │
        #   │  Zona 2: Tablero 2 columnas  (middle)        │  ← se reduce
        #   │                                              │
        #   ├──────────────────────────────────────────────┤
        #   │  Zona 3: Historial           (bottom)        │  ← se reduce
        #   ├──────────────────────────────────────────────┤
        #   │  Zona 4: Permisos (HITL)     (bottom, fijo)  │  ← SIEMPRE visible
        #   └──────────────────────────────────────────────┘
        #
        # Las zonas 1 y 4 se empaquetan primero y último respectivamente,
        # de modo que si la ventana se reduce verticalmente el espacio
        # sobrante se recorta de las zonas 2 y 3, manteniendo prompt y
        # permisos siempre visibles.
        # ------------------------------------------------------------------

        # Zona 1: Prompt + Ejecutar (superior) — SIEMPRE VISIBLE.
        top = ttk.Frame(self.root, style="TFrame", padding=10)
        top.pack(side="top", fill="x")

        ttk.Label(top, text="📝 Nueva instrucción para el agente", style="Title.TLabel").pack(
            anchor="w"
        )
        self.prompt_text = Text(
            top,
            height=4,
            wrap="word",
            font=(CONFIG.ui_mono_font_family, CONFIG.ui_mono_font_size),
            relief="flat",
            borderwidth=0,
            background=CONFIG.ui_prompt_bg,
            foreground=CONFIG.ui_prompt_fg,
            highlightthickness=0,
        )
        self.prompt_text.pack(fill="x", pady=(6, 6))

        btn_row = ttk.Frame(top, style="TFrame")
        btn_row.pack(fill="x")
        ttk.Button(
            btn_row,
            text="▶ Ejecutar",
            style="Execute.TButton",
            command=self._on_execute,
        ).pack(side="left")
        ttk.Button(
            btn_row,
            text="🧹 Limpiar",
            command=self._on_clear_prompt,
        ).pack(side="left", padx=(8, 0))
        self.config_label = ttk.Label(
            btn_row,
            text=self._build_config_label_text(),
            style="TLabel",
        )
        self.config_label.pack(side="right")

        # Zona 4: Aviso de aprobación (condicional, parte inferior) — SIEMPRE VISIBLE.
        # Se empaqueta con side="bottom" antes que las zonas 2 y 3 para que
        # tenga prioridad y no quede oculto si la ventana se reduce verticalmente.
        self.approval_frame = ttk.Frame(self.root, style="Card.TFrame", padding=10)
        self.approval_frame.pack(side="bottom", fill="x", padx=10, pady=(0, 10))
        self._build_approval_panel()

        # Barra de progreso de consumo de tokens — SIEMPRE VISIBLE.
        # Se empaqueta con side="bottom" DESPUÉS del panel de aprobación, por
        # lo que tkinter la coloca visualmente ENCIMA de dicho panel. Al estar
        # fuera del contenedor intermedio (que es el que se reduce al
        # redimensionar la ventana), nunca queda oculta.
        self._build_context_bar()

        # Contenedor intermedio que ocupa el espacio restante entre el prompt
        # (arriba) y la barra de contexto (abajo). Alberga las zonas 2 y 3.
        middle_container = ttk.Frame(self.root, style="TFrame")
        middle_container.pack(side="top", fill="both", expand=True)
        middle_container.pack_propagate(False)

        # Zona 2: Tablero 2 columnas (medio).
        # Altura fija para que el tablero no crezca al añadir tareas y desplace
        # los botones de aprobación fuera de la pantalla.
        middle = ttk.Frame(middle_container, style="TFrame", padding=(10, 0))
        middle.pack(side="top", fill="x")
        middle.pack_propagate(False)
        middle.configure(height=420)
        middle.columnconfigure(0, weight=1)
        middle.columnconfigure(1, weight=1)
        middle.rowconfigure(1, weight=1)

        ttk.Label(
            middle,
            text="📋 Tablero de tareas",
            style="Title.TLabel",
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))

        # Columna izquierda: pendientes / en ejecución.
        left = ttk.Frame(middle, style="Card.TFrame", padding=8)
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 5))
        ttk.Label(
            left,
            text="Pendientes y en ejecución",
            style="Header.TLabel",
        ).pack(anchor="w")
        self.left_list_frame = self._make_scrollable_frame(left)

        # Columna derecha: ejecutadas / históricas.
        right = ttk.Frame(middle, style="Card.TFrame", padding=8)
        right.grid(row=1, column=1, sticky="nsew", padx=(5, 0))
        ttk.Label(
            right,
            text="Ejecutadas / Históricas",
            style="Header.TLabel",
        ).pack(anchor="w")
        self.right_list_frame = self._make_scrollable_frame(right)

        # Zona 3: Historial por tarea (izquierda) + Explorador de ficheros (derecha).
        # Es la zona que se reduce primero cuando la ventana pierde altura,
        # preservando el prompt y el panel de aprobación.
        # El ancho se reparte 50/50 entre historial (columna 0) y explorador
        # (columna 1) mediante columnconfigure(weight=1) en ambos.
        bottom = ttk.Frame(middle_container, style="TFrame", padding=(10, 8, 10, 4))
        bottom.pack(side="top", fill="both", expand=True)
        bottom.columnconfigure(0, weight=1)  # Historial: 50%
        bottom.columnconfigure(1, weight=1)  # Explorador: 50%
        bottom.rowconfigure(0, weight=1)

        # --- Columna izquierda: Historial de la tarea seleccionada ---
        history_panel = ttk.Frame(bottom, style="Card.TFrame", padding=8)
        history_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        history_header = ttk.Frame(history_panel, style="Card.TFrame")
        history_header.pack(fill="x")
        self.history_title_var = StringVar(value="Historial de tarea (ninguna seleccionada)")
        ttk.Label(
            history_header,
            textvariable=self.history_title_var,
            style="Header.TLabel",
        ).pack(side="left")
        ttk.Button(
            history_header,
            text="🔄 Refrescar",
            command=self._refresh_task_lists,
        ).pack(side="right")

        self.history_view = ScrolledText(
            history_panel,
            height=12,
            wrap="word",
            font=(CONFIG.ui_mono_font_family, CONFIG.ui_mono_font_size - 1),
            state="disabled",
            background=CONFIG.ui_history_bg,
            foreground=CONFIG.ui_history_fg,
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
        )
        # Tags de color para resaltar tipos de evento en el historial.
        # Solo cambia el color del texto; el fondo se mantiene igual.
        self.history_view.tag_configure(
            "final_answer",
            foreground=CONFIG.ui_final_answer_fg,
            font=(CONFIG.ui_mono_font_family, CONFIG.ui_mono_font_size, "bold"),
        )
        self.history_view.tag_configure(
            "thought",
            foreground=CONFIG.ui_thought_fg,
            font=(CONFIG.ui_mono_font_family, CONFIG.ui_mono_font_size - 1, "italic"),
        )
        self.history_view.tag_configure(
            "info",
            foreground=CONFIG.ui_info_fg,
        )
        self.history_view.tag_configure(
            "tool_call",
            foreground=CONFIG.ui_tool_call_fg,
        )
        self.history_view.tag_configure(
            "tool_result",
            foreground=CONFIG.ui_tool_result_fg,
        )
        self.history_view.tag_configure(
            "approval_request",
            foreground=CONFIG.ui_approval_request_fg,
        )
        self.history_view.tag_configure(
            "approval_granted",
            foreground=CONFIG.ui_approval_granted_fg,
        )
        self.history_view.tag_configure(
            "approval_denied",
            foreground=CONFIG.ui_approval_denied_fg,
        )
        self.history_view.tag_configure(
            "error",
            foreground=CONFIG.ui_error_fg,
        )
        self.history_view.tag_configure(
            "status_change",
            foreground=CONFIG.ui_status_change_fg,
        )
        self.history_view.tag_configure(
            "loop_detected",
            foreground=CONFIG.ui_loop_detected_fg,
        )
        self.history_view.tag_configure(
            "context_compacted",
            foreground=CONFIG.ui_context_compacted_fg,
        )
        self.history_view.pack(fill="both", expand=True, pady=(6, 0))

        # --- Columna derecha: Explorador de ficheros del workspace ---
        browser_panel = ttk.Frame(bottom, style="Card.TFrame", padding=8)
        browser_panel.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        browser_header = ttk.Frame(browser_panel, style="Card.TFrame")
        browser_header.pack(fill="x")
        self.browser_title_var = StringVar(value=f"📁 Explorador: {WORKSPACE_DIR}")
        ttk.Label(
            browser_header,
            textvariable=self.browser_title_var,
            style="Header.TLabel",
        ).pack(side="left")
        browser_btns = ttk.Frame(browser_header, style="Card.TFrame")
        browser_btns.pack(side="right")
        ttk.Button(
            browser_btns,
            text="⬆ Padre",
            command=self._on_browser_up,
        ).pack(side="left")
        ttk.Button(
            browser_btns,
            text="🔄 Refrescar",
            command=self._refresh_file_browser,
        ).pack(side="left", padx=(4, 0))

        # Ruta actual del explorador (relativa al workspace).
        self._browser_current_dir: Path = WORKSPACE_DIR
        # Treeview con scrollbar para mostrar el contenido del directorio.
        browser_body = ttk.Frame(browser_panel, style="Card.TFrame")
        browser_body.pack(fill="both", expand=True, pady=(6, 0))

        self.browser_tree = ttk.Treeview(
            browser_body,
            columns=("size",),
            show="tree headings",
            selectmode="browse",
        )
        self.browser_tree.heading("#0", text="Nombre")
        self.browser_tree.heading("size", text="Tamaño")
        self.browser_tree.column("#0", width=240, stretch=True)
        self.browser_tree.column("size", width=90, stretch=False, anchor="e")

        browser_scroll = ttk.Scrollbar(
            browser_body, orient="vertical", command=self.browser_tree.yview
        )
        self.browser_tree.configure(yscrollcommand=browser_scroll.set)
        self.browser_tree.pack(side="left", fill="both", expand=True)
        browser_scroll.pack(side="right", fill="y")

        # Doble clic: abre carpeta o muestra el contenido del fichero en
        # una ventana independiente (Toplevel).
        self.browser_tree.bind("<Double-1>", self._on_browser_activate)
        # Tecla Enter: mismo efecto que doble clic.
        self.browser_tree.bind("<Return>", self._on_browser_activate)

        # Carga inicial del explorador.
        self._refresh_file_browser()

        # Almacén de uso de contexto por tarea. La barra visual se construye
        # en _build_context_bar() como un frame independiente en self.root,
        # empaquetado con side="bottom" justo encima del panel de aprobación,
        # para que permanezca visible aunque la ventana se reduzca.
        self._context_usage: Dict[int, Dict[str, int]] = {}

    def _build_context_bar(self) -> None:
        """Crea la barra de progreso de consumo de tokens como frame propio.

        Se empaqueta en self.root con side="bottom" después del panel de
        aprobación, de modo que quede visualmente **encima** de dicho panel
        y nunca quede oculta al redimensionar la ventana (el área que se
        reduce es el contenedor intermedio con las zonas 2 y 3).
        """
        context_frame = ttk.Frame(self.root, style="Card.TFrame", padding=(10, 4))
        context_frame.pack(side="bottom", fill="x", padx=10, pady=(0, 4))

        ttk.Label(
            context_frame,
            text="📊 Contexto:",
            style="Card.TLabel",
        ).pack(side="left")

        self.context_canvas = Canvas(
            context_frame,
            height=16,
            bg=CONFIG.ui_context_bar_bg,
            highlightthickness=1,
            highlightbackground=CONFIG.ui_fg_color,
            borderwidth=0,
        )
        self.context_canvas.pack(side="left", fill="x", expand=True, padx=(6, 6))
        self.context_canvas.bind("<Configure>", self._on_context_canvas_configure)

        self.context_label_var = StringVar(value="0% (0/0 tokens)")
        ttk.Label(
            context_frame,
            textvariable=self.context_label_var,
            style="Card.TLabel",
        ).pack(side="right")

    def _build_approval_panel(self) -> None:
        for child in self.approval_frame.winfo_children():
            child.destroy()

        header = ttk.Frame(self.approval_frame, style="Card.TFrame")
        header.pack(fill="x")
        # Encabezado dinámico: muestra el contador de solicitudes pendientes
        # cuando hay más de una en cola.
        self.approval_header_var = StringVar(
            value="⚠ Control de permisos (Human-in-the-Loop)"
        )
        ttk.Label(
            header,
            textvariable=self.approval_header_var,
            style="Header.TLabel",
        ).pack(side="left")

        self.approval_info_var = StringVar(value="Sin solicitudes pendientes.")
        ttk.Label(
            self.approval_frame,
            textvariable=self.approval_info_var,
            style="Card.TLabel",
            wraplength=1200,
            justify="left",
        ).pack(anchor="w", pady=(6, 6))

        self.approval_args_view = ScrolledText(
            self.approval_frame,
            height=4,
            wrap="word",
            font=(CONFIG.ui_mono_font_family, CONFIG.ui_mono_font_size - 1),
            state="disabled",
            background=CONFIG.ui_approval_bg,
            foreground=CONFIG.ui_approval_fg,
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
        )
        self.approval_args_view.pack(fill="x", pady=(0, 6))

        btn_row = ttk.Frame(self.approval_frame, style="Card.TFrame")
        btn_row.pack(fill="x")
        self.allow_btn = ttk.Button(
            btn_row,
            text="✅ Permitir",
            style="Allow.TButton",
            command=lambda: self._resolve_approval(True),
            state="disabled",
        )
        self.allow_btn.pack(side="left")
        self.deny_btn = ttk.Button(
            btn_row,
            text="❌ Cancelar",
            style="Deny.TButton",
            command=lambda: self._resolve_approval(False),
            state="disabled",
        )
        self.deny_btn.pack(side="left", padx=(8, 0))

        # Casilla "preautorizar": cuando está marcada, las solicitudes de
        # aprobación se consultan al LLM antes de mostrarse al usuario.
        # Si el modelo responde afirmativamente, la acción se autoriza
        # automáticamente; si no, queda pendiente para decisión humana.
        # El prompt se envía SEPARADO del contexto del agente (no se añade
        # a la conversación principal ni al historial de la tarea).
        self.preauth_var = BooleanVar(value=False)
        ttk.Checkbutton(
            btn_row,
            text="🤖 Preautorizar",
            variable=self.preauth_var,
            style="Card.TCheckbutton",
        ).pack(side="right")

        # Cola FIFO de solicitudes de aprobación pendientes. Permite que
        # múltiples tareas en estado AWAITING_APPROVAL coexistan sin que
        # una solicitud sobrescriba a otra en la UI.
        self._approval_queue: "collections.deque[Dict[str, Any]]" = collections.deque()
        self._update_approval_header()

    # --- Acciones de la Zona 1 ---

    def _on_clear_prompt(self) -> None:
        self.prompt_text.delete("1.0", "end")

    def _on_execute(self) -> None:
        prompt = self.prompt_text.get("1.0", "end").strip()
        if not prompt:
            return
        title = prompt.splitlines()[0][:80]
        # Crea la tarea PADRE (sin subtask_type). El orquestador creará
        # las subtareas (Requisitos → Desarrollo → Ejecución/Verificación
        # → Rectificación si falla) y las ejecutará secuencialmente.
        task = self.db.create_task(title=title, prompt=prompt)
        self._on_clear_prompt()
        self._refresh_task_lists()
        self._select_task(task.id)
        # Lanza el orquestador en hilo separado.
        threading.Thread(
            target=self.orchestrator.run,
            args=(task,),
            daemon=True,
            name=f"orchestrator-task-{task.id}",
        ).start()

    # --- Tablero de tareas ---

    def _refresh_task_lists(self) -> None:
        # Limpia columnas.
        for frame in (self.left_list_frame, self.right_list_frame):
            for child in frame.winfo_children():
                child.destroy()

        active = self.db.list_tasks(
            [
                TaskStatus.PENDING,
                TaskStatus.IN_PROGRESS,
                TaskStatus.AWAITING_APPROVAL,
            ]
        )
        finished = self.db.list_tasks(
            [
                TaskStatus.COMPLETED,
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
            ]
        )

        # Filtrar para mostrar solo tareas PADRE en el tablero principal.
        # Las subtareas se renderizan anidadas bajo su padre.
        active_parents = [t for t in active if t.parent_task_id is None]
        finished_parents = [t for t in finished if t.parent_task_id is None]

        if not active_parents:
            ttk.Label(
                self.left_list_frame,
                text="(sin tareas activas)",
                style="Card.TLabel",
            ).pack(anchor="w", pady=4)
        else:
            for t in active_parents:
                self._render_task_with_subtasks(self.left_list_frame, t)

        if not finished_parents:
            ttk.Label(
                self.right_list_frame,
                text="(sin tareas finalizadas)",
                style="Card.TLabel",
            ).pack(anchor="w", pady=4)
        else:
            for t in finished_parents:
                self._render_task_with_subtasks(self.right_list_frame, t)

        # Si la tarea seleccionada ya no existe, limpia el historial.
        if self.selected_task_id is not None:
            current = self.db.get_task(self.selected_task_id)
            if current is None:
                self._select_task(None)

    def _render_task_with_subtasks(
        self, parent: ttk.Frame, task: Task,
    ) -> None:
        """Renderiza una tarea padre y, anidadas debajo, sus subtareas."""
        self._render_task_row(parent, task, indent=0)
        if task.id is None:
            return
        subtasks = self.db.list_subtasks(task.id)
        for st in subtasks:
            self._render_task_row(parent, st, indent=1)

    def _render_task_row(
        self, parent: ttk.Frame, task: Task, indent: int = 0,
    ) -> None:
        row = ttk.Frame(parent, style="Card.TFrame", padding=4)
        row.pack(fill="x", pady=2)

        status_style = f"Status.{task.status.value}.TLabel"
        # Prefijo visual para subtareas (indentación con espacios).
        prefix = "    " * indent
        id_text = f"{prefix}#{task.id}"
        ttk.Label(
            row,
            text=id_text,
            style="Card.TLabel",
            width=4 + len(prefix),
        ).pack(side="left")
        ttk.Label(
            row,
            text=task.status.value,
            style=status_style,
            width=18,
        ).pack(side="left")
        title_lbl = ttk.Label(
            row,
            text=task.title,
            style="Card.TLabel",
        )
        title_lbl.pack(side="left", padx=(6, 6))
        # Botón seleccionar.
        btn = ttk.Button(
            row,
            text="Ver",
            command=lambda tid=task.id: self._select_task(tid),
        )
        btn.pack(side="right")

    @staticmethod
    def _tag_for_event(event_type: EventType) -> Optional[str]:
        """
        Devuelve el nombre del tag de color para un tipo de evento, o None
        si el evento no debe resaltarse.
        """
        mapping = {
            EventType.FINAL_ANSWER: "final_answer",
            EventType.THOUGHT: "thought",
            EventType.INFO: "info",
            EventType.TOOL_CALL: "tool_call",
            EventType.TOOL_RESULT: "tool_result",
            EventType.APPROVAL_REQUEST: "approval_request",
            EventType.APPROVAL_GRANTED: "approval_granted",
            EventType.APPROVAL_DENIED: "approval_denied",
            EventType.ERROR: "error",
            EventType.STATUS_CHANGE: "status_change",
            EventType.LOOP_DETECTED: "loop_detected",
            EventType.CONTEXT_COMPACTED: "context_compacted",
        }
        return mapping.get(event_type)

    def _select_task(self, task_id: Optional[int]) -> None:
        self.selected_task_id = task_id
        self.history_view.configure(state="normal")
        self.history_view.delete("1.0", "end")
        if task_id is None:
            self.history_title_var.set("Historial de tarea (ninguna seleccionada)")
            self.history_view.configure(state="disabled")
            return
        task = self.db.get_task(task_id)
        if task is None:
            self.history_title_var.set(f"Tarea #{task_id} (no encontrada)")
            self.history_view.configure(state="disabled")
            return
        self.history_title_var.set(
            f"Historial de tarea #{task.id} — {task.title}  [{task.status.value}]"
            + (
                f"  (subtarea de #{task.parent_task_id})"
                if task.parent_task_id is not None
                else ""
            )
        )
        entries = self.db.get_history(task_id)
        for e in entries:
            label = EVENT_LABELS.get(e.event_type.value, e.event_type.value)
            header = f"[{e.timestamp}] {label}\n"
            body = f"{e.content}\n{'-' * 60}\n"
            tag = self._tag_for_event(e.event_type)
            if tag:
                # Cabecera y cuerpo resaltados con el mismo tag.
                self.history_view.insert("end", header, (tag,))
                self.history_view.insert("end", body, (tag,))
            else:
                self.history_view.insert("end", header + body)
        self.history_view.see("end")
        self.history_view.configure(state="disabled")
        # Actualizar la barra de contexto para la tarea seleccionada.
        self._refresh_context_bar()

    # --- Barra de uso de contexto ---

    def _on_context_canvas_configure(self, _event: Any) -> None:
        """Redibuja la barra cuando cambia su tamaño."""
        self._redraw_context_bar()

    def _redraw_context_bar(self) -> None:
        """Redibuja la barra de contexto con el valor de la tarea seleccionada."""
        self.context_canvas.delete("all")
        width = self.context_canvas.winfo_width()
        if width <= 1:
            return
        height = self.context_canvas.winfo_height() or 16

        percent = 0
        if self.selected_task_id is not None:
            usage = self._context_usage.get(self.selected_task_id, {})
            percent = max(0, min(100, int(usage.get("percent", 0))))

        fill_width = int(width * percent / 100)

        # Color según el nivel de uso.
        if percent < 60:
            color = CONFIG.ui_context_bar_low
        elif percent < 85:
            color = CONFIG.ui_context_bar_medium
        else:
            color = CONFIG.ui_context_bar_high

        if fill_width > 0:
            self.context_canvas.create_rectangle(
                0, 0, fill_width, height,
                fill=color, outline="",
            )

    def _refresh_context_bar(self) -> None:
        """Actualiza la etiqueta y la barra para la tarea seleccionada."""
        if self.selected_task_id is None:
            self.context_label_var.set("0% (0/0 tokens)")
            self._redraw_context_bar()
            return
        usage = self._context_usage.get(self.selected_task_id)
        if usage is None:
            self.context_label_var.set("0% (0/0 tokens)")
        else:
            tokens_used = usage.get("tokens_used", 0)
            max_tokens = usage.get("max_tokens", 0)
            percent = usage.get("percent", 0)
            self.context_label_var.set(
                f"{percent}% ({tokens_used}/{max_tokens} tokens)"
            )
        self._redraw_context_bar()

    def _update_context_bar(self, event: Dict[str, Any]) -> None:
        """Almacena el uso de contexto y actualiza la barra si aplica."""
        task_id = event.get("task_id")
        if task_id is None:
            return
        self._context_usage[task_id] = {
            "tokens_used": int(event.get("tokens_used", 0)),
            "max_tokens": int(event.get("max_tokens", 0)),
            "percent": int(event.get("percent", 0)),
        }
        if task_id == self.selected_task_id:
            self._refresh_context_bar()

    # --- Zona 4: aprobación ---

    def _resolve_approval(self, granted: bool) -> None:
        if not self._approval_queue:
            return
        # Extrae la primera solicitud de la cola (FIFO) y la resuelve.
        current = self._approval_queue.popleft()
        request_id = current["request_id"]
        task_id = current["task_id"]
        tool_name = current["tool_name"]
        self.permissions.resolve(
            request_id,
            granted,
            reason="permitido por el usuario" if granted else "cancelado por el usuario",
        )
        # Muestra feedback inmediato de la decisión sobre la solicitud resuelta.
        if granted:
            # Aprobado: fondo verde muy claro, texto negro.
            self.approval_info_var.set(
                f"✅ Aprobado: herramienta '{tool_name}' permitida."
            )
            bg, fg = CONFIG.ui_approval_granted_bg, CONFIG.ui_approval_granted_fg
        else:
            # Denegado: fondo rojo claro, texto negro.
            self.approval_info_var.set(
                f"❌ Denegado: herramienta '{tool_name}' cancelada."
            )
            bg, fg = CONFIG.ui_approval_denied_bg, CONFIG.ui_approval_denied_fg
        self.approval_args_view.configure(background=bg, foreground=fg)
        self.approval_args_view.configure(state="normal")
        self.approval_args_view.delete("1.0", "end")
        self.approval_args_view.configure(state="disabled")
        # Refresca tablero e historial.
        self._refresh_task_lists()
        if task_id == self.selected_task_id:
            self._select_task(task_id)
        # Si quedan solicitudes pendientes en la cola, muestra la siguiente
        # automáticamente; si no, deshabilita los botones y actualiza el
        # encabezado.
        if self._approval_queue:
            self._render_current_approval()
        else:
            self.allow_btn.configure(state="disabled")
            self.deny_btn.configure(state="disabled")
            self._update_approval_header()

    # --- Polling de la cola UI -> agente ---

    def _poll_queue(self) -> None:
        try:
            while True:
                event = self.ui_queue.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        self.root.after(self.POLL_INTERVAL_MS, self._poll_queue)

    def _handle_event(self, event: Dict[str, Any]) -> None:
        etype = event.get("type")
        if etype == "status_change":
            self._refresh_task_lists()
            if event.get("task_id") == self.selected_task_id:
                self._select_task(self.selected_task_id)
        elif etype == "history_update":
            if event.get("task_id") == self.selected_task_id:
                self._select_task(self.selected_task_id)
        elif etype == "context_usage":
            self._update_context_bar(event)
        elif etype == "approval_request":
            self._show_approval(event)
        elif etype == "refresh_file_browser":
            self._refresh_file_browser()

    def _show_approval(self, event: Dict[str, Any]) -> None:
        """
        Encola una nueva solicitud de aprobación y muestra la primera pendiente.

        Si la casilla "preautorizar" está marcada, se consulta al LLM en
        segundo plano antes de mostrar la solicitud al usuario. Si el modelo
        responde afirmativamente, la acción se autoriza automáticamente; si
        no, la solicitud queda pendiente para que el usuario la resuelva.

        Si ya hay una solicitud visible, la nueva queda encolada y se mostrará
        automáticamente cuando el usuario resuelva la actual. Esto evita que
        una segunda solicitud sobrescriba a la primera y la deje invisible
        en el panel (el hilo del agente correspondiente quedaría esperando
        hasta el timeout de 10 minutos).
        """
        # Si la casilla "preautorizar" está marcada, se consulta al LLM
        # en segundo plano antes de mostrar la solicitud al usuario.
        if self.preauth_var.get():
            self._start_preauthorization(event)
            return
        self._approval_queue.append(event)
        # Notificación visual siempre que llegue una nueva solicitud.
        try:
            self.root.bell()
        except Exception:  # noqa: BLE001
            pass
        # Si ya había una solicitud visible, la nueva queda encolada.
        if len(self._approval_queue) > 1:
            self._update_approval_header()
            return
        self._render_current_approval()

    def _start_preauthorization(self, event: Dict[str, Any]) -> None:
        """
        Consulta al LLM en segundo plano para preautorizar una solicitud.

        Muestra feedback inmediato en el panel ("Consultando al modelo...")
        y lanza un hilo que:
          - Envía un prompt aislado al LLM (separado del contexto del agente).
          - Si el modelo responde afirmativamente, resuelve la aprobación
            automáticamente y registra el evento en el historial.
          - Si responde negativamente o la respuesta es ambigua, encola
            la solicitud para que el usuario la resuelva manualmente.

        Si ya hay otra solicitud visible en el panel, el preauth se ejecuta
        en silencio (sin sobrescribir el panel) y el resultado se aplica
        cuando termina: o bien se resuelve directamente, o bien se encola
        para mostrarse cuando el usuario resuelva la solicitud actual.
        """
        request_id = event["request_id"]
        task_id = event["task_id"]
        tool_name = event["tool_name"]

        # Si ya hay una solicitud visible en el panel, no lo sobrescribimos:
        # ejecutamos el preauth en silencio y encolamos/resolvedemos al terminar.
        panel_busy = len(self._approval_queue) > 0

        if not panel_busy:
            # Feedback inmediato en el panel.
            self.approval_info_var.set(
                f"🤖 Consultando al modelo sobre la seguridad de '{tool_name}'..."
            )
            self.approval_args_view.configure(
                background=CONFIG.ui_approval_request_bg,
                foreground=CONFIG.ui_approval_request_fg,
            )
            self.approval_args_view.configure(state="normal")
            self.approval_args_view.delete("1.0", "end")
            self.approval_args_view.insert(
                "end",
                f"Tarea #{task_id}  ·  Herramienta: {tool_name}\n"
                f"Esperando respuesta del modelo...",
            )
            self.approval_args_view.configure(state="disabled")
            self.allow_btn.configure(state="disabled")
            self.deny_btn.configure(state="disabled")

        def _worker() -> None:
            try:
                approved, reason = self._query_llm_for_preauth(event)
            except Exception as exc:  # noqa: BLE001
                approved, reason = False, f"error en la consulta al LLM: {exc}"

            def _apply_result() -> None:
                if approved:
                    # Autorización automática: desbloquea el hilo del agente.
                    self.permissions.resolve(
                        request_id,
                        True,
                        reason=f"preautorizado por LLM: {reason}",
                    )
                    self._log_event(
                        task_id,
                        EventType.PREAUTHORIZATION_GRANTED,
                        (
                            f"🤖 Preautorizado por LLM: herramienta '{tool_name}'. "
                            f"Motivo: {reason}"
                        ),
                    )
                    if not panel_busy:
                        self.approval_info_var.set(
                            f"🤖 Preautorizado por LLM: '{tool_name}' — {reason}"
                        )
                        self.approval_args_view.configure(
                            background=CONFIG.ui_approval_granted_bg,
                            foreground=CONFIG.ui_approval_granted_fg,
                        )
                        self.approval_args_view.configure(state="normal")
                        self.approval_args_view.delete("1.0", "end")
                        self.approval_args_view.configure(state="disabled")
                    self._refresh_task_lists()
                    if task_id == self.selected_task_id:
                        self._select_task(task_id)
                    self._update_approval_header()
                else:
                    # El LLM recomienda no autorizar: encolar para el usuario.
                    self._log_event(
                        task_id,
                        EventType.PREAUTHORIZATION_DENIED,
                        (
                            f"🤖 LLM recomienda NO autorizar '{tool_name}'. "
                            f"Motivo: {reason}. Pendiente de decisión del usuario."
                        ),
                    )
                    self._approval_queue.append(event)
                    if not panel_busy:
                        self._render_current_approval()
                    else:
                        self._update_approval_header()

            try:
                self.root.after(0, _apply_result)
            except Exception:  # noqa: BLE001
                pass

        threading.Thread(
            target=_worker,
            daemon=True,
            name=f"preauth-{request_id[:8]}",
        ).start()

    def _query_llm_for_preauth(self, event: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Envía un prompt aislado al LLM para evaluar la seguridad de una acción.

        El prompt está completamente separado del contexto del agente: no
        se añade a la conversación principal ni afecta al historial de la
        tarea. El LLM recibe un system prompt que le instruye actuar como
        auditor de seguridad y responder únicamente con SI/NO + justificación.

        Devuelve (aprobado, motivo). Si la respuesta es ambigua o el LLM
        no responde, devuelve (False, motivo) por seguridad.
        """
        tool_name = event.get("tool_name", "?")
        tool_desc = event.get("tool_description", "")
        risk = event.get("risk", "?")
        args = event.get("arguments", {}) or {}
        args_str = _format_approval_args(tool_name, args)

        system_msg = (
            "Eres un auditor de seguridad de un agente autónomo. "
            "Tu única tarea es evaluar si una acción propuesta es SEGURA "
            "para los ficheros del usuario y NO expone datos privados. "
            "Responde ÚNICAMENTE con una línea que comience por 'SI' o 'NO' "
            "seguida de una justificación breve (máximo 200 caracteres). "
            "Criterios de evaluación:\n"
            "- ¿La acción podría borrar, sobrescribir o corromper ficheros del usuario?\n"
            "- ¿La acción expone datos privados (contraseñas, claves API, datos personales)?\n"
            "- ¿La acción accede a rutas fuera del workspace permitido?\n"
            "- ¿La acción ejecuta comandos del sistema potencialmente destructivos?\n"
            "Si cualquiera de estos riesgos es real, responde NO."
        )
        user_msg = (
            f"Herramienta: {tool_name}\n"
            f"Descripción: {tool_desc}\n"
            f"Riesgo declarado: {risk}\n"
            f"Argumentos:\n{args_str}\n\n"
            f"¿Es seguro ejecutar esta acción sin intervención humana? "
            f"Responde SI o NO seguido de una justificación breve."
        )

        response = self.llm.chat(
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ]
        )
        content = (
            response.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )

        # Parsear respuesta: buscar SI/NO al inicio (tolerando signos de
        # interrogación/exclamación y espacios).
        upper = content.upper().lstrip("¿?!.,;: \t")
        affirmative_prefixes = ("SI", "SÍ", "YES", "APROBAR", "SEGURO", "AUTORIZAR")
        negative_prefixes = ("NO", "DENEGAR", "INSEGURO", "PELIGROSO", "RECHAZAR")

        if upper.startswith(affirmative_prefixes):
            return True, content[:200]
        if upper.startswith(negative_prefixes):
            return False, content[:200]
        # Ambiguo: por seguridad, no preautorizar.
        return False, f"respuesta ambigua del LLM: {content[:200]}"

    def _log_event(
        self,
        task_id: int,
        event_type: EventType,
        content: str,
    ) -> None:
        """
        Registra un evento en el historial desde la UI.

        Equivalente a Agent._log pero invocable desde el hilo de la UI
        (no requiere una referencia al Agent). Escribe en la BD y publica
        un evento history_update en la cola para refrescar la vista.
        """
        self.db.add_history(task_id, event_type, content)
        self.ui_queue.put(
            {
                "type": "history_update",
                "task_id": task_id,
                "event_type": event_type.value,
                "content": content,
            }
        )

    def _render_current_approval(self) -> None:
        """Renderiza en el panel la primera solicitud pendiente de la cola."""
        if not self._approval_queue:
            self.approval_info_var.set("Sin solicitudes pendientes.")
            self.approval_args_view.configure(state="normal")
            self.approval_args_view.delete("1.0", "end")
            self.approval_args_view.configure(state="disabled")
            self.allow_btn.configure(state="disabled")
            self.deny_btn.configure(state="disabled")
            self._update_approval_header()
            return
        event = self._approval_queue[0]
        args = event.get("arguments", {}) or {}
        args_str = _format_approval_args(event.get("tool_name", ""), args)
        info = (
            f"Tarea #{event['task_id']}  ·  Herramienta: {event['tool_name']}  "
            f"·  Riesgo: {event['risk']}\n"
            f"Descripción: {event.get('tool_description', '')}"
        )
        self.approval_info_var.set(info)
        # Solicitud pendiente: fondo gris claro, texto negro.
        self.approval_args_view.configure(
            background=CONFIG.ui_approval_request_bg,
            foreground=CONFIG.ui_approval_request_fg,
        )
        self.approval_args_view.configure(state="normal")
        self.approval_args_view.delete("1.0", "end")
        self.approval_args_view.insert("end", args_str)
        self.approval_args_view.configure(state="disabled")
        self.allow_btn.configure(state="normal")
        self.deny_btn.configure(state="normal")
        self._update_approval_header()

    def _update_approval_header(self) -> None:
        """Actualiza el encabezado del panel con el contador de pendientes."""
        pending = len(self._approval_queue)
        if pending == 0:
            self.approval_header_var.set(
                "⚠ Control de permisos (Human-in-the-Loop)"
            )
        elif pending == 1:
            self.approval_header_var.set(
                "⚠ Control de permisos (Human-in-the-Loop) — 1 solicitud pendiente"
            )
        else:
            self.approval_header_var.set(
                f"⚠ Control de permisos (Human-in-the-Loop) — {pending} solicitudes pendientes"
            )

    # --- Explorador de ficheros del workspace ---

    def _refresh_file_browser(self) -> None:
        """
        Recarga el contenido del directorio actual en el explorador.

        Las entradas se muestran ordenadas: primero las carpetas (alfabético),
        luego los ficheros (alfabético). Cada fila incluye el tamaño formateado.
        Las entradas especiales "." y ".." se omiten; para subir al directorio
        padre se usa el botón "⬆ Padre".
        """
        # Limpia el treeview.
        for iid in self.browser_tree.get_children():
            self.browser_tree.delete(iid)

        current = self._browser_current_dir
        # Seguridad: nunca salirse del workspace.
        try:
            current.relative_to(WORKSPACE_DIR)
        except ValueError:
            self._browser_current_dir = WORKSPACE_DIR
            current = WORKSPACE_DIR

        # Encabezado con la ruta actual.
        try:
            display_path = current.relative_to(WORKSPACE_DIR).as_posix()
        except ValueError:
            display_path = current.as_posix()
        if display_path in ("", "."):
            display_path = "/"
        else:
            display_path = "/" + display_path
        self.browser_title_var.set(f"📁 Explorador: {display_path}")

        if not current.exists() or not current.is_dir():
            self.browser_tree.insert(
                "", "end", iid="__missing__", text="(directorio no disponible)",
                values=("",),
            )
            return

        try:
            entries = sorted(
                current.iterdir(),
                key=lambda p: (not p.is_dir(), p.name.lower()),
            )
        except OSError as e:
            self.browser_tree.insert(
                "", "end", iid="__error__", text=f"(error al leer: {e})",
                values=("",),
            )
            return

        for entry in entries:
            try:
                if entry.is_dir():
                    label = f"📁 {entry.name}"
                    size_text = "—"
                else:
                    try:
                        size_text = _format_size(entry.stat().st_size)
                    except OSError:
                        size_text = "?"
                    label = f"📄 {entry.name}"
            except OSError:
                continue
            # iid = ruta absoluta para identificarla de forma única.
            self.browser_tree.insert(
                "", "end", iid=str(entry), text=label, values=(size_text,),
            )

    def _on_browser_activate(self, _event: Any) -> None:
        """
        Maneja doble clic / Enter sobre una entrada del explorador.

        - Si es una carpeta: navega dentro de ella.
        - Si es un fichero: abre una ventana independiente (Toplevel)
          con el contenido completo del fichero.
        """
        selection = self.browser_tree.selection()
        if not selection:
            return
        iid = selection[0]
        if iid in ("__missing__", "__error__"):
            return
        try:
            target = Path(iid)
        except ValueError:
            return
        if not target.exists():
            self._refresh_file_browser()
            return
        if target.is_dir():
            # Seguridad: no salir del workspace.
            try:
                target.relative_to(WORKSPACE_DIR)
            except ValueError:
                return
            self._browser_current_dir = target
            self._refresh_file_browser()
            return
        # Fichero: abrir ventana independiente con su contenido.
        self._open_file_viewer(target)

    def _open_file_viewer(self, target: Path) -> None:
        """
        Abre una ventana Toplevel con el contenido del fichero seleccionado.

        La ventana es modal respecto al dashboard (no se puede interactuar
        con el dashboard mientras está abierta) y muestra la ruta completa
        en el título junto con el nombre del fichero. El contenido se
        carga en un ScrolledText de solo lectura. Si el fichero es binario
        o no se puede decodificar como UTF-8, se muestra un aviso y los
        primeros bytes en hexadecimal.
        """
        try:
            size = target.stat().st_size
        except OSError as e:
            messagebox.showerror(
                "Error al abrir fichero",
                f"No se pudo acceder a {target}:\n{e}",
                parent=self.root,
            )
            return

        # Crear ventana Toplevel modal.
        viewer = Toplevel(self.root)
        viewer.title(f"📄 {target.name}  —  {target}")
        viewer.geometry("900x600")
        viewer.minsize(500, 300)
        viewer.configure(background=CONFIG.ui_bg_color)
        viewer.transient(self.root)
        viewer.grab_set()

        # Cabecera con la ruta completa y el tamaño.
        header = ttk.Frame(viewer, style="Card.TFrame", padding=8)
        header.pack(fill="x")
        try:
            rel = target.relative_to(WORKSPACE_DIR)
            rel_text = str(rel)
        except ValueError:
            rel_text = str(target)
        ttk.Label(
            header,
            text=f"📁 {rel_text}    ·    {_format_size(size)}",
            style="Header.TLabel",
        ).pack(side="left")
        ttk.Button(
            header,
            text="✖ Cerrar",
            command=viewer.destroy,
        ).pack(side="right")

        # Contenido del fichero en Text de solo lectura con scroll vertical
        # y horizontal (las líneas largas no se truncan: se puede desplazar
        # lateralmente con la barra inferior o con Shift+rueda del ratón).
        content_frame = ttk.Frame(viewer, style="Card.TFrame")
        content_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        content_frame.rowconfigure(0, weight=1)
        content_frame.columnconfigure(0, weight=1)

        content_view = Text(
            content_frame,
            wrap="none",
            font=(CONFIG.ui_mono_font_family, CONFIG.ui_mono_font_size),
            state="disabled",
            background=CONFIG.ui_history_bg,
            foreground=CONFIG.ui_history_fg,
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
        )
        v_scroll = ttk.Scrollbar(
            content_frame, orient="vertical", command=content_view.yview
        )
        h_scroll = ttk.Scrollbar(
            content_frame, orient="horizontal", command=content_view.xview
        )
        content_view.configure(
            yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set
        )
        content_view.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

        # Shift+rueda del ratón → scroll horizontal (más cómodo que la barra).
        def _on_shift_mousewheel(event: Any) -> None:
            content_view.xview_scroll(int(-1 * (event.delta / 120)), "units")

        content_view.bind("<Enter>", lambda _e: content_view.bind_all(
            "<Shift-MouseWheel>", _on_shift_mousewheel
        ))
        content_view.bind("<Leave>", lambda _e: content_view.unbind_all(
            "<Shift-MouseWheel>"
        ))

        # Cargar contenido.
        content_view.configure(state="normal")
        content_view.delete("1.0", "end")
        if size == 0:
            content_view.insert("end", "(fichero vacío)")
        else:
            try:
                # Intentar leer como texto UTF-8.
                content = target.read_text(encoding="utf-8", errors="strict")
                content_view.insert("end", content)
            except (UnicodeDecodeError, ValueError):
                # Fichero binario: mostrar aviso y primeros bytes en hex.
                content_view.insert(
                    "end",
                    f"(fichero binario: {_format_size(size)} — "
                    f"se muestran los primeros 4096 bytes en hexadecimal)\n\n",
                )
                try:
                    with target.open("rb") as fh:
                        raw = fh.read(4096)
                    hex_lines: List[str] = []
                    for offset in range(0, len(raw), 16):
                        chunk = raw[offset:offset + 16]
                        hex_part = " ".join(f"{b:02x}" for b in chunk)
                        ascii_part = "".join(
                            chr(b) if 32 <= b < 127 else "." for b in chunk
                        )
                        hex_lines.append(f"{offset:08x}  {hex_part:<47}  {ascii_part}")
                    content_view.insert("end", "\n".join(hex_lines))
                except OSError as e:
                    content_view.insert("end", f"(no se pudo leer: {e})")
            except OSError as e:
                content_view.insert("end", f"(no se pudo leer: {e})")

        content_view.see("1.0")
        content_view.configure(state="disabled")

        # Centrar la ventana sobre el dashboard.
        viewer.update_idletasks()
        try:
            root_x = self.root.winfo_rootx()
            root_y = self.root.winfo_rooty()
            root_w = self.root.winfo_width()
            root_h = self.root.winfo_height()
            vw = viewer.winfo_width()
            vh = viewer.winfo_height()
            x = root_x + (root_w - vw) // 2
            y = root_y + (root_h - vh) // 2
            viewer.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        except Exception:  # noqa: BLE001
            pass

        # Cerrar con Escape.
        viewer.bind("<Escape>", lambda _e: viewer.destroy())

    def _on_browser_up(self) -> None:
        """Sube al directorio padre (sin salir del workspace)."""
        current = self._browser_current_dir
        if current == WORKSPACE_DIR or current.parent == current:
            return
        parent = current.parent
        try:
            parent.relative_to(WORKSPACE_DIR)
        except ValueError:
            # El padre está fuera del workspace: volver a la raíz.
            self._browser_current_dir = WORKSPACE_DIR
        else:
            self._browser_current_dir = parent
        self._refresh_file_browser()


# ============================================================================
# POPUP DE BIENVENIDA
# ============================================================================

class WelcomeDialog:
    """
    Ventana modal de bienvenida que se muestra al iniciar la aplicación.

    Muestra el nombre del proyecto "Hercules" en arte ASCII, el nombre del
    desarrollador y un enlace clicable al repositorio de GitHub. El usuario
    puede cerrar la ventana con el botón "Comenzar" o marcando la casilla
    "No mostrar de nuevo" para que no vuelva a aparecer en futuros arranques.
    """

    PROJECT_NAME = "Hercules"
    DEVELOPER_NAME = "Rubén Pastor"
    GITHUB_URL = "https://github.com/bondwell79/agentes"
    GITHUB_DISPLAY = "github.com/bondwell79/agentes"

    ASCII_ART = r"""
██╗  ██╗███████╗██████╗  ██████╗██╗   ██╗██╗     ███████╗███████╗
██║  ██║██╔════╝██╔══██╗██╔════╝██║   ██║██║     ██╔════╝██╔════╝
███████║█████╗  ██████╔╝██║     ██║   ██║██║     █████╗  ███████╗
██╔══██║██╔══╝  ██╔══██╗██║     ██║   ██║██║     ██╔══╝  ╚════██║
██║  ██║███████╗██║  ██║╚██████╗╚██████╔╝███████╗███████╗███████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ 
"""

    def __init__(self, parent: Tk) -> None:
        self.parent = parent
        self.dont_show_again = BooleanVar(value=False)

        self.window = Toplevel(parent)
        self.window.title(f"Bienvenido a {self.PROJECT_NAME}")
        self.window.resizable(False, False)
        # Colores coherentes con el dashboard.
        try:
            self.window.configure(bg=CONFIG.ui_bg_color)
        except Exception:  # noqa: BLE001
            pass

        # Hacer la ventana modal y centrarla sobre la principal.
        self.window.transient(parent)
        self.window.grab_set()
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)

        self._build_layout()

        # Centrar la ventana en la pantalla una vez construida.
        self.window.update_idletasks()
        try:
            sw = self.window.winfo_screenwidth()
            sh = self.window.winfo_screenheight()
            ww = self.window.winfo_reqwidth()
            wh = self.window.winfo_reqheight()
            x = max(0, (sw) // 2-(ww) // 2)
            y = max(0, (sh) // 2-(wh) // 2)
            self.window.geometry(f"+{x}+{y}")
        except Exception:  # noqa: BLE001
            pass

        # Atajo: Enter y Escape cierran el diálogo.
        self.window.bind("<Return>", lambda _e: self._on_close())
        self.window.bind("<Escape>", lambda _e: self._on_close())

    def _build_layout(self) -> None:
        """Construye los widgets del popup de bienvenida."""
        # Marco principal con padding.
        try:
            frame_bg = CONFIG.ui_card_bg
            fg_color = CONFIG.ui_fg_color
            mono_family = CONFIG.mono_font_family
            mono_size = CONFIG.mono_font_size
            font_family = CONFIG.ui_font_family
            font_size = CONFIG.ui_font_size
        except Exception:  # noqa: BLE001
            frame_bg = "#2d2d30"
            fg_color = "#e0e0e0"
            mono_family = "Consolas"
            mono_size = 10
            font_family = "Segoe UI"
            font_size = 10

        outer = ttk.Frame(self.window, style="Card.TFrame", padding=24)
        outer.pack(fill="both", expand=True)

        # Arte ASCII del nombre del proyecto.
        ascii_label = Text(
            outer,
            height=len(self.ASCII_ART.strip("\n").splitlines()),
            width=max(len(line) for line in self.ASCII_ART.splitlines()),
            font=(mono_family, mono_size + 4, "bold"),
            bg=frame_bg,
            fg="#4fc3f7",
            bd=0,
            relief="flat",
            highlightthickness=0,
            takefocus=0,
            cursor="arrow",
        )
        ascii_label.insert("1.0", self.ASCII_ART)
        ascii_label.configure(state="disabled")
        ascii_label.pack(pady=(0, 12))

        # Nombre del desarrollador.
        dev_label = ttk.Label(
            outer,
            text=f"Desarrollado por {self.DEVELOPER_NAME}",
            style="Card.TLabel",
            font=(font_family, font_size + 1),
        )
        dev_label.pack(pady=(0, 4))

        # Enlace al repositorio de GitHub (Label con cursor de mano).
        link_frame = ttk.Frame(outer, style="Card.TFrame")
        link_frame.pack(pady=(0, 16))

        link_prefix = ttk.Label(
            link_frame,
            text="Repositorio: ",
            style="Card.TLabel",
            font=(font_family, font_size),
        )
        link_prefix.pack(side="left")

        self._link_label = ttk.Label(
            link_frame,
            text=self.GITHUB_DISPLAY,
            style="Card.TLabel",
            foreground="#4fc3f7",
            font=(font_family, font_size, "underline"),
            cursor="hand2",
        )
        self._link_label.pack(side="left")
        self._link_label.bind("<Button-1>", self._on_link_click)
        self._link_label.bind("<Enter>", self._on_link_enter)
        self._link_label.bind("<Leave>", self._on_link_leave)

        # Separador visual.
        ttk.Separator(outer, orient="horizontal").pack(fill="x", pady=(0, 12))

        # Casilla "No mostrar de nuevo".
        dont_show = ttk.Checkbutton(
            outer,
            text="No mostrar este mensaje al iniciar",
            variable=self.dont_show_again,
            style="Card.TCheckbutton",
        )
        dont_show.pack(anchor="w", pady=(0, 12))

        # Botón "Comenzar".
        try:
            style_name = "Accent.TButton"
            self.window.tk.call("ttk::style", "configure", style_name, "-foreground", fg_color)
        except Exception:  # noqa: BLE001
            style_name = "TButton"

        button = ttk.Button(
            outer,
            text="Comenzar",
            command=self._on_close,
            style=style_name,
        )
        button.pack(fill="x")
        button.focus_set()

    def _on_link_click(self, _event: Any) -> None:
        """Abre el repositorio de GitHub en el navegador predeterminado."""
        try:
            webbrowser.open_new_tab(self.GITHUB_URL)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(
                "Error al abrir el enlace",
                f"No se pudo abrir el navegador:\n{exc}\n\nURL: {self.GITHUB_URL}",
                parent=self.window,
            )

    def _on_link_enter(self, _event: Any) -> None:
        try:
            self._link_label.configure(foreground="#81d4fa")
        except Exception:  # noqa: BLE001
            pass

    def _on_link_leave(self, _event: Any) -> None:
        try:
            self._link_label.configure(foreground="#4fc3f7")
        except Exception:  # noqa: BLE001
            pass

    def _on_close(self) -> None:
        """Cierra el diálogo y, si procede, persiste la preferencia."""
        if self.dont_show_again.get():
            try:
                _save_welcome_pref(False)
            except Exception as exc:  # noqa: BLE001
                print(f"[welcome] No se pudo guardar la preferencia: {exc}")
        try:
            self.window.grab_release()
        except Exception:  # noqa: BLE001
            pass
        self.window.destroy()


def _load_welcome_pref() -> bool:
    """
    Devuelve True si debe mostrarse el popup de bienvenida.

    La preferencia se persiste en un fichero `.welcome` dentro del
    directorio de trabajo. Por defecto se muestra siempre (True).
    """
    try:
        pref_path = Path(CONFIG.workspace_path) / ".welcome"
        if pref_path.exists():
            return pref_path.read_text(encoding="utf-8").strip().lower() not in (
                "false", "0", "no", "off"
            )
    except Exception:  # noqa: BLE001
        pass
    return True


def _save_welcome_pref(show: bool) -> None:
    """Persiste la preferencia del usuario sobre el popup de bienvenida."""
    pref_path = Path(CONFIG.workspace_path) / ".welcome"
    pref_path.parent.mkdir(parents=True, exist_ok=True)
    pref_path.write_text("true" if show else "false", encoding="utf-8")


# ============================================================================
# PUNTO DE ENTRADA
# ============================================================================

def main() -> None:
    root = Tk()
    Dashboard(root)
    # Mostrar el popup de bienvenida (a menos que el usuario lo haya desactivado).
    try:
        if _load_welcome_pref():
            WelcomeDialog(root)
    except Exception as exc:  # noqa: BLE001
        print(f"[welcome] No se pudo mostrar el popup de bienvenida: {exc}")
    root.mainloop()


if __name__ == "__main__":
    main()
