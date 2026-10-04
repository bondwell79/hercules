#!/usr/bin/env python3
"""
hercules.py

Gestor de modelos LLM con Control de Permisos (HITL - Human-in-the-Loop).

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
import re
import base64
import collections
import configparser
import io
import json
import os
import queue
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
import traceback
import urllib.error
import urllib.request
import uuid
import webbrowser
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


def _set_process_dpi_aware() -> None:
    """Fija la conciencia DPI antes de inicializar Tkinter o PyAutoGUI."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:  # noqa: BLE001
        pass


_set_process_dpi_aware()

from tkinter import BooleanVar, Canvas, Frame, Label as TkLabel, Tk, StringVar, Text, Toplevel, colorchooser, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any, Callable, Dict, List, Optional, Tuple

import computer_tools


# ============================================================================
# CONFIGURACIÓN (config.ini + variables de entorno)
# ============================================================================

CONFIG_PATH = os.environ.get("HERCULES_CONFIG", "config.ini")
VERSION = "Alpha 0.3.0"
SUBTAREAS_INI_PATH = os.environ.get("HERCULES_SUBTAREAS_INI", "subtareas.ini")

# Patrones peligrosos organizados por categoría.
# Cada entrada: (regex compilado, razón legible, severidad).
_DANGEROUS_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    # --- Destrucción masiva de archivos ---
    (re.compile(r'\brm\s+(-\w*r\w*f|-\w*f\w*r|-rf|-fr)\b\s+/', re.I),
     "Eliminación recursiva forzada desde raíz", "CRITICAL"),
    (re.compile(r'\brm\s+(-\w*r\w*f|-\w*f\w*r|-rf|-fr)\b\s+~', re.I),
     "Eliminación recursiva forzada del home", "CRITICAL"),
    (re.compile(r'\bdel\s+.*(/s|/q|/f)', re.I),
     "Eliminación recursiva Windows", "CRITICAL"),
    (re.compile(r'\brd\s+.*(/s|/q)', re.I),
     "Eliminación de directorio Windows", "CRITICAL"),
    (re.compile(r'\bRemove-Item\s+.*(-Recurse|-Force)', re.I),
     "Eliminación recursiva PowerShell", "CRITICAL"),
    
    # --- Operaciones de disco ---
    (re.compile(r'\b(format|mkfs|mkfs\.\w+|mkswap|fdisk|parted)\b\s+', re.I),
     "Operación destructiva de disco", "CRITICAL"),
    (re.compile(r'\bdd\s+.*of=/dev/(sd|hd|nvme|mmcblk|xvd)', re.I),
     "Escritura directa a dispositivo de bloque", "CRITICAL"),
    
    # --- Control del sistema ---
    (re.compile(r'\b(shutdown|halt|poweroff|reboot|restart)\b', re.I),
     "Apagado/reinicio del sistema", "CRITICAL"),
    (re.compile(r'\binit\s+[016]\b', re.I),
     "Cambio de runlevel", "CRITICAL"),
    (re.compile(r'\bsystemctl\s+(poweroff|reboot|halt)', re.I),
     "Apagado vía systemd", "CRITICAL"),
    
    # --- Escalada de privilegios ---
    (re.compile(r'\b(sudo|doas)\s+', re.I),
     "Escalada de privilegios", "HIGH"),
    (re.compile(r'\bsu\s+(-c\s+)?', re.I),
     "Cambio de usuario", "HIGH"),
    (re.compile(r'\bchmod\s+[0-7]*[sS]\b', re.I),
     "Asignación de SUID/SGID", "HIGH"),
    
    # --- Pipes a intérpretes (ejecución remota) ---
    (re.compile(r'\b(curl|wget|fetch)\s+.*\|\s*(sh|bash|zsh|python|perl|ruby|node)', re.I),
     "Ejecución de código remoto vía pipe", "CRITICAL"),
    (re.compile(r'\b(curl|wget)\s+.*-o\s+-\s*\|\s*(sh|bash)', re.I),
     "Descarga y ejecución inmediata", "CRITICAL"),
    
    # --- Fork bomb ---
    (re.compile(r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:', re.I),
     "Fork bomb", "CRITICAL"),
    
    # --- Modificación de archivos del sistema ---
    (re.compile(r'(>>?)\s*(/etc/|/boot/|/proc/|/sys/|/dev/)', re.I),
     "Escritura en directorio del sistema", "CRITICAL"),
    (re.compile(r'\btee\s+(/etc/|/boot/|/proc/|/sys/)', re.I),
     "Escritura en directorio del sistema", "CRITICAL"),
    
    # --- Modificación de Windows system ---
    (re.compile(r'(>>?)\s*(C:\\Windows\\|C:\\System32\\|C:\\Program Files\\)', re.I),
     "Escritura en directorio del sistema Windows", "CRITICAL"),
    
    # --- Red y exfiltración ---
    (re.compile(r'\bnc\s+.*-[el]', re.I),
     "Netcat en modo listener/ejecución", "HIGH"),
    (re.compile(r'\bssh\s+.*@.*\s+(rm|dd|mkfs)', re.I),
     "Comando destructivo vía SSH remoto", "CRITICAL"),
    
    # --- Cron y persistencia ---
    (re.compile(r'\bcrontab\s+-[elr]\b', re.I),
     "Modificación de cron", "HIGH"),
    (re.compile(r'\b(systemctl|service)\s+(enable|disable|mask)\b', re.I),
     "Modificación de servicios del sistema", "MEDIUM"),
    
    # --- Gestión de usuarios ---
    (re.compile(r'\b(useradd|userdel|passwd|chpasswd)\b', re.I),
     "Modificación de usuarios", "HIGH"),
    
    # --- Firewall/red ---
    (re.compile(r'\b(iptables|ufw|firewalld|nft)\s+.*(-F|--flush|reset)', re.I),
     "Reset de firewall", "HIGH"),
    
    # --- Git destructivo ---
    (re.compile(r'\bgit\s+(push\s+.*--force|reset\s+--hard)', re.I),
     "Operación destructiva de git", "MEDIUM"),
    
    # --- Base64 + ejecución ---
    (re.compile(r'\bbase64\s+.*(-d|--decode)\s*\|\s*(sh|bash)', re.I),
     "Ejecución de código decodificado", "CRITICAL"),
]

# Paths críticos que nunca deben ser objetivo de escritura/borrado.
_CRITICAL_PATH_PATTERNS: List[re.Pattern] = [
    re.compile(r'(>>?|rm\s+.*|del\s+.*|rd\s+.*)\s*[/\\]?(etc|boot|proc|sys|dev)([/\\]|$)', re.I),
    re.compile(r'(>>?|rm\s+.*|del\s+.*|rd\s+.*)\s*C:[/\\](Windows|System32|Program Files)', re.I),
]

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
            "preauth_timeout": "15",
            "preauth_fallback_to_human": "true",
            "no_authorization": "false",
            "command_timeout": "120",
        },
        "UI": {
            "fullscreen": "false",
            "bg_color": "#0f1115",
            "fg_color": "#e6e8eb",
            "frame_bg": "#14171c",
            "card_bg": "#1a1d23",
            "prompt_bg": "#12141a",
            "prompt_fg": "#e6e8eb",
            "history_bg": "#12141a",
            "history_fg": "#d1d5db",
            "approval_bg": "#12141a",
            "approval_fg": "#86efac",
            "approval_request_bg": "#12141a",
            "approval_request_fg": "#fbbf24",
            "approval_granted_bg": "#12141a",
            "approval_granted_fg": "#34d399",
            "approval_denied_bg": "#12141a",
            "approval_denied_fg": "#f87171",
            "final_answer_fg": "#4ade80",
            "thought_fg": "#fdba74",
            "info_fg": "#fbbf24",
            "tool_call_fg": "#60a5fa",
            "tool_result_fg": "#5eead4",
            "error_fg": "#f87171",
            "status_change_fg": "#94a3b8",
            "loop_detected_fg": "#c4b5fd",
            "context_compacted_fg": "#c4b5fd",
            "context_overflow_fg": "#fb7185",
            "status_pending": "#9ca3af",
            "status_in_progress": "#60a5fa",
            "status_awaiting_approval": "#fbbf24",
            "status_completed": "#4ade80",
            "status_failed": "#f87171",
            "status_cancelled": "#6b7280",
            "font_family": "Segoe UI",
            "font_size": "10",
            "mono_font_family": "Consolas",
            "mono_font_size": "10",
            "context_bar_bg": "#2a2e37",
            "context_bar_low": "#4ade80",
            "context_bar_medium": "#fbbf24",
            "context_bar_high": "#f87171",
            "browser_bg": "#1a1d23",
            "browser_fg": "#e6e8eb",
            "browser_header_bg": "#14171c",
            "browser_selected_bg": "#1e3a5f",
            "browser_selected_fg": "#ffffff",
            "browser_border": "#2a2e37",
            "button_bg": "#272b33",
            "button_fg": "#e6e8eb",
            "checkbox_bg": "#1a1d23",
            "checkbox_fg": "#e6e8eb",
            "scrollbar_trough": "#14171c",
            "scrollbar_thumb": "#3a3f4b",
            "scrollbar_thumb_hover": "#4b5160",
            "scrollbar_arrow": "#9ca3af",
            "tab_bg": "#12141a",
            "tab_fg": "#9ca3af",
            "tab_hover_bg": "#1f232a",
            "tab_selected_bg": "#1a1d23",
            "tab_selected_fg": "#60a5fa",
            "separator_color": "#2a2e37",
            # --- Opciones de interfaz moderna (transparencias, esquinas redondeadas) ---
            "corner_radius": "10",
            "window_alpha": "1.0",
            "button_hover_bg": "#343944",
            "button_pressed_bg": "#1d2026",
            "button_accent_bg": "#3b82f6",
            "button_accent_fg": "#ffffff",
            "button_accent_hover_bg": "#60a5fa",
            "button_accent_pressed_bg": "#2563eb",
            "button_danger_bg": "#dc2626",
            "button_danger_fg": "#ffffff",
            "button_danger_hover_bg": "#ef4444",
            "button_danger_pressed_bg": "#b91c1c",
            "card_border_color": "#2a2e37",
            "card_border_width": "1",
            "card_shadow_color": "#000000",
            "accent_color": "#60a5fa",
            "gradient_enabled": "true",
            "hover_animation_ms": "80",
            # --- Barra de título moderna (Windows 10/11) ---
            # Estilo: "system" (por defecto), "dark" (modo oscuro nativo),
            # "accent" (color de acento del sistema), "custom" (color propio).
            "titlebar_style": "dark",
            # Color de fondo de la barra de título cuando titlebar_style="custom".
            # Acepta "#rrggbb" (Windows 11 22H2+) o "system" para usar el color
            # de acento del sistema.
            "titlebar_color": "#0f1115",
            # Color del texto/iconos de la barra de título cuando
            # titlebar_style="custom". Acepta "#rrggbb" o "system".
            "titlebar_text_color": "#e6e8eb",
            # --- Barra de título personalizada (overrideredirect) ---
            # Si es true, reemplaza la barra nativa por una barra
            # tkinter con botones minimizar/maximizar/cerrar y estilo
            # moderno minimalista.
            "custom_titlebar": "true",
            # Altura en píxeles de la barra personalizada (20-60).
            "custom_titlebar_height": "32",
        },
    }

    def __init__(self, path: str = CONFIG_PATH) -> None:
        self._path = path
        self.reload()

    @property
    def path(self) -> str:
        return self._path

    def reload(self) -> None:
        """Relee los valores por defecto y el fichero de configuración."""
        self._parser = configparser.ConfigParser()
        # Cargar valores por defecto primero.
        self._parser.read_dict(self.DEFAULTS)
        # Sobrescribir con config.ini si existe.
        if os.path.exists(self._path):
            try:
                self._parser.read(self._path, encoding="utf-8")
            except configparser.Error as e:
                print(f"[AVISO] Error leyendo {self._path}: {e}. Usando valores por defecto.")

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

    @property
    def preauth_timeout(self) -> float:
        """
        Timeout (en segundos) para la consulta de preautorización al LLM.

        Es independiente de ``llm_timeout`` porque una decisión de
        seguridad debe resolverse rápido: si el LLM tarda más de este
        umbral, se considera que no ha podido decidir y se aplica el
        fallback configurado en ``preauth_fallback_to_human``.
        """
        env_val = os.environ.get("HERCULES_PREAUTH_TIMEOUT")
        if env_val:
            try:
                return float(env_val)
            except ValueError:
                return self._parser.getfloat("Agent", "preauth_timeout")
        return self._parser.getfloat("Agent", "preauth_timeout")

    @property
    def preauth_fallback_to_human(self) -> bool:
        """
        Si es True (por defecto), cuando el LLM no puede decidir una
        preautorización (timeout, error o respuesta ambigua), la
        solicitud se encola para decisión humana en lugar de quedar
        bloqueada o resolverse automáticamente.

        Si es False, el sistema resuelve automáticamente como denegado
        en caso de fallo del LLM (modo "fail-closed" sin intervención
        humana).
        """
        env_val = os.environ.get("HERCULES_PREAUTH_FALLBACK")
        if env_val is not None:
            return _str_to_bool(env_val)
        return self._parser.getboolean("Agent", "preauth_fallback_to_human")

    @property
    def no_authorization(self) -> bool:
        """
        Si es True, todas las solicitudes de aprobación humana se conceden
        automáticamente sin consultar al usuario ni al LLM.

        Pensado para entornos de prueba/desarrollo. NO usar en producción:
        elimina por completo la barrera de seguridad HITL.
        """
        env_val = os.environ.get("HERCULES_NO_AUTHORIZATION")
        if env_val is not None:
            return _str_to_bool(env_val)
        return self._parser.getboolean("Agent", "no_authorization")

    @property
    def command_timeout(self) -> float:
        """
        Timeout (en segundos) para la ejecución de comandos del sistema
        invocados por la herramienta ``execute_command``.

        Si el comando tarda más de este umbral, `subprocess.run` lanza
        `TimeoutExpired` y la herramienta devuelve un error al modelo.
        """
        env_val = os.environ.get("HERCULES_COMMAND_TIMEOUT")
        if env_val:
            try:
                return float(env_val)
            except ValueError:
                return self._parser.getfloat("Agent", "command_timeout")
        return self._parser.getfloat("Agent", "command_timeout")

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
    def ui_context_overflow_fg(self) -> str:
        return self._parser.get("UI", "context_overflow_fg")

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
    def ui_browser_border(self) -> str:
        return self._parser.get("UI", "browser_border")

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

    @property
    def ui_scrollbar_trough(self) -> str:
        return self._parser.get("UI", "scrollbar_trough")

    @property
    def ui_scrollbar_thumb(self) -> str:
        return self._parser.get("UI", "scrollbar_thumb")

    @property
    def ui_scrollbar_thumb_hover(self) -> str:
        return self._parser.get("UI", "scrollbar_thumb_hover")

    @property
    def ui_scrollbar_arrow(self) -> str:
        return self._parser.get("UI", "scrollbar_arrow")

    @property
    def ui_tab_bg(self) -> str:
        return self._parser.get("UI", "tab_bg")

    @property
    def ui_tab_fg(self) -> str:
        return self._parser.get("UI", "tab_fg")

    @property
    def ui_tab_hover_bg(self) -> str:
        return self._parser.get("UI", "tab_hover_bg")

    @property
    def ui_tab_selected_bg(self) -> str:
        return self._parser.get("UI", "tab_selected_bg")

    @property
    def ui_tab_selected_fg(self) -> str:
        return self._parser.get("UI", "tab_selected_fg")

    @property
    def ui_separator_color(self) -> str:
        return self._parser.get("UI", "separator_color")

    # --- Opciones de interfaz moderna ---

    @property
    def ui_corner_radius(self) -> int:
        """Radio de las esquinas redondeadas (en píxeles)."""
        try:
            return max(0, self._parser.getint("UI", "corner_radius"))
        except (ValueError, configparser.Error):
            return 10

    @property
    def ui_window_alpha(self) -> float:
        """Transparencia de la ventana principal (0.5 - 1.0)."""
        env_val = os.environ.get("HERCULES_WINDOW_ALPHA")
        if env_val is not None:
            try:
                return max(0.5, min(1.0, float(env_val)))
            except ValueError:
                pass
        try:
            return max(0.5, min(1.0, self._parser.getfloat("UI", "window_alpha")))
        except (ValueError, configparser.Error):
            return 1.0

    @property
    def ui_titlebar_style(self) -> str:
        """
        Estilo de la barra de título nativa de Windows.

        Valores aceptados:
          - "system": barra de título nativa sin cambios (aspecto clásico).
          - "dark": modo oscuro nativo (texto/iconos blancos sobre fondo
            oscuro del sistema). Funciona en Windows 10 1903+ y Windows 11.
          - "accent": usa el color de acento del sistema como fondo de la
            barra de título (Windows 11 22H2+).
          - "custom": usa los colores definidos en ``ui_titlebar_color`` y
            ``ui_titlebar_text_color`` (Windows 11 22H2+).
        """
        env_val = os.environ.get("HERCULES_TITLEBAR_STYLE")
        if env_val:
            return env_val.strip().lower()
        try:
            return self._parser.get("UI", "titlebar_style").strip().lower()
        except (configparser.Error, ValueError):
            return "system"

    @property
    def ui_titlebar_color(self) -> str:
        """Color de fondo de la barra de título cuando ``titlebar_style="custom"``."""
        env_val = os.environ.get("HERCULES_TITLEBAR_COLOR")
        if env_val:
            return env_val.strip()
        try:
            return self._parser.get("UI", "titlebar_color").strip()
        except (configparser.Error, ValueError):
            return "#1e1e1e"

    @property
    def ui_titlebar_text_color(self) -> str:
        """Color del texto de la barra de título cuando ``titlebar_style="custom"``."""
        env_val = os.environ.get("HERCULES_TITLEBAR_TEXT_COLOR")
        if env_val:
            return env_val.strip()
        try:
            return self._parser.get("UI", "titlebar_text_color").strip()
        except (configparser.Error, ValueError):
            return "#e0e0e0"

    @property
    def ui_custom_titlebar(self) -> bool:
        """
        Si es ``True``, usa una barra de título personalizada (tkinter)
        con ``overrideredirect(True)`` en lugar de la barra nativa.

        La barra personalizada usa los colores definidos en
        ``ui_titlebar_color`` y ``ui_titlebar_text_color``, e incluye
        botones minimizar, maximizar y cerrar con efecto hover.
        """
        env_val = os.environ.get("HERCULES_CUSTOM_TITLEBAR")
        if env_val is not None:
            return env_val.strip().lower() in ("1", "true", "yes", "on")
        try:
            return self._parser.getboolean("UI", "custom_titlebar")
        except (configparser.Error, ValueError):
            return True

    @property
    def ui_custom_titlebar_height(self) -> int:
        """Altura en píxeles de la barra de título personalizada."""
        env_val = os.environ.get("HERCULES_CUSTOM_TITLEBAR_HEIGHT")
        if env_val is not None:
            try:
                return max(20, min(60, int(env_val)))
            except ValueError:
                pass
        try:
            return max(20, min(60, self._parser.getint("UI", "custom_titlebar_height")))
        except (ValueError, configparser.Error):
            return 32

    @property
    def ui_button_hover_bg(self) -> str:
        return self._parser.get("UI", "button_hover_bg")

    @property
    def ui_button_pressed_bg(self) -> str:
        return self._parser.get("UI", "button_pressed_bg")

    @property
    def ui_button_accent_bg(self) -> str:
        return self._parser.get("UI", "button_accent_bg")

    @property
    def ui_button_accent_fg(self) -> str:
        return self._parser.get("UI", "button_accent_fg")

    @property
    def ui_button_accent_hover_bg(self) -> str:
        return self._parser.get("UI", "button_accent_hover_bg")

    @property
    def ui_button_accent_pressed_bg(self) -> str:
        return self._parser.get("UI", "button_accent_pressed_bg")

    @property
    def ui_button_danger_bg(self) -> str:
        return self._parser.get("UI", "button_danger_bg")

    @property
    def ui_button_danger_fg(self) -> str:
        return self._parser.get("UI", "button_danger_fg")

    @property
    def ui_button_danger_hover_bg(self) -> str:
        return self._parser.get("UI", "button_danger_hover_bg")

    @property
    def ui_button_danger_pressed_bg(self) -> str:
        return self._parser.get("UI", "button_danger_pressed_bg")

    @property
    def ui_card_border_color(self) -> str:
        return self._parser.get("UI", "card_border_color")

    @property
    def ui_card_border_width(self) -> int:
        try:
            return max(0, self._parser.getint("UI", "card_border_width"))
        except (ValueError, configparser.Error):
            return 1

    @property
    def ui_card_shadow_color(self) -> str:
        return self._parser.get("UI", "card_shadow_color")

    @property
    def ui_accent_color(self) -> str:
        return self._parser.get("UI", "accent_color")

    @property
    def ui_gradient_enabled(self) -> bool:
        try:
            return self._parser.getboolean("UI", "gradient_enabled")
        except (ValueError, configparser.Error):
            return True

    @property
    def ui_hover_animation_ms(self) -> int:
        try:
            return max(0, self._parser.getint("UI", "hover_animation_ms"))
        except (ValueError, configparser.Error):
            return 80


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
COMMAND_TIMEOUT = CONFIG.command_timeout

# Directorio del script (para resolver rutas relativas como modelos/).
SCRIPT_DIR = Path(__file__).parent.resolve()
LOG_DIR = SCRIPT_DIR / "log"


_LLM_LOG_LOCK = threading.Lock()


def _redact_image_payloads(value: Any) -> Any:
    """Oculta los bytes Base64 de imágenes antes de registrar peticiones LLM."""
    if isinstance(value, dict):
        sanitized = {key: _redact_image_payloads(item) for key, item in value.items()}
        image_url = sanitized.get("image_url")
        if isinstance(image_url, dict):
            url = image_url.get("url")
            if isinstance(url, str) and url.startswith("data:image/"):
                image_url["url"] = "data:image/[contenido omitido del log]"
        return sanitized
    if isinstance(value, list):
        return [_redact_image_payloads(item) for item in value]
    return value


def _log_llm_exchange(direction: str, endpoint: str, content: str) -> None:
    """Registra el cuerpo de una petición/respuesta LLM en el log diario."""
    try:
        logged_content = json.dumps(
            _redact_image_payloads(json.loads(content)), ensure_ascii=False
        )
    except (json.JSONDecodeError, TypeError):
        logged_content = content

    now = datetime.now()
    log_path = LOG_DIR / f"llm_{now.strftime('%Y%m%d')}.txt"
    entry = (
        f"[{now.isoformat(timespec='seconds')}] {direction} {endpoint}\n"
        f"{logged_content}\n"
        f"{'-' * 80}\n"
    )
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with _LLM_LOG_LOCK, log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(entry)
    except OSError:
        pass


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
    
    @classmethod
    def finished(cls) -> List["TaskStatus"]:
        """Estados de tareas que han terminado y deben limpiarse al iniciar."""
        return [s for s in cls if s in cls.TERMINAL_STATUSES]  # type: ignore[attr-defined]  # noqa: F821

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
    CONTEXT_OVERFLOW = "context_overflow"
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
    image_data: Optional[str] = None


def _screenshot_data_uri(output: str) -> Optional[str]:
    """Carga la captura generada por la herramienta como un data URI PNG."""
    prefix = "Captura de pantalla guardada en: "
    if not output.startswith(prefix):
        return None

    path_text = output[len(prefix):].rsplit(" (", 1)[0]
    screenshot_path = Path(path_text)
    try:
        screenshot_path = screenshot_path.resolve(strict=True)
        screenshot_path.relative_to(WORKSPACE_DIR)
        if screenshot_path.suffix.lower() != ".png" or not screenshot_path.is_file():
            return None
        image_bytes = screenshot_path.read_bytes()
    except (OSError, ValueError):
        return None

    if not image_bytes.startswith(bytes.fromhex("89504e470d0a1a0a")):
        return None
    if len(image_bytes) > 4 * 1024 * 1024:
        try:
            from PIL import Image

            with Image.open(screenshot_path) as image:
                image = image.convert("RGB")
                for _ in range(8):
                    buffer = io.BytesIO()
                    image.save(buffer, format="JPEG", quality=85, optimize=True)
                    image_bytes = buffer.getvalue()
                    if len(image_bytes) <= 4 * 1024 * 1024:
                        break
                    image.thumbnail((max(1, int(image.width * 0.8)), max(1, int(image.height * 0.8))))
                else:
                    return None
            mime_type = "image/jpeg"
        except Exception:  # noqa: BLE001
            return None
    else:
        mime_type = "image/png"
    encoded = base64.b64encode(image_bytes).decode("ascii")
    return f"data:{mime_type};base64,{encoded}"


def _image_message(image_data: str) -> Dict[str, Any]:
    """Crea un mensaje multimodal compatible con Chat Completions."""
    return {
        "role": "user",
        "content": [
            {"type": "text", "text": "Analiza la siguiente captura de pantalla."},
            {"type": "image_url", "image_url": {"url": image_data}},
        ],
    }


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
        now = datetime.now(UTC).isoformat(timespec="seconds")
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
        _log_llm_exchange("SALIDA LOCAL", "llama-cpp-python", json.dumps(kwargs, ensure_ascii=False))
        try:
            result = self._local_llm.create_chat_completion(**kwargs)
        except Exception as e:  # noqa: BLE001
            _log_llm_exchange("ENTRADA LOCAL ERROR", "llama-cpp-python", f"{type(e).__name__}: {e}")
            raise LLMError(f"Error en inferencia local: {e}") from e
        # llama-cpp-python devuelve un dict estilo OpenAI.
        if isinstance(result, dict):
            response = result
        else:
            try:
                response = dict(result)
            except Exception as e:  # noqa: BLE001
                _log_llm_exchange("ENTRADA LOCAL ERROR", "llama-cpp-python", f"{type(e).__name__}: {e}")
                raise LLMError(f"Respuesta local en formato inesperado: {e}") from e
        _log_llm_exchange("ENTRADA LOCAL", "llama-cpp-python", json.dumps(response, ensure_ascii=False, default=str))
        return response

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

        request_body = json.dumps(payload, ensure_ascii=False)
        _log_llm_exchange("SALIDA", url, request_body)
        data = request_body.encode("utf-8")
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
                _log_llm_exchange("ENTRADA", url, body)
                return json.loads(body)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            _log_llm_exchange("ENTRADA ERROR", url, detail)
            raise LLMError(f"HTTP {e.code} desde {url}: {detail}") from e
        except urllib.error.URLError as e:
            _log_llm_exchange("ENTRADA ERROR", url, f"{type(e).__name__}: {e.reason}")
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
    return datetime.now(UTC).replace(tzinfo=None).isoformat(timespec="seconds")


def tool_take_screenshot(args: Dict[str, Any]) -> str:
    try:
        path = _resolve_workspace_path(args.get("path", "")) if args.get("path") else None
        return computer_tools.take_screenshot(path, workspace_dir=WORKSPACE_DIR)
    except (OSError, ValueError) as exc:
        return f"ERROR: {exc}"


def tool_mouse_click(args: Dict[str, Any]) -> str:
    return computer_tools.mouse_click(
        x=args["x"],
        y=args["y"],
        button=args.get("button", "left"),
        clicks=args.get("clicks", 1),
    )


def tool_mouse_move(args: Dict[str, Any]) -> str:
    return computer_tools.mouse_move(
        x=args["x"], y=args["y"], duration=args.get("duration", 0.0)
    )


def tool_write_file(args: Dict[str, Any]) -> str:
    path = _resolve_workspace_path(args.get("path", ""))
    content = args.get("content", "")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        return f"ERROR al escribir {path}: {e}"
    return f"OK: escrito {len(content)} caracteres en {path}"


def tool_create_file(args: Dict[str, Any]) -> str:
    if "content" not in args or not isinstance(args["content"], str):
        return "ERROR: 'content' es obligatorio y debe ser texto"
    path = _resolve_workspace_path(args.get("path", ""))
    content = args["content"]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8", newline="") as file:
            file.write(content)
    except FileExistsError:
        return f"ERROR: el archivo ya existe: {path}"
    except Exception as e:  # noqa: BLE001
        return f"ERROR al crear {path}: {e}"
    return f"OK: creado {len(content)} caracteres en {path}"


def tool_edit_file(args: Dict[str, Any]) -> str:
    path = _resolve_workspace_path(args.get("path", ""))
    old_text = args.get("old_text", "")
    new_text = args.get("new_text", "")
    if not path.exists() or not path.is_file():
        return f"ERROR: el archivo no existe o no es un archivo: {path}"
    try:
        content = path.read_text(encoding="utf-8")
        if old_text == "":
            path.write_text(new_text, encoding="utf-8")
            return f"OK: editado {path}"
        occurrences = content.count(old_text)
        if occurrences != 1:
            return (
                f"ERROR: se esperaba una única coincidencia de 'old_text' en {path}, "
                f"pero se encontraron {occurrences}"
            )
        path.write_text(content.replace(old_text, new_text, 1), encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        return f"ERROR al editar {path}: {e}"
    return f"OK: editado {path}"


def tool_search_in_files(args: Dict[str, Any]) -> str:
    query = args.get("query", "")
    base = _resolve_workspace_path(args.get("path", "."))
    file_pattern = args.get("file_pattern", "*")
    if not query:
        return "ERROR: 'query' es obligatorio"
    if not base.exists() or not base.is_dir():
        return f"ERROR: directorio inválido: {base}"

    matches: List[str] = []
    try:
        for candidate in base.rglob(file_pattern):
            if not candidate.is_file():
                continue
            resolved = candidate.resolve()
            try:
                resolved.relative_to(WORKSPACE_DIR)
            except ValueError:
                continue
            try:
                lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for line_number, line in enumerate(lines, start=1):
                if query in line:
                    relative = resolved.relative_to(WORKSPACE_DIR)
                    matches.append(f"{relative}:{line_number}: {line}")
                    if len(matches) >= 200:
                        matches.append("... [truncado, más de 200 coincidencias]")
                        return "\n".join(matches)
    except Exception as e:  # noqa: BLE001
        return f"ERROR al buscar: {e}"
    return "\n".join(matches) if matches else "(sin coincidencias)"


def _is_command_safe(command: str) -> Tuple[bool, str]:

    """
    Analiza un comando y devuelve (es_seguro, razón_si_no).
    
    Estrategia:
        1. Detectar y analizar subshells recursivamente.
        2. Dividir por chaining operators y analizar cada segmento.
        3. Comprobar patrones peligrosos (regex).
        4. Comprobar paths críticos.
        5. Detectar encoding + ejecución.
    """
    if not command or not command.strip():
        return False, "Comando vacío"
    
    # 1. Subshells: extraer y analizar recursivamente.
    for subshell in re.findall(r'\$\(([^)]*)\)', command):
        safe, reason = _is_command_safe(subshell)
        if not safe:
            return False, f"Subshell peligroso: {reason}"
    for subshell in re.findall(r'`([^`]*)`', command):
        safe, reason = _is_command_safe(subshell)
        if not safe:
            return False, f"Backtick peligroso: {reason}"
    
    # 2. Dividir por chaining y analizar cada segmento.
    segments = re.split(r'[;&|]+', command)
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        
        # 3. Comprobar patrones peligrosos.
        for pattern, reason, severity in _DANGEROUS_PATTERNS:
            if pattern.search(segment):
                return False, f"[{severity}] {reason}"
        
        # 4. Comprobar paths críticos.
        for path_pattern in _CRITICAL_PATH_PATTERNS:
            if path_pattern.search(segment):
                return False, f"[CRITICAL] Acceso a path del sistema: {segment[:80]}"
    
    return True, ""

def tool_execute_command(args: Dict[str, Any]) -> str:
    """
    Ejecuta un comando del sistema de forma restringida al workspace.
    Se aplica una lista de denegación para comandos peligrosos.
    """
    command = args.get("command", "")
    if not command:
        return "ERROR: 'command' es obligatorio"

    # Validación robusta de seguridad.
    safe, reason = _is_command_safe(command)
    if not safe:
        return f"ERROR: comando bloqueado por política de seguridad: {reason}"

    try:
        # cwd restringido al workspace.
        result = subprocess.run(
            command,
            shell=True,
            cwd=str(WORKSPACE_DIR),
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return f"ERROR: timeout ({COMMAND_TIMEOUT:g}s) ejecutando el comando"
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
                name="take_screenshot",
                description=(
                    "Captura la pantalla y guarda una imagen PNG dentro del workspace. "
                    "Argumento opcional: path (ruta de salida relativa al workspace; "
                    "por defecto, un archivo en la raíz del workspace)."
                ),
                risk=RiskLevel.SAFE,
                parameters={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Ruta de salida del PNG (opcional).",
                        }
                    },
                },
                runner=tool_take_screenshot,
            )
        )
        self.register(
            ToolDefinition(
                name="mouse_click",
                description=(
                    "Hace clic con el ratón en coordenadas de pantalla. "
                    "Argumentos: x, y; button (left/right/middle, por defecto left), "
                    "clicks (por defecto 1)."
                ),
                risk=RiskLevel.SAFE,
                parameters={
                    "type": "object",
                    "properties": {
                        "x": {"type": "integer", "description": "Coordenada horizontal."},
                        "y": {"type": "integer", "description": "Coordenada vertical."},
                        "button": {
                            "type": "string",
                            "enum": ["left", "right", "middle"],
                            "description": "Botón del ratón.",
                        },
                        "clicks": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Número de clics.",
                        },
                    },
                    "required": ["x", "y"],
                },
                runner=tool_mouse_click,
            )
        )
        self.register(
            ToolDefinition(
                name="mouse_move",
                description=(
                    "Mueve el puntero a coordenadas de pantalla. "
                    "Argumentos: x, y; duration (duración en segundos, por defecto 0)."
                ),
                risk=RiskLevel.SAFE,
                parameters={
                    "type": "object",
                    "properties": {
                        "x": {"type": "integer", "description": "Coordenada horizontal."},
                        "y": {"type": "integer", "description": "Coordenada vertical."},
                        "duration": {
                            "type": "number",
                            "minimum": 0,
                            "description": "Duración del movimiento en segundos.",
                        },
                    },
                    "required": ["x", "y"],
                },
                runner=tool_mouse_move,
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
                name="create_file",
                description=(
                    "Crea un archivo nuevo dentro del workspace sin sobrescribir uno existente. "
                    "Argumentos: path, content (obligatorio)."
                ),
                risk=RiskLevel.CRITICAL,
                parameters={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Ruta del archivo nuevo."},
                        "content": {"type": "string", "description": "Contenido inicial (opcional)."},
                    },
                    "required": ["path", "content"],
                },
                runner=tool_create_file,
            )
        )
        self.register(
            ToolDefinition(
                name="edit_file",
                description=(
                    "Reemplaza una cadena exacta en un archivo existente, solo si hay una coincidencia; "
                    "si old_text está vacío, sustituye todo el contenido. "
                    "Argumentos: path, old_text, new_text."
                ),
                risk=RiskLevel.CRITICAL,
                parameters={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Ruta del archivo a editar."},
                        "old_text": {"type": "string", "description": "Texto a reemplazar; si está vacío, sustituye todo el contenido del archivo."},
                        "new_text": {"type": "string", "description": "Texto que reemplaza la coincidencia."},
                    },
                    "required": ["path", "old_text", "new_text"],
                },
                runner=tool_edit_file,
            )
        )
        self.register(
            ToolDefinition(
                name="search_in_files",
                description=(
                    "Busca una cadena literal en el contenido de archivos dentro del workspace. "
                    "Argumentos: query, path (opcional), file_pattern (opcional, por defecto '*')."
                ),
                risk=RiskLevel.SAFE,
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Texto literal a buscar."},
                        "path": {"type": "string", "description": "Directorio base (opcional)."},
                        "file_pattern": {"type": "string", "description": "Patrón glob de archivos (opcional)."},
                    },
                    "required": ["query"],
                },
                runner=tool_search_in_files,
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
        cancel_event: Optional[threading.Event] = None,
    ) -> PermissionDecision:
        """
        Solicita aprobación humana para una herramienta CRITICAL.

        Publica un evento en la cola de la UI y espera la decisión.
        """
        # Bypass total: no se requiere autorización humana ni del LLM.
        if CONFIG.no_authorization:
            return PermissionDecision(
                True,
                "autorización omitida por configuración (no_authorization=true)",
            )

        if cancel_event is not None and cancel_event.is_set():
            return PermissionDecision(False, "tarea abortada por el usuario")

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
        # El timeout es una red de seguridad: la decisión real llega vía
        # ``resolve()``. Si la preautorización está habilitada, el flujo
        # preauth + decisión humana debería completarse en
        # ``preauth_timeout + buffer``; si está deshabilitada, se mantiene
        # el límite generoso de 10 minutos para decisión humana directa.
        if CONFIG.preauth_fallback_to_human:
            wait_timeout = max(60.0, float(CONFIG.preauth_timeout) + 30.0)
        else:
            wait_timeout = 600.0  # 10 minutos máximo.
        deadline = time.monotonic() + wait_timeout
        while not event.wait(timeout=min(0.2, max(0.0, deadline - time.monotonic()))):
            if cancel_event is not None and cancel_event.is_set():
                self.resolve(request_id, False, "tarea abortada por el usuario")
                break
            if time.monotonic() >= deadline:
                break

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
    Detecta cuando el modelo está repitiendo la misma respuesta.

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

    def reset(self) -> None:
        """Reinicia el detector (p.ej. tras una compactación de contexto)."""
        self._counts.clear()


# ============================================================================
# MOTOR DEL AGENTE (ReAct)
# ============================================================================

SYSTEM_PROMPT = """Eres un agente autónomo con acceso a HERRAMIENTAS (tools/functions). Tienes permiso y DEBES usarlas cuando la tarea lo requiera.

HERRAMIENTAS DISPONIBLES:
- read_file(path): Lee el contenido de un archivo del workspace.
- create_file(path, content): Crea un archivo nuevo sin sobrescribir uno existente.
- edit_file(path, old_text, new_text): Reemplaza una coincidencia exacta; si old_text está vacío, sustituye todo el contenido.
- search_in_files(query, path, file_pattern): Busca texto literal dentro de archivos.
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

        latest_image_message = next(
            (
                msg for msg in reversed(middle)
                if msg.get("role") == "user"
                and isinstance(msg.get("content"), list)
                and any(
                    isinstance(part, dict) and part.get("type") == "image_url"
                    for part in msg["content"]
                )
            ),
            None,
        )

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
        compacted_count = 4 if latest_image_message is not None else 3
        summary_description = "system + user + resumen"
        if latest_image_message is not None:
            summary_description += " + imagen"
        self._log(
            task_id,
            EventType.CONTEXT_COMPACTED,
            (
                f"Contexto compactado: {len(messages)} mensajes → "
                f"{compacted_count} mensajes ({summary_description})."
            ),
        )

        compacted = [system_msg, user_msg, summary_msg]
        if latest_image_message is not None:
            compacted.append(latest_image_message)
        return compacted

    # --- Ejecución de tool calls ---

    def _execute_tool_call(
        self,
        task_id: int,
        call: ToolCall,
        cancel_event: Optional[threading.Event] = None,
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
            if cancel_event is None:
                decision = self.permissions.request(task_id, tool, call.arguments)
            else:
                decision = self.permissions.request(
                    task_id, tool, call.arguments, cancel_event=cancel_event
                )
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
        image_data = (
            _screenshot_data_uri(output)
            if success and tool.name == "take_screenshot"
            else None
        )
        return ToolResult(call.id, call.name, success, output, image_data)

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
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text = part.get("text", "")
                        if isinstance(text, str):
                            total_chars += len(text)
                    elif isinstance(part, dict) and part.get("type") == "image_url":
                        total_chars += 4096
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

    def run(
        self,
        task: Task,
        cancel_event: Optional[threading.Event] = None,
    ) -> None:
        """Ejecuta el bucle de razonamiento para una tarea."""
        if task.id is None:
            return

        task_id = task.id
        if cancel_event is not None and cancel_event.is_set():
            self._set_status(task_id, TaskStatus.CANCELLED)
            return
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
                if cancel_event is not None and cancel_event.is_set():
                    self._log(task_id, EventType.INFO, "Tarea abortada por el usuario.")
                    self._set_status(task_id, TaskStatus.CANCELLED)
                    return
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

                if cancel_event is not None and cancel_event.is_set():
                    self._log(task_id, EventType.INFO, "Tarea abortada por el usuario.")
                    self._set_status(task_id, TaskStatus.CANCELLED)
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

                image_messages: List[Dict[str, Any]] = []
                for tc in tool_calls:
                    self._log(
                        task_id,
                        EventType.TOOL_CALL,
                        (
                            f"Llamada a herramienta: {tc.name}\n"
                            f"Argumentos: {json.dumps(tc.arguments, ensure_ascii=False, indent=2)}"
                        ),
                    )
                    if cancel_event is not None and cancel_event.is_set():
                        self._log(task_id, EventType.INFO, "Tarea abortada por el usuario.")
                        self._set_status(task_id, TaskStatus.CANCELLED)
                        return
                    result = self._execute_tool_call(task_id, tc, cancel_event=cancel_event)
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": result.tool_call_id,
                            "content": result.output,
                        }
                    )
                    if result.image_data:
                        image_messages.append(_image_message(result.image_data))
                    if tc.name in {"create_file", "edit_file", "write_file", "execute_command", "delete_file"} and result.success:
                        # refrescamos explorador de ficheros
                        self.ui_queue.put({"type": "refresh_file_browser", "task_id": task_id})

                messages.extend(image_messages)

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
        "1. USA las herramientas disponibles (create_file, edit_file, "
        "search_in_files, write_file, execute_command, read_file, etc.) "
        "para implementar la solución.\n"
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
        "2. USA las herramientas disponibles (edit_file, search_in_files, "
        "write_file, execute_command, read_file, etc.) para corregir los problemas.\n"
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
    ``value`` del enum como nombre de sección: ``REQUIREMENTS``,
    ``DEVELOPMENT``, ``EXECUTION_VERIFICATION``, ``RECTIFICATION``) y una
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

    def run(
        self,
        parent_task: Task,
        cancel_event: Optional[threading.Event] = None,
    ) -> None:
        """
        Ejecuta el flujo completo de descomposición para una tarea padre.

        La tarea padre ya debe existir en la BD (creada por el dashboard).
        Este método crea las subtareas, las ejecuta secuencialmente y
        actualiza el estado de la tarea padre al final.
        """
        if parent_task.id is None:
            return
        parent_id = parent_task.id
        if cancel_event is not None and cancel_event.is_set():
            self._cancel_parent(parent_id, "Tarea abortada por el usuario.")
            return

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
        requirements_output = self._run_subtask(requirements_task, cancel_event)
        if requirements_output is None:
            if cancel_event is not None and cancel_event.is_set():
                self._cancel_parent(parent_id, "Tarea abortada por el usuario.")
                return
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
        solution_output = self._run_subtask(development_task, cancel_event)
        if solution_output is None:
            if cancel_event is not None and cancel_event.is_set():
                self._cancel_parent(parent_id, "Tarea abortada por el usuario.")
                return
            self._fail_parent(parent_id, "La subtarea de desarrollo no produjo resultado.")
            return

        # --- Subtarea 3: Ejecución y verificación (con ciclo de rectificación) ---
        attempt = 0
        verification_output: Optional[str] = None
        previous_solution = solution_output

        while True:
            if cancel_event is not None and cancel_event.is_set():
                self._cancel_parent(parent_id, "Tarea abortada por el usuario.")
                return
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
            verification_output = self._run_subtask(verification_task, cancel_event)

            if verification_output is None:
                if cancel_event is not None and cancel_event.is_set():
                    self._cancel_parent(parent_id, "Tarea abortada por el usuario.")
                    return
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
            rectified_solution = self._run_subtask(rectification_task, cancel_event)
            if rectified_solution is None:
                if cancel_event is not None and cancel_event.is_set():
                    self._cancel_parent(parent_id, "Tarea abortada por el usuario.")
                    return
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

    def _run_subtask(
        self,
        task: Task,
        cancel_event: Optional[threading.Event] = None,
    ) -> Optional[str]:
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
        if cancel_event is None:
            self.agent.run(task)
        else:
            self.agent.run(task, cancel_event=cancel_event)
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
        verificacion_estado = None

        if text.startswith(_VERIFICATION_FAILURE_PREFIX):
            verificacion_estado = False
        if text.startswith(_VERIFICATION_SUCCESS_PREFIX):
            verificacion_estado = True
        if verificacion_estado is None:
            # No se reconoce el prefijo:busamos en todo el texto.
            if _VERIFICATION_SUCCESS_PREFIX in text:
                verificacion_estado = True
            elif _VERIFICATION_FAILURE_PREFIX in text:
                verificacion_estado = False

        return verificacion_estado

    def _cancel_parent(self, parent_id: int, reason: str) -> None:
        """Marca la tarea padre como cancelada y registra el motivo."""
        self.db.update_task_status(
            parent_id,
            TaskStatus.CANCELLED,
            final_answer=f"CANCELLED: {reason}",
        )
        self.ui_queue.put(
            {"type": "status_change", "task_id": parent_id, "status": TaskStatus.CANCELLED.value}
        )
        self._log_parent(
            parent_id,
            EventType.STATUS_CHANGE,
            f"⛔ Tarea padre #{parent_id} → CANCELLED. Motivo: {reason}",
        )

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
# WIDGETS PERSONALIZADOS (interfaz moderna)
# ============================================================================
# Estos widgets se construyen sobre Canvas para conseguir efectos que
# tkinter/ttk no soporta de forma nativa:
#   - Esquinas redondeadas en frames y botones.
#   - Efectos hover/pressed con animación suave de color.
#   - Fondos con degradado (gradiente vertical).
#   - Bordes y sombras simuladas.
#
# Se mantiene la filosofía del proyecto: cero dependencias externas,
# solo biblioteca estándar de Python (tkinter).
# ============================================================================


def _apply_modern_titlebar(window: Any) -> None:
    """
    Aplica un estilo moderno a la barra de título nativa de Windows.

    Usa la API DWM (Desktop Window Manager) vía ``ctypes`` para
    personalizar la barra de título sin necesidad de dependencias
    externas. Soporta cuatro estilos configurables desde
    ``CONFIG.ui_titlebar_style``:

      - ``"system"``: no hace nada (aspecto clásico de Windows).
      - ``"dark"``: activa el modo oscuro nativo (texto/iconos blancos
        sobre fondo oscuro del sistema). Funciona en Windows 10 1903+
        y Windows 11.
      - ``"accent"``: usa el color de acento del sistema como fondo de
        la barra de título (Windows 11 22H2+).
      - ``"custom"``: usa los colores definidos en
        ``CONFIG.ui_titlebar_color`` y ``CONFIG.ui_titlebar_text_color``
        (Windows 11 22H2+).

    En plataformas distintas de Windows, o si la API DWM no está
    disponible, la función no hace nada (no rompe la aplicación).

    Atributos DWM utilizados:
      - ``DWMWA_USE_IMMERSIVE_DARK_MODE`` (20): modo oscuro.
      - ``DWMWA_CAPTION_COLOR`` (35): color de fondo (Win 11 22H2+).
      - ``DWMWA_TEXT_COLOR`` (36): color del texto (Win 11 22H2+).
    """
    # Solo Windows soporta personalización de la barra de título vía DWM.
    if sys.platform != "win32":
        return

    style = (CONFIG.ui_titlebar_style or "system").strip().lower()
    if style == "system":
        return

    try:
        import ctypes
        from ctypes import wintypes

        # Resolver el HWND de la ventana tkinter.
        try:
            hwnd = int(window.frame(), 16)
        except Exception:
            try:
                hwnd = window.winfo_id()
            except Exception:
                return

        # Cargar dwmapi.dll y la función DwmSetWindowAttribute.
        try:
            dwmapi = ctypes.WinDLL("dwmapi")
        except Exception:
            return

        DwmSetWindowAttribute = dwmapi.DwmSetWindowAttribute
        DwmSetWindowAttribute.restype = ctypes.HRESULT
        DwmSetWindowAttribute.argtypes = [
            wintypes.HWND,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]

        def _set_attr(attr_id: int, value: int) -> bool:
            """Llama a DwmSetWindowAttribute con un valor entero (BOOL/COLORREF)."""
            try:
                value_c = ctypes.c_int(value)
                hr = DwmSetWindowAttribute(
                    hwnd,
                    attr_id,
                    ctypes.byref(value_c),
                    ctypes.sizeof(value_c),
                )
                return hr == 0  # S_OK
            except Exception:
                return False

        # --- Modo oscuro (DWMWA_USE_IMMERSIVE_DARK_MODE = 20) ---
        if style == "dark":
            # True = 1, False = 0. Probamos también con el atributo 19
            # (DWMWA_USE_IMMERSIVE_DARK_MODE antes de 20H1) por
            # compatibilidad con versiones antiguas de Windows 10.
            _set_attr(20, 1) or _set_attr(19, 1)
            return

        # --- Color personalizado / acento (Win 11 22H2+) ---
        # DWMWA_CAPTION_COLOR = 35, DWMWA_TEXT_COLOR = 36.
        # El valor es un COLORREF: 0x00BBGGRR (formato little-endian BGR).
        def _hex_to_colorref(hex_color: str) -> int:
            """Convierte '#rrggbb' a COLORREF (0x00BBGGRR)."""
            c = hex_color.strip().lstrip("#")
            if len(c) != 6:
                return 0
            try:
                r = int(c[0:2], 16)
                g = int(c[2:4], 16)
                b = int(c[4:6], 16)
            except ValueError:
                return 0
            return (b << 16) | (g << 8) | r

        if style == "custom":
            bg = _hex_to_colorref(CONFIG.ui_titlebar_color)
            fg = _hex_to_colorref(CONFIG.ui_titlebar_text_color)
            if bg:
                _set_attr(35, bg)
            if fg:
                _set_attr(36, fg)
            # Activar también el modo oscuro para que el texto se vea
            # bien sobre el fondo oscuro personalizado.
            _set_attr(20, 1) or _set_attr(19, 1)
            return

        if style == "accent":
            # DWORD = 0xFFFFFFFF significa "usar color de acento del sistema".
            _set_attr(35, 0xFFFFFFFF)
            _set_attr(20, 1) or _set_attr(19, 1)
            return

    except Exception:
        # Cualquier error se ignora silenciosamente: la barra de título
        # simplemente quedará con el aspecto por defecto de Windows.
        pass


def _hex_to_rgb(color: str) -> Tuple[int, int, int]:
    """Convierte un color hexadecimal (#rrggbb) a una tupla (r, g, b)."""
    c = color.strip().lstrip("#")
    if len(c) == 3:
        c = "".join(ch * 2 for ch in c)
    if len(c) != 6:
        return (0, 0, 0)
    try:
        return (int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16))
    except ValueError:
        return (0, 0, 0)


def _rgb_to_hex(rgb: Tuple[int, int, int]) -> str:
    """Convierte una tupla (r, g, b) a color hexadecimal (#rrggbb)."""
    r, g, b = (max(0, min(255, int(v))) for v in rgb)
    return f"#{r:02x}{g:02x}{b:02x}"


def _blend_colors(color_a: str, color_b: str, t: float) -> str:
    """
    Interpola linealmente entre dos colores hexadecimales.

    ``t`` en [0.0, 1.0]: 0.0 devuelve ``color_a``, 1.0 devuelve ``color_b``.
    """
    t = max(0.0, min(1.0, float(t)))
    ra, ga, ba = _hex_to_rgb(color_a)
    rb, gb, bb = _hex_to_rgb(color_b)
    return _rgb_to_hex(
        (
            ra + (rb - ra) * t,
            ga + (gb - ga) * t,
            ba + (bb - ba) * t,
        )
    )


def _use_ttk_scrollbar(widget: ScrolledText) -> None:
    """Sustituye la barra clásica de un ScrolledText por una ttk con tema."""
    old = widget.vbar
    new = ttk.Scrollbar(widget.frame, orient="vertical", command=widget.yview)
    widget.configure(yscrollcommand=new.set)
    old.destroy()
    # El Text queda empaquetado en el frame; se reordena para que la barra se reserve primero.
    widget.tk.call("pack", "forget", widget._w)
    new.pack(side="right", fill="y")
    widget.tk.call("pack", widget._w, "-side", "left", "-fill", "both", "-expand", "1")
    widget.vbar = new
    widget.frame.configure(background=widget.cget("background"))


def _draw_rounded_rect(
    canvas: Canvas,
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    radius: float,
    **kwargs: Any,
) -> int:
    """
    Dibuja un rectángulo con esquinas redondeadas en un Canvas.

    Usa ``create_polygon`` con una secuencia de puntos que aproxima las
    cuatro esquinas con arcos. Es la técnica estándar para esquinas
    redondeadas en tkinter puro (sin dependencias externas).

    Devuelve el id del objeto creado.
    """
    r = max(0.0, float(radius))
    # Si el radio es 0 o el rectángulo es demasiado pequeño, dibuja un
    # rectángulo normal (más rápido y visualmente idéntico).
    if r <= 0 or (x2 - x1) < 2 * r or (y2 - y1) < 2 * r:
        return canvas.create_rectangle(x1, y1, x2, y2, **kwargs)

    # 12 puntos por esquina (cada 30°) → 48 puntos en total.
    # Suficiente para que la curva se vea suave a simple vista.
    steps_per_corner = 12
    points: List[float] = []

    # Esquina superior izquierda: centro (x1+r, y1+r), de 180° a 270°.
    cx, cy = x1 + r, y1 + r
    for i in range(steps_per_corner + 1):
        angle = 180 + (90 * i / steps_per_corner)
        import math
        rad = math.radians(angle)
        points.extend([cx + r * math.cos(rad), cy + r * math.sin(rad)])

    # Esquina superior derecha: centro (x2-r, y1+r), de 270° a 360°.
    cx, cy = x2 - r, y1 + r
    for i in range(steps_per_corner + 1):
        angle = 270 + (90 * i / steps_per_corner)
        rad = math.radians(angle)
        points.extend([cx + r * math.cos(rad), cy + r * math.sin(rad)])

    # Esquina inferior derecha: centro (x2-r, y2-r), de 0° a 90°.
    cx, cy = x2 - r, y2 - r
    for i in range(steps_per_corner + 1):
        angle = 0 + (90 * i / steps_per_corner)
        rad = math.radians(angle)
        points.extend([cx + r * math.cos(rad), cy + r * math.sin(rad)])

    # Esquina inferior izquierda: centro (x1+r, y2-r), de 90° a 180°.
    cx, cy = x1 + r, y2 - r
    for i in range(steps_per_corner + 1):
        angle = 90 + (90 * i / steps_per_corner)
        rad = math.radians(angle)
        points.extend([cx + r * math.cos(rad), cy + r * math.sin(rad)])

    return canvas.create_polygon(points, smooth=True, **kwargs)


class RoundedFrame:
    """
    Frame con esquinas redondeadas, borde opcional y sombra simulada.

    Internamente es un ``Canvas`` que ocupa todo el espacio del contenedor
    padre. Los widgets hijos se empaquetan en un ``Frame`` interno
    (``self.inner``) que se redimensiona junto con el Canvas.

    El Canvas ajusta su tamaño automáticamente al contenido del Frame
    interno (más el padding), de modo que ``pack``/``grid`` propagan el
    tamaño correcto hacia el contenedor padre.

    Uso típico (sustituye a ``ttk.Frame`` con ``style="Card.TFrame"``)::

        card = RoundedFrame(parent, bg=CONFIG.ui_card_bg,
                            border_color=CONFIG.ui_card_border_color,
                            border_width=CONFIG.ui_card_border_width,
                            radius=CONFIG.ui_corner_radius)
        card.pack(fill="both", expand=True, padx=4, pady=4)
        ttk.Label(card.inner, text="Hola", style="Card.TLabel").pack()

    Atributos públicos:
        inner: Frame donde deben añadirse los widgets hijos.
    """

    def __init__(
        self,
        parent: Any,
        bg: Optional[str] = None,
        border_color: Optional[str] = None,
        border_width: int = 0,
        radius: int = 10,
        shadow: bool = False,
        shadow_color: Optional[str] = None,
        padding: int = 0,
        **kwargs: Any,
    ) -> None:
        self._bg = bg or CONFIG.ui_card_bg
        self._border_color = border_color or CONFIG.ui_card_border_color
        self._border_width = max(0, int(border_width))
        self._radius = max(0, int(radius))
        self._shadow = bool(shadow)
        self._shadow_color = shadow_color or CONFIG.ui_card_shadow_color
        self._padding = max(0, int(padding))

        # Canvas exterior: aquí se dibujan el fondo redondeado, el borde
        # y (opcionalmente) la sombra. Se inicializa con un tamaño mínimo
        # de 1x1 para que ``winfo_reqwidth``/``winfo_reqheight`` devuelvan
        # un valor válido desde el primer momento.
        self.canvas = Canvas(
            parent,
            bg=CONFIG.ui_bg_color,  # mismo color que el fondo del dashboard
            highlightthickness=0,
            borderwidth=0,
            width=1,
            height=1,
        )
        # Frame interior: aquí se empaquetan los widgets hijos.
        # Su fondo coincide con el del Canvas para que no se vea "hueco"
        # en las esquinas redondeadas.
        self.inner = Frame(
            self.canvas,
            bg=self._bg,
            highlightthickness=0,
            borderwidth=0,
        )
        self._inner_window = self.canvas.create_window(
            self._padding, self._padding,
            window=self.inner,
            anchor="nw",
        )

        # Eventos de redimensionamiento.
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        # Cuando el Frame interno cambia su tamaño solicitado, ajustamos
        # el Canvas para que ``pack``/``grid`` propaguen el tamaño correcto.
        self.inner.bind("<Configure>", self._on_inner_configure)
        # Cuando el Canvas se mapea por primera vez, forzamos el recálculo
        # del tamaño basándonos en el contenido del Frame interno.
        self.canvas.bind("<Map>", self._on_map)

    # --- API compatible con widgets tkinter ---

    def pack(self, **kwargs: Any) -> None:
        self.canvas.pack(**kwargs)

    def grid(self, **kwargs: Any) -> None:
        self.canvas.grid(**kwargs)

    def place(self, **kwargs: Any) -> None:
        self.canvas.place(**kwargs)

    def pack_propagate(self, flag: bool) -> None:
        # No-op: el Canvas no propaga tamaño a los hijos de la misma
        # manera que un Frame. Se mantiene por compatibilidad.
        pass

    def winfo_children(self) -> List[Any]:
        return list(self.inner.winfo_children())

    def configure(self, **kwargs: Any) -> None:
        if "bg" in kwargs:
            self._bg = kwargs["bg"]
            self.inner.configure(bg=self._bg)
            self._redraw()
        if "border_color" in kwargs:
            self._border_color = kwargs["border_color"]
            self._redraw()
        if "border_width" in kwargs:
            self._border_width = max(0, int(kwargs["border_width"]))
            self._redraw()
        if "radius" in kwargs:
            self._radius = max(0, int(kwargs["radius"]))
            self._redraw()

    # --- Redibujado ---

    def _on_canvas_configure(self, _event: Any) -> None:
        """Se ejecuta cuando el Canvas cambia de tamaño (por pack/grid)."""
        self._redraw()

    def _on_map(self, _event: Any) -> None:
        """Se ejecuta cuando el Canvas se mapea por primera vez.

        Fuerza el recálculo del tamaño basándose en el contenido del
        Frame interno. Esto es necesario porque antes del mapeo,
        ``winfo_reqwidth``/``winfo_reqheight`` pueden devolver valores
        incorrectos.
        """
        # Forzar el recálculo del layout.
        try:
            self.inner.update_idletasks()
            self.canvas.update_idletasks()
        except Exception:  # noqa: BLE001
            pass
        # Llamar a _on_inner_configure manualmente.
        self._on_inner_configure(None)

    def _on_inner_configure(self, _event: Any) -> None:
        """Se ejecuta cuando el Frame interno cambia su tamaño solicitado.

        Ajusta el tamaño del Canvas para que coincida con el contenido
        del Frame interno más el padding. Esto permite que ``pack``/``grid``
        propaguen el tamaño correcto hacia el contenedor padre.

        Solo se aplica cuando el Canvas ya está mapeado (visible en
        pantalla); antes de eso, ``winfo_reqwidth``/``winfo_reqheight``
        pueden devolver valores incorrectos (típicamente 1).
        """
        # Si el Canvas aún no está mapeado, no hacemos nada: el tamaño
        # se ajustará cuando se mapee (vía ``<Map>``).
        try:
            if not self.canvas.winfo_ismapped():
                return
        except Exception:  # noqa: BLE001
            return
        try:
            self.inner.update_idletasks()
            req_w = self.inner.winfo_reqwidth()
            req_h = self.inner.winfo_reqheight()
        except Exception:  # noqa: BLE001
            return
        # Si los valores solicitados son demasiado pequeños (típico antes
        # de que los hijos calculen su tamaño), no actualizamos.
        if req_w < 2 or req_h < 2:
            return
        # Tamaño total del Canvas = contenido + padding a ambos lados.
        canvas_w = req_w + 2 * self._padding
        canvas_h = req_h + 2 * self._padding
        # Solo actualizamos si el tamaño realmente cambió (evita bucles).
        try:
            cur_w = int(self.canvas.cget("width"))
            cur_h = int(self.canvas.cget("height"))
        except Exception:  # noqa: BLE001
            cur_w, cur_h = 0, 0
        if cur_w != canvas_w or cur_h != canvas_h:
            self.canvas.configure(width=canvas_w, height=canvas_h)

    def _redraw(self) -> None:
        self.canvas.delete("card")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w <= 1 or h <= 1:
            return

        # Sombra simulada: un rectángulo redondeado desplazado hacia
        # abajo-derecha, en color shadow_color, sin outline.
        if self._shadow and w > 4 and h > 4:
            _draw_rounded_rect(
                self.canvas,
                2, 2, w, h,
                radius=self._radius,
                fill=self._shadow_color,
                outline="",
                tags="card",
            )

        # Tarjeta principal.
        _draw_rounded_rect(
            self.canvas,
            0, 0, w - 2 if self._shadow else w,
            h - 2 if self._shadow else h,
            radius=self._radius,
            fill=self._bg,
            outline=self._border_color if self._border_width > 0 else "",
            width=self._border_width if self._border_width > 0 else 0,
            tags="card",
        )

        # Ajustar el tamaño del frame interior al área útil
        # (descontando padding y, si hay sombra, el desplazamiento).
        inner_w = max(1, w - 2 * self._padding - (2 if self._shadow else 0))
        inner_h = max(1, h - 2 * self._padding - (2 if self._shadow else 0))
        self.canvas.coords(self._inner_window, self._padding, self._padding)
        self.canvas.itemconfigure(
            self._inner_window, width=inner_w, height=inner_h,
        )


class RoundedButton:
    """
    Botón con esquinas redondeadas, efecto hover y efecto pressed.

    Sustituye a ``ttk.Button`` para conseguir un aspecto moderno. El
    texto se centra sobre un Canvas con esquinas redondeadas; al pasar
    el ratón por encima, el color de fondo se anima suavemente hacia
    ``hover_bg``; al pulsarlo, hacia ``pressed_bg``.

    Uso típico::

        btn = RoundedButton(parent, text="▶ Ejecutar",
                            command=self._on_execute,
                            bg=CONFIG.ui_button_accent_bg,
                            fg=CONFIG.ui_button_accent_fg,
                            hover_bg=CONFIG.ui_button_accent_hover_bg,
                            pressed_bg=CONFIG.ui_button_accent_pressed_bg,
                            radius=CONFIG.ui_corner_radius)
        btn.pack(side="left")

    Atributos públicos:
        canvas: Canvas subyacente (por si se necesita acceso directo).
    """

    def __init__(
        self,
        parent: Any,
        text: str = "",
        command: Optional[Callable[[], Any]] = None,
        bg: Optional[str] = None,
        fg: Optional[str] = None,
        hover_bg: Optional[str] = None,
        pressed_bg: Optional[str] = None,
        radius: Optional[int] = None,
        font: Optional[Tuple[str, int, str]] = None,
        padding_x: int = 14,
        padding_y: int = 6,
        disabled: bool = False,
        **kwargs: Any,
    ) -> None:
        self._bg = bg or CONFIG.ui_button_bg
        self._fg = fg or CONFIG.ui_button_fg
        self._hover_bg = hover_bg or CONFIG.ui_button_hover_bg
        self._pressed_bg = pressed_bg or CONFIG.ui_button_pressed_bg
        self._radius = CONFIG.ui_corner_radius if radius is None else max(0, int(radius))
        self._font = font or (CONFIG.ui_font_family, CONFIG.ui_font_size)
        self._command = command
        self._disabled = bool(disabled)
        self._padding_x = max(0, int(padding_x))
        self._padding_y = max(0, int(padding_y))
        self._anim_ms = CONFIG.ui_hover_animation_ms
        self._anim_after_id: Optional[str] = None
        self._current_color = self._bg

        self.canvas = Canvas(
            parent,
            bg=CONFIG.ui_bg_color,
            highlightthickness=0,
            borderwidth=0,
            cursor="hand2" if not self._disabled else "arrow",
        )
        self._text_id = self.canvas.create_text(
            0, 0,
            text=text,
            fill=self._fg,
            font=self._font,
            anchor="center",
        )
        self._rect_id: Optional[int] = None

        # Calcular el tamaño inicial del Canvas basándose en el texto.
        # Esto permite que ``pack``/``grid`` propaguen el tamaño correcto
        # desde el primer momento, sin esperar al evento ``<Configure>``.
        self._update_canvas_size()

        # Eventos.
        self.canvas.bind("<Configure>", self._on_configure)
        if not self._disabled:
            self.canvas.bind("<Enter>", self._on_enter)
            self.canvas.bind("<Leave>", self._on_leave)
            self.canvas.bind("<ButtonPress-1>", self._on_press)
            self.canvas.bind("<ButtonRelease-1>", self._on_release)
            # Atajo: Enter y Space disparan el comando cuando el botón
            # tiene foco.
            self.canvas.bind("<Return>", lambda _e: self._invoke())
            self.canvas.bind("<space>", lambda _e: self._invoke())
            # El Canvas puede recibir foco con Tab.
            self.canvas.bind("<FocusIn>", self._on_focus_in)
            self.canvas.bind("<FocusOut>", self._on_focus_out)

    # --- API compatible con widgets tkinter ---

    def pack(self, **kwargs: Any) -> None:
        self.canvas.pack(**kwargs)

    def grid(self, **kwargs: Any) -> None:
        self.canvas.grid(**kwargs)

    def place(self, **kwargs: Any) -> None:
        self.canvas.place(**kwargs)

    def focus_set(self) -> None:
        self.canvas.focus_set()

    def configure(self, **kwargs: Any) -> None:
        if "text" in kwargs:
            self.canvas.itemconfigure(self._text_id, text=kwargs["text"])
            self._update_canvas_size()
        if "state" in kwargs:
            self._disabled = (str(kwargs["state"]) == "disabled")
            if self._disabled:
                self.canvas.unbind("<Enter>")
                self.canvas.unbind("<Leave>")
                self.canvas.unbind("<ButtonPress-1>")
                self.canvas.unbind("<ButtonRelease-1>")
                self.canvas.unbind("<Return>")
                self.canvas.unbind("<space>")
                self.canvas.unbind("<FocusIn>")
                self.canvas.unbind("<FocusOut>")
                self.canvas.configure(cursor="arrow")
                self._animate_to(self._bg)
            else:
                self.canvas.bind("<Enter>", self._on_enter)
                self.canvas.bind("<Leave>", self._on_leave)
                self.canvas.bind("<ButtonPress-1>", self._on_press)
                self.canvas.bind("<ButtonRelease-1>", self._on_release)
                self.canvas.bind("<Return>", lambda _e: self._invoke())
                self.canvas.bind("<space>", lambda _e: self._invoke())
                self.canvas.bind("<FocusIn>", self._on_focus_in)
                self.canvas.bind("<FocusOut>", self._on_focus_out)
                self.canvas.configure(cursor="hand2")
        if "bg" in kwargs:
            self._bg = kwargs["bg"]
            self._animate_to(self._bg)
        if "fg" in kwargs:
            self._fg = kwargs["fg"]
            self.canvas.itemconfigure(self._text_id, fill=self._fg)

    # --- Redibujado ---

    def _on_configure(self, _event: Any) -> None:
        self._redraw()

    def _update_canvas_size(self) -> None:
        """Ajusta el tamaño del Canvas al texto + padding.

        Se llama al inicializar el botón y cada vez que cambia el texto,
        para que ``pack``/``grid`` propaguen el tamaño correcto.
        """
        try:
            self.canvas.update_idletasks()
            bbox = self.canvas.bbox(self._text_id)
        except Exception:  # noqa: BLE001
            bbox = None
        if bbox is None:
            # Fallback: usar un tamaño mínimo razonable.
            text_w, text_h = 60, 20
        else:
            text_w = bbox[2] - bbox[0]
            text_h = bbox[3] - bbox[1]
        canvas_w = text_w + 2 * self._padding_x
        canvas_h = text_h + 2 * self._padding_y
        try:
            self.canvas.configure(width=canvas_w, height=canvas_h)
        except Exception:  # noqa: BLE001
            pass

    def _redraw(self) -> None:
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w <= 1 or h <= 1:
            return
        # Centrar el texto.
        self.canvas.coords(self._text_id, w / 2, h / 2)
        # Redibujar el rectángulo redondeado con el color actual.
        if self._rect_id is not None:
            self.canvas.delete(self._rect_id)
        self._rect_id = _draw_rounded_rect(
            self.canvas,
            0, 0, w, h,
            radius=self._radius,
            fill=self._current_color,
            outline="",
        )
        # Asegurar que el texto queda por encima del rectángulo.
        self.canvas.tag_raise(self._text_id)

    # --- Eventos ---

    def _on_enter(self, _event: Any) -> None:
        if self._disabled:
            return
        self._animate_to(self._hover_bg)

    def _on_leave(self, _event: Any) -> None:
        if self._disabled:
            return
        self._animate_to(self._bg)

    def _on_press(self, _event: Any) -> None:
        if self._disabled:
            return
        self._animate_to(self._pressed_bg)

    def _on_release(self, event: Any) -> None:
        if self._disabled:
            return
        # Si el ratón sigue dentro del botón al soltar, mantenemos el
        # color hover; si no, volvemos al color base.
        x = self.canvas.canvasx(event.x)
        y = self.canvas.canvasy(event.y)
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if 0 <= x <= w and 0 <= y <= h:
            self._animate_to(self._hover_bg)
            self._invoke()
        else:
            self._animate_to(self._bg)

    def _on_focus_in(self, _event: Any) -> None:
        if self._disabled:
            return
        # Resaltar el foco con un borde sutil.
        self.canvas.itemconfigure(
            self._text_id, fill=self._fg,
        )

    def _on_focus_out(self, _event: Any) -> None:
        if self._disabled:
            return
        self.canvas.itemconfigure(self._text_id, fill=self._fg)

    def _invoke(self) -> None:
        if self._disabled or self._command is None:
            return
        try:
            self._command()
        except Exception as exc:  # noqa: BLE001
            print(f"[button] Error al ejecutar comando: {exc}")

    # --- Animación de color ---

    def _animate_to(self, target: str) -> None:
        """
        Anima el color de fondo desde ``self._current_color`` hasta
        ``target`` en ``self._anim_ms`` milisegundos.

        Si la animación está deshabilitada (``anim_ms == 0``) o el
        color ya coincide, simplemente repinta.
        """
        if self._anim_after_id is not None:
            try:
                self.canvas.after_cancel(self._anim_after_id)
            except Exception:  # noqa: BLE001
                pass
            self._anim_after_id = None

        if self._anim_ms <= 0 or self._current_color == target:
            self._current_color = target
            self._redraw()
            return

        # Animación en 6 pasos (~80 ms total por defecto).
        steps = 6
        delay = max(1, self._anim_ms // steps)
        start = self._current_color

        def _step(i: int) -> None:
            t = i / float(steps)
            self._current_color = _blend_colors(start, target, t)
            self._redraw()
            if i < steps:
                self._anim_after_id = self.canvas.after(delay, _step, i + 1)
            else:
                self._anim_after_id = None

        _step(1)


# ============================================================================
# BARRA DE TÍTULO PERSONALIZADA (overrideredirect + estilo moderno)
# ============================================================================

def _force_taskbar_visibility(window: Any) -> None:
    """
    Fuerza la ventana a aparecer en la barra de tareas de Windows.

    Las ventanas con ``overrideredirect(True)`` no aparecen en la
    barra de tareas por defecto. Para que sigan apareciendo (y
    puedan ser activadas con Alt+Tab), se añade el estilo extendido
    ``WS_EX_APPWINDOW`` mediante la API de Win32.

    En plataformas distintas de Windows, o si la API no está
    disponible, la función no hace nada.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes

        try:
            hwnd = int(window.frame(), 16)
        except Exception:
            try:
                hwnd = window.winfo_id()
            except Exception:
                return

        GWL_EXSTYLE = -20
        WS_EX_APPWINDOW = 0x00040000
        WS_EX_TOOLWINDOW = 0x00000080
        try:
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            GetWindowLongW = user32.GetWindowLongW
            GetWindowLongW.restype = wintypes.LONG
            GetWindowLongW.argtypes = [wintypes.HWND, wintypes.INT]
            SetWindowLongW = user32.SetWindowLongW
            SetWindowLongW.restype = wintypes.LONG
            SetWindowLongW.argtypes = [wintypes.HWND, wintypes.INT, wintypes.LONG]
            style = GetWindowLongW(hwnd, GWL_EXSTYLE)
            SetWindowLongW(
                hwnd, GWL_EXSTYLE, (style | WS_EX_APPWINDOW) & ~WS_EX_TOOLWINDOW
            )
        except Exception:
            pass
    except Exception:
        pass


def _win32_minimize(window: Any) -> bool:
    """Minimiza una ventana overrideredirect conservando su icono en la barra de tareas."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        window.update_idletasks()
        try:
            hwnd = int(window.frame(), 16)
        except Exception:
            hwnd = window.winfo_id()
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        SW_HIDE, SW_SHOWMINNOACTIVE = 0, 7
        # Ocultar antes de cambiar estilos para que el shell refresque la barra de tareas.
        user32.ShowWindow(hwnd, SW_HIDE)
        _force_taskbar_visibility(window)
        user32.ShowWindow(hwnd, SW_SHOWMINNOACTIVE)
        return True
    except Exception:
        return False


def _bring_to_front(window: Any, *, keep_on_top: bool = False) -> None:
    """Sube una ventana (incluida overrideredirect) al frente y le da foco."""
    try:
        window.update_idletasks()
        window.attributes("-topmost", True)
        window.lift()
        if not keep_on_top:
            window.focus_force()
        if not keep_on_top:
            # Se quita topmost tras mostrarse para no quedar sobre otras apps.
            window.after(
                300,
                lambda: window.winfo_exists() and window.attributes("-topmost", False),
            )
    except Exception:  # noqa: BLE001
        pass


def _is_minimized(window: Any) -> bool:
    """Indica si la ventana está minimizada (incluye ventanas overrideredirect)."""
    if sys.platform == "win32":
        try:
            import ctypes

            try:
                hwnd = int(window.frame(), 16)
            except Exception:  # noqa: BLE001
                hwnd = window.winfo_id()
            return bool(ctypes.WinDLL("user32").IsIconic(hwnd))
        except Exception:  # noqa: BLE001
            pass
    try:
        return window.state() == "iconic"
    except Exception:  # noqa: BLE001
        return False


class _TrayNotifier:
    """Icono temporal en la bandeja del sistema (Windows) con globo de aviso."""

    _UID = 0x4852
    _active_hwnd: Optional[int] = None

    @classmethod
    def _data(cls, hwnd: int, title: str = "", message: str = "") -> Any:
        import ctypes
        from ctypes import wintypes

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("hWnd", wintypes.HWND),
                ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT),
                ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128),
                ("dwState", wintypes.DWORD),
                ("dwStateMask", wintypes.DWORD),
                ("szInfo", wintypes.WCHAR * 256),
                ("uVersion", wintypes.UINT),
                ("szInfoTitle", wintypes.WCHAR * 64),
                ("dwInfoFlags", wintypes.DWORD),
                ("guidItem", ctypes.c_byte * 16),
                ("hBalloonIcon", wintypes.HICON),
            ]

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.LoadIconW.restype = wintypes.HICON
        user32.LoadIconW.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
        data = NOTIFYICONDATAW()
        data.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        data.hWnd = hwnd
        data.uID = cls._UID
        data.uFlags = 0x2 | 0x4 | 0x10  # NIF_ICON | NIF_TIP | NIF_INFO
        data.hIcon = user32.LoadIconW(None, 32515)  # IDI_WARNING
        data.szTip = "Hercules: autorización pendiente"
        data.szInfoTitle = title[:63]
        data.szInfo = message[:255]
        data.dwInfoFlags = 0x2  # NIIF_WARNING
        return data

    @classmethod
    def show(cls, window: Any, title: str, message: str) -> None:
        if sys.platform != "win32":
            return
        try:
            import ctypes

            window.update_idletasks()
            try:
                hwnd = int(window.frame(), 16)
            except Exception:  # noqa: BLE001
                hwnd = window.winfo_id()
            shell32 = ctypes.WinDLL("shell32", use_last_error=True)
            data = cls._data(hwnd, title, message)
            if cls._active_hwnd is None:
                shell32.Shell_NotifyIconW(0, ctypes.byref(data))  # NIM_ADD
                cls._active_hwnd = hwnd
            else:
                shell32.Shell_NotifyIconW(1, ctypes.byref(data))  # NIM_MODIFY
        except Exception:  # noqa: BLE001
            pass

    @classmethod
    def remove(cls) -> None:
        if sys.platform != "win32" or cls._active_hwnd is None:
            return
        try:
            import ctypes

            shell32 = ctypes.WinDLL("shell32", use_last_error=True)
            data = cls._data(cls._active_hwnd)
            shell32.Shell_NotifyIconW(2, ctypes.byref(data))  # NIM_DELETE
        except Exception:  # noqa: BLE001
            pass
        finally:
            cls._active_hwnd = None


class CustomTitleBar:
    """
    Barra de título personalizada con estilo moderno y minimalista.


    Reemplaza la barra de título nativa de Windows cuando la ventana
    usa ``overrideredirect(True)``. Incluye:

      - Icono y título de la aplicación a la izquierda.
      - Botones minimizar, maximizar/restaurar y cerrar a la derecha.
      - Arrastrar para mover la ventana.
      - Doble clic sobre el área de título para maximizar/restaurar.
      - Colores configurables desde ``config.ini``.
      - Efectos hover en los botones.

    Atributos:
        frame: Frame de tkinter que contiene la barra. Se debe
            empaquetar/gridar en la ventana padre.
    """

    DEFAULT_HEIGHT = 32

    def __init__(
        self,
        parent: Any,
        title: str = "",
        icon: str = "",
        bg: Optional[str] = None,
        fg: Optional[str] = None,
        hover_bg: Optional[str] = None,
        close_hover_bg: Optional[str] = None,
        height: Optional[int] = None,
        show_minimize: bool = True,
        show_maximize: bool = True,
        close_callback: Optional[Callable[[], None]] = None,
        settings_callback: Optional[Callable[[], None]] = None,
    ) -> None:
        self.parent = parent
        self._settings_callback = settings_callback
        self._title_text = title
        self._icon_text = icon
        self._bg = bg or CONFIG.ui_titlebar_color
        self._fg = fg or CONFIG.ui_titlebar_text_color
        self._hover_bg = hover_bg or CONFIG.ui_button_hover_bg
        self._close_hover_bg = close_hover_bg or CONFIG.ui_button_danger_bg
        self._height = height if height is not None else self.DEFAULT_HEIGHT
        self._close_callback = close_callback
        self._show_minimize = show_minimize
        self._show_maximize = show_maximize
        self._drag_data: Dict[str, int] = {"x": 0, "y": 0}
        self._is_maximized = False
        self._pre_maximize_geometry: Optional[str] = None
        self._resize_border = 7
        self._resize_direction: Optional[str] = None
        self._resize_start: Optional[Tuple[int, int, int, int, int, int]] = None
        self._resize_cursor_widget: Optional[Any] = None
        self._resize_cursor_original = ""
        self._resize_bindings: List[Tuple[str, str]] = []

        # Frame principal de la barra de título.
        self.frame = Frame(
            parent,
            bg=self._bg,
            height=self._height,
            highlightthickness=0,
            borderwidth=0,
        )
        # Evitar que el frame se encoja al empaquetar contenido.
        self.frame.pack_propagate(False)

        # --- Lado izquierdo: icono + título ---
        left = Frame(
            self.frame,
            bg=self._bg,
            highlightthickness=0,
            borderwidth=0,
        )
        left.pack(side="left", fill="both", expand=True)

        title_display = (
            f"{self._icon_text}  {self._title_text}"
            if self._icon_text
            else self._title_text
        )
        self._title_label = TkLabel(
            left,
            text=title_display,
            bg=self._bg,
            fg=self._fg,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size, "bold"),
            padx=12,
            pady=0,
            anchor="w",
        )
        self._title_label.pack(side="left", fill="y")

        # --- Lado derecho: botones de ventana ---
        right = Frame(
            self.frame,
            bg=self._bg,
            highlightthickness=0,
            borderwidth=0,
        )
        self._controls_frame = right
        right.pack(side="right", fill="y")

        if self._settings_callback is not None:
            self._settings_btn = self._create_title_button(
                right, "\u2699", self._settings_callback, is_close=False
            )
            self._settings_btn.pack(side="left", fill="y")

        if self._show_minimize:
            self._min_btn = self._create_title_button(
                right, "\u2014", self._on_minimize, is_close=False
            )
            self._min_btn.pack(side="left", fill="y")

        if self._show_maximize:
            self._max_btn = self._create_title_button(
                right, "\u25a1", self._on_toggle_maximize, is_close=False
            )
            self._max_btn.pack(side="left", fill="y")

        self._close_btn = self._create_title_button(
            right, "\u2715", self._on_close, is_close=True
        )
        self._close_btn.pack(side="left", fill="y")

        # --- Bindings de arrastre ---
        # El arrastre funciona sobre el frame, el área izquierda y la
        # etiqueta de título. Los botones tienen sus propios handlers
        # y consumen el evento para que no se inicie el arrastre.
        drag_widgets = [self.frame, left, self._title_label]
        for w in drag_widgets:
            w.bind("<Button-1>", self._on_drag_start)
            w.bind("<B1-Motion>", self._on_drag_motion)
            w.bind("<Double-Button-1>", self._on_double_click)

        # Bindings globales para detectar los bordes también sobre los
        # widgets hijos. La ventana sigue usando overrideredirect y conserva
        # la barra personalizada; solo se ajustan sus dimensiones y posición.
        for sequence, callback in (
            ("<Motion>", self._on_resize_hover),
            ("<Button-1>", self._on_resize_start),
            ("<B1-Motion>", self._on_resize_drag),
            ("<ButtonRelease-1>", self._on_resize_end),
        ):
            binding_id = self.parent.bind_all(sequence, callback, add="+")
            if binding_id:
                self._resize_bindings.append((sequence, binding_id))
        self.parent.bind("<Destroy>", self._on_resize_destroy, add="+")

    def _create_title_button(
        self,
        parent: Any,
        text: str,
        command: Callable[[], None],
        is_close: bool = False,
    ) -> TkLabel:
        """Crea un botón de la barra de título con efecto hover."""
        btn = TkLabel(
            parent,
            text=text,
            bg=self._bg,
            fg=self._fg,
            font=(CONFIG.ui_font_family, 10),
            width=4,
            cursor="hand2",
            padx=0,
            pady=0,
        )
        btn._normal_bg = self._bg
        btn._hover_bg = self._close_hover_bg if is_close else self._hover_bg
        btn._command = command
        btn.bind("<Enter>", lambda _e: btn.configure(bg=btn._hover_bg))
        btn.bind("<Leave>", lambda _e: btn.configure(bg=btn._normal_bg))
        # Usamos Button-1 con return "break" para que no se propague
        # al frame y no inicie un arrastre.
        btn.bind("<Button-1>", lambda _e: (command(), "break")[1])
        return btn

    # --- Handlers de botones ---

    def _on_minimize(self) -> None:
        """Minimiza la ventana a la barra de tareas."""
        if _win32_minimize(self.parent):
            return
        # Fallback: desactivar overrideredirect temporalmente y restaurarlo en <Map>.
        try:
            self.parent.update_idletasks()
            self.parent.overrideredirect(False)
            self.parent.iconify()
            self._restore_bind = self.parent.bind("<Map>", self._on_restore_from_minimize, add="+")
        except Exception:
            pass

    def _on_restore_from_minimize(self, event: Any) -> None:
        """Reaplica el modo sin bordes al restaurar la ventana minimizada."""
        if event.widget is not self.parent:
            return
        try:
            self.parent.unbind("<Map>")
            self.parent.overrideredirect(True)
            _force_taskbar_visibility(self.parent)
            _bring_to_front(self.parent)
        except Exception:
            pass

    def _on_toggle_maximize(self) -> None:
        """Alterna entre maximizado y tamaño normal."""
        try:
            # La app puede arrancar ya maximizada, así que se consulta el estado real.
            maximized = self._is_maximized or self.parent.state() == "zoomed"
            if maximized:
                self.parent.state("normal")
                self.parent.update_idletasks()
                sw = self.parent.winfo_screenwidth()
                sh = self.parent.winfo_screenheight()
                geo = self._pre_maximize_geometry
                if not geo or geo.startswith(f"{sw}x{sh}"):
                    w, h = int(sw * 0.7), int(sh * 0.7)
                    geo = f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}"
                self.parent.geometry(geo)
                self._is_maximized = False
            else:
                self._pre_maximize_geometry = self.parent.geometry()
                self.parent.state("zoomed")
                self._is_maximized = True
        except Exception:
            pass

    def _on_close(self) -> None:
        """Cierra la ventana (o llama al callback personalizado)."""
        if self._close_callback is not None:
            try:
                self._close_callback()
            except Exception:
                pass
        else:
            try:
                self.parent.destroy()
            except Exception:
                pass

    # --- Handlers de arrastre ---

    def _on_drag_start(self, event: Any) -> None:
        """Inicia el arrastre de la ventana."""
        self._drag_data["x"] = event.x_root
        self._drag_data["y"] = event.y_root

    def _on_drag_motion(self, event: Any) -> None:
        """Mueve la ventana siguiendo el cursor."""
        if self._resize_direction is not None:
            return
        # Si está maximizada, restaurar al tamaño previo antes de mover.
        if self._is_maximized:
            # Restaurar a un tamaño razonable proporcional a la posición.
            try:
                self.parent.state("normal")
                self._is_maximized = False
                # Reposicionar la ventana para que el cursor quede sobre
                # la barra de título (estilo Windows 11).
                sw = self.parent.winfo_screenwidth()
                ratio = max(0.3, min(0.7, event.x_root / max(1, sw)))
                new_w = max(800, int(sw * 0.7))
                new_h = max(500, int(self.parent.winfo_screenheight() * 0.7))
                x = max(0, event.x_root - int(new_w * ratio))
                y = max(0, event.y_root - 16)
                self.parent.geometry(f"{new_w}x{new_h}+{x}+{y}")
                self._drag_data["x"] = event.x_root
                self._drag_data["y"] = event.y_root
                return
            except Exception:
                return

        try:
            x = self.parent.winfo_x() + (event.x_root - self._drag_data["x"])
            y = self.parent.winfo_y() + (event.y_root - self._drag_data["y"])
            self.parent.geometry(f"+{x}+{y}")
            self._drag_data["x"] = event.x_root
            self._drag_data["y"] = event.y_root
        except Exception:
            pass

    def _window_edges(self, x_root: int, y_root: int) -> str:
        """Devuelve los bordes/corner bajo el puntero, si son redimensionables."""
        if self._is_maximized:
            return ""
        try:
            if self.parent.state() == "zoomed":
                return ""
            left = self.parent.winfo_rootx()
            top = self.parent.winfo_rooty()
            right = left + self.parent.winfo_width()
            bottom = top + self.parent.winfo_height()
            border = self._resize_border
            if not (left <= x_root < right and top <= y_root < bottom):
                return ""
            horizontal = "w" if x_root < left + border else (
                "e" if x_root >= right - border else ""
            )
            vertical = "n" if y_root < top + border else (
                "s" if y_root >= bottom - border else ""
            )
            return vertical + horizontal
        except Exception:
            return ""

    def _is_in_title_controls(self, widget: Any) -> bool:
        """Evita interceptar los clics de minimizar/maximizar/cerrar."""
        current = widget
        while current is not None:
            if current is self._controls_frame:
                return True
            current = getattr(current, "master", None)
        return False

    def _set_resize_cursor(self, widget: Any, direction: str) -> None:
        cursors = {
            "n": "size_ns", "s": "size_ns", "e": "size_we", "w": "size_we",
            "ne": "size_ne_sw", "sw": "size_ne_sw",
            "nw": "size_nw_se", "se": "size_nw_se",
        }
        if widget is self._resize_cursor_widget:
            return
        self._restore_resize_cursor()
        try:
            self._resize_cursor_original = widget.cget("cursor")
            widget.configure(cursor=cursors[direction])
            self._resize_cursor_widget = widget
        except Exception:
            self._resize_cursor_widget = None

    def _restore_resize_cursor(self) -> None:
        if self._resize_cursor_widget is not None:
            try:
                self._resize_cursor_widget.configure(cursor=self._resize_cursor_original)
            except Exception:
                pass
            self._resize_cursor_widget = None

    def _on_resize_hover(self, event: Any) -> None:
        if not self._belongs_to_window(event.widget):
            self._restore_resize_cursor()
            return
        direction = self._window_edges(event.x_root, event.y_root)
        if direction and not self._is_in_title_controls(event.widget):
            self._set_resize_cursor(event.widget, direction)
        else:
            self._restore_resize_cursor()

    def _belongs_to_window(self, widget: Any) -> bool:
        current = widget
        while current is not None:
            if current is self.parent:
                return True
            current = getattr(current, "master", None)
        return False

    def _on_resize_start(self, event: Any) -> None:
        if not self._belongs_to_window(event.widget) or self._is_in_title_controls(event.widget):
            return
        direction = self._window_edges(event.x_root, event.y_root)
        if not direction:
            return
        try:
            self.parent.update_idletasks()
            self._resize_direction = direction
            self._resize_start = (
                event.x_root, event.y_root,
                self.parent.winfo_x(), self.parent.winfo_y(),
                self.parent.winfo_width(), self.parent.winfo_height(),
            )
        except Exception:
            self._resize_direction = None
            self._resize_start = None

    def _on_resize_drag(self, event: Any) -> None:
        if self._resize_direction is None or self._resize_start is None:
            return
        start_x, start_y, x, y, width, height = self._resize_start
        dx, dy = event.x_root - start_x, event.y_root - start_y
        try:
            min_width, min_height = self.parent.minsize()
            min_width, min_height = int(min_width), int(min_height)
        except Exception:
            min_width, min_height = 1, 1

        direction = self._resize_direction
        new_width, new_height = width, height
        new_x, new_y = x, y
        if "e" in direction:
            new_width = max(min_width, width + dx)
        elif "w" in direction:
            new_width = max(min_width, width - dx)
            new_x = x + width - new_width
        if "s" in direction:
            new_height = max(min_height, height + dy)
        elif "n" in direction:
            new_height = max(min_height, height - dy)
            new_y = y + height - new_height
        try:
            self.parent.geometry(f"{new_width}x{new_height}{new_x:+d}{new_y:+d}")
        except Exception:
            pass

    def _on_resize_end(self, _event: Any) -> None:
        self._resize_direction = None
        self._resize_start = None

    def _on_resize_destroy(self, event: Any) -> None:
        if event.widget is not self.parent:
            return
        self._restore_resize_cursor()
        root = self.parent._root()
        for sequence, binding_id in self._resize_bindings:
            try:
                root._unbind(("bind", "all", sequence), binding_id)
            except Exception:
                pass
        self._resize_bindings.clear()

    def _on_double_click(self, _event: Any) -> None:
        """Maximiza/restaurar al hacer doble clic sobre el título."""
        if self._show_maximize:
            self._on_toggle_maximize()

    # --- Helpers de empaquetado ---

    def pack(self, **kwargs: Any) -> None:
        """Empaqueta el frame de la barra de título."""
        self.frame.pack(**kwargs)

    def grid(self, **kwargs: Any) -> None:
        """Posiciona el frame de la barra de título con grid."""
        self.frame.grid(**kwargs)

    def set_title(self, title: str) -> None:
        """Actualiza el texto del título."""
        self._title_text = title
        display = (
            f"{self._icon_text}  {title}" if self._icon_text else title
        )
        try:
            self._title_label.configure(text=display)
        except Exception:
            pass


class GradientCanvas(Canvas):
    """
    Canvas con fondo en degradado vertical entre dos colores.

    Se usa para barras de progreso, cabeceras y otros elementos que
    quieran un aspecto más "moderno". El degradado se redibuja
    automáticamente al cambiar el tamaño del widget.
    """

    def __init__(
        self,
        parent: Any,
        color_top: str,
        color_bottom: str,
        radius: int = 0,
        corner_bg: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        # Quitar ``bg`` de kwargs si está presente para evitar conflicto.
        kwargs.pop("bg", None)
        kwargs.pop("highlightthickness", None)
        super().__init__(
            parent,
            highlightthickness=0,
            borderwidth=0,
            bg=corner_bg or CONFIG.ui_bg_color,
            **kwargs,
        )
        self._color_top = color_top
        self._color_bottom = color_bottom
        self._radius = max(0, int(radius))
        self._corner_bg = corner_bg or CONFIG.ui_bg_color
        self.bind("<Configure>", self._on_configure)

    def _on_configure(self, _event: Any) -> None:
        self._redraw()

    def set_colors(self, color_top: str, color_bottom: str) -> None:
        self._color_top = color_top
        self._color_bottom = color_bottom
        self._redraw()

    def _redraw(self) -> None:
        self.delete("gradient")
        w = self.winfo_width()
        h = self.winfo_height()
        if w <= 1 or h <= 1:
            return
        # Degradado vertical: una banda por cada píxel de alto.
        # Para widgets pequeños (<200 px) es perfectamente fluido.
        if h <= 256:
            for y in range(h):
                t = y / max(1, h - 1)
                color = _blend_colors(self._color_top, self._color_bottom, t)
                self.create_line(
                    0, y, w, y,
                    fill=color, tags="gradient",
                )
        else:
            # Para alturas grandes, usa bandas de 4 px (más eficiente).
            band = 4
            for y in range(0, h, band):
                t = y / max(1, h - 1)
                color = _blend_colors(self._color_top, self._color_bottom, t)
                self.create_rectangle(
                    0, y, w, min(y + band, h),
                    fill=color, outline=color, tags="gradient",
                )
        # Si hay radio, recortar las esquinas redondeadas pintando
        # el color de fondo del padre en las cuatro esquinas.
        if self._radius > 0:
            r = self._radius
            bg = self._corner_bg
            # Esquina superior izquierda.
            self.create_arc(
                0, 0, 2 * r, 2 * r,
                start=90, extent=90, style="pieslice",
                fill=bg, outline=bg, tags="gradient",
            )
            # Esquina superior derecha.
            self.create_arc(
                w - 2 * r, 0, w, 2 * r,
                start=0, extent=90, style="pieslice",
                fill=bg, outline=bg, tags="gradient",
            )
            # Esquina inferior izquierda.
            self.create_arc(
                0, h - 2 * r, 2 * r, h,
                start=180, extent=90, style="pieslice",
                fill=bg, outline=bg, tags="gradient",
            )
            # Esquina inferior derecha.
            self.create_arc(
                w - 2 * r, h - 2 * r, w, h,
                start=270, extent=90, style="pieslice",
                fill=bg, outline=bg, tags="gradient",
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
    EventType.CONTEXT_OVERFLOW.value: "⚠ Desbordamiento de contexto",
    EventType.SUBTASK_CREATED.value: "➕ Subtarea creada",
    EventType.SUBTASK_STARTED.value: "▶ Subtarea iniciada",
    EventType.SUBTASK_COMPLETED.value: "✔ Subtarea completada",
    EventType.SUBTASK_FAILED.value: "✘ Subtarea fallida",
    EventType.ORCHESTRATION_DECISION.value: "🎼 Decisión de orquestación",
    EventType.PREAUTHORIZATION_REQUEST.value: "🤖 Consulta de preautorización",
    EventType.PREAUTHORIZATION_GRANTED.value: "🤖 Preautorizado por LLM",
    EventType.PREAUTHORIZATION_DENIED.value: "🤖 LLM denegó preautorización",
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

    if tool_name in {"create_file", "write_file"}:
        path = args.get("path", "")
        content = args.get("content", "")
        preview = content if len(content) <= 500 else content[:500] + "\n... [contenido truncado, total: {} caracteres]".format(len(content))
        lines.append(f"📄 Archivo a escribir: {path}")
        lines.append(f"📏 Tamaño: {len(content)} caracteres")
        lines.append("")
        lines.append("── Vista previa del contenido ──")
        lines.append(preview)
    elif tool_name == "edit_file":
        path = args.get("path", "")
        old_text = args.get("old_text", "")
        new_text = args.get("new_text", "")
        lines.append(f"📝 Archivo a editar: {path}")
        lines.append(f"🔎 Texto a reemplazar: {old_text[:500]}")
        lines.append(f"✏️ Texto nuevo: {new_text[:500]}")
    elif tool_name == "execute_command":
        cmd = args.get("command", "")
        lines.append("💻 Comando a ejecutar:")
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
        self.root.title(f"Hercules {VERSION}")
        self.root.geometry("1920x1080")
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
        # Mientras sea True, historial y barra siguen a la última tarea en
        # progreso; pulsar "Ver" lo desactiva y crear una tarea lo reactiva.
        self._follow_active_task = True
        self._active_task_cancel_event: Optional[threading.Event] = None
        self._active_task_thread: Optional[threading.Thread] = None
        # Variable de la casilla "Preautorizar" de la barra superior.
        # Se inicializa aquí (antes de _build_layout) porque el checkbox
        # se construye dentro del layout y necesita esta variable.
        self.preauth_var = BooleanVar(value=False)
        self._build_styles()
        self._build_layout()
        # --- Spinner animado para tareas IN_PROGRESS ---
        # Frames del spinner en orden de rotación.
        self._spinner_frames = ("-", "\\","|","/")
        self._spinner_counter = 0
        # Mapa task_id -> Label del spinner. Se rellena en
        # _render_task_row y se vacía en _refresh_task_lists.
        self._spinner_labels: Dict[int, ttk.Label] = {}
        self._refresh_task_lists()
        self._poll_queue()
        self._tick_spinner()

    def _apply_ui_config(self) -> None:
        """Aplica colores, fuente, transparencia y modo fullscreen desde la configuración."""
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
        # Barra de título personalizada (overrideredirect). Se aplica
        # ANTES del fullscreen para que la ventana ya sea borderless
        # cuando se maximiza. Solo si está habilitada en config.ini.
        if CONFIG.ui_custom_titlebar:
            try:
                self.root.overrideredirect(True)
            except Exception:  # noqa: BLE001
                pass
            # Forzar que la ventana aparezca en la barra de tareas de
            # Windows (overrideredirect la oculta por defecto).
            try:
                _force_taskbar_visibility(self.root)
            except Exception:  # noqa: BLE001
                pass
        # Fullscreen si está habilitado en config.ini.
        if CONFIG.ui_fullscreen:
            try:
                self.root.state("zoomed")
            except Exception:  # noqa: BLE001
                self.root.attributes("-fullscreen", True)
        # Transparencia de la ventana (0.5 - 1.0). Solo funciona en
        # plataformas que soporten el atributo "-alpha" (Windows, macOS,
        # algunos X11). Si falla, se ignora silenciosamente.
        try:
            alpha = float(CONFIG.ui_window_alpha)
            if 0.5 <= alpha <= 1.0:
                self.root.attributes("-alpha", alpha)
        except Exception:  # noqa: BLE001
            pass
        # Barra de título moderna (modo oscuro / color personalizado).
        # Solo funciona en Windows 10/11 vía DWM. En otras plataformas
        # o si la API no está disponible, se ignora silenciosamente.
        # Si se usa la barra personalizada (overrideredirect), esta
        # llamada es un no-op porque no hay barra nativa.
        try:
            _apply_modern_titlebar(self.root)
        except Exception:  # noqa: BLE001
            pass

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
            bordercolor=CONFIG.ui_browser_border,
            lightcolor=CONFIG.ui_browser_border,
            darkcolor=CONFIG.ui_browser_border,
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
            bordercolor=CONFIG.ui_browser_border,
            lightcolor=CONFIG.ui_browser_header_bg,
            darkcolor=CONFIG.ui_browser_header_bg,
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
            foreground=CONFIG.ui_accent_color,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size + 2, "bold"),
        )
        style.configure(
            "Header.TLabel",
            background=CONFIG.ui_card_bg,
            foreground=CONFIG.ui_accent_color,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size + 1, "bold"),
        )
        style.configure("Status.PENDING.TLabel", foreground=EVENT_STATUS_COLORS[TaskStatus.PENDING.value])
        style.configure("Status.IN_PROGRESS.TLabel", foreground=EVENT_STATUS_COLORS[TaskStatus.IN_PROGRESS.value])
        style.configure("Status.AWAITING_APPROVAL.TLabel", foreground=EVENT_STATUS_COLORS[TaskStatus.AWAITING_APPROVAL.value])
        style.configure("Status.COMPLETED.TLabel", foreground=EVENT_STATUS_COLORS[TaskStatus.COMPLETED.value])
        style.configure("Status.FAILED.TLabel", foreground=EVENT_STATUS_COLORS[TaskStatus.FAILED.value])
        style.configure("Status.CANCELLED.TLabel", foreground=EVENT_STATUS_COLORS[TaskStatus.CANCELLED.value])
        # Estilo base de todos los botones (los específicos heredan de aquí).
        # Se mantienen los estilos ttk originales para compatibilidad con
        # widgets que aún no se hayan migrado a RoundedButton.
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
                ("active", CONFIG.ui_button_hover_bg),
                ("disabled", CONFIG.ui_card_bg),
            ],
            foreground=[
                ("disabled", CONFIG.ui_status_cancelled),
            ],
        )
        style.configure(
            "Execute.TButton",
            background=CONFIG.ui_button_accent_bg,
            foreground=CONFIG.ui_button_accent_fg,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size, "bold"),
            borderwidth=0,
        )
        style.map(
            "Execute.TButton",
            background=[
                ("active", CONFIG.ui_button_accent_hover_bg),
                ("disabled", CONFIG.ui_card_bg),
            ],
        )
        style.configure(
            "Allow.TButton",
            background=CONFIG.ui_status_completed,
            foreground="#ffffff",
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size, "bold"),
            borderwidth=0,
        )
        style.map(
            "Allow.TButton",
            background=[
                ("active", CONFIG.ui_button_hover_bg),
                ("disabled", CONFIG.ui_card_bg),
            ],
        )
        style.configure(
            "Deny.TButton",
            background=CONFIG.ui_button_danger_bg,
            foreground=CONFIG.ui_button_danger_fg,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size, "bold"),
            borderwidth=0,
        )
        style.map(
            "Deny.TButton",
            background=[
                ("active", CONFIG.ui_button_danger_hover_bg),
                ("disabled", CONFIG.ui_card_bg),
            ],
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
        # Barras de desplazamiento (vertical y horizontal).
        style.configure(
            "TScrollbar",
            background=CONFIG.ui_scrollbar_thumb,
            troughcolor=CONFIG.ui_scrollbar_trough,
            bordercolor=CONFIG.ui_scrollbar_trough,
            lightcolor=CONFIG.ui_scrollbar_thumb,
            darkcolor=CONFIG.ui_scrollbar_thumb,
            arrowcolor=CONFIG.ui_scrollbar_arrow,
            relief="flat",
            borderwidth=0,
            arrowsize=12,
        )
        style.map(
            "TScrollbar",
            background=[
                ("pressed", CONFIG.ui_scrollbar_thumb_hover),
                ("active", CONFIG.ui_scrollbar_thumb_hover),
            ],
            lightcolor=[
                ("pressed", CONFIG.ui_scrollbar_thumb_hover),
                ("active", CONFIG.ui_scrollbar_thumb_hover),
            ],
            darkcolor=[
                ("pressed", CONFIG.ui_scrollbar_thumb_hover),
                ("active", CONFIG.ui_scrollbar_thumb_hover),
            ],
        )
        # Pestañas de tareas (Notebook).
        style.configure(
            "TNotebook",
            background=CONFIG.ui_card_bg,
            bordercolor=CONFIG.ui_card_bg,
            lightcolor=CONFIG.ui_card_bg,
            darkcolor=CONFIG.ui_card_bg,
            borderwidth=0,
            tabmargins=(0, 0, 0, 0),
        )
        style.configure(
            "TNotebook.Tab",
            background=CONFIG.ui_tab_bg,
            foreground=CONFIG.ui_tab_fg,
            bordercolor=CONFIG.ui_card_bg,
            lightcolor=CONFIG.ui_tab_bg,
            darkcolor=CONFIG.ui_tab_bg,
            focuscolor=CONFIG.ui_tab_bg,
            padding=(14, 6),
            borderwidth=0,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size),
        )
        style.map(
            "TNotebook.Tab",
            background=[
                ("selected", CONFIG.ui_tab_selected_bg),
                ("active", CONFIG.ui_tab_hover_bg),
            ],
            foreground=[
                ("selected", CONFIG.ui_tab_selected_fg),
                ("active", CONFIG.ui_fg_color),
            ],
            lightcolor=[("selected", CONFIG.ui_accent_color)],
            bordercolor=[("selected", CONFIG.ui_card_bg)],
            focuscolor=[("selected", CONFIG.ui_tab_selected_bg)],
            expand=[("selected", (0, 0, 0, 0))],
        )
        style.configure("TSeparator", background=CONFIG.ui_separator_color)
        # Campos de entrada y listas desplegables (diálogo de ajustes).
        for _name in ("TEntry", "TCombobox"):
            style.configure(
                _name,
                fieldbackground=CONFIG.ui_prompt_bg,
                background=CONFIG.ui_button_bg,
                foreground=CONFIG.ui_prompt_fg,
                insertcolor=CONFIG.ui_prompt_fg,
                bordercolor=CONFIG.ui_card_border_color,
                lightcolor=CONFIG.ui_card_border_color,
                darkcolor=CONFIG.ui_card_border_color,
                arrowcolor=CONFIG.ui_scrollbar_arrow,
                selectbackground=CONFIG.ui_browser_selected_bg,
                selectforeground=CONFIG.ui_browser_selected_fg,
                padding=4,
            )
            style.map(
                _name,
                bordercolor=[("focus", CONFIG.ui_accent_color)],
                lightcolor=[("focus", CONFIG.ui_accent_color)],
                darkcolor=[("focus", CONFIG.ui_accent_color)],
                fieldbackground=[("readonly", CONFIG.ui_prompt_bg)],
                foreground=[("readonly", CONFIG.ui_prompt_fg)],
                selectbackground=[("readonly", CONFIG.ui_prompt_bg)],
                selectforeground=[("readonly", CONFIG.ui_prompt_fg)],
            )
        # Lista desplegable de los Combobox (es un Listbox clásico de Tk).
        self.root.option_add("*TCombobox*Listbox.background", CONFIG.ui_prompt_bg)
        self.root.option_add("*TCombobox*Listbox.foreground", CONFIG.ui_prompt_fg)
        self.root.option_add("*TCombobox*Listbox.selectBackground", CONFIG.ui_browser_selected_bg)
        self.root.option_add("*TCombobox*Listbox.selectForeground", CONFIG.ui_browser_selected_fg)
        style.configure(
            "Muted.TLabel",
            background=CONFIG.ui_card_bg,
            foreground=CONFIG.ui_tab_fg,
            font=(CONFIG.ui_font_family, max(8, CONFIG.ui_font_size - 1)),
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
        # Distribución vertical del dashboard (nuevo diseño):
        #
        #   ┌──────────────────────────────────────────────┐
        #   │  Prompt + Ejecutar     │  Explorador         │  ← mitad y mitad
        #   ├──────────────────────────────────────────────┤
        #   │                                              │
        #   │  Zona 2 (PROMINENTE):                        │
        #   │  ┌────────────────┬────────────────────────┐ │
        #   │  │                │  [Tarea en curso]      │ │
        #   │  │   Historial    │  [Tareas terminadas]   │ │
        #   │  │   (izquierda)  │  (derecha, tabs)       │ │
        #   │  │                │                        │ │
        #   │  └────────────────┴────────────────────────┘ │
        #   │                                              │
        #   ├──────────────────────────────────────────────┤
        #   │  Barra de contexto       │  Info modelo/WS   │  ← mitad y mitad
        #   └──────────────────────────────────────────────┘
        #
        # Las solicitudes de aprobación (HITL) se muestran ahora como
        # POPUP modal (Toplevel) en lugar de un panel inline, para dar
        # más protagonismo al historial y a las tareas.
        #
        # Los marcos principales usan RoundedFrame (esquinas redondeadas,
        # borde sutil y sombra simulada) para conseguir un aspecto moderno.
        # Los botones usan RoundedButton con efectos hover/pressed animados.
        # ------------------------------------------------------------------

        # Barra de título personalizada (overrideredirect). Solo se crea
        # si está habilitada en config.ini. Se empaqueta en la parte
        # superior, antes del resto de zonas, para que ocupe siempre la
        # primera fila del layout.
        if CONFIG.ui_custom_titlebar:
            self.title_bar = CustomTitleBar(
                self.root,
                title="Hercules",
                icon="\u2694",  # ⚔
                bg=CONFIG.ui_titlebar_color,
                fg=CONFIG.ui_titlebar_text_color,
                hover_bg=CONFIG.ui_button_hover_bg,
                close_hover_bg=CONFIG.ui_button_danger_bg,
                height=CONFIG.ui_custom_titlebar_height,
                show_minimize=True,
                show_maximize=True,
                close_callback=self.root.destroy,
                settings_callback=self._open_settings,
            )
            self.title_bar.pack(side="top", fill="x")

        # Fila superior: prompt y explorador comparten el ancho disponible.
        top = ttk.Frame(self.root, style="TFrame", padding=(10, 8, 10, 4))
        top.pack(side="top", fill="x")
        top.columnconfigure(0, weight=1, uniform="top_panels")
        top.columnconfigure(1, weight=1, uniform="top_panels")
        top.rowconfigure(0, weight=1)
        prompt_container = ttk.Frame(top, style="TFrame")
        prompt_container.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        browser_container = ttk.Frame(top, style="TFrame")
        browser_container.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        browser_container.pack_propagate(False)
        browser_container.configure(height=210)

        # Sin barra de título personalizada, el botón de ajustes va en la esquina superior derecha.
        if not CONFIG.ui_custom_titlebar:
            ttk.Button(
                prompt_container, text="\u2699", width=3, command=self._open_settings
            ).place(relx=1.0, x=0, y=0, anchor="ne")

        ttk.Label(prompt_container, text="📝 Nueva instrucción para el agente", style="Title.TLabel").pack(
            anchor="w"
        )

        # Caja del prompt con esquinas redondeadas.
        prompt_card = RoundedFrame(
            prompt_container,
            bg=CONFIG.ui_prompt_bg,
            border_color=CONFIG.ui_card_border_color,
            border_width=CONFIG.ui_card_border_width,
            radius=CONFIG.ui_corner_radius,
            padding=2,
        )
        prompt_card.pack(fill="x", pady=(6, 6))
        self.prompt_text = Text(
            prompt_card.inner,
            height=4,
            wrap="word",
            font=(CONFIG.ui_mono_font_family, CONFIG.ui_mono_font_size),
            relief="flat",
            borderwidth=0,
            background=CONFIG.ui_prompt_bg,
            foreground=CONFIG.ui_prompt_fg,
            insertbackground=CONFIG.ui_prompt_fg,
            selectbackground=CONFIG.ui_browser_selected_bg,
            highlightthickness=0,
            padx=8,
            pady=6,
        )
        self.prompt_text.pack(fill="both", expand=True)
        # Las ventanas overrideredirect no reciben foco de teclado del WM.
        self.prompt_text.bind("<Button-1>", lambda _e: self.prompt_text.focus_force())
        self.root.after(300, self.prompt_text.focus_force)

        btn_row = ttk.Frame(prompt_container, style="TFrame")
        btn_row.pack(fill="x")
        # Botón principal "Ejecutar" con color de acento.
        self.execute_button = RoundedButton(
            btn_row,
            text="▶ Ejecutar",
            command=self._on_execute,
            bg=CONFIG.ui_button_accent_bg,
            fg=CONFIG.ui_button_accent_fg,
            hover_bg=CONFIG.ui_button_accent_hover_bg,
            pressed_bg=CONFIG.ui_button_accent_pressed_bg,
            radius=CONFIG.ui_corner_radius,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size, "bold"),
            padding_x=18,
            padding_y=8,
        )
        self.execute_button.pack(side="left")
        self.abort_button = RoundedButton(
            btn_row,
            text="⏹ Abortar tareas",
            command=self._on_abort,
            bg=CONFIG.ui_button_danger_bg,
            fg=CONFIG.ui_button_danger_fg,
            hover_bg=CONFIG.ui_button_danger_hover_bg,
            pressed_bg=CONFIG.ui_button_danger_bg,
            radius=CONFIG.ui_corner_radius,
            padding_x=14,
            padding_y=6,
            disabled=True,
        )
        self.abort_button.pack(side="left", padx=(8, 0))
        RoundedButton(
            btn_row,
            text="🧹 Limpiar",
            command=self._on_clear_prompt,
            bg=CONFIG.ui_button_bg,
            fg=CONFIG.ui_button_fg,
            hover_bg=CONFIG.ui_button_hover_bg,
            pressed_bg=CONFIG.ui_button_pressed_bg,
            radius=CONFIG.ui_corner_radius,
            padding_x=14,
            padding_y=6,
        ).pack(side="left", padx=(8, 0))
        RoundedButton(
            btn_row,
            text="🗑 Borrar tareas terminadas",
            command=self._on_delete_finished_tasks,
            bg=CONFIG.ui_button_bg,
            fg=CONFIG.ui_button_fg,
            hover_bg=CONFIG.ui_button_hover_bg,
            pressed_bg=CONFIG.ui_button_pressed_bg,
            radius=CONFIG.ui_corner_radius,
            padding_x=14,
            padding_y=6,
        ).pack(side="left", padx=(8, 0))
        # Casilla global de preautorización: cuando está marcada, todas
        # las solicitudes se consultan primero con el LLM y solo las que
        # el modelo deniega se muestran al usuario como popup.
        ttk.Checkbutton(
            btn_row,
            text="🤖 Preautorizar",
            variable=self.preauth_var,
            style="Card.TCheckbutton",
        ).pack(side="left", padx=(8, 0))

        # Explorador de ficheros: ocupa la mitad derecha de la fila superior.
        browser_panel = RoundedFrame(
            browser_container,
            bg=CONFIG.ui_card_bg,
            border_color=CONFIG.ui_card_border_color,
            border_width=CONFIG.ui_card_border_width,
            radius=CONFIG.ui_corner_radius,
            padding=8,
        )
        browser_panel.pack(fill="both", expand=True)

        browser_header = ttk.Frame(browser_panel.inner, style="Card.TFrame")
        browser_header.pack(fill="x")
        self.browser_title_var = StringVar(value=f"📁 Explorador: {WORKSPACE_DIR}")
        ttk.Label(
            browser_header,
            textvariable=self.browser_title_var,
            style="Header.TLabel",
        ).pack(side="left")
        browser_btns = ttk.Frame(browser_header, style="Card.TFrame")
        browser_btns.pack(side="right")
        RoundedButton(
            browser_btns,
            text="⬆ Padre",
            command=self._on_browser_up,
            bg=CONFIG.ui_button_bg,
            fg=CONFIG.ui_button_fg,
            hover_bg=CONFIG.ui_button_hover_bg,
            pressed_bg=CONFIG.ui_button_pressed_bg,
            radius=CONFIG.ui_corner_radius,
            padding_x=12,
            padding_y=4,
        ).pack(side="left")
        RoundedButton(
            browser_btns,
            text="🔄 Refrescar",
            command=self._refresh_file_browser,
            bg=CONFIG.ui_button_bg,
            fg=CONFIG.ui_button_fg,
            hover_bg=CONFIG.ui_button_hover_bg,
            pressed_bg=CONFIG.ui_button_pressed_bg,
            radius=CONFIG.ui_corner_radius,
            padding_x=12,
            padding_y=4,
        ).pack(side="left", padx=(4, 0))

        # Ruta actual del explorador (relativa al workspace).
        self._browser_current_dir: Path = WORKSPACE_DIR
        browser_body = ttk.Frame(browser_panel.inner, style="Card.TFrame")
        browser_body.pack(fill="both", expand=True, pady=(4, 0))

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
        self.browser_tree.bind("<Double-1>", self._on_browser_activate)
        self.browser_tree.bind("<Return>", self._on_browser_activate)

        # Barra de progreso de consumo de tokens — SIEMPRE VISIBLE.
        # Se empaqueta con side="bottom" para que quede en la parte
        # inferior de la ventana y nunca quede oculta al redimensionar.
        self._build_context_bar()

        # Contenedor intermedio que ocupa el espacio restante entre la fila
        # superior y la barra informativa inferior. La zona de historial y
        # tareas llega directamente hasta dicha barra.
        middle_container = ttk.Frame(self.root, style="TFrame")
        middle_container.pack(side="top", fill="both", expand=True)
        middle_container.pack_propagate(False)

        # ==================================================================
        # Zona 2 (PROMINENTE): Historial (izquierda) + Tabs (derecha)
        # ==================================================================
        # Esta zona ocupa la mayor parte del espacio disponible. Se divide
        # en dos columnas:
        #   - Izquierda (50%): Historial de la tarea seleccionada.
        #   - Derecha (50%): Notebook con dos pestañas:
        #       * "Tarea en curso": tareas activas (PENDING, IN_PROGRESS,
        #         AWAITING_APPROVAL) con sus subtareas anidadas.
        #       * "Tareas terminadas": tareas en estado terminal
        #         (COMPLETED, FAILED, CANCELLED).
        prominent = ttk.Frame(middle_container, style="TFrame", padding=(10, 0, 10, 0))
        prominent.pack(side="top", fill="both", expand=True)
        prominent.columnconfigure(0, weight=1, uniform="top_panels")  # Historial: 50%
        prominent.columnconfigure(1, weight=1, uniform="top_panels")  # Tabs: 50%
        prominent.rowconfigure(0, weight=1)

        # --- Columna izquierda: Historial de la tarea seleccionada ---
        history_panel = RoundedFrame(
            prominent,
            bg=CONFIG.ui_card_bg,
            border_color=CONFIG.ui_card_border_color,
            border_width=CONFIG.ui_card_border_width,
            radius=CONFIG.ui_corner_radius,
            padding=10,
        )
        history_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        history_header = ttk.Frame(history_panel.inner, style="Card.TFrame")
        history_header.pack(fill="x")
        self.history_title_var = StringVar(value="📜 Historial de tarea (ninguna seleccionada)")
        ttk.Label(
            history_header,
            textvariable=self.history_title_var,
            style="Header.TLabel",
        ).pack(side="left")
        RoundedButton(
            history_header,
            text="🔄 Refrescar",
            command=self._refresh_task_lists,
            bg=CONFIG.ui_button_bg,
            fg=CONFIG.ui_button_fg,
            hover_bg=CONFIG.ui_button_hover_bg,
            pressed_bg=CONFIG.ui_button_pressed_bg,
            radius=CONFIG.ui_corner_radius,
            padding_x=12,
            padding_y=4,
        ).pack(side="right")

        self.history_view = ScrolledText(
            history_panel.inner,
            height=12,
            wrap="word",
            font=(CONFIG.ui_mono_font_family, CONFIG.ui_mono_font_size - 1),
            state="disabled",
            background=CONFIG.ui_history_bg,
            foreground=CONFIG.ui_history_fg,
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
            padx=6,
            pady=6,
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
        self.history_view.tag_configure(
            "context_overflow",
            foreground=CONFIG.ui_context_overflow_fg,
        )
        _use_ttk_scrollbar(self.history_view)
        self.history_view.pack(fill="both", expand=True, pady=(6, 0))

        # --- Columna derecha: Notebook con tabs "Tarea en curso" / "Tareas terminadas" ---
        tabs_panel = RoundedFrame(
            prominent,
            bg=CONFIG.ui_card_bg,
            border_color=CONFIG.ui_card_border_color,
            border_width=CONFIG.ui_card_border_width,
            radius=CONFIG.ui_corner_radius,
            padding=10,
        )
        tabs_panel.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        # Título del panel de tabs.
        tabs_header = ttk.Frame(tabs_panel.inner, style="Card.TFrame")
        tabs_header.pack(fill="x")
        ttk.Label(
            tabs_header,
            text="📋 Tareas",
            style="Header.TLabel",
        ).pack(side="left")
        RoundedButton(
            tabs_header,
            text="🔄 Refrescar",
            command=self._refresh_task_lists,
            bg=CONFIG.ui_button_bg,
            fg=CONFIG.ui_button_fg,
            hover_bg=CONFIG.ui_button_hover_bg,
            pressed_bg=CONFIG.ui_button_pressed_bg,
            radius=CONFIG.ui_corner_radius,
            padding_x=12,
            padding_y=4,
        ).pack(side="right")

        # Notebook (pestañas) con dos páginas.
        self.task_notebook = ttk.Notebook(tabs_panel.inner)
        self.task_notebook.pack(fill="both", expand=True, pady=(6, 0))

        # --- Pestaña 1: Tarea en curso ---
        self.tab_current = ttk.Frame(self.task_notebook, style="Card.TFrame", padding=4)
        self.task_notebook.add(self.tab_current, text="▶ Tarea en curso")
        self.current_list_frame = self._make_scrollable_frame(self.tab_current)

        # --- Pestaña 2: Tareas terminadas ---
        self.tab_finished = ttk.Frame(self.task_notebook, style="Card.TFrame", padding=4)
        self.task_notebook.add(self.tab_finished, text="✅ Tareas terminadas")
        self.finished_list_frame = self._make_scrollable_frame(self.tab_finished)

        # Carga inicial del explorador.
        self._refresh_file_browser()

        # Almacén de uso de contexto por tarea. La barra visual y la
        # información del modelo se construyen en _build_context_bar() en
        # la fila inferior, siempre visible aunque la ventana se reduzca.
        self._context_usage: Dict[int, Dict[str, int]] = {}

        # Cola FIFO de solicitudes de aprobación pendientes. Cada solicitud
        # se muestra como un popup modal (ApprovalPopup). Cuando el usuario
        # resuelve la solicitud actual, se muestra automáticamente la
        # siguiente de la cola (si queda alguna).
        self._approval_queue: "collections.deque[Dict[str, Any]]" = collections.deque()
        # Popup actualmente visible (None si no hay ninguno).
        self._current_approval_popup: Optional[ApprovalPopup] = None
        # ``self.preauth_var`` se crea en __init__ antes de _build_layout; no
        # recrearla aquí, o la casilla quedaría desvinculada de la variable.

    def _build_context_bar(self) -> None:
        """Crea la barra inferior en dos mitades: contexto e información LLM."""
        status_frame = ttk.Frame(self.root, style="TFrame", padding=(10, 4, 10, 8))
        status_frame.pack(side="bottom", fill="x")
        status_frame.columnconfigure(0, weight=1, uniform="status_panels")
        status_frame.columnconfigure(1, weight=1, uniform="status_panels")

        context_frame = ttk.Frame(status_frame, style="TFrame", padding=(0, 0, 6, 0))
        context_frame.grid(row=0, column=0, sticky="nsew")
        info_frame = ttk.Frame(status_frame, style="TFrame", padding=(6, 0, 0, 0))
        info_frame.grid(row=0, column=1, sticky="nsew")

        ttk.Label(
            context_frame,
            text="📊 Contexto:",
            style="TLabel",
        ).pack(side="left")

        # Barra de progreso con esquinas redondeadas.
        bar_radius = max(0, CONFIG.ui_corner_radius - 4)
        self.context_canvas = GradientCanvas(
            context_frame,
            color_top=CONFIG.ui_context_bar_bg,
            color_bottom=CONFIG.ui_context_bar_bg,
            radius=bar_radius,
            corner_bg=CONFIG.ui_frame_bg,
            height=16,
        )
        self.context_canvas.pack(side="left", fill="x", expand=True, padx=(6, 6))
        self.context_canvas.bind("<Configure>", self._on_context_canvas_configure)

        self.context_label_var = StringVar(value="0% (0/0 tokens)")
        ttk.Label(
            context_frame,
            textvariable=self.context_label_var,
            style="TLabel",
        ).pack(side="right")

        self.config_label = ttk.Label(
            info_frame,
            text=self._build_config_label_text(),
            style="TLabel",
            anchor="w",
            justify="left",
        )
        self.config_label.pack(fill="x", expand=True)

        def _fit_config_label(event: Any) -> None:
            self.config_label.configure(wraplength=max(100, event.width - 16))

        info_frame.bind("<Configure>", _fit_config_label)

    # --- Acciones de la Zona 1 ---

    def _on_clear_prompt(self) -> None:
        self.prompt_text.delete("1.0", "end")

    def _on_delete_finished_tasks(self) -> None:
        """
        Elimina todas las tareas en estado terminal (COMPLETED, FAILED,
        CANCELLED) de la base de datos y refresca el tablero.

        Las subtareas se borran en cascada por la FK de la tabla ``history``
        y por la FK de ``tasks.parent_task_id`` (si está definida con
        ON DELETE CASCADE en el esquema).
        """
        try:
            finished = TaskStatus.finished()
            deleted = self.db.delete_tasks_by_status(finished)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(
                "Error al borrar tareas",
                f"No se pudieron eliminar las tareas terminadas:\n{exc}",
            )
            return
        self._refresh_task_lists()
        # Si la tarea seleccionada era una de las borradas, limpia el historial.
        if self.selected_task_id is not None:
            if self.db.get_task(self.selected_task_id) is None:
                self._select_task(None)
        messagebox.showinfo(
                "Tareas eliminadas",
                f"{deleted} tarea(s) terminada(s) eliminada(s)."
            )


    def _set_task_controls_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.prompt_text.configure(state=state)
        self.execute_button.configure(state=state)
        self.abort_button.configure(state="disabled" if enabled else "normal")

    def _on_abort(self) -> None:
        if self._active_task_cancel_event is not None:
            self._active_task_cancel_event.set()
            self.abort_button.configure(state="disabled")

    def _on_task_thread_finished(self) -> None:
        self._active_task_cancel_event = None
        self._active_task_thread = None
        self._set_task_controls_enabled(True)

    def _on_execute(self) -> None:
        if self._active_task_thread is not None and self._active_task_thread.is_alive():
            return
        prompt = self.prompt_text.get("1.0", "end").strip()
        if not prompt:
            return
        title = prompt.splitlines()[0][:80]
        # Crea la tarea PADRE (sin subtask_type). El orquestador creará
        # las subtareas (Requisitos → Desarrollo → Ejecución/Verificación
        # → Rectificación si falla) y las ejecutará secuencialmente.
        task = self.db.create_task(title=title, prompt=prompt)
        self._on_clear_prompt()
        self._follow_active_task = True
        self._refresh_task_lists()
        self._select_task(task.id)
        # Bloquear nuevos envíos hasta que termine el orquestador completo.
        cancel_event = threading.Event()
        self._active_task_cancel_event = cancel_event
        self._set_task_controls_enabled(False)

        def _run_task() -> None:
            try:
                self.orchestrator.run(task, cancel_event=cancel_event)
            finally:
                self.ui_queue.put({"type": "orchestrator_finished"})

        self._active_task_thread = threading.Thread(
            target=_run_task,
            daemon=True,
            name=f"orchestrator-task-{task.id}",
        )
        self._active_task_thread.start()

    # --- Tablero de tareas ---

    def _refresh_task_lists(self) -> None:
        # Limpia las dos pestañas del notebook.
        for frame in (self.current_list_frame, self.finished_list_frame):
            for child in frame.winfo_children():
                child.destroy()

        # Las tareas que sigan IN_PROGRESS se registran de nuevo
        # en _render_task_row; las que ya no lo estén dejan de
        # aparecer en el diccionario.
        self._spinner_labels.clear()

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

        # --- Pestaña "Tarea en curso": tareas activas ---
        if not active_parents:
            ttk.Label(
                self.current_list_frame,
                text="(sin tareas activas)",
                style="Card.TLabel",
            ).pack(anchor="w", pady=4)
        else:
            for t in active_parents:
                self._render_task_with_subtasks(self.current_list_frame, t)

        # --- Pestaña "Tareas terminadas": tareas en estado terminal ---
        if not finished_parents:
            ttk.Label(
                self.finished_list_frame,
                text="(sin tareas finalizadas)",
                style="Card.TLabel",
            ).pack(anchor="w", pady=4)
        else:
            for t in finished_parents:
                self._render_task_with_subtasks(self.finished_list_frame, t)

        # Si la tarea seleccionada ya no existe, limpia el historial.
        if self.selected_task_id is not None:
            current = self.db.get_task(self.selected_task_id)
            if current is None:
                self._select_task(None)

    def _tick_spinner(self) -> None:
        """
        Avanza un frame del spinner animado y lo aplica a todas las
        tareas IN_PROGRESS visibles en el tablero.

        Se ejecuta de forma periódica mediante ``root.after()``,
        independiente del polling de la cola de eventos, para que la
        animación continúe aunque no haya eventos nuevos.
        """
        self._spinner_counter = (self._spinner_counter + 1) % len(self._spinner_frames)
        frame = self._spinner_frames[self._spinner_counter]
        # Itera sobre una copia de los valores: si _refresh_task_lists
        # vacía el diccionario mientras estamos iterando, no hay error.
        for label in list(self._spinner_labels.values()):
            try:
                label.configure(text=frame)
            except Exception:
                # El label pudo haber sido destruido entre el listado
                # y el configure; lo ignoramos.
                pass
        # ~150 ms ≈ 6.7 fps: suficientemente suave para que se note
        # el movimiento sin parpadeos.
        self.root.after(150, self._tick_spinner)

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

        # Spinner animado: solo aparece en tareas IN_PROGRESS.
        # Se reutiliza el mismo estilo de color que el estado para
        # que el símbolo vaya en el color de "IN_PROGRESS".
        if task.status == TaskStatus.IN_PROGRESS and task.id is not None:
            spinner = ttk.Label(
                row,
                text=self._spinner_frames[self._spinner_counter],
                style=status_style,
                width=2,
            )
            spinner.pack(side="left", padx=(2, 0))
            self._spinner_labels[task.id] = spinner

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
            command=lambda tid=task.id: self._on_view_task(tid),
        )
        btn.pack(side="right")

    def _on_view_task(self, task_id: Optional[int]) -> None:
        """Selección manual desde el botón "Ver": detiene el seguimiento automático."""
        self._follow_active_task = False
        self._select_task(task_id)

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
            EventType.CONTEXT_OVERFLOW: "context_overflow",
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
        # El GradientCanvas ya dibujó el fondo redondeado; solo añadimos
        # el rectángulo de progreso encima (también con esquinas redondeadas
        # para mantener la coherencia visual).
        self.context_canvas.delete("fill")
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
            # Usar esquinas redondeadas para el relleno, con un radio
            # ligeramente menor que el del fondo para que se vea "dentro".
            fill_radius = max(0, (CONFIG.ui_corner_radius - 4) - 1)
            _draw_rounded_rect(
                self.context_canvas,
                0, 0, fill_width, height,
                radius=fill_radius,
                fill=color,
                outline="",
                tags="fill",
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

    # --- Zona de aprobación (ahora como popup modal) ---

    def _resolve_specific_approval(self, event: Dict[str, Any], granted: bool) -> None:
        """
        Resuelve una solicitud de aprobación concreta (la del popup actual).

        - Si la solicitud está al frente de la cola, la extrae y la resuelve.
        - Si está en otra posición (caso raro), la busca y la elimina.
        - Cierra el popup actual y muestra el siguiente si queda alguno.
        """
        request_id = event["request_id"]
        task_id = event["task_id"]

        # Extraer la solicitud de la cola (puede estar en cualquier posición).
        try:
            self._approval_queue.remove(event)
        except ValueError:
            pass

        self.permissions.resolve(
            request_id,
            granted,
            reason="permitido por el usuario" if granted else "cancelado por el usuario",
        )

        # Refresca tablero e historial.
        self._refresh_task_lists()
        if task_id == self.selected_task_id:
            self._select_task(task_id)

        # Cierra el popup actual (si lo hay) y muestra el siguiente.
        self._current_approval_popup = None
        if self._approval_queue:
            self._render_current_approval()

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
            if self._follow_active_task:
                in_progress = self.db.list_tasks([TaskStatus.IN_PROGRESS])
                if in_progress:
                    latest = max(in_progress, key=lambda t: t.id or 0)
                    if latest.id != self.selected_task_id:
                        self._select_task(latest.id)
        elif etype == "history_update":
            if event.get("task_id") == self.selected_task_id:
                self._select_task(self.selected_task_id)
        elif etype == "context_usage":
            self._update_context_bar(event)
        elif etype == "approval_request":
            self._show_approval(event)
        elif etype == "refresh_file_browser":
            self._refresh_file_browser()
        elif etype == "orchestrator_finished":
            self._on_task_thread_finished()

    def _show_approval(self, event: Dict[str, Any]) -> None:
        """
        Encola una nueva solicitud de aprobación y muestra la primera pendiente
        como popup modal.

        Si la casilla "preautorizar" está marcada, se consulta al LLM en
        segundo plano antes de mostrar la solicitud al usuario. Si el modelo
        responde afirmativamente, la acción se autoriza automáticamente; si
        no, la solicitud queda pendiente para que el usuario la resuelva.

        Si ya hay un popup visible, la nueva solicitud queda encolada y se
        mostrará automáticamente cuando el usuario resuelva la actual. Esto
        evita que una segunda solicitud sobrescriba a la primera y la deje
        invisible (el hilo del agente correspondiente quedaría esperando
        hasta el timeout de 10 minutos).
        """
        # Bypass total: resolver directamente sin preauth ni cola de UI.
        if CONFIG.no_authorization:
            self.permissions.resolve(
                event["request_id"],
                True,
                reason="autorización omitida por configuración (no_authorization=true)",
            )
            self._log_event(
                event["task_id"],
                EventType.APPROVAL_GRANTED,
                f"⚠ Autorización omitida por configuración: '{event['tool_name']}'",
            )
            self._refresh_task_lists()
            if event["task_id"] == self.selected_task_id:
                self._select_task(event["task_id"])
            return

        # Si la casilla global "Preautorizar" está marcada, consultamos
        # al LLM en segundo plano antes de mostrar nada al usuario. Solo
        # las solicitudes que el LLM deniegue acabarán en un popup.
        if self.preauth_var.get():
            self._start_preauthorization_for_event(event, popup=None)
            return

        # Modo normal: encolar y mostrar popup directamente.
        self._approval_queue.append(event)
        # Notificación visual siempre que llegue una nueva solicitud.
        try:
            self.root.bell()
        except Exception:  # noqa: BLE001
            pass
        # Si ya había un popup visible, la nueva queda encolada.
        if len(self._approval_queue) > 1:
            return
        self._render_current_approval()

    def _start_preauthorization_for_event(
        self,
        event: Dict[str, Any],
        popup: Optional[ApprovalPopup],
    ) -> None:
        """
        Lanza la consulta al LLM para preautorizar una solicitud.

        Si se pasa un popup, se actualiza su indicador de estado mientras
        dura la consulta y se deshabilitan sus botones. Si no hay popup
        (caso de preauth silencioso porque ya hay otro popup visible),
        simplemente se ejecuta en segundo plano.
        """
        request_id = event["request_id"]
        task_id = event["task_id"]
        tool_name = event["tool_name"]

        # Si ya hay un popup visible, no lo sobrescribimos: ejecutamos el
        # preauth en silencio y encolamos/resolvemos al terminar.
        panel_busy = len(self._approval_queue) > 0

        if popup is not None:
            popup.set_preauth_status(
                f"🤖 Preautorizando {tool_name}… (timeout {CONFIG.preauth_timeout:.0f}s)"
            )
            popup.disable_buttons()

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
                    self._refresh_task_lists()
                    if task_id == self.selected_task_id:
                        self._select_task(task_id)
                    # Si había popup, cerrarlo (la solicitud queda resuelta).
                    if popup is not None:
                        popup._close()
                        self._current_approval_popup = None
                    # Si quedan solicitudes pendientes, mostrar la siguiente.
                    if self._approval_queue:
                        self._render_current_approval()
                else:
                    # El LLM recomienda no autorizar (o no pudo decidir).
                    if CONFIG.preauth_fallback_to_human:
                        # Modo por defecto: encolar para decisión humana.
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
                        # Fallback deshabilitado: resolver automáticamente
                        # como denegado (modo "fail-closed" sin intervención
                        # humana). El agente recibe la denegación y continúa.
                        self.permissions.resolve(
                            request_id,
                            False,
                            reason=f"denegado por LLM (fallback deshabilitado): {reason}",
                        )
                        self._log_event(
                            task_id,
                            EventType.PREAUTHORIZATION_DENIED,
                            (
                                f"🤖 LLM denegó '{tool_name}' y fallback humano "
                                f"deshabilitado: {reason}. Acción bloqueada."
                            ),
                        )
                        self._refresh_task_lists()
                        if task_id == self.selected_task_id:
                            self._select_task(task_id)
                        # Si había popup, cerrarlo.
                        if popup is not None:
                            popup._close()
                            self._current_approval_popup = None
                        # Si quedan solicitudes pendientes, mostrar la siguiente.
                        if self._approval_queue:
                            self._render_current_approval()

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

        # Ejecutar la consulta al LLM con un timeout dedicado
        # (``CONFIG.preauth_timeout``), independiente del timeout general
        # de inferencia. Una decisión de seguridad debe resolverse rápido:
        # si el LLM tarda demasiado, se considera que no ha podido decidir
        # y se devuelve False para activar el fallback configurado.
        response_holder: Dict[str, Any] = {}
        error_holder: Dict[str, BaseException] = {}

        def _call_llm() -> None:
            try:
                response_holder["response"] = self.llm.chat(
                    messages=[
                        {"role": "system", "content": system_msg},
                        {"role": "user", "content": user_msg},
                    ]
                )
            except BaseException as e:  # noqa: BLE001
                error_holder["error"] = e

        worker = threading.Thread(target=_call_llm, daemon=True)
        worker.start()
        timeout_s = max(1.0, float(CONFIG.preauth_timeout))
        worker.join(timeout=timeout_s)

        if worker.is_alive():
            # El LLM no respondió a tiempo. Por seguridad, no preautorizar.
            return False, f"timeout ({timeout_s:.0f}s) sin respuesta del LLM"
        if "error" in error_holder:
            err = error_holder["error"]
            return False, f"error del LLM: {type(err).__name__}: {err}"
        response = response_holder.get("response", {})
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
        """
        Muestra la primera solicitud pendiente de la cola como popup modal.

        Si ya hay un popup visible, no hace nada (la nueva solicitud ya
        está encolada y se mostrará cuando el usuario resuelva la actual).
        """
        if not self._approval_queue:
            return
        # Si ya hay un popup visible, no crear otro (la cola ya está
        # actualizada y se mostrará al cerrar el actual).
        if self._current_approval_popup is not None:
            try:
                if self._current_approval_popup.winfo_exists():
                    return
            except Exception:  # noqa: BLE001
                pass
        event = self._approval_queue[0]
        # Con la app minimizada solo se avisa en la bandeja; el popup se abre al restaurarla.
        if _is_minimized(self.root):
            _TrayNotifier.show(
                self.root,
                "Autorización requerida",
                f"Tarea #{event.get('task_id', '?')}: {event.get('tool_name', '')}",
            )
            if getattr(self, "_approval_poll_id", None) is None:
                self._approval_poll_id = self.root.after(300, self._poll_pending_approval)
            return
        popup = ApprovalPopup(self, event)
        self._current_approval_popup = popup

    def _poll_pending_approval(self) -> None:
        """Espera a que se restaure la ventana principal para mostrar la solicitud pendiente."""
        self._approval_poll_id = None
        if not self._approval_queue:
            _TrayNotifier.remove()
            return
        if _is_minimized(self.root):
            self._approval_poll_id = self.root.after(300, self._poll_pending_approval)
            return
        # Margen para que la geometría se estabilice antes de centrar el popup.
        self._approval_poll_id = self.root.after(250, self._show_pending_after_restore)

    def _show_pending_after_restore(self) -> None:
        self._approval_poll_id = None
        self._render_current_approval()

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

        La ventana muestra la ruta completa del fichero en el título junto
        con su nombre y el contenido en un ScrolledText de solo lectura. No
        captura globalmente la entrada, por lo que otra ventana en primer plano
        conserva el foco.
        El contenido se
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

        # Barra de título personalizada (overrideredirect) coherente con
        # la ventana principal. Solo se aplica si está habilitada en
        # config.ini. Se crea ANTES del contenido para que se empaquete
        # en la parte superior.
        if getattr(CONFIG, "ui_custom_titlebar", True):
            try:
                viewer.overrideredirect(True)
            except Exception:  # noqa: BLE001
                pass
            try:
                _force_taskbar_visibility(viewer)
            except Exception:  # noqa: BLE001
                pass
            try:
                file_title_bar = CustomTitleBar(
                    viewer,
                    title=f"{target.name}",
                    icon="📄",
                    bg=CONFIG.ui_titlebar_color,
                    fg=CONFIG.ui_titlebar_text_color,
                    hover_bg=CONFIG.ui_button_hover_bg,
                    close_hover_bg=CONFIG.ui_button_danger_bg,
                    height=CONFIG.ui_custom_titlebar_height,
                    show_minimize=False,
                    show_maximize=True,
                    close_callback=viewer.destroy,
                )
                file_title_bar.pack(side="top", fill="x")
            except Exception:  # noqa: BLE001
                pass

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

        _bring_to_front(viewer)

    def _open_settings(self) -> None:
        """Abre el popup de edición de config.ini."""
        SettingsDialog(self)

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
# POPUP DE AUTORIZACIÓN (HITL)
# ============================================================================

class ApprovalPopup:
    """
    Ventana emergente (Toplevel) para solicitudes de aprobación HITL.

    Se muestra como popup flotante sobre el dashboard cuando el agente
    necesita autorización humana para ejecutar una acción sensible. El
    popup muestra:

      - Cabecera con el nombre de la herramienta y el nivel de riesgo.
      - Descripción de la herramienta.
      - Argumentos completos que se van a ejecutar.
      - Botones "✅ Permitir" y "❌ Cancelar".
      - Casilla "🤖 Preautorizar" (consulta al LLM antes de mostrar).

    El popup permanece encima de las demás ventanas mientras haya una
    autorización pendiente, sin capturar globalmente la entrada: el foco
    sigue perteneciendo a la ventana que esté en primer plano. Solo se cierra
    cuando el usuario resuelve la solicitud o cuando el LLM la preautoriza/
    deniega automáticamente.

    Atajos de teclado:
      - Enter: Permitir
      - Escape: Cancelar
    """

    def __init__(self, dashboard: "Dashboard", event: Dict[str, Any]) -> None:
        self.dashboard = dashboard
        self.event = event
        self._resolved = False  # evita doble-resolución si el usuario hace doble clic

        self.window = Toplevel(dashboard.root)
        self.window.title("⚠ Autorización requerida")
        self.window.geometry("720x640")
        self.window.minsize(520, 480)
        try:
            self.window.configure(background=CONFIG.ui_bg_color)
        except Exception:  # noqa: BLE001
            pass
        # Sin transient para que no quede oculta al minimizar/restaurar el
        # dashboard. Se mantiene topmost, pero no toma una captura global de
        # entrada: el foco sigue la ventana activa del sistema.
        # Si el usuario cierra la ventana con la X, se trata como "Cancelar".
        self.window.protocol("WM_DELETE_WINDOW", self._on_deny)

        # Barra de título personalizada (overrideredirect) coherente con
        # la ventana principal. Solo se aplica si está habilitada en
        # config.ini. Se crea ANTES del layout para que el contenido
        # se empaquete debajo de ella.
        if getattr(CONFIG, "ui_custom_titlebar", True):
            try:
                self.window.overrideredirect(True)
            except Exception:  # noqa: BLE001
                pass
            try:
                _force_taskbar_visibility(self.window)
            except Exception:  # noqa: BLE001
                pass
            try:
                self.title_bar = CustomTitleBar(
                    self.window,
                    title="Autorización requerida",
                    icon="⚠",
                    bg=CONFIG.ui_titlebar_color,
                    fg=CONFIG.ui_titlebar_text_color,
                    hover_bg=CONFIG.ui_button_hover_bg,
                    close_hover_bg=CONFIG.ui_button_danger_bg,
                    height=CONFIG.ui_custom_titlebar_height,
                    show_minimize=False,
                    show_maximize=False,
                    close_callback=self._on_deny,
                )
                self.title_bar.pack(side="top", fill="x")
            except Exception:  # noqa: BLE001
                pass

        self._build_layout()
        self._center_on_dashboard()

        # Aplicar el mismo estilo de barra de título que el dashboard
        # para mantener la coherencia visual (no-op si ya hay barra
        # personalizada con overrideredirect).
        try:
            _apply_modern_titlebar(self.window)
        except Exception:  # noqa: BLE001
            pass

        # Atajos de teclado.
        self.window.bind("<Escape>", lambda _e: self._on_deny())
        self.window.bind("<Return>", lambda _e: self._on_allow())
        _bring_to_front(self.window, keep_on_top=True)
        try:
            # Si el dashboard se restaura, el popup vuelve al frente.
            dashboard.root.bind("<Map>", self._on_dashboard_map, add="+")
        except Exception:  # noqa: BLE001
            pass
        # Aviso en la bandeja del sistema y parpadeo en la barra de tareas.
        _TrayNotifier.show(
            dashboard.root,
            "Autorización requerida",
            f"Tarea #{event.get('task_id', '?')}: {event.get('tool_name', '')}",
        )
        # Sonido de aviso.
        try:
            dashboard.root.bell()
        except Exception:  # noqa: BLE001
            pass

    def _on_dashboard_map(self, event: Any) -> None:
        if event.widget is not self.dashboard.root or self._resolved:
            return
        _bring_to_front(self.window, keep_on_top=True)

    def _build_layout(self) -> None:
        """Construye los widgets del popup de autorización."""
        # Marco principal con esquinas redondeadas.
        outer = RoundedFrame(
            self.window,
            bg=CONFIG.ui_card_bg,
            border_color=CONFIG.ui_card_border_color,
            border_width=CONFIG.ui_card_border_width,
            radius=CONFIG.ui_corner_radius,
            padding=14,
        )
        outer.pack(fill="both", expand=True, padx=6, pady=6)

        # --- Cabecera ---
        header = ttk.Frame(outer.inner, style="Card.TFrame")
        header.pack(fill="x")

        # Icono + título de la herramienta.
        tool_name = self.event.get("tool_name", "?")
        risk = self.event.get("risk", "?")
        task_id = self.event.get("task_id", "?")
        title_text = f"⚠ Autorización requerida — Tarea #{task_id}"
        ttk.Label(
            header,
            text=title_text,
            style="Header.TLabel",
        ).pack(side="left")

        # Etiqueta de riesgo (a la derecha).
        risk_colors = {
            "CRITICAL": CONFIG.ui_button_danger_bg,
            "HIGH": CONFIG.ui_button_danger_bg,
            "MEDIUM": CONFIG.ui_status_awaiting_approval,
            "LOW": CONFIG.ui_status_completed,
        }
        risk_fg = {
            "CRITICAL": "#ffffff",
            "HIGH": "#ffffff",
            "MEDIUM": "#000000",
            "LOW": "#ffffff",
        }
        risk_bg = risk_colors.get(str(risk).upper(), CONFIG.ui_status_awaiting_approval)
        risk_fgc = risk_fg.get(str(risk).upper(), "#000000")
        risk_label = TkLabel(
            header,
            text=f"  Riesgo: {risk}  ",
            bg=risk_bg,
            fg=risk_fgc,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size, "bold"),
            padx=8,
            pady=2,
        )
        risk_label.pack(side="right")

        # --- Información de la herramienta ---
        info_frame = ttk.Frame(outer.inner, style="Card.TFrame")
        info_frame.pack(fill="x", pady=(10, 6))

        ttk.Label(
            info_frame,
            text=f"🔧 Herramienta: {tool_name}",
            style="Card.TLabel",
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size + 1, "bold"),
        ).pack(anchor="w")

        tool_desc = self.event.get("tool_description", "")
        if tool_desc:
            desc_label = ttk.Label(
                info_frame,
                text=f"📄 {tool_desc}",
                style="Card.TLabel",
                wraplength=640,
                justify="left",
            )
            desc_label.pack(anchor="w", pady=(2, 0))

        # --- Argumentos (caja con esquinas redondeadas) ---
        args_label = ttk.Label(
            outer.inner,
            text="📋 Argumentos que se van a ejecutar:",
            style="Card.TLabel",
        )
        args_label.pack(anchor="w", pady=(8, 4))

        args_card = RoundedFrame(
            outer.inner,
            bg=CONFIG.ui_approval_bg,
            border_color=CONFIG.ui_card_border_color,
            border_width=CONFIG.ui_card_border_width,
            radius=max(0, CONFIG.ui_corner_radius - 2),
            padding=2,
        )
        args_card.pack(fill="both", expand=True, pady=(0, 8))

        args_str = _format_approval_args(tool_name, self.event.get("arguments", {}) or {})
        self.args_view = ScrolledText(
            args_card.inner,
            height=8,
            wrap="word",
            font=(CONFIG.ui_mono_font_family, CONFIG.ui_mono_font_size - 1),
            state="disabled",
            background=CONFIG.ui_approval_bg,
            foreground=CONFIG.ui_approval_fg,
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
            padx=6,
            pady=4,
        )
        _use_ttk_scrollbar(self.args_view)
        self.args_view.pack(fill="both", expand=True)
        self.args_view.configure(state="normal")
        self.args_view.insert("end", args_str)
        self.args_view.configure(state="disabled")

        # --- Indicador de preautorización (oculto por defecto) ---
        self.preauth_status_var = StringVar(value="")
        ttk.Label(
            outer.inner,
            textvariable=self.preauth_status_var,
            style="Card.TLabel",
            foreground=CONFIG.ui_info_fg,
        ).pack(anchor="w", pady=(0, 4))

        # --- Botones de acción ---
        btn_row = ttk.Frame(outer.inner, style="Card.TFrame")
        btn_row.pack(fill="x")

        # Botón "Permitir" en verde.
        self.allow_btn = RoundedButton(
            btn_row,
            text="✅ Permitir  (Enter)",
            command=self._on_allow,
            bg=CONFIG.ui_status_completed,
            fg="#ffffff",
            hover_bg=CONFIG.ui_button_hover_bg,
            pressed_bg=CONFIG.ui_button_pressed_bg,
            radius=CONFIG.ui_corner_radius,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size, "bold"),
            padding_x=16,
            padding_y=8,
        )
        self.allow_btn.pack(side="left")

        # Botón "Cancelar" en rojo.
        self.deny_btn = RoundedButton(
            btn_row,
            text="❌ Cancelar  (Esc)",
            command=self._on_deny,
            bg=CONFIG.ui_button_danger_bg,
            fg=CONFIG.ui_button_danger_fg,
            hover_bg=CONFIG.ui_button_danger_hover_bg,
            pressed_bg=CONFIG.ui_button_danger_pressed_bg,
            radius=CONFIG.ui_corner_radius,
            font=(CONFIG.ui_font_family, CONFIG.ui_font_size, "bold"),
            padding_x=16,
            padding_y=8,
        )
        self.deny_btn.pack(side="left", padx=(8, 0))

        # Foco inicial en el botón Permitir.
        self.allow_btn.focus_set()

    def _center_on_dashboard(self) -> None:
        """Centra el popup sobre la ventana del dashboard."""
        self.window.update_idletasks()
        try:
            root_x = self.dashboard.root.winfo_rootx()
            root_y = self.dashboard.root.winfo_rooty()
            root_w = self.dashboard.root.winfo_width()
            root_h = self.dashboard.root.winfo_height()
            pw = self.window.winfo_width()
            ph = self.window.winfo_height()
            x = root_x + (root_w - pw) // 2
            y = root_y + (root_h - ph) // 2
            self.window.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        except Exception:  # noqa: BLE001
            pass

    def _on_allow(self) -> None:
        """Resuelve la solicitud como aprobada y cierra el popup."""
        if self._resolved:
            return
        self._resolved = True
        try:
            self.dashboard._resolve_specific_approval(self.event, granted=True)
        finally:
            self._close()

    def _on_deny(self) -> None:
        """Resuelve la solicitud como denegada y cierra el popup."""
        if self._resolved:
            return
        self._resolved = True
        try:
            self.dashboard._resolve_specific_approval(self.event, granted=False)
        finally:
            self._close()

    def _close(self) -> None:
        """Cierra la ventana del popup de autorización."""
        _TrayNotifier.remove()
        try:
            self.window.destroy()
        except Exception:  # noqa: BLE001
            pass

    def set_preauth_status(self, text: str) -> None:
        """Actualiza el indicador de estado de preautorización."""
        try:
            self.preauth_status_var.set(text)
        except Exception:  # noqa: BLE001
            pass

    def disable_buttons(self) -> None:
        """Deshabilita los botones mientras se preautoriza."""
        try:
            self.allow_btn.configure(state="disabled")
            self.deny_btn.configure(state="disabled")
        except Exception:  # noqa: BLE001
            pass


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

    DEVELOPER_NAME = "Rubén Pastor"
    GITHUB_URL = "https://github.com/bondwell79/hercules"
    GITHUB_DISPLAY = "github.com/bondwell79/hercules"
    VERSION_PN = "1.0"

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
        self.window.title(f"Bienvenido a Hercules {self.VERSION_PN}")
        self.window.resizable(False, False)
        # Colores coherentes con el dashboard.
        try:
            self.window.configure(bg=CONFIG.ui_bg_color)
        except Exception:  # noqa: BLE001
            pass

        # Modal: el grab se aplica al final, cuando la ventana ya es visible.
        self.window.transient(parent)
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)

        # Barra de título personalizada (overrideredirect) coherente con
        # la ventana principal. Solo se aplica si está habilitada en
        # config.ini. Se crea ANTES del layout para que el contenido
        # se empaquete debajo de ella.
        if getattr(CONFIG, "ui_custom_titlebar", True):
            try:
                self.window.overrideredirect(True)
            except Exception:  # noqa: BLE001
                pass
            try:
                _force_taskbar_visibility(self.window)
            except Exception:  # noqa: BLE001
                pass
            try:
                self.title_bar = CustomTitleBar(
                    self.window,
                    title=f"Bienvenido a Hercules {self.VERSION_PN}",
                    icon="👋",
                    bg=CONFIG.ui_titlebar_color,
                    fg=CONFIG.ui_titlebar_text_color,
                    hover_bg=CONFIG.ui_button_hover_bg,
                    close_hover_bg=CONFIG.ui_button_danger_bg,
                    height=CONFIG.ui_custom_titlebar_height,
                    show_minimize=False,
                    show_maximize=False,
                    close_callback=self._on_close,
                )
                self.title_bar.pack(side="top", fill="x")
            except Exception:  # noqa: BLE001
                pass

        self._build_layout()

        # Aplicar el mismo estilo de barra de título que el dashboard
        # para mantener la coherencia visual (no-op si ya hay barra
        # personalizada con overrideredirect).
        try:
            _apply_modern_titlebar(self.window)
        except Exception:  # noqa: BLE001
            pass

        # Centrar la ventana en la pantalla una vez construida.
        self.window.update()
        try:
            sw = self.window.winfo_screenwidth()
            sh = self.window.winfo_screenheight()
            ww = self.window.winfo_width()
            wh = self.window.winfo_height()
            x = max(0, (sw) // 2-(ww) // 2)
            y = max(0, (sh) // 2-(wh) // 2)
            self.window.geometry(f"+{x}+{y}")
        except Exception:  # noqa: BLE001
            pass

        # Atajo: Enter y Escape cierran el diálogo.
        self.window.bind("<Return>", lambda _e: self._on_close())
        self.window.bind("<Escape>", lambda _e: self._on_close())

        # Una ventana overrideredirect no recibe foco ni z-order del WM:
        # hay que subirla explícitamente o queda tras el dashboard.
        _bring_to_front(self.window)

    def _build_layout(self) -> None:
        """Construye los widgets del popup de bienvenida."""
        # Marco principal con padding.
        try:
            frame_bg = CONFIG.ui_card_bg
            mono_family = CONFIG.mono_font_family
            mono_size = CONFIG.mono_font_size
            font_family = CONFIG.ui_font_family
            font_size = CONFIG.ui_font_size
            accent_bg = CONFIG.ui_button_accent_bg
            accent_fg = CONFIG.ui_button_accent_fg
            accent_hover = CONFIG.ui_button_accent_hover_bg
            accent_pressed = CONFIG.ui_button_accent_pressed_bg
            radius = CONFIG.ui_corner_radius
        except Exception:  # noqa: BLE001
            frame_bg = "#2d2d30"
            mono_family = "Consolas"
            mono_size = 10
            font_family = "Segoe UI"
            font_size = 10
            accent_bg = "#007acc"
            accent_fg = "#ffffff"
            accent_hover = "#1a8ad8"
            accent_pressed = "#005a9e"
            radius = 10

        # Marco principal con esquinas redondeadas.
        outer = RoundedFrame(
            self.window,
            bg=frame_bg,
            border_color=CONFIG.ui_card_border_color,
            border_width=CONFIG.ui_card_border_width,
            radius=radius,
            padding=24,
        )
        outer.pack(fill="both", expand=True, padx=4, pady=4)

        # Arte ASCII del nombre del proyecto.
        ascii_label = Text(
            outer.inner,
            height=len(self.ASCII_ART.strip("\n").splitlines())+1,
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
            outer.inner,
            text=f"Desarrollado por {self.DEVELOPER_NAME}",
            style="Card.TLabel",
            font=(font_family, font_size + 1),
        )
        dev_label.pack(pady=(0, 4))

        # Enlace al repositorio de GitHub (Label con cursor de mano).
        link_frame = ttk.Frame(outer.inner, style="Card.TFrame")
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
        ttk.Separator(outer.inner, orient="horizontal").pack(fill="x", pady=(0, 12))

        # Casilla "No mostrar de nuevo".
        dont_show = ttk.Checkbutton(
            outer.inner,
            text="No mostrar este mensaje al iniciar",
            variable=self.dont_show_again,
            style="Card.TCheckbutton",
        )
        dont_show.pack(anchor="w", pady=(0, 12))

        # Botón "Comenzar" con esquinas redondeadas y color de acento.
        button = RoundedButton(
            outer.inner,
            text="Comenzar",
            command=self._on_close,
            bg=accent_bg,
            fg=accent_fg,
            hover_bg=accent_hover,
            pressed_bg=accent_pressed,
            radius=radius,
            font=(font_family, font_size + 1, "bold"),
            padding_x=20,
            padding_y=8,
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
        self.window.destroy()


def _load_welcome_pref() -> bool:
    """
    Devuelve True si debe mostrarse el popup de bienvenida.

    La preferencia se persiste en un fichero `.welcome` dentro del
    directorio de trabajo. Por defecto se muestra siempre (True).
    """
    try:
        pref_path = SCRIPT_DIR / ".welcome"
        if pref_path.exists():
            return pref_path.read_text(encoding="utf-8").strip().lower() not in (
                "false", "0", "no", "off"
            )
    except Exception:  # noqa: BLE001
        pass
    return True


def _save_welcome_pref(show: bool) -> None:
    """Persiste la preferencia del usuario sobre el popup de bienvenida."""
    pref_path = SCRIPT_DIR / ".welcome"
    pref_path.parent.mkdir(parents=True, exist_ok=True)
    pref_path.write_text("true" if show else "false", encoding="utf-8")


# ============================================================================
# AJUSTES (edición de config.ini)
# ============================================================================

_CONFIG_SECTION_RE = re.compile(r"^\s*\[(?P<name>[^\]]+)\]")
_CONFIG_KEY_RE = re.compile(r"^(?P<key>[^\s;#=\[][^=]*?)\s*=\s*(?P<value>.*)$")
_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def _scan_config_file(path: str) -> Dict[str, List[Tuple[str, str]]]:
    """Devuelve, por sección, las claves del fichero en orden con su comentario descriptivo."""
    result: Dict[str, List[Tuple[str, str]]] = {}
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return result
    section: Optional[str] = None
    pending: List[str] = []
    after_blank = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            after_blank = True
            continue
        m = _CONFIG_SECTION_RE.match(line)
        if m:
            section = m.group("name").strip()
            result.setdefault(section, [])
            pending, after_blank = [], False
            continue
        if line[0] in ";#":
            # Un bloque de comentarios nuevo tras una línea en blanco sustituye al anterior.
            if after_blank:
                pending, after_blank = [], False
            body = line.lstrip(";#").strip()
            if body and not set(body) <= set("-="):
                pending.append(body)
            continue
        m = _CONFIG_KEY_RE.match(line)
        if m and section is not None:
            result[section].append((m.group("key").strip().lower(), " ".join(pending)))
        pending, after_blank = [], False
    return result


def _update_config_file(path: str, updates: Dict[str, Dict[str, str]]) -> None:
    """
    Actualiza valores de config.ini conservando comentarios y orden.

    Las claves inexistentes se añaden al final de su sección.
    """
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines(keepends=True)
    except FileNotFoundError:
        lines = []
    remaining = {sec: dict(kv) for sec, kv in updates.items() if kv}
    out: List[str] = []

    def flush(sec: Optional[str]) -> None:
        missing = remaining.get(sec or "")
        if not missing:
            return
        idx = len(out)
        while idx > 0 and not out[idx - 1].strip():
            idx -= 1
        if idx > 0 and not out[idx - 1].endswith("\n"):
            out[idx - 1] += "\n"
        out[idx:idx] = [f"{k} = {v}\n" for k, v in missing.items()]
        remaining[sec or ""] = {}

    section: Optional[str] = None
    for line in lines:
        body = line.rstrip("\r\n")
        newline = line[len(body):]
        m = _CONFIG_SECTION_RE.match(body)
        if m:
            flush(section)
            section = m.group("name").strip()
            out.append(line)
            continue
        stripped = body.strip()
        if section is not None and stripped and stripped[0] not in ";#":
            km = _CONFIG_KEY_RE.match(stripped)
            if km:
                key = km.group("key").strip()
                sec_updates = remaining.get(section, {})
                if key.lower() in sec_updates:
                    out.append(f"{key} = {sec_updates.pop(key.lower())}{newline or chr(10)}")
                    continue
        out.append(line)
    flush(section)
    for sec, kv in remaining.items():
        if kv:
            if out and out[-1].strip():
                out.append("\n")
            out.append(f"[{sec}]\n")
            out.extend(f"{k} = {v}\n" for k, v in kv.items())

    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8", newline="") as fh:
        fh.write("".join(out))
    os.replace(tmp_path, path)


class SettingsDialog:
    """
    Popup modal para editar config.ini desde la interfaz.

    Muestra una pestaña por sección con un campo por clave y su comentario
    del fichero como ayuda. Al guardar solo se reescriben las claves
    modificadas (se conservan comentarios y orden). Los cambios se aplican
    al reiniciar la aplicación.
    """

    SECTION_TITLES = {
        "LLM": "\U0001f9e0 LLM",
        "Workspace": "\U0001f4c1 Workspace",
        "Database": "\U0001f5c4 Base de datos",
        "Agent": "\U0001f916 Agente",
        "UI": "\U0001f3a8 Interfaz",
    }
    CHOICES = {
        ("LLM", "mode"): ("local", "http"),
        ("UI", "titlebar_style"): ("system", "dark", "accent", "custom"),
    }

    def __init__(self, dashboard: "Dashboard") -> None:
        self.dashboard = dashboard
        root = dashboard.root
        self._vars: Dict[Tuple[str, str], StringVar] = {}
        self._initial: Dict[Tuple[str, str], str] = {}

        self.window = Toplevel(root)
        self.window.title("Ajustes")
        self.window.geometry("820x680")
        self.window.minsize(600, 400)
        self.window.configure(background=CONFIG.ui_bg_color)
        self.window.transient(root)

        if CONFIG.ui_custom_titlebar:
            try:
                self.window.overrideredirect(True)
                _force_taskbar_visibility(self.window)
                CustomTitleBar(
                    self.window,
                    title="Ajustes",
                    icon="\u2699",
                    bg=CONFIG.ui_titlebar_color,
                    fg=CONFIG.ui_titlebar_text_color,
                    hover_bg=CONFIG.ui_button_hover_bg,
                    close_hover_bg=CONFIG.ui_button_danger_bg,
                    height=CONFIG.ui_custom_titlebar_height,
                    show_minimize=False,
                    show_maximize=False,
                    close_callback=self._close,
                ).pack(side="top", fill="x")
            except Exception:  # noqa: BLE001
                pass

        # El pie se empaqueta antes que las pestañas para que siempre quede visible.
        footer = ttk.Frame(self.window, style="TFrame", padding=10)
        footer.pack(side="bottom", fill="x")
        ttk.Label(
            footer,
            text="Los cambios se guardan en config.ini y se aplican al reiniciar Hercules.",
            style="TLabel",
        ).pack(side="left")
        RoundedButton(
            footer, text="Guardar", command=self._save,
            bg=CONFIG.ui_button_accent_bg, fg=CONFIG.ui_button_accent_fg,
            hover_bg=CONFIG.ui_button_accent_hover_bg,
            pressed_bg=CONFIG.ui_button_accent_pressed_bg,
            radius=CONFIG.ui_corner_radius, padding_x=16, padding_y=6,
        ).pack(side="right")
        RoundedButton(
            footer, text="Cancelar", command=self._close,
            bg=CONFIG.ui_button_bg, fg=CONFIG.ui_button_fg,
            hover_bg=CONFIG.ui_button_hover_bg,
            pressed_bg=CONFIG.ui_button_pressed_bg,
            radius=CONFIG.ui_corner_radius, padding_x=16, padding_y=6,
        ).pack(side="right", padx=(0, 8))

        notebook = ttk.Notebook(self.window)
        notebook.pack(side="top", fill="both", expand=True, padx=10, pady=(10, 0))
        self._build_tabs(notebook)

        self.window.bind("<Escape>", lambda _e: self._close())
        self.window.bind("<Control-s>", lambda _e: self._save())

        self.window.update_idletasks()
        try:
            x = root.winfo_rootx() + (root.winfo_width() - self.window.winfo_width()) // 2
            y = root.winfo_rooty() + (root.winfo_height() - self.window.winfo_height()) // 2
            self.window.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        except Exception:  # noqa: BLE001
            pass
        _bring_to_front(self.window)

    # --- Construcción ---

    def _build_tabs(self, notebook: ttk.Notebook) -> None:
        parser = CONFIG._parser
        scanned = _scan_config_file(CONFIG.path)
        sections = [s for s in self.SECTION_TITLES if parser.has_section(s)]
        sections += [s for s in parser.sections() if s not in sections]
        for sec in sections:
            described: Dict[str, str] = {}
            for key, desc in scanned.get(sec, []):
                described.setdefault(key, desc)
            keys = list(described) + [k for k in parser.options(sec) if k not in described]

            tab = ttk.Frame(notebook, style="Card.TFrame", padding=4)
            notebook.add(tab, text=self.SECTION_TITLES.get(sec, sec))
            inner = self.dashboard._make_scrollable_frame(tab)
            inner.columnconfigure(1, weight=1)
            for i, key in enumerate(keys):
                self._add_row(inner, i, sec, key, described.get(key, ""))

    def _add_row(self, parent: ttk.Frame, index: int, sec: str, key: str, desc: str) -> None:
        value = CONFIG._parser.get(sec, key, raw=True)
        var = StringVar(value=value)
        self._vars[(sec, key)] = var
        self._initial[(sec, key)] = value
        row = index * 2

        ttk.Label(parent, text=key, style="Card.TLabel").grid(
            row=row, column=0, sticky="w", padx=(8, 12), pady=(10, 0)
        )
        default = Config.DEFAULTS.get(sec, {}).get(key, "")
        choices = self.CHOICES.get((sec, key))
        if choices is None and (default.lower() in ("true", "false") or value.lower() in ("true", "false")):
            choices = ("true", "false")

        if choices:
            ttk.Combobox(
                parent, textvariable=var, values=choices, state="readonly"
            ).grid(row=row, column=1, sticky="ew", padx=(0, 8), pady=(10, 0))
        else:
            ttk.Entry(
                parent, textvariable=var, show="\u2022" if key == "api_key" else ""
            ).grid(row=row, column=1, sticky="ew", padx=(0, 8), pady=(10, 0))
            if _HEX_COLOR_RE.match(value) or _HEX_COLOR_RE.match(default):
                self._add_swatch(parent, row, var)

        if desc:
            ttk.Label(
                parent, text=desc, style="Muted.TLabel", wraplength=640, justify="left"
            ).grid(row=row + 1, column=0, columnspan=3, sticky="w", padx=8, pady=(2, 0))

    def _add_swatch(self, parent: ttk.Frame, row: int, var: StringVar) -> None:
        swatch = TkLabel(
            parent, width=4, cursor="hand2", relief="flat", borderwidth=0,
            highlightthickness=1, highlightbackground=CONFIG.ui_card_border_color,
        )
        swatch.grid(row=row, column=2, padx=(0, 8), pady=(10, 0), sticky="ns")

        def refresh(*_a: Any) -> None:
            try:
                self.window.winfo_rgb(var.get())
                swatch.configure(bg=var.get())
            except Exception:  # noqa: BLE001
                pass

        def pick(_e: Any) -> None:
            chosen = colorchooser.askcolor(color=var.get(), parent=self.window)[1]
            if chosen:
                var.set(chosen)

        var.trace_add("write", refresh)
        swatch.bind("<Button-1>", pick)
        refresh()

    # --- Acciones ---

    def _validate(self, sec: str, key: str, value: str) -> Optional[str]:
        """Devuelve un mensaje de error o None si el valor es válido."""
        if "%" in value:
            return "no puede contener '%'"
        default = Config.DEFAULTS.get(sec, {}).get(key)
        if default is None:
            return None
        try:
            if re.fullmatch(r"-?\d+", default):
                int(value)
            elif re.fullmatch(r"-?\d+\.\d+", default):
                float(value)
            elif default.lower() in ("true", "false"):
                if value.lower() not in ("true", "false"):
                    return "debe ser true o false"
            elif _HEX_COLOR_RE.match(default):
                if not (key.startswith("titlebar") and value.lower() == "system"):
                    self.window.winfo_rgb(value)
        except ValueError:
            return "debe ser un número" if not _HEX_COLOR_RE.match(default) else "color no válido"
        except Exception:  # noqa: BLE001
            return "color no válido (use nombre CSS o #RRGGBB)"
        return None

    def _save(self) -> None:
        updates: Dict[str, Dict[str, str]] = {}
        for (sec, key), var in self._vars.items():
            value = var.get().strip()
            if value == self._initial[(sec, key)]:
                continue
            error = self._validate(sec, key, value)
            if error:
                messagebox.showerror(
                    "Valor no válido", f"[{sec}] {key}: {error}", parent=self.window
                )
                return
            updates.setdefault(sec, {})[key] = value
        if not updates:
            self._close()
            return
        try:
            _update_config_file(CONFIG.path, updates)
        except OSError as exc:
            messagebox.showerror(
                "Error al guardar", f"No se pudo escribir {CONFIG.path}:\n{exc}", parent=self.window
            )
            return
        messagebox.showinfo(
            "Ajustes guardados",
            "Reinicia Hercules para aplicar los cambios.",
            parent=self.window,
        )
        self._close()

    def _close(self) -> None:
        self.window.destroy()


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
