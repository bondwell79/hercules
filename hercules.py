#!/usr/bin/env python3
"""
hercules.py

Motor de Hercules: gestión de tareas LLM, herramientas y permisos HITL.
La interfaz Qt se implementa en ``hercules_qt.py``.

Características:
    - Gestión del ciclo de vida de tareas (PENDING, IN_PROGRESS, AWAITING_APPROVAL,
      COMPLETED, FAILED, CANCELLED).
    - Control de seguridad humano: validación manual de acciones sensibles.
    - Trazabilidad completa: historial estructurado y auditable por tarea.
    - Persistencia local en SQLite.
    - Conector HTTP para LLMs compatibles con OpenAI / Ollama.

Configuración mediante variables de entorno:
    LLM_BASE_URL   - URL base del endpoint (por defecto: http://localhost:11434/v1)
    LLM_API_KEY    - Clave de API (opcional para Ollama)
    LLM_USER_AGENT - User-Agent enviado al endpoint HTTP
    LLM_MODEL      - Modelo a utilizar (por defecto: llama3.2)
    LLM_TIMEOUT    - Timeout en segundos (por defecto: 120)
"""

from __future__ import annotations
import re
import base64
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
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


from typing import Any, Callable, Dict, List, Optional, Tuple

import computer_tools


# ============================================================================
# CONFIGURACIÓN (config.ini + variables de entorno)
# ============================================================================

CONFIG_PATH = os.environ.get("HERCULES_CONFIG", "config.ini")
VERSION = "1.50"
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
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
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
            # Opciones heredadas de la interfaz Tk; se conservan para
            # no descartar configuraciones existentes.
            "custom_titlebar": "true",
            # Altura heredada de la barra personalizada (20-60).
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
    def llm_user_agent(self) -> str:
        return os.environ.get("LLM_USER_AGENT", self._parser.get("LLM", "user_agent"))

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
        Opción heredada de Tk, retenida para compatibilidad con config.ini.
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
        """Altura heredada de la barra Tk, retenida para compatibilidad."""
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
LLM_USER_AGENT = CONFIG.llm_user_agent
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
        user_agent: str = LLM_USER_AGENT,
    ) -> None:
        self.mode = mode.strip().lower()
        if self.mode not in self._VALID_MODES:
            raise LLMError(
                f"Modo LLM inválido: '{mode}'. Válidos: {self._VALID_MODES}"
            )
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.user_agent = user_agent
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
                **({"User-Agent": self.user_agent} if self.user_agent else {}),
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


def tool_read_binary_file(args: Dict[str, Any]) -> str:
    path = _resolve_workspace_path(args.get("path", ""))
    if not path.exists():
        return f"ERROR: el archivo no existe: {path}"
    if not path.is_file():
        return f"ERROR: no es un archivo: {path}"
    try:
        with path.open("rb") as file:
            content = file.read(50_001)
    except Exception as e:  # noqa: BLE001
        return f"ERROR al leer {path}: {e}"
    truncated = len(content) > 50_000
    content = content[:50_000]
    result = f"Base64 ({len(content)} bytes): {base64.b64encode(content).decode('ascii')}"
    if truncated:
        result += "\n... [truncado a 50000 bytes]"
    return result


def tool_read_binary_hex(args: Dict[str, Any]) -> str:
    path = _resolve_workspace_path(args.get("path", ""))
    offset = args.get("offset", 0)
    length = args.get("length", 256)
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        return "ERROR: 'offset' debe ser un entero no negativo"
    if isinstance(length, bool) or not isinstance(length, int) or length < 0:
        return "ERROR: 'length' debe ser un entero no negativo"
    if length > 4096:
        return "ERROR: 'length' no puede superar 4096 bytes"
    if not path.exists():
        return f"ERROR: el archivo no existe: {path}"
    if not path.is_file():
        return f"ERROR: no es un archivo: {path}"
    try:
        with path.open("rb") as file:
            file.seek(offset)
            content = file.read(length)
    except Exception as e:  # noqa: BLE001
        return f"ERROR al leer {path}: {e}"

    lines = []
    for row_offset in range(0, len(content), 16):
        row = content[row_offset : row_offset + 16]
        hex_bytes = " ".join(f"{byte:02x}" for byte in row)
        ascii_bytes = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in row)
        lines.append(f"{offset + row_offset:08x}  {hex_bytes:<47}  |{ascii_bytes}|")
    return "\n".join(lines) if lines else "(sin datos en el rango solicitado)"


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
            encoding="utf-8",
            errors="replace",
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
                name="read_binary_file",
                description=(
                    "Lee un archivo binario del workspace y devuelve su contenido codificado en Base64 "
                    "(máximo 50000 bytes). Argumentos: path (ruta del archivo)."
                ),
                risk=RiskLevel.SAFE,
                parameters={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Ruta del archivo binario a leer.",
                        }
                    },
                    "required": ["path"],
                },
                runner=tool_read_binary_file,
            )
        )
        self.register(
            ToolDefinition(
                name="read_binary_hex",
                description=(
                    "Lee un rango de un archivo binario y lo muestra como volcado hexadecimal con ASCII. "
                    "Argumentos: path, offset (opcional, por defecto 0), length (opcional, por defecto 256; máximo 4096)."
                ),
                risk=RiskLevel.SAFE,
                parameters={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Ruta del archivo binario a leer.",
                        },
                        "offset": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Posición inicial en bytes.",
                        },
                        "length": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 4096,
                            "description": "Cantidad máxima de bytes a leer.",
                        },
                    },
                    "required": ["path"],
                },
                runner=tool_read_binary_hex,
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
                risk=RiskLevel.SAFE,
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
                risk=RiskLevel.SAFE,
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
                risk=RiskLevel.SAFE,
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
                risk=RiskLevel.SAFE,
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
- read_file(path): Lee el contenido de texto de un archivo del workspace.
- read_binary_file(path): Lee un archivo binario y devuelve su contenido en Base64 (máximo 50000 bytes).
- read_binary_hex(path, offset, length): Muestra un rango de un archivo binario como volcado hexadecimal con ASCII.
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
# EVENTOS Y HELPERS COMPARTIDOS CON LA INTERFAZ QT
# ============================================================================
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




class Dashboard:
    """Shared approval and history helpers used by the Qt dashboard."""

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


# ============================================================================
# DATOS COMPARTIDOS DEL DIÁLOGO DE BIENVENIDA QT
# ============================================================================

class WelcomeDialog:
    """Data shared with the Qt welcome dialog."""

    ASCII_ART = r"""
██╗  ██╗███████╗██████╗  ██████╗██╗   ██╗██╗     ███████╗███████╗
██║  ██║██╔════╝██╔══██╗██╔════╝██║   ██║██║     ██╔════╝██╔════╝
███████║█████╗  ██████╔╝██║     ██║   ██║██║     █████╗  ███████╗
██╔══██║██╔══╝  ██╔══██╗██║     ██║   ██║██║     ██╔══╝  ╚════██║
██║  ██║███████╗██║  ██║╚██████╗╚██████╔╝███████╗███████╗███████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝
    """


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




# ============================================================================
# PUNTO DE ENTRADA
# ============================================================================

def main() -> None:
    try:
        from hercules_qt import main as run_qt_ui
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("PySide6"):
            install_command = (
                f'"{sys.executable}" -m pip install '
                "PySide6==6.12.0 PySide6-WebEngine==6.12.0.140"
            )
            raise SystemExit(
                "No se encuentra Qt (PySide6) en este intérprete.\n"
                "Instala las dependencias usando el mismo Python con el que "
                "ejecutas Hercules:\n"
                f"  {install_command}\n"
                "En Windows también puedes iniciar Hercules con run.bat."
            ) from exc

    run_qt_ui(core_module=sys.modules[__name__])


if __name__ == "__main__":
    main()
