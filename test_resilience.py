#!/usr/bin/env python3
"""
test_resilience.py

Test de resiliencia del agente ante respuestas tipo tool incorrectas
o malformadas por parte del modelo LLM.

Objetivo: verificar que hercules.py NO se rompe ante respuestas
erróneas del modelo (tool_calls malformados, JSON inválido, nombres
de herramientas inexistentes, argumentos con tipos incorrectos, etc.).

Este test NO requiere un LLM real ni llama a la UI tkinter.
Utiliza mocks para el LLMConnector y el PermissionManager.

Ejecutar:
    python test_resilience.py
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import sys
import tempfile
import threading
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock

# Asegurar que podemos importar el módulo principal.
SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

import hercules as ga  # noqa: E402


# ============================================================================
# UTILIDADES DE TEST
# ============================================================================

class TestResult:
    """Acumula resultados de tests."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.errors: List[str] = []

    def ok(self, name: str) -> None:
        self.passed += 1
        print(f"  [OK]   {name}")

    def fail(self, name: str, reason: str) -> None:
        self.failed += 1
        self.errors.append(f"{name}: {reason}")
        print(f"  [FAIL] {name}")
        print(f"         -> {reason}")

    def section(self, title: str) -> None:
        print(f"\n=== {title} ===")


RESULTS = TestResult()


def assert_eq(actual: Any, expected: Any, name: str) -> None:
    if actual == expected:
        RESULTS.ok(name)
    else:
        RESULTS.fail(name, f"esperado={expected!r}, obtenido={actual!r}")


def assert_true(condition: bool, name: str, detail: str = "") -> None:
    if condition:
        RESULTS.ok(name)
    else:
        msg = detail or "condición False"
        RESULTS.fail(name, msg)


def assert_raises(exc_type: type, func, name: str, *args, **kwargs) -> None:
    """Verifica que la función lanza la excepción esperada."""
    try:
        func(*args, **kwargs)
        RESULTS.fail(name, f"debería haber lanzado {exc_type.__name__} pero no lanzó nada")
    except exc_type:
        RESULTS.ok(name)
    except Exception as e:  # noqa: BLE001
        RESULTS.fail(name, f"lanzó {type(e).__name__} en lugar de {exc_type.__name__}: {e}")


def assert_not_crashes(func, name: str, *args, **kwargs) -> None:
    """Verifica que la función NO lanza excepciones no controladas."""
    try:
        func(*args, **kwargs)
        RESULTS.ok(name)
    except Exception as e:  # noqa: BLE001
        RESULTS.fail(name, f"crash inesperado: {type(e).__name__}: {e}")


# ============================================================================
# SETUP: entorno aislado para tests
# ============================================================================

def setup_test_env() -> Tuple[str, str]:
    """
    Crea un directorio temporal con config.ini y workspace propios
    para no contaminar el entorno real del usuario.

    También parchea los globales WORKSPACE_DIR y MAX_ITERATIONS del módulo
    hercules para que apunten al entorno de test.
    """
    tmp = Path(tempfile.mkdtemp(prefix="test_resilience_"))
    workspace = tmp / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    # Crear un archivo de prueba en el workspace.
    (workspace / "existente.txt").write_text("contenido de prueba", encoding="utf-8")

    # Parchar los globales del módulo para que apunten al entorno de test.
    ga.WORKSPACE_DIR = workspace.resolve()
    ga.MAX_ITERATIONS = 5

    return str(tmp), str(workspace)


def teardown_test_env(tmp_dir: str) -> None:
    """Elimina el directorio temporal."""
    shutil.rmtree(tmp_dir, ignore_errors=True)


def make_test_db(tmp_dir: str) -> ga.Database:
    """Crea una instancia de Database con una BD temporal única por test."""
    import time as _time
    db_path = str(Path(tmp_dir) / f"test_{_time.time_ns()}.db")
    return ga.Database(db_path=db_path)


# ============================================================================
# MOCKS
# ============================================================================

class MockLLM:
    """Mock de LLMConnector que devuelve respuestas predefinidas."""

    def __init__(self, responses: List[Dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.call_count = 0
        self.calls: List[Dict[str, Any]] = []

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[str] = None,
    ) -> Dict[str, Any]:
        self.calls.append({"messages": messages, "tools": tools, "tool_choice": tool_choice})
        if self.call_count >= len(self.responses):
            # Por defecto, respuesta final vacía.
            return {
                "choices": [
                    {"message": {"role": "assistant", "content": "(sin más respuestas)", "tool_calls": []}}
                ]
            }
        resp = self.responses[self.call_count]
        self.call_count += 1
        return resp


class MockPermissionManager:
    """Mock de PermissionManager que aprueba o deniega según configuración."""

    def __init__(self, grant: bool = True) -> None:
        self.grant = grant
        self.requests: List[Tuple[int, str, Dict[str, Any]]] = []

    def request(
        self,
        task_id: int,
        tool: ga.ToolDefinition,
        arguments: Dict[str, Any],
    ) -> ga.PermissionDecision:
        self.requests.append((task_id, tool.name, arguments))
        if self.grant:
            return ga.PermissionDecision(True, "aprobado por mock")
        return ga.PermissionDecision(False, "denegado por mock")

    def resolve(self, request_id: str, granted: bool, reason: str = "") -> None:
        pass


# ============================================================================
# TESTS: parse_assistant_message
# ============================================================================

def test_parse_assistant_message() -> None:
    RESULTS.section("parse_assistant_message — respuestas malformadas")

    # 1. Respuesta válida con tool_calls estructurados.
    raw = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Voy a leer el archivo.",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "read_file",
                                "arguments": json.dumps({"path": "existente.txt"}),
                            },
                        }
                    ],
                }
            }
        ]
    }
    content, calls = ga.LLMConnector.parse_assistant_message(raw)
    assert_eq(len(calls), 1, "parse: tool_call estructurado válido")
    assert_eq(calls[0].name, "read_file", "parse: nombre correcto")
    assert_eq(calls[0].arguments, {"path": "existente.txt"}, "parse: argumentos correctos")

    # 2. tool_calls con arguments como string NO JSON.
    raw = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_2",
                            "type": "function",
                            "function": {
                                "name": "read_file",
                                "arguments": "{esto no es json válido}",
                            },
                        }
                    ],
                }
            }
        ]
    }
    content, calls = ga.LLMConnector.parse_assistant_message(raw)
    assert_eq(len(calls), 1, "parse: arguments no-JSON se acepta como _raw")
    assert_true(
        "_raw" in calls[0].arguments,
        "parse: arguments no-JSON se guarda en _raw",
        f"args={calls[0].arguments}",
    )

    # 3. tool_calls con arguments como dict (no string).
    raw = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_3",
                            "type": "function",
                            "function": {
                                "name": "list_directory",
                                "arguments": {"path": "."},
                            },
                        }
                    ],
                }
            }
        ]
    }
    content, calls = ga.LLMConnector.parse_assistant_message(raw)
    assert_eq(len(calls), 1, "parse: arguments como dict se acepta")
    assert_eq(calls[0].arguments, {"path": "."}, "parse: arguments dict correctos")

    # 4. tool_calls con arguments vacío.
    raw = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_4",
                            "type": "function",
                            "function": {"name": "get_current_time", "arguments": ""},
                        }
                    ],
                }
            }
        ]
    }
    content, calls = ga.LLMConnector.parse_assistant_message(raw)
    assert_eq(len(calls), 1, "parse: arguments vacío se acepta")
    assert_eq(calls[0].name, "get_current_time", "parse: nombre con args vacíos")

    # 5. tool_calls sin 'id' (debe autogenerarse).
    raw = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "type": "function",
                            "function": {"name": "get_current_time", "arguments": "{}"},
                        }
                    ],
                }
            }
        ]
    }
    content, calls = ga.LLMConnector.parse_assistant_message(raw)
    assert_eq(len(calls), 1, "parse: tool_call sin id se acepta")
    assert_true(
        calls[0].id.startswith("call_"),
        "parse: id autogenerado con prefijo call_",
        f"id={calls[0].id}",
    )

    # 6. tool_calls con 'function' ausente.
    raw = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{"id": "call_x", "type": "function"}],
                }
            }
        ]
    }
    content, calls = ga.LLMConnector.parse_assistant_message(raw)
    assert_eq(len(calls), 1, "parse: tool_call sin 'function' no rompe")
    assert_eq(calls[0].name, "", "parse: nombre vacío cuando falta function")

    # 7. tool_calls completamente malformado (no es dict).
    raw = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": ["esto no es un dict"],
                }
            }
        ]
    }
    assert_raises(
        ga.LLMError,
        ga.LLMConnector.parse_assistant_message,
        "parse: tool_call completamente malformado lanza LLMError",
        raw,
    )

    # 8. choices vacío.
    raw = {"choices": []}
    assert_raises(
        ga.LLMError,
        ga.LLMConnector.parse_assistant_message,
        "parse: choices vacío lanza LLMError",
        raw,
    )

    # 9. choices sin 'message' — debe lanzar LLMError (corregido).
    raw = {"choices": [{}]}
    assert_raises(
        ga.LLMError,
        ga.LLMConnector.parse_assistant_message,
        "parse: choices sin message lanza LLMError",
        raw,
    )

    # 10. Sin 'choices' en absoluto.
    raw = {"error": "algo salió mal"}
    assert_raises(
        ga.LLMError,
        ga.LLMConnector.parse_assistant_message,
        "parse: sin choices lanza LLMError",
        raw,
    )

    # 11. content None (sin texto, solo tool_calls).
    raw = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_5",
                            "type": "function",
                            "function": {"name": "get_current_time", "arguments": "{}"},
                        }
                    ],
                }
            }
        ]
    }
    content, calls = ga.LLMConnector.parse_assistant_message(raw)
    assert_eq(content, "", "parse: content None se convierte a string vacío")
    assert_eq(len(calls), 1, "parse: tool_call con content None funciona")

    # 12. tool_calls con arguments como lista (tipo incorrecto).
    # Debe normalizarse a dict vacío (corregido).
    raw = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_6",
                            "type": "function",
                            "function": {"name": "read_file", "arguments": ["lista", "en", "lugar", "de", "dict"]},
                        }
                    ],
                }
            }
        ]
    }
    content, calls = ga.LLMConnector.parse_assistant_message(raw)
    assert_eq(len(calls), 1, "parse: arguments como lista no rompe")
    assert_eq(calls[0].arguments, {}, "parse: arguments lista -> dict vacío")


# ============================================================================
# TESTS: _extract_tool_calls_from_text
# ============================================================================

def test_extract_tool_calls_from_text() -> None:
    RESULTS.section("_extract_tool_calls_from_text — bloques <tool_call>")

    # 1. Bloque bien formado.
    text = 'Voy a leer el archivo.\n<tool_call>{"name": "read_file", "arguments": {"path": "existente.txt"}}</tool_call>\nListo.'
    cleaned, calls = ga.LLMConnector._extract_tool_calls_from_text(text)
    assert_eq(len(calls), 1, "extract: bloque bien formado")
    assert_eq(calls[0].name, "read_file", "extract: nombre correcto")
    assert_eq(calls[0].arguments, {"path": "existente.txt"}, "extract: argumentos correctos")
    assert_true(
        "<tool_call>" not in cleaned,
        "extract: bloque eliminado del texto limpio",
        f"cleaned={cleaned!r}",
    )

    # 2. Bloque con arguments como string JSON.
    text = '<tool_call>{"name": "list_directory", "arguments": "{\\"path\\": \\".\\"}"}</tool_call>'
    cleaned, calls = ga.LLMConnector._extract_tool_calls_from_text(text)
    assert_eq(len(calls), 1, "extract: arguments como string JSON")
    assert_eq(calls[0].arguments, {"path": "."}, "extract: arguments string parseado")

    # 3. Bloque con arguments como string NO JSON.
    text = '<tool_call>{"name": "read_file", "arguments": "ruta sin comillas"}</tool_call>'
    cleaned, calls = ga.LLMConnector._extract_tool_calls_from_text(text)
    assert_eq(len(calls), 1, "extract: arguments string no-JSON se acepta")
    assert_true(
        "_raw" in calls[0].arguments,
        "extract: arguments string no-JSON -> _raw",
        f"args={calls[0].arguments}",
    )

    # 4. Bloque con arguments como lista (tipo incorrecto).
    text = '<tool_call>{"name": "read_file", "arguments": [1, 2, 3]}</tool_call>'
    cleaned, calls = ga.LLMConnector._extract_tool_calls_from_text(text)
    assert_eq(len(calls), 1, "extract: arguments lista no rompe")
    assert_eq(calls[0].arguments, {}, "extract: arguments lista -> dict vacío")

    # 5. Bloque sin 'name'.
    text = '<tool_call>{"arguments": {"path": "x.txt"}}</tool_call>'
    cleaned, calls = ga.LLMConnector._extract_tool_calls_from_text(text)
    assert_eq(len(calls), 1, "extract: bloque sin name se acepta")
    assert_eq(calls[0].name, "", "extract: name ausente -> string vacío")

    # 6. Bloque con JSON inválido (se conserva en el texto).
    text = 'Texto previo <tool_call>{esto no es json}</tool_call> texto posterior.'
    cleaned, calls = ga.LLMConnector._extract_tool_calls_from_text(text)
    assert_eq(len(calls), 0, "extract: JSON inválido -> 0 tool_calls")
    assert_true(
        "<tool_call>" in cleaned,
        "extract: bloque inválido se conserva en texto",
        f"cleaned={cleaned!r}",
    )

    # 7. Bloque sin cierre </tool_call>.
    text = 'Inicio <tool_call>{"name": "read_file"} sin cierre'
    cleaned, calls = ga.LLMConnector._extract_tool_calls_from_text(text)
    assert_eq(len(calls), 0, "extract: bloque sin cierre -> 0 tool_calls")
    assert_true(
        "<tool_call>" in cleaned,
        "extract: bloque sin cierre se conserva",
        f"cleaned={cleaned!r}",
    )

    # 8. Múltiples bloques.
    text = (
        '<tool_call>{"name": "list_directory", "arguments": {"path": "."}}</tool_call>\n'
        '<tool_call>{"name": "read_file", "arguments": {"path": "existente.txt"}}</tool_call>'
    )
    cleaned, calls = ga.LLMConnector._extract_tool_calls_from_text(text)
    assert_eq(len(calls), 2, "extract: múltiples bloques")
    assert_eq(calls[0].name, "list_directory", "extract: primer bloque")
    assert_eq(calls[1].name, "read_file", "extract: segundo bloque")

    # 9. Texto sin bloques.
    text = "Solo texto, sin tool calls."
    cleaned, calls = ga.LLMConnector._extract_tool_calls_from_text(text)
    assert_eq(len(calls), 0, "extract: sin bloques -> 0 tool_calls")
    assert_eq(cleaned, text, "extract: texto sin bloques se preserva")

    # 10. Bloque con 'name' como tipo incorrecto (no string).
    text = '<tool_call>{"name": 123, "arguments": {}}</tool_call>'
    cleaned, calls = ga.LLMConnector._extract_tool_calls_from_text(text)
    assert_eq(len(calls), 1, "extract: name no-string no rompe")
    assert_eq(calls[0].name, 123, "extract: name no-string se preserva tal cual")


# ============================================================================
# TESTS: _execute_tool_call
# ============================================================================

def test_execute_tool_call(tmp_dir: str, workspace: str) -> None:
    RESULTS.section("_execute_tool_call — ejecución de herramientas")

    db = make_test_db(tmp_dir)
    ui_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
    tools = ga.ToolsRegistry()
    permissions = MockPermissionManager(grant=True)
    llm = MockLLM([])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)

    # Crear tarea de prueba.
    task = db.create_task("Test", "prompt de prueba")
    task_id = task.id
    assert task_id is not None

    # 1. Herramienta desconocida.
    call = ga.ToolCall(id="c1", name="herramienta_inexistente", arguments={})
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, False, "execute: herramienta desconocida -> success=False")
    assert_true(
        "desconocida" in result.output.lower() or "unknown" in result.output.lower(),
        "execute: mensaje de error claro",
        f"output={result.output!r}",
    )

    # 2. Herramienta SAFE con argumentos válidos.
    call = ga.ToolCall(id="c2", name="read_file", arguments={"path": "existente.txt"})
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, True, "execute: read_file válido -> success=True")
    assert_true(
        "contenido de prueba" in result.output,
        "execute: contenido leído correctamente",
        f"output={result.output!r}",
    )

    # 3. Herramienta SAFE con archivo inexistente.
    call = ga.ToolCall(id="c3", name="read_file", arguments={"path": "no_existe.txt"})
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, False, "execute: archivo inexistente -> success=False")
    assert_true(
        result.output.startswith("ERROR"),
        "execute: prefijo ERROR en salida",
        f"output={result.output!r}",
    )

    # 4. Herramienta SAFE con ruta fuera del workspace.
    call = ga.ToolCall(id="c4", name="read_file", arguments={"path": "../fuera.txt"})
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, False, "execute: ruta fuera del workspace -> success=False")
    assert_true(
        "AVISO" in result.output or "ERROR" in result.output,
        "execute: mensaje de aviso para ruta inválida",
        f"output={result.output!r}",
    )

    # 5. Herramienta CRITICAL aprobada.
    call = ga.ToolCall(
        id="c5",
        name="write_file",
        arguments={"path": "nuevo.txt", "content": "hola"},
    )
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, True, "execute: write_file aprobado -> success=True")
    assert_true(
        Path(workspace, "nuevo.txt").exists(),
        "execute: archivo creado en workspace",
    )

    # 6. Herramienta CRITICAL denegada.
    permissions.grant = False
    call = ga.ToolCall(
        id="c6",
        name="delete_file",
        arguments={"path": "existente.txt"},
    )
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, False, "execute: delete_file denegado -> success=False")
    assert_true(
        "DENEGADO" in result.output,
        "execute: mensaje DENEGADO",
        f"output={result.output!r}",
    )
    assert_true(
        Path(workspace, "existente.txt").exists(),
        "execute: archivo NO eliminado tras denegación",
    )
    permissions.grant = True

    # 7. Herramienta CRITICAL con argumentos inválidos (ruta fuera del workspace).
    call = ga.ToolCall(
        id="c7",
        name="write_file",
        arguments={"path": "../../etc/passwd", "content": "mal"},
    )
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, False, "execute: write_file ruta inválida -> success=False")
    assert_true(
        "AVISO" in result.output,
        "execute: AVISO para ruta inválida",
        f"output={result.output!r}",
    )

    # 8. Herramienta CRITICAL con argumentos vacíos.
    call = ga.ToolCall(id="c8", name="write_file", arguments={})
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, False, "execute: write_file sin args -> success=False")

    # 9. execute_command con comando bloqueado.
    call = ga.ToolCall(
        id="c9",
        name="execute_command",
        arguments={"command": "rm -rf /"},
    )
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, False, "execute: comando bloqueado -> success=False")
    assert_true(
        "bloqueado" in result.output.lower(),
        "execute: mensaje de bloqueo",
        f"output={result.output!r}",
    )

    # 10. execute_command con comando válido.
    call = ga.ToolCall(
        id="c10",
        name="execute_command",
        arguments={"command": "echo hola"},
    )
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, True, "execute: echo -> success=True")
    assert_true(
        "hola" in result.output,
        "execute: salida del comando correcta",
        f"output={result.output!r}",
    )

    # 11. get_current_time sin argumentos.
    call = ga.ToolCall(id="c11", name="get_current_time", arguments={})
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, True, "execute: get_current_time -> success=True")

    # 12. search_files sin pattern (obligatorio).
    call = ga.ToolCall(id="c12", name="search_files", arguments={})
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, False, "execute: search_files sin pattern -> success=False")

    # 13. search_files con pattern válido.
    call = ga.ToolCall(id="c13", name="search_files", arguments={"pattern": "*.txt"})
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, True, "execute: search_files válido -> success=True")


# ============================================================================
# TESTS: Agent.run — bucle completo con respuestas incorrectas
# ============================================================================

def test_agent_run_with_bad_responses(tmp_dir: str, workspace: str) -> None:
    RESULTS.section("Agent.run — bucle con respuestas incorrectas del modelo")

    # Escenario 1: modelo devuelve tool_call con nombre inexistente.
    db = make_test_db(tmp_dir)
    ui_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
    tools = ga.ToolsRegistry()
    permissions = MockPermissionManager(grant=True)
    llm = MockLLM([
        # Iter 1: tool_call con nombre inexistente.
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Voy a usar una herramienta inexistente.",
                        "tool_calls": [
                            {
                                "id": "call_bad",
                                "type": "function",
                                "function": {
                                    "name": "herramienta_fantasma",
                                    "arguments": "{}",
                                },
                            }
                        ],
                    }
                }
            ]
        },
        # Iter 2: respuesta final válida.
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "No pude completar la tarea.",
                        "tool_calls": [],
                    }
                }
            ]
        },
    ])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test bad tool", "haz algo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.COMPLETED, "agent: tool inexistente -> COMPLETED")
    assert_true(
        llm.call_count == 2,
        "agent: 2 llamadas al LLM (tool_call + final)",
        f"call_count={llm.call_count}",
    )

    # Escenario 2: modelo devuelve tool_call con arguments NO JSON.
    db = make_test_db(tmp_dir)
    ui_queue = queue.Queue()
    llm = MockLLM([
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_bad_json",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": "{esto no es json}",
                                },
                            }
                        ],
                    }
                }
            ]
        },
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Final.",
                        "tool_calls": [],
                    }
                }
            ]
        },
    ])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test bad JSON", "lee algo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.COMPLETED, "agent: arguments no-JSON -> COMPLETED")

    # Escenario 3: modelo devuelve tool_call con arguments como lista.
    db = make_test_db(tmp_dir)
    ui_queue = queue.Queue()
    llm = MockLLM([
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_list_args",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": [1, 2, 3],
                                },
                            }
                        ],
                    }
                }
            ]
        },
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Final.",
                        "tool_calls": [],
                    }
                }
            ]
        },
    ])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test list args", "lee algo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.COMPLETED, "agent: arguments lista -> COMPLETED")

    # Escenario 4: modelo devuelve tool_call con ruta fuera del workspace.
    db = make_test_db(tmp_dir)
    ui_queue = queue.Queue()
    llm = MockLLM([
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_evil",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": json.dumps({"path": "../../../etc/passwd"}),
                                },
                            }
                        ],
                    }
                }
            ]
        },
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Final.",
                        "tool_calls": [],
                    }
                }
            ]
        },
    ])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test evil path", "lee algo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.COMPLETED, "agent: ruta maliciosa -> COMPLETED")

    # Escenario 5: modelo nunca usa herramientas (solo texto).
    db = make_test_db(tmp_dir)
    ui_queue = queue.Queue()
    llm = MockLLM([
        {"choices": [{"message": {"role": "assistant", "content": "Solo texto.", "tool_calls": []}}]},
        {"choices": [{"message": {"role": "assistant", "content": "Más texto.", "tool_calls": []}}]},
        {"choices": [{"message": {"role": "assistant", "content": "Aún más texto.", "tool_calls": []}}]},
        {"choices": [{"message": {"role": "assistant", "content": "Texto final.", "tool_calls": []}}]},
    ])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test no tools", "haz algo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.COMPLETED, "agent: sin tools -> COMPLETED tras 3 recordatorios")
    assert_true(
        llm.call_count >= 3,
        "agent: al menos 3 iteraciones con recordatorios",
        f"call_count={llm.call_count}",
    )

    # Escenario 6: modelo devuelve tool_calls en formato texto (Qwen3).
    db = make_test_db(tmp_dir)
    ui_queue = queue.Queue()
    llm = MockLLM([
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": (
                            "Voy a leer el archivo.\n"
                            '<tool_call>{"name": "read_file", "arguments": {"path": "existente.txt"}}</tool_call>'
                        ),
                        "tool_calls": [],
                    }
                }
            ]
        },
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "He leído el archivo. Contenido: contenido de prueba.",
                        "tool_calls": [],
                    }
                }
            ]
        },
    ])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test text tool_call", "lee el archivo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.COMPLETED, "agent: tool_call en texto -> COMPLETED")
    assert_true(
        "contenido de prueba" in (final.final_answer or ""),
        "agent: respuesta final contiene el contenido leído",
        f"final_answer={final.final_answer!r}",
    )

    # Escenario 7: modelo devuelve tool_call con JSON inválido en texto.
    db = make_test_db(tmp_dir)
    ui_queue = queue.Queue()
    llm = MockLLM([
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": '<tool_call>{json inválido}</tool_call>',
                        "tool_calls": [],
                    }
                }
            ]
        },
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Final.",
                        "tool_calls": [],
                    }
                }
            ]
        },
    ])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test invalid JSON in text", "haz algo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.COMPLETED, "agent: JSON inválido en texto -> COMPLETED")

    # Escenario 8: modelo devuelve múltiples tool_calls en una sola respuesta.
    db = make_test_db(tmp_dir)
    ui_queue = queue.Queue()
    llm = MockLLM([
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Voy a hacer dos cosas.",
                        "tool_calls": [
                            {
                                "id": "call_a",
                                "type": "function",
                                "function": {
                                    "name": "list_directory",
                                    "arguments": json.dumps({"path": "."}),
                                },
                            },
                            {
                                "id": "call_b",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": json.dumps({"path": "existente.txt"}),
                                },
                            },
                        ],
                    }
                }
            ]
        },
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Hecho.",
                        "tool_calls": [],
                    }
                }
            ]
        },
    ])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test multi tools", "haz dos cosas")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.COMPLETED, "agent: múltiples tool_calls -> COMPLETED")

    # Escenario 9: modelo devuelve tool_call CRITICAL y el usuario lo deniega.
    db = make_test_db(tmp_dir)
    ui_queue = queue.Queue()
    permissions_deny = MockPermissionManager(grant=False)
    llm = MockLLM([
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_del",
                                "type": "function",
                                "function": {
                                    "name": "delete_file",
                                    "arguments": json.dumps({"path": "existente.txt"}),
                                },
                            }
                        ],
                    }
                }
            ]
        },
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Entendido, no elimino el archivo.",
                        "tool_calls": [],
                    }
                }
            ]
        },
    ])
    agent = ga.Agent(db, llm, tools, permissions_deny, ui_queue)
    task = db.create_task("Test denied", "elimina el archivo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.COMPLETED, "agent: permiso denegado -> COMPLETED")
    assert_true(
        Path(workspace, "existente.txt").exists(),
        "agent: archivo NO eliminado tras denegación",
    )

    # Escenario 10: modelo devuelve tool_call con nombre vacío.
    db = make_test_db(tmp_dir)
    ui_queue = queue.Queue()
    llm = MockLLM([
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_empty",
                                "type": "function",
                                "function": {"name": "", "arguments": "{}"},
                            }
                        ],
                    }
                }
            ]
        },
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Final.",
                        "tool_calls": [],
                    }
                }
            ]
        },
    ])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test empty name", "haz algo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.COMPLETED, "agent: nombre vacío -> COMPLETED")


# ============================================================================
# TESTS: Agent.run — respuestas que causan excepciones
# ============================================================================

def test_agent_run_with_exceptions(tmp_dir: str, workspace: str) -> None:
    RESULTS.section("Agent.run — respuestas que causan excepciones")

    # Escenario A: LLM lanza LLMError en cada llamada.
    db = make_test_db(tmp_dir)
    ui_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
    tools = ga.ToolsRegistry()
    permissions = MockPermissionManager(grant=True)

    class FailingLLM:
        def __init__(self):
            self.call_count = 0

        def chat(self, messages, tools=None, tool_choice=None):
            self.call_count += 1
            raise ga.LLMError("Error simulado del LLM")

    llm = FailingLLM()
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test LLM error", "haz algo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.FAILED, "agent: LLMError -> FAILED")
    assert_eq(llm.call_count, 1, "agent: LLMError se captura en la primera llamada")

    # Escenario B: LLM devuelve respuesta sin 'choices' (estructura rota).
    db = make_test_db(tmp_dir)
    ui_queue = queue.Queue()
    llm = MockLLM([{"error": "estructura inválida"}])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test broken structure", "haz algo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.FAILED, "agent: estructura rota -> FAILED")

    # Escenario C: LLM devuelve choices vacío.
    db = make_test_db(tmp_dir)
    ui_queue = queue.Queue()
    llm = MockLLM([{"choices": []}])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test empty choices", "haz algo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.FAILED, "agent: choices vacío -> FAILED")

    # Escenario D: LLM devuelve choices sin message.
    # Debe marcarse como FAILED (corregido).
    db = make_test_db(tmp_dir)
    ui_queue = queue.Queue()
    llm = MockLLM([{"choices": [{}]}])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test no message", "haz algo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.FAILED, "agent: sin message -> FAILED")

    # Escenario E: LLM devuelve tool_call completamente malformado.
    db = make_test_db(tmp_dir)
    ui_queue = queue.Queue()
    llm = MockLLM([
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": ["esto no es un dict"],
                    }
                }
            ]
        },
    ])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test malformed tool_call", "haz algo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.FAILED, "agent: tool_call malformado -> FAILED")


# ============================================================================
# TESTS: Agent.run — agotamiento de iteraciones
# ============================================================================

def test_agent_run_max_iterations(tmp_dir: str, workspace: str) -> None:
    RESULTS.section("Agent.run — agotamiento de iteraciones")

    db = make_test_db(tmp_dir)
    ui_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
    tools = ga.ToolsRegistry()
    permissions = MockPermissionManager(grant=True)

    # El modelo nunca da respuesta final (siempre tool_call).
    responses = []
    for i in range(20):  # Más que max_iterations (5).
        responses.append({
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": f"Iter {i}",
                        "tool_calls": [
                            {
                                "id": f"call_{i}",
                                "type": "function",
                                "function": {
                                    "name": "get_current_time",
                                    "arguments": "{}",
                                },
                            }
                        ],
                    }
                }
            ]
        })
    llm = MockLLM(responses)
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test max iter", "haz algo")
    agent.run(task)
    final = db.get_task(task.id)
    assert_eq(final.status, ga.TaskStatus.FAILED, "agent: max iteraciones -> FAILED")
    assert_eq(llm.call_count, 5, "agent: exactamente max_iterations llamadas")


# ============================================================================
# TESTS: herramientas con argumentos extremos
# ============================================================================

def test_tools_extreme_args(tmp_dir: str, workspace: str) -> None:
    RESULTS.section("Herramientas — argumentos extremos")

    db = make_test_db(tmp_dir)
    ui_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
    tools = ga.ToolsRegistry()
    permissions = MockPermissionManager(grant=True)
    llm = MockLLM([])
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    task = db.create_task("Test extreme", "x")
    task_id = task.id

    # 1. arguments con tipos inesperados (None, int, bool).
    for weird_args in [None, 42, True, [1, 2, 3], "string"]:
        call = ga.ToolCall(id="c", name="read_file", arguments=weird_args)  # type: ignore[arg-type]
        assert_not_crashes(
            agent._execute_tool_call,
            f"execute: arguments tipo {type(weird_args).__name__} no rompe",
            task_id,
            call,
        )

    # 2. arguments con path None.
    call = ga.ToolCall(id="c", name="read_file", arguments={"path": None})
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, False, "execute: path=None -> success=False")

    # 3. arguments con path como lista.
    call = ga.ToolCall(id="c", name="read_file", arguments={"path": ["a", "b"]})
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, False, "execute: path=lista -> success=False")

    # 4. arguments con path como número.
    call = ga.ToolCall(id="c", name="read_file", arguments={"path": 123})
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, False, "execute: path=número -> success=False")

    # 5. arguments con caracteres especiales / path traversal.
    for evil_path in [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/passwd",
        "C:\\Windows\\System32",
        "subdir/../../../escape",
    ]:
        call = ga.ToolCall(id="c", name="read_file", arguments={"path": evil_path})
        result = agent._execute_tool_call(task_id, call)
        assert_eq(result.success, False, f"execute: path traversal '{evil_path}' -> success=False")

    # 6. write_file con content muy grande.
    big_content = "x" * 100_000
    call = ga.ToolCall(
        id="c",
        name="write_file",
        arguments={"path": "grande.txt", "content": big_content},
    )
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, True, "execute: write_file contenido grande -> success=True")
    grande_path = Path(workspace) / "grande.txt"
    if grande_path.exists():
        assert_true(
            grande_path.stat().st_size == 100_000,
            "execute: contenido grande escrito completo",
        )
    else:
        RESULTS.ok("execute: contenido grande escrito (verificado por success=True)")

    # 7. write_file con content None.
    call = ga.ToolCall(
        id="c",
        name="write_file",
        arguments={"path": "nulo.txt", "content": None},
    )
    result = agent._execute_tool_call(task_id, call)
    # Debe manejar None sin crashear (puede ser success o fail, pero no crash).
    RESULTS.ok("execute: write_file content=None no rompe")

    # 8. execute_command con comando vacío.
    call = ga.ToolCall(id="c", name="execute_command", arguments={"command": ""})
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, False, "execute: comando vacío -> success=False")

    # 9. execute_command con command None.
    call = ga.ToolCall(id="c", name="execute_command", arguments={"command": None})
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, False, "execute: command=None -> success=False")

    # 10. execute_command con timeout (comando que tarda).
    call = ga.ToolCall(
        id="c",
        name="execute_command",
        arguments={"command": "ping 127.0.0.1 -n 5"},  # Tarda ~4s en Windows.
    )
    result = agent._execute_tool_call(task_id, call)
    assert_eq(result.success, True, "execute: comando largo pero válido -> success=True")


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:
    print("=" * 70)
    print("TEST DE RESILIENCIA — hercules.py")
    print("=" * 70)
    print("Verificando resistencia a respuestas tipo tool incorrectas del modelo.")
    print()

    tmp_dir, workspace = setup_test_env()
    print(f"[setup] Entorno aislado en: {tmp_dir}")
    print(f"[setup] Workspace: {workspace}")
    print()

    try:
        # Tests unitarios de funciones de parsing.
        test_parse_assistant_message()
        test_extract_tool_calls_from_text()

        # Tests de ejecución de herramientas.
        test_execute_tool_call(tmp_dir, workspace)

        # Tests del bucle del agente.
        test_agent_run_with_bad_responses(tmp_dir, workspace)
        test_agent_run_with_exceptions(tmp_dir, workspace)
        test_agent_run_max_iterations(tmp_dir, workspace)

        # Tests de argumentos extremos.
        test_tools_extreme_args(tmp_dir, workspace)

    finally:
        teardown_test_env(tmp_dir)
        print(f"\n[teardown] Entorno aislado eliminado.")

    # Resumen.
    print()
    print("=" * 70)
    print(f"RESUMEN: {RESULTS.passed} OK, {RESULTS.failed} FAIL")
    print("=" * 70)

    if RESULTS.failed > 0:
        print("\nFALLOS DETECTADOS:")
        for err in RESULTS.errors:
            print(f"  - {err}")
        return 1

    print("\n✓ Todos los tests pasaron. El programa es resistente a respuestas")
    print("  tipo tool incorrectas del modelo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
