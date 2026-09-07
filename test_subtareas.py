#!/usr/bin/env python3
"""
test_subtareas.py

Test del orquestador de subtareas (TaskOrchestrator).

Verifica que el sistema de descomposición de tareas funciona correctamente:

    1. Una tarea del usuario se divide en 3 subtareas:
       REQUIREMENTS → DEVELOPMENT → EXECUTION_VERIFICATION.

    2. Si EXECUTION_VERIFICATION falla, se crea una subtarea
       RECTIFICATION y se vuelve a ejecutar EXECUTION_VERIFICATION.

    3. El ciclo se repite hasta que la verificación sea exitosa o se
       alcance max_rectification_retries.

    4. Las subtareas quedan registradas en la BD con parent_task_id
       apuntando a la tarea padre.

    5. La tarea padre se marca como COMPLETED solo si la verificación
       final es exitosa; en caso contrario, como FAILED.

Este test NO requiere un LLM real ni la UI tkinter.

Ejecutar:
    python test_subtareas.py
"""

from __future__ import annotations

import queue
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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


# ============================================================================
# SETUP: entorno aislado para tests
# ============================================================================

def setup_test_env() -> Tuple[str, str]:
    """Crea un directorio temporal con workspace propio."""
    tmp = Path(tempfile.mkdtemp(prefix="test_subtareas_"))
    workspace = tmp / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    ga.WORKSPACE_DIR = workspace.resolve()
    ga.MAX_ITERATIONS = 10
    return str(tmp), str(workspace)


def make_test_db(tmp_dir: str) -> ga.Database:
    """Crea una instancia de Database con una BD temporal única por test."""
    db_path = str(Path(tmp_dir) / f"test_{time.time_ns()}.db")
    return ga.Database(db_path=db_path)


def teardown_test_env(tmp_dir: str) -> None:
    """Elimina el directorio temporal."""
    shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================================
# MOCKS
# ============================================================================

class ScriptedLLM:
    """
    Mock de LLMConnector que devuelve respuestas según un guion.

    El guion es un diccionario indexado por tipo de subtarea:
        {"REQUIREMENTS": [...], "DEVELOPMENT": [...], ...}

    Cada entrada es una lista de respuestas que se consumen secuencialmente
    SOLO para esa instancia de subtarea. El mock detecta qué subtarea se
    está ejecutando inspeccionando el contenido del prompt del usuario,
    y detecta el inicio de una nueva instancia cuando los mensajes se
    resetean (solo system + user).

    Para distinguir entre instancias de la misma subtarea (por ejemplo,
    dos verificaciones consecutivas), el guion puede usar la clave
    ``"<SUBTASK>_N"`` donde N es el número de instancia (0, 1, 2...).
    Si no existe esa clave, se usa ``<SUBTASK>`` como fallback.
    """

    def __init__(self, script: Dict[str, List[Dict[str, Any]]]) -> None:
        self.script = script
        # Contador de instancias por tipo de subtarea.
        self._instance_counters: Dict[str, int] = {}
        # Contador de llamadas dentro de la instancia actual.
        self._call_counters: Dict[str, int] = {}
        self.calls: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def _detect_subtask(self, messages: List[Dict[str, Any]]) -> str:
        """Detecta qué subtarea se está ejecutando por el contenido del prompt."""
        if len(messages) < 2:
            return "UNKNOWN"
        user_msg = messages[1].get("content", "")
        if "NO ejecutes ninguna acción" in user_msg:
            return "REQUIREMENTS"
        if "modo corrección" in user_msg.lower():
            return "RECTIFICATION"
        if "verificador" in user_msg.lower() and "SOLUCIÓN IMPLEMENTADA" in user_msg:
            return "EXECUTION_VERIFICATION"
        if "desarrollador" in user_msg.lower() and "REQUISITOS TÉCNICOS" in user_msg:
            return "DEVELOPMENT"
        return "UNKNOWN"

    def _resolve_script_key(self, subtask: str) -> Optional[str]:
        """Resuelve la clave del guion para la instancia actual de la subtarea."""
        instance = self._instance_counters.get(subtask, 0)
        # Buscar clave específica de instancia: "<SUBTASK>_<N>"
        instance_key = f"{subtask}_{instance}"
        if instance_key in self.script:
            return instance_key
        # Fallback a la clave genérica.
        if subtask in self.script:
            return subtask
        return None

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[str] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            self.calls.append(
                {"messages": messages, "tools": tools, "tool_choice": tool_choice}
            )
            subtask = self._detect_subtask(messages)
            # Detectar inicio de nueva instancia: si los mensajes tienen
            # solo system + user (2 mensajes), es una nueva instancia.
            # El contador de instancias empieza en 0 para la primera.
            if len(messages) == 2 and subtask != "UNKNOWN":
                if subtask not in self._instance_counters:
                    self._instance_counters[subtask] = 0
                else:
                    self._instance_counters[subtask] += 1
                self._call_counters[subtask] = 0
            script_key = self._resolve_script_key(subtask)
            if script_key is None:
                return _final_response("(sin más respuestas)")
            responses = self.script[script_key]
            idx = self._call_counters.get(subtask, 0)
            if idx >= len(responses):
                # Guion agotado: repetir la última respuesta.
                resp = responses[-1]
            else:
                resp = responses[idx]
                self._call_counters[subtask] = idx + 1
            return _build_response(resp)


def _final_response(content: str) -> Dict[str, Any]:
    """Construye una respuesta final sin tool_calls."""
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": content,
                    "tool_calls": [],
                }
            }
        ]
    }


def _tool_response(name: str, args: Dict[str, Any], content: str = "OK") -> Dict[str, Any]:
    """Construye una respuesta con un tool_call."""
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": f"call_{name}_{time.time_ns()}",
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": _json_dumps(args),
                            },
                        }
                    ],
                }
            }
        ]
    }


def _json_dumps(obj: Any) -> str:
    import json
    return json.dumps(obj, ensure_ascii=False)


def _build_response(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Construye una respuesta a partir de una especificación del guion."""
    if "final" in spec:
        return _final_response(spec["final"])
    if "tool" in spec:
        return _tool_response(spec["tool"], spec.get("args", {}))
    return _final_response("")


class MockPermissionManager:
    """Mock de PermissionManager que aprueba todas las solicitudes."""

    def __init__(self, grant: bool = True) -> None:
        self.grant = grant

    def request(
        self,
        task_id: int,
        tool: ga.ToolDefinition,
        arguments: Dict[str, Any],
    ) -> ga.PermissionDecision:
        if self.grant:
            return ga.PermissionDecision(True, "aprobado por mock")
        return ga.PermissionDecision(False, "denegado por mock")

    def resolve(self, request_id: str, granted: bool, reason: str = "") -> None:
        pass


# ============================================================================
# HELPERS
# ============================================================================

def make_orchestrator(
    db: ga.Database,
    script: Dict[str, List[Dict[str, Any]]],
    max_retries: int = 3,
) -> Tuple[ga.TaskOrchestrator, ScriptedLLM]:
    """Crea un orquestador con un MockLLM guionizado."""
    ui_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
    tools = ga.ToolsRegistry()
    permissions = MockPermissionManager(grant=True)
    llm = ScriptedLLM(script)
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    orchestrator = ga.TaskOrchestrator(
        db=db,
        agent=agent,
        ui_queue=ui_queue,
        max_retries=max_retries,
    )
    return orchestrator, llm


def run_orchestrator(
    db: ga.Database,
    orchestrator: ga.TaskOrchestrator,
    prompt: str,
    timeout: float = 30.0,
) -> ga.Task:
    """Lanza el orquestador en un hilo y espera a que termine."""
    title = prompt.splitlines()[0][:80]
    parent = db.create_task(title=title, prompt=prompt)
    thread = threading.Thread(
        target=orchestrator.run,
        args=(parent,),
        daemon=True,
        name=f"orchestrator-{parent.id}",
    )
    thread.start()
    thread.join(timeout=timeout)
    return parent


# ============================================================================
# TESTS
# ============================================================================

def test_happy_path_no_rectification(tmp_dir: str, workspace: str) -> None:
    """
    Escenario feliz: las 3 subtareas se ejecutan correctamente y la
    verificación es exitosa en el primer intento. No debe haber
    subtareas de rectificación.
    """
    RESULTS.section("Flujo feliz: 3 subtareas, verificación exitosa al primer intento")

    db = make_test_db(tmp_dir)
    script = {
        "REQUIREMENTS": [
            {"final": "Requisitos:\n- Crear archivo hola.txt con contenido 'Hola mundo'."},
        ],
        "DEVELOPMENT": [
            {"tool": "write_file", "args": {"path": "hola.txt", "content": "Hola mundo"}},
            {"final": "He creado hola.txt con el contenido solicitado."},
        ],
        "EXECUTION_VERIFICATION": [
            {"tool": "read_file", "args": {"path": "hola.txt"}},
            {"final": "VERIFICACIÓN EXITOSA: el archivo hola.txt contiene 'Hola mundo'."},
        ],
    }
    orchestrator, _ = make_orchestrator(db, script)
    parent = run_orchestrator(db, orchestrator, "Crea un archivo hola.txt")

    # Verificar estado de la tarea padre.
    parent_after = db.get_task(parent.id)
    assert_eq(parent_after.status, ga.TaskStatus.COMPLETED, "tarea padre → COMPLETED")
    assert_true(
        parent_after.final_answer is not None
        and parent_after.final_answer.startswith("VERIFICACIÓN EXITOSA"),
        "final_answer de la tarea padre comienza con VERIFICACIÓN EXITOSA",
    )

    # Verificar que se crearon exactamente 3 subtareas.
    subtasks = db.list_subtasks(parent.id)
    assert_eq(len(subtasks), 3, "se crean exactamente 3 subtareas")

    # Verificar el orden y tipo de las subtareas.
    expected_types = [
        ga.SubtaskType.REQUIREMENTS,
        ga.SubtaskType.DEVELOPMENT,
        ga.SubtaskType.EXECUTION_VERIFICATION,
    ]
    actual_types = [st.subtask_type for st in subtasks]
    assert_eq(actual_types, expected_types, "orden y tipo de subtareas correcto")

    # Verificar que todas las subtareas están COMPLETED.
    for st in subtasks:
        assert_eq(st.status, ga.TaskStatus.COMPLETED, f"subtarea #{st.id} → COMPLETED")

    # Verificar que NO hay subtareas de rectificación.
    rectifications = [
        st for st in subtasks if st.subtask_type == ga.SubtaskType.RECTIFICATION
    ]
    assert_eq(len(rectifications), 0, "no hay subtareas de rectificación")


def test_one_rectification_cycle(tmp_dir: str, workspace: str) -> None:
    """
    La verificación falla en el primer intento pero tiene éxito tras
    una rectificación. Debe haber 4 subtareas (3 + 1 rectificación)
    y la tarea padre debe quedar COMPLETED.
    """
    RESULTS.section("Un ciclo de rectificación: verificación falla → rectifica → verifica OK")

    db = make_test_db(tmp_dir)
    failure_msg = "VERIFICACIÓN FALLIDA: el archivo test.txt no existe."
    success_msg = "VERIFICACIÓN EXITOSA: test.txt existe y contiene 'test'."
    script = {
        "REQUIREMENTS": [
            {"final": "Requisitos:\n- Crear archivo test.txt con contenido 'test'."},
        ],
        "DEVELOPMENT": [
            {"tool": "write_file", "args": {"path": "test.txt", "content": "test"}},
            {"final": "He creado test.txt."},
        ],
        # Primera verificación (instancia 0): siempre falla.
        "EXECUTION_VERIFICATION_0": [
            {"final": failure_msg},
        ],
        "RECTIFICATION": [
            {"tool": "write_file", "args": {"path": "test.txt", "content": "test"}},
            {"final": "He recreado test.txt."},
        ],
        # Segunda verificación (instancia 1): siempre tiene éxito.
        "EXECUTION_VERIFICATION_1": [
            {"final": success_msg},
        ],
    }

    orchestrator, _ = make_orchestrator(db, script, max_retries=3)
    parent = run_orchestrator(db, orchestrator, "Crea test.txt")

    parent_after = db.get_task(parent.id)
    assert_eq(parent_after.status, ga.TaskStatus.COMPLETED, "tarea padre → COMPLETED tras rectificación")

    subtasks = db.list_subtasks(parent.id)
    # Flujo: REQUIREMENTS + DEVELOPMENT + VERIFICATION(0) + RECTIFICATION(0) + VERIFICATION(1)
    assert_eq(len(subtasks), 5, "se crean 5 subtareas (3 + 1 rectificación + 1 verificación extra)")

    rectifications = [
        st for st in subtasks if st.subtask_type == ga.SubtaskType.RECTIFICATION
    ]
    assert_eq(len(rectifications), 1, "hay exactamente 1 subtarea de rectificación")

    verifications = [
        st for st in subtasks if st.subtask_type == ga.SubtaskType.EXECUTION_VERIFICATION
    ]
    assert_eq(len(verifications), 2, "hay 2 subtareas de verificación")
    assert_eq(verifications[0].attempt_number, 0, "primera verificación → attempt 0")
    assert_eq(verifications[1].attempt_number, 1, "segunda verificación → attempt 1")


def test_max_retries_exhausted(tmp_dir: str, workspace: str) -> None:
    """
    La verificación falla siempre. Tras agotar max_retries, la tarea
    padre debe quedar FAILED.
    """
    RESULTS.section("Agotamiento de reintentos: verificación siempre falla")

    db = make_test_db(tmp_dir)
    # Todas las verificaciones fallan; las rectificaciones "corrigen"
    # pero la verificación sigue fallando.
    script = {
        "REQUIREMENTS": [
            {"final": "Requisitos:\n- Tarea imposible."},
        ],
        "DEVELOPMENT": [
            {"final": "He intentado hacer la tarea."},
        ],
        "EXECUTION_VERIFICATION": [
            {"final": "VERIFICACIÓN FALLIDA: error 1."},
            {"final": "VERIFICACIÓN FALLIDA: error 2."},
            {"final": "VERIFICACIÓN FALLIDA: error 3."},
            {"final": "VERIFICACIÓN FALLIDA: error 4."},
        ],
        "RECTIFICATION": [
            {"final": "Intento de corrección 1."},
            {"final": "Intento de corrección 2."},
            {"final": "Intento de corrección 3."},
        ],
    }

    max_retries = 2
    orchestrator, _ = make_orchestrator(db, script, max_retries=max_retries)
    parent = run_orchestrator(db, orchestrator, "Tarea imposible")

    parent_after = db.get_task(parent.id)
    assert_eq(parent_after.status, ga.TaskStatus.FAILED, "tarea padre → FAILED tras agotar reintentos")

    subtasks = db.list_subtasks(parent.id)
    # Flujo con max_retries=2:
    # REQUIREMENTS + DEVELOPMENT + VERIFICATION(0) + RECTIFICATION(0) +
    # VERIFICATION(1) + RECTIFICATION(1) + VERIFICATION(2)
    # = 3 iniciales + max_retries rectificaciones + max_retries verificaciones extra
    # = 3 + 2 + 2 = 7
    expected_count = 3 + max_retries + max_retries
    assert_eq(len(subtasks), expected_count, f"se crean {expected_count} subtareas")

    rectifications = [
        st for st in subtasks if st.subtask_type == ga.SubtaskType.RECTIFICATION
    ]
    assert_eq(len(rectifications), max_retries, f"hay {max_retries} rectificaciones")


def test_subtask_failure_marks_parent_failed(tmp_dir: str, workspace: str) -> None:
    """
    Si la subtarea de REQUISITOS falla (no produce respuesta final),
    la tarea padre debe quedar FAILED sin crear más subtareas.
    """
    RESULTS.section("Fallo en subtarea de requisitos → tarea padre FAILED")

    db = make_test_db(tmp_dir)
    # La subtarea de requisitos no produce respuesta final (se agotan
    # las iteraciones del agente).
    script = {
        "REQUIREMENTS": [],  # Sin respuestas → el agente se queda sin iteraciones.
    }

    orchestrator, _ = make_orchestrator(db, script)
    parent = run_orchestrator(db, orchestrator, "Tarea cualquiera")

    parent_after = db.get_task(parent.id)
    assert_eq(parent_after.status, ga.TaskStatus.FAILED, "tarea padre → FAILED")

    subtasks = db.list_subtasks(parent.id)
    assert_eq(len(subtasks), 1, "solo se crea la subtarea de requisitos")
    assert_eq(subtasks[0].subtask_type, ga.SubtaskType.REQUIREMENTS, "la única subtarea es REQUIREMENTS")


def test_subtasks_have_correct_parent_link(tmp_dir: str, workspace: str) -> None:
    """
    Todas las subtareas deben tener parent_task_id apuntando a la
    tarea padre correcta.
    """
    RESULTS.section("Relación padre-subtarea en la BD")

    db = make_test_db(tmp_dir)
    script = {
        "REQUIREMENTS": [{"final": "Requisitos OK."}],
        "DEVELOPMENT": [{"final": "Desarrollo OK."}],
        "EXECUTION_VERIFICATION": [{"final": "VERIFICACIÓN EXITOSA: todo bien."}],
    }
    orchestrator, _ = make_orchestrator(db, script)
    parent = run_orchestrator(db, orchestrator, "Tarea de prueba")

    subtasks = db.list_subtasks(parent.id)
    for st in subtasks:
        assert_eq(st.parent_task_id, parent.id, f"subtarea #{st.id} tiene parent_task_id correcto")


def test_database_schema_migration(tmp_dir: str, workspace: str) -> None:
    """
    Verifica que el esquema de la BD incluye las nuevas columnas
    (parent_task_id, subtask_type, attempt_number).
    """
    RESULTS.section("Esquema de BD con nuevas columnas")

    db = make_test_db(tmp_dir)
    # Crear una tarea padre y una subtarea para verificar el esquema.
    parent = db.create_task(title="padre", prompt="test")
    child = db.create_task(
        title="hijo",
        prompt="test",
        parent_task_id=parent.id,
        subtask_type=ga.SubtaskType.REQUIREMENTS,
        attempt_number=0,
    )

    # Releer y verificar que los campos se conservan.
    parent_after = db.get_task(parent.id)
    child_after = db.get_task(child.id)

    assert_true(
        parent_after.parent_task_id is None,
        "tarea padre tiene parent_task_id=None",
    )
    assert_eq(
        child_after.parent_task_id,
        parent.id,
        "subtarea tiene parent_task_id apuntando al padre",
    )
    assert_eq(
        child_after.subtask_type,
        ga.SubtaskType.REQUIREMENTS,
        "subtarea tiene subtask_type correcto",
    )
    assert_eq(child_after.attempt_number, 0, "subtarea tiene attempt_number correcto")


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:
    tmp_dir, workspace = setup_test_env()
    try:
        test_database_schema_migration(tmp_dir, workspace)
        test_happy_path_no_rectification(tmp_dir, workspace)
        test_one_rectification_cycle(tmp_dir, workspace)
        test_max_retries_exhausted(tmp_dir, workspace)
        test_subtask_failure_marks_parent_failed(tmp_dir, workspace)
        test_subtasks_have_correct_parent_link(tmp_dir, workspace)
    finally:
        teardown_test_env(tmp_dir)

    print(f"\n{'=' * 60}")
    print(f"Resultados: {RESULTS.passed} OK, {RESULTS.failed} FAIL")
    print(f"{'=' * 60}")
    if RESULTS.failed > 0:
        print("\nErrores:")
        for err in RESULTS.errors:
            print(f"  - {err}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
