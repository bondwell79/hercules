#!/usr/bin/env python3
"""
test_subtareas.py

Pruebas del orquestador de fases secuenciales configuradas en subtareas.ini.

Este test NO requiere un LLM real ni la interfaz gráfica.

Ejecutar:
    python test_subtareas.py
"""

from __future__ import annotations

import configparser
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
    Mock de LLMConnector que devuelve respuestas según un guion indexado por etapa.

    Para distinguir entre instancias de una etapa, se puede usar la clave
    ``"<ETAPA>_N"``; en su ausencia se usa la clave general de la etapa.
    """

    def __init__(self, script: Dict[str, List[Dict[str, Any]]]) -> None:
        self.script = script
        # Contador de instancias por nombre de etapa.
        self._instance_counters: Dict[str, int] = {}
        # Contador de llamadas dentro de la instancia actual.
        self._call_counters: Dict[str, int] = {}
        self.calls: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def _detect_subtask(self, messages: List[Dict[str, Any]]) -> str:
        """Detecta la subtarea por sus marcadores de prueba en el prompt."""
        if len(messages) < 2:
            return "UNKNOWN"
        prompt = messages[1].get("content", "")
        for marker, subtask in (
            ("[TEST:PREPARAR]", "PREPARAR"),
            ("[TEST:FABRICAR]", "FABRICAR"),
            ("[TEST:VALIDAR]", "VALIDAR"),
            ("[TEST:ETAPA_FALLA]", "ETAPA_FALLA"),
        ):
            if marker in prompt:
                return subtask
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
                # Sin entrada en el guion: simular un error del LLM para
                # que el Agent marque la subtarea como FAILED y el
                # orquestador aborte el flujo en lugar de continuar con
                # respuestas vacías.
                raise ga.LLMError(
                    f"ScriptedLLM: no hay guion configurado para la "
                    f"subtarea '{subtask}'."
                )
            responses = self.script[script_key]
            if not responses:
                # Guion vacío: el agente no tiene respuestas para esta
                # subtarea. Lanzar LLMError para que el Agent la marque
                # como FAILED (en lugar de aceptar un texto vacío como
                # respuesta final).
                raise ga.LLMError(
                    f"ScriptedLLM: el guion para '{subtask}' está vacío."
                )
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

def _write_test_plan(tmp_dir: str, *sections: Tuple[str, str]) -> Path:
    path = Path(tmp_dir) / f"plan-{time.time_ns()}.ini"
    parser = configparser.ConfigParser(interpolation=None)
    for name, prompt in sections:
        parser[name] = {"prompt": prompt}
    with path.open("w", encoding="utf-8") as config_file:
        parser.write(config_file)
    ga.SUBTAREAS_INI_PATH = str(path)
    return path


def test_configured_plan_runs_only_declared_stages(tmp_dir: str, workspace: str) -> None:
    RESULTS.section("Plan de etapas completamente configurable")
    old_plan_path = ga.SUBTAREAS_INI_PATH
    config_path = _write_test_plan(
        tmp_dir,
        ("PREPARAR", "[TEST:PREPARAR] {user_prompt}"),
        ("FABRICAR", "[TEST:FABRICAR] Petición={user_prompt}; anterior={PREPARAR}"),
        ("VALIDAR", "[TEST:VALIDAR] Fabricación={FABRICAR}"),
    )
    try:
        db = make_test_db(tmp_dir)
        orchestrator, _ = make_orchestrator(
            db,
            {
                "PREPARAR": [{"final": "Preparación lista."}],
                "FABRICAR": [{"final": "Fabricación lista."}],
                "VALIDAR": [{"final": "Validación lista."}],
            },
        )
        parent = run_orchestrator(db, orchestrator, "Crear una pieza")
        parent_after = db.get_task(parent.id)
        subtasks = db.list_subtasks(parent.id)
        assert_eq(parent_after.status, ga.TaskStatus.COMPLETED, "el plan configurado completa la tarea")
        assert_eq([task.subtask_name for task in subtasks], ["PREPARAR", "FABRICAR", "VALIDAR"], "solo se ejecutan etapas declaradas y en orden")
        assert_eq(len(subtasks), 3, "cada fase configurada genera una subtarea")
        assert_true("Crear una pieza" in subtasks[0].prompt, "{user_prompt} se resuelve")
        assert_true("Preparación lista." in subtasks[1].prompt, "placeholder anterior se resuelve")
        assert_true("Fabricación lista." in subtasks[2].prompt, "se puede referenciar cualquier etapa previa")
    finally:
        ga.SUBTAREAS_INI_PATH = old_plan_path
        config_path.unlink(missing_ok=True)


def test_stage_failure_stops_plan(tmp_dir: str, workspace: str) -> None:
    RESULTS.section("Un fallo detiene las etapas siguientes")
    old_plan_path = ga.SUBTAREAS_INI_PATH
    config_path = _write_test_plan(
        tmp_dir,
        ("ETAPA_FALLA", "[TEST:ETAPA_FALLA] {user_prompt}"),
        ("NUNCA_EJECUTAR", "Esto no debe ejecutarse"),
    )
    try:
        db = make_test_db(tmp_dir)
        orchestrator, _ = make_orchestrator(db, {"ETAPA_FALLA": []})
        parent = run_orchestrator(db, orchestrator, "Probar fallo")
        assert_eq(db.get_task(parent.id).status, ga.TaskStatus.FAILED, "el padre falla con la subtarea")
        assert_eq([task.subtask_name for task in db.list_subtasks(parent.id)], ["ETAPA_FALLA"], "no se ejecutan fases posteriores")
    finally:
        ga.SUBTAREAS_INI_PATH = old_plan_path
        config_path.unlink(missing_ok=True)


def test_subtasks_have_correct_parent_link(tmp_dir: str, workspace: str) -> None:
    """Todas las subtareas registran el padre correcto."""
    RESULTS.section("Relación padre-subtarea en la BD")
    old_plan_path = ga.SUBTAREAS_INI_PATH
    config_path = _write_test_plan(tmp_dir, ("PREPARAR", "[TEST:PREPARAR] {user_prompt}"))
    try:
        db = make_test_db(tmp_dir)
        orchestrator, _ = make_orchestrator(db, {"PREPARAR": [{"final": "Listo."}]})
        parent = run_orchestrator(db, orchestrator, "Tarea de prueba")
        subtasks = db.list_subtasks(parent.id)
        for st in subtasks:
            assert_eq(st.parent_task_id, parent.id, f"subtarea #{st.id} tiene parent_task_id correcto")
    finally:
        ga.SUBTAREAS_INI_PATH = old_plan_path
        config_path.unlink(missing_ok=True)


def test_database_schema_migration(tmp_dir: str, workspace: str) -> None:
    """
    Verifica que el esquema de la BD incluye las columnas de subtarea.
    """
    RESULTS.section("Esquema de BD con nuevas columnas")

    db = make_test_db(tmp_dir)
    # Crear una tarea padre y una subtarea para verificar el esquema.
    parent = db.create_task(title="padre", prompt="test")
    child = db.create_task(
        title="hijo",
        prompt="test",
        parent_task_id=parent.id,
        subtask_name="PREPARAR",
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
        child_after.subtask_name,
        "PREPARAR",
        "subtarea conserva el nombre personalizado",
    )
    assert_eq(child_after.attempt_number, 0, "subtarea tiene attempt_number correcto")


def test_custom_subtask_plan(tmp_dir: str, workspace: str) -> None:
    """Las etapas configurables resuelven placeholders y nombres de salida."""
    RESULTS.section("Plan configurable con placeholders")
    old_plan_path = ga.SUBTAREAS_INI_PATH
    config_path = _write_test_plan(
        tmp_dir,
        ("PREPARAR", "[TEST:PREPARAR] {user_prompt}"),
        ("FABRICAR", "[TEST:FABRICAR] Petición={user_prompt}; previo={PREPARAR}"),
    )
    try:
        db = make_test_db(tmp_dir)
        orchestrator, _ = make_orchestrator(
            db,
            {
                "PREPARAR": [{"final": "Preparación completada."}],
                "FABRICAR": [{"final": "Fabricación completada."}],
            },
        )
        parent = run_orchestrator(db, orchestrator, "Crear una pieza")
        subtasks = db.list_subtasks(parent.id)
        parent_after = db.get_task(parent.id)
        assert_eq(parent_after.status, ga.TaskStatus.COMPLETED, "plan configurable completa la tarea")
        assert_eq(len(subtasks), 2, "se crean las dos etapas configuradas")
        if len(subtasks) == 2:
            assert_true("FABRICAR" in subtasks[1].title, "nombre personalizado visible en el título")
            assert_true(
                "Crear una pieza" in subtasks[1].prompt
                and "{user_prompt}" not in subtasks[1].prompt,
                "placeholder {user_prompt} reemplazado",
            )
            assert_true(
                "Preparación completada." in subtasks[1].prompt,
                "placeholder de etapa previa sustituido por su salida",
            )
            assert_eq(subtasks[1].subtask_name, "FABRICAR", "nombre personalizado persistido")
    finally:
        ga.SUBTAREAS_INI_PATH = old_plan_path
        config_path.unlink(missing_ok=True)


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:
    tmp_dir, workspace = setup_test_env()
    try:
        test_database_schema_migration(tmp_dir, workspace)
        test_configured_plan_runs_only_declared_stages(tmp_dir, workspace)
        test_stage_failure_stops_plan(tmp_dir, workspace)
        test_subtasks_have_correct_parent_link(tmp_dir, workspace)
        test_custom_subtask_plan(tmp_dir, workspace)
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
