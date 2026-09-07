#!/usr/bin/env python3
"""
test_funcionamiento.py

Test de funcionamiento del agente: verifica que el programa puede aceptar
dos tareas simultáneas, solicitadas una tras otra por el usuario, y que
ambas se ejecutan en paralelo hasta completarse correctamente.

Escenario simulado:
    1. El usuario escribe el primer prompt y pulsa "Ejecutar".
       -> Se crea la tarea #1 en estado PENDING y el agente se lanza
          en un hilo separado.
    2. Sin esperar a que la tarea #1 termine, el usuario escribe el
       segundo prompt y vuelve a pulsar "Ejecutar".
       -> Se crea la tarea #2 en estado PENDING y se lanza un segundo
          hilo de agente.
    3. Ambos agentes corren en paralelo. El test verifica que:
       - Ambas tareas son aceptadas (existen en la BD con IDs distintos).
       - Ambas tareas pasan por los estados correctos.
       - Ambas tareas finalizan en estado COMPLETED.
       - Cada tarea conserva SU prompt y SU respuesta final (no se
         mezclan entre sí).
       - Los historiales son independientes (el de la tarea #1 no
         contiene eventos de la tarea #2 y viceversa).

Nota sobre el diseño del test:
    Cada tarea recibe su propio Agent con su propio MockLLM. Esto
    aísla el test a lo que realmente queremos verificar: el sistema
    de gestión de tareas (acepta múltiples tareas, las ejecuta en
    paralelo, mantiene historiales independientes). En el sistema real,
    el LLMConnector es compartido, pero las respuestas son independientes
    por tarea; aquí simulamos esa independencia con mocks separados.

Este test NO requiere un LLM real ni la UI tkinter.

Ejecutar:
    python test_funcionamiento.py
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
    """
    Crea un directorio temporal con workspace propio para no contaminar
    el entorno real del usuario. Parchea los globales WORKSPACE_DIR y
    MAX_ITERATIONS del módulo hercules para que apunten al
    entorno de test.
    """
    tmp = Path(tempfile.mkdtemp(prefix="test_funcionamiento_"))
    workspace = tmp / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    # Crear archivos de prueba en el workspace.
    (workspace / "datos_tarea1.txt").write_text("datos para tarea 1", encoding="utf-8")
    (workspace / "datos_tarea2.txt").write_text("datos para tarea 2", encoding="utf-8")

    # Parchar los globales del módulo para que apunten al entorno de test.
    ga.WORKSPACE_DIR = workspace.resolve()
    ga.MAX_ITERATIONS = 10

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
    """
    Mock de LLMConnector que devuelve respuestas predefinidas.

    Cada llamada a `chat()` consume la siguiente respuesta de la cola.
    Si se agotan las respuestas, devuelve una respuesta final vacía.
    """

    def __init__(self, responses: List[Dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.call_count = 0
        self.calls: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

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
            if self.call_count >= len(self.responses):
                return {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": "(sin más respuestas)",
                                "tool_calls": [],
                            }
                        }
                    ]
                }
            resp = self.responses[self.call_count]
            self.call_count += 1
            return resp


class MockPermissionManager:
    """Mock de PermissionManager que aprueba todas las solicitudes."""

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
# HELPERS: simulación del flujo del usuario
# ============================================================================

def make_agent_for_task(
    db: ga.Database,
    responses: List[Dict[str, Any]],
    grant_permissions: bool = True,
) -> Tuple[ga.Agent, MockLLM, MockPermissionManager]:
    """
    Crea un Agent con su propio MockLLM y MockPermissionManager.

    Cada tarea usa su propio Agent para aislar las respuestas del LLM
    y las solicitudes de permiso (en el sistema real, el LLM es
    compartido, pero las respuestas son independientes por tarea).
    """
    ui_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
    tools = ga.ToolsRegistry()
    permissions = MockPermissionManager(grant=grant_permissions)
    llm = MockLLM(responses)
    agent = ga.Agent(db, llm, tools, permissions, ui_queue)
    return agent, llm, permissions


def simulate_user_execute(
    db: ga.Database,
    agent: ga.Agent,
    prompt: str,
) -> ga.Task:
    """
    Simula la acción del usuario al pulsar el botón "Ejecutar" en el
    dashboard: crea la tarea en la BD y lanza el agente en un hilo
    separado (igual que hace Dashboard._on_execute).

    Retorna la tarea recién creada.
    """
    title = prompt.splitlines()[0][:80]
    task = db.create_task(title=title, prompt=prompt)
    thread = threading.Thread(
        target=agent.run,
        args=(task,),
        daemon=True,
        name=f"agent-task-{task.id}",
    )
    thread.start()
    return task


def wait_for_completion(
    db: ga.Database,
    task_ids: List[int],
    timeout: float = 30.0,
    poll_interval: float = 0.05,
) -> bool:
    """
    Espera (con timeout) a que todas las tareas indicadas alcancen un
    estado terminal (COMPLETED, FAILED o CANCELLED).

    Retorna True si todas terminaron dentro del timeout, False en caso
    contrario.
    """
    terminal = {
        ga.TaskStatus.COMPLETED,
        ga.TaskStatus.FAILED,
        ga.TaskStatus.CANCELLED,
    }
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        all_done = True
        for tid in task_ids:
            t = db.get_task(tid)
            if t is None or t.status not in terminal:
                all_done = False
                break
        if all_done:
            return True
        time.sleep(poll_interval)
    return False


# ============================================================================
# TESTS
# ============================================================================

def test_two_sequential_tasks_run_in_parallel(tmp_dir: str, workspace: str) -> None:
    """
    Verifica el escenario principal: el usuario lanza dos tareas una
    tras otra y ambas corren en paralelo hasta completarse.
    """
    RESULTS.section("Dos tareas simultáneas lanzadas secuencialmente por el usuario")

    # --- Preparación: cada tarea tiene su propio Agent/MockLLM ---
    db = make_test_db(tmp_dir)

    # Respuestas para tarea 1: tool_call (read_file) + respuesta final.
    responses_1 = [
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Leyendo datos de la tarea 1.",
                        "tool_calls": [
                            {
                                "id": "t1_call_1",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": '{"path": "datos_tarea1.txt"}',
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
                        "content": "Tarea 1 completada: leí 'datos para tarea 1'.",
                        "tool_calls": [],
                    }
                }
            ]
        },
    ]

    # Respuestas para tarea 2: tool_call (read_file) + respuesta final.
    responses_2 = [
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Leyendo datos de la tarea 2.",
                        "tool_calls": [
                            {
                                "id": "t2_call_1",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": '{"path": "datos_tarea2.txt"}',
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
                        "content": "Tarea 2 completada: leí 'datos para tarea 2'.",
                        "tool_calls": [],
                    }
                }
            ]
        },
    ]

    agent_1, llm_1, _ = make_agent_for_task(db, responses_1)
    agent_2, llm_2, _ = make_agent_for_task(db, responses_2)

    # --- Paso 1: el usuario lanza la primera tarea ---
    prompt_1 = "Lee el archivo datos_tarea1.txt y dime su contenido."
    task_1 = simulate_user_execute(db, agent_1, prompt_1)
    assert_true(
        task_1.id is not None,
        "flujo: primera tarea creada con ID válido",
        f"task_1.id={task_1.id}",
    )
    assert_eq(
        task_1.status,
        ga.TaskStatus.PENDING,
        "flujo: primera tarea inicia en estado PENDING",
    )
    assert_eq(task_1.prompt, prompt_1, "flujo: prompt de tarea 1 almacenado correctamente")

    # Pequeña pausa para que el hilo de la tarea 1 arranque antes de
    # lanzar la tarea 2 (simula la acción humana de escribir el segundo
    # prompt y pulsar Ejecutar).
    time.sleep(0.05)

    # --- Paso 2: el usuario lanza la segunda tarea (sin esperar a la 1ª) ---
    prompt_2 = "Lee el archivo datos_tarea2.txt y dime su contenido."
    task_2 = simulate_user_execute(db, agent_2, prompt_2)
    assert_true(
        task_2.id is not None,
        "flujo: segunda tarea creada con ID válido",
        f"task_2.id={task_2.id}",
    )
    assert_true(
        task_2.id != task_1.id,
        "flujo: segunda tarea tiene ID distinto de la primera",
        f"task_1.id={task_1.id}, task_2.id={task_2.id}",
    )
    assert_eq(
        task_2.status,
        ga.TaskStatus.PENDING,
        "flujo: segunda tarea inicia en estado PENDING",
    )
    assert_eq(task_2.prompt, prompt_2, "flujo: prompt de tarea 2 almacenado correctamente")

    # --- Paso 3: ambas tareas deben estar activas simultáneamente ---
    # Verificamos que, en algún momento, ambas tareas están en estados
    # no terminales (PENDING, IN_PROGRESS o AWAITING_APPROVAL).
    saw_both_active = False
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        t1 = db.get_task(task_1.id)
        t2 = db.get_task(task_2.id)
        if t1 is None or t2 is None:
            break
        active_states = {
            ga.TaskStatus.PENDING,
            ga.TaskStatus.IN_PROGRESS,
            ga.TaskStatus.AWAITING_APPROVAL,
        }
        if t1.status in active_states and t2.status in active_states:
            saw_both_active = True
            break
        time.sleep(0.02)
    assert_true(
        saw_both_active,
        "concurrencia: ambas tareas activas al mismo tiempo en algún momento",
    )

    # --- Paso 4: esperar a que ambas terminen ---
    completed = wait_for_completion(db, [task_1.id, task_2.id], timeout=15.0)
    assert_true(completed, "ejecución: ambas tareas finalizan dentro del timeout")

    # --- Paso 5: verificar estado final de cada tarea ---
    final_1 = db.get_task(task_1.id)
    final_2 = db.get_task(task_2.id)
    assert_eq(
        final_1.status,
        ga.TaskStatus.COMPLETED,
        "resultado: tarea 1 termina en COMPLETED",
    )
    assert_eq(
        final_2.status,
        ga.TaskStatus.COMPLETED,
        "resultado: tarea 2 termina en COMPLETED",
    )

    # --- Paso 6: verificar que cada tarea conserva SU respuesta final ---
    assert_true(
        final_1.final_answer is not None and "tarea 1" in final_1.final_answer,
        "aislamiento: respuesta final de tarea 1 contiene su propio contenido",
        f"final_1.final_answer={final_1.final_answer!r}",
    )
    assert_true(
        final_2.final_answer is not None and "tarea 2" in final_2.final_answer,
        "aislamiento: respuesta final de tarea 2 contiene su propio contenido",
        f"final_2.final_answer={final_2.final_answer!r}",
    )
    assert_true(
        "tarea 2" not in (final_1.final_answer or ""),
        "aislamiento: respuesta de tarea 1 NO contiene contenido de tarea 2",
    )
    assert_true(
        "tarea 1" not in (final_2.final_answer or ""),
        "aislamiento: respuesta de tarea 2 NO contiene contenido de tarea 1",
    )

    # --- Paso 7: verificar historiales independientes ---
    history_1 = db.get_history(task_1.id)
    history_2 = db.get_history(task_2.id)
    assert_true(
        len(history_1) > 0,
        "historial: tarea 1 tiene eventos registrados",
        f"len={len(history_1)}",
    )
    assert_true(
        len(history_2) > 0,
        "historial: tarea 2 tiene eventos registrados",
        f"len={len(history_2)}",
    )

    # El historial de cada tarea debe contener SU tool_call (identificado
    # por el nombre de la herramienta y los argumentos) y NO el de la otra.
    history_1_content = "\n".join(e.content for e in history_1)
    history_2_content = "\n".join(e.content for e in history_2)
    assert_true(
        "datos_tarea1.txt" in history_1_content,
        "historial: tarea 1 contiene su propio tool_call (read_file datos_tarea1.txt)",
    )
    assert_true(
        "datos_tarea2.txt" not in history_1_content,
        "historial: tarea 1 NO contiene tool_call de tarea 2",
    )
    assert_true(
        "datos_tarea2.txt" in history_2_content,
        "historial: tarea 2 contiene su propio tool_call (read_file datos_tarea2.txt)",
    )
    assert_true(
        "datos_tarea1.txt" not in history_2_content,
        "historial: tarea 2 NO contiene tool_call de tarea 1",
    )

    # Cada historial debe contener su prompt original.
    assert_true(
        prompt_1 in history_1_content,
        "historial: tarea 1 contiene su prompt original",
    )
    assert_true(
        prompt_2 in history_2_content,
        "historial: tarea 2 contiene su prompt original",
    )

    # --- Paso 8: verificar que el LLM fue llamado 2 veces por tarea ---
    assert_eq(
        llm_1.call_count, 2,
        "LLM: tarea 1 realizó 2 llamadas (tool_call + final)",
    )
    assert_eq(
        llm_2.call_count, 2,
        "LLM: tarea 2 realizó 2 llamadas (tool_call + final)",
    )


def test_two_tasks_with_critical_actions(tmp_dir: str, workspace: str) -> None:
    """
    Verifica que dos tareas con acciones CRITICAL (que requieren
    aprobación HITL) pueden ejecutarse en paralelo y ambas completarse.
    """
    RESULTS.section("Dos tareas simultáneas con acciones CRITICAL (HITL)")

    db = make_test_db(tmp_dir)

    # Respuestas para tarea 1: tool_call CRITICAL (write_file) + final.
    responses_1 = [
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Voy a escribir el archivo de la tarea 1.",
                        "tool_calls": [
                            {
                                "id": "t1_write",
                                "type": "function",
                                "function": {
                                    "name": "write_file",
                                    "arguments": '{"path": "salida_t1.txt", "content": "resultado tarea 1"}',
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
                        "content": "Tarea 1 finalizada: escribí salida_t1.txt.",
                        "tool_calls": [],
                    }
                }
            ]
        },
    ]

    # Respuestas para tarea 2: tool_call CRITICAL (write_file) + final.
    responses_2 = [
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Voy a escribir el archivo de la tarea 2.",
                        "tool_calls": [
                            {
                                "id": "t2_write",
                                "type": "function",
                                "function": {
                                    "name": "write_file",
                                    "arguments": '{"path": "salida_t2.txt", "content": "resultado tarea 2"}',
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
                        "content": "Tarea 2 finalizada: escribí salida_t2.txt.",
                        "tool_calls": [],
                    }
                }
            ]
        },
    ]

    agent_1, _, permissions_1 = make_agent_for_task(db, responses_1, grant_permissions=True)
    agent_2, _, permissions_2 = make_agent_for_task(db, responses_2, grant_permissions=True)

    # Lanzar ambas tareas secuencialmente (como haría el usuario).
    task_1 = simulate_user_execute(
        db, agent_1, "Crea el archivo salida_t1.txt con contenido 'resultado tarea 1'."
    )
    time.sleep(0.05)
    task_2 = simulate_user_execute(
        db, agent_2, "Crea el archivo salida_t2.txt con contenido 'resultado tarea 2'."
    )

    # Esperar a que ambas terminen.
    completed = wait_for_completion(db, [task_1.id, task_2.id], timeout=15.0)
    assert_true(completed, "HITL paralelo: ambas tareas finalizan dentro del timeout")

    final_1 = db.get_task(task_1.id)
    final_2 = db.get_task(task_2.id)
    assert_eq(final_1.status, ga.TaskStatus.COMPLETED, "HITL paralelo: tarea 1 COMPLETED")
    assert_eq(final_2.status, ga.TaskStatus.COMPLETED, "HITL paralelo: tarea 2 COMPLETED")

    # Verificar que ambos archivos se crearon en el workspace.
    assert_true(
        Path(workspace, "salida_t1.txt").exists(),
        "HITL paralelo: archivo de tarea 1 creado en workspace",
    )
    assert_true(
        Path(workspace, "salida_t2.txt").exists(),
        "HITL paralelo: archivo de tarea 2 creado en workspace",
    )

    # Verificar contenidos correctos.
    content_1 = Path(workspace, "salida_t1.txt").read_text(encoding="utf-8")
    content_2 = Path(workspace, "salida_t2.txt").read_text(encoding="utf-8")
    assert_eq(content_1, "resultado tarea 1", "HITL paralelo: contenido de archivo tarea 1 correcto")
    assert_eq(content_2, "resultado tarea 2", "HITL paralelo: contenido de archivo tarea 2 correcto")

    # Verificar que cada PermissionManager recibió la solicitud de SU tarea.
    requested_task_ids_1 = {tid for tid, _, _ in permissions_1.requests}
    requested_task_ids_2 = {tid for tid, _, _ in permissions_2.requests}
    assert_true(
        task_1.id in requested_task_ids_1,
        "HITL paralelo: PermissionManager de tarea 1 recibió solicitud de tarea 1",
        f"task_ids solicitados={requested_task_ids_1}",
    )
    assert_true(
        task_2.id in requested_task_ids_2,
        "HITL paralelo: PermissionManager de tarea 2 recibió solicitud de tarea 2",
        f"task_ids solicitados={requested_task_ids_2}",
    )


def test_three_sequential_tasks(tmp_dir: str, workspace: str) -> None:
    """
    Verifica que el programa puede aceptar más de dos tareas lanzadas
    secuencialmente por el usuario (robustez adicional).
    """
    RESULTS.section("Tres tareas lanzadas secuencialmente")

    db = make_test_db(tmp_dir)

    # 3 tareas, cada una con su propio Agent y respuestas.
    agents_and_responses = []
    for i in range(1, 4):
        responses = [
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": f"Tarea {i}: leyendo archivo.",
                            "tool_calls": [
                                {
                                    "id": f"t{i}_call",
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
            },
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": f"Tarea {i} completada.",
                            "tool_calls": [],
                        }
                    }
                ]
            },
        ]
        agent, _, _ = make_agent_for_task(db, responses)
        agents_and_responses.append((agent, responses))

    tasks = []
    for i, (agent, _) in enumerate(agents_and_responses, start=1):
        t = simulate_user_execute(db, agent, f"Tarea número {i}")
        tasks.append(t)
        time.sleep(0.05)

    # Verificar que todas tienen IDs distintos.
    ids = [t.id for t in tasks]
    assert_eq(len(set(ids)), 3, "robustez: 3 tareas con IDs únicos")

    completed = wait_for_completion(db, ids, timeout=15.0)
    assert_true(completed, "robustez: las 3 tareas finalizan dentro del timeout")

    for i, t in enumerate(tasks, start=1):
        final = db.get_task(t.id)
        assert_eq(
            final.status,
            ga.TaskStatus.COMPLETED,
            f"robustez: tarea {i} termina en COMPLETED",
        )
        assert_true(
            f"Tarea {i} completada" in (final.final_answer or ""),
            f"robustez: tarea {i} tiene su respuesta final correcta",
            f"final_answer={final.final_answer!r}",
        )


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:
    print("=" * 70)
    print("TEST DE FUNCIONAMIENTO — hercules.py")
    print("=" * 70)
    print("Verificando que el programa acepta dos tareas simultáneas,")
    print("solicitadas una tras otra por el usuario.")
    print()

    tmp_dir, workspace = setup_test_env()
    print(f"[setup] Entorno aislado en: {tmp_dir}")
    print(f"[setup] Workspace: {workspace}")
    print()

    try:
        test_two_sequential_tasks_run_in_parallel(tmp_dir, workspace)
        test_two_tasks_with_critical_actions(tmp_dir, workspace)
        test_three_sequential_tasks(tmp_dir, workspace)
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

    print("\n✓ Todos los tests pasaron. El programa puede aceptar dos")
    print("  tareas simultáneas, una tras otra, solicitadas por el usuario.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
