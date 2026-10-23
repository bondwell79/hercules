#!/usr/bin/env python3
"""Tests de la herramienta spawn_parallel_task (tareas paralelas lanzadas por el LLM)."""

from __future__ import annotations

import json
import queue
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

import hercules as ga  # noqa: E402


def _message(content: Optional[str], tool_calls: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {
        "choices": [
            {"message": {"role": "assistant", "content": content, "tool_calls": tool_calls or []}}
        ]
    }


def _tool_call(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": f"call_{time.time_ns()}",
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


class FakeLLM:
    """
    LLM guionizado por el prompt de la tarea (segundo mensaje).

    ``handlers`` asocia un marcador del prompt con una función
    ``(messages, tools) -> respuesta`` que decide qué contestar.
    """

    def __init__(self, handlers: Dict[str, Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], Dict[str, Any]]]) -> None:
        self.handlers = handlers
        self.tools_seen: Dict[str, List[str]] = {}
        self._lock = threading.Lock()

    def chat(self, messages, tools=None, tool_choice=None, cancel_event=None):
        prompt = messages[1]["content"]
        for marker, handler in self.handlers.items():
            if marker in prompt:
                with self._lock:
                    self.tools_seen[marker] = [t["function"]["name"] for t in tools or []]
                return handler(messages, tools or [])
        raise ga.LLMError(f"sin guion para el prompt: {prompt!r}")


class ParallelTaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = ga.Database(db_path=str(Path(self.tmp.name) / "test.db"))
        self.ui_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        patcher = patch.object(ga, "MAX_ITERATIONS", 10)
        patcher.start()
        self.addCleanup(patcher.stop)

    def make_agent(self, llm: FakeLLM, max_parallel: int = 3) -> ga.Agent:
        permissions = ga.PermissionManager(self.ui_queue)
        agent = ga.Agent(self.db, llm, ga.ToolsRegistry(), permissions, self.ui_queue)
        agent.parallel = ga.ParallelTaskManager(agent, max_parallel=max_parallel)
        self.addCleanup(self._wait_for_runs, agent)
        return agent

    @staticmethod
    def _wait_for_runs(agent: ga.Agent) -> None:
        """Evita borrar la BD temporal mientras una tarea paralela aún escribe."""
        agent.parallel.wait_all(15)

    def run_task(self, agent: ga.Agent, prompt: str, cancel: Optional[threading.Event] = None) -> ga.Task:
        task = self.db.create_task(title="padre", prompt=prompt)
        thread = threading.Thread(target=agent.run, args=(task, cancel), daemon=True)
        thread.start()
        thread.join(timeout=20)
        self.assertFalse(thread.is_alive(), "la tarea padre no terminó")
        updated = self.db.get_task(task.id)
        assert updated is not None
        return updated

    @staticmethod
    def parent_script(*child_prompts: str, final: str = "listo") -> Callable[..., Dict[str, Any]]:
        """Primero lanza una tarea paralela por prompt y luego responde."""

        def handler(messages, tools):
            if not any(m.get("role") == "tool" for m in messages):
                return _message(
                    None,
                    [_tool_call("spawn_parallel_task", {"prompt": p}) for p in child_prompts],
                )
            return _message(final)

        return handler

    def test_spawn_creates_child_and_parent_waits_for_result(self) -> None:
        llm = FakeLLM(
            {
                "[PADRE]": self.parent_script("[HIJA] genera un informe"),
                "[HIJA]": lambda m, t: _message("informe terminado"),
            }
        )
        parent = self.run_task(self.make_agent(llm), "[PADRE] coordina")

        self.assertEqual(parent.status, ga.TaskStatus.COMPLETED)
        children = self.db.list_subtasks(parent.id)
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].prompt, "[HIJA] genera un informe")
        self.assertEqual(children[0].subtask_name, "PARALELA-1")
        self.assertEqual(children[0].status, ga.TaskStatus.COMPLETED)
        self.assertIn("listo", parent.final_answer)
        self.assertIn("informe terminado", parent.final_answer)
        self.assertIn("PARALELA-1", parent.final_answer)

    def test_spawn_returns_immediately_without_blocking_parent(self) -> None:
        release_child = threading.Event()
        parent_continued = threading.Event()

        def child(messages, tools):
            self.assertTrue(release_child.wait(10))
            return _message("hecho")

        def parent(messages, tools):
            if not any(m.get("role") == "tool" for m in messages):
                return _message(None, [_tool_call("spawn_parallel_task", {"prompt": "[HIJA] lenta"})])
            parent_continued.set()
            return _message("padre sigue")

        agent = self.make_agent(FakeLLM({"[PADRE]": parent, "[HIJA]": child}))
        task = self.db.create_task(title="padre", prompt="[PADRE]")
        thread = threading.Thread(target=agent.run, args=(task,), daemon=True)
        thread.start()

        self.assertTrue(parent_continued.wait(10), "el padre quedó bloqueado por la hija")
        self.assertTrue(thread.is_alive(), "el padre debe esperar a la hija antes de terminar")
        release_child.set()
        thread.join(timeout=20)
        self.assertFalse(thread.is_alive())
        self.assertIn("hecho", self.db.get_task(task.id).final_answer)

    def test_concurrency_is_limited_by_max_parallel(self) -> None:
        lock = threading.Lock()
        state = {"running": 0, "peak": 0}

        def child(messages, tools):
            with lock:
                state["running"] += 1
                state["peak"] = max(state["peak"], state["running"])
            time.sleep(0.2)
            with lock:
                state["running"] -= 1
            return _message("ok")

        prompts = [f"[HIJA] n{i}" for i in range(5)]
        llm = FakeLLM({"[PADRE]": self.parent_script(*prompts), "[HIJA]": child})
        parent = self.run_task(self.make_agent(llm, max_parallel=2), "[PADRE]")

        self.assertEqual(parent.status, ga.TaskStatus.COMPLETED)
        self.assertEqual(state["peak"], 2)
        children = self.db.list_subtasks(parent.id)
        self.assertEqual(len(children), 5)
        self.assertTrue(all(c.status == ga.TaskStatus.COMPLETED for c in children))
        self.assertEqual([c.subtask_name for c in children], [f"PARALELA-{i}" for i in range(1, 6)])

    def test_parallel_tasks_cannot_spawn_more_tasks(self) -> None:
        llm = FakeLLM(
            {
                "[PADRE]": self.parent_script("[HIJA] intenta recursión"),
                "[HIJA]": lambda m, t: _message("sin recursión"),
            }
        )
        parent = self.run_task(self.make_agent(llm), "[PADRE]")

        self.assertEqual(parent.status, ga.TaskStatus.COMPLETED)
        self.assertIn("spawn_parallel_task", llm.tools_seen["[PADRE]"])
        self.assertNotIn("spawn_parallel_task", llm.tools_seen["[HIJA]"])

    def test_spawn_from_parallel_task_is_rejected_at_runtime(self) -> None:
        agent = self.make_agent(FakeLLM({"[X]": lambda m, t: _message("x")}))
        parent = self.db.create_task(title="padre", prompt="p")
        child = agent.parallel.spawn(parent.id, "[X]")
        self.assertTrue(agent.parallel.is_parallel_task(child.id))
        self.assertFalse(agent.parallel.is_parallel_task(parent.id))
        result = agent._spawn_parallel(child.id, {"prompt": "otra"}, None)
        self.assertTrue(result.startswith("ERROR"))
        self.assertEqual(len(self.db.list_subtasks(parent.id)), 1)

    def test_empty_prompt_is_rejected(self) -> None:
        agent = self.make_agent(FakeLLM({}))
        parent = self.db.create_task(title="padre", prompt="p")
        self.assertTrue(agent._spawn_parallel(parent.id, {"prompt": "  "}, None).startswith("ERROR"))
        self.assertTrue(agent._spawn_parallel(parent.id, {}, None).startswith("ERROR"))
        self.assertEqual(self.db.list_subtasks(parent.id), [])

    def test_failed_child_is_reported_without_failing_parent(self) -> None:
        def broken(messages, tools):
            raise ga.LLMError("fallo simulado")

        llm = FakeLLM({"[PADRE]": self.parent_script("[HIJA] rota"), "[HIJA]": broken})
        parent = self.run_task(self.make_agent(llm), "[PADRE]")

        self.assertEqual(parent.status, ga.TaskStatus.COMPLETED)
        self.assertIn(ga.TaskStatus.FAILED.value, parent.final_answer)

    def test_cancelling_parent_cancels_children(self) -> None:
        cancel = threading.Event()
        child_started = threading.Event()

        def child(messages, tools):
            child_started.set()
            cancel.wait(10)
            time.sleep(0.1)
            return _message("tarde")

        llm = FakeLLM({"[PADRE]": self.parent_script("[HIJA] larga"), "[HIJA]": child})
        agent = self.make_agent(llm)
        task = self.db.create_task(title="padre", prompt="[PADRE]")
        thread = threading.Thread(target=agent.run, args=(task, cancel), daemon=True)
        thread.start()
        self.assertTrue(child_started.wait(10))
        cancel.set()
        thread.join(timeout=20)

        self.assertFalse(thread.is_alive())
        self.assertEqual(self.db.get_task(task.id).status, ga.TaskStatus.CANCELLED)
        child_task = self.db.list_subtasks(task.id)[0]
        deadline = time.monotonic() + 10
        while child_task.status not in ga.TaskStatus.finished() and time.monotonic() < deadline:
            time.sleep(0.05)
            child_task = self.db.get_task(child_task.id)
        self.assertEqual(child_task.status, ga.TaskStatus.CANCELLED)

    def test_wait_parallel_task_returns_result_before_final_answer(self) -> None:
        seen: List[str] = []

        def parent(messages, tools):
            tool_msgs = [m for m in messages if m.get("role") == "tool"]
            if not tool_msgs:
                return _message(None, [_tool_call("spawn_parallel_task", {"prompt": "[HIJA] calcula"})])
            if len(tool_msgs) == 1:
                child_id = int(tool_msgs[0]["content"].split("#")[1].split()[0])
                return _message(None, [_tool_call("wait_parallel_task", {"task_id": child_id})])
            seen.append(tool_msgs[1]["content"])
            return _message("fin")

        llm = FakeLLM({"[PADRE]": parent, "[HIJA]": lambda m, t: _message("resultado 42")})
        result = self.run_task(self.make_agent(llm), "[PADRE]")

        self.assertEqual(result.status, ga.TaskStatus.COMPLETED)
        self.assertEqual(len(seen), 1)
        self.assertIn("resultado 42", seen[0])
        self.assertIn("[completed]", seen[0].lower())

    def test_wait_parallel_task_rejects_unknown_and_times_out(self) -> None:
        release = threading.Event()
        agent = self.make_agent(FakeLLM({"[X]": lambda m, t: (release.wait(10), _message("x"))[1]}))
        parent = self.db.create_task(title="padre", prompt="p")
        self.assertTrue(agent._wait_parallel(parent.id, {"task_id": 999}, None).startswith("ERROR"))
        self.assertTrue(agent._wait_parallel(parent.id, {}, None).startswith("ERROR"))
        child = agent.parallel.spawn(parent.id, "[X]")
        self.assertTrue(agent._wait_parallel(parent.id, {"task_id": child.id, "timeout": 0.3}, None).startswith("EN CURSO"))
        release.set()
        self.assertIn("PARALELA-1", agent._wait_parallel(parent.id, {"task_id": child.id, "timeout": 10}, None))

    def test_wait_timeout_cancels_stuck_children(self) -> None:
        stop = threading.Event()

        def child(messages, tools):
            stop.wait(10)
            return _message("tarde")

        llm = FakeLLM({"[PADRE]": self.parent_script("[HIJA] colgada"), "[HIJA]": child})
        agent = self.make_agent(llm)
        agent.parallel.wait_timeout = 0.5
        agent.parallel.CANCEL_GRACE_SECONDS = 0.5
        self.addCleanup(stop.set)
        parent = self.run_task(agent, "[PADRE]")

        self.assertEqual(parent.status, ga.TaskStatus.COMPLETED)
        self.assertIn("RESULTADOS", parent.final_answer)
        history = [h.content for h in self.db.get_history(parent.id)]
        self.assertTrue(any("Tiempo de espera agotado" in c for c in history))

    def test_concurrent_file_modification_is_blocked(self) -> None:
        agent = self.make_agent(FakeLLM({}))
        parent = self.db.create_task(title="padre", prompt="p")
        release = threading.Event()
        agent.llm.handlers["[X]"] = lambda m, t: (release.wait(10), _message("x"))[1]
        self.addCleanup(release.set)
        child = agent.parallel.spawn(parent.id, "[X]")
        target = {"path": "compartido.txt"}

        self.assertIsNone(agent._claim_file_access(child.id, "write_file", target))
        self.assertIsNone(agent._claim_file_access(child.id, "write_file", target))
        warning = agent._claim_file_access(parent.id, "edit_file", target)
        self.assertIsNotNone(warning)
        self.assertIn(f"#{child.id}", warning)
        self.assertIsNone(agent._claim_file_access(parent.id, "write_file", {"path": "otro.txt"}))
        self.assertIsNone(agent._claim_file_access(parent.id, "read_file", target))
        release.set()
        agent.parallel.wait_all(10)
        self.assertIsNone(agent._claim_file_access(parent.id, "write_file", target))

    def test_cancel_all_cancels_live_children(self) -> None:
        release = threading.Event()
        started = threading.Event()

        def child(messages, tools):
            started.set()
            release.wait(10)
            return _message("x")

        agent = self.make_agent(FakeLLM({"[X]": child}))
        parent = self.db.create_task(title="padre", prompt="p")
        task = agent.parallel.spawn(parent.id, "[X]")
        self.assertTrue(started.wait(10))
        agent.parallel.cancel_all()
        release.set()
        self.assertTrue(agent.parallel.wait_all(10))
        self.assertEqual(self.db.get_task(task.id).status, ga.TaskStatus.CANCELLED)

    def test_parallel_naming_is_unique_per_root(self) -> None:
        agent = self.make_agent(FakeLLM({"[X]": lambda m, t: _message("x")}))
        parent = self.db.create_task(title="padre", prompt="p")
        names = [agent.parallel.spawn(parent.id, "[X]").subtask_name for _ in range(3)]
        agent.parallel.wait_all(10)
        self.assertEqual(names, ["PARALELA-1", "PARALELA-2", "PARALELA-3"])

    def test_tool_schema_requires_prompt(self) -> None:
        tool = ga.ToolsRegistry().get("spawn_parallel_task")
        self.assertIsNotNone(tool)
        self.assertEqual(tool.parameters["required"], ["prompt"])
        self.assertIn("subcarpeta", tool.description)
        names = [t["function"]["name"] for t in ga.ToolsRegistry().to_openai_tools(exclude=["spawn_parallel_task"])]
        self.assertNotIn("spawn_parallel_task", names)

    def test_max_parallel_tasks_config(self) -> None:
        self.assertEqual(ga.Config.DEFAULTS["Agent"]["max_parallel_tasks"], "3")
        self.assertGreaterEqual(ga.CONFIG.max_parallel_tasks, 1)
        with patch.dict("os.environ", {"HERCULES_MAX_PARALLEL_TASKS": "7"}):
            self.assertEqual(ga.CONFIG.max_parallel_tasks, 7)
        with patch.dict("os.environ", {"HERCULES_MAX_PARALLEL_TASKS": "0"}):
            self.assertGreaterEqual(ga.CONFIG.max_parallel_tasks, 1)


if __name__ == "__main__":
    unittest.main()
