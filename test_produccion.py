#!/usr/bin/env python3
"""
test_produccion.py

Tests de robustez para producción: cancelación de peticiones al LLM,
compactación de contexto, configuración tolerante a errores, cierre de
conexiones SQLite, orquestación ante excepciones y arranque.

Ejecutar:
    python test_produccion.py
"""

from __future__ import annotations

import http.server
import json
import os
import queue
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.resolve()))

import hercules as ga  # noqa: E402


class _HangingServer:
    """Servidor TCP que acepta conexiones y nunca responde."""

    def __init__(self) -> None:
        import socket

        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.conns: list = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                self.conns.append(self.sock.accept())
            except OSError:
                return

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.sock.getsockname()[1]}/v1"

    def close(self) -> None:
        self.sock.close()
        for conn, _ in self.conns:
            conn.close()


class LLMCancellationTests(unittest.TestCase):
    def test_http_request_is_aborted_when_cancel_event_is_set(self) -> None:
        server = _HangingServer()
        self.addCleanup(server.close)
        llm = ga.LLMConnector(mode="http", base_url=server.base_url, timeout=60)
        cancel = threading.Event()
        threading.Timer(0.5, cancel.set).start()
        started = time.monotonic()
        with self.assertRaises(ga.LLMCancelled):
            llm.chat([{"role": "user", "content": "x"}], cancel_event=cancel)
        self.assertLess(time.monotonic() - started, 5)

    def test_waiting_for_busy_llm_lock_is_cancellable(self) -> None:
        llm = ga.LLMConnector(mode="http", base_url="http://127.0.0.1:1/v1", timeout=60)
        cancel = threading.Event()
        self.assertTrue(llm._lock.acquire(timeout=1))
        self.addCleanup(llm._lock.release)
        threading.Timer(0.4, cancel.set).start()
        started = time.monotonic()
        with self.assertRaises(ga.LLMCancelled):
            llm.chat([{"role": "user", "content": "x"}], cancel_event=cancel)
        self.assertLess(time.monotonic() - started, 5)

    def test_waiting_for_busy_llm_lock_honours_timeout(self) -> None:
        llm = ga.LLMConnector(mode="http", base_url="http://127.0.0.1:1/v1", timeout=60)
        self.assertTrue(llm._lock.acquire(timeout=1))
        self.addCleanup(llm._lock.release)
        started = time.monotonic()
        with self.assertRaises(ga.LLMError) as ctx:
            llm.chat([{"role": "user", "content": "x"}], timeout=0.5)
        self.assertIn("Timeout", str(ctx.exception))
        self.assertLess(time.monotonic() - started, 5)

    def test_local_model_is_not_loaded_in_constructor(self) -> None:
        llm = ga.LLMConnector(mode="local", model_path="no_existe", model="x.gguf")
        with self.assertRaises(ga.LLMError):
            llm.chat([{"role": "user", "content": "x"}])


class _ScriptedLLM:
    """LLM falso: devuelve respuestas guiadas y registra los mensajes."""

    def __init__(self, responses: list) -> None:
        self.responses = list(responses)
        self.calls: list = []

    def chat(self, messages, tools=None, tool_choice=None, timeout=None, cancel_event=None):
        self.calls.append([dict(m) for m in messages])
        item = self.responses.pop(0) if self.responses else self._final("fin")
        if isinstance(item, BaseException):
            raise item
        return item

    @staticmethod
    def _final(text: str) -> dict:
        return {"choices": [{"message": {"role": "assistant", "content": text}}]}

    @staticmethod
    def tool_call(name: str, args: dict, call_id: str = "c1") -> dict:
        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": call_id,
                                "type": "function",
                                "function": {"name": name, "arguments": json.dumps(args)},
                            }
                        ],
                    }
                }
            ]
        }


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = ga.Database(db_path=str(Path(self.tmp.name) / "t.db"))
        self.ui_queue: queue.Queue = queue.Queue()
        self.permissions = ga.PermissionManager(self.ui_queue)

    def make_agent(self, llm) -> ga.Agent:
        return ga.Agent(self.db, llm, ga.ToolsRegistry(), self.permissions, self.ui_queue)


class CompactionTests(_Base):
    def _messages(self) -> list:
        return [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "haz algo"},
            {
                "role": "assistant",
                "content": "pienso",
                "tool_calls": [
                    {"id": "1", "type": "function", "function": {"name": "read_file", "arguments": "{}"}}
                ],
            },
            {"role": "tool", "tool_call_id": "1", "content": "resultado"},
        ]

    def test_compaction_never_leaves_consecutive_user_messages(self) -> None:
        task = self.db.create_task("t", "p")
        agent = self.make_agent(_ScriptedLLM([]))
        compacted = agent._compact_context(task.id, self._messages(), reason="bucle")
        roles = [m["role"] for m in compacted]
        self.assertEqual(roles, ["system", "user"])
        self.assertIn("haz algo", compacted[1]["content"])
        self.assertIn("CONTEXTO COMPACTADO", compacted[1]["content"])

    def test_repeated_compaction_does_not_accumulate_summaries(self) -> None:
        task = self.db.create_task("t", "p")
        agent = self.make_agent(_ScriptedLLM([]))
        first = agent._compact_context(task.id, self._messages(), reason="bucle")
        again = first + self._messages()[2:]
        second = agent._compact_context(task.id, again, reason="bucle")
        self.assertEqual(second[1]["content"].count("haz algo"), 1)
        self.assertEqual(second[1]["content"].count("CONTEXTO COMPACTADO:"), 1)

    def test_compaction_keeps_latest_image_in_user_message(self) -> None:
        task = self.db.create_task("t", "p")
        agent = self.make_agent(_ScriptedLLM([]))
        messages = self._messages() + [ga._image_message("data:image/png;base64,AAAA")]
        compacted = agent._compact_context(task.id, messages, reason="exceso_contexto")
        self.assertEqual([m["role"] for m in compacted], ["system", "user"])
        kinds = [p["type"] for p in compacted[1]["content"]]
        self.assertEqual(kinds, ["text", "image_url"])

    def test_oversized_prompt_still_reaches_the_model(self) -> None:
        """Un prompt que ya supera el umbral no debe agotar las iteraciones."""
        llm = _ScriptedLLM([_ScriptedLLM._final("ok")])
        agent = self.make_agent(llm)
        big = "x" * (ga.LLM_N_CTX * 4)
        task = self.db.create_task("t", big)
        with patch.object(ga, "MAX_ITERATIONS", 5):
            agent.run(task)
        self.assertGreaterEqual(len(llm.calls), 1)
        self.assertEqual(self.db.get_task(task.id).status, ga.TaskStatus.COMPLETED)

    def test_server_context_overflow_triggers_compaction_and_retry(self) -> None:
        llm = _ScriptedLLM(
            [
                _ScriptedLLM.tool_call("get_current_time", {}),
                ga.LLMContextOverflow("HTTP 400: context length exceeded"),
                _ScriptedLLM._final("hecho"),
            ]
        )
        agent = self.make_agent(llm)
        task = self.db.create_task("t", "dime la hora")
        agent.run(task)
        self.assertEqual(self.db.get_task(task.id).status, ga.TaskStatus.COMPLETED)
        retry_messages = llm.calls[-1]
        self.assertEqual([m["role"] for m in retry_messages], ["system", "user"])

    def test_huge_tool_output_is_trimmed_for_context(self) -> None:
        text = "y" * 500_000
        fitted = ga.Agent._fit_tool_output(text)
        self.assertLess(len(fitted), len(text))
        self.assertIn("recortado", fitted)
        self.assertEqual(ga.Agent._fit_tool_output("corto"), "corto")

    def test_cancelled_llm_call_marks_task_cancelled(self) -> None:
        llm = _ScriptedLLM([ga.LLMCancelled("cancelada")])
        agent = self.make_agent(llm)
        task = self.db.create_task("t", "p")
        agent.run(task, cancel_event=threading.Event())
        self.assertEqual(self.db.get_task(task.id).status, ga.TaskStatus.CANCELLED)


class OrchestratorFailureTests(_Base):
    def test_unexpected_exception_leaves_no_task_unfinished(self) -> None:
        class Exploding:
            def run(self, task, cancel_event=None):
                raise RuntimeError("boom")

        plan = [("ETAPA_1", "haz {user_prompt}"), ("ETAPA_2", "luego")]
        orch = ga.TaskOrchestrator(self.db, Exploding(), self.ui_queue)
        parent = self.db.create_task("padre", "prompt")
        with patch.object(ga, "_load_subtask_plan", return_value=plan):
            orch.run(parent)
        self.assertEqual(self.db.get_task(parent.id).status, ga.TaskStatus.FAILED)
        for child in self.db.list_subtasks(parent.id):
            self.assertIn(child.status, ga.TaskStatus.finished())

    def test_parent_is_marked_in_progress_while_running(self) -> None:
        seen: list = []

        class Recorder:
            def __init__(inner, db):
                inner.db = db

            def run(inner, task, cancel_event=None):
                seen.append(inner.db.get_task(task.parent_task_id).status)
                inner.db.update_task_status(task.id, ga.TaskStatus.COMPLETED, final_answer="ok")

        orch = ga.TaskOrchestrator(self.db, Recorder(self.db), self.ui_queue)
        parent = self.db.create_task("padre", "prompt")
        with patch.object(ga, "_load_subtask_plan", return_value=[("E", "x")]):
            orch.run(parent)
        self.assertEqual(seen, [ga.TaskStatus.IN_PROGRESS])
        self.assertEqual(self.db.get_task(parent.id).status, ga.TaskStatus.COMPLETED)


class DatabaseTests(_Base):
    def test_connections_are_closed_so_file_can_be_deleted(self) -> None:
        task = self.db.create_task("t", "p")
        self.db.add_history(task.id, ga.EventType.INFO, "hola")
        self.db.get_history(task.id)
        self.db.list_tasks([ga.TaskStatus.PENDING])
        os.remove(self.db.db_path)
        self.assertFalse(os.path.exists(self.db.db_path))

    def test_history_after_and_subtasks_many(self) -> None:
        parent = self.db.create_task("p", "p")
        e1 = self.db.add_history(parent.id, ga.EventType.INFO, "a")
        self.db.add_history(parent.id, ga.EventType.INFO, "b")
        self.assertEqual([h.content for h in self.db.get_history_after(parent.id, e1.id)], ["b"])
        c1 = self.db.create_task("c1", "x", parent_task_id=parent.id)
        c2 = self.db.create_task("c2", "x", parent_task_id=parent.id)
        grouped = self.db.list_subtasks_many([parent.id, 9999])
        self.assertEqual([t.id for t in grouped[parent.id]], [c1.id, c2.id])
        self.assertEqual(grouped[9999], [])

    def test_concurrent_writers_do_not_fail(self) -> None:
        task = self.db.create_task("t", "p")
        errors: list = []

        def writer() -> None:
            try:
                for i in range(30):
                    self.db.add_history(task.id, ga.EventType.INFO, str(i))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=writer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(self.db.get_history(task.id)), 120)


class ConfigTests(unittest.TestCase):
    def _config(self, text: str) -> ga.Config:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "config.ini"
        path.write_text(text, encoding="utf-8")
        return ga.Config(str(path))

    def test_invalid_numbers_in_ini_fall_back_to_defaults(self) -> None:
        cfg = self._config(
            "[LLM]\ntimeout = abc\nn_ctx = 12.5\n[Agent]\nmax_iterations = -3\n"
            "command_timeout = nan\nno_authorization = quizas\n"
        )
        self.assertEqual(cfg.llm_timeout, 120.0)
        self.assertEqual(cfg.llm_retries, 3)
        self.assertEqual(cfg.llm_n_ctx, 8192)
        self.assertEqual(cfg.max_iterations, 10)
        self.assertEqual(cfg.command_timeout, 120.0)
        self.assertFalse(cfg.no_authorization)

    def test_http_retries_below_minimum_fall_back_to_default(self) -> None:
        cfg = self._config("[LLM]\nretries = 0\n")
        self.assertEqual(cfg.llm_retries, 3)

    def test_invalid_environment_values_do_not_crash(self) -> None:
        cfg = self._config("[LLM]\ntimeout = 33\n")
        with patch.dict(os.environ, {"LLM_TIMEOUT": "rapido", "HERCULES_MAX_ITER": "x"}):
            self.assertEqual(cfg.llm_timeout, 33.0)
            self.assertEqual(cfg.max_iterations, 10)

    def test_percent_sign_in_values_is_accepted(self) -> None:
        cfg = self._config("[LLM]\nuser_agent = Agent 100% real\n")
        self.assertEqual(cfg.llm_user_agent, "Agent 100% real")

    def test_default_paths_are_anchored_to_application_dir(self) -> None:
        self.assertTrue(Path(ga.DB_PATH).is_absolute())
        self.assertTrue(Path(ga.CONFIG_PATH).is_absolute() or os.environ.get("HERCULES_CONFIG"))
        self.assertTrue(ga.WORKSPACE_DIR.is_absolute())


class StartupTests(unittest.TestCase):
    def test_unrelated_missing_module_is_not_masked(self) -> None:
        with patch.dict(sys.modules, {"hercules_qt": None}), patch.object(ga, "setup_logging"):
            with self.assertRaises(ImportError) as ctx:
                ga.main()
        self.assertNotIsInstance(ctx.exception, UnboundLocalError)

    def test_missing_pyside_exits_with_message(self) -> None:
        err = ModuleNotFoundError("No module named 'PySide6'", name="PySide6")
        real_import = __import__

        def fake_import(name, *args, **kwargs):
            if name == "hercules_qt":
                raise err
            return real_import(name, *args, **kwargs)

        with (
            patch("builtins.__import__", side_effect=fake_import),
            patch.object(ga, "setup_logging"),
            patch.object(ga, "_report_fatal_startup_error") as report,
        ):
            with self.assertRaises(SystemExit) as ctx:
                ga.main()
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("PySide6", report.call_args.args[0])


class LogTests(unittest.TestCase):
    def test_log_entries_are_truncated_and_rotated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.object(ga, "LOG_DIR", Path(tmp)),
                patch.object(ga, "_LLM_LOG_ENTRY_MAX_CHARS", 100),
                patch.object(type(ga.CONFIG), "log_max_bytes", property(lambda _s: 1000)),
            ):
                for _ in range(20):
                    ga._log_llm_exchange("SALIDA", "u", "z" * 5000)
                files = sorted(p.name for p in Path(tmp).iterdir())
                total = sum(p.stat().st_size for p in Path(tmp).iterdir())
        self.assertTrue(any(name.endswith(".1") for name in files), files)
        self.assertLess(total, 20 * 1000)

    def test_old_logs_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "llm_20000101.txt"
            fresh = Path(tmp) / "llm_29990101.txt"
            old.write_text("x")
            fresh.write_text("x")
            past = time.time() - 365 * 86400
            os.utime(old, (past, past))
            with patch.object(ga, "LOG_DIR", Path(tmp)):
                ga._cleanup_old_logs()
            self.assertFalse(old.exists())
            self.assertTrue(fresh.exists())


class HttpErrorMappingTests(unittest.TestCase):
    def test_http_context_overflow_error_is_classified(self) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = b'{"error": "prompt is too long: exceeds the available context size"}'
                self.send_response(400)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        llm = ga.LLMConnector(
            mode="http", base_url=f"http://127.0.0.1:{server.server_address[1]}/v1", timeout=5
        )
        with self.assertRaises(ga.LLMContextOverflow):
            llm.chat([{"role": "user", "content": "x"}])

    def test_http_retries_connection_failure_before_success(self) -> None:
        llm = ga.LLMConnector(mode="http", base_url="http://localhost/v1", retries=2)
        with patch.object(
            ga.LLMConnector,
            "_perform_http",
            side_effect=[ga._LLMRetryableError("connection reset"), {"ok": True}],
        ) as perform:
            result = llm._chat_http(
                [{"role": "user", "content": "x"}], None, None
            )
        self.assertEqual(result, {"ok": True})
        self.assertEqual(perform.call_count, 2)

    def test_http_retries_stop_at_configured_limit(self) -> None:
        llm = ga.LLMConnector(mode="http", base_url="http://localhost/v1", retries=1)
        with patch.object(
            ga.LLMConnector,
            "_perform_http",
            side_effect=ga._LLMRetryableError("connection reset"),
        ) as perform:
            with self.assertRaises(ga._LLMRetryableError):
                llm._chat_http(
                    [{"role": "user", "content": "x"}], None, None
                )
        self.assertEqual(perform.call_count, 2)


class GuiResponsivenessTests(unittest.TestCase):
    """Comprueba la GUI real (Qt offscreen) con una BD real."""

    @classmethod
    def setUpClass(cls) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
        os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu --no-sandbox")
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        import types

        from hercules_qt import QtDashboard

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        tmp = Path(self.tmp.name)
        db_path = str(tmp / "gui.db")
        core = types.SimpleNamespace(**{k: getattr(ga, k) for k in dir(ga) if not k.startswith("__")})
        core.WORKSPACE_DIR = tmp
        core.Database = lambda: ga.Database(db_path=db_path)
        core.LLMConnector = lambda: object()
        self.window = QtDashboard(core)
        self.addCleanup(self.window.close)
        self.db = self.window.db

    def _history_text(self) -> str:
        return self.window.history_view.toPlainText()

    def test_history_updates_are_appended_not_redrawn(self) -> None:
        task = self.db.create_task("t", "p")
        self.window._select_task(task.id)
        self.db.add_history(task.id, ga.EventType.INFO, "primera")
        self.window.ui_queue.put({"type": "history_update", "task_id": task.id})
        self.window._poll_queue()
        self.assertIn("primera", self._history_text())
        with patch.object(self.window, "_select_task", side_effect=AssertionError("repintado completo")):
            self.db.add_history(task.id, ga.EventType.INFO, "segunda")
            self.window.ui_queue.put({"type": "history_update", "task_id": task.id})
            self.window._poll_queue()
        text = self._history_text()
        self.assertEqual(text.count("primera"), 1)
        self.assertEqual(text.count("segunda"), 1)

    def test_burst_of_events_is_coalesced_and_bounded(self) -> None:
        task = self.db.create_task("t", "p")
        self.window._select_task(task.id)
        for i in range(2000):
            self.db.add_history(task.id, ga.EventType.INFO, f"e{i}")
        for _ in range(2000):
            self.window.ui_queue.put({"type": "history_update", "task_id": task.id})
        calls: list = []
        original = self.window._refresh_history_incremental
        self.window._refresh_history_incremental = lambda tid: (calls.append(tid), original(tid))[1]
        started = time.monotonic()
        self.window._poll_queue()
        self.assertLess(time.monotonic() - started, 2)
        self.assertLessEqual(len(calls), 1)
        while not self.window.ui_queue.empty():
            self.window._poll_queue()
        self.assertEqual(self._history_text().count("e1999"), 1)

    def test_failing_event_does_not_block_following_events(self) -> None:
        self.window.ui_queue.put({"type": "approval_request"})
        self.window.ui_queue.put({"type": "refresh_file_browser"})
        self.window.ui_queue.put({"type": "context_usage", "task_id": 7, "tokens_used": 1, "max_tokens": 2, "percent": 50})
        self.window._poll_queue()
        self.assertEqual(self.window._context_usage[7]["percent"], 50)

    def test_task_tree_is_not_rebuilt_when_nothing_changed(self) -> None:
        parent = self.db.create_task("padre", "p")
        self.db.create_task("hijo", "x", parent_task_id=parent.id)
        self.window._refresh_task_lists()
        tree = self.window.active_tasks
        first_item = tree.topLevelItem(0)
        self.assertIsNotNone(first_item)
        self.assertEqual(first_item.childCount(), 1)
        self.window._refresh_task_lists()
        self.assertIs(tree.topLevelItem(0), first_item)
        self.db.update_task_status(parent.id, ga.TaskStatus.IN_PROGRESS)
        self.window._refresh_task_lists()
        self.assertIsNot(tree.topLevelItem(0), first_item)

    def test_subtasks_are_fetched_with_a_single_query(self) -> None:
        for i in range(5):
            parent = self.db.create_task(f"p{i}", "p")
            self.db.create_task(f"c{i}", "x", parent_task_id=parent.id)
        with patch.object(self.db, "list_subtasks", side_effect=AssertionError("N+1")):
            self.window._refresh_task_lists()
        self.assertEqual(self.window.active_tasks.topLevelItemCount(), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
