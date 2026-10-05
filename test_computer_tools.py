#!/usr/bin/env python3
"""Tests de herramientas de captura de pantalla y control del ratón."""

from __future__ import annotations

import base64
import random
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

import computer_tools  # noqa: E402
import hercules  # noqa: E402


class ToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.workspace = Path(self.temp_dir.name).resolve()
        self.workspace_patch = patch.object(hercules, "WORKSPACE_DIR", self.workspace)
        self.workspace_patch.start()
        self.addCleanup(self.workspace_patch.stop)
        (self.workspace / "sample.txt").write_text("alpha\nbeta alpha\n", encoding="utf-8")

    def test_registry_includes_every_tool_and_correct_risk(self) -> None:
        expected_risks = {
            "read_file": hercules.RiskLevel.SAFE,
            "read_binary_file": hercules.RiskLevel.SAFE,
            "read_binary_hex": hercules.RiskLevel.SAFE,
            "list_directory": hercules.RiskLevel.SAFE,
            "search_files": hercules.RiskLevel.SAFE,
            "get_current_time": hercules.RiskLevel.SAFE,
            "take_screenshot": hercules.RiskLevel.SAFE,
            "mouse_click": hercules.RiskLevel.SAFE,
            "mouse_move": hercules.RiskLevel.SAFE,
            "write_file": hercules.RiskLevel.SAFE,
            "create_file": hercules.RiskLevel.SAFE,
            "edit_file": hercules.RiskLevel.SAFE,
            "search_in_files": hercules.RiskLevel.SAFE,
            "execute_command": hercules.RiskLevel.CRITICAL,
            "delete_file": hercules.RiskLevel.SAFE,
        }
        tools = {tool.name: tool for tool in hercules.ToolsRegistry().all()}

        self.assertEqual(set(tools), set(expected_risks))
        for name, expected_risk in expected_risks.items():
            with self.subTest(tool=name):
                self.assertEqual(tools[name].risk, expected_risk)
                self.assertTrue(callable(tools[name].runner))

    def test_read_file(self) -> None:
        self.assertEqual(hercules.tool_read_file({"path": "sample.txt"}), "alpha\nbeta alpha\n")
        self.assertIn("no existe", hercules.tool_read_file({"path": "missing.txt"}))

    def test_read_binary_file_returns_base64(self) -> None:
        (self.workspace / "sample.bin").write_bytes(b"\x00\xffbinary")
        result = hercules.tool_read_binary_file({"path": "sample.bin"})
        self.assertEqual(result, "Base64 (8 bytes): AP9iaW5hcnk=")
        self.assertIn("no existe", hercules.tool_read_binary_file({"path": "missing.bin"}))

    def test_read_binary_hex_supports_offset_and_length(self) -> None:
        (self.workspace / "sample.bin").write_bytes(b"\x00ABCD\xff")
        result = hercules.tool_read_binary_hex(
            {"path": "sample.bin", "offset": 1, "length": 4}
        )
        self.assertEqual(result, "00000001  41 42 43 44                                      |ABCD|")
        self.assertEqual(
            hercules.tool_read_binary_hex({"path": "sample.bin", "offset": 7, "length": 8}),
            "(sin datos en el rango solicitado)",
        )
        self.assertIn("no puede superar", hercules.tool_read_binary_hex({"path": "sample.bin", "length": 4097}))

    def test_list_directory(self) -> None:
        listing = hercules.tool_list_directory({"path": "."})
        self.assertIn("sample.txt", listing)
        self.assertIn("no existe", hercules.tool_list_directory({"path": "missing"}))

    def test_search_files(self) -> None:
        self.assertIn("sample.txt", hercules.tool_search_files({"pattern": "*.txt"}))
        self.assertIn("obligatorio", hercules.tool_search_files({"pattern": ""}))

    def test_screenshot_data_uri_requires_workspace_png_and_valid_signature(self) -> None:
        screenshot = self.workspace / "screen.png"
        screenshot.write_bytes(bytes.fromhex("89504e470d0a1a0a") + b"image-data")
        output = f"Captura de pantalla guardada en: {screenshot} (10x20)"

        with patch.object(hercules, "WORKSPACE_DIR", self.workspace):
            data_uri = hercules._screenshot_data_uri(output)

        self.assertIsNotNone(data_uri)
        self.assertTrue(data_uri.startswith("data:image/png;base64,"))
        image_message = hercules._image_message(data_uri)
        self.assertEqual(image_message["content"][1]["type"], "image_url")
        redacted = hercules._redact_image_payloads(image_message)
        self.assertEqual(
            redacted["content"][1]["image_url"]["url"],
            "data:image/[contenido omitido del log]",
        )
        self.assertIsNone(hercules._screenshot_data_uri("screenshot"))

    def test_oversized_screenshot_is_compressed_under_four_megabytes(self) -> None:
        from PIL import Image

        screenshot = self.workspace / "large.png"
        rng = random.Random(42)
        pixels = rng.randbytes(1800 * 1800 * 3)
        Image.frombytes("RGB", (1800, 1800), pixels).save(screenshot, format="PNG")
        self.assertGreater(screenshot.stat().st_size, 4 * 1024 * 1024)
        output = f"Captura de pantalla guardada en: {screenshot} (1800x1800)"

        with patch.object(hercules, "WORKSPACE_DIR", self.workspace):
            data_uri = hercules._screenshot_data_uri(output)

        self.assertIsNotNone(data_uri)
        self.assertTrue(data_uri.startswith("data:image/jpeg;base64,"))
        encoded_image = data_uri.split(",", 1)[1]
        image_bytes = base64.b64decode(encoded_image)
        self.assertLessEqual(len(image_bytes), 4 * 1024 * 1024)

    def test_get_current_time_returns_iso_timestamp(self) -> None:
        timestamp = hercules.tool_get_current_time({})
        self.assertEqual(len(timestamp), 19)
        self.assertEqual(timestamp[4], "-")
        self.assertEqual(timestamp[10], "T")

    def test_screenshot_saves_png_to_requested_path(self) -> None:
        image = Mock(width=1920, height=1080)
        pyautogui = Mock(screenshot=Mock(return_value=image))
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "nested" / "screen.png"
            with patch.object(computer_tools, "_get_pyautogui", return_value=pyautogui):
                result = computer_tools.take_screenshot(str(output_path))

        pyautogui.screenshot.assert_called_once_with()
        image.save.assert_called_once_with(str(output_path.resolve()), format="PNG")
        self.assertIn(str(output_path.resolve()), result)
        self.assertIn("1920x1080", result)

    def test_mouse_click_forwards_coordinates_and_options(self) -> None:
        pyautogui = Mock()
        with patch.object(computer_tools, "_get_pyautogui", return_value=pyautogui):
            result = computer_tools.mouse_click(12, 34, button="right", clicks=2)

        pyautogui.click.assert_called_once_with(x=12, y=34, clicks=2, button="right")
        self.assertIn("(12, 34)", result)

    def test_mouse_move_forwards_coordinates_and_duration(self) -> None:
        pyautogui = Mock()
        with patch.object(computer_tools, "_get_pyautogui", return_value=pyautogui):
            result = computer_tools.mouse_move(56, 78, duration=0.5)

        pyautogui.moveTo.assert_called_once_with(x=56, y=78, duration=0.5)
        self.assertIn("(56, 78)", result)

    def test_invalid_mouse_arguments_are_rejected(self) -> None:
        with patch.object(computer_tools, "_get_pyautogui") as get_pyautogui:
            with self.assertRaises(ValueError):
                computer_tools.mouse_click(1, 2, button="auxiliary")
            with self.assertRaises(ValueError):
                computer_tools.mouse_click(1, 2, clicks=0)
            with self.assertRaises(ValueError):
                computer_tools.mouse_move(1, 2, duration=-1)
        get_pyautogui.assert_not_called()

    def test_write_file(self) -> None:
        result = hercules.tool_write_file({"path": "nested/out.txt", "content": "written"})
        self.assertIn("OK: escrito 7 caracteres", result)
        self.assertEqual((self.workspace / "nested" / "out.txt").read_text(encoding="utf-8"), "written")

    def test_create_file(self) -> None:
        result = hercules.tool_create_file({"path": "new.txt", "content": "created"})
        self.assertIn("OK: creado 7 caracteres", result)
        self.assertEqual((self.workspace / "new.txt").read_text(encoding="utf-8"), "created")
        self.assertIn("ya existe", hercules.tool_create_file({"path": "new.txt", "content": "again"}))

    def test_edit_file(self) -> None:
        result = hercules.tool_edit_file({"path": "sample.txt", "old_text": "beta", "new_text": "gamma"})
        self.assertIn("OK: editado", result)
        self.assertEqual((self.workspace / "sample.txt").read_text(encoding="utf-8"), "alpha\ngamma alpha\n")
        self.assertIn("0", hercules.tool_edit_file({"path": "sample.txt", "old_text": "missing", "new_text": "x"}))

    def test_search_in_files(self) -> None:
        result = hercules.tool_search_in_files({"query": "alpha", "file_pattern": "*.txt"})
        self.assertIn("sample.txt:1: alpha", result)
        self.assertIn("sample.txt:2: beta alpha", result)
        self.assertIn("obligatorio", hercules.tool_search_in_files({"query": ""}))

    def test_execute_command(self) -> None:
        with patch.object(hercules.subprocess, "run", return_value=Mock(stdout="command output", stderr="", returncode=0)) as run:
            result = hercules.tool_execute_command({"command": "echo test"})
        self.assertEqual(result, "command output")
        self.assertEqual(run.call_args.kwargs["cwd"], str(self.workspace))
        self.assertIn("obligatorio", hercules.tool_execute_command({"command": ""}))
        with patch.object(hercules.subprocess, "run") as run:
            blocked = hercules.tool_execute_command({"command": "shutdown /s"})
        self.assertIn("bloqueado", blocked)
        run.assert_not_called()

    def test_delete_file(self) -> None:
        (self.workspace / "remove.txt").write_text("remove", encoding="utf-8")
        result = hercules.tool_delete_file({"path": "remove.txt"})
        self.assertIn("OK: eliminado", result)
        self.assertFalse((self.workspace / "remove.txt").exists())
        self.assertIn("no existe", hercules.tool_delete_file({"path": "remove.txt"}))

    def test_hercules_tool_adapters_forward_arguments(self) -> None:
        with patch.object(hercules.computer_tools, "take_screenshot", return_value="screenshot") as shot:
            self.assertEqual(hercules.tool_take_screenshot({"path": "out.png"}), "screenshot")
            shot.assert_called_once_with(self.workspace / "out.png", workspace_dir=self.workspace)

            shot.reset_mock()
            self.assertEqual(hercules.tool_take_screenshot({}), "screenshot")
            shot.assert_called_once_with(None, workspace_dir=self.workspace)

            shot.reset_mock()
            outside_path = Path(self.temp_dir.name).parent / "outside.png"
            result = hercules.tool_take_screenshot({"path": str(outside_path)})
            self.assertIn("fuera del workspace", result)
            shot.assert_not_called()

        with patch.object(hercules.computer_tools, "mouse_click", return_value="clicked") as click:
            self.assertEqual(hercules.tool_mouse_click({"x": 2, "y": 3}), "clicked")
            click.assert_called_once_with(x=2, y=3, button="left", clicks=1)

        with patch.object(hercules.computer_tools, "mouse_move", return_value="moved") as move:
            self.assertEqual(hercules.tool_mouse_move({"x": 4, "y": 5}), "moved")
            move.assert_called_once_with(x=4, y=5, duration=0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
