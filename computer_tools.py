"""Funciones de automatización del ratón y captura de pantalla."""

from __future__ import annotations

import math
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


def _get_pyautogui() -> Any:
    try:
        import pyautogui
    except ImportError as exc:
        raise RuntimeError(
            "La automatización del escritorio requiere pyautogui. "
            "Instálalo con: python -m pip install pyautogui"
        ) from exc
    return pyautogui


def take_screenshot(
    path: Optional[str] = None, workspace_dir: Optional[Path] = None
) -> str:
    """Captura la pantalla y guarda el PNG, opcionalmente restringido al workspace."""
    pyautogui = _get_pyautogui()
    workspace = Path(workspace_dir).expanduser().resolve() if workspace_dir else None
    if path:
        requested_path = Path(path).expanduser()
        if workspace is not None and not requested_path.is_absolute():
            requested_path = workspace / requested_path
        output_path = requested_path.resolve()
    else:
        filename = datetime.now().strftime("hercules_screenshot_%Y%m%d_%H%M%S_%f.png")
        output_path = ((workspace or Path.cwd()) / filename).resolve()

    if workspace is not None:
        try:
            output_path.relative_to(workspace)
        except ValueError as exc:
            raise ValueError(
                f"Ruta fuera del workspace permitido ({workspace}): {output_path}"
            ) from exc

    output_path.parent.mkdir(parents=True, exist_ok=True)
    image = pyautogui.screenshot()
    image.save(str(output_path), format="PNG")
    return f"Captura de pantalla guardada en: {output_path} ({image.width}x{image.height})"


def mouse_click(x: int, y: int, button: str = "left", clicks: int = 1) -> str:
    """Hace clic en una posición de pantalla con el botón indicado."""
    if button not in {"left", "right", "middle"}:
        raise ValueError("button debe ser 'left', 'right' o 'middle'")
    if isinstance(clicks, bool) or not isinstance(clicks, int) or clicks < 1:
        raise ValueError("clicks debe ser un entero mayor que cero")

    _get_pyautogui().click(x=x, y=y, clicks=clicks, button=button)
    return f"Clic ({button}) realizado en ({x}, {y}); cantidad: {clicks}."


def mouse_move(x: int, y: int, duration: float = 0.0) -> str:
    """Mueve el puntero a una posición de pantalla."""
    if isinstance(duration, bool) or not isinstance(duration, (int, float)):
        raise ValueError("duration debe ser un número no negativo")
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("duration debe ser un número finito no negativo")

    _get_pyautogui().moveTo(x=x, y=y, duration=duration)
    return f"Puntero movido a ({x}, {y})."
