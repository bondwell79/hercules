#!/usr/bin/env python3
"""
test_global.py

Ejecuta todas las suites de tests del proyecto y muestra un resumen
global con el resultado de cada una.

Suites ejecutadas (en este orden):
    1. test_resilience.py     — resiliencia ante respuestas malformadas del LLM.
    2. test_funcionamiento.py — tareas simultáneas e historiales independientes.
    3. test_subtareas.py      — orquestador de subtareas y rectificación.

Cada suite se lanza como subproceso independiente para mantener el
aislamiento entre ellas (cada una crea y destruye su propio entorno
temporal). El código de salida de cada subproceso determina si la
suite pasa (0) o falla (distinto de 0).

Uso:
    python test_global.py
    python test_global.py --verbose   # muestra la salida completa de cada suite
    python test_global.py --quiet     # solo imprime el resumen final

Salida:
    0 si todas las suites pasan.
    1 si alguna suite falla.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, NamedTuple, Optional


# ============================================================================
# CONFIGURACIÓN
# ============================================================================

SCRIPT_DIR = Path(__file__).parent.resolve()

# Suites a ejecutar, en el orden deseado.
# (ruta_al_script, nombre_legible)
SUITES: List[tuple] = [
    (SCRIPT_DIR / "test_resilience.py",     "test_resilience"),
    (SCRIPT_DIR / "test_funcionamiento.py", "test_funcionamiento"),
    (SCRIPT_DIR / "test_subtareas.py",      "test_subtareas"),
]


# ============================================================================
# TIPOS
# ============================================================================

class SuiteResult(NamedTuple):
    name: str
    path: Path
    returncode: int
    duration: float
    stdout: str
    stderr: str


# ============================================================================
# EJECUCIÓN
# ============================================================================

def run_suite(path: Path, name: str, verbose: bool) -> SuiteResult:
    """Ejecuta una suite de tests como subproceso y devuelve su resultado."""
    if not path.exists():
        return SuiteResult(
            name=name,
            path=path,
            returncode=-1,
            duration=0.0,
            stdout="",
            stderr=f"No se encontró el fichero: {path}",
        )

    print(f"\n{'=' * 70}")
    print(f"  EJECUTANDO: {name}")
    print(f"  FICHERO:    {path.name}")
    print(f"{'=' * 70}")

    start = time.monotonic()
    try:
        # Forzar UTF-8 en stdout/stderr del subproceso para que los
        # caracteres Unicode (✓, →, etc.) de las suites no revienten
        # en Windows con cp1252.
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"

        completed = subprocess.run(
            [sys.executable, str(path)],
            cwd=str(SCRIPT_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=600,  # 10 minutos de tope por suite
        )
        duration = time.monotonic() - start
        return SuiteResult(
            name=name,
            path=path,
            returncode=completed.returncode,
            duration=duration,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    except subprocess.TimeoutExpired as e:
        duration = time.monotonic() - start
        return SuiteResult(
            name=name,
            path=path,
            returncode=-2,
            duration=duration,
            stdout=e.stdout or "",
            stderr=(e.stderr or "") + "\n[test_global] TIMEOUT: la suite excedió el tiempo máximo.",
        )
    except Exception as e:
        duration = time.monotonic() - start
        return SuiteResult(
            name=name,
            path=path,
            returncode=-3,
            duration=duration,
            stdout="",
            stderr=f"[test_global] Error al lanzar la suite: {e}",
        )


def print_suite_result(result: SuiteResult, verbose: bool, quiet: bool) -> None:
    """Imprime el resultado de una suite."""
    status = "OK " if result.returncode == 0 else "FAIL"
    print(f"\n  -> {status}  {result.name}  ({result.duration:.1f}s, exit={result.returncode})")

    if result.returncode != 0:
        # En modo normal o verbose, mostrar stderr siempre que haya fallo.
        if result.stderr.strip():
            print("\n  --- stderr ---")
            for line in result.stderr.rstrip().splitlines():
                print(f"  {line}")

    if verbose and not quiet:
        if result.stdout.strip():
            print("\n  --- stdout ---")
            for line in result.stdout.rstrip().splitlines():
                print(f"  {line}")


# ============================================================================
# MAIN
# ============================================================================

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ejecuta todas las suites de tests del proyecto.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Muestra la salida completa (stdout) de cada suite.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Solo imprime el resumen final (silencia la salida de cada suite).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    print("=" * 70)
    print("  TEST GLOBAL — hercules")
    print("=" * 70)
    print(f"  Suites a ejecutar: {len(SUITES)}")
    for _, name in SUITES:
        print(f"    - {name}")
    print()

    results: List[SuiteResult] = []
    for path, name in SUITES:
        result = run_suite(path, name, verbose=args.verbose)
        results.append(result)
        print_suite_result(result, verbose=args.verbose, quiet=args.quiet)

    # Resumen global.
    print()
    print("=" * 70)
    print("  RESUMEN GLOBAL")
    print("=" * 70)

    passed = sum(1 for r in results if r.returncode == 0)
    failed = len(results) - passed
    total_time = sum(r.duration for r in results)

    print(f"  Suites pasadas:  {passed}/{len(results)}")
    print(f"  Suites fallidas: {failed}/{len(results)}")
    print(f"  Tiempo total:    {total_time:.1f}s")
    print()
    print("  Detalle:")
    for r in results:
        status = "OK  " if r.returncode == 0 else "FAIL"
        print(f"    [{status}] {r.name:<22}  {r.duration:>5.1f}s  exit={r.returncode}")

    print()
    if failed == 0:
        print("  ✓ Todas las suites pasaron correctamente.")
        return 0

    print(f"  ✗ {failed} suite(s) con fallos. Revisa la salida anterior.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
