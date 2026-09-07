# Contribuir

## Reportar bugs

Abre un [issue](https://github.com/ruben-pastor/gestor-agentes/issues) con:
- Pasos para reproducir.
- Salida esperada vs. obtenida.
- Versión de Python y SO.
- Contenido relevante de `hercules.db` (si aplica).

## Proponer features

Abre un issue con la etiqueta `enhancement` antes de enviar un PR.

## Estilo de código

- PEP 8.
- Type hints en funciones públicas.
- Docstrings en clases y funciones no triviales.
- Sin dependencias externas (excepto `llama-cpp-python` opcional).

## Tests

Antes de enviar un PR:

```bash
python test_global.py
```

Ejecuta las 3 suites (`test_resilience.py`, `test_funcionamiento.py`, `test_subtareas.py`); todas deben pasar al 100%. Añade tests para cualquier bug que corrijas.

## Contacto

**Rubén Pastor** — `bondwell_@hotmail.com`
