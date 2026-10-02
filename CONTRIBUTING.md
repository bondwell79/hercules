# Contribuir

## Reportar bugs

Abre un [issue](https://github.com/bondwell79/hercules/issues) con:
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

Ejecuta las 8 suites (resiliencia, funcionamiento, subtareas, imports/widgets/layout de UI, barra de título y diálogo de bienvenida); todas deben pasar al 100%. Añade tests para cualquier bug que corrijas.

Si añades una suite nueva, regístrala en la lista `SUITES` de `test_global.py`.

## Contacto

**Rubén Pastor** — `bondwell_@hotmail.com`
