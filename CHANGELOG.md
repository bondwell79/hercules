# Changelog

Todos los cambios notables se documentan aquí. Formato basado en [Keep a Changelog](https://keepachangelog.com/).

**Mantenedor:** Rubén Pastor — `bondwell_@hotmail.com`

## [Unreleased]

### Fixed (robustez para producción)
- **Abortar ya interrumpe la petición al LLM.** `LLMConnector.chat()` acepta `cancel_event`: la espera del lock y la petición HTTP se cancelan en ~0,1 s (nueva excepción `LLMCancelled`) en lugar de bloquear hasta `timeout`. En modo local se detiene además la generación.
- **La consulta de preautorización ya no deja el LLM bloqueado:** al expirar su plazo aborta su petición y libera el lock; la espera del lock respeta el timeout y la cancelación.
- **Compactación de contexto:** el resumen se fusiona en el mensaje de usuario original (nunca dos `user` seguidos), no se acumula entre compactaciones y la petición se envía en la misma iteración (un prompt enorme ya no agota las iteraciones sin llamar al modelo). La estimación de tokens cuenta el esquema de herramientas (3 caracteres/token), los resultados de herramienta se acotan y un error de desbordamiento del servidor (`LLMContextOverflow`) dispara una compactación con reintento.
- **Tareas huérfanas:** `TaskOrchestrator.run` marca la tarea padre como `IN_PROGRESS` y, ante cualquier excepción, deja padre y subtareas en `FAILED`.
- **Arranque:** los valores numéricos/booleanos inválidos de `config.ini` o de variables de entorno ya no tumban la aplicación (se avisa y se usa el valor por defecto); `%` en un valor no provoca error de interpolación; el modelo local se carga en la primera inferencia (no bloquea la GUI ni impide abrirla si falta); `config.ini`, `hercules.db`, `workspace` y `subtareas.ini` se resuelven respecto al directorio de la aplicación, no al directorio de trabajo.
- **`main()`:** un módulo ausente distinto de PySide6 ya no provoca `UnboundLocalError`; los fallos de arranque se muestran en un cuadro de diálogo (builds sin consola) y se registran.
- **GUI fluida con tareas largas:** el historial se actualiza de forma incremental, la cola de eventos se vacía con presupuesto de tiempo y agrupando refrescos, un evento defectuoso ya no bloquea al resto, y el tablero de tareas usa una sola consulta para las subtareas y solo se reconstruye si cambia.
- **SQLite:** las conexiones se cierran realmente (antes solo se confirmaba la transacción) y se usa modo WAL.
- **Logs:** `log/hercules.log` con rotación recoge las excepciones no controladas de cualquier hilo; los logs de intercambio con el LLM se acotan por entrada y por tamaño, y se purgan por antigüedad (`log_max_mb`, `log_retention_days` en `[Agent]`).
- Nueva suite `test_produccion.py` incluida en `test_global.py`.

### Added
- **Barra de título moderna (Windows 10/11 vía DWM).** Nueva función `_apply_modern_titlebar()` que personaliza la barra de título nativa usando la API DWM (`DwmSetWindowAttribute`) sin dependencias externas. Cuatro estilos configurables desde `[UI]` en `config.ini`:
  - `titlebar_style = "system"` — aspecto clásico de Windows (por defecto).
  - `titlebar_style = "dark"` — modo oscuro nativo (texto/iconos blancos sobre fondo oscuro del sistema). Funciona en Windows 10 1903+ y Windows 11.
  - `titlebar_style = "accent"` — usa el color de acento del sistema como fondo de la barra de título (Windows 11 22H2+).
  - `titlebar_style = "custom"` — usa los colores definidos en `titlebar_color` y `titlebar_text_color` (Windows 11 22H2+).
- Variables de entorno equivalentes: `HERCULES_TITLEBAR_STYLE`, `HERCULES_TITLEBAR_COLOR`, `HERCULES_TITLEBAR_TEXT_COLOR`.
- El estilo se aplica automáticamente al dashboard principal, al popup de aprobación y al diálogo de bienvenida para mantener la coherencia visual.
- En plataformas distintas de Windows, o si la API DWM no está disponible, la función no hace nada (no rompe la aplicación).
- Suite de tests `test_modern_titlebar.py` que verifica la función helper y la configuración.
- **Descomposición automática de tareas en subtareas.** Cada tarea del usuario se divide en 4 fases:
  1. 📋 **Requisitos técnicos** — análisis y documentación.
  2. 🛠 **Desarrollo de la solución** — implementación.
  3. ✅ **Ejecución y comprobación** — verificación.
  4. 🔧 **Rectificación** (condicional) — corrección si la verificación falla.
- Clase `TaskOrchestrator` que gestiona el flujo secuencial y el ciclo de rectificación.
- Enum `SubtaskType` con 4 valores: `REQUIREMENTS`, `DEVELOPMENT`, `EXECUTION_VERIFICATION`, `RECTIFICATION`.
- Nuevas columnas en la tabla `tasks`: `parent_task_id`, `subtask_type`, `attempt_number`.
- Migración ligera de esquema (compatible con BDs existentes).
- Configuración `max_rectification_retries` en `[Agent]` de `config.ini` (por defecto 3).
- Tablero de tareas con subtareas anidadas bajo su tarea padre.
- Nuevos tipos de evento: `SUBTASK_CREATED`, `SUBTASK_STARTED`, `SUBTASK_COMPLETED`, `SUBTASK_FAILED`, `ORCHESTRATION_DECISION`.
- Suite de tests `test_subtareas.py` con 27 escenarios del orquestador.

### Changed
- `_on_execute()` del dashboard ahora lanza el orquestador en lugar del agente directamente.
- `_refresh_task_lists()` muestra solo tareas padre en el tablero principal; las subtareas se renderizan anidadas.
- Python mínimo documentado: 3.11 (el código usa `datetime.UTC`).
- README y CONTRIBUTING actualizados: 8 suites de tests, URLs del repositorio y nuevas funcionalidades.

### Fixed
- URL del repositorio en el diálogo de bienvenida (`bondwell79/hercules`).
- `test_global.py` ya no falla con `UnicodeEncodeError` al redirigir la salida en Windows.
- Caracteres corruptos (mojibake) en comentarios de `LoopDetector`.
- f-string sin placeholders en `_format_approval_args`.

### Removed
- Código muerto: `_tokenize_command`, `LoopDetector.is_looping`, los métodos no-op `_build_approval_panel` y `_update_approval_header`, los wrappers `_resolve_approval` y `_start_preauthorization`, `RoundedFrame._tk_widget`, `WelcomeDialog.PROJECT_NAME` y variables locales sin uso.
- Imports duplicados/sin uso (`field`, segundo `datetime`) y propiedades de configuración duplicadas (`ui_approval_*_fg`).

## [1.0.0] - 2026-09-02

### Added
- Suite de tests de resiliencia con 40+ escenarios.
- Suite de tests de funcionamiento (tareas en paralelo).
- Mecanismo de detección de bucles y compactación de contexto.
- Barra de uso de contexto en el dashboard.
- Herramientas `get_current_time` y `delete_file`.
- Soporte de bloques `<tool_call>` en texto plano.
- Modo dual LLM (local con GGUF / HTTP con OpenAI/Ollama).

### Changed
- Migración de PyInstaller a Nuitka para compilación.
- Layout de UI reorganizado en 4 zonas con prioridad estricta.
- Tema oscuro por defecto con colores configurables.

### Fixed
- Crash cuando `choices[0]` no contenía `message`.
- Argumentos con tipos extremos (`None`, `int`, `bool`) ya no rompen el parser.
