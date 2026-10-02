# Changelog

Todos los cambios notables se documentan aquí. Formato basado en [Keep a Changelog](https://keepachangelog.com/).

**Mantenedor:** Rubén Pastor — `bondwell_@hotmail.com`

## [Unreleased]

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
