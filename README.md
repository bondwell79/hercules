# Hercules

```text
..................................................................
██╗  ██╗███████╗██████╗  ██████╗██╗   ██╗██╗     ███████╗███████╗
██║  ██║██╔════╝██╔══██╗██╔════╝██║   ██║██║     ██╔════╝██╔════╝
███████║█████╗  ██████╔╝██║     ██║   ██║██║     █████╗  ███████╗
██╔══██║██╔══╝  ██╔══██╗██║     ██║   ██║██║     ██╔══╝  ╚════██║
██║  ██║███████╗██║  ██║╚██████╗╚██████╔╝███████╗███████╗███████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝
..................................................................
```

> Gestor agéntico de modelos LLM con control de permisos humano-en-el-bucle (HITL), construido exclusivamente con la biblioteca estándar de Python

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/optional%20dependencies-pyautogui-blue)

## ✨ Características

- 🤖 **Agente** con bucle de razonamiento y herramientas.
- 🖱️ **Herramientas de escritorio**: la captura de pantalla (`take_screenshot`) no requiere aprobación; los clics y movimientos del ratón sí requieren autorización humana. La captura se adjunta como imagen multimodal en la siguiente petición al modelo, limitada a 4 MB (si el proveedor/modelo admite imágenes). Las capturas PNG que superan ese límite se comprimen y convierten a JPEG para el envío.
- 🎼 **Descomposición automática en subtareas:** cada tarea se divide en Requisitos → Desarrollo → Ejecución/Verificación → Rectificación (si falla, hasta `max_rectification_retries` intentos). Las plantillas de prompt se editan en `subtareas.ini`.
- 🛡️ **Human-in-the-Loop (HITL):** aprobación manual de acciones críticas mediante popups modales, con preautorización opcional por el propio LLM y análisis de seguridad de comandos.
- 🪟 **Barra de título moderna** en Windows 10/11 (DWM): estilos `system`, `dark`, `accent` y `custom`.
- 🔌 **Modo dual LLM:** local (GGUF con `llama-cpp-python`) o HTTP (OpenAI/Ollama/llama.cpp server).
- 📊 **Dashboard tkinter** con 4 zonas: prompt, tablero de tareas, historial y panel de aprobación.
- 💾 **Persistencia SQLite** historial de tareas realizadas.
- 📦 **Ejecutable autónomo** compilable con Nuitka (cero instalación en el destino).

## 🎨 Interfaz moderna

La interfaz gráfica ha sido rediseñada con un aspecto moderno y personalizable:

- **Esquinas redondeadas** en marcos, tarjetas, botones y barras de progreso (widgets `RoundedFrame`, `RoundedButton` y `GradientCanvas`).
- **Bordes sutiles** en las tarjetas para separarlas visualmente del fondo.
- **Efectos hover y pressed** en los botones: cambian de color al pasar el ratón por encima y al hacer clic, con una animación suave de transición.
- **Transparencia de la ventana** configurable (rango 0.5 - 1.0) mediante el atributo `-alpha` de tkinter.
- **Color de acento** para títulos y cabeceras, configurable desde `config.ini`.
- **Botón "Ejecutar" destacado** con color de acento (azul) para diferenciarlo de los botones secundarios; permanece deshabilitado junto al prompt mientras se procesa toda la cola de tareas.
- **Botón "Abortar tareas"** junto a "Ejecutar" para cancelar la ejecución en curso.
- **Botón "Denegar/Cancelar" en rojo** y **"Permitir" en verde** para identificar visualmente las acciones críticas del panel HITL.

Todas estas opciones se configuran en la sección `[UI]` de `config.ini`:

| Clave | Descripción | Valor por defecto |
|---|---|---|
| `corner_radius` | Radio de las esquinas redondeadas (px) | `10` |
| `card_border_width` | Grosor del borde de las tarjetas (px) | `1` |
| `card_border_color` | Color del borde de las tarjetas | `#3c3c3c` |
| `accent_color` | Color de acento para títulos | `#4fc3f7` |
| `window_alpha` | Transparencia de la ventana (0.5 - 1.0) | `1.0` |
| `button_accent_bg` | Color base del botón "Ejecutar" | `#007acc` |
| `button_accent_hover_bg` | Color hover del botón "Ejecutar" | `#1a8ad8` |
| `button_accent_pressed_bg` | Color pressed del botón "Ejecutar" | `#005a9e` |
| `button_hover_bg` | Color hover de botones secundarios | `#505050` |
| `button_pressed_bg` | Color pressed de botones secundarios | `#2a2a2a` |
| `button_danger_bg` | Color base del botón "Denegar" | `#d32f2f` |
| `button_danger_hover_bg` | Color hover del botón "Denegar" | `#e53935` |
| `button_danger_pressed_bg` | Color pressed del botón "Denegar" | `#b71c1c` |

> Para desactivar las esquinas redondeadas y volver al aspecto clásico, basta con poner `corner_radius = 0` en `config.ini`.

## 📦 Requisitos

- Python 3.11 o superior
- Creado para windows pero compatible con linux.
- Opcional: `pyautogui` (para las herramientas autorizadas de captura de pantalla y ratón; instalar con `python -m pip install pyautogui`).
- Opcional: `llama-cpp-python` (solo para modo local)
- Opcional: un modelo GGUF (ver carpeta `modelos/`)

## 🚀 Instalación rápida

```bash
git clone https://github.com/bondwell79/hercules.git
cd hercules
python hercules.py
```

En OS Windows se recomienda usar el script específico de arranque:

Usar el script `run.bat`, que activa el entorno virtual y lanza `hercules.py`.

El fichero `config.ini` ya viene incluido con valores por defecto; edítalo para ajustar la ruta del modelo GGUF, el modo del LLM (`local` / `http`) y otros parámetros.

El fichero `subtareas.ini` edítalo para ajustar el plan de trabajo del agente.

La barra de título se configura con `titlebar_style` (`system` | `dark` | `accent` | `custom`) en `[UI]`; también admite las variables de entorno `HERCULES_TITLEBAR_STYLE`, `HERCULES_TITLEBAR_COLOR` y `HERCULES_TITLEBAR_TEXT_COLOR`. En plataformas distintas de Windows no tiene efecto.

## 🧪 Tests

```bash
python test_global.py             # ejecuta todas las suites y muestra el resumen
python test_global.py --verbose   # con la salida completa de cada suite
```

Suites individuales:

| Suite | Contenido |
|---|---|
| `test_resilience.py` | resiliencia ante respuestas malformadas del LLM |
| `test_funcionamiento.py` | tareas en paralelo con historiales independientes |
| `test_subtareas.py` | orquestador de subtareas y rectificación |
| `test_ui_imports.py` | importación de widgets y opciones de configuración |
| `test_ui_widgets.py` | instanciación y render de widgets |
| `test_ui_layout.py` | layout del dashboard con contenido realista |
| `test_modern_titlebar.py` | helper de barra de título (DWM) |
| `test_welcome_dialog.py` | diálogo de bienvenida |
| `test_computer_tools.py` | herramientas de captura de pantalla y control del ratón |

## 🏗️ Compilar ejecutable en Windows

```bash
pip install nuitka
nuitka.bat
```

El ejecutable queda en `hercules.dist/hercules.exe`.

## 📄 Licencia

MIT — ver [LICENSE](LICENSE).

## 👤 Autor

**Rubén Pastor** — `bondwell_@hotmail.com`
