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

> Gestor agéntico de modelos LLM con control de permisos humano-en-el-bucle (HITL). El motor usa la biblioteca estándar de Python; la interfaz gráfica utiliza PySide6.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/optional%20dependencies-pyautogui-blue)

## ✨ Características

- 🤖 **Agente** con bucle de razonamiento y herramientas.

# Herramientas disponibles

## 📁 Gestión de archivos

| Herramienta | Descripción |
|---|---|
| `read_file` | Lee el contenido de un archivo de texto |
| `read_binary_file` | Lee un archivo binario (devuelve Base64, máx. 50000 bytes) |
| `read_binary_hex` | Muestra un volcado hexadecimal de un archivo binario |
| `write_file` | Escribe contenido en un archivo (crea directorios si no existen) |
| `create_file` | Crea un archivo nuevo sin sobrescribir |
| `edit_file` | Reemplaza una cadena exacta en un archivo |
| `delete_file` | Elimina un archivo o directorio |
| `list_directory` | Lista el contenido de un directorio |
| `search_files` | Busca archivos por patrón glob |
| `search_in_files` | Busca una cadena literal en el contenido de archivos |

## 🖥️ Navegador integrado

| Herramienta | Descripción |
|---|---|
| `browser_navigate` | Navega a una URL HTTP(S) o documento local |
| `browser_snapshot` | Devuelve URL, título, texto y controles interactivos |
| `browser_click` | Hace clic en un control (por referencia) |
| `browser_fill` | Rellena un campo de formulario |
| `browser_scroll` | Desplaza la página |
| `browser_press_key` | Envía una tecla nativa al navegador |
| `browser_screenshot` | Captura el navegador y adjunta la imagen |
| `browser_back` | Retrocede en el historial |
| `browser_forward` | Avanza en el historial |
| `browser_reload` | Recarga la página |

## ⌨️ Interacción con el escritorio

| Herramienta | Descripción |
|---|---|
| `take_screenshot` | Captura la pantalla (PNG) |
| `mouse_click` | Hace clic con el ratón en coordenadas |
| `mouse_move` | Mueve el puntero a coordenadas |
| `keyboard_type_text` | Escribe texto en el elemento con foco |
| `keyboard_press_keys` | Pulsa una tecla o combinación |

## ⚙️ Ejecución de comandos y tareas

| Herramienta | Descripción |
|---|---|
| `execute_command` | Ejecuta un comando del sistema |
| `spawn_parallel_task` | Lanza una tarea en paralelo (segundo plano) |
| `wait_parallel_task` | Espera a que termine una tarea paralela |
| `get_current_time` | Devuelve la fecha/hora UTC actual |


## 🎨 Interfaz moderna

La interfaz gráfica utiliza Qt for Python (PySide6). A la izquierda se muestran
el prompt, las tareas y el historial; a la derecha, el explorador del workspace
y un navegador embebido basado en Qt WebEngine (Chromium), con soporte para
JavaScript. El acceso desde documentos locales del navegador queda restringido
al workspace.

## 📦 Requisitos

- Python 3.11 o superior
- PySide6 y PySide6-WebEngine (se instalan desde `requirements.txt`)
- Creado para windows pero compatible con linux.
- Opcional: `pyautogui` (para las herramientas autorizadas de captura de pantalla, ratón y teclado; instalar con `python -m pip install pyautogui`).
- Opcional: `llama-cpp-python` (solo para modo local)
- Opcional: un modelo GGUF (ver carpeta `modelos/`)

## 🚀 Instalación rápida

```bash
git clone https://github.com/bondwell79/hercules.git
cd hercules
python -m pip install PySide6==6.12.0 PySide6-WebEngine==6.12.0.140
python hercules.py
```

En OS Windows se recomienda usar el script específico de arranque:

Usar el script `run.bat`, que activa el entorno virtual y lanza `hercules.py`.

El fichero `config.ini` ya viene incluido con valores por defecto; edítalo para ajustar la ruta del modelo GGUF, el modo del LLM (`local` / `http`) y otros parámetros. En el menú de configuración puedes cambiar el tema, la pantalla completa y la tipografía, y comprobarlos en la vista previa de Interfaz.

El fichero `subtareas.ini` es la única definición del plan de trabajo del agente: cada sección en orden que tenga un `prompt` crea una subtarea con ese nombre. Puedes añadir, quitar, renombrar o reordenar fases libremente; usa `{user_prompt}` para incluir la petición original y `{NOMBRE_SECCION}` para insertar la salida de una subtarea anterior. No hay fases especiales ni plan predeterminado: si falta el fichero o no define subtareas válidas, el programa no ejecuta ninguna subtarea. El `subtareas.ini` distribuido incluye un plan inicial (`ANALIZAR`, `IMPLEMENTAR`, `COMPROBAR`) que puedes sustituir por completo.
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
| `test_ui_imports.py` | importación del dashboard Qt, Qt WebEngine y configuración de UI |
| `test_ui_widgets.py` | instanciación de controles Qt del dashboard |
| `test_ui_layout.py` | layout Qt y ejecución de JavaScript en Chromium |
| `test_modern_titlebar.py` | opciones de barra de título en Configuración Qt |
| `test_welcome_dialog.py` | diálogo Qt de bienvenida durante el arranque |
| `test_computer_tools.py` | herramientas de captura de pantalla y control del ratón y teclado |

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
