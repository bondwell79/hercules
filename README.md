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
https://bondwell79.github.io/hercules/

Versión actual: 2.1

> Gestor agéntico de modelos LLM con control de permisos humano-en-el-bucle (HITL). El motor usa la biblioteca estándar de Python; la interfaz gráfica utiliza PySide6.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/optional%20dependencies-pyautogui-blue)

## ✨ Características

- 🤖 **Agente autónomo** con bucle ReAct, detección de bucles y compactación de contexto.
- 🧩 **Flujo configurable por subtareas** definido mediante `subtareas.ini`.
- ⚡ **Tareas paralelas** con límite configurable y espera/cancelación controlada.
- 🖱️ **Control humano HITL** para herramientas con autorización, preautorización y cancelación.
- 🌐 **Navegador integrado** con snapshot, controles interactivos y consola JavaScript.
- 🪟 **Interfaz Qt moderna** adaptable, con temas, terminal integrado y barra de título nativa en Windows.
- 🛡️ **Arranque y ejecución robustos** ante configuración inválida, errores de contexto, LLM bloqueado y fallos de tareas.

# Herramientas disponibles

## 📁 Gestión de archivos

| Herramienta | Descripción |
|---|---|
| `read_file` | Lee el contenido de un archivo de texto |
| `read_binary_file` | Lee un archivo binario (devuelve Base64, máx. 50000 bytes) |
| `read_binary_hex` | Muestra un volcado hexadecimal de un archivo binario |
| `read_media_file` | Adjunta imágenes y fotogramas de vídeo; para audio devuelve metadatos |
| `write_file` | Escribe contenido en un archivo (crea directorios si no existen) |
| `create_file` | Crea un archivo nuevo sin sobrescribir |
| `edit_file` | Reemplaza una cadena exacta en un archivo |
| `delete_file` | Elimina un archivo o directorio |
| `list_directory` | Lista el contenido de un directorio |
| `search_files` | Busca archivos por patrón glob |
| `search_in_files` | Busca una cadena literal en el contenido de archivos |

Las herramientas de texto usan UTF-8 y saltos de línea `LF` de forma uniforme: `write_file` y `create_file` convierten `CRLF`/`CR` a `LF`, `edit_file` busca y escribe con esa misma normalización, y `read_file`/`search_in_files` leen con saltos normalizados. `read_file` cuenta offsets como puntos de código Unicode desde 0 (no bytes ni líneas); `search_in_files` muestra líneas desde 1. Los bytes UTF-8 inválidos se sustituyen por `U+FFFD` al leer/buscar, mientras que `edit_file` los rechaza para evitar una edición con pérdida.

Las herramientas binarias usan offsets de bytes desde 0. `read_binary_file` devuelve Base64; `read_binary_hex` recibe offsets numéricos decimales, aunque muestra las direcciones en hexadecimal. Los resultados truncados indican el siguiente offset en su unidad correspondiente.

## 🖥️ Navegador integrado

| Herramienta | Descripción |
|---|---|
| `browser_navigate` | Navega a una URL HTTP(S) o documento local |
| `browser_fetch` | Devuelve el HTML bruto de una URL HTTP(S) o de la página actual; admite `offset` en caracteres (0 = inicio), puede guardar la captura completa dentro del workspace y limita la respuesta a 50.000 caracteres |
| `browser_snapshot` | Devuelve URL, título, texto y controles interactivos, asignando referencias `@e1`, `@e2`, etc. |
| `browser_console` | Sin argumentos, devuelve los mensajes de consola pendientes; con `code`, ejecuta JavaScript en la página cargada y devuelve su resultado |
| `browser_click` | Hace clic en un control usando una referencia del último snapshot o, por compatibilidad, un selector CSS |
| `browser_fill` | Rellena un campo usando una referencia del último snapshot o, por compatibilidad, un selector CSS |
| `browser_scroll` | Desplaza la página |
| `browser_press_key` | Envía una tecla nativa al navegador |
| `browser_screenshot` | Captura el navegador y adjunta la imagen |
| `browser_back` | Retrocede en el historial |
| `browser_forward` | Avanza en el historial |
| `browser_reload` | Recarga la página |

Las referencias del snapshot caducan al navegar, desplazarse o interactuar, y tras tomar
otro snapshot. Solicita siempre un nuevo `browser_snapshot` para obtener referencias vigentes.
La opción `code` de `browser_console` permite inyectar y evaluar código JavaScript directamente
en el documento mostrado por el navegador integrado, lo que facilita pruebas DOM, lectura de
valores y depuración. Ejecuta código únicamente en páginas de confianza.

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
| `spawn_parallel_task` | Lanza una tarea hija autónoma en segundo plano; admite hasta `max_parallel_tasks` simultáneas |
| `wait_parallel_task` | Espera el resultado de una tarea hija con un timeout opcional; el timeout no cancela la tarea |
| `run_http_server` | Inicia un servidor HTTP local de solo lectura para servir el workspace en `http://127.0.0.1:8000/` |
| `get_current_time` | Devuelve la fecha/hora UTC actual |

Las tareas paralelas trabajan en historiales independientes. Antes de finalizar, el agente
principal espera sus resultados o aplica el timeout configurado en
`parallel_task_timeout`. Al cerrar Hercules se cancelan las tareas hijas pendientes.


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

## 📦 Modelos LLM recomendados (de menor a mayor)

Tras diferentes pruebas exhaustivas, recomendamos los siguientes modelos multimodales en entorno local:

- Ornith 1.5 35B Q8. Este modelo Q8 es capaz de utilizar todas las herramientas disponibles con una mayor solvencia y estabilidad, y la consideramos la mejor opción local.
- Qwen 3.6 35B A3B / 3.8 35B A3B. Ambos modelos utilizan con solvencia la totalidad de las herramientas.
- Gemma 4 26B A4B. Este modelo utiliza casi la totalidad de las herramientas y destaca en visión y escritura.

En entorno cloud, casi la totalidad de modelos multimodales son capaces de hacer uso completo de herramientas y capacidades avanzadas de desarrollo, y destacan:

- Minimax m2.5 / m3. 
- Qwen 3.8 Flash.
- Modelos Openai compatibles frontera.

## 🚀 Instalación rápida

```bash
git clone https://github.com/bondwell79/hercules.git
cd hercules
pip install -r requirements.txt
python hercules.py
```

En OS Windows se recomienda usar el script específico de arranque:

Usar el script `run.bat`, que activa el entorno virtual y lanza `hercules.py`.

El fichero `config.ini` ya viene incluido con valores por defecto; edítalo para ajustar la ruta del modelo GGUF, el modo del LLM (`local` / `http`) y otros parámetros. En el menú de configuración puedes cambiar el tema, la pantalla completa y la tipografía, y comprobarlos en la vista previa de Interfaz.

El fichero `tools.ini` permite definir herramientas globales en `[global]` y perfiles adicionales, por ejemplo `[creador_web]`. Cada sección acepta valores `true` / `false`; un perfil solo necesita incluir las herramientas que sobrescribe y hereda las demás de `[global]`. La pestaña **Herramientas** permite ajustar los valores globales. El perfil para cada tarea se elige en el desplegable bajo el prompt. Las herramientas desactivadas no se anuncian al modelo y cualquier intento de ejecución se deniega. Los cambios de configuración se aplican al reiniciar Hercules.

El fichero `subtareas.ini` es la única definición del plan de trabajo del agente: cada sección en orden que tenga un `prompt` crea una subtarea con ese nombre. Puedes añadir, quitar, renombrar o reordenar fases libremente; usa `{user_prompt}` para incluir la petición original y `{NOMBRE_SECCION}` para insertar la salida de una subtarea anterior. No hay fases especiales ni plan predeterminado: si falta el fichero o no define subtareas válidas, el programa no ejecuta ninguna subtarea. El plan distribuido incluye una etapa inicial `EJECUTAR`, configurable sin restricciones.

El `[Agent]` de `config.ini` permite ajustar límites y robustez: `max_parallel_tasks`
(3 por defecto), `parallel_task_timeout` (1800 segundos; 0 desactiva el límite),
`context_compact_threshold`, `preauth_timeout`, `preauth_fallback_to_human`,
`command_timeout`, `log_max_mb` y `log_retention_days`.
Al alcanzar la mitad de `context_compact_threshold`, Hercules elimina los
adjuntos multimodales antiguos y conserva el más reciente de cada tipo; al
alcanzar el umbral completo, compacta el historial.
La barra de contexto usa `usage.prompt_tokens` cuando el modelo lo informa y,
si no está disponible, mantiene la estimación actual.

La barra de título se configura con `titlebar_style` (`system` | `dark` | `accent` |
`custom`) en `[UI]`; también admite las variables de entorno
`HERCULES_TITLEBAR_STYLE`, `HERCULES_TITLEBAR_COLOR` y
`HERCULES_TITLEBAR_TEXT_COLOR`. En plataformas distintas de Windows no tiene efecto.

Hercules tolera valores inválidos en `config.ini` y variables de entorno, cargando
los valores predeterminados seguros. Los logs rotan en `log/`, las conexiones SQLite
usan WAL y se cierran al terminar. Si el contexto se desborda o se detecta un bucle,
el agente compacta el contexto y reintenta sin perder el hilo de trabajo.

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
| `test_produccion.py` | cancelación, contexto, configuración, SQLite y robustez de arranque |
| `test_parallel_tasks.py` | tareas paralelas, límites, espera y cancelación |

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
