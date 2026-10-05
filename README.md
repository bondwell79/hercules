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
- 🖱️ **Herramientas **: soporta las herramientas estandar de llm: 

Tool	            Nivel	Descripción
read_file	        SAFE	Lee un archivo de texto del workspace.
read_binary_file	SAFE	Lee un archivo binario y devuelve su contenido en Base64, hasta 50 000 bytes.
read_binary_hex	    SAFE	Muestra un rango de un archivo binario como volcado hexadecimal y ASCII; admite hasta 4096 bytes.
list_directory	    SAFE	Lista los archivos y subdirectorios de una carpeta del workspace.
search_files	    SAFE	Busca archivos por patrón glob, por ejemplo *.txt.
get_current_time	SAFE	Devuelve la fecha y hora UTC actuales.
take_screenshot	    SAFE	Captura la pantalla y guarda la imagen PNG en el workspace.
mouse_click	        SAFE	Hace uno o más clics en unas coordenadas de pantalla.
mouse_move	        SAFE	Mueve el puntero a unas coordenadas de pantalla.
write_file	        SAFE	Escribe contenido en un archivo; puede sobrescribir uno existente.
create_file	        SAFE	Crea un archivo nuevo sin sobrescribir uno existente.
edit_file	        SAFE	Reemplaza una coincidencia de texto en un archivo; también puede sustituir todo su contenido.
search_in_files	    SAFE	Busca una cadena literal dentro de archivos del workspace.
execute_command	    CRITICAL	Ejecuta un comando del sistema desde el workspace; requiere aprobación y aplica comprobaciones de seguridad.
delete_file	        SAFE	Elimina un archivo o directorio del workspace.

- 🛡️ **Human-in-the-Loop (HITL):** las herramientas `write_file`, `create_file`, `edit_file` y `delete_file` están limitadas al workspace y se clasifican como SAFE; las acciones CRITICAL, como ejecutar comandos, requieren aprobación manual mediante popups modales. Incluye preautorización opcional por el LLM y análisis de seguridad de comandos.
- 🔌 **Modo dual LLM:** local (GGUF con `llama-cpp-python`) o HTTP (OpenAI/Ollama/llama.cpp server).

## 🎨 Interfaz moderna

La interfaz gráfica ha sido rediseñada con un aspecto moderno y personalizable.

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
