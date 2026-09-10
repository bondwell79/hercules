# Hercules 09/09/2026

```text
..................................................................
██╗  ██╗███████╗██████╗  ██████╗██╗    ██╗██╗     ███████╗███████╗
██║  ██║██╔════╝██╔══██╗██╔════╝██║    ██║██║     ██╔════╝██╔════╝
███████║█████╗  ██████╔╝██║     ██║    ██║██║     █████╗  ███████╗
██╔══██║██╔══╝  ██╔══██╗██║     ██║    ██║██║     ██╔══╝  ╚════██║
██║  ██║███████╗██║  ██║╚██████╗╚██████╔╝███████╗███████╗███████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝
..................................................................
```

> Gestor agéntico de modelos LLM con control de permisos humano-en-el-bucle (HITL), construido exclusivamente con la biblioteca estándar de Python

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)

## ✨ Características

- 🤖 **Agente** con bucle de razonamiento y herramientas.
- 🎼 **Descomposición automática en subtareas:** cada tarea se divide en Requisitos → Desarrollo → Ejecución/Verificación → Rectificación (si falla).
- 🛡️ **Human-in-the-Loop (HITL):** aprobación manual de acciones críticas.
- 🔌 **Modo dual LLM:** local (GGUF con `llama-cpp-python`) o HTTP (OpenAI/Ollama/llama.cpp server).
- 📊 **Dashboard tkinter** con 4 zonas: prompt, tablero de tareas, historial y panel de aprobación.
- 💾 **Persistencia SQLite** historial de tareas realizadas.
- 📦 **Ejecutable autónomo** compilable con Nuitka (cero instalación en el destino).

## 📦 Requisitos

- Python 3.10 o superior
- Creado para windows pero compatible con linux.
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

## 🧪 Tests de funcionamiento

```bash
python test_global.py             # ejecuta todas las suites y muestra el resumen
python test_resilience.py         # escenarios de resiliencia del agente
python test_funcionamiento.py     # tareas en paralelo
python test_subtareas.py          # orquestador de subtareas
```

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
