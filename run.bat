@echo off
chcp 65001 >nul
setlocal
echo ..................................................................
echo ██╗  ██╗███████╗██████╗  ██████╗██╗   ██╗██╗     ███████╗███████╗
echo ██║  ██║██╔════╝██╔══██╗██╔════╝██║   ██║██║     ██╔════╝██╔════╝
echo ███████║█████╗  ██████╔╝██║     ██║   ██║██║     █████╗  ███████╗
echo ██╔══██║██╔══╝  ██╔══██╗██║     ██║   ██║██║     ██╔══╝  ╚════██║
echo ██║  ██║███████╗██║  ██║╚██████╗╚██████╔╝███████╗███████╗███████║
echo ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ 
echo ..................................................................
echo Iniciando ... (si es la primera vez puede tardar un rato)
echo ..................................................................

:: 1. Comprobar si existe el entorno virtual; si no, crearlo
if not exist "venv\" (
    echo [INFO] No se encontro el entorno virtual. Creando venv...
    call python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Fallo al crear el entorno virtual. Verifica que Python este en el PATH.
        exit /b 1
    )
)

:: 2. Activar el entorno virtual
echo [INFO] Activando el entorno virtual...
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
) else (
    echo [ERROR] No se encontro venv\Scripts\activate.bat.
    exit /b 1
)

:: 3. Verificar si llama-cpp-python esta instalado; si no, instalar la rueda precompilada para CPU
python -c "import llama_cpp" >nul 2>&1
if errorlevel 1 (
    echo [INFO] llama-cpp-python no detectado. Instalando binario precompilado para CPU...
    python -m pip install --upgrade pip
    pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
    if errorlevel 1 (
        echo [ERROR] Error al instalar llama-cpp-python.
        exit /b 1
    )
) else (
    echo [INFO] llama-cpp-python ya esta instalado.
)

:: 4. Ejecutar el modelo
cd modelos
call qwen3-instruct.bat
cd ..

:: 5. Ejecutar el script principal
echo [INFO] Ejecutando el script de Python...
python hercules.py

endlocal