@echo off
set "URL=https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507-GGUF/resolve/main/Qwen3-4B-Instruct-2507-Q8_0.gguf"
set "OUTPUT=Qwen3-4B-Instruct-2507-Q8_0.gguf"

echo ========================================================
echo   Descargando: %OUTPUT%
echo ========================================================
echo.

REM Descarga con curl soportando reanudacion (-C -) y redirecciones (-L)
curl.exe -L --retry 5 --retry-delay 2 -C - -o "%OUTPUT%" "%URL%"

if %ERRORLEVEL% equ 0 (
    echo.
    echo ========================================================
    echo [EXITO] Descarga completada correctamente.
    echo ========================================================
) else (
    echo.
    echo ========================================================
    echo [ERROR] La descarga fallo con codigo %ERRORLEVEL%.
    echo ========================================================
)
