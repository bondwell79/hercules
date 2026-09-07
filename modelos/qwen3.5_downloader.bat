@echo off
set "URL=https://huggingface.co/unsloth/Qwen3.5-4B-GGUF/resolve/main/Qwen3.5-4B-Q4_0.gguf"
set "OUTPUT=Qwen3.5-4B-Q4_0.gguf"

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

pause