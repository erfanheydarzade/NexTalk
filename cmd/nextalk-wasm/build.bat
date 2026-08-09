@echo off
setlocal enabledelayedexpansion

REM Builds cmd/nextalk-wasm into a browser-loadable nextalk.wasm
REM and copies the matching wasm_exec.js from the local Go installation.
REM
REM Usage:
REM   build.bat
REM   build.bat custom-output-dir
REM
REM Default output:
REM   .\web\wasm

cd /d "%~dp0..\.."
if errorlevel 1 (
    echo [!] Failed to change to repository root.
    exit /b 1
)

set "OUT_DIR=%~1"
if "%OUT_DIR%"=="" set "OUT_DIR=web\wasm"

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

set "VERSION=%NEXTALK_VERSION%"
if "%VERSION%"=="" (
    for /f "delims=" %%V in ('git describe --tags --always --dirty 2^>nul') do set "VERSION=%%V"
)
if "%VERSION%"=="" set "VERSION=dev"

echo [*] Building nextalk.wasm (version: %VERSION%) ...

set "GOOS=js"
set "GOARCH=wasm"

go build -ldflags "-X github.com/erfanheydarzade/NexTalk/internal/wasmbridge.buildVersion=%VERSION%" -o "%OUT_DIR%\nextalk.wasm" .\cmd\nextalk-wasm

if errorlevel 1 (
    echo [!] Failed to build nextalk.wasm.
    exit /b 1
)

set "GOROOT="
for /f "delims=" %%G in ('go env GOROOT') do set "GOROOT=%%G"

if not defined GOROOT (
    echo [!] Could not determine GOROOT.
    exit /b 1
)

set "WASM_EXEC=%GOROOT%\lib\wasm\wasm_exec.js"

if not exist "%WASM_EXEC%" (
    set "WASM_EXEC=%GOROOT%\misc\wasm\wasm_exec.js"
)

if not exist "%WASM_EXEC%" (
    echo [!] Could not find wasm_exec.js under:
    echo     %GOROOT%
    echo.
    echo     Copy it manually into:
    echo     %OUT_DIR%
    exit /b 1
)

copy /Y "%WASM_EXEC%" "%OUT_DIR%\wasm_exec.js" >nul

if errorlevel 1 (
    echo [!] Failed to copy wasm_exec.js.
    exit /b 1
)

echo.
echo [+] Done. Output in %OUT_DIR%\
echo     - nextalk.wasm
echo     - wasm_exec.js

endlocal