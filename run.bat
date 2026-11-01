@echo off
rem PR Sentinel: opens the app in your browser. Double-click this file.
rem Close this window (or press Ctrl+C) to stop the app.
setlocal
cd /d "%~dp0"
chcp 65001 >nul
title PR Sentinel

where uv >nul 2>nul
if errorlevel 1 (
    echo uv is not installed. Install it with:
    echo   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 ^| iex"
    echo Then double-click run.bat again.
    pause
    exit /b 1
)

echo Starting PR Sentinel...
uv sync --frozen --quiet
if errorlevel 1 (
    echo Installing dependencies failed - see the messages above.
    pause
    exit /b 1
)

uv run pr-sentinel gui %*
if errorlevel 1 pause
endlocal
