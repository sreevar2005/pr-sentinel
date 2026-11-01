@echo off
rem PR Sentinel: run the test suite, then review the demo pull request offline.
rem Double-click this file, or run it from a terminal in this folder.
setlocal
cd /d "%~dp0"
chcp 65001 >nul

where uv >nul 2>nul
if errorlevel 1 (
    echo uv is not installed. Install it with:
    echo   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    goto :end
)

echo ============================================================
echo  1/3  Installing dependencies (uv sync)
echo ============================================================
uv sync --frozen --quiet
if errorlevel 1 goto :failed

echo.
echo ============================================================
echo  2/3  Running the test suite
echo ============================================================
uv run pytest
if errorlevel 1 goto :failed

echo.
echo ============================================================
echo  3/3  Reviewing the demo PR (examples\demo\pr.diff)
echo       Rules + checks + a scripted AI reply, no API key needed
echo ============================================================
echo.
uv run pr-sentinel --config .github\pr-sentinel.yml review-local ^
    --diff examples\demo\pr.diff ^
    --checks-dir examples\demo\checks ^
    --fake-response examples\demo\ai-response.json ^
    --title "Add user export" ^
    --show-inline
if errorlevel 1 goto :failed

echo.
echo Done. Everything ran successfully.
goto :end

:failed
echo.
echo A step failed - see the output above.

:end
echo.
pause
endlocal
