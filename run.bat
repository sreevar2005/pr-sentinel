@echo off
rem PR Sentinel launcher.
rem   Double-click for a menu, or pass an option: run.bat 1 / 2 / 3 / 4 / 5
setlocal EnableDelayedExpansion
cd /d "%~dp0"
chcp 65001 >nul

where uv >nul 2>nul
if errorlevel 1 (
    echo uv is not installed. Install it with:
    echo   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 ^| iex"
    goto :end
)

set "CHOICE=%~1"
if not "%CHOICE%"=="" goto :dispatch

echo.
echo  ==================== PR Sentinel ====================
echo   1  Run the test suite
echo   2  Demo review of a risky PR (offline, no API key)
echo   3  Review my uncommitted / unpushed changes
echo   4  Run code quality checks (lint, format, types)
echo   5  Everything (1 + 4 + 2)
echo   Q  Quit
echo  ======================================================
set /p "CHOICE=Choose an option [5]: "
if "%CHOICE%"=="" set "CHOICE=5"

:dispatch
if /i "%CHOICE%"=="Q" goto :end
echo %CHOICE%| findstr /r "^[1-5]$" >nul || (echo Unknown option "%CHOICE%". Use 1-5 or Q. & goto :end)
call :setup || goto :failed
if "%CHOICE%"=="1" call :tests     || goto :failed
if "%CHOICE%"=="2" call :demo      || goto :failed
if "%CHOICE%"=="3" call :mychanges || goto :failed
if "%CHOICE%"=="4" call :quality   || goto :failed
if "%CHOICE%"=="5" (
    call :tests   || goto :failed
    call :quality || goto :failed
    call :demo    || goto :failed
)
echo.
echo Done. Everything ran successfully.
goto :end

rem ---------------------------------------------------------------------------
:setup
echo.
echo ---- Installing dependencies (uv sync) ----
uv sync --frozen --quiet
exit /b %errorlevel%

:tests
echo.
echo ---- Running the test suite ----
uv run pytest
exit /b %errorlevel%

:quality
echo.
echo ---- Lint (ruff) ----
uv run ruff check . || exit /b 1
echo ---- Formatting (ruff format) ----
uv run ruff format --check . || exit /b 1
echo ---- Types (mypy --strict) ----
uv run mypy
exit /b %errorlevel%

:demo
echo.
echo ---- Demo review: examples\demo\pr.diff ----
echo      Rules + check results + a scripted AI reply. No API key needed.
echo.
uv run pr-sentinel --config .github\pr-sentinel.yml review-local ^
    --diff examples\demo\pr.diff ^
    --checks-dir examples\demo\checks ^
    --fake-response examples\demo\ai-response.json ^
    --title "Add user export" ^
    --show-inline
exit /b %errorlevel%

:mychanges
echo.
echo ---- Reviewing your changes against main ----
where git >nul 2>nul || (echo git is not installed. & exit /b 1)
set "DIFF=%TEMP%\pr-sentinel-local.diff"
git diff main > "%DIFF%" || exit /b 1
for %%A in ("%DIFF%") do if %%~zA==0 (
    echo No changes compared to main. Edit some files, then run this option again.
    exit /b 0
)
echo      Uses the AI provider in .github\pr-sentinel.yml with the key from .env.
echo      If the key does not work, rule findings are still shown.
echo.
uv run pr-sentinel --config .github\pr-sentinel.yml review-local --diff "%DIFF%" --show-inline
exit /b %errorlevel%

:failed
echo.
echo A step failed - see the output above.

:end
echo.
pause
endlocal
