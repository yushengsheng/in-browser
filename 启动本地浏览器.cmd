@echo off
setlocal
if exist "%~dp0runtime\python\pythonw.exe" (
    start "" /D "%~dp0app" "%~dp0runtime\python\pythonw.exe" "%~dp0app\local_browser.pyw"
    exit /b 0
)
if exist "%~dp0app\data\portable-mode.bin" (
    echo Portable runtime is missing. Please copy the complete program folder including runtime.
    pause
    exit /b 1
)
if exist "%~dp0app\launcher.lnk" (
    start "" "%~dp0app\launcher.lnk"
    exit /b 0
)
where pythonw.exe >nul 2>nul
if errorlevel 1 (
    echo Python runtime was not found. Please use the existing Python environment.
    pause
    exit /b 1
)
start "" /D "%~dp0app" pythonw.exe "%~dp0app\local_browser.pyw"
