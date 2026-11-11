@echo off
setlocal DisableDelayedExpansion
if not exist "%~dp0runtime\python\pythonw.exe" (
    echo Portable runtime is incomplete. Restore the complete portable folder including runtime.
    pause
    exit /b 1
)
if not exist "%~dp0runtime\webview2\msedgewebview2.exe" (
    echo Portable WebView2 is missing. Restore the complete portable folder including runtime.
    pause
    exit /b 1
)
if not exist "%~dp0app\local_browser.pyw" (
    echo Portable application is incomplete. Restore the complete portable folder.
    pause
    exit /b 1
)
start "" /D "%~dp0app" "%~dp0runtime\python\pythonw.exe" -B "%~dp0app\local_browser.pyw"
exit /b 0
