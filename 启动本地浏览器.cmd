@echo off
setlocal DisableDelayedExpansion
rem Enumerate the name so broken links also block before touching the runtime.
for /f "eol=| delims=" %%G in ('dir /a /b "%~dp0" 2^>nul') do if /I "%%G"==".program-update" goto update_incomplete
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
:update_incomplete
echo Program update is incomplete. Keep this folder and recover the update before launching.
pause
exit /b 1
