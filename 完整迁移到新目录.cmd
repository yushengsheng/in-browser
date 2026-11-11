@echo off
setlocal
if not exist "%~dp0runtime\python\python.exe" (
    echo Bundled Python is missing. Use the complete clean program package.
    pause
    exit /b 1
)
"%~dp0runtime\python\python.exe" -B "%~dp0tools\portable_transfer.py"
set "transfer_result=%errorlevel%"
pause
exit /b %transfer_result%
