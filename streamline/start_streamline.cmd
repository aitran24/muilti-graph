@echo off
setlocal
powershell -ExecutionPolicy Bypass -File "%~dp0start_streamline.ps1" %*
endlocal
