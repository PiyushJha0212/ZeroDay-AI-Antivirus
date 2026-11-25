@echo off
title Launch AntivirusAI Demo
cd /d "%~dp0\.."
if exist "..\venv\Scripts\activate.bat" (
    call "..\venv\Scripts\activate.bat"
) else if exist "venv\Scripts\activate.bat" (
    call "venv\Scripts\activate.bat"
)
start "" python -m avscan.gui
exit
