@echo off
echo Stopping ZeroDay-AI-Antivirus and background monitor...
powershell -NoProfile -Command "Get-Process -Name AntiVirusAI -ErrorAction SilentlyContinue | Stop-Process -Force; Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*avscan*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }" >nul 2>&1
echo ZeroDay-AI-Antivirus has been stopped successfully.
ping -n 2 127.0.0.1 >nul
