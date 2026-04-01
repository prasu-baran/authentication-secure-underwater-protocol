@echo off
REM Launch bundled Scyther GUI from this repository
cd /d "%~dp0scyther\scyther-w32-v1.3.0"
echo Launching bundled Scyther GUI...
py scyther-gui.py
pause
