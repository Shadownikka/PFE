@echo off
echo ====================================
echo NetCut3 Windows - Admin Launcher
echo ====================================
echo.
echo This will launch NetCut3 with Administrator privileges.
echo Press any key to continue...
pause >nul

:: Check if already running as admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running as Administrator...
    python NetCut3_Windows.py
) else (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %CD% && python NetCut3_Windows.py && pause' -Verb RunAs"
)
