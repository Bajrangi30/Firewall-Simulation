@echo off
title Firewall Simulation Setup
echo ==========================================
echo      Firewall Simulation - Auto Setup
echo ==========================================
echo.

:: Check Python
echo Checking Python installation...
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Python is not installed!
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b
)
echo Python found!
echo.

:: Install requirements
echo Installing required modules...
pip install customtkinter >nul 2>&1
pip install tkinter >nul 2>&1

echo.
echo Requirements installed successfully!
echo.

:: Run the GUI
echo Starting Firewall GUI...
python GUI.py

echo.
pause
