@echo off
rem Build DNS-Checker.exe with PyInstaller (Windows).
rem Result: dist\DNS-Checker\DNS-Checker.exe
rem --windowed        = no black console window
rem --collect-data    = take CustomTkinter themes and fonts into the build
pip install -r requirements.txt pyinstaller
pyinstaller --noconfirm --windowed --name DNS-Checker --collect-data customtkinter dns_checker_gui.py
