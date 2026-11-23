@echo off
rem Build DNS-Checker.exe with PyInstaller (Windows).
rem Result: dist\DNS-Checker\DNS-Checker.exe
rem Сборка идёт через DNS-Checker.spec: там тема (--windowed) и набор
rem рабочих файлов, которые кладутся рядом с .exe — программа читает их
rem по пути рядом с .exe и позволяет править их прямо в папке программы.
pip install -r requirements.txt pyinstaller
pyinstaller --noconfirm DNS-Checker.spec
copy /y servers.txt consoles.json reply_template.txt cloud_config.json ip_overrides.json dist\DNS-Checker\
