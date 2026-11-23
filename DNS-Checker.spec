# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files

datas = []
datas += collect_data_files('customtkinter')

# Рабочие файлы рядом с программой: при первом запуске они должны лежать рядом
# с .exe (программа читает их по пути argv[0]). Дополнительные файлы не затирают
# пользовательские правки: PyInstaller кладёт свои копии только при распаковке.
for name in ('servers.txt', 'consoles.json', 'reply_template.txt',
             'cloud_config.json', 'ip_overrides.json'):
    datas.append((name, '.'))


a = Analysis(
    ['dns_checker_gui.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='DNS-Checker',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='DNS-Checker',
)
