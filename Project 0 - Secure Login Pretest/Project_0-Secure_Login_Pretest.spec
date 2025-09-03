# -*- mode: python ; coding: utf-8 -*-
import os

block_cipher = None

a = Analysis(
    ['dist-obf\\Project_0-Secure_Login_Pretest.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'hmac',
        'getpass',
        'uuid',
        'socket',
        'hashlib',
        're',
        'os',
        'sys',
        'datetime',
        'tkinter',
        'tkinter.messagebox',
        'winreg',
        'ttkbootstrap'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['hook_antidebug.py'],  # Runtime tamper detection
    excludes=[],
    noarchive=False,
    optimize=2,  # Highest optimization
    cipher=block_cipher
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SAS-ZJ-3610',
    debug=False,
    bootloader_ignore_signals=True,
    strip=True,                      # Remove debug symbols
    upx=True,                        # Enable UPX compression
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,                   # Set to False to hide console window (GUI app)
    disable_windowed_traceback=True,  # Prevent traceback popup
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None
)