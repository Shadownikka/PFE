# NetMind Windows — PyInstaller Build Spec
# Run: pyinstaller NetMind.spec

import os
import sys

block_cipher = None
ROOT = os.path.abspath('.')

a = Analysis(
    ['NetMindDesktop.py'],
    pathex=[ROOT],
    binaries=[],
    datas=[
        ('assets', 'assets'),
        ('core', 'core'),
        ('LICENSE', '.'),
    ],
    hiddenimports=[
        'PyQt6', 'PyQt6.QtWidgets', 'PyQt6.QtCore', 'PyQt6.QtGui',
        'scapy', 'scapy.all', 'psutil',
        'ollama', 'flask', 'requests',
        'prometheus_client',
        'core.tool', 'core.ai', 'core.api_server', 'core.platform_win',
        'core.onboarding', 'core.voice_handler', 'core.autopilot',
        'core.net_agent', 'core.metrics_exporter',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NetMind',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,   # No console window — pure GUI
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico' if os.path.exists('assets/icon.ico') else None,
    uac_admin=True,  # Request admin on launch (needed for network scanning)
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='NetMind',
)
