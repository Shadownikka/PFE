# NetMind.spec — PyInstaller packaging (updated for NetMindDesktop.py)
# Build: cd "/home/mahdi/NetMind Project/NetMind" && pyinstaller packaging/NetMind.spec --clean
# Output: dist/NetMind (folder) — run with: sudo dist/NetMind/NetMind

import os
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

# ── Collect all source files ─────────────────────────────────────────────────
project_root = os.path.abspath(os.path.join(os.path.dirname(SPEC), '..'))

datas = [
    # Core engine modules
    (os.path.join(project_root, 'core', 'tool.py'),             'core'),
    (os.path.join(project_root, 'core', 'net_agent.py'),        'core'),
    (os.path.join(project_root, 'core', 'autopilot.py'),        'core'),
    (os.path.join(project_root, 'core', 'onboarding.py'),       'core'),
    (os.path.join(project_root, 'core', 'metrics_exporter.py'), 'core'),
    (os.path.join(project_root, 'core', 'ai.py'),               'core'),
    # Assets
    (os.path.join(project_root, 'assets'),                       'assets'),
    # Observability configs
    (os.path.join(project_root, 'observability'),                'observability'),
] + collect_data_files('scapy')

hiddenimports = [
    'scapy', 'scapy.all', 'scapy.layers.l2', 'scapy.layers.inet',
    'scapy.layers.dns', 'scapy.layers.http',
    'netifaces', 'ollama',
    'speech_recognition', 'pyaudio',
    'prometheus_client',
    'termcolor',
    'PyQt6.QtWidgets', 'PyQt6.QtCore', 'PyQt6.QtGui',
    'PyQt6.QtNetwork',
] + collect_submodules('scapy')

a = Analysis(
    [os.path.join(project_root, 'NetMindDesktop.py')],
    pathex=[project_root, os.path.join(project_root, 'core')],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        'matplotlib', 'numpy', 'pandas', 'PIL', 'cv2',
        'tkinter', 'PyQt6.QtWebEngineWidgets',
        'test', 'unittest',
    ],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name='NetMind',
    debug=False,
    strip=False,
    upx=True,
    console=False,      # No terminal window
    icon=os.path.join(project_root, 'assets', 'netmind.png'),
)

coll = COLLECT(
    exe, a.binaries, a.zipfiles, a.datas,
    strip=False, upx=True, name='NetMind'
)
