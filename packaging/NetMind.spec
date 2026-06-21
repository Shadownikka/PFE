# NetMind.spec — PyInstaller packaging
# Build: pyinstaller NetMind.spec --clean
# Output: dist/NetMind/NetMind (Linux) or dist/NetMind/NetMind.exe (Windows)

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

datas = [
    ('tool.py',            '.'),
    ('ai.py',              '.'),
    ('net_agent.py',       '.'),
    ('autopilot.py',       '.'),
    ('onboarding.py',      '.'),
    ('voice_handler.py',   '.'),
    ('metrics_exporter.py','.'),
] + collect_data_files('scapy')

hiddenimports = [
    'scapy', 'scapy.all', 'scapy.layers.l2', 'scapy.layers.inet',
    'netifaces', 'ollama', 'speech_recognition', 'prometheus_client',
    'flask', 'flask_cors', 'termcolor',
    'PyQt6.QtWidgets', 'PyQt6.QtCore', 'PyQt6.QtGui',
] + collect_submodules('scapy')

a = Analysis(
    ['NetMindDesktop.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'pandas', 'PIL', 'cv2',
              'tkinter', 'PyQt6.QtWebEngineWidgets'],
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
    console=False,           # No terminal window on Windows
    # icon='logo.ico',       # Uncomment when logo is ready
)

coll = COLLECT(exe, a.binaries, a.zipfiles, a.datas,
               strip=False, upx=True, name='NetMind')
