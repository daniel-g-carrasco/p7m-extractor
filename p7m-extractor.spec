# -*- mode: python ; coding: utf-8 -*-
# PyInstaller build spec. A spec file is required (instead of CLI flags)
# because the gi hook collects GTK 3 by default: hooksconfig is the only
# way to make it bundle the GTK 4 typelibs and libraries.
import os
import shutil
import sys
from pathlib import Path

WIN = sys.platform == 'win32'
ICON = 'assets/icon.ico' if WIN else None

# Application icons for the GTK icon theme (window icon, About dialog).
# PyInstaller's GLib runtime hook points XDG_DATA_DIRS at <bundle>/share.
datas = [('data/icons', 'share/icons')]
binaries = []

if WIN:
    prefix = Path(sys.prefix)  # MSYS2: C:/msys64/mingw64

    # gdbus.exe lets GLib autolaunch a session bus on Windows, which
    # GApplication needs for its single-instance behaviour (a second launch
    # forwards its files to the running window). GLib looks for it next to
    # libgio-2.0-0.dll, i.e. in the bundle's _internal directory.
    gdbus = shutil.which('gdbus') or (
        str(prefix / 'bin' / 'gdbus.exe') if (prefix / 'bin' / 'gdbus.exe').is_file() else None)
    if gdbus:
        binaries.append((gdbus, '.'))
    else:
        print('WARNING: gdbus.exe not found: every launch will open a new window')

    # CA bundle for the update check: MSYS2's OpenSSL does not necessarily
    # read the Windows certificate store (see _ssl_context()).
    import ssl
    candidates = [
        prefix / 'etc' / 'ssl' / 'certs' / 'ca-bundle.crt',
        prefix / 'etc' / 'ssl' / 'cert.pem',
        Path(ssl.get_default_verify_paths().openssl_cafile or ''),
    ]
    for ca in candidates:
        if ca.is_file():
            datas.append((str(ca), 'certs'))
            if ca.name != 'ca-bundle.crt':
                print(f'NOTE: bundling {ca} as certs/{ca.name}; expected name is ca-bundle.crt')
            break
    else:
        print('WARNING: no CA bundle found: the update check may fail on TLS')

a = Analysis(
    ['p7m_extractor.py'],
    binaries=binaries,
    datas=datas,
    hooksconfig={
        'gi': {
            'module-versions': {
                'Gtk': '4.0',
                'Gdk': '4.0',
            },
        },
    },
)

pyz = PYZ(a.pure)

# Start-up splash (Windows only): drawn by the bootloader long before Python
# and GTK are loaded, so a double-click on a .p7m gives immediate feedback.
# The app closes it (pyi_splash.close()) as soon as its window is on screen.
# The image is 1.5x (600x225): the process is DPI aware (see the manifest
# below), so it is shown pixel for pixel, never scaled by Windows.
splash = None
if WIN:
    try:
        splash = Splash(
            'assets/splash.png',
            binaries=a.binaries,
            datas=a.datas,
            text_pos=(210, 183),
            text_size=10,
            text_color='#888b8c',  # dim label on the GTK Default light palette
            text_default='Avvio in corso…',
            minify_script=True,
            always_on_top=True,
        )
        print('splash screen: enabled')
    except BaseException as e:  # noqa: BLE001 - Tcl/Tk missing in the build env
        print(f'WARNING: splash screen disabled: {e!r}')
        splash = None

# Windows: embed our own manifest, which declares per-monitor DPI awareness
# (crisp, stable splash on HiDPI screens) on top of PyInstaller's defaults.
MANIFEST = os.path.join(SPECPATH, 'build-aux', 'windows', 'p7m-extractor.manifest') if WIN else None

exe = EXE(
    pyz,
    a.scripts,
    *([splash] if splash else []),
    exclude_binaries=True,
    name='p7m-extractor',
    console=False,
    icon=ICON,
    manifest=MANIFEST,
)

coll = COLLECT(
    exe,
    *([splash.binaries] if splash else []),
    a.binaries,
    a.datas,
    name='p7m-extractor',
)
