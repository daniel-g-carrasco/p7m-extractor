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
datas = [('data/icons', 'share/icons'), ('src/p7m_extractor/gui/style.css', 'p7m_extractor/gui')]
binaries = []

# Translations, compiled from po/ by `python tools/compile_po.py` (CI does it
# before running PyInstaller).
LOCALE_DIR = os.path.join(SPECPATH, 'locale')
if os.path.isdir(LOCALE_DIR):
    datas.append((LOCALE_DIR, 'share/locale'))
else:
    print('WARNING: locale/ missing: run tools/compile_po.py first (UI will be English only)')

# The GPL wants its text with the program: in licenses/ of the bundle, so in
# the installer, the zip and the tar.gz alike.
datas.append((os.path.join(SPECPATH, 'LICENSE'), 'licenses'))

if WIN:
    prefix = Path(sys.prefix)  # MSYS2: C:/msys64/ucrt64 (the one with libadwaita)

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

# Signature verification (pyHanko): the certificates of the European list of
# trusted lists, the XML schemas and the tables its libraries read at run
# time are files next to the modules, which PyInstaller does not take by
# itself; and the modules pyHanko loads by name. Without pyHanko the build
# is made all the same and says it cannot verify.
hidden = []
try:
    import pyhanko  # noqa: F401
    from importlib.metadata import PackageNotFoundError
    from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata
    for package in ('pyhanko', 'pyhanko_certvalidator', 'signxml', 'xsdata', 'certifi', 'tzdata'):
        datas += collect_data_files(package)
    # the licences of what is bundled travel with it (they are in each
    # package's metadata folder, which PyInstaller leaves out by itself)
    for package in ('pyhanko', 'pyhanko-certvalidator', 'cryptography', 'cffi', 'pycparser', 'lxml', 'asn1crypto',
                    'oscrypto', 'uritools', 'signxml', 'xsdata', 'typing-extensions', 'certifi', 'tzlocal', 'tzdata',
                    'aiohttp', 'aiohappyeyeballs', 'aiosignal', 'attrs', 'frozenlist', 'idna', 'multidict',
                    'propcache', 'yarl'):
        try:
            datas += copy_metadata(package)
        except PackageNotFoundError:
            pass            # not on this system (tzdata is Windows' only)
    hidden = collect_submodules('pyhanko.sign.validation') + collect_submodules('pyhanko.generated')
except ImportError:
    print('WARNING: pyHanko missing: this build will not verify signatures')

# Introspection modules the gi hook must collect: a libadwaita app on both
# systems (on Windows inside a window with the system title bar).
GI_VERSIONS = {'Gtk': '4.0', 'Gdk': '4.0', 'Adw': '1'}
gi_config = {'module-versions': GI_VERSIONS}
hooks = {'gi': gi_config}
if WIN:
    gi_config.update(icons=['Adwaita'], languages=['en', 'en_US', 'it'])
    # GTK links GStreamer, but P7M never opens media.
    hooks['gstreamer'] = {'include_plugins': []}
elif os.environ.get("P7M_LINUX_SOURCE_INPUTS"):
    # The release uses distribution assets. GLib also searches /usr/local/share
    # by default, which would bundle icons for unrelated apps on the build host.
    os.environ["XDG_DATA_DIRS"] = "/usr/share"

a = Analysis(
    [os.path.join(SPECPATH, 'build-aux', 'windows', 'p7m_extractor_main.py')],
    pathex=[os.path.join(SPECPATH, 'src')],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden,
    hookspath=[os.path.join(SPECPATH, 'build-aux', 'windows', 'hooks')] if WIN else [],
    excludes=['PIL', 'numpy', 'fontTools', 'threadpoolctl'] if WIN else [],
    hooksconfig=hooks,
)



if WIN:
    root = Path(SPECPATH)
    # Pango on Windows uses the platform's fonts. Keep its configuration.
    a.datas = [row for row in a.datas if not (
        Path(row[0]).parts[:2] == ('share', 'fonts')
        or Path(row[0]).name == 'icon-theme.cache'
        # pip bookkeeping is generated at install time and unused at runtime.
        or (Path(row[0]).parent.suffix == '.dist-info'
            and Path(row[0]).name in ('INSTALLER', 'RECORD', 'REQUESTED', 'direct_url.json'))
    )]
    # A shared hicolor directory can contain icons installed by unrelated apps.
    theme = prefix / 'share' / 'icons' / 'hicolor' / 'index.theme'
    a.datas.append(('share/icons/hicolor/index.theme', str(theme), 'DATA'))
    # Since Windows 10 the OS provides UCRT and these API-set forwarders.
    # Keep the runtime shipped by MSYS2 (e.g. libgcc and libwinpthread).
    a.binaries = [row for row in a.binaries if not (
        Path(row[0]).name.lower().startswith('api-ms-win-')
        or Path(row[0]).name.lower() == 'ucrtbase.dll'
    )]
    # Ship the exact public CA data from the certifi wheel. The MSYS2 CA
    # file is regenerated from the host's trust store by a pacman hook.
    import certifi
    a.datas.append(('certs/ca-bundle.crt', certifi.where(), 'DATA'))
    sys.path.insert(0, str(root / "tools"))
    from package_inventory import inventory

    # PyInstaller creates empty namespace modules for which no source file exists.
    pure = [row for row in a.pure if row[1] != '-']
    record, notices = inventory([*a.binaries, *a.datas, *pure, *a.scripts],
                                prefix.parent, root, Path(workpath),
                                revision=os.environ.get("APP_SOURCE_REVISION") or os.environ.get("GITHUB_SHA", "dev"))
    a.datas += notices
elif os.environ.get("P7M_LINUX_SOURCE_INPUTS"):
    root = Path(SPECPATH).resolve()
    sys.path.insert(0, str(root / "tools"))
    from linux_source_inputs import capture

    a.datas += capture([*a.binaries, *a.datas, *a.pure, *a.scripts], root, Path(workpath).resolve())


pyz = PYZ(a.pure)

# Windows: embed our own manifest, which declares system DPI awareness on
# top of PyInstaller's defaults, from the first instruction: GTK cannot
# switch the process to per-monitor awareness, where it would keep to whole
# scales (see the manifest).
MANIFEST = os.path.join(SPECPATH, 'build-aux', 'windows', 'p7m-extractor.manifest') if WIN else None

exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name='p7m-extractor',
    console=False,
    icon=ICON,
    manifest=MANIFEST,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    name='p7m-extractor',
)
