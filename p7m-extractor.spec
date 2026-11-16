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

a = Analysis(
    [os.path.join(SPECPATH, 'build-aux', 'windows', 'p7m_extractor_main.py')],
    pathex=[os.path.join(SPECPATH, 'src')],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden,
    hooksconfig={'gi': {'module-versions': GI_VERSIONS}},
)



def msys2_licences(toc, root):
    """Windows: the licence texts of the MSYS2 packages the bundle takes files
    from, and licenses/msys2/PACKAGES.txt with each package's version, licence
    and source archive. The owner of each file is read from pacman's database."""
    db = root / 'var' / 'lib' / 'pacman' / 'local'
    if not db.is_dir():
        print(f'WARNING: no pacman database in {db}: the MSYS2 licences are not bundled')
        return []
    owner, packages = {}, {}
    for entry in db.iterdir():
        try:
            desc = (entry / 'desc').read_text(encoding='utf-8').split('\n\n')
            names = (entry / 'files').read_text(encoding='utf-8').split('%FILES%\n', 1)[1].split('\n\n')[0].split('\n')
        except (OSError, IndexError):
            continue
        fields = {block.split('\n')[0]: block.split('\n')[1:] for block in desc if block.startswith('%')}
        packages[entry.name] = fields, [n for n in names if '/share/licenses/' in n and not n.endswith('/')]
        for name in names:
            if name.startswith(('ucrt64/', 'mingw64/')) and not name.endswith('/'):
                owner[name.lower()] = entry.name
    used = set()
    for _dest, source, _kind in toc:
        try:
            relative = Path(source).resolve().relative_to(root.resolve()).as_posix().lower()
        except (ValueError, OSError):
            continue
        if relative in owner:
            used.add(owner[relative])
    entries, lines = [], ['MSYS2 packages the bundle takes files from (https://www.msys2.org).',
                          'Their licence texts are in this folder; the sources of each version are',
                          'at the address given (and in https://github.com/msys2/MINGW-packages).', '']
    for package in sorted(used):
        fields, licences = packages[package]
        name, version = fields['%NAME%'][0], fields['%VERSION%'][0]
        base = (fields.get('%BASE%') or [name])[0]
        lines += [f'{name} {version}', f'  licence: {" ".join(fields.get("%LICENSE%", ["?"]))}',
                  f'  source: https://repo.msys2.org/mingw/sources/{base}-{version}.src.tar.zst', '']
        for licence in licences:
            path = root / licence
            if path.is_file():
                inner = licence.split('/share/licenses/', 1)[1]
                entries.append((f'licenses/msys2/{inner}', str(path), 'DATA'))
    listing = Path(workpath) / 'PACKAGES.txt'
    listing.parent.mkdir(parents=True, exist_ok=True)
    listing.write_text('\n'.join(lines), encoding='utf-8', newline='\n')
    entries.append(('licenses/msys2/PACKAGES.txt', str(listing), 'DATA'))
    print(f'NOTE: licences of {len(used)} MSYS2 packages bundled ({len(entries) - 1} files)')
    return entries


if WIN:
    a.datas += msys2_licences(a.binaries + a.datas, prefix.parent)

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
