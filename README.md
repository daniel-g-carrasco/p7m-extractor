<p align="center">
  <img src="assets/icon.png" alt="P7M Extractor" width="128" height="128">
</p>

<h1 align="center">P7M Extractor</h1>

<p align="center">
  Extract the original document from CAdES <code>.p7m</code> digitally signed files, and check who signed them.
</p>

<p align="center">
  <a href="https://github.com/daniel-g-carrasco/p7m-extractor/actions/workflows/build.yml">
    <img src="https://github.com/daniel-g-carrasco/p7m-extractor/actions/workflows/build.yml/badge.svg" alt="Build">
  </a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
</p>

<p align="center"><a href="CODE_SIGNING.md">Code signing policy</a></p>

The `.p7m` format is used across Italy for signed drawings, contracts,
PEC attachments and electronic invoices (Fattura Elettronica). It wraps the
original document (PDF, XML, …) in a PKCS#7/CMS signature envelope; this tool
unwraps it.

Drag & drop GUI (GTK 4 / libadwaita) + CLI, installable or portable on
**Windows**, Flatpak or portable on **Linux**. The PKCS#7/CMS envelope is
parsed directly by a small pure-Python BER parser, with no third-party
package: the extracted file is **byte-for-byte identical** to what was signed.
Since 1.4 the app also [checks the signatures](#verifying-signatures): who
signed, whether the document is still the one that was signed, and whether
the certifier is in the European trusted lists.

<p align="center">
  <img src="data/screenshots/demo.gif" alt="Dropping a folder of .p7m files on P7M Extractor: the rows fill in with their outcome while the extracted PDFs appear next to the signed files in the file manager" width="800">
</p>

## Download

Grab a build from the
[**Releases**](https://github.com/daniel-g-carrasco/p7m-extractor/releases) page:

| Platform | File | Notes |
|---|---|---|
| Windows installer | `p7m-extractor-setup-*-windows-x64.exe` | Start menu entry, uninstaller, `.p7m` file association and Explorer context menu (both optional), built-in update check |
| Windows portable | `p7m-extractor-*-windows-x64-portable.zip` | unzip anywhere, run `p7m-extractor.exe` — no installation, no admin rights; Explorer integration can be enabled from *Preferenze* |
| Linux Flatpak | [our repository](https://daniel-g-carrasco.github.io/p7m-extractor/) | `flatpak install https://daniel-g-carrasco.github.io/p7m-extractor/p7m-extractor.flatpakref`, updates arrive through GNOME Software; a `.flatpak` bundle is attached to every release too |
| Linux portable | `p7m-extractor-*-linux-x64-portable.tar.gz` | untar, run `./p7m-extractor` |

Everything (GTK included) ships inside the Windows and portable packages.
The installer defaults to a per-user install, so no administrator rights are
needed there either.

[Code signing policy](CODE_SIGNING.md): since 1.3.3 every file of a release
is signed with minisign (the public key and how to check a download are
there), and the installed app checks the signature of an update before
running it. An Authenticode signature by SignPath Foundation is to come:
until then Windows' SmartScreen warns about the installer.

## Run from source

Only Python ≥ 3.9, PyGObject/GTK 4 and libadwaita 1.5 or newer are needed,
all packaged on every distribution. libadwaita is optional: without it the GUI
falls back to plain GTK 4.

```bash
# Debian/Ubuntu          # Fedora                          # Arch
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1
                         sudo dnf install python3-gobject gtk4 libadwaita
                                                           sudo pacman -S python-gobject gtk4 libadwaita
python3 bin/p7m-extractor
```

On Windows, use a release build or MSYS2 UCRT64
(`pacman -S mingw-w64-ucrt-x86_64-gtk4 mingw-w64-ucrt-x86_64-libadwaita mingw-w64-ucrt-x86_64-python-gobject`).

Checking the signatures needs [pyHanko](https://github.com/MatthiasValvekens/pyHanko)
as well: `pip install "pyhanko[etsi]==$(python3 tools/flatpak_wheels.py --version)"`,
the version every build carries. On MSYS2 take what has compiled parts from
pacman first (`mingw-w64-ucrt-x86_64-python-pip`, `-python-cryptography`,
`-python-lxml`, `-python-aiohttp`, `-python-asn1crypto`), then the same `pip`
line with `--break-system-packages`. Without pyHanko everything else works,
and the app says that it cannot verify.

## CLI

The same executable works headless when given arguments
(the CLI core is pure stdlib — it runs even without GTK installed):

```bash
p7m-extractor invoice.xml.p7m                 # single file
p7m-extractor --overwrite projects/           # whole folder, recursive
p7m-extractor a.pdf.p7m b.pdf.p7m c.xml.p7m   # batch
p7m-extractor --verify contract.pdf.p7m       # who signed, and whether the signature holds
p7m-extractor --verify --offline projects/    # without the network: the integrity alone
p7m-extractor --check-update                  # print the latest release
p7m-extractor --register | --unregister       # Windows: Explorer integration
```

Exit code is non-zero if any file failed. Existing outputs are skipped unless
`--overwrite` is given. `--verify` extracts nothing and ends with 0 when every
signature of every file passed, 3 when something could not be established (or
only the integrity was checked), 1 when a signature is wrong or a file could
not be read.

## Features

- **Drag & drop** files *or folders* (folders are scanned recursively)
- **Batch**: hundreds of files in one go, every file listed at once with its
  state (queued, extracting with progress, done); double-click a finished
  row to open the document, or use its folder button to reveal it
- **Single window**: opening more files (double-click, context menu, several
  files selected at once) adds them to the window already open
- **Nested signatures** (`doc.pdf.p7m.p7m`) unwrapped in a single pass
- **Signatures checked** after the extraction: each row says who signed and
  how the check went, and its shield opens the details
  ([Verifying signatures](#verifying-signatures))
- **Binary and base64/PEM** `.p7m` containers auto-detected
- **BER streaming** (indefinite-length, chunked content) fully supported —
  the encoding used by common Italian signing tools
- Output is written next to the source file, never modifying the original
- **Light / dark theme** following the system (Windows personalization
  setting, freedesktop settings portal on Linux), or forced from *Preferences*
- **English and Italian** UI, following the desktop language (or forced from
  *Preferences*); the Windows installer is bilingual too and hands its
  language choice over to the app

### Windows integration

<p align="center">
  <img src="data/screenshots/windows-main-window.png" alt="P7M Extractor on Windows 11: native title bar, drop zone and the empty results list" width="400">
  <img src="data/screenshots/windows-main-menu.png" alt="The main menu on Windows: Controlla aggiornamenti…, Preferenze (Ctrl+,), Informazioni su P7M Extractor" width="400">
</p>

- **Double-click** a `.p7m` to extract it on the spot (file association):
  the file lands in the window's list as *In coda*, then shows its
  extraction progress (read and write, useful on network shares) and the
  outcome. Further files join the queue in the same window.
- The main menu opens with F10 (GTK convention) or a tap on Alt (Windows
  habit); another tap on Alt closes it.
- **Context menu**: right-click one or more `.p7m` files →
  *Estrai il contenuto con P7M Extractor*. On Windows 11 the entry lives
  under *Mostra altre opzioni* (Shift+F10), like every classic shell verb.
- **Default app prompt**: at start-up the app offers to become the default
  handler for `.p7m` (buttons *Imposta come predefinita* / *Non ora*, plus
  *Non chiedere più*). Since Windows 10 an app cannot override a default the
  user already chose, so in that case the app opens the *Default apps* page
  of Settings directly on its own entry.
- **Updates**: menu → *Controlla aggiornamenti…*, plus an automatic daily
  check (can be turned off in *Preferenze*). Installed builds download the
  new installer and launch it; the portable build is sent to the release page.
- Everything above is per-user (`HKEY_CURRENT_USER`), also for the portable
  build; *Preferenze* → *Rimuovi* takes it all away, as does the uninstaller.
- **libadwaita inside, Windows outside**: the content is the same libadwaita
  interface as on Linux (drop zone, card list, toasts, dialogs), while the
  system title bar (dark when the theme is dark) handles moving, snapping and
  restoring from maximized, which GTK's own decorations get wrong on Windows.
  *Preferenze* switches to libadwaita's header bar, at the cost of snapping.

<p align="center">
  <img src="data/screenshots/windows-context-menu.png" alt="Explorer context menu on a .p7m file: Apri, with the P7M Extractor icon, extracts it on the spot" width="500">
</p>

### Linux

- A libadwaita application: current GNOME look, `AdwStyleManager` follows the
  system light/dark preference on its own, `AdwAboutDialog` and
  `AdwPreferencesDialog` for the secondary windows.
- Registers as a handler for `application/pkcs7-mime` through its desktop
  entry, so it shows up in *Open With* and can be set as default from the
  file manager — no in-app prompt, as the GNOME HIG prescribes.
- No self-updater: updates come from Flatpak / the distribution, and the
  release notes are shipped as AppStream metadata for GNOME Software.

## Why not just `openssl smime`?

Two traps that this tool exists to avoid:

1. `openssl smime` chokes on BER indefinite-length encoding
   (`asn1 encoding routines:wrong tag`) — many Italian `.p7m` use it.
2. `openssl cms -verify` **without `-binary` silently corrupts binary
   content** by converting line endings (LF → CRLF): the extracted PDF grows
   by a few KB, its cross-reference offsets shift, and strict viewers
   (e.g. Nitro PDF) refuse to open it.

If you prefer OpenSSL, the correct incantation is:

```bash
openssl cms -verify -noverify -binary -inform DER -in file.pdf.p7m -out file.pdf
```

P7M Extractor sidesteps both problems by parsing the envelope itself and
copying the embedded octets verbatim.

## Verifying signatures

After the extraction the app checks every signature of the file, also those
of an envelope inside another (`doc.pdf.p7m.p7m`: each envelope is checked on
what it signed, and the window draws them one inside the other, however many
they are). For each signature it says who signed (name, organisation and
identifier, as the certificate writes them), which certifier issued the
certificate and its dates, the time of signing and whether a time stamp
proves it, and one of four outcomes:

| Outcome | What it means |
|---|---|
| **Valid** | the document is the one that was signed, the certificate leads to a certifier in the European trusted lists, and the certifier answered that it is not revoked |
| **Not established** | nothing is wrong with the signature itself, but something could not be confirmed: the certificate has expired and no time stamp proves that the signature is older, the certifier is not in the lists, the revocation could not be asked |
| **Not valid** | the document was changed after the signature, or the signature does not match its certificate |
| **Intact** | without the network, or with `--offline`: the integrity was checked, the certificate and its certifier were not |

The first three are the outcomes of ETSI EN 319 102-1 (passed, indeterminate,
failed); the fourth is the app's own way of saying that it checked less. A
signature is never called valid unless the revocation was asked, and a
certificate that calls itself qualified is said to be so only when its
certifier is in the lists as qualified for signatures.

**What goes over the network.** The European list of trusted lists and the
list of the country of the signer's certificate are fetched and kept for a day
in `trusted-lists`, next to the settings; without the network the copy kept is
used, and its age is said. The certifier's revocation server (OCSP or CRL) is
asked about the certificate, which it knows by its serial number. No document
and no file name leave the computer. *Preferences → Signatures* turns the
whole check off.

**What this is not.** The check is made on your computer with
[pyHanko](https://github.com/MatthiasValvekens/pyHanko) (MIT), following the
European rules for validating signatures, but P7M Extractor is not a
*qualified validation service* in the sense of Article 33 of Regulation (EU)
No 910/2014 (eIDAS): what it says is an informed check, not a report with
legal value. When one is needed (a tender, a dispute, an archive), use a
qualified service or the verifier of a qualified provider (GoSign, ArubaSign,
the AgID-accredited online verifiers).

## Flatpak

The app is published in its own Flatpak repository, served from GitHub Pages
and signed with the key `CD01 04C4 EBDE 041D 4B63 E635 9240 718A F4C3 3BD2`;
the GNOME runtime comes from Flathub. Install once, updates follow:

```bash
flatpak install https://daniel-g-carrasco.github.io/p7m-extractor/p7m-extractor.flatpakref
```

Every `v*` tag is published there by CI
([flatpak-repo.yml](.github/workflows/flatpak-repo.yml)). To build locally
instead:

```bash
flatpak install flathub org.gnome.Platform//50 org.gnome.Sdk//50
flatpak-builder --user --install --force-clean build-dir \
    build-aux/flatpak/io.github.daniel_g_carrasco.p7m-extractor.yaml
flatpak run io.github.daniel_g_carrasco.p7m-extractor
```

The manifest ([build-aux/flatpak/](build-aux/flatpak/)) installs the script,
the desktop entry, the AppStream metainfo and the icons from
[data/](data/). CI builds a `.flatpak` bundle for every push and attaches it
to releases. The app needs `--filesystem=host` because the extracted file is
written next to the signed one, wherever that is, and `--share=network` to
ask the trusted lists and the certifier when it checks a signature. pyHanko
and what it needs are built in from wheels pinned by URL and SHA-256:
`python3 tools/flatpak_wheels.py --write` writes that block of the manifest,
and the build runs `tests/test_verify.py` with them.

The app ID `io.github.daniel_g_carrasco.p7m-extractor` is derived from the
GitHub repository, so Flathub verifies ownership through the GitHub account
and no domain is involved. Submitting needs, in addition: a screenshot at
`data/screenshots/main-window.png` (referenced by the metainfo at the
release tag) and a copy of the manifest with a `type: git` source pinned to
the release tag.

The [site/](site/) folder is the project page, https://p7m.neistar.com,
deployed with Cloudflare Pages (repository connected, no build command,
output directory `site`).

## Development

The code is the package `src/p7m_extractor/`, in four layers with the
imports going one way only: `core/` (plain logic), `data/` (the .p7m
container, bytes in and bytes out), `app/` (extraction of a file, the check
of its signatures, settings, updates, the Windows registry; no toolkit) and
`gui/` (the GTK window, the
only place `gi` is imported). `gui` uses `app`, `app` uses `core` and `data`,
`core` and `data` know nobody. `tests/test_strati.py` reads the imports and
fails with file, line and rule.

```bash
python tests/test_extract.py     # self-contained test suite, no deps
python tests/test_strati.py      # the layers: every import goes one way
python tests/test_verify.py      # the signatures: the words always, the checking where pyHanko is; no network
python tools/flatpak_wheels.py --check   # the Flatpak's wheels are the pinned ones (asks PyPI)
python tools/compile_po.py       # compile po/*.po into locale/ (needed to see translations)
python tools/make_icon.py        # regenerate assets/icon.*, data/icons PNGs, installer bitmaps (Pillow)
desktop-file-validate data/io.github.daniel_g_carrasco.p7m-extractor.desktop
appstreamcli validate --no-net data/io.github.daniel_g_carrasco.p7m-extractor.metainfo.xml
```

Builds are produced by [CI](.github/workflows/build.yml) (PyInstaller;
MSYS2 on Windows; installer compiled with Inno Setup; Flatpak via
flatpak-builder). Tagging `v*` publishes a release; the tag must match
`__version__` in `src/p7m_extractor/__init__.py`, and the release should be listed in
the metainfo. Most of the package size is the bundled GTK stack; CI strips
unused locales and icon-theme variants to keep it in check. pyHanko's version
is written in one place, `tools/flatpak_wheels.py`, which every build asks;
each build is then tried on a file signed by the tests' own certifier, which
no build may call valid.

Preferences are stored in `%LOCALAPPDATA%\p7m-extractor\settings.ini` on
Windows and `$XDG_CONFIG_HOME/p7m-extractor/settings.ini` on Linux; the
trusted lists are kept in `trusted-lists` in the same folder.

Translations live in `po/` (English source strings in the code, one `.po`
per language). To refresh the template after changing strings:
`xgettext --from-code=UTF-8 --keyword=_ -o po/p7m-extractor.pot $(find src -name '*.py' | sort)`,
then merge with `msgmerge -U po/it.po po/p7m-extractor.pot`.
Set `P7M_STARTUP_LOG=<file>` to get start-up timestamps appended to a file
(profiling aid).

## License

[MIT](LICENSE) © Daniel Grasso
