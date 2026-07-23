# P7M Extractor

[![Build](https://github.com/TheErasedChild/p7m-extractor/actions/workflows/build.yml/badge.svg)](https://github.com/TheErasedChild/p7m-extractor/actions/workflows/build.yml)

Extract the original document (PDF, XML, …) from CAdES **`.p7m`** digitally
signed files — the format used across Italy for signed drawings, contracts,
PEC attachments and electronic invoices (Fattura Elettronica).

Drag & drop GUI (GTK 4) + CLI, portable builds for **Windows** and **Linux**,
zero runtime dependencies: the PKCS#7/CMS envelope is parsed directly by a
small pure-Python BER parser. The extracted file is **byte-for-byte identical**
to what was signed.

**🇮🇹 In breve:** trascina i file (o intere cartelle) `.p7m` nella finestra e
il documento originale viene estratto accanto al file firmato. Gestisce
fatture elettroniche, PDF firmati, firme annidate (`.pdf.p7m.p7m`) e file
codificati base64/PEM.

## Download

Grab the portable build from the
[**Releases**](https://github.com/TheErasedChild/p7m-extractor/releases) page:

| Platform | File | Run |
|---|---|---|
| Windows x64 | `p7m-extractor-*-windows-x64.zip` | unzip, run `p7m-extractor.exe` |
| Linux x64 | `p7m-extractor-*-linux-x64.tar.gz` | untar, run `./p7m-extractor` |

No installation, no admin rights. Everything (GTK included) is inside the folder.

## Run from source

Only Python ≥ 3.9 and PyGObject/GTK 4 are needed — both usually one package
away on Linux:

```bash
# Debian/Ubuntu          # Fedora                        # Arch
sudo apt install python3-gi gir1.2-gtk-4.0
                         sudo dnf install python3-gobject gtk4
                                                         sudo pacman -S python-gobject gtk4
python3 p7m_extractor.py
```

On Windows, use the portable build or MSYS2
(`pacman -S mingw-w64-x86_64-gtk4 mingw-w64-x86_64-python-gobject`).

## CLI

The same executable works headless when given arguments
(the CLI core is pure stdlib — it runs even without GTK installed):

```bash
p7m-extractor fattura.xml.p7m                 # single file
p7m-extractor --overwrite progetti/           # whole folder, recursive
p7m-extractor a.pdf.p7m b.pdf.p7m c.xml.p7m   # batch
```

Exit code is non-zero if any file failed. Existing outputs are skipped unless
`--overwrite` is given.

## Features

- **Drag & drop** files *or folders* (folders are scanned recursively)
- **Batch**: hundreds of files in one go, results listed live
- **Nested signatures** (`doc.pdf.p7m.p7m`) unwrapped in a single pass
- **Binary and base64/PEM** `.p7m` containers auto-detected
- **BER streaming** (indefinite-length, chunked content) fully supported —
  the encoding used by common Italian signing tools
- Output is written next to the source file, never modifying the original

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

> **Note on legal validity** — this tool *extracts* the signed content; it
> does **not** validate certificates, trust chains or revocation. For legally
> meaningful verification use a qualified service (GoSign, ArubaSign, the
> AgID-accredited online verifiers).

## Development

```bash
python tests/test_extract.py     # self-contained test suite, no deps
```

Portable builds are produced by [CI](.github/workflows/build.yml)
(PyInstaller; MSYS2 on Windows). Tagging `v*` publishes a release.

## License

[MIT](LICENSE) © Daniel Grasso
