# Changelog

What changes for the user from one version to the next. The notes of the
versions up to 1.4.0 are on the
[releases page](https://github.com/daniel-g-carrasco/p7m-extractor/releases).

## [1.5.3] - 2026-11-27

### Fixed

- The extracted file is written whole or not at all: it is first written
  next to the destination under a temporary name and then put in place.
  An extraction that stops halfway (a full disk, the program closed) no
  longer leaves a cut file with the document's name, and a file with that
  name created meanwhile is not overwritten.

### Changed

- The download of the corresponding sources, offered with each release, is
  now put together and signed by the automated build, for Windows too.

## [1.5.2] - 2026-11-18

### Changed

- Secondary windows on Windows use the system title bar.
- The new update window shows what changed, with Italian notes when the app is in Italian.
- Preferences and Signatures use the same layout and spacing as the other windows.
- The packages include licence notices for the bundled libraries. The release offers the corresponding sources alongside the downloads.
- The Windows installer and portable package are smaller.

## [1.5.1] - 2026-11-17

### Changed
- A new icon, in the style now shared by the apps of the same family (Scriba, Meridiana and the others): a red wax seal with two straight ribbons on a blue canvas,
  flat shapes with the light on the left and the shadow on the right, on a square canvas with a little thickness below
  it. On Windows the icon reaches the edge of its square in the taskbar, with a drawing of its own for 16-24 px.
  `tools/make_icon.py` now makes every size from the SVG.

## [1.5.0] - 2026-11-16

### Changed

- **Licence: GPL-3.0-or-later** (the GNU General Public License, version 3
  or later) from this version on. P7M Extractor now shares some of its
  modules with the author's other apps, which are under this licence; the
  versions up to 1.4.0 were released under the MIT licence, and they stay
  so. The About window, the AppStream metadata, the README and the site say
  it. The text of the licence comes with every build, in `licenses/`; the
  Windows builds carry also the licence texts of the MSYS2 libraries they
  include, with the address of their sources.
- Windows: the check for a newer version is made at start and when the
  window is restored from the taskbar, every 4 hours at most; it was once
  a day, at start. The first start after the update checks again.
- The About window has a *Troubleshooting* section: version, system, the
  folders, the settings and the errors file, to copy or save for a report
  of a problem. Nothing of the files opened is in it.
- Two messages of the update say GitHub and the project: "unexpected answer
  from GitHub" (it said "the server"), "the installer is not signed by the
  project" (it said "the installer's signature is not valid"); the Italian
  follows them.

### Fixed

- The errors of the window are kept in `errors.log` in the state folder
  (`%LOCALAPPDATA%\p7m-extractor\state` on Windows,
  `~/.local/state/p7m-extractor` on Linux), rotated past 1 MB: started from
  the desktop or from File Explorer they were lost.
- `settings.ini` is written whole or not at all, and the save is tried again
  for a moment when Windows refuses it (an antivirus or the indexer holding
  the file): a failure half way could leave it truncated.

[1.5.0]: https://github.com/daniel-g-carrasco/p7m-extractor/compare/v1.4.0...v1.5.0
