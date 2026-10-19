# Code signing policy

## Signature of the releases (minisign)

Since 1.3.3 every file of a release (the Windows installer and portable zip,
the Linux archive, the Flatpak bundle) is signed with
[minisign](https://jedisct1.github.io/minisign/). The release workflow signs
the files with the project's key, whose secret half is a secret of this
repository, checks each signature with the public key and publishes it next
to the file as `<file>.minisig`; its trusted comment names the file. The
installed Windows app checks this signature before running an update: an
installer not signed with this key, for that very file, is never started.

Public key (key id `CEFFF9269F08F845`):

    RWRF+AifJvn/zhz0o7MBObIYHgw9+sWoc4GaBK+qYnJY0AqeJm540y0a

To check a download by hand, with the `.minisig` of the release in the same
folder:

    minisign -Vm p7m-extractor-setup-vX.Y.Z-windows-x64.exe -P RWRF+AifJvn/zhz0o7MBObIYHgw9+sWoc4GaBK+qYnJY0AqeJm540y0a

The same key signs the releases of PDF Cropper and Cartiglio.

This is not an Authenticode signature: Windows does not know it, and
SmartScreen still warns when the installer is started from a download.

## Authenticode (SignPath Foundation)

The Windows releases (the installer and the programs in the portable zip)
are to be signed with free code signing provided by
[SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org). The project applied for the
SignPath Foundation program in October 2026, and was asked to apply again
once it has more of a reputation: until then the Windows releases have no
Authenticode signature.

## Team roles

- Committers and reviewers: [Daniel Grasso](https://github.com/daniel-g-carrasco)
- Approvers: [Daniel Grasso](https://github.com/daniel-g-carrasco)

Every release is built by GitHub Actions from this repository, from the tag
of its version: the build scripts and the workflow are part of the
repository. A release is signed only after it is approved by hand.

## Privacy policy

This program will not transfer any information to other networked systems
unless specifically requested by the user or the person installing or
operating it. The one exception is the update check of the Windows build:
once a day it asks GitHub Releases (api.github.com) whether a newer version
exists, sending nothing about the user or their files; it can be turned off
in Preferences ("Check for updates at start-up"). The files opened with the
program never leave the computer.
