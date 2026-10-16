# Code signing policy

Windows releases (the installer and the programs in the portable zip) are to
be signed with free code signing provided by [SignPath.io](https://about.signpath.io),
certificate by [SignPath Foundation](https://signpath.org). The project applied
for the SignPath Foundation program in October 2026: until it is accepted,
the Windows releases are not signed.

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
