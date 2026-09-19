# Upstream sources, security triage and the update target

Every managed shell package is one upstream release, pinned by URL and SHA-256, plus KalaReach's
own patch set. This page is the register of those sources, the record of what has been triaged
against them, and the update target each package is published under.

Upstream is never vendored: `scripts/build-shells.sh` fetches the pinned archive, checks its digest
and applies the ordered patches in `shells/<shell>/patches`. The pins live in
`shells/<shell>/manifest.json`, and the identity record the build writes beside the binary
(`kr-shell-identity.json`) carries the archive it actually fetched, its digest, the patches it
applied and the module tree it installed. The qualification reads all three and refuses a package
whose record does not agree with the pin, so this page cannot drift from what is installed without
a test failing.

## The sources each package tracks

<!-- kr:pins -->
| Package | Upstream | Pinned revision | Source | SHA-256 | Advisories watched |
| --- | --- | --- | --- | --- | --- |
| zsh | Zsh | zsh-5.9 | https://downloads.sourceforge.net/project/zsh/zsh/5.9/zsh-5.9.tar.xz | 9b8d1ecedd5b5e81fbf1918e876752a7dd948e05c1a0dba10ab863842d45acd5 | the zsh-announce and zsh-workers lists, and the project's own release notes |
| bash | GNU Bash | bash-5.2.37 | https://ftp.gnu.org/gnu/bash/bash-5.2.37.tar.gz | 9599b22ecd1d5787ad7d3b7bf0c59f312b3396d1e281175dd1f8a4014da621ff | the bug-bash list and the official patch series under ftp.gnu.org/gnu/bash/bash-5.2-patches |
| fish | fish-shell | fish-4.9.3 | https://github.com/fish-shell/fish-shell/releases/download/4.9.3/fish-4.9.3.tar.xz | 20998a25f73217ddcc19f499055fd587e9912d1ad6e7109120fbcf2871f0b98c | the fish-shell repository's security advisories and its release notes |
| psreadline | PSReadLine | psreadline-2.3.4 to 3.0.0 on PowerShell 7.4 or later | https://github.com/PowerShell/PowerShell | qualified rather than fetched | PowerShell/Announcements, and the PSReadLine and PowerShell repositories' security advisories |
<!-- /kr:pins -->

The PSReadLine package rebuilds no shell. What it pins is the range of the editor it was qualified
against, and the identity it publishes records the editor it found on the machine it qualified. A
security update to PowerShell or to PSReadLine is therefore a requalification rather than a rebuild,
and the same triage applies to it.

That range is a statement about the editor this integration works with, not about which releases
inside it carry which fixes. A person runs the host their machine has, so an advisory against
PowerShell or PSReadLine is triaged against the versions it names and against the identity the
qualification recorded, and it gets a row of its own below.

## The update target this publishes

<!-- kr:target -->
A security-relevant upstream change is triaged within one working day of the advisory. A package
that the change affects is rebuilt against the fixed upstream release, requalified against the
whole corpus under `tests/shells/`, and published within fourteen days of that release. No binary
is distributed before its requalification passes, and no package is swapped into a session that is
already running: a session keeps the package identity it started with until it ends.
<!-- /kr:target -->

## A package that cannot meet its target

A package whose fourteen days pass without a requalified build is flagged in the triage record
below, and the flag names the choices rather than leaving a stale package as a silent default. The
choices are:

* **Keep the pinned package.** The managed contract stays, the flag stays visible, and the session
  says which package it is running.
* **Run that shell in `native_compat`.** The lifecycle and the transfers stay; the managed
  empty-prompt Ctrl-D and the fenced launch do not, because an unqualified system shell cannot
  claim either.
* **Run a different managed shell.** The other packages are unaffected by one upstream's delay.

Each is an explicit selection. Nothing falls back on its own.

## Triage record

`assessment` says what the change is and whether the pinned release already carries it.
`status` is one of `released` (a requalified package is published), `scheduled` (inside its target
date), `flagged` (past its target date, with the choices above) or `not-affected`.

<!-- kr:triage -->
| Date | Upstream change | Packages | Assessment | Target release | Status |
| --- | --- | --- | --- | --- | --- |
| 2026-09-20 | CVE-2021-45444, prompt expansion in zsh before 5.8.1 | zsh | The pinned release is 5.9, which is after the fix. Nothing to rebuild. | 2026-10-04 | not-affected |
| 2026-09-20 | The official GNU Bash 5.2 patch series, 001 to 037 | bash | The pinned release is 5.2.37, which carries every patch published for 5.2 at the time of this pin. | 2026-10-04 | not-affected |
| 2026-09-20 | The fish-shell advisories published against 4.x | fish | The pinned release is 4.9.3, which is the newest 4.x release at the time of this pin and carries every advisory fix published for the series. | 2026-10-04 | not-affected |
| 2026-09-20 | The editor identity this package was qualified against | psreadline | This package was qualified against PSReadLine 2.4.5 on PowerShell 7.6.6, which is the identity its record names. The range it declares says which editor the integration works with and not which releases inside it carry which fixes, so an advisory against either project is triaged against the versions that advisory names and gets its own row. | 2026-10-04 | not-affected |
<!-- /kr:triage -->

## Requalifying a package

1. Change the pin in `shells/<shell>/manifest.json` to the fixed upstream release and its digest.
2. `bash scripts/build-shells.sh --<shell> --check-patches` — the patches have to apply to the new
   release with no fuzz. A patch that does not is a patch to rewrite, not one to force.
3. `bash scripts/build-shells.sh --<shell> --require-upstream-tests` — the build fetches the new
   archive, verifies the digest, applies the patches and runs the shell's own suite.
4. `bash scripts/fetch-shell-stacks.sh` — the startup customisations, if they are not already here.
5. `bash scripts/e2e-fence.sh` — the whole qualification against the rebuilt package, on a real
   daemon and a real shell.
6. Add a row to the triage record with the date, the change, the packages, the assessment, the
   target release date and the status.

The identity the rebuild writes is a digest of its inputs, so the same pin and the same patches
land in the same place and a rebuild that changed nothing says so.
