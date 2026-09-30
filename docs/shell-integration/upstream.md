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
`status` is one of `released` (a requalified package is published, and the assessment names the
identity it was published under), `scheduled` (inside its target date), `flagged` (past its target
date, with the choices above) or `not-affected`.

<!-- kr:triage -->
| Date | Upstream change | Packages | Assessment | Target release | Status |
| --- | --- | --- | --- | --- | --- |
| 2026-09-20 | CVE-2021-45444, prompt expansion in zsh before 5.8.1 | zsh | The pinned release is 5.9, which is after the fix. Nothing to rebuild. | 2026-10-04 | not-affected |
| 2026-09-20 | The official GNU Bash 5.2 patch series, 001 to 037 | bash | The pinned release is 5.2.37, which carries every patch published for 5.2 at the time of this pin. | 2026-10-04 | not-affected |
| 2026-09-20 | The fish-shell advisories published against 4.x | fish | The pinned release is 4.9.3, which is the newest 4.x release at the time of this pin and carries every advisory fix published for the series. | 2026-10-04 | not-affected |
| 2026-09-20 | The editor identity this package was qualified against | psreadline | This package was qualified against PSReadLine 2.4.5 on PowerShell 7.6.6, which is the identity its record names. The range it declares says which editor the integration works with and not which releases inside it carry which fixes, so an advisory against either project is triaged against the versions that advisory names and gets its own row. | 2026-10-04 | not-affected |
| 2026-09-20 | CVE-2026-62801, PowerShell, published at github.com/PowerShell/Announcements/issues/98; fixed in 7.4.20, 7.5.11 and 7.6.6 | psreadline | The host this package was qualified against is 7.6.6, which is the fixed release of its own series, so the qualified identity carries the fix. A person on an earlier 7.4 or 7.5 release is on an affected host and updates it; this package qualifies the editor against the host the person runs and does not ship one. | 2026-10-04 | not-affected |
<!-- /kr:triage -->

## Native modules and the editor ABI

A person can load a native Zsh module of their own into a managed session. Zsh's loader records no
editor ABI and refuses nothing for a module that binds its imports lazily, so a module built against
an editor whose functions this package lacks loads without complaint and ends the shell at the first
call that needs the missing function. The session answers that with a named error before it is
ready. It never reaches a ready state with such a module loaded.

The triage record above, the update target and the requalification steps are the standing record for
the packages. This section is the proof that the editor check refuses what it claims to, and the
limits of what it claims.

### What the check does

When the integration reports that its hooks are live, which is after every startup file has run, the
Zsh package lists each dynamic module the shell holds that did not come from the package's own
module directory. For each one it reads the undefined symbols in the module's file (Mach-O, fat
files included, and ELF64) and asks the running shell whether the shell, the modules already loaded
or the module's own libraries provide each name. A module from the package's own tree is skipped by
a path check, and a name the module imports weakly is not judged. The report says, for each module,

* `bound`: every name resolves;
* `missing`: the first name that does not, with the module and its path;
* `not_read`: why the file could not be inspected (unreadable, too large, a format the reader does
  not know, a path the loader does not give).

The worker refuses the session on `missing` and on `not_read`, because an inspection that cannot be
made whole is not a pass. The create answers `SHELL_INTEGRATION_UNSUPPORTED` with the reason
`module_tree_unsupported` and names the module and the import, or the module and why it could not
be checked. The Bash, Fish and PowerShell bridges send an empty list.

### The proof

`crates/kr-shell-integration/tests/module_abi.rs` compiles modules as a person compiles one, against
the headers of this repository's own Zsh package (`tests/shells/zsh/native-module-abi/`), loads each
from a startup file into the built package, and reads the report the shell sends.

| Module | What it is | Result |
| --- | --- | --- |
| compatible | imports only what the package provides | loads, `bound`, the session may qualify |
| newer | also calls a function no editor of this release has | loads, `missing` naming that function, the session is refused with `module_tree_unsupported` |
| lazy | imports from a package module that is not loaded yet | `bound`: the shell loads that module on demand |
| weak | imports a name it is content to lose | `bound` |
| removed | loads, and its file is removed by the startup file that loaded it | `not_read`, refused with the module named and why it could not be checked |
| a file the loader refuses | not a module in any format the shell loads | the loader reports it; the report has no entry, and the session is not refused for a module that never loaded |
| the package's own modules, loaded from another directory | what a module of the shell's own kind imports | every one `bound` |

The newer module is the control that matters: the loader accepts it, which is the false ready state
the check exists to prevent, and the check refuses it.

### What it does not detect

* **A layout difference whose symbols resolve.** A module built against another layout of the same
  names binds every symbol it imports, and no import check tells it from one built for this editor.
  Two configures of the pinned release show it. `--enable-multibyte` and `--disable-multibyte`
  export the same editor state, `zleline`, `zlell` and `zlecs`, with different element types
  (`wchar_t` and `char`), and 1,131 function names in common. A module that uses only shared names
  binds in either build. A module that calls one of the 27 functions only the multibyte build
  exports, or one of the 8 only the other does, is refused by the other.
* **A changed signature, meaning or data type** behind a name that still resolves.
* **A module loaded after the hooks go live**: a later `precmd`, `zle-line-init`, deferred or
  on-demand loading, or a `module_path` the person extended after the check.
* **A module the loader refuses.** The loader reports that itself.
* **Loadable builtins and modules of other shells**: Bash's `enable -f`, Fish and PowerShell's
  binary modules. PowerShell's own editor range is enforced by the PSReadLine package, and this
  proof does not cover it.

### What the check costs at activation

The check runs once per session, when the hooks go live, on the shell's own thread, and reads only
regular files, each at most 64 MiB. A shell that loaded no module of its own pays for the list and
a path check per package module. Each module of the person's own adds one read of its file and one
lookup per undefined name.

Measured from a timer around the whole check in a session under the built package, median of ten
sessions per row, file cache warm:

| The shell holds | Apple M4 Pro, macOS 26 | AMD EPYC 7502P, Linux (glibc 2.43) |
| --- | --- | --- |
| no module of its own | 0.12 ms | 0.10 ms |
| 1 small module | 0.22 ms | 0.16 ms |
| 3 small modules | 0.28 ms | 0.17 ms |
| 8 small modules | 0.62 ms | 0.43 ms |
| 10 of the package's own modules, read from another directory | 2.2 ms | 0.73 ms |
| about 35 of the package's own modules, read from another directory | 4.7 ms | 1.8 ms |

A `.zshrc` that loads the package's own modules pays only the path check. One that loads a few
modules of its own pays about a tenth of a millisecond for each. The last two rows are the worst
case, every one of the package's dozens of modules read as if it were the person's, and they stay
under five milliseconds. A cold read adds the time to fetch each module's file from disk, which
these figures leave out.


## Requalifying a package

1. Change the pin in `shells/<shell>/manifest.json` to the fixed upstream release and its digest.
2. `bash scripts/build-shells.sh --<shell> --check-patches` — the patches have to apply to the new
   release with no fuzz. A patch that does not is a patch to rewrite, not one to force.
3. `bash scripts/build-shells.sh --<shell> --require-upstream-tests` — the build fetches the new
   archive, verifies the digest, applies the patches and runs the shell's own suite. The PSReadLine
   package builds no shell and the script takes no option for it: it is requalified by importing
   `shells/psreadline/module` on the host in question and running `Publish-KalaReachQualification`,
   which `scripts/e2e-fence.sh` does as one of its own steps.
4. `bash scripts/fetch-shell-stacks.sh` — the startup customisations, if they are not already here.
5. `bash scripts/e2e-fence.sh` — the whole qualification against the rebuilt package, on a real
   daemon and a real shell.
6. `cargo test -p kr-shell-integration --test module_abi --test relocation -- --include-ignored` —
   the native-module proof described below, and the proof that a moved Zsh tree still finds its
   modules, against the rebuilt package. A release whose editor changed is the release that can
   make a module the last one accepted fail to bind.
7. Add a row to the triage record with the date, the change, the packages, the assessment, the
   target release date and the status.

The identity the rebuild writes is a digest of its inputs, so the same pin and the same patches
land in the same place and a rebuild that changed nothing says so.
