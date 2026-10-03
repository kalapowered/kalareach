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

A person can load native Zsh modules of their own into a managed session. Specifically, the loader does not record the editor's ABI, and the loader refuses nothing for a module that binds its imports lazily. In short, a native Zsh module built against an editor whose functions this package lacks can be loaded without error, but will end the shell at the first call that needs the missing function. The session answers with a named error before it is ready, for the modules and the limits described below. However, it is not guaranteed that all incompatible modules will be detected.

The triage record above, the update target and the requalification steps are the standing record for the packages. This section shows that the editor check refuses what it claims to refuse, and says where its claims stop.

### What the check does

The integration reports when its hooks are live. On Zsh the judgment of dynamically loaded modules happens when the first prompt is drawn, after the shell has loaded all the startup files. The Zsh package judges all dynamic modules the shell holds. Note that it will also judge modules that ship with the Zsh package, but the location of a module is not relevant, they are bound the same way.

For each module held in the shell it judges the module as the shell loaded it. It does this by reading the dynamic section (Linux) or the `__LINKEDIT` segment (macOS) in memory. The undefined symbols of the module are taken from the tables the loader used when binding the module, which are still available in memory. Note that no file is ever opened, since the module's file might have been removed or replaced after loading, and the file then found is not the code the shell runs. On Linux, the tables are only read if they appear in the loadable segments of the object that are loaded in memory. The symbols are then looked up in the shell itself, other modules that were already loaded at the time or the libraries the module was loaded with. If the symbol had a version it is looked up with that version in the global scope of the shell and in the libraries the module was loaded with. Symbols that were weakly imported by the module are not judged. The report gives one of three results for each module:

* `bound`: every name resolves.
* `missing`: the first name that does not, with the module and its path.
* `not_read`: why the module could not be inspected. The loader does not say where it mapped the module, a table is not one this reader knows, or the platform's format is unknown.

The worker refuses the session on `missing` and on `not_read`, because an inspection that cannot be made whole is not a pass. The create answers `SHELL_INTEGRATION_UNSUPPORTED` with the reason `module_tree_unsupported`. It names the module and the import, or the module and why it could not be checked. The Bash, Fish and PowerShell bridges send an empty list.

The reader only supports shared objects generated by the linker on macOS and Linux with glibc. On other platforms all modules are `not_read`, which refuses the session.

### The proof

The test source is `crates/kr-shell-integration/tests/module_abi.rs`. It compiles the modules the way a person compiles one, against the headers in this repository's own Zsh package (`tests/shells/zsh/native-module-abi/`). It then loads each one from a startup file into the built package, and reads what the shell sends in its report. It does this on macOS and Linux.

| Module | What it is | Result |
| --- | --- | --- |
| compatible | imports only what the package provides | loads, `bound`, the session may qualify |
| newer | also calls a function no editor of this release has | loads, `missing` naming that function, the session is refused with `module_tree_unsupported` |
| newer, then removed | the startup file that loaded it removes its file | still `missing`: the module the shell holds is judged |
| newer, then replaced | the startup file puts a module that binds where its file was, or a link to a module of the package | still `missing`; and a compatible module replaced by a newer one is still `bound` |
| newer, beside a copy of the editor | a copy of the package's editor is first on the module path | `missing`: a neighbour of a copy is not the package's |
| lazy | imports from a package module | `missing` while that module is not loaded, `bound` once the startup file has loaded it |
| weak | imports a name it is content to lose | `bound` |
| versioned | calls the C library, whose names carry a version on Linux | `bound` |
| a file the loader refuses | not a module in any format the shell loads | the loader reports it; the report has no entry, and the session is not refused for a module that never loaded |
| the package's own modules | all loaded from another directory, and each loaded alone | every one `bound` |

The newer module is the control that matters. The loader accepts it, which is the false ready state the check exists to prevent, and the check refuses it. The refusal that `not_read` carries is proved in the contract's own tests. No module in these tests reaches `not_read`. Two known cases end there and refuse the session: a Mach-O import that has no C underscore prefix, and an ELF object whose table addresses the reader cannot place in the object's own memory.

### What it does not detect, and what it refuses

* **A layout difference whose symbols resolve.** A module built against another layout of the same names binds every symbol it imports, and there is no way for an import check to tell it from one built for this editor. Two configures of the pinned release show the case. `--enable-multibyte` and `--disable-multibyte` export the same editor state, `zleline`, `zlell` and `zlecs`, with different element types (`wchar_t` and `char`), and the two builds share 1,131 function names. A module that imports only shared names binds in either build. A module that calls one of the 27 functions only the multibyte build exports, or one of the 8 only the other build exports, is refused by the other build.
* **A changed signature, meaning or data type** behind a name that still resolves.
* **A name that a library imports in its turn.** The check reads the module, not the libraries the module needs or opens for itself. What such a library imports is not read. A name the module looks up itself with `dlsym` is not seen either. On macOS a lazily bound name is found in any loaded image, not only in the library its two-level namespace names, and a module whose setup function comes from a library it links is judged as that library.
* **A module loaded after the check.** That includes a later `precmd`, `zle-line-init`, deferred or on-demand loading, and a `module_path` the person extended after the check. The entry point installed at startup defers producing the report until the first time the prompt is displayed, so that the modules the startup files load are taken into account. A startup file that runs the activation builtin by hand earlier gets a report based on what has been loaded at that time, and the create can answer ready on that report. A module loaded after it is judged only by the report the entry sends at the first prompt, and a refusal then degrades a session that was already reported ready.
* **A module the loader refuses.** The loader reports that itself.
* **A module built to be missed.** The check is meant for an accidental mismatch. A module is the person's own code and runs with their authority.
* **Loadable builtins and modules of other shells.** Bash's `enable -f`, Fish and PowerShell's binary modules are not checked. PowerShell's own editor range is enforced by the PSReadLine package, and this proof does not cover it.

A module can be refused even though it would work. This can happen when the module imports a name it never calls, when it is unreadable, or, as the main case, when it imports a name from a package module that is not loaded when the hooks go live. Zsh loads a package module when that module's own features are needed, never because another module imports a name from it. A call that needs the provider before it loads ends the shell, so the session is refused by name. A startup file that loads the provider first makes the module bind.

### What the check costs at activation

This check is performed when the hooks are activated, which happens once for each report the integration sends, and the activation builtin can be run again. The check is performed entirely within the shell: no file is opened and no program is run. It involves iterating over the in-memory tables and making at most a couple of lookups to the loader for each undefined name.

Each lookup can run a resolver. When a library defines a name as an indirect function, the loader runs that function to answer, for every such name the check looks up, including names the module never calls. The lookup also takes the loader's lock. Both are the loader's normal work: a module that binds its names at once, or a call that reaches the same name, does the same in the same thread. The C library's own resolvers read data the process already holds, such as the CPU's features and the kernel's vDSO entry points, and the lock is normally free because the shell runs one thread.

The check itself waits on nothing outside the process. It opens no file, starts no process, uses no network and sets no sleep or deadline. A library that ships a resolver that blocks would make the check wait, as it would make the shell wait at any call that reached the same name. The medians below are the cost of the check.

Each number is the median of ten sessions, measured with a timer around the whole check in a real session under the built package. The slowest of the ten sessions is in brackets.

| The shell holds | Apple M4 Pro, macOS 26 | AMD EPYC 7502P, Linux (glibc 2.43) |
| --- | --- | --- |
| only the modules it loaded itself (two on macOS, one on Linux) | 0.22 ms (0.32) | 0.12 ms (0.15) |
| and 1 small module of the person's own | 0.22 ms (0.50) | 0.12 ms (0.15) |
| and 3 | 0.24 ms (0.51) | 0.12 ms (0.18) |
| and 8 | 0.29 ms (0.59) | 0.14 ms (0.17) |
| and 10 of the package's modules, read from another directory | 1.2 ms (1.3) | 0.29 ms (0.36) |
| and about 35 of the package's modules, read from another directory | 1.9 ms (3.2) | 0.49 ms (0.83) |

A `.zshrc` that loads a few modules of its own pays about a quarter of a millisecond on the Mac, at most 0.6 ms in the slowest run measured, and about a tenth of a millisecond on Linux. The last row loads the whole module tree of the package, which amounts to dozens of modules, and stays under four milliseconds.


## Requalifying a package

1. Change the pin in `shells/<shell>/manifest.json` to the fixed upstream release and its digest.
2. `bash scripts/build-shells.sh --<shell> --check-patches`: the patches have to apply to the new
   release with no fuzz. A patch that does not is a patch to rewrite, not one to force.
3. `bash scripts/build-shells.sh --<shell> --require-upstream-tests`: the build fetches the new
   archive, verifies the digest, applies the patches and runs the shell's own suite. The PSReadLine
   package builds no shell and the script takes no option for it: it is requalified by importing
   `shells/psreadline/module` on the host in question and running `Publish-KalaReachQualification`,
   which `scripts/e2e-fence.sh` does as one of its own steps.
4. `bash scripts/fetch-shell-stacks.sh`: the startup customisations, if they are not already here.
5. `bash scripts/e2e-fence.sh`: the whole qualification against the rebuilt package, on a real
   daemon and a real shell.
6. `cargo test -p kr-shell-integration --test module_abi --test relocation -- --include-ignored`, which runs
   the native-module proof and the relocation proof against the rebuilt package.
7. Add a row to the triage record with the date, the change, the packages, the assessment, the
   target release date and the status.

The identity the rebuild writes is a digest of its inputs, so the same pin and the same patches
land in the same place and a rebuild that changed nothing says so.
