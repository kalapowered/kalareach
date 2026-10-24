# Upstream sources, security triage and the update target

Every managed shell package is one upstream release, pinned by URL and SHA-256, plus KalaReach's
own patch set. This page is the register of those sources, the record of what has been triaged
against them, and the update target each package is published under.

Upstream is never vendored: `scripts/place-shell-sources.sh` fetches the pinned archive,
`scripts/build-shells.sh` checks its digest and applies the ordered patches in `shells/<shell>/patches`. The pins live in
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
| fish | fish-shell | fish-4.9.3 | https://github.com/fish-shell/fish-shell/releases/download/4.9.3/fish-4.9.3.tar.xz | 20998a25f73217ddcc19f499055fd587e9912d1ad6e7109120fbcf2871f0b98c | the fish-shell repository's security advisories and its release notes, RustSec advisories published from 2026-09-20 against the crates and repositories in fish's `Cargo.lock`, and, where the build compiles or links PCRE2, PCRE2's own advisories published from that day |
| psreadline | PSReadLine | psreadline-2.3.4 to 3.0.0 on PowerShell 7.4 or later, except a release below the fixed release of an advisory in the triage record (CVE-2026-62801: 7.4.20, 7.5.11 and 7.6.6), or on Linux and macOS a host on a .NET runtime below the fixed runtime of CVE-2026-96225 (8.0.32, 9.0.21, 10.0.13 and 11.0.0-rc.2, which PowerShell 7.4.21, 7.5.12 and 7.6.7 carry) | https://github.com/PowerShell/PowerShell | qualified rather than fetched | PowerShell/Announcements, and the PSReadLine and PowerShell repositories' security advisories |
<!-- /kr:pins -->

The PSReadLine package rebuilds no shell. What it pins is the range of the editor it was qualified
against, and the identity it publishes records the editor it found on the machine it qualified. A
security update to PowerShell or to PSReadLine is therefore a requalification rather than a rebuild,
and the same triage applies to it.

The module holds the advisories against PowerShell itself, or against the .NET runtime it runs on, that it refuses to
run under, each with the first fixed release of every series it lists, and the package manifest holds the same list.
An advisory against the runtime is judged by the runtime the host reports, on the platforms the advisory lists. A release of a listed
series below that, a pre-release of the fixed release included, is refused with a diagnostic that names the
advisory and the first fixed release. A series an advisory does not list is judged by that advisory's own
ranges, and the module does not refuse it, so a preview of a newer series is not refused here.

That range is a statement about the editor this integration works with, not about which releases
inside it carry which fixes. A person runs the host their machine has, so an advisory against
PowerShell or PSReadLine is triaged against the versions it names and against the identity the
qualification recorded, and it gets a row of its own below.

## The crates and repositories the fish build uses

The fish package is built from Rust, and its release names more than its own archive. Its `Cargo.lock` file, included in its archive, lists the crates it takes from crates.io, each with a checksum. It also includes 3 git repositories at a locked revision: `fluent-rs` and `rust-pcre2` from github.com, and `fluent-ftl-tools` from codeberg.org. Cargo downloads none of them. Instead, the crates and a git bundle of each of the repositories are placed in the sources cache beside the archive by `scripts/place-shell-sources.sh`. Then, when building, `scripts/build-shells.sh` first checks each of them against its pin before cargo sees it: the lock's checksum pins a crate, and the `cargo.git` list in `shells/fish/manifest.json` pins a repository. The latter pins the locked revision for each repository and also the digest of the files within the repository at that revision. This means that cargo reaches no server, and if the lock names a git repository that the manifest does not pin, or a source of any other kind, the build will stop with an error naming it. (These pins are not rows of the register above, because they change with the fish release.) An advisory published from 2026-09-20 against any of these crates or repositories, or against the PCRE2 the build compiles, affects the fish package and gets a triage row with the same target as an advisory against fish itself. The package builds the PCRE2 that comes with its Rust bindings (10.43, built without JIT) and links no PCRE2 of the machine that builds it. The triage record starts on that day, and an advisory published before it gets a row only when its affected range includes what the package pins: fish itself, that PCRE2, and every crate in the lock, which the audit of the lock reports whatever the advisory's date.

If the lock file changes with a new release of fish, running `bash scripts/build-shells.sh --fish --check-sources` will name the first repository it now depends on that is not pinned in the manifest, and it stops there, so run it again after each fix. A pin that the new lock no longer uses is refused too, and has to be removed. Add a pin to the manifest for a new repository with a digest of 64 zeros, then run `bash scripts/place-shell-sources.sh --fish` to get its git bundle. Then re-run the check and it will refuse the repository because the digest is wrong, but this time it will print the digest of the files it found, which is the value to pin.

## What reads this register

`.github/workflows/shell-advisories.yml` runs `scripts/check-shell-advisories.py` once a day and on
demand, and fails when something an upstream published has no row below. It reads, from public
sources only, the security advisories of the fish, PowerShell, PSReadLine and PCRE2 repositories;
the issues of PowerShell/Announcements that carry the Security label, or whose title says they
are a security advisory or names a CVE and that a member of the organisation opened, where
Microsoft publishes the advisories that reach PowerShell, the ones against .NET included (not
every one carries the label, and anyone can open an issue); the stable releases of fish and PowerShell
that are newer than what the packages pin, the tags of zsh, and the releases of bash together with
the patches of the pinned series and the newest patch of each newer series, which are the only
signal zsh and bash give; and a cargo-audit report of fish's lock. That report matches the crates
the lock takes from crates.io. The crates it takes from git (`pcre2` and `pcre2-sys`, the `fluent`
crates, `intl-memoizer` and `gettext-po-file-parser`) have no RustSec source to match, so no
advisory against one of them is reported by it; PCRE2 itself is watched through its own
repository's advisories.

A change needs a row when it was first published on or after 2026-09-20, or when its affected
range includes what a package pins. The newest row that names the package and the change by its
identifier (a CVE, a GHSA, a RustSec identifier, a release tag, a patch name) is the assessment
that stands, and the rows before it are the record of what was thought earlier. It covers the
change when it has a status defined below, is not `scheduled` past its target, quotes every
affected range the source gives, as the source gives it, and is dated on or after the day the
source last revised the change; a revision therefore needs a newer row. A GitHub advisory
reports its own revision date. An issue of PowerShell/Announcements is revised when its body
dates a revision (the revision list and the "Last Updated" line Microsoft writes), and a comment
on it revises nothing; an edit that Microsoft does not date is not seen. A change with no row
passes for one working day after it was published or last revised and fails after, except that a
RustSec advisory has no such allowance, because the report carries no date on which it reached the
database. Each row after the first day names the date the upstream released the change after the
word `released`, and its target is at most the number of days the update target allows after that
date, so a late assessment cannot move its own deadline. A row for a RustSec advisory against
fish's lock carries no release date.

PowerShell previews are judged by each advisory's own ranges: the module refuses a pre-release of
a series the advisory lists when it is below that series' first fixed release, and a series the
advisory does not list is not refused by it.

## The update target this publishes

<!-- kr:target -->
A security-relevant upstream change is triaged within one working day of the advisory. A package
that the change affects is rebuilt against the fixed upstream release, requalified against the
whole corpus under `tests/shells/`, and published within fourteen days of that release. No binary
is distributed before its requalification passes, and no package is swapped into a session that is
already running: a session keeps the package identity it started with until it ends.
<!-- /kr:target -->

The requalification has parts, and each runs where it can. The patches, the shells' own suites
(`--require-upstream-tests`) and the fence run of `scripts/e2e-fence.sh` on a real daemon are run
by hand when a pin changes. The core workflow's `shell-packages` job runs, on x86-64 Linux, the
contract suites of the packages, the startup customisations, the second Zsh build and the
PowerShell package. Before a release tree is assembled, each of its four targets builds the Zsh,
Bash and Fish packages natively and runs the contract suites of the three, the Fish source checks,
the native-module proof of Zsh and the case that compares each package with its pin, against the
packages it just built; a failing suite stops the tree before anything is assembled or signed.
The Developer ID signature is put on the programs after that. The PowerShell package is not part
of a release tree, and the startup customisations are pinned for two of the four targets, so the
whole corpus does not run on the other two.

## A package that cannot meet its target

The flag is a row of this register: no host, CLI or companion code reads it, and none of them tells a person that a package is past its target. A package whose fourteen days pass without a requalified build is flagged in the triage record
below, and the flag names the choices rather than leaving a stale package as a silent default. The
choices are:

* **Keep the pinned package.** The managed contract stays, the flag stays visible, and the session
  says which package it is running.
* **Run that shell in `native_compat`.** The lifecycle and the transfers stay; the managed
  empty-prompt Ctrl-D and the fenced launch do not, because an unqualified system shell cannot
  claim either.
* **Run a different managed shell.** The other packages are unaffected by one upstream's delay.

The first is what a session does when the person selects nothing; the other two are selected by the person, and nothing falls back to either on its own.

## Triage record

`assessment` says what the change is and whether the pinned release already carries it.
`Date` is the day the assessment was made. The first assessments (2026-09-20) were made when this register was started, so they count their target from that day and say nothing about when the upstream advisory was published or fixed. `status` is one of `released` (a requalified package is published, and the assessment names the
identity it was published under), `scheduled` (inside its target date), `flagged` (past its target
date, with the choices above) or `not-affected`.

<!-- kr:triage -->
| Date | Upstream change | Packages | Assessment | Target release | Status |
| --- | --- | --- | --- | --- | --- |
| 2026-09-20 | CVE-2021-45444, prompt expansion in zsh before 5.8.1 | zsh | The pinned release is 5.9, which is after the fix. Nothing to rebuild. | 2026-10-04 | not-affected |
| 2026-09-20 | The official GNU Bash 5.2 patch series, 001 to 037 | bash | The pinned release is 5.2.37, which carries every patch published for 5.2 at the time of this pin. | 2026-10-04 | not-affected |
| 2026-09-20 | The fish-shell advisories published against 4.x | fish | The pinned release is 4.9.3, which is the newest 4.x release at the time of this pin and carries every advisory fix published for the series. | 2026-10-04 | not-affected |
| 2026-09-20 | The editor identity this package was qualified against | psreadline | This package was qualified against PSReadLine 2.4.5 on PowerShell 7.6.6, which is the identity its record names. The range it declares says which editor the integration works with and not which releases inside it carry which fixes, so an advisory against either project is triaged against the versions that advisory names and gets its own row. | 2026-10-04 | not-affected |
| 2026-09-20 | CVE-2026-62801, PowerShell, published at github.com/PowerShell/Announcements/issues/98; fixed in 7.4.20, 7.5.11 and 7.6.6 | psreadline | The host this package was qualified against is 7.6.6, which is the fixed release of its own series, so the qualified identity carries the fix. A person on an earlier 7.4, 7.5 or 7.6 release is on an affected host and updates it; this package qualifies the editor against the host the person runs and does not ship one, and the module refuses to bind into a release below 7.4.20, 7.5.11 or 7.6.6, naming this advisory and the first fixed release. | 2026-10-04 | not-affected |
| 2026-10-24 | CVE-2026-40400, PowerShell, published at github.com/PowerShell/Announcements/issues/99; fixed in 7.4.18, 7.5.11 and 7.6.6; Windows only; released 2026-09-11 | psreadline | The module's bound for CVE-2026-62801 (7.4.20, 7.5.11 and 7.6.6) is at or above every first fixed release of this advisory, so a host this advisory affects is refused. This assessment was made after the one working day the target allows. | 2026-09-25 | not-affected |
| 2026-10-24 | CVE-2026-69806, a .NET vulnerability in PowerShell, published at github.com/PowerShell/Announcements/issues/101 and updated on 2026-09-23; fixed in 7.5.11 and 7.6.6; Linux only, and 7.4 is not affected; released 2026-09-11 | psreadline | The module's bound for CVE-2026-62801 is at or above the first fixed release of both affected series, so a host this advisory affects is refused. This assessment was made after the one working day the target allows. | 2026-09-25 | not-affected |
| 2026-10-24 | CVE-2026-96225, a .NET vulnerability in Microsoft.NETCore.App.Runtime and System.Private.CoreLib, published at github.com/dotnet/announcements/issues/476; Unix named mutexes and shared memory; Linux and macOS only; affected `>= 8.0.0, <= 8.0.31`, `>= 9.0.0, <= 9.0.20`, `>= 10.0.0, <= 10.0.12` and `>= 11.0.0-preview.1, <= 11.0.0-rc.1`, fixed in 8.0.32, 9.0.21, 10.0.13 and 11.0.0-rc.2; released 2026-10-13 | psreadline | PSReadLine creates a named mutex for its history file in every interactive host, and on Linux and macOS .NET keeps it in the shared directory `/tmp/.dotnet/shm` that the advisory describes. A trace of PowerShell 7.6.6 on .NET 10.0.12 and of 7.6.7 on 10.0.13 on Linux shows the same calls in both (the session directory made with mode 0777, the mutex file with mode 0666): it shows that the host uses the component, and the fix is in the runtime, where the advisory puts it. There is no trace on macOS. A host on a listed runtime reaches the advisory with no command from the person, so PowerShell 7.4.20, 7.5.11 and 7.6.6, which carry .NET 8.0.31, 9.0.20 and 10.0.12, are in range, and so are a 7.7 preview on .NET 11.0.0-rc.1 and a framework-dependent host on an old shared runtime. The module refuses a host on Linux or macOS whose runtime is below the fixed one, whatever its PowerShell release, naming this advisory. A host on Windows is not affected by this advisory and is not refused for it. See "The .NET servicing of 2026-10-13". This assessment was made after the one working day the target allows. | 2026-10-27 | not-affected |
| 2026-10-24 | CVE-2026-96231, a .NET vulnerability in Microsoft.NETCore.App.Runtime and System.Private.CoreLib, published at github.com/dotnet/announcements/issues/479; Unix named mutexes and shared memory; Linux and macOS only; affected `>= 8.0.0, <= 8.0.31`, `>= 9.0.0, <= 9.0.20`, `>= 10.0.0, <= 10.0.12` and `>= 11.0.0-preview.1, <= 11.0.0-rc.1`, fixed in 8.0.32, 9.0.21, 10.0.13 and 11.0.0-rc.2; released 2026-10-13 | psreadline | The advisory gives the same summary, platforms, affected ranges and fixed runtimes as CVE-2026-96225, and has its own discussion at dotnet/runtime/issues/135707. The module's runtime bound for CVE-2026-96225 is the first fixed runtime of every series the advisory lists, on both platforms it lists, so a host this advisory affects is refused. This assessment was made after the one working day the target allows. | 2026-10-27 | not-affected |
| 2026-10-24 | PowerShell v7.4.21, a release of the 7.4 series with .NET SDK 8.0.426 and the .NET 8.0.32 runtime; released 2026-10-13 | psreadline | The release is the first of the series on the runtime that fixes CVE-2026-96225 and CVE-2026-96231, and carries System.Security.Cryptography.Pkcs 8.0.2 and System.Security.Cryptography.Xml 8.0.5, so its runtime pack and both packages are at the fixed versions the advisories of the servicing of 2026-10-13 name. Its notes list a session restriction check in Show-Command and a tolerant read of the per-user configuration file, and its commits hold six more changes that no note or advisory calls security fixes, none of which is a command the bridge or PSReadLine calls, and the two language-mode changes concern constrained language mode. The release carries a runtime at or above the fixed one, so the module accepts it on every platform, and the releases of the series before it, which carry an affected runtime, are refused on Linux and macOS. See "The .NET servicing of 2026-10-13". This assessment was made after the one working day the target allows. | 2026-10-27 | not-affected |
| 2026-10-24 | PowerShell v7.5.12, a release of the 7.5 series with .NET SDK 9.0.319 and the .NET 9.0.21 runtime; released 2026-10-13 | psreadline | The release is the first of the series on the runtime that fixes CVE-2026-96225 and CVE-2026-96231, and carries System.Security.Cryptography.Pkcs and System.Security.Cryptography.Xml 9.0.21, so its runtime pack and both packages are at the fixed versions the advisories of the servicing of 2026-10-13 name. Its notes list a session restriction check in Show-Command and a tolerant read of the per-user configuration file, and its commits hold six more changes that no note or advisory calls security fixes, none of which is a command the bridge or PSReadLine calls, and the two language-mode changes concern constrained language mode. The release carries a runtime at or above the fixed one, so the module accepts it on every platform, and the releases of the series before it, which carry an affected runtime, are refused on Linux and macOS. See "The .NET servicing of 2026-10-13". This assessment was made after the one working day the target allows. | 2026-10-27 | not-affected |
| 2026-10-24 | PowerShell v7.6.7, a release of the 7.6 series with .NET SDK 10.0.402 and the .NET 10.0.13 runtime; released 2026-10-13 | psreadline | The release is the first of the series on the runtime that fixes CVE-2026-96225 and CVE-2026-96231. On Linux and macOS its archive still carries System.Security.Cryptography.Pkcs and System.Security.Cryptography.Xml at the 10.0.10 build, and the Windows archive carries them at 10.0.13; advisories 468 and 488 to 490 list that build, neither the bridge nor PSReadLine reaches them, and 7.6.8 carries 10.0.13 on every platform. The package is qualified on this release. Its notes list a session restriction check in Show-Command, a tolerant read of the per-user configuration file and three cmdlet fixes, and its commits hold six more changes that no note or advisory calls security fixes, none of which is a command the bridge or PSReadLine calls, and the two language-mode changes concern constrained language mode. The release carries a runtime at or above the fixed one, so the module accepts it on every platform, and the releases of the series before it, which carry an affected runtime, are refused on Linux and macOS. See "The .NET servicing of 2026-10-13". This assessment was made after the one working day the target allows. | 2026-10-27 | not-affected |
| 2026-10-24 | PowerShell v7.6.8, a release of the 7.6 series with .NET SDK 10.0.402 and the .NET 10.0.13 runtime; released 2026-10-22 | psreadline | The release removes the update notification and carries System.Security.Cryptography.Pkcs and System.Security.Cryptography.Xml at 10.0.13 on every platform, which 7.6.7 carries at 10.0.10 on Linux and macOS. It changes nothing the bridge or PSReadLine runs. The module accepts it. | 2026-11-05 | not-affected |
| 2026-10-24 | zsh-5.9.1, the first release after the pinned 5.9; released 2026-05-31 | zsh | Between zsh-5.9 and zsh-5.9.2 upstream fixed memory errors that no advisory names, among them a use after free when TRAPEXIT runs (54479), a heredoc buffer size that could overflow (54538), an overflow check in the command lookup (54595), a signed buffer size in the path lookup (54596), a buffer overwritten in the completion list (54601), a heap corruption when rotating lines (44874) and an unterminated line buffer (54483). The pinned 5.9 carries none of them. A change to the pin re-bases the package's ZLE patches on the new release and requalifies it, which this record does not do, so the package is flagged: keep the pinned package until the pin moves. This assessment was made after the one working day the target allows. | 2026-06-14 | flagged |
| 2026-10-24 | zsh-5.9.2, the newest release; released 2026-07-12 | zsh | zsh-5.9.2 carries every fix listed for zsh-5.9.1 and the later ones, and its NEWS lists new features (the kill options, the _as_if completion helper) and no security fix. The pinned 5.9 carries none of the fixes; see the row for zsh-5.9.1. The package is flagged: keep the pinned package until the pin moves to a release that carries them. This assessment was made after the one working day the target allows. | 2026-07-26 | flagged |
| 2026-10-24 | bash-5.3, the series after the pinned 5.2, and its patches bash53-001 to bash53-020; the first patches are dated 2025-07-23 and the tarball 2025-07-30; released 2025-07-05 | bash | The 5.2 series has no patch after 5.2.37, which is pinned. Of the twenty patches to 5.3, eight apply to the sources of 5.2.37 apart from the version line: a use after free when a mapfile callback unsets its array (011), an exit trap run in a subshell that received a fatal signal (012), an index of -1 into the read builtin's buffer (015), a glob range (006) and display, job and portability fixes (010, 018, 019, 020). The others change code that 5.2.37 does not have. Upstream will not patch 5.2, and no advisory names any of them. A defect that a command triggers in the shell gives the command nothing it does not have, but moving the pin to 5.3 is a requalification of its own that this record does not do, so the package is flagged: keep the pinned package until the pin moves. This assessment was made after the one working day the target allows. | 2025-07-19 | flagged |
| 2026-10-24 | PCRE2 CVE-2026-103111 (GHSA-r9hj-j2rw-4q3m), an out-of-bounds write in JIT matching with a growable stack, affected `<=10.48`, fixed in 10.49; released 2026-09-28 | fish | The advisory affects only JIT matching with a growable JIT stack, and the bundled PCRE2 is built without JIT (the bindings' jit feature is off), so it does not apply. The fish package now builds the PCRE2 bundled with its Rust bindings (10.43, built without JIT), uses only its 32-bit library, and its executable depends on no PCRE2 library of the machine that built it. Before this, the release trees linked the PCRE2 of the build machine (libpcre2-32.so.0 on Linux and Homebrew's libraries on macOS), which this record did not track, and a Mac without that library could not start the shell. This assessment was made after the one working day the target allows. | 2026-10-12 | not-affected |
| 2026-10-24 | PCRE2 CVE-2026-89156 (GHSA-2p8c-ff85-vh9x), an out-of-bounds read after a JIT fallback with invalid UTF, affected `<= 10.47`, fixed in 10.48; released 2026-08-31 | fish | The advisory affects the 8-bit library through JIT and Unicode matching, and fish uses only the 32-bit library of a PCRE2 built without JIT, so it does not apply. The fish package now builds the PCRE2 bundled with its Rust bindings (10.43, built without JIT), uses only its 32-bit library, and its executable depends on no PCRE2 library of the machine that built it. This assessment was made after the one working day the target allows. | 2026-09-14 | not-affected |
| 2026-10-24 | PCRE2 CVE-2026-86145 (GHSA-3r4p-g7gg-ppmf), an out-of-bounds write in pcre2_dfa_match() with recursive patterns, affected `>= 10.32, <= 10.47`, fixed in 10.48; released 2026-08-31 | fish | The advisory affects pcre2_dfa_match() only, which fish never calls: it uses the pcre2 crate's Regex, which compiles with pcre2_compile and matches with pcre2_match. The fish package now builds the PCRE2 bundled with its Rust bindings (10.43, built without JIT), uses only its 32-bit library, and its executable depends on no PCRE2 library of the machine that built it. This assessment was made after the one working day the target allows. | 2026-09-14 | not-affected |
| 2026-10-24 | PCRE2 CVE-2026-89157 (GHSA-q8g2-wprr-34m9), an out-of-bounds write in pcre2_pattern_convert() on 32-bit systems, affected `>= 10.30, <= 10.47`, fixed in 10.48; released 2026-08-31 | fish | The advisory affects pcre2_pattern_convert() on systems with a 32-bit size_t. Fish never calls it, and every target the package ships for is 64-bit. The fish package now builds the PCRE2 bundled with its Rust bindings (10.43, built without JIT), uses only its 32-bit library, and its executable depends on no PCRE2 library of the machine that built it. This assessment was made after the one working day the target allows. | 2026-09-14 | not-affected |
| 2026-10-24 | PCRE2 CVE-2026-89160 (GHSA-9qww-pwc4-77qq), out-of-bounds reads with PCRE2_MATCH_INVALID_UTF, affected `>= 10.34, <= 10.47`, fixed in 10.48; released 2026-08-31 | fish | The advisory affects the 8-bit and 16-bit libraries and says the 32-bit library is unaffected, which is the one fish links. The fish package now builds the PCRE2 bundled with its Rust bindings (10.43, built without JIT), uses only its 32-bit library, and its executable depends on no PCRE2 library of the machine that built it. This assessment was made after the one working day the target allows. | 2026-09-14 | not-affected |
| 2026-10-24 | PCRE2 CVE-2026-89158 (GHSA-fmgr-6ggq-9859), an integer overflow in pcre2_compile_32() on 32-bit systems, affected `<= 10.47`, fixed in 10.48; released 2026-08-31 | fish | The advisory affects the 32-bit library in a process with a 32-bit size_t, and every target the package ships for is 64-bit. The fish package now builds the PCRE2 bundled with its Rust bindings (10.43, built without JIT), uses only its 32-bit library, and its executable depends on no PCRE2 library of the machine that built it. This assessment was made after the one working day the target allows. | 2026-09-14 | not-affected |
| 2026-10-24 | PCRE2 GHSA-43gg-c3xx-7w7g, an out-of-bounds read in JIT-compiled matching on AArch64, affected `< 10.47`, fixed in 10.47; released 2025-10-24 | fish | The advisory affects JIT-compiled matching, and the bundled PCRE2 is built without JIT. The fish package now builds the PCRE2 bundled with its Rust bindings (10.43, built without JIT), uses only its 32-bit library, and its executable depends on no PCRE2 library of the machine that built it. This assessment was made after the one working day the target allows. | 2025-11-07 | not-affected |
| 2026-10-24 | RUSTSEC-2026-0204, crossbeam-epoch 0.9.18 in fish 4.9.3's Cargo.lock, an invalid pointer dereference in the fmt::Pointer impl of its Atomic and Shared pointers (Debug is not affected), fixed in 0.9.20 | fish | The crate is reached only through ignore, a dependency of the workspace member xtask, which is the fish tree's own development tool; it is in no dependency graph of the shipped fish. Checked with cargo tree over the lock with the features the package ships (--no-default-features --features localize-messages, normal and build edges) for the four release targets. | 2026-11-07 | not-affected |
| 2026-10-24 | RUSTSEC-2024-0436, paste 1.0.15 in fish 4.9.3's Cargo.lock, unmaintained | fish | The notice reports that the crate is no longer maintained and no defect. It is a procedural macro reached through macro_rules_attribute, so it runs while fish is compiled and none of its code is in the executable. Checked with cargo tree over the lock with the features the package ships (--no-default-features --features localize-messages, normal and build edges) for the four release targets. | 2026-11-07 | not-affected |
| 2026-10-24 | RUSTSEC-2026-0190, anyhow 1.0.102 in fish 4.9.3's Cargo.lock, unsound Error::downcast_mut() | fish | The crate is reached through the WASI bindings of getrandom, the Fluent tooling used for checks and extraction, the PO file parser and xtask; it is in no dependency graph of the shipped fish. Checked with cargo tree over the lock with the features the package ships (--no-default-features --features localize-messages, normal and build edges) for the four release targets. | 2026-11-07 | not-affected |
| 2026-10-24 | RUSTSEC-2026-0253, lru 0.18.0 in fish 4.9.3's Cargo.lock, a use after free if a key's Drop panics inside LruCache::pop(), fixed in 0.18.2 | fish | The crate is a direct dependency of fish and its pop is called (wait_handle.rs, autoload.rs), with process identifiers and wide strings as keys. Neither type has a Drop that can panic, and the defect needs one to panic inside pop, so the advisory does not apply. Checked with cargo tree over the lock with the features the package ships (--no-default-features --features localize-messages, normal and build edges) for the four release targets. | 2026-11-07 | not-affected |
| 2026-10-24 | RUSTSEC-2026-0205, scc 2.4.0 in fish 4.9.3's Cargo.lock, unsound if the compare function of Array::insert panics | fish | The crate is reached only through serial_test, a development dependency used by fish's own tests; it is in no dependency graph of the shipped fish. Checked with cargo tree over the lock with the features the package ships (--no-default-features --features localize-messages, normal and build edges) for the four release targets. | 2026-11-07 | not-affected |
<!-- /kr:triage -->

## The .NET servicing of 2026-10-13

On 2026-10-13 the .NET team published 46 advisories (dotnet/announcements issues 445 to 490) and fixed them in .NET 8.0.32, 9.0.21 and 10.0.13. PowerShell 7.4.21, 7.5.12 and 7.6.7 were released the same day on those runtimes. PowerShell/Announcements names no PowerShell advisory for them as of 2026-10-24, so this account is the register's own. A PowerShell archive is self-contained and carries the runtime it was built with, so a release below those three carries a runtime in the range of each advisory that lists .NET 8, 9 or 10; a framework-dependent host and a preview run on the runtime they find, and the module judges the runtime.

Each advisory is judged by two questions: whether a PowerShell package carries the component it names, and whether the bridge, or the editor it binds into, uses that component without a command from the person. The first was read from the Linux x64, macOS arm64 and Windows x64 archives of 7.4.20 to 7.6.8, each checked against the digest its release notes publish: the runtime packs and packages in `pwsh.deps.json`, the file listing and the file versions of the assemblies. The second was read from the bridge's source and from a system-call trace of an interactive PowerShell on Linux.

| Advisories (CVE-2026-) | Component | Carried by a PowerShell package | Reached by the bridge's host |
| --- | --- | --- | --- |
| 13: 102870, 70159, 70175, 70179, 70181, 70183, 70186, 70188, 70196, 88092, 92707, 96230, 96236 (issues 445, 452, 457 to 462, 465, 472, 473, 478, 484) | ASP.NET Core, Blazor, SignalR and Kestrel | No: no archive holds an `AspNetCore` assembly | No |
| 6: 70161, 70165, 70190, 96237, 96238, 96957 (issues 453, 455, 463, 485 to 487) | The .NET SDK: workloads, templates and file-based apps | No: the SDK builds PowerShell and is in no archive | No |
| 1: 70194 (issue 464) | TLS post-handshake client authentication, .NET 11 only | Only by a release built on .NET 11 before 11.0.0-rc.2; the 7.4 to 7.6 series run .NET 8 to 10 | No |
| 2: 96225, 96231 (issues 476, 479) | Unix named mutexes and shared memory, in `System.Private.CoreLib` | Yes: the runtime of every archive, on Linux and macOS | Yes. PSReadLine creates a named mutex for its history file in every interactive host. A trace of PowerShell 7.6.6 on .NET 10.0.12 shows `/tmp/.dotnet/shm/session<N>` made with mode 0777 and `PSReadLineHistoryFile_<hash>` made with mode 0666 in the shared directory the advisories describe, and a trace of 7.6.7 on 10.0.13 shows the same calls: the traces show the use of the component, and the fix is in the runtime |
| 11: 70007, 70035, 70174, 83520, 85363, 87697, 96224, 96229, 96232, 96234, 96235 (issues 450, 451, 456, 467, 469, 471, 475, 477, 480, 482, 483) | WPF, in the WindowsDesktop runtime | Windows archives only: `PresentationCore`, `wpfgfx_cor3` and the others, for the Out-GridView and Show-Command windows (`Microsoft.PowerShell.GraphicalHost`) | No: the bridge opens neither window, and the flaws need XAML, XPS, pixel-shader or font content that a script loads itself |
| 2: 105016, 85790 (issues 446, 470) | MsQuic | Windows archives only: `msquic.dll` 2.5.10.0 below the first fixed releases and 2.5.11.0 at them and in 7.6.8, loaded by `System.Net.Quic`; advisory 470 lists `< 2.5.12`, which includes both, and advisory 446 lists only 2.5.11-ci.156755675 | No: neither the bridge nor the editor uses QUIC, and a PowerShell host opens no QUIC listener of its own |
| 6: 58280, 69651 (issues 447, 449) and 96222, 96958, 96959, 96960 (issues 474, 488 to 490) | Signed XML: `System.Private.Xml` in the runtime and the `System.Security.Cryptography.Xml` package | Yes. The package is at 8.0.4 in 7.4.20 and 8.0.5 in 7.4.21, at 9.0.20 in 7.5.11 and 9.0.21 in 7.5.12, and in the 7.6 series at 10.0.10 in 7.6.6 and 7.6.7 on Linux and macOS, at 10.0.12 and 10.0.13 in 7.6.6 and 7.6.7 on Windows, and at 10.0.13 in 7.6.8 everywhere | No: only code that signs, verifies or decrypts XML reaches it, and neither the bridge nor the editor does |
| 2: 70162, 84008 (issues 454, 468) | CMS and PKCS#7: the `System.Security.Cryptography.Pkcs` package | Yes: 8.0.1 in 7.4.20 and 8.0.2 in 7.4.21, 9.0.20 and 9.0.21, and in the 7.6 series as the Xml package (advisory 454 lists Windows only) | No: only code that decodes or verifies CMS data reaches it, and neither the bridge nor the editor does |
| 1: 66822 (issue 448) | `System.Net.Http`: a proxy credential kept across a redirect | Yes: the runtime | No: the bridge makes no HTTP request, and a script's own request through a proxy with basic credentials, across a redirect, is the exposure |
| 1: 70197 (issue 466) | `System.Net.Sockets`: datagram sockets on Windows | Yes: the runtime | No: the bridge uses a named pipe on Windows and a Unix stream socket elsewhere |
| 1: 96233 (issue 481) | `System.Private.CoreLib`: parsing a date under a Hebrew calendar | Yes: the runtime | No: the bridge formats time and parses no date, and a script that parses untrusted text under a Hebrew calendar culture is the exposure |

The two advisories that reach the bridge's host set the module's runtime bound, on Linux and macOS: .NET 8.0.32, 9.0.21, 10.0.13 and 11.0.0-rc.2, which PowerShell 7.4.21, 7.5.12 and 7.6.7 are the first releases of their series to carry. The advisories marked "No" do not move it; whether a person's own scripts reach the components they name is theirs to judge. A release at the bound is still not free of them on every platform: 7.6.7 carries the Pkcs and Xml packages at the 10.0.10 build on Linux and macOS, and 7.6.8 carries them at 10.0.13.

The commits of 7.4.21, 7.5.12 and 7.6.7 also hold six changes that the release notes do not list and no advisory names: language-mode checks on property sets (`PSSetMemberBinder` and the `ForEach` method), a shadowing bypass through an alias in `Import-PSSession` and `Export-PSSession`, a wildcard Hyper-V socket binding, the module-name limit and error handling of the cabinet extraction in Update-Help, and a fetch of external `$ref` schemas by `Test-Json`. None is a command the bridge or PSReadLine calls, and the two language-mode changes concern constrained language mode. The notes of all three releases also list an update of `Microsoft.PowerShell.Native` (700.0.2), which every Unix host loads and no advisory names. When PowerShell/Announcements names an advisory for them, the check asks for a row.

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

The fish patch `0004-fish-command-resolve` patches the `exec_external_command` function in
`src/exec.rs`, the closure that runs the body of a block process in the same file, which counts that body as
not being a second line, as well as the interactive loop in `src/reader/reader.rs`. To check if the patch still
applies after moving to a new release of fish, run
`bash scripts/build-shells.sh --fish --check-patches`. To check if it still asks, run the test case
named `a_real_package_asks_the_real_worker_before_each_command_and_runs_a_bypass_as_typed` in
`crates/kr-worker/tests/fence.rs`, specifically the part under the case fish.

The identity the rebuild writes is a digest of its inputs, so the same pin and the same patches
land in the same place and a rebuild that changed nothing says so.
