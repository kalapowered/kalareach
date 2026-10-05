# Release platforms and baselines

A KalaReach release runs on Windows 11, macOS 14 or later and Linux with glibc 2.35 or later, each
on x86-64 and ARM64, and its companion application runs on iOS and iPadOS 17 and Android 10. Those
are the baselines. `release-baselines.yml` builds the host's executables, which are listed below,
for every one of those desktop targets (the description process is the one exception, below) and
reads each one's own headers for the oldest system it says it runs on. A header states what the
executable declares, and the check holds that to the baseline; starting each executable on the
runner that built it is a separate step. A macOS executable has to declare exactly the baseline; a
Linux or Windows one may need less than its baseline, and never more.

## The baselines

| Platform | Architectures | Oldest supported release | What the executable itself declares |
| --- | --- | --- | --- |
| Windows | x86-64 and ARM64 | Windows 11 | a PE subsystem version no newer than 10.0, which is what Windows 11 reports |
| macOS | Apple Silicon and Intel | macOS 14 | a Mach-O minimum system version of exactly 14.0 |
| Linux | x86-64 and ARM64 | glibc 2.35, the glibc of Ubuntu 22.04 | no glibc symbol version newer than 2.35 |
| iOS and iPadOS | ARM64 | 17 | the companion's bundle configuration, `minimumSystemVersion` 17.0 |
| Android | every architecture the bundle carries | Android 10, API level 29 | the companion's bundle configuration, `minSdkVersion` 29 |

The companion's desktop build declares macOS 14.0 as well, in the same configuration.

A WSL2 distribution uses the Linux build, inside the distribution, like any other Linux host. The
hosted `windows-2025` runner starts WSL2 distributions: `wsl-probe.yml` imports a root file system
as WSL 2 and runs a command in it, and can be run again by hand when the runner image changes. That
runner is a Windows Server, which does not offer mirrored networking, so `wsl-acceptance.yml`
measures NAT there and says that it did. WSL1
and Windows 10 are not release targets: nothing is built for them and nothing is tested on them.
Windows 10 reports the same NT 10.0 as Windows 11, so a Windows executable may well start there, but
that is not a configuration a release is checked against.

## The targets, and where each one is built

Every target has a standard GitHub-hosted runner of its own platform, so each executable is built
natively and then started on the machine that built it. None is only cross-built.

| Target | Built and started on |
| --- | --- |
| `x86_64-unknown-linux-gnu` | `ubuntu-22.04` |
| `aarch64-unknown-linux-gnu` | `ubuntu-22.04-arm` |
| `aarch64-apple-darwin` | `macos-15`; the hosted Apple Silicon runners start at macOS 15 |
| `x86_64-apple-darwin` | `macos-15-intel`; the hosted Intel runners start at macOS 15 |
| `x86_64-pc-windows-msvc` | `windows-2025` |
| `aarch64-pc-windows-msvc` | `windows-11-arm` |

The executables are `kr`, `kr-attach-guard`, `kr-worker`, `kr-controller`, `kr-describe-inference`,
`kr-hook` and `kr-plugin-host`. The names of the programs to include in a release for each target
are defined in `scripts/release-programs.json`. This is the one list that the two release workflows,
the Windows archive check, `kr host install` and `kr host update` read. `release-baselines.yml`
builds each program it names by a Cargo command of its own, as `release-windows.yml` does, so that
the dependencies resolve exactly as they do for the release. The `release-windows.yml` workflow
builds and signs all of these programs for the x86-64 Windows target, and will fail if any of them
are not present in the release archive. Additionally, `kr host update` refuses a release for a macOS
or Linux host whose manifest does not list all seven as programs. This list does not include the
description process for the `aarch64-pc-windows-msvc` target because the CPU backend of llama.cpp
does not build with MSVC there and no model profile lists the target. On x86-64, the description
process requires the host to support the `x86-64-v3` instruction sets (SSE4.2, POPCNT, AVX, AVX2,
BMI1, BMI2, FMA, F16C, LZCNT and MOVBE); see `docs/describe/README.md` for what happens when it
doesn't.

## How each floor is read

`scripts/check-release-floors.py` reads the floor out of the binary rather than trusting the build
settings that were meant to put it there. It needs nothing but Python's standard library, so it runs
on every runner above, and it checks each executable's machine type too, so an executable built for
the other architecture is refused rather than read.

On macOS the floor is the minimum system version in the Mach-O header of every architecture the file
carries. The release builds with `MACOSX_DEPLOYMENT_TARGET=14.0`, which the C compiled into the
executables reads as well, and the check wants exactly 14.0. Lower means the build did not target the
baseline: Rust's own default is 11.0 on Apple Silicon, and an executable built at it claims to run on
three macOS releases nobody tests. Higher means it would refuse to start on macOS 14.

On Linux the floor is the newest glibc symbol version the executable needs, read from its version
requirements. Building on Ubuntu 22.04 keeps it at or below that release's glibc, 2.35. A refusal
names the version it found, and the usual cause is a build on a newer distribution, whose C headers
redirect ordinary calls to newer symbols. glibc's private symbols, and ABI markers the check does not
know, are refused as well.

On Windows the floor is the subsystem version in the PE header, the oldest Windows the image says it
will load on. Windows 11 is NT 10.0, so anything newer is refused.

The check tests itself before it is trusted: it is put through synthetic executables of all three
formats whose floors are known, and on macOS it also builds one program at Rust's default target,
which it must refuse, and one at 14.0, which it must pass.

```sh
python3 scripts/check-release-floors.py self-test
python3 scripts/check-release-floors.py check --target aarch64-apple-darwin \
  target/aarch64-apple-darwin/release/kr target/aarch64-apple-darwin/release/kr-controller
```

## Linux distributions tested

Each Linux executable is started, on x86-64 and on ARM64, in clean images of Ubuntu 22.04, Ubuntu
24.04, Debian 12 and Debian 13, as well as on the Ubuntu 22.04 runner that built it. A clean image
has only its own libraries, so what starts there is the executable against that distribution and
nothing a runner image added. The host's full test suite runs on Ubuntu 24.04 on x86-64, in core-ci.

## When it runs

`.github/workflows/release-baselines.yml` runs the floor check's self-test, builds the executables
for all six targets, reads each floor back, and starts each executable where it was built and, on
the Linux targets, in the four distributions above. On the x86-64 targets it also fails when the
description process's llama.cpp archives hold an AVX-512, AVX-VNNI or AMX instruction; on Windows
the one exception is AVX-512 code that runs only after a test of MSVC's `__isa_available` shows that
the processor has AVX-512. The WSL workflows and core-ci's test suite run separately. It runs every
night and by hand:

```sh
gh workflow run release-baselines.yml --repo kalapowered/kalareach
```

A floor that does not match its baseline fails that target's job, and the job's summary lists every
executable with the floor it declares.
