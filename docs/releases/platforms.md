# Release platforms and baselines

A KalaReach release runs on Windows 11, macOS 14 or later and Linux with glibc 2.35 or later, each
on x86-64 and ARM64, and its companion application runs on iOS and iPadOS 17 and Android 10. Those
are the baselines. Every executable the host ships is built for every one of those desktop targets,
and each one's own headers are read back to confirm it runs on its baseline. A macOS executable has
to declare exactly the baseline; a Linux or Windows one may need less than its baseline, and never
more.

## The baselines

| Platform | Architectures | Oldest supported release | What the executable itself declares |
| --- | --- | --- | --- |
| Windows | x86-64 and ARM64 | Windows 11 | a PE subsystem version no newer than 10.0, which is what Windows 11 reports |
| macOS | Apple Silicon and Intel | macOS 14 | a Mach-O minimum system version of exactly 14.0 |
| Linux | x86-64 and ARM64 | glibc 2.35, the glibc of Ubuntu 22.04 | no glibc symbol version newer than 2.35 |
| iOS and iPadOS | ARM64 | 17 | the companion's bundle configuration, `minimumSystemVersion` 17.0 |
| Android | every architecture the bundle carries | Android 10, API level 29 | the companion's bundle configuration, `minSdkVersion` 29 |

The companion's desktop build declares macOS 14.0 as well, in the same configuration.

A WSL2 distribution uses the Linux build, inside the distribution, like any other Linux host. WSL1
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
| `aarch64-apple-darwin` | `macos-14`, the baseline itself |
| `x86_64-apple-darwin` | `macos-15-intel`; the hosted Intel runners start at macOS 15 |
| `x86_64-pc-windows-msvc` | `windows-2025` |
| `aarch64-pc-windows-msvc` | `windows-11-arm` |

The executables are `kr`, `kr-attach-guard`, `kr-worker`, `kr-controller`, `kr-hook` and
`kr-plugin-host`. Each one is built by a Cargo command of its own, as the Windows release builds
them, so its dependencies resolve exactly as they do for the release.

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

`.github/workflows/release-baselines.yml` does all of the above for all six targets. It runs every
night and by hand:

```sh
gh workflow run release-baselines.yml --repo kalapowered/kalareach
```

A floor that does not match its baseline fails that target's job, and the job's summary lists every
executable with the floor it declares.
