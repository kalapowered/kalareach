# Desktops, logout and sleep, per platform

A session's terminal and its processes are different things. `kr new --invisible` decides whether
you see a window; the execution profile decides which desktop the commands inside the session can
reach. This page is the per-platform half of that: how each platform names a graphical login, what
it does to a session when that login ends, and what each one lets the host do about sleep.

## What identifies a desktop

Four things, together: the operating-system user, the platform's own login-session identifier, the
boot the host is running, and the login-session generation. Any of them changing is a different
desktop. The generation is there for a reason: Linux and Windows both reuse a login-session
number, so the number alone would say a session created in one login belongs to the next one to get
that number.

Every platform has one process that owns its login session, and its kernel start value is the
generation. A new login is a new process, so the two logins are told apart even when the platform
hands out the same number.

| | macOS | Linux | Windows |
| --- | --- | --- | --- |
| The login session | the Aqua security session behind the user's graphical launchd domain | the login manager's session for the user's graphical login | the interactive logon session |
| Read through | `launchctl print gui/<uid>`, whose handle is the security session and whose creator is the process below | `loginctl show-session`, for the session the login manager reports as the user's display | the task listing, for the session the worker's own process runs in |
| The owning process | `loginwindow` | the session leader | that session's `winlogon` |
| Also reported | whether the domain is the graphical one | the session type (X11 or Wayland), its desktop environment, its state and its locked hint | whether the session is a remote desktop one |
| Not read | the screen's lock state: macOS does not publish one this host can read without involving the person at the machine, so a locked Aqua session reads as present, which is the answer a bound session needs: its session and its processes keep running | | container membership |

A session records that identity when it is created, and `kr status` prints it. A worker asks one
question afterwards, on every wake of its supervision: is the process that owns my login session
still running, with the same start value? That is one kernel query, which is what lets it be asked
that often.

## What logout does

`desktop_bound` promises persistence through losing every attachment and through the control daemon
restarting. It does not promise persistence through logout, and it never rebinds: when the login
session ends, the session closes with `desktop_lost` and you create a new one.

| Platform | `desktop_bound` | `headless_user` |
| --- | --- | --- |
| macOS | ends with the graphical login. A job in the graphical domain is torn down with the domain, which is what a logout does to it | ends with the logout as well. macOS ends a user's agents when the user logs out, including one loaded into the background domain; only a system-level daemon survives, and that is not a per-user execution context |
| Linux | ends with the graphical login session | survives logout only while lingering is enabled for the user, which keeps the user's service manager running. It is off unless somebody enables it |
| Windows | ends with the sign-out of the interactive session | ends with the sign-out. A per-user task runs in the user's own session and stops with it; work that must outlive a sign-out needs a service under an account granted the right to log on as a service |

`kr doctor` and `environment.capabilities` report the answer for the host you are on rather than
the one this table says you probably have. The answer names the service mechanism it is about, and
a claim that a headless session survives logout also names what makes it survive.

### Enabling persistence on Linux

Lingering is the user's own setting and KalaReach never enables it. Installing the host does not
enable it, creating a session does not enable it, and neither does the power setting below. To turn
it on:

```sh
loginctl enable-linger "$USER"
```

Then `kr doctor` reports `survives_logout` for the headless profile instead of
`available_by_choice`. Turning it off again is `loginctl disable-linger "$USER"`, and any headless
session still running then ends with the next logout.

## What a reboot does

A reboot ends the live executions of both profiles: a desktop-bound worker went with its login
session and a headless one went with the machine. Sessions published in an earlier boot are closed
as the control daemon starts, before it tries to recover anything, and their records say the host
restarted rather than describing a worker that vanished.

## Containers and Windows Subsystem for Linux

A container and a WSL distribution each have their own process namespace and their own idea of a
display. Neither reaches the desktop of the machine hosting it, and KalaReach does not pretend
otherwise: a session created in one gets none of the desktop's variables, and every desktop
capability in its environment answers `incompatible` with that as the reason.

A container is recognised by the markers its own runtime writes: the file a Docker container
carries, the file a Podman container carries, and the control groups a container's first process is
placed in. A WSL distribution is recognised by its kernel release and its own variables, and it is
checked for first, because a distribution can carry a container's markers too.

## Sleep

The host does not change this machine's sleep policy unless you ask it to. `kr host power` shows
the setting and changes it:

```sh
kr host power                        # what the setting is, and what it is doing
kr host power --set mains_only       # keep this host awake for admitted work, on mains power
kr host power --set battery_too      # the same on battery, which is a separate choice
kr host power --set off              # the default
```

With the setting on, an assertion is held while the host has verified foreground work or a request
it has accepted and not answered: an agent working, a decision waiting for an answer, or a closure
still stopping processes and draining their output. An idle shell is not work, however much output
it has produced. The assertion is released when that ends, and `kr status`, `kr doctor` and
`kr host power` all print what is held and why.

| Platform | The facility | What it asks for |
| --- | --- | --- |
| macOS | a power-management assertion, through `caffeinate -i` | that the system does not sleep because nobody is using it. The display is not kept awake; that is the person's business |
| Linux | the login manager's own sleep inhibitor, through `systemd-inhibit --what=sleep:idle --mode=block` | the same, and the inhibitor refuses automatic sleep rather than merely asking to be told about it |
| Windows | an execution-state request from the per-user host agent | the same, for the session the agent runs in |

Each facility ties the assertion to the life of a process, and the host runs that process as a
child with a pipe on its input. Releasing it is closing the pipe. Nothing is signalled, and a
control daemon that dies releases everything it held, because the pipe dies with the process.

The assertion asks the operating system not to sleep on its own. It does not stop somebody closing
the lid, an administrator forcing sleep, or a platform policy overriding the request. KalaReach
treats every one of those as a possible loss of reachability rather than as something to prevent:
the host can be suspended at any moment, and every deadline is measured on a clock that counts
suspended time. So waking up never brings an expired action window, lease or grant back.

The platform's own listing is the thing that settles whether sleep is actually inhibited. On macOS:

```sh
pmset -g assertions
```

The assertion KalaReach holds names the process it is held on behalf of, and `kr host power --json`
reports the same process, so the two can be compared.

## What may be done on a desktop

Selecting a desktop is not evidence that anything may be done on it. `environment.capabilities`
answers each capability separately, says what produced the answer, and says what makes it stale.

| Platform | Established without asking the person for anything | Left as `not_tested` |
| --- | --- | --- |
| macOS | the display server, and launching an application, which needs no privacy permission | a screen image, synthetic input and the accessibility tree. Each needs a permission granted per signed application, and the check that would establish it is the operation itself, so performing it is what asks the person at the machine. The setup assistant runs those checks with them present |
| Linux, X11 | all of them, where a tool for them is installed: a client holding the display and its authority needs no further permission | nothing, unless this host could not name the display server |
| Linux, Wayland | a screen image and synthetic input where the compositor implements the protocols the installed tool uses, which `sway`, `river`, `hyprland`, `wayfire`, `labwc` and `niri` do | the same two on a compositor that asks the user for them each time instead, such as GNOME's screen-sharing portal. The answer names the compositor and the tool it is about |
| Windows | the display server, and launching an application in the interactive session | a screen image, synthetic input and the accessibility tree, which are checks that belong with the person present, because an unattended probe would act on whatever is on the screen |

A locked desktop refuses the screen and keeps the session: the capability says
`temporarily_unavailable` and the session and its processes are unaffected. A session with no
desktop (the headless profile, an SSH-only host, a host with no graphical login) has no desktop
capability at all, and says so rather than reporting a permission problem.

There is no general desktop-control interface. Desktop automation here means your own tools running
in the selected context under the permissions the operating system actually granted them; the
`automation.manage` right is about workflow definitions, not about pointers and keyboards.
