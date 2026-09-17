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
| Also reported | whether the domain is the graphical one, and whether the screen is locked while this user is the one at the console, which is the session the window server's lock state is about | the session type (X11 or Wayland), its desktop environment, its state and its locked hint | whether the session is a remote desktop one |
| Not read | | | whether the session is attended, locked or disconnected, so its availability reads as unknown rather than as a screen that is there for the taking |

A reading that names a login session but not its generation is not a desktop. The platform session
number alone cannot tell one login from the next one given that number, so a context built on it
would say a session created in one login belongs to another. Such a reading is treated as this host
not having found out, which is a third answer and not the same as there being no desktop: a
desktop-bound session closes when the platform says its login has gone, and not when the platform
declines to answer.

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
| macOS | ends with the graphical login. The worker's job is bootstrapped into the user's graphical domain, and a logout tears that domain down | started outside the graphical login, in this user's background domain, so it has no Aqua access to inherit. That domain outlives the graphical login; how long it lasts after the user's last session is the platform's own behaviour, which this host does not read, so it reports the lifetime as not established rather than guessing. Work that must outlive a logout with certainty needs a service in the system's own domain, which is a different execution context and an installation step this host does not take |
| Linux | ends with the graphical login session | survives logout only while lingering is enabled for the user, which keeps the user's service manager running. It is off unless somebody enables it |
| Windows | ends with the sign-out of the interactive session | ends with the sign-out. A per-user task runs in the user's own session and stops with it; work that must outlive a sign-out needs a service under an account granted the right to log on as a service |

`kr doctor` and `environment.capabilities` report the answer for the host you are on rather than
the one this table says you probably have. The answer names the service mechanism it is about, and
a claim that a headless session survives logout also names what makes it survive.

On a host with no per-user service manager the fallback is a detached process in its own process
group, reparented to the system's first process. A worker started that way is in whatever login
context the control daemon is in, so a headless session there has the desktop's variables stripped
rather than a login context of its own. `kr doctor` reports that as what it is. Windows uses that
fallback, and it also runs every one of a user's processes in that user's own interactive session,
so a headless session there is a session with no desktop handles and no promise about the desktop
rather than one that cannot reach it; its capability records say so.

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
session and a headless one went with the machine. Every session recorded in an earlier boot is
closed as the control daemon starts, before it tries to recover anything, and their records say the
host restarted rather than describing a worker that vanished.

The boot each environment last ran in is kept in a `boot` file in its own state directory, beside
the registry. That is the only place that survives what a reboot removes: on most hosts the runtime
directory is cleared with the boot it belonged to, taking the published descriptors with it, so a
daemon that compared descriptors would find nothing to compare after exactly the event it was
looking for.

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

The setting is per-user host configuration, kept in `power.json` in the environment's own state
directory, which `kr doctor` prints the path of. The document carries its own version, and a
document whose version this build does not know is left alone and read as off rather than guessed
at. Writing it installs no service, obtains no privilege and changes nothing else about the
machine.

```json
{
  "version": 1,
  "sleep_inhibition": "mains_only"
}
```

With the setting on, an assertion is held while the host has verified foreground work or a request
it has accepted and not answered. Four things count, and the host reads each of them rather than
guessing: a create it has accepted and not finished, a closure that is still stopping processes and
draining their output, a session whose worker reports an agent at work, and a session waiting for a
decision to be answered. An idle shell is not work, however much output it has produced. The assertion is released when those end, and `kr status`, `kr doctor` and
`kr host power` all print what is held and why.

Work begins and ends without the host being told, so while the setting is on the host looks at the
question every fifteen seconds, as well as whenever a session is created or closed and whenever it
is asked. That interval plus the two seconds the host gives itself to ask its sessions is the bound
on how long after work ends an assertion can still be held. While the setting is off nothing looks
at anything.

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

Nothing here performs the operation a capability is, and nothing here changes a screen, a clipboard
or an input queue. What a platform query can do is refuse a capability, and what it cannot do is
establish one: on every platform the operation itself is the check. So each record says which of
those happened.

| Platform | Established | Refused, with the reason | Left as `not_tested` |
| --- | --- | --- | --- |
| macOS | the display server, and launching an application, which needs no privacy permission | a capability whose facility is not installed | a screen image, synthetic input and the accessibility tree. Each needs a permission granted per signed application; this host neither performs the operation nor reads the permission, so it says so |
| Linux, X11 | the display server and launching an application | a context with no display or authority, which cannot reach the X server at all; a capability with no tool installed | a screen image and synthetic input where a tool is installed and this context holds the display. X11 grants those to any client that holds it, and nothing here has opened it |
| Linux, Wayland | the display server and launching an application | a compositor that asks the user for the operation each time, such as GNOME's screen-sharing portal, which is a permission the user grants rather than one a tool holds; a capability with no tool installed | a screen image or synthetic input on a compositor that implements the protocols the installed tool uses, which `sway`, `river`, `hyprland`, `wayfire`, `labwc` and `niri` do. The answer names the compositor, the tool and the operation |
| Windows | the display server, and launching an application in the interactive session | a capability whose facility is not installed | a screen image, synthetic input and the accessibility tree, which act on whatever is on the screen |

Each record also names the facility it is about: its path, its length, and a digest of its
contents. A tool replaced at the same path is a different file here even when it kept the path, the
length and the timestamps. The digest is for noticing a change rather than for proving one: a
capability record is evidence about what is feasible, never authority, and nothing here signs it.

The revision every record carries advances whenever any of this changes. It is kept in the
environment's state directory and written before it is handed out, so a host that restarts does not
hand out a revision it has used before; where that record cannot be read the revision stays at
zero, which claims nothing, rather than starting again from one.

The Wayland answers name the route as well as the tool, because the three routes a Wayland desktop
offers are different things: a protocol the compositor implements, the desktop portal (which asks
the user each time), and a tool's own service reaching the input devices directly. A permission
prompt cannot supply a protocol a compositor does not implement, so a tool built for one
compositor family on another leaves the answer unestablished rather than blamed on a permission.

A locked desktop refuses the screen and keeps the session: the capability says
`temporarily_unavailable` and the session and its processes are unaffected. A session with no
desktop (the headless profile, an SSH-only host, a host with no graphical login) has no desktop
capability at all, and says so rather than reporting a permission problem.

There is no general desktop-control interface. Desktop automation here means your own tools running
in the selected context under the permissions the operating system actually granted them; the
`automation.manage` right is about workflow definitions, not about pointers and keyboards.
