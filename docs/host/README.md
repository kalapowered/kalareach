# The KalaReach host

A KalaReach host runs one control daemon per operating-system user and environment, and one worker
per terminal session. The split is the point: a worker owns a shell, and nothing the control daemon
does (restarting, being upgraded, crashing) may end it.

```text
kr  ──────────────┐
                  ├─▶ kr-controller ──spawn──▶ service manager ──▶ kr-worker ──▶ PTY ──▶ shell
kr attach ────────┴─────────────────────────────────────────────▶ kr-worker

paired device ──iroh──▶ kr-controller ──proxy──▶ kr-worker
```

`kr attach` does not go through the control daemon. It reads a published descriptor, challenges the
worker named in it, and attaches. That is what keeps attaching possible while the daemon is
restarting.

A paired device does go through it, because a worker has no network endpoint and the daemon is what
authenticates a device. The network path is below.

## Directories

Two roots, both owner-only, both checked rather than assumed on every open.

| Root | macOS | Linux | Override | Holds |
| --- | --- | --- | --- | --- |
| runtime | `$TMPDIR/kalareach` | `$XDG_RUNTIME_DIR/kalareach` | `KR_RUNTIME_DIR` | the control socket, the rendezvous socket, worker endpoints, published descriptors |
| state | `~/Library/Application Support/KalaReach` | `$XDG_STATE_HOME/kalareach` | `KR_STATE_DIR` | the registry, worker journals, output spools, generated job definitions, the secret-store fallback, the transfer store and its staging area, the backup store and its staged ciphertext, what a daemon `kr new` started writes (`controller.log`), and the record of the startup files `kr shell install` put an entry in (`shell-entries.json`) |

Everything above a root is created with the platform's ordinary permissions; `/tmp` is
world-writable by design and `~/.cache` is usually group-readable, and neither is KalaReach's to
change. The root and everything below it is created with mode 0700 and verified on every open. A
directory that is a symbolic link, or that belongs to another user, is refused rather than repaired.

On Linux, $XDG_RUNTIME_DIR/kalareach is the default runtime root, unless that directory would end up
in a location shared between all WSL distros. WSLg sets $XDG_RUNTIME_DIR to /mnt/wslg/runtime-dir,
which is on shared storage and accessible from the entire VM. Therefore, if the resolved path is on
/mnt/wslg, on /mnt/wsl, would be linked into /mnt/wslg or /mnt/wsl, or is on the same storage as
/mnt/wslg or /mnt/wsl, ~/.cache/kalareach/run will be used instead. ~/.cache/kalareach/run will also
be used if $XDG_RUNTIME_DIR is not set, because each distro has its own $HOME. A path that cannot be
said to lie anywhere, such as one that climbs out of a directory that does not exist yet with .., is
treated as shared, and ~/.cache/kalareach/run is used for it too. A socket path there must still fit
a Unix socket address, which a very long $HOME does not: the runtime root is refused then, and the
product does not fall back to shared storage.

Per environment the directories are `<runtime>/<prefix>` and `<state>/environments/<prefix>`, where
the prefix is the first four bytes of the environment identifier in hexadecimal. The prefix is
short because a Unix socket address is 104 bytes on macOS and the runtime directory already spends
much of that; it is not unique, so each directory also carries an `environment` file holding the
complete identifier. A second environment whose identifier shares the prefix is refused, never
silently given another environment's registry.

Endpoints are `c.sock` (clients), `r.sock` (the owner-only rendezvous), `t.sock` (attachment
chunks) and `w<display>.sock` (one worker). On Windows they are named pipes scoped by user and
environment, carrying an owner-only access-control list, because the pipe namespace has no directory
permissions to inherit. That namespace is shared by every account on the machine, so the list is not
the only line. The listener proves each caller's account from the connection itself, at the
connection's first read, and nothing a caller of another account sends reaches a reader. This
host's own clients open a pipe for identification only, so the server cannot act as them, and check
before they write that the pipe is owned by an account the client could have created it as, and
that its list admits no account the machine does not already trust. That is this account's user,
the owner this account's new objects receive, or the Administrators group where the client's token
holds that group enabled as an owner, as an elevated administrator's token does whatever default
owner it was given: a shell of Git for Windows gives its processes the user as default owner, and
a tree or a pipe an elevated process made is still that administrator's own. An account that
already holds the machine that way is not something these checks keep out, and a token filtered
down to what a standard user holds trusts no pipe that group owns. An entry for an identifier
that no account on the machine holds, such as a copied image carries, is refused like any other
account. The state and runtime directories are checked by the same rule. A name another account
created first while the host was not listening is refused rather than served or trusted, and the
host does not start on a name another account holds.

A session's output spool is created the same way rather than inheriting the process umask, because
it holds the terminal's own output: mode 0700 on Unix, and on Windows the owner-only access list of
the state directory above it.

**Keys are OS-protected where the operating system offers protection, and the limit is
documented.** On macOS the device keys live in the login keychain, and on Windows in the
credential manager. On Linux the Secret Service is available only where a session keyring is, which
a headless host usually has not got: there the keys fall back to a file under the owner-only state
root, protected by the directory's own permissions and by nothing else. That is the documented
headless Linux limitation, and it is a limitation rather than a defect of this host: a key file an
account can read is a key its own account can read, and no file permission makes it otherwise.
A host that must do better needs a hardware-backed store, which is a separate decision from this
one.

## Configuration

One versioned document per user, per environment: `config.json`, in the location the platform keeps
configuration in. On Linux that is `$XDG_CONFIG_HOME/kalareach/environments/<prefix>/config.json`,
or `~/.config/kalareach/...` when the variable is unset, which keeps configuration out of the state
tree the way the desktop conventions ask. On macOS and Windows it is the environment's own state
directory, which is where those platforms keep a per-user application's settings. An environment
whose state directory was chosen explicitly, with `KR_STATE_DIR`, keeps its document inside that
directory on every platform, so an isolated installation stays isolated. It is the only
configuration file this host reads.

```json
{
  "version": 1,
  "revision": 3,
  "preferences": { "sleep_inhibition": "mains_only" },
  "profiles": { "review": { "worker_profile": "headless_user" } },
  "default_profile": null,
  "ceilings": {
    "session_limit": 16,
    "grant_rights": null,
    "enrolment": { "retained_generations": 5 },
    "disable_policy": "disable_at_next_admission"
  },
  "secrets": [{ "name": "relay", "store": "login_keychain", "item": "kalareach/relay" }],
  "network": { "enabled": true, "relay_urls": ["https://relay.example.com"] },
  "voice": { "broker_origin": "https://voice.example.com" },
  "startup": { "controller": "standalone" },
  "agents": { "kalareach/codex": { "ownership": "reduced" } }
}
```

| Rule | What it means |
| --- | --- |
| `version` | The schema version. A document declaring one this build does not know is left exactly as it is, nothing is read out of it, every value falls to the product default, and `kr doctor` reports the version it found |
| `revision` | Rises by one with each validated edit. An edit names the revision it was built on and is refused if another writer moved it first, so no edit silently erases another |
| 64 KiB | The most of the document that is ever read. A larger file is not one of ours and is refused rather than parsed |
| owner-only | A document that is a symbolic link, or that belongs to another user, is refused rather than read |
| unknown fields | Refused. A misspelled key is a mistake a person can see, not a setting that quietly does nothing |
| omitted fields | The product's own value, and reported as the product's own. Every budget inside `enrolment` is separate: the example above configures one of the eleven, and `kr doctor` names that one rather than reporting eleven choices nobody made |

Editing is validated before a revision is applied, and one writer edits at a time: a writer takes an
operating-system lock on `.config.lock` in the environment's state directory, reads, validates,
checks that the
document is still what it was and still says what it said, writes, puts the change where the things
it restricts read it, and releases the lock. The lock lives in the open file handle, so a process
that ends without releasing it releases it anyway and nothing has to guess from a timestamp whether
a holder is still alive.

A change that would affect authority fences dispatch before the change is acknowledged, so work
admitted under the old authority cannot be dispatched by the time the caller is told the change is
in force. A change to the execution context invalidates the capability evidence taken under the old
one and migrates no worker: a running session keeps the context it was created in.

Those effects belong to the document, not to the command that wrote it. The host puts the document
on disk into force whenever it is asked what it is configured as, and what it does is decided by
what moved since the last time it read one, so a ceiling lowered in a text editor fences dispatch
and a profile changed there replaces the evidence, exactly as the same edit made through `kr` does.
Fencing dispatch withdraws the authority every open connection was admitted under, so a command
that asked reconnects and asks again under the authority now in force; that is the change working
rather than a failure.

It is also one reading: what `kr doctor` prints is what was put into force, so a value in a report
is never a value nothing is enforcing. Where an effect cannot be applied, the report prints what is
in force, says what the document asked for, and the `configuration-in-force` check fails with the
reason. Where the fence a ceiling raised has not been acknowledged by every worker, that same check
warns and names them: the values are in force for everything admitted from then on, and the
revocation is complete for a worker once it acknowledges the revision or is confirmed ended. Asking
for the same change again is told the same thing until it is.

That debt is durable. The write that advances the environment's authority revision records, in the
same statement, that the fence it raises is owed; the record is cleared only when every worker has
acknowledged that revision or is confirmed ended. So a host that stops between raising a fence and
hearing the last answer comes back still owing it, announces the revision again to the workers it
reconnects to, and keeps refusing to call the change complete. An effect that fails afterwards, a
configuration document that later becomes unreadable, and a restart are none of them a worker
answering, and none of them settles it.

### The network and the voice broker

Whether this host joins the network, and every service it uses there, is the document's `network`
section. The managed voice broker it names to its paired devices is the `voice` section. Nothing
else chooses either. No environment variable reaches them, so a daemon started with the variables
an older build read joins nothing because of them.

```json
"network": {
  "enabled": true,
  "bind_address": "0.0.0.0:4433",
  "relay_urls": ["https://relay.example.com"],
  "pkarr_publisher_url": "https://discovery.example.com/pkarr",
  "pkarr_resolver_url": "https://discovery.example.com/pkarr",
  "dns_origin": "discovery.example.com",
  "relay_trust_anchors": ["/etc/kalareach/relay-ca.der"],
  "relay_only": false,
  "local_discovery": false,
  "mainline_dht": false,
  "proxy_url": "http://proxy.example.com:3128"
},
"voice": { "broker_origin": "https://voice.example.com" }
```

| Field | What it selects | What it accepts |
| --- | --- | --- |
| `network.enabled` | whether the daemon joins the network; without it the host serves its local endpoint alone | `true` or `false` |
| `network.bind_address` | the socket address the endpoint binds to; absent binds an unspecified address and a free port | a socket address |
| `network.relay_urls` | the relay map | at most 32 absolute `https` or `http` URLs |
| `network.pkarr_publisher_url` | the discovery server this host publishes its signed record to | an absolute `https` or `http` URL |
| `network.pkarr_resolver_url` | the discovery server this host resolves peers from | an absolute `https` or `http` URL |
| `network.dns_origin` | the DNS origin this host resolves peers from | a dotted domain name with no scheme, port or path |
| `network.relay_trust_anchors` | DER certificate files trusted for a relay's HTTPS, beside the public anchors | at most 32 absolute paths |
| `network.relay_only` | every packet through the relay, and no direct path | `true` or `false`; `true` needs at least one relay |
| `network.local_discovery` | discovery of peers on the local network | `true` or `false` |
| `network.mainline_dht` | the public Mainline DHT, which carries no KalaReach service guarantee | `true` or `false` |
| `network.proxy_url` | the HTTP proxy this host's outbound HTTPS goes through: the endpoint's relays and Pkarr servers, the rendezvous, delivery and webhooks, and plugin repositories; name lookups and mail submission do not use it, and absent everything goes directly | an absolute `http` or `https` origin, with no user information, no path and no trailing slash |
| `voice.broker_origin` | the managed broker a device's voice session talks to | an absolute `https` or `http` origin in lower case, with no path and no port its scheme already implies |

A field the document does not write selects nothing, because there is no public relay or discovery
server to fall back on. A URL or an origin names its host the one way the protocol spells every
origin it compares: a lower-case name or the canonical form of an address, no port its scheme
already implies, and no user information. A name in its `xn--` A-label form is refused, because the
URL parser the endpoint uses decodes that punycode and this check cannot decode it the same way. A
path is letters, digits and `- . _ ~ /`, with no `.` or `..` segment, and the whole URL fits the 253
bytes of printable ASCII that an invitation carries it in, counting the `/` the parser adds to a URL
with no path. The proxy is an origin by the same rules, with nothing after its host and port, and a
proxy address that names a user or a password, even an empty one, is refused as a proxy that needs
credentials, which is not supported; it is never used with the credential dropped. Every address
the document accepts is therefore one the endpoint accepts. A value outside these rules makes the
whole document invalid, as it would in any other section: the host keeps its product defaults,
`kr doctor` names the key and withholds the value, and an edit to another section is refused until
the document is fixed. The proxy is this machine's own choice, and no invitation or host bundle
carries it.

One rule covers the proxy. Every outbound HTTPS connection this host makes goes through it when the
document names one: the endpoint's relays and Pkarr servers, the rendezvous it reserves a code's
locator at and opens the room at, delivery to the push gateway and to webhook addresses, and plugin
repositories. Nothing goes around it, so an address the proxy cannot reach fails, a webhook
included. Mail submission is SMTP and connects directly, and name lookups go directly too. Without
a proxy every one of those connections goes directly, apart from iroh's relay latency probe and
captive-portal check, which then follow `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` when those are
set. The daemon reads the proxy when it starts, like the rest of the section, and every client takes
that one reading.

The daemon reads both sections once, when it starts, because that is when its endpoint and its
voice service are built. `kr doctor` prints each field with its value, its source
(`host_configuration` where the document wrote it and `default` where it did not) and
`applies at the next start`. The `configuration-network` check reports what the running services
are doing, read from them: whether the endpoint is up, how many sockets it holds, how many relays
and discovery services it was built with, and whether the voice service names a broker. When the
document now selects something other than what the daemon started with, the check warns that the
edit applies at the next start. What only the start can find out, a trust anchor file that is
missing or empty or a bind address somebody else holds, stops the start with the key named, rather
than leaving a host that appears to run and cannot be reached.

### How the daemon is started

A headless or SSH-first host has its per-user daemon started on demand, and only once it has been
set up for that. The document's `startup` section records the setup:

```json
"startup": { "controller": "standalone" }
```

| Field | What it selects | What it accepts |
| --- | --- | --- |
| `startup.controller` | how `kr new` starts this environment's control daemon when none is running; absent starts none, and `kr new` answers `HOST_NOT_CONFIGURED` with the setup action | `service`, `standalone` |

`service` has this user's own service manager start the daemon, from a definition that
`kr host startup --set service` writes and records: a launchd job on macOS, a systemd user unit on
Linux. `kr new` then asks the manager to start it, and the manager is the daemon's parent.
[docs/cli/README.md](../cli/README.md#kr-host-startup) says what is written, where, and what
`--clear` removes.

`standalone` is the standalone headless profile, for a host with no service manager set up to start
the daemon. `kr new` then runs the `kr-controller` installed beside it, detached: in a session and a
process group of its own with no controlling terminal, its standard streams going to
`controller.log` in the environment's state directory, working in that directory, and given the
environment's own runtime and state roots. It inherits the command's environment, `PATH` included,
as a daemon started by hand from the same shell does. Its IPC is the owner-only endpoints every
daemon serves, and it takes the environment's singleton lock and advances its generation like any
other start; several commands starting it at once leave one daemon. The command waits up to 30
seconds for it to answer, and
[docs/cli/README.md](../cli/README.md#when-no-control-daemon-is-running) says what a person sees.

On Windows `standalone` is this user's scheduled task for the environment, which
`kr host startup --set standalone` registers and `kr new` asks the Task Scheduler to run; the task's
starter starts the daemon, as [Windows](#windows) describes, and `service` is not available.

`kr host startup` writes the section as one validated edit with no daemon running, and `kr doctor`
reports it with its source and as applying at the next start, and, for `service`, whether the
definition matches what kr wrote. Like the network and the voice broker, no request, profile or
environment variable reaches it, so a variable exported in one terminal cannot make a command start
a daemon on a host that was never set up to have one started. Starting the daemon installs nothing,
enables no lingering and obtains no privilege, under either start. The one thing a choice installs
is the service definition `kr host startup --set service` writes and records, and choosing anything
else removes it. A value this build does not know makes the document invalid, and the host starts
nothing.

### What leaves this host

A support bundle, and any diagnostic written into one, is an export: it is made to be sent to
somebody who is not at this machine. Every field in one is redacted by what it is rather than by
what it looks like. Each exported field is listed once, in `kr_protocol::hostinfo::export`, with the
class of value it holds. A class either carries its own text out of this host or it does not.

The two forms are two types. What the host answers the owner's own control path with names the
paths it resolved and the labels they chose, because that is a person asking their own machine
where its files are; the export form is `export::Exported`, and the only way to build one is to
take a value through the allowlist. A display value therefore cannot be serialised into a bundle by
a caller who did not think about where it was going, and a value that has already crossed the
boundary is not measured a second time.

Reading is the other way to hold these types. A program that parses a bundle or a reply gets the
same types back, filled with whatever that document said, and what they then hold is the sending
host's word rather than this one's. `kr doctor` is such a reader: it asks the daemon for the
diagnostics and writes a bundle from the answer, so the redaction a bundle carries is the answering
host's work.

A bundle is two types for the same reason. `SupportBundle` is what a reader parses, with members
anybody can look at. `ComposedBundle` is what a host composes: its members are private, it does not
parse, and its one constructor takes every member through the allowlist. A writer takes the composed
type and nothing else. So a bundle that arrived has nowhere to go, whether it is passed on whole or
taken apart and its members set beside fresh ones: it has the reader's type, and reading never
produces the writer's. A file this host writes is this host's own reading of itself.

The rule that holds for both is one sentence: an export quotes text as this build's own words only
where this process composed it from literals in this source, and everything else is typed, measured
or withheld. It is the value that answers, not the caller. Every field whose class says it carries
the product's own words holds a type that knows where its text came from (`export::Stated` for a
literal, `export::Sentence` for one composed from literals, numbers, identifiers this host generated
and the measure of everything else), and reading clears that mark, because a document, a reply or a
bundle somebody else wrote is not this build. So a value that arrived already claiming to be this
host's own leaves as its length rather than as itself, whichever field it arrived in, and a plain
string has nowhere in such a field to go at all.

A class beside a string is a claim about the string, and it arrived in the same document the string
did, so it is never believed either. Two classes can be checked against the text itself: a term,
against the closed sets this build defines, and a number, against its digits. Those two are the only
ones a plain string leaves as itself. A row that arrived saying its value is an identifier or
another structure is measured like everything else.

What the types establish is where a value was composed, not that nobody worked to defeat them.
Leaking a runtime string gives it the lifetime a literal has, and a caller determined to launder
text through `Stated::new` can. The guarantee is against the mistake that happens: a value read off
the wire or out of a library repeated as though this host had written it. The constructors are what
make that mistake impossible rather than merely discouraged. Taking an already exported value
through the boundary a second time is possible as well, and what it costs is meaning rather than
safety: a path measured twice reports the length of its own placeholder.

The ones that do are the ones this build decides: sentences it spells out in its own source, the
words of the closed sets it defines, its numbers, and the identifiers it generated. Everything else
leaves as its class and its length, or not at all: a message from a library or an upstream, a
command line, a path, a network location, a header value, the value of an environment variable, and
a name an account, a platform or a person supplied.

A check's sentence is built the same way, and its constructors are the enforcement. It takes text
only as a literal in this source, a number, one of the identifier types this host generates, or the
value of a field the allowlist already classes, taken on that field's terms. A library's error
message, a path or a person's name therefore reaches one as a class and a length and cannot reach it
as itself; a check, a recorded error and a reported value are each built by one constructor that
writes their text fields, so there is no second way to make one.

What that costs the reader of an export is a length in place of a sentence, and what it buys is that
a bundle cannot repeat something it was handed. A check's identifier, title, detail and remedy, the
prose beside each effective value, a ceiling's configured and in-force values and what narrowed
them, the precedence ladder, the documented rule for each location, why an override sits where it
does, what stopped a document taking effect, what a fence is still owed, a component's name and
version, what produced a redacted error and what a selected content export contains: each of them is
one of those two types. A test walks every type a bundle and the four host-and-environment answers
a paired device is sent can reach, fills each field that takes arbitrary text with a marker by
reading it in, and exports the result; the marker never appears.

The allowlist is checked against the same roots, through the schema of what a serialiser writes
rather than through a list of types. Every reference and everything beside it is followed, arrays
and alternatives are descended, and every object the walk arrives at must have a class for each of
its members, so a type that is reachable only inside another one is covered and a member added to
one fails the build's own tests on the day it is added. A form the walk cannot account for is
refused rather than passed over: a value of any shape, a map, whose keys are text nothing classes,
and a keyword that holds a schema the walk does not follow. Nothing may be classed that no export
reaches, which keeps the list a record of what leaves rather than a place entries accumulate. One value is reported by its kind alone: the boot identity is
opaque bytes that identify one boot of one machine, so an export says which kernel facility this
platform reads it from and carries none of the value.

### What a paired device reads of this host

The four host-and-environment reads, `host.info`, `environment.list`, `environment.capabilities` and
`host.doctor`, answer the owner's own socket with the display form and everybody else, a paired
device among them, with the export form. One function in the daemon decides which form leaves, by
who asked, and each answer's reduction sits beside its type, so a member added to an answer is
reduced there or not at all.

What a device reads is which environments these are, what they run on, how busy they are and what
they can do, in this build's own words and numbers. It never reads an account name, a local path or
what the platform said:

| Read | What the device gets instead |
| --- | --- |
| `environment.list` | the operating-system user as a name's class and length; the runtime and state directories as a path's; a label written again as `environment <prefix> on <platform>`, because the owner's label names the account |
| `host.info` | the name the platform shows for a sleep assertion and its reason for withholding one as their class and length; the facility the boot identity is read from, with none of its bytes; the build named in full only when it parses as one of this product's builds |
| `environment.capabilities` | the capability evidence, the desktop context and the persistence table on the same terms as a support bundle |
| `host.doctor` | the checks and the effective configuration on the same terms as a support bundle |

The allowlist walk above has all four answers as roots, so a field added to one fails the build's
own tests until it is classed.

Nothing reads a value to decide about it, which is why an unfamiliar spelling changes nothing: a
credential written in lower case, in an alphabet nobody expected, or in the middle of an ordinary
sentence is gone for the same reason as any other, that the field it arrived in is one this host
does not publish the text of.

The locations `kr doctor` reports are both: the paths this host resolved, and the rule this platform
follows. `$XDG_STATE_HOME/kalareach/environments/<prefix>`, or `~/.local/state/kalareach/...` where
that variable is not set, says where a state directory belongs on every Linux host; the resolved
path says where this one person's is. The rule is what survives an export, because the resolved
path carries their account name to say it.

The preferences are what this host applies. `sleep_inhibition` is what the daemon holds an assertion
under; `worker_profile` is the execution context a create request gets when it does not choose one,
which is what `kr new` without `--desktop` or `--headless` uses. `command_integrations` names the
installed packages, as `publisher/plugin`, whose command integration a session applies. The host
fills a session's integrations in when the session is launched: one entry for each admitted package
whose integration applies there, on where this list names the package and off where it does not. A
create request that names one is refused, and an entry that is off carries no flags. A session
carries at most 256 KiB of flags and 128 entries. Past that, and wherever its launch message cannot
carry them beside the create request, the largest integrations turned on are left out, and one note
in the doctor's catalogue check names the session and each of them. A profile's list replaces the
host's, and an empty list turns every integration off at that level. `kr plugin integration enable`
and `disable` edit the host's list, and the change reaches the sessions created afterwards.

`kr doctor` reports each package the list names, with its state, and each integration an admitted
release declares: what a new session gets of it and why, the mode its command runs in, the flags
and variables it adds, and the executable the daemon's own search path resolves the command to,
with the version a signed qualification record gives that executable. An installed release the
admissions leave out is reported only where the list names it, and where the admissions cannot be
computed each listed package is reported as `unknown`. An integration a new session would be
launched without for its size is reported as `too_large`. One answer carries at most 256 reports
and 384 KiB of them, the listed packages first, and the check counts any it leaves out. A session
whose own search path differs can find another; a launch the host records names the one it ran.

`agents` records the choice of a reduced-ownership profile for one agent, by package
(`publisher/plugin`). An entry names `ownership`, as `reduced` or `full`, and nothing else. A
package with no entry has full ownership, and a document this host cannot use chooses nothing. The
document is refused if a key is not a `publisher/plugin` identifier, if an ownership is neither
`full` nor `reduced`, if an entry names anything besides `ownership`, or if it names more than 64
packages, so a malformed key is never read as no choice. `kr doctor` reports the choice as the value
`agents.ownership`, whose effect it gives as applying to nothing, and prints one line for each
package the document chooses `reduced` for: `reduced ownership is recorded and no launch on this
host reads it; on Windows a launch whose profile records reduced is tracked by start identity and
its closure never reads complete, and the command route has no such profile`. An export carries the
package names by their class and length. The worker's launch runs an agent under the `ownership` its
profile records and does not read this document, every profile this host writes records `full`, and
this host starts no agent through that launch, so no edit to this section changes a launch on this
host.

`environment_additions` is the preference that adds variables to a session started with the host's
environment, described under *The environment a session starts with*.

The document the sleep setting used to live in, `power.json`, is not read. A copy found beside the
configuration is reported by `kr doctor` in one line and ignored.

### Precedence

For an ordinary preference, highest first:

1. an explicit request or command-line option;
2. the selected session or environment profile;
3. the per-user host configuration;
4. the product default.

Every ordinary preference resolves through one function, so the order cannot drift between call
sites. A profile a request names and this host does not have contributes nothing and the value
falls through to the document.

The creator's shell environment is what the session's own processes run with, and nothing this host decides is taken from it. The daemon holds it in memory from the reservation until the worker claims it. Because it is never written anywhere, environmental variables containing security credentials are never written to the registry, to a WAL, or to any log. Only the variables below participate in configuration, and they are read from the host's own environment.

| Variable | Supplies | Acts at | Why there |
| --- | --- | --- | --- |
| `KR_RUNTIME_DIR` | the runtime tree | an explicit request | it selects the runtime tree, which no document inside that tree can name |
| `KR_STATE_DIR` | the state tree | an explicit request | it selects the state tree the configuration document itself is read from |

No other inherited variable takes part in the precedence. No entry in that table names authority, an
organisation restriction, a grant ceiling, a hard resource limit or a provider origin, and none can:
each entry has to name an ordinary preference, and those are not.

Three other groups of variables this build reads are outside the precedence, and `kr doctor` lists
those set here rather than leaving the sentence above to be read as more than it says.

| Group | Variables | What they select |
| --- | --- | --- |
| platform locations | `TMPDIR`, `XDG_RUNTIME_DIR`, `XDG_STATE_HOME`, `XDG_CONFIG_HOME`, `HOME`, `LOCALAPPDATA`, `USERPROFILE` | the operating system's own conventional directories, which is what the native locations above are derived from, and on Windows the home an agent's tool configuration is written under |
| session readings | `PATH`, `DISPLAY`, `XAUTHORITY`, `XDG_SESSION_ID`, `SESSIONNAME`, `USER`, `LOGNAME`, `USERNAME` | what the platform says about the login this host is running in, its account name included, and where a capability probe looks for the tools it reports on |
| network library | `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` and their lower-case spellings, `REQUEST_METHOD`, `SystemRoot` | with no `network.proxy_url`, the proxy iroh's relay latency probe and captive-portal check go through; and on Windows where the endpoint reads the hosts file. iroh reads these itself and offers no way not to |

No group reaches authority, a provider origin or whom this host trusts. The network library's
variables move where two relay checks and a lookup go; they choose no relay, no service and no
trust. No variable selects a network service, the proxy or the voice broker: those are the
configuration document's `network` and `voice` sections. The managed-service, rendezvous, delivery,
plugin repository and mail clients verify a server against the platform's own store, and
`SSL_CERT_FILE` and `SSL_CERT_DIR` are not read, so an authority given only through them is not
trusted by those clients until it is installed in the system store; `kr doctor` says so. The
endpoint verifies its relays and discovery servers against the public anchors and
`network.relay_trust_anchors`, and a private authority for those is named there.
No variable names this host's owner either: the owner is recorded through local IPC, by the pairing
that establishes it (see "Pairing and the host's owner" below).

### Ceilings

Authority, organisation restrictions, grant ceilings and hard resource limits are intersections
rather than defaults a flag can raise. A configured value more permissive than what is already in
force is refused and reported as refused.

| Ceiling | Intersected with |
| --- | --- |
| `session_limit` | what this machine's own resources allow. 128 is the product default rather than a maximum: the owner may set a higher number, and this host establishes no resource limit, so nothing narrows the choice and `kr doctor` says so |
| `grant_rights` | the rights the grant and this host's policy already allow, which the grant intersection decides; this ceiling only removes |
| `disable_policy` | not an intersection but the administrator's own setting: what happens to a live binding whose release its repository revokes. `warn_only` (the default), `disable_at_next_admission` or `disable_at_once` |
| `enrolment` | section 11's own budgets: what one repository's metadata, kept generations and cached payloads may cost, how large one package may be and how many bytes one synchronisation may transfer; a cached payload budget above 1 GiB is a full mirror and needs `full_offline_mirror` set explicitly |

A ceiling is applied where the thing it restricts reads it, and an edit whose value the intersection
would refuse is refused before it is written rather than recorded and then silently read back
narrower. `session_limit` becomes the number this host admits a create against, at startup and again
after every acceptance. A document this host can use decides that number whether it names one or
leaves it to the product default, because removing a ceiling is a choice. A document that is absent
and one this build cannot read decide nothing at all, and then the number already in force stays and
is what the report prints: a restriction an owner accepted is never lifted, or reported as lifted,
because a later build could not read the file it was in.

`grant_rights` is applied where a paired device's request is decided. Every request a device sends
goes through one decision: its grant, intersected with this host's policy (the organisation lease a
grant requires and the bounded offline validity an owner chose) and then with the rights ceiling in
force, before the method's required rights are checked. So a method whose right the ceiling has
removed is refused, and the refusal names the right and says this host's configuration removed it,
although the device's grant carries it. A ceiling that names a right a grant never carried adds
nothing to that grant. The rights a device's mutation is forwarded to its worker with are the ones
this decision left, so an attachment a worker admits cannot carry a capability the ceiling took
away. The ceiling in force follows the document the same way the session number does: an
acceptance that read a usable document puts its ceiling in force before it raises the fence that
ceiling owes, and one that read no usable document leaves the ceiling as it was. `kr doctor` prints
the rights in force, names every right they remove from every grant on this host, and says so when
the ceiling in force is one this host accepted earlier rather than one the document in front of it
decided.

A narrower ceiling fences dispatch before the edit is acknowledged. The authority revision advances
first, which withdraws every connection admitted under the wider ceiling; a device that reconnects
is admitted at the new revision, and its requests are decided under the narrower ceiling from then
on. The fence answers for the ceiling devices are served under as well as for the document this
host last finished accepting. The two differ after an edit whose ceiling went into force while
another of its effects failed, and a later edit that withdraws what that ceiling allowed is fenced
like any other. A fence that could not be raised, because the revision could not be written, stays
owed: every later reading raises it, whether or not anything in the document moved, and only a
fence that was raised settles it. The host policy moves to that revision with the registry, so a device paired after the edit is
issued a grant this host recognises as its own.

`enrolment` is applied where each budget is used, and follows the document the way the session
number does. An enrolment asks for its own budgets, and `catalogue.add` refuses one that asks for
more than the configuration allows, before anything is fetched, with `QUOTA_EXCEEDED` and the name of
the budget. `retained_metadata_bytes` bounds the metadata a repository keeps across the generations
it keeps. A document that names none gets `metadata_bytes` times `retained_generations`, as each is
resolved, and `kr doctor` says the value is the product's own. `package_bytes`, `object_count` and
`expanded_pack_bytes` hold every package to a declared size, a number of files and a size once
extracted, each no larger than the package format's own maximum: 64 MiB, 512 files and 64 MiB,
which are also the defaults. They are read each time a package is installed, enabled or admitted,
so a lowered limit reaches packages already installed; one past a limit is not admitted, and the
catalogue check in `kr doctor` warns about it. A change to them moves the plugin admissions to a new
revision in the same step, and an acceptance whose revision cannot be written puts none of the
budgets in force and reports why, so the next acceptance tries again. `transfer_bytes` bounds the
bytes one synchronisation transfers, the metadata, the index and a full mirror's payloads together,
2 GiB by default; a sync past it is refused by name and the generation in use stays.

`disable_policy` is put in force from the next admission, at start and at every acceptance after it,
by the rule the enrolment budgets follow: a document this host loaded decides it, and one that names
none has the default, `warn_only`; a document that is absent, unreadable, of a version this build
does not know or invalid decides nothing, and the policy this host holds stays in force, which `kr
doctor` says is the one last accepted. It is recorded with the plugin admission revision it moves in
one step, so every worker is sent a round and a policy equal to the one in force sends none; an
acceptance whose revision cannot be written puts none in force and reports why, so the next
acceptance tries again. A policy this host holds and cannot read is reported as not known, never as
the default. A document that does not use the setting has no `disable_policy` member. Under
`disable_at_next_admission` a binding on a revoked release keeps observing and is refused every
rich admission; under `disable_at_once` it ends at its next admission boundary once the request it
admitted has completed.

A secret is never in the document. `secrets` holds named references: what this configuration calls
it, which secure store it lives in and its name inside that store. There is no field a value would
fit in, so `kr doctor` and a support bundle print the reference and can print nothing else.

## The bundled generation

A fresh host has no repository and may have no network, so a signed catalogue generation travels
with it: the metadata, the index and the nine packages the synchronisation script lists. The bytes
are in `bundled-plugins/`, and `bundled-plugins.lock` beside them names every file with its digest
and exact length, the highest trust root, and the repository, commit and generation the copy came
from. The plugin runtime reference describes the layout and how the copy is made.

The host compiles the bundle in and checks every byte against the lock when it reads the bundle in,
before anything is parsed. A bundle whose files do not all match its lock is refused whole.

At every start the daemon seeds the catalogue from the bundle, before it binds its local endpoints.
A build trusts the bundle's root only if the root's key identifiers are ones it commits: a shipped
build commits no production root, so it refuses the bundle, and a build with debug assertions also
trusts the development lineage and seeds only when it is started with `--seed`. Where the root is
trusted, the seed enrols the official repository against it, activates the bundled generation
without the network, and installs each bundled package once, enabled and with an empty grant. A
later start finishes what an earlier one did not reach and takes a newer bundled generation after an
update. It never replaces an installation that is already there, and an uninstall or a disable by
the owner is never undone.

What the bundle is not: a catalogue or a grant. It carries one generation, frozen at the commit it
was copied from, and a package's capability requests, grants and repository ceiling are applied to
it exactly as they are to anything installed. A bundled package that asks for a native bridge gets
its first grant through `plugin.install`, with the owner's confirmation.

## Descriptors

The control daemon publishes one descriptor per live session, atomically: written to a temporary
file in the same directory, then renamed, then the directory entry flushed. A descriptor carries
the session identifier and epoch, the environment, the display number, the boot identity, the
worker's process-start identity, the protocol version, the endpoint, the worker's public key and
its profile. It carries no secret.

A reader checks the file before it reads it: a symbolic link, another user's file, a file others
can read or write, or one larger than any descriptor this host writes is refused. A descriptor
whose contents name a different session from its filename, or a different environment from its
directory, is refused too.

Nothing in a descriptor is acted on until the worker behind the endpoint has answered a challenge.

## Identity and verification

There are four proofs, and each has its own job.

| Proof | Who signs | What it settles |
| --- | --- | --- |
| rendezvous | the worker, once at startup | this process is the worker the daemon reserved |
| verification | the worker, on every challenge | the process answering this endpoint is that worker, now |
| generation | the control daemon | this connection speaks for the current daemon generation |
| peer credentials | the kernel | the caller on this socket is this user |

The worker generates an Ed25519 keypair from the operating system's random generator at startup and
keeps the private half in memory for its whole life. It is never written to disk, placed in an
argument vector or put in an environment variable.

Every local host process states its build in its answer to a hello: its build identifier, such as
`kr-worker/0.1.0`, and the version of the protocol package it was built from, which
`packages/protocol/package.json` sets and the build compiles in. A worker outlives an upgrade, so a
client can meet one of another build, and the statement is how it tells before it meets a frame it
cannot read. `kr attach` reads a worker's screens only when the two versions share a compatibility
level, and refuses any other worker before it asks the session for anything; the
[`kr attach` reference](../cli/README.md#kr-attach) has the rule and the refusal. A process of a
build before the statement states none. The daemon still reads its answer, because it goes on
speaking to the workers that outlived its upgrade, and `kr attach` takes it for an earlier build.

Boot and process-start identities come from the kernel:

| Platform | Boot identity | Process start identity |
| --- | --- | --- |
| Linux | `/proc/sys/kernel/random/boot_id` | `/proc/<pid>/stat` field 22 |
| macOS | `kern.bootsessionuuid` | `proc_pidinfo(PROC_PIDTBSDINFO)` |
| Windows | the kernel's boot counter and its System process's creation time | `GetProcessTimes`: the creation time in hundreds of nanoseconds since 1970 |

A macOS kernel that publishes no boot session identifier is refused by name, with its release, and
the host does not start on it. Its boot time is not used instead: the kernel moves the boot time
when the clock is set, so a host running across a clock set would read one boot as two and take its
own sessions for those of an earlier boot. macOS 14 and later, the releases the host runs on, publish
the identifier.

Windows gives an ordinary account no identifier for a boot. The Windows boot identity is therefore
a pair of records the kernel keeps for its boot: the boot counter it publishes in the page it shares
with every process (`KUSER_SHARED_DATA.BootId`), and the time it recorded when it created its
System process, process 4, which it keeps for as long as it runs. Neither record changes while the
kernel runs. A clock set, a sleep, a hibernation, or a hypervisor setting the clock after pausing
the machine leaves both as they were, so every read in one boot gives the same value. A restart
normally gives the pair another value, and the pair repeats exactly when both records repeat. The
new kernel records its System process's creation as the clock it starts from plus the time it took
to start, to the hundred nanoseconds. Unless the clock went back between two starts, the later one
records a later time. The time repeats whenever that sum comes out the same at two starts, whichever
of them read the earlier clock, as it can when a dead battery resets the real-time clock to one
instant and two starts take the same time. The counter usually advances at a restart, but nothing
guarantees that it does. A repeat would take the new boot for the old one and measure the old
boot's continuous deadlines on the new boot's clock.

A build before this one identified a Windows boot by its boot time in whole seconds. Its boot
record, its workers' descriptors, and the deadlines and checkpoints it bound to the current boot
all read as an earlier boot once, after the upgrade. The daemon closes the sessions that build
recorded, as it would after a restart, and `kr bind` skips its workers' descriptors.

A process identifier alone is never enough. Every ownership check compares the start value as well,
so a recycled identifier reads as a different process. A query the operating system refuses is
reported as unknown, never as death: a recovery path that treated a failed query as a death would
release a session identity while its worker was still running.

A process query answers one of three things: the process and its start identity, gone, or cannot
be established. Only an answer that no process holds the identifier is "gone": a missing
`/proc/<pid>/stat` on Linux, `ESRCH` from `proc_pidinfo` on macOS, and on Windows the kernel's
refusal to open an identifier no process holds. A refusal of access, or a process whose times cannot
be read, is a query that failed. A creation time of zero, one before 1970, or one more than a day
after the current time is one whose start the operating system would not give; none of these can
be established. Windows describes a process that has exited for as long as anything holds it open,
so a process whose identity matches is asked as well whether it has exited.

Windows records a creation time in hundreds of nanoseconds, and the start value keeps them, so two
processes created under one identifier within one second are two start identities. A worker of the
previous release states its start in whole seconds, and so do the records it and its controller
wrote. Such an identity names the process that holds the identifier now if that process was created
in the same second, which is how that release read it. Each time the controller opens its
registry, a record in whole seconds whose process is still running is rewritten at the finer value,
one whose process has gone is marked ended, and one the kernel will not describe is left for the
next opening; each worker's row keeps the source the worker itself states. Whole seconds are read
until the first release after one in which every running worker states the finer value.

### Where the daemon keeps its keys

`kr-controller --secret-store` chooses where the controller identity and this host's network
device keys go. One selection covers both:

| Value | Store | Who uses it |
| --- | --- | --- |
| `platform` (the default) | the operating system's credential store, with the owner-only directory where section 10 offers it | an installed host |
| `file` | this environment's own `secrets` directory | a test, a bench or a demonstration run |

The two key sets are opened separately, because the identity is opened at startup, behind the
singleton lock, and the network keys only when the environment selects a network. Under `platform`
each takes the store it always took: the identity follows the `.store-kind` record this host made,
and the network keys take the platform's credential store where there is one and the owner-only
directory where there is not. On a Linux host whose secret service appeared after it recorded the
directory, that is two different stores, which is what an installed host has.

Under `file` both go in the environment's own `secrets` directory. `file` names where the keys go
and nothing else: it allocates no directory and deletes nothing afterwards, so a run that wants its
keys to disappear gives the daemon a state directory it owns and throws away. That is what the
harnesses do, and it is why nothing a test or a measurement does reaches the person's own
credential store; the in-process suites call `kr_crypto::store::open_store_in` for the same reason.
The daemon names the store it opened in its first line of output, so a run's log says where its
keys went.

## Supervision

A worker's lifetime belongs to the platform, not to the control daemon.

| Platform | How a worker starts | Where its identity comes from |
| --- | --- | --- |
| macOS | a per-session launchd job, bootstrapped into `gui/<uid>` and started once with `launchctl kickstart -p` | the kickstart output's process identifier, then `proc_pidinfo` |
| Linux with systemd | a transient user *service*, `systemd-run --user --unit=... --collect -p Type=exec -p Restart=no` | `systemctl --user show -p MainPID`, then `/proc/<pid>/stat` |
| other Unix | a child in its own process group, reparented to init when the daemon exits | the spawned child |
| Windows | the spawned child, outside the daemon's kill-on-close Job | the child's identifier and creation time |

`kickstart -p`, never `-k`: the second restarts a job that is already running, which for a session
worker means killing a live shell to start another one.

launchd keeps a job loaded after its process has exited until something removes it, so the daemon
removes a worker's job once the worker has ended. After a session's closure is recorded, or a launch
fails, it waits for the kernel to say the worker's process has gone and then removes the job. When
it starts, before it serves anything, it looks at every job the environment still has a definition
for and removes each one whose process has ended: a worker that ended while no daemon was running
leaves nothing loaded either. A job whose process is still running is never removed, because
removing it would end that worker. The job's definition under `jobs/` goes with it, and its
`.diagnostics` file stays.

The plugin host is started the same way, as a job of its own, and its job goes the same way. The
launch that started a host watches its process and removes the job once the kernel says it has
gone, or at once where the start failed. A host that ended while no daemon was watching it leaves
its job to the next plugin-host launch in the environment, which removes every such job whose
process has ended before it starts its own.

systemd drops a transient unit once its process has ended, and `--collect` makes that so for a
unit whose process failed as well, which would otherwise stay listed as failed until somebody
reset it. Every command put to launchd or to the user manager, whether it asks, loads, starts or
removes, is given ten seconds to answer; one that does not is ended and counted as a failure of a
command that may have reached the manager.

The service manager reports a process identifier as soon as it has spawned the process, which can
be before the kernel will describe it. The daemon retries briefly rather than refusing a worker
that started perfectly well.

The profile decides which login context a worker is started in, not only which variables it is
given. On macOS a desktop-bound worker's job goes into the user's graphical domain and a headless
one's into the background domain, because a headless worker inside the graphical login would have
that login's access however little of its environment it was given. On Windows a worker is a child
of this daemon and runs in the logon session this daemon runs in, so a headless session there is one
with no desktop handles and no promise about the desktop rather than one that cannot reach it.

Linux places a job in no login session at all: a user service manager started at boot has no
display, no compositor socket and no session message bus, because those belong to a graphical login
that happened later. So a desktop-bound worker's transient unit is given the selected session's own
handles explicitly, read from that session's leader, and every other login-session handle is removed
from what the unit would otherwise inherit. Both halves are needed on a host where one user is
logged in twice: the manager holds one environment for the whole user, so what it offers is used
only when it says which session it describes and says the selected one, and a handle that was not
collected is cleared rather than left to arrive from the other login. A headless worker is given
none of them.

The fallback supervisor, which a host with no service manager uses, has no domains to choose
between: a worker it starts is in whatever login context this daemon is in, and a headless worker
there has the desktop's variables stripped rather than a login context of its own.

What a logout does to a worker of either profile is the platform's answer, and
`docs/host/platforms.md` records it per platform along with the explicit setting that changes it on
Linux. Nothing here enables that setting: creating a session never turns on a persistence option,
and neither does installing the host.

### Privacy permissions

A worker started by the service manager is not a child of the terminal that asked for it. On macOS
that makes it its own process as far as the operating system's privacy controls are concerned, so
the first time a worker reads a protected location (an external volume, the desktop, the documents
folder), the person is asked to allow it, once per installed binary. That is the operating system
working as intended; nothing here asks for blanket access on the user's behalf.

Two consequences are worth knowing. A session whose working directory is on a protected volume will
prompt when its shell starts, not when the person later opens a file. And a host whose binaries are
replaced (a new build, an upgrade) is a new binary to those controls, so the question is asked
again.

A launchd job's standard error goes to `<state>/environments/<prefix>/jobs/<label>.diagnostics`. A
worker that fails before its rendezvous has no terminal, no connection and no journal yet, so that
file is the only place its diagnosis can go.

### The plugin runtime

A worker is not the only thing whose lifetime belongs to the platform. Components run in
`kr-plugin-host`, one process per environment, started through the same supervisor as its own job
outside the daemon's kill tree, and started only when a binding first needs one: an environment
whose shells never use a component has no plugin process at all.

It reports itself on a rendezvous endpoint of its own, signed with a keypair it generated at startup
and keeps in memory, and the daemon publishes an owner-only descriptor at `plugin-host.json` beside
the worker descriptors. Workers read it, challenge the process behind the endpoint, register their
bindings and keep their own ledgers. Nothing durable lives in that process, so its death invalidates
rich bindings, kills no worker and loses no request; a worker notices, re-registers, and carries on.

`docs/plugins/runtime.md` has the execution model, the per-instance limits, the compiled-code cache
and the protocol.

### The plugin catalogue

The daemon also owns the environment's plugin catalogues: the repositories it is enrolled in, the
signed metadata snapshot of each one, the packages installed from them and what each package may do.
It keeps them under `catalogue/` in the environment's state directory:

```text
catalogue/
  catalogue.sqlite3            the enrolments, installations and action receipts
  repositories/<enrolment>/    one directory per enrolment, named by this host's key for it
    datastore/                 the client's own trusted metadata
    index/<digest>.json        each verified generation's index, whole and named by its own digest
    payloads/<digest>          cached payloads, by content hash
    packages/<digest>/         an activated package's files, under its manifest digest
```

The database is the one owner of what the catalogue must still know after a restart, written with a
write-ahead log and full synchronisation: each enrolment with its trust root and budgets, which
generation it is on, each installation with what it may do, and the receipt of every catalogue
action. Every change reads what it changes inside its own transaction, so two requests, or two
daemons pointed at one directory, never write back a stale copy over each other. The files are
named by what they hold and a reader relies on one only once a committed row names it. A
repository's directory is named by its enrolment rather than by the repository's name, so removing
a repository and enrolling the same name again under another root starts a new directory, and what
the old enrolment installed stays with the old enrolment.

Both method groups arrive through the ordinary path. A read is checked against current authority; a
mutation carries an action window and is checked against the method registry and its envelope. That
admission travels into the catalogue and is asked again where the change becomes durable: the
catalogue's transaction, and every file it publishes or reclaims, runs while the daemon holds its
table of admitted connections, so a revocation or a withdrawn connection is ordered wholly before
the change or wholly after it, and a request whose deadline or authority ran out while it waited
behind a sync or a download changes nothing. A mutation is claimed durably before it is performed,
under the caller and the action identifier, and the transaction that makes its change also records
the answer it gave. A retry of an applied action is answered with that answer and a refused one
with its refusal, without performing anything again. An action a stopped daemon left mid-way is
settled as unknown when the next daemon opens the catalogue, and is never performed again: an
action that may have happened is not reported as one that did not. `action.read` reads the same
receipt, for the actor that submitted the action: to a local caller, and to a paired device only
while its grant still carries `host.manage`, the right every catalogue mutation required.

Two decisions are the owner's and are not side effects of anything else. Adopting a trust root is
`catalogue.add`, and it needs the owner's confirmation of that exact action: a single-use
confirmation, bound to a digest of the repository, its locations, the root's keys, its budgets and the
trust it asks for, with a short lifetime.
Being authenticated as the owner is not that confirmation. `catalogue.add` never re-anchors or
widens a repository already enrolled: it refuses one this host already holds, so changing a root or
a ceiling is `catalogue.remove` and then `catalogue.add`, two deliberate acts with a confirmation on
the second. A sync verifies inside the ceiling the enrolment already has and refuses a generation
that would need more.
Granting a capability is `plugin.grant`, confirmed the same way and bound to the package digest and
the capabilities it is about; an install refuses a grant wider than the installation already held
and says which method that decision belongs to.

A terminal asks for the same two decisions without holding an owner key. It asks
`owner.confirmation.request` for a challenge naming the `catalogue_add` or `plugin_install` subject,
which carries the exact `catalogue.add` or `plugin.install` request without its proof. The host
works out what an owner device is shown from that request and from what it holds. For an enrolment
that is the repository's name, kind and locations, the root's digest and key identifiers, its
budgets and its ceiling. For an installation it is the repository's ceiling, the release, the
package hash and the grant, and, if the grant holds `native_bridge.install`, the publisher's
statement from the verified manifest of that exact package hash. The host then sets the challenge to
the digest of the plan the effect builds from the same request, which covers everything shown on the
owner device. The owner device builds the same plan again from what it is shown, and signs only when
the digest matches the one sent by the host. The host's own notice that a native bridge runs outside
the plugin sandbox is a separate text, shown apart from the publisher's. The terminal then repeats
the same request without proof, and the host spends once the oldest answer an owner device recorded
for exactly that request. The challenge has to be one the host described: it never spends an answer
for a challenge a caller described, even one with the same digest, unless the proof is presented.
Only the owner may ask, and that is decided before the host reads anything for the subject. On a
host that is not on the network, the methods that need an owner device return `HOST_NOT_CONFIGURED`.

Removing a repository stops trusting its root and uninstalls nothing. A package installed from it is
still installed, on the hash it was installed at, and the answer names what is still there. What it
may do goes on being answered from what the installation recorded: the capabilities the package
asked for and the ceiling of the repository it came from, both held with the installation, so
enabling, pinning, granting and uninstalling it all work with no enrolment behind them. Enabling one
whose payloads are no longer cached is refused as unavailable offline, because there is no longer a
root to verify a fetch against.

An installed release whose manifest carries a native bridge recipe, installed with
`native_bridge.install` granted, has the recipe applied in the application's own directory while the
installation stands: the package is enabled, its repository has not revoked the release and the
organisation's adapter allowlist, where there is one, names it. Disabling the package, a revocation,
a list that no longer names it, a grant that withdraws that capability and removing the package each
take the recipe out again, whatever the disable policy says about live bindings, and the
installation stays. After every plugin change, every synchronisation, pin and removal, every change
of the allowlist, and each time the daemon starts, the package's bridge is brought to what its
installation wants, so a recipe a stopped daemon left part way is finished or taken out before
anything else is served. The recipe keeps a journal of its own for each package under
`native-bridges/` in the environment's state directory, apart from the catalogue's records, and
never changes a method's answer or receipt: an installation's answer says what the catalogue did,
and the journal says what the recipe did. Its version check needs a signed record that names the
application's executable by digest: a build the release's entry in the repository's signed index
names for this host's platform. Records arrive with a synchronisation, so the bridges are brought up
to date after every sync as well. A recipe is refused, and the journal says why, when no signed
record names an executable of the application, when no such executable is on the search path, when
an executable there is not one a record names, and when the version a record names is outside the
range the recipe is written for. `docs/plugins/catalogue.md` has what is checked before anything is
written and what a removal leaves.

The registry admits a paired device to all thirteen of these methods, and the daemon serves them
through the same module a local caller reaches, so a device's `catalogue.list` and the owner's are
one answer. A catalogue and an installed package belong to the environment, so there is no worker to
forward a mutation to and no session content to narrow: the grant's environment selector is what
scopes them, the envelope check refuses a target naming a session or an application, and the effect
runs on a task a dropped connection cannot cancel part way. Every mutation in both groups, and
`catalogue.list`, require `host.manage`; `plugin.list` and `plugin.capabilities` require no right,
because what they describe is what this environment already runs. The owner's confirmation is the
same ceremony on both doors, and a device cannot stand in for it.

What a session may bind is the daemon's to decide and the worker's to enforce. The daemon computes
the environment's plugin admissions from the catalogue's current records: every installation that
is enabled, supported on this host's operating system and architecture, whole in the store, within
the package limits in force and not revoked. Every change that could alter them raises an admission
revision in the catalogue's own transaction. Each worker is handed the admissions with its launch
specification, and a round on its authority connection after every such change and every 30
seconds while it has not answered at the current revision or holds a release no installation
describes; its answer reports every live binding and the release it holds. A worker binds only what
the admissions it holds admit.

`plugin.list` counts live bindings from answers every worker gives after the read began, so a count
is exact or null: null while any worker has not answered. It also lists every release a worker
holds that no installation describes, such as one an upgrade left, until its bindings end.
`plugin.remove` answers with the bindings its own refresh found, or null. Every other answer that
carries a summary carries no count. A reclaim of a repository's space that needs room waits until
every worker has answered at the current revision, so no release a live binding holds is removed.

`docs/plugins/catalogue.md` has the sync, the budgets, the extraction rules and what a signed
qualification may not do.

## Creating a session

1. The daemon records the reservation durably: the actor, the create token, the immutable payload
   digest, the create request without its environment variables, the allocated session identifier
   and display number, and the launch phase. Display numbers increase and are never reused.
2. The reservation moves to `spawned` **before** anything starts, because a worker can reach the
   rendezvous socket the instant the service manager starts it. Before that, while privacy mode is
   on, the daemon records the session's obligation (see *Privacy mode*).
3. The service manager starts the worker. Its job definition carries only non-secret facts: the
   reservation, the session, the environment, the display number, the rendezvous address and the
   two directory roots.
4. The worker connects to the rendezvous socket and presents its signed claim. The daemon checks
   the signature, matches the reservation, and compares the connecting process (both its
   identifier and the kernel's record of its start) with what the launcher reported. Exactly one
   rendezvous per reservation succeeds; a second is refused, recorded, and fences the reservation.
5. The daemon sends the launch specification over that private channel: the create request with the
   environment variables the session starts with (see *The environment a session starts with*),
   taken from memory, whose environment they are and the names of the configured ones among them,
   its own public key, its generation and the privacy state in force.
6. The worker binds its endpoint, creates the pseudo-terminal, applies the privacy state, launches
   the root shell and reports itself ready. The daemon records the worker's public key inside the
   same transaction that marks the session live, then publishes the descriptor.

The create token is the request's action identifier. A retry with the same payload resolves to the
same reservation; the same token with a different payload is refused rather than becoming a second
session. A lost reply never causes a second launch.

A reservation records the create request without the environment variables its creator sent. The list in a recorded request is always empty and says nothing about what the creator sent. The environment is kept in memory in the daemon in the entry corresponding to a create request waiting for a worker to claim it. When a worker claims the create request, the environment is "moved" (once) from the waiting create request to the specification of what needs to be launched by the worker. A create that stops waiting takes back whatever the claim has not taken, whether its launch could not start or the 30 seconds it waits for its worker ran out, so a claim that arrives afterwards finds none.

When a worker claims a create request, if there is no more environment, the claim is refused. A reservation that is still `spawned` becomes `failed` without any key, and nothing is launched with an environment its creator did not send. Another case where this can happen is when the daemon is restarted in between a reservation and the claim of a worker created by the previous daemon. A second claim on a reservation that was already claimed still fences it. A repeat under the same token is answered from the record: with the session once it exists, or with an error that names the reservation's phase. A `claimed` reservation can still become a session. A `spawned` one can only while its create is waiting or a claim has already taken the variables; otherwise it becomes `failed` when its worker's claim is refused or, once its worker has ended, at a later start. A `failed` one cannot. Note that if a worker claimed the create request in time but is not answering anymore, the answer to the create request will be `OUTCOME_UNKNOWN`. In that case, the create request can be sent again under the same token, but a new session should only be created if the answer is `failed`.

### Which shell, and what the session claims

A create request names a shell mode, and the two modes are different promises rather than degrees of
the same one.

**Managed** launches a KalaReach-qualified package: the exact binary its reader patch was built
into, with the flags that package declares. The daemon resolves the package before it records a
reservation, so a shell no package qualifies is `SHELL_INTEGRATION_UNSUPPORTED` by name rather than a
session that closes itself a moment later, and a command line rather than an executable is refused
the same way. Step 6 changes for a managed session: the worker binds the root-editor endpoint
*before* the shell starts, because the address and a one-time secret travel to it in its own
environment, and it reports itself ready only after the integration has qualified, which is after the
user's startup files have run. An integration that fails before that closes the session that was
being created and records why; an explicit compatibility retry is a new create request.

**`native_compat`** launches the selected stock shell. It keeps create, attach, detach, close,
transfer and terminal presentation, and it claims none of the managed editor: Ctrl-D follows that
shell's own behaviour and can close the session, a launch installs no command, and `kr detach`
remains available. It is an explicit choice and never an automatic substitution for a managed
request that could not be served.

[docs/shell-integration/host.md](../shell-integration/host.md) describes the endpoint, the handshake,
the phases, the launch transaction and the guarded startup entries `kr shell` writes.

### The environment a session starts with

Whose environment a shell starts with depends on where the create came through, what the client says it is, and whether anyone is shown the session. It never depends on whether the request happens to carry variables.

A session the command line creates for a person to see starts with that command line's own environment, which the command line sends with the request. The worker filters it as [the shell host's document](../shell-integration/host.md) describes. A session an app creates, a session created invisibly (from the command line too, which then sends nothing) and a session a paired device asks for all start with the host's environment instead. A request for one of those that carries variables is refused, and the refusal repeats none of them. A connection that declared itself the control daemon or a worker creates no session. The kind a client declares decides whose environment its sessions get, and gives it no authority.

The host's environment is an allowlist of the daemon's own, read once when the daemon starts: `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG`, `TZ`, `TMPDIR` and every `LC_` variable. On Windows the allowlist is `PATH`, `PATHEXT`, `SYSTEMROOT`, `WINDIR`, `COMSPEC`, `USERNAME`, `USERPROFILE`, `HOMEDRIVE`, `HOMEPATH`, `APPDATA`, `LOCALAPPDATA`, `TEMP`, `TMP`, `LANG`, `TZ` and every `LC_` variable, and names are compared without regard to case. A credential in the environment the daemon was started from, an agent socket or a terminal's identity never reaches a session. Desktop variables come from the execution context the session runs in, as *The desktop a session runs on* describes.

The owner can add to it. The `environment_additions` preference is a map from variable names to values, set in the configuration document on the host's rung or on a profile. A session started with the host's environment gets each of them over the host's own value of the same name, and a value replaces the host's whole: a `PATH` added there is the session's `PATH`, and nothing in it is expanded or joined to another. A profile's map replaces the host's rather than adding to it, and an empty map adds nothing. A session started with the command line's environment gets none of them. The daemon uses the configuration it last accepted, so an edit reaches the sessions created after the daemon accepts it.

A rung holds at most 64 names. A value is at most 32,767 bytes and holds no NUL, and a rung's names and values together are at most 256 KiB. A name the host owns is refused in any letter case: the `KR_` names, the terminal identity variables, `TERM`, `COLORTERM`, `SHELL`, `SSH_TTY` and the desktop's variables. `TERMINFO` and `TERMINFO_DIRS` are not among them, and [the shell host's document](../shell-integration/host.md) says how they are kept. On Windows two names that differ only in case are one variable, so a document that names both is refused. The values stay in the document. `kr doctor` names the variables a rung adds and never a value, a refusal names a name by its class and length, and the map prints only its names when something prints it.

The worker records where three things came from, and the session's summary says so. The list of sessions, a read, the worker's ready report and the worker's journal all carry it. For `PATH` the answer is `creator_snapshot`, `host_context`, `configured_addition`, `execution_context` or `unset`. The locale takes the same words, for the first of `LC_ALL`, `LC_CTYPE` and `LANG` that is not empty, which is how a POSIX shell picks its character set. The working directory is `create_request` when the request named one, and `worker_default` when it named none and the worker asked for the root directory. A named directory that is not one cannot be used as it is: the launch library starts the shell elsewhere or the launch fails, depending on the platform, and the word still says the request named it. The words describe what the shell was asked to start with, and a startup file changes the rest as it does for any shell. A summary the host composes without its worker, and one an older worker wrote, carry no words. A daemon that starts again lists them as before, because the worker holds them.

`kr doctor` prints a line for each session the host lists, saying the source is not known where there are no words. It adds one line when the host counted more sessions than the list shows, which can be a session that ended between the two reads. Where it could not read the list within fifteen seconds it says so and prints no session line. The content export carries the three words in each session's record, `null` where there are none, and a bundle without content carries none.

## The desktop a session runs on

Where a session is shown and where its processes run are different questions. `kr new --invisible`
answers the first. The execution profile answers the second, and it decides which display, which
message bus and which operating-system permissions a command inside the session has.

| Profile | What it is bound to | What ends it |
| --- | --- | --- |
| `desktop_bound` | the boot, the operating-system user, the platform's login-session identifier and the login-session generation | the graphical login ending, which closes the session with `desktop_lost`. Losing every attachment does not, and neither does this daemon restarting |
| `headless_user` | the boot and the operating-system user | the platform's own answer, which this host reports rather than assumes |

A desktop host creates sessions in its own desktop's context and an SSH-only or headless
installation creates them in its configured headless context. `kr new` prints which one it is about
to use before it creates anything, and the create receipt records the one it used. `--invisible`
changes neither: an invisible session in a desktop context keeps that desktop's access, which is
what lets an agent with no terminal window drive a browser on the screen in front of you.

The identity is the whole of it, and nothing is ever rebound to a new login: a session whose
desktop ended is closed and you create another. How well a reused login-session number is told
apart from the login before it depends on the platform, because the generation is the start value
of the process that owns the login and each platform owns its login differently.
`docs/host/platforms.md` says what each one establishes, including where the answer is weaker.
`docs/host/platforms.md` has the per-platform detail, including what each platform does at logout
and what it will not tell this host.

A desktop is not a permission. Screen capture and input injection each need an operating-system
permission that selecting a desktop does not carry, and `environment.capabilities` answers each of
them separately, in the shared capability-evidence shape, saying what produced the answer and what
makes it stale. Nothing there performs the operation a capability is: a platform query can refuse
either of them and cannot establish one, so an answer nothing has run says exactly that. There is no
general desktop-control interface here either: desktop automation means the user's own tools running
in the selected context under the permissions they were granted.

## First-start permissions

Selecting a desktop is not a permission, and neither is holding one permission evidence for
another. On macOS, Accessibility, Screen & System Audio Recording, Full Disk Access and the
Automation grants are four separate things granted to one signed application, and Full Disk Access
does not stand in for the rest: an application holding it still cannot take a screen image or send
a keystroke. The microphone and Remote Desktop belong to the features that use them and nothing
asks for them until you do.

None of these can be enabled by KalaReach. Some of them can only be set in System Settings at all,
so setup takes you to the right pane and you set the switch.

### What a check can establish, and what it cannot

A permission cannot be verified without performing the operation it guards. Asking the platform
what a permission is set to is not the same question, and on macOS it is not a question a program
can put about itself. So the checks perform the operations:

| Check | What it does | What it touches |
| --- | --- | --- |
| Read a file you authorised | opens the file you nominated and reads its first few thousand bytes | that file, and nothing else on the filesystem |
| Take a screen image | takes one image of the desktop and measures it | writes the image into the check's own directory and removes it before answering |
| Find an element | asks the accessibility tree for the name of one element | reads the tree; selects nothing, moves nothing, clicks nothing |
| Open an application | starts one new hidden instance of the platform's own calculator, and ends the instance it started | nothing you already have open: the application it starts has no documents to reopen |
| Send a keystroke | delivers one keystroke | this one changes something, so it runs only inside a test context that owns the application the keystroke lands in, and this build has none |

Each of them runs in the same execution context an agent's own tools run in, each declares what it
does before it runs, each is bounded, and none sends input to an application you did not ask about
or changes anything you own. The last one is the exception that proves the rule. Delivering a
keystroke safely means owning the application it lands in, and the platform's own input facility
delivers to whatever is in front instead, so it is not performed here at all: its record says
nothing was established either way rather than claiming an answer.

Every result is a capability record in the shared shape: the state, `disclosed_probe` as what
produced it, the exact facility it was established about, and what makes it stale. That last part
is what decides when a check runs again: the facility or the host agent being replaced, an
operating-system permission changing, a new login, or a different execution profile. Time is not on
the list. Nothing about a permission changes because an hour passed, and a check that re-ran on a
clock would take an image of your screen for no reason.

### What each answer means

`ready` is an operation that was performed and worked. `permission_required` is one the operating
system refused, and the record names which grant. `desktop_unavailable` is a desktop that is not
there to act on, and a check that ran on a desktop that is there and did not get far enough says
that instead. A capability nothing has performed the operation for says so, and that is an answer
rather than a failure: it means nothing is known either way, which is different from knowing it
cannot be done.

One more answer belongs to the person rather than to the host. macOS gives a new grant to a process
when that process starts, so an application that was already running when you granted something is
still running without it. When a permission has been granted and the capability still reports that
the permission is required, the answer is to open KalaReach again.

A tool-specific permission stays its own record throughout. An accessibility grant this context
holds says nothing about a screen image, and no part of this ever reports one as evidence for the
other.

### Where a grant is recorded

An operating system files a permission under a signed application, which is why setup shows that
identity before it guides you anywhere: the bundle identifier, the file it is running from, and the
signature on that file as the platform's own signing tool reports it.

Having a signature is not enough: it has to be one the operating system will recognise again. An
ad-hoc signature is one the machine made for that file; the next build carries a different one, and
every grant given to the old one stays with it. The same goes for a bundle inside a build directory,
which the next build overwrites. Install a signed build first.

### Running the demonstration

`scripts/e2e-permissions.sh` runs the whole of it on the machine it is run on: a real control
daemon, a real worker in your own graphical login, what the host publishes through
`kr doctor --json`, the four checks performed from that session's own shell and the records they
produce, and the tools an agent reaches for on that desktop. It ends every process it started, it writes its artefacts under
`KR_TEST_ARTIFACTS_DIR`, and it asks for no account of any kind. It needs macOS and a person
logged in at the console; on a host without a graphical login it fails and says so, because a run
that checked nothing has not passed.

## Sleep

This host does not change the machine's sleep policy unless the owner asks it to. The setting is
off until then, `kr host power` shows and changes it, and the two choices are separate: mains power
only, or battery as well.

With it on, the host holds the platform's own assertion against automatic sleep while it has
verified foreground work or a request it has accepted and not answered: a session whose worker
reports an agent at work, a session waiting for a decision to be answered, or a closure that is
still stopping processes and draining their output. Work begins and ends without this daemon being
told, so while the setting is on it looks at the question every fifteen seconds as well as whenever
a session is created or closed and whenever it is asked; while the setting is off nothing looks at
anything. A close that arrived over the network reaches the same review at the same point, when
the worker has accepted it, so a closure a device asked for is looked at under the owner's setting
rather than releasing an assertion the host never took. The review runs on its own task and the
device's answer does not wait for it, so what this establishes is that the setting is looked at
rather than that an assertion is held for every instant of every closure. Each session gets half a second to answer and the whole round two seconds, so the answer
does not get slower as sessions are added. Host status, `kr status` and `kr doctor` each print what
is held and why.

The assertion is held by running the platform's facility as a child with a pipe on its input, so
releasing it is closing the pipe and a daemon that dies releases everything it held. A facility
that has already exited holds nothing, so one that does is reported as an assertion this host does
not have rather than as one it does.

An assertion asks the operating system not to sleep on its own. It does not stop a closed lid, a
forced sleep or a platform policy that overrides the request, and none of those need to be stopped:
every deadline this host decides is measured on a clock that counts suspended time, so waking up
never brings an expired action window, lease or grant back.

## The terminal

The host is the terminal, not whatever is attached to it. Every byte the shell writes passes
through the worker's canonical grid (`kr-term`) before any attachment sees it, and the retained
history keeps the raw stream underneath.

| What arrives | What an attached terminal gets |
| --- | --- |
| Ordinary output | the same bytes, forwarded unchanged, in direct mode |
| A query | nothing; the host answers it once, into the application's own input |
| A bell, clipboard write, notification or progress report | delivered to the one attachment holding the input lease, and to nobody else |
| A sequence the profile does not name | nothing; it is consumed with a rate-limited diagnostic |

Two presentations, and the choice is the host's:

| Presentation | What it receives | When it applies |
| --- | --- | --- |
| `direct` | the spans of the raw stream the engine cleared | the terminal is exactly the canonical size, has declared the terminal it probed, and the stream is still carryable |
| `viewport` | a rendering of the canonical grid, clipped to the terminal's own size | every other case |

`kr attach --no-probe` withholds the declaration, so that attachment is projected: a host that has
not been told which terminal it is talking to does not hand it a byte stream and hope.

An attachment never receives replayed history. What it is given when it joins, and again whenever
it resynchronises, is the screen as it is now, rendered from a closed set of operations with no
member that can ring, copy, notify, download, launch or ask anything. A terminal that was not there
when the history happened does not have the history happen to it.

Asking for the screen again over the same connection replaces that connection's subscription at a
frame boundary. The old stream will finish sending a frame that is already part way to the client,
but no further output will be written to it other than any enqueued side effects, which will be
written or recorded as described below, after which the new screen will be sent.

Rendering a screen back into bytes cannot carry everything a client that holds its own grid could
apply. What it leaves out is counted rather than assumed away: the rows of the buffer that is not
showing, for a client shown the live screen alone; the saved cursor of the buffer that is not
showing, and a saved cursor of the showing buffer that lies outside the window; the keyboard
negotiation of the buffer that is not showing, and all of it for a client that declared no terminal
profile, together with the keyboard stack the session holds; the virtual title stack; soft-wrap
markers; the right-hand side of a row wider than the window; and a pending wrap, whether the
cursor's or a saved cursor's, that the window shows. A terminal given a screen that left out any of
these but the right-hand side of a row is not handed the stream afterwards. Its attachment is shown
a projection, with the reason `restoration_incomplete`, until the session's screen is one a
restoration can carry. An earlier reason in [the CLI reference's
list](../cli/README.md#--json-shapes), such as `no_terminal_profile`, is reported in its place and
keeps the projection for as long as it holds.

A restoration begins by writing the plain state its screen is drawn under and saving the cursor with
`ESC 7`. The state is the cursor hidden, the plain rendition, no open link, origin mode and left and
right margins off, the whole screen as the scroll region, ASCII designated for `G0` and `G1` with
`G0` in use, the default cursor shape, and the cursor at home, which also ends a pending wrap.
Autowrap and reverse video are the session's own, because kitty saves both with the cursor and a
restore would put back what an earlier application left. The restoration writes all of it where the
terminal stands, enters the alternate buffer and writes it there, then returns to the primary buffer
and writes it again. The terminal can be showing either buffer when the restoration begins, and the
one it is not showing can hold a cursor an earlier application saved there. A restore that came
before any save of the application's would go where that cursor was, so each buffer is left holding
the state of a session that saved none. A terminal that keeps one saved cursor for both buffers
holds the last one written.

None of this is asked of a soft reset, which a restoration never sends, because terminals do not
agree about what one does. xterm resets origin mode, the scroll region and the character sets, and
saves a fresh cursor in the buffer that is showing. Alacritty, Ghostty, tmux and GNU screen ignore
it. foot leaves origin mode and its saved cursors as they were. kitty and foot empty the keyboard
stack, foot also empties the title stack, and xterm, foot and WezTerm reset the `modifyOtherKeys`
level. All of those belong to the person's other programs and not to this session. A switch of
buffer can bring back a link that a terminal saved with its cursor, so the restoration closes any
link the stream left open after every switch. The cursor stays hidden until its own operation at the
end decides whether it shows.

To paint the buffer that is not showing, the restoration enters it through mode 1049 (clearing it)
and leaves it (retaining what was painted) before installing anything, since leaving restores the
cursor and may turn off line-feed/new-line mode on some terminals, undoing anything that was put in.
When the primary buffer is showing, the other buffer is painted immediately after those saves, and
the plain state is saved again to replace the cursor that entering saved. When the alternate buffer
is showing, the primary buffer is painted between leaving and re-entering the alternate buffer.
Re-entering the alternate buffer after that paint saves a plain cursor (the default pen and shape,
no link, at home). Mode 47 is not one the profile tracks, and a restoration never asks a terminal
for it. A saved cursor the session holds for the buffer that is showing is installed afterwards,
except for a pending wrap it holds, which is counted as not carried. The one it holds for the other
buffer is counted as not carried.

The session's left and right margins are written straight after that save, with the saved state
still in force. The sequence that sets them, `CSI Pl;Pr s`, saves the cursor on Alacritty, foot,
tmux and GNU screen, which have no margin mode, and written anywhere else it would replace the
cursor just saved. Where the restoration installs no saved cursor for the buffer that is showing,
the plain state is saved again first and the margins follow it.

A sequence the profile does not name is consumed rather than forwarded, and the engine counts it;
`Session::terminal_diagnostics` reports those totals. A side effect that arrives while nothing holds
the input lease has no destination, so it becomes a durable host event in the worker's own journal
rather than being shown to whoever happens to be watching.

A side effect with a destination is delivered whole, never trimmed as if it were a span of the
stream, and ahead of any request to begin again that the same output makes of that attachment,
because the byte that ends a clipboard write can also be the byte that lets a held terminal take the
stream. A side effect which cannot be delivered is recorded as a host event, as if it had no
destination. Reasons for not delivering a side effect include: the lease has moved to another
attachment; the attachment has no subscription; its stream has been told to begin again; its queue
has no room; or a write to it failed. When a subscription is replaced by another, the former
subscription writes the effects still queued on its stream, each whole, before it stops, and records
the ones it cannot write. A subscription replaced before its attachment has been sent the beginning
of its stream writes no side effects and records them all. For a direct attachment the beginning is
the whole first screen, so a gap notice, or part of the screen, does not count. For a projected
attachment it is the first frame after any gap notice. A connection that ends, or an authority that
is withdrawn, stops a delivery where it stands, and the effects still queued on its stream go with
it.

The host's own replies to the application's questions are measured on the session's continuous
clock. A reply waits behind the person's open bracketed paste and is dropped after two seconds. Each
time the lane is drained it writes at most 4 KiB of replies, and the rest wait for a later drain
within the same two seconds. A session answers at most 256 questions a second. A step of the wall
clock neither drops a reply early nor holds one longer.

## Windows

The terminal on Windows is a pseudo-console. It is the same session, the same lease and the same
retained history; what differs is the three things this platform does its own way.

**The console, and where byte preservation begins.** ConPTY renders an application's console-API
output into VT sequences before the host sees any of it. So the promise this host makes starts at
ConPTY's output pipe: every byte that arrives there is carried through unchanged, and what an
application did through the console API rather than by writing bytes is whatever ConPTY made of it.
A session never claims to have preserved writes it was never handed.

**The job object.** The worker holds the sole owning handle for one job object per session, with
kill-on-close, and the shell joins that job *before* it runs: it is created suspended, assigned,
confirmed to be held, and only then resumed. An agent the worker's launch starts joins it as it is
created, unless it runs under reduced ownership. Both limits are read back from the
kernel rather than taken from what was asked for. Default breakaway stays disabled, so a child
cannot leave by asking. A vendor sandbox that creates a job of its own nests inside this one;
nesting and breakaway are separate questions, and disabling the second says nothing about the first.
Where the job cannot be created, cannot hold what it must, or does not hold the shell, the **launch
fails by name**: no session is silently given a weaker boundary instead. Section 7's other permitted
outcome, an explicitly selected reduced-ownership execution profile, belongs to an agent and not to
a session: no session is given one, and an agent runs under one only where its launch profile
records `ownership` as `reduced`. A GUI resource that has to outlive the session is created outside
the job and is never ended by closing one. *A vendor's own sandbox*, below, says what an agent's sandbox needs of these
jobs.

A closure says what it could not establish. A job that stops answering, a process the operating
system will not describe, and a termination the kernel refused are each carried into the closure
receipt as a surviving resource, and any one of them keeps the ownership coverage incomplete: a
record that ended says nothing about a boundary that was never read.

**The interrupt, and asking a shell to stop.** There is no foreground process group here and no
signal to send one. The interrupt is the byte the console turns into a control event for whatever
is attached to it, written through the console's own input rather than through the session's, so
it is not queued behind input this host has not yet delivered. What it cannot get ahead of is what
is already in the pipe, which the console reads in order; a console with no room takes none of it
and says so rather than reporting an interrupt that did not happen.

The same byte is how a closure *asks*. The five-second grace period needs a request the shell can
answer, and this platform has no other; force is the step after it, and it is the job object that
carries force to the descendants.

**win32 input mode.** A ConPTY asks for console key records with `CSI ?9001h` and disables them
with `CSI ?9001l`. Both stop here: neither is forwarded to a client, and neither appears in a
snapshot or in a restoration, which are the other two ways bytes reach one. The worker records what
its own backend asked for.

The encoding is `CSI Vk;Sc;Uc;Kd;Cs;Rc_` (a final underscore, not an APC string), carrying the
virtual key, the scan code the console reported, one UTF-16 code unit, the key-down flag, the
control-key state and the repeat count, with all six fields written every time. A reader fills in
`0,0,0,0,0,1` for any that were omitted. Nothing decodes a record and encodes it again with a scan
code this host chose. A client that sends no records sends legacy VT input, which is accepted
without any claim about scan-code fidelity.

What a console inside the session does (`wsl.exe`, an `ssh` client or a nested ConPTY) happens on
the boundary between that console and the one this worker owns, below this host: what arrives here
is whatever the owned console chose to send, and what this host records is that. Restoring the
*client's* console to the modes it had before an attachment is the attach client's own saved mode
words, and that is what a detach writes back.

**What the console path does not do.** The console reader and the encoder exist and are tested, and
the worker selects the ConPTY backend so that a mode request from its own console is recorded rather
than ignored. There is no transport between them: the session protocol carries input as bytes, so a
local attach client on Windows sends bytes rather than typed key records, and the worker does not
choose the encoding per client. A session therefore runs on the legacy VT path. Nothing reports that
at runtime: the engine tracks which fidelity the backend asked for and the reader knows which one it
is reading, but no receipt, diagnostic or client message carries either answer, so this page is where
the limit is stated.

**The standalone start, and signing out.** The standalone start on Windows is one scheduled task
per environment, `KalaReach-` and the first eight digits of the environment's identifier, in the
Task Scheduler's root folder. `kr host startup --set standalone` registers it. Its principal is the
user's own account, and it logs on as the user where the user is signed in, with the least
privilege. It has no trigger, runs its instances in parallel, has no time limit and runs at normal
priority, and its one action runs this installation's `kr-controller` as the environment's starter.
Its description carries the
environment's full identifier, and the principal and the description together say whose it is: a
task under the name that is not this environment's own when kr looks at it is never replaced or
removed. The Task Scheduler changes a task by its name alone and cannot be asked to change one only
while it is what was looked at, so an edit another program or the user makes in the moment between
kr's look and its change is not refused; kr writes what it registers before it looks, so nothing
comes between the two but the Task Scheduler's command starting. `kr new` runs
it when no daemon answers, having left a request its starter takes once, and the starter starts the
daemon, so the daemon and every process it starts are outside the command's jobs. The starter gives
the daemon a console of its own that shows no window, and the console programs the daemon runs share
it rather than each opening a window on the signed-in desktop. A task that logs
on as the signed-in user runs its starter in a job of the Task Scheduler's own that neither kills its
members on close nor lets them leave, so the daemon stays in that job. That holds up only while the
Task Scheduler does not end the job before the user's session ends, and the job's own limits cannot
show whether it will.

The daemon runs in the session where the user is signed in, at the console or over remote desktop,
connected or not, with the user's own credential store. Signing out of that session ends the daemon,
every worker and everything they started, as Windows ends every process of a session at sign-out; a
remote desktop that disconnects without signing out ends nothing. A reboot ends everything too, and
the task stays registered with no trigger, so nothing starts until a `kr new` after the next sign-in.
A `kr new` run over SSH on a machine where the user is signed in nowhere cannot use the task: the
Task Scheduler does not start it, and `kr new` says so.
Removing the task, as `kr host startup --clear` does, ends nothing it started.

### A vendor's own sandbox

An agent the worker's launch starts is in the session's job and in a job of its own. A vendor's
sandbox that makes jobs of its own nests under both: it limits processes, memory and the user
interface, and closing the session's job ends every process it made. Codex 0.155.1 does this. Its
sandbox runs a command as a restricted-token child of `codex.exe` inside the session's job. A child
of that command that asks to break away leaves the sandbox's job and stays in the session's, which
still holds it. The closure reads the session's ownership coverage as complete once the job lists
nothing.

A sandbox cannot start under a job that restricts access to desktops, because it makes a desktop of
its own and the system refuses (`CreateDesktopW failed: 5`). Before a launch starts anything it
reads the limits of the session's job and of the innermost job the worker itself is in. A
restriction it finds is a named launch failure: nothing starts, the vendor's sandbox is left as it
is, and no breakaway is granted. The jobs this product makes carry no such restriction, and the
limits of a job above the worker cannot be read; there the vendor fails at its own start and the
launch reports that exit.

The other outcome is a choice, and it is somebody's to make. A launch whose profile records
`ownership` as `reduced` starts that agent in a kill-on-close job of its own and not in the
session's. The closure lists what that job holds by start identity and ends it, and reads its
ownership coverage as incomplete, with the reason in the receipt. A worker that dies ends the agent
too, since the worker holds the only handle to the job. The choice is no way past a restriction on
the worker's own job, and it never switches the vendor's sandbox off. The `agents` section of the
configuration document (see *Configuration*) is where the choice is written down for a package, and
`kr doctor` reports it; the launch takes it from the profile it is given, and this host starts no
agent through the worker's launch, so no edit to that section changes a launch on this host.
Because the jobs this product makes restrict nothing, the profile is the explicit escape section 7
asks for, and a test builds the job that needs it.

The command route has no such profile: a program it starts runs in the shell's own job. A launcher
whose job restricts desktops declines before it creates the program and says why to the backend,
which keeps the reason on the launch attempt. The typed command then runs as typed, as it does
without the integration.

A launch that meets a session already closing is refused by name before anything is created. A
closure that begins while a launch is creating its agent ends what the launch made, and the launch
fails by name, because a process created in a job that has been ended is not ended with it. The
launch records a reduced agent's job on the session before its process exists, so a closure that
begins at any point reads it. A launch is in flight on its session from the moment the session admits
it, before the application's own configuration is read, until it has committed or undone everything
it made. A closure waits for every launch admitted before it began, and a launch still under way
when that wait ends keeps the closure's coverage incomplete, with the reason in the receipt.

### Running the Windows tests

Two machines run them and they run different things.

**The GitHub-hosted runner** (`windows-2025`, the `windows` job in `.github/workflows/core-ci.yml`)
compiles the whole workspace and its tests with `-D warnings` and then runs what has been qualified
on this platform, one command per step, among them:

```
cargo test --locked -p kr-term -p kr-project -p kr-cli
cargo test --locked -p kr-worker --lib
cargo test --locked -p kr-worker --test windows
cargo test --locked -p kr-shell-integration --test pwsh_windows
cargo test --locked -p kr-shell-integration --lib host::scripted::
```

followed by the repository boundary again on its own, so a result names the system it happened on,
and the `aarch64-pc-windows-msvc` compile. The pseudo-console tests open a console of their own and
drive it, which the runner can do. The two bridge steps need neither a console nor an installed
editor: a named pipe has no terminal behind it, and the PowerShell suite loads the module files
from the checkout and drives the handshake against a real endpoint.

The worker's integration suites that the runner does not run are compiled and not run. They drive a
session the way a Unix pseudo-terminal behaves, and on Windows a number of them fail on that
difference rather than on the code they are checking. Each of the suites that the runner does run
leaves out the cases that need a Unix terminal, a Unix shell package or Git: those cases are
ignored on Windows, and running `cargo test` prints the reason beside each one. A Windows
pseudo-console draws the screen itself, so what a session retains is the console's rendering and
not the sequences the application wrote. It also answers the terminal's queries itself, holds back
an unfinished sequence and a lone Escape, and adds sequences of its own to what it sends, so the
cases that read the application's output, the terminal's echo or its input behaviour are ignored
for that. This platform runs no Git, so a case that needs a repository operation is ignored for
that. One test in the worker's service is skipped on this platform for its own stated reason, which
`cargo test` prints.

What the runner cannot do is the release matrix. It has no interactive logon, no window manager, no
IME and no physical keyboard, so nothing about Windows Terminal, a real desktop session, IME
composition at the keyboard or a GUI logout is established there. Those need a machine.

**The Windows test machine.** Prerequisites, all of which the CI runner also has:

| What | Why |
| --- | --- |
| Windows 11 or Windows Server 2025, x86-64 or ARM64 | the release baseline |
| Visual Studio 2022 Build Tools, the C++ tools for the target, Windows 11 SDK 22621 | the MSVC toolchain the product is built with |
| LLVM, with `clang` on `PATH` | `ring` compiles its ARM64 Windows sources with clang rather than `cl.exe`, so the ARM64 build needs it |
| CMake, on `PATH` | the description crate's inference runtime vendors C and C++ sources and configures them with CMake, so a whole-workspace compile stops without it |
| rustup with `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc` | the two targets the product ships on |
| PowerShell 7 | the shell the product launches, and the one `crates/kr-worker/tests/windows.rs` qualifies |
| Git for Windows | its `usr\bin\sh.exe` is the POSIX shell the test scripts run in; `kr_worker::testing` finds it |

The test list, in the order it is worth running:

```
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p kr-term -p kr-project -p kr-cli
cargo test -p kr-worker --lib
cargo test -p kr-worker --test windows -- --nocapture
cargo test -p kr-project --test boundary -- --nocapture
cargo test -p kr-ipc --lib paths::
cargo test -p kr-shell-integration --test pwsh_windows
cargo test -p kr-shell-integration --lib host::scripted::
cargo check -p kr-ipc -p kr-worker -p kr-controller -p kr-cli -p kr-term -p kr-project \
  --target aarch64-pc-windows-msvc
```

Every command in that list needs the developer environment for the target loaded first, which
`vcvarsall.bat x64` or `vcvarsall.bat x64_arm64` does.

The runner runs the worker's suites one at a time (its library, and the `windows`,
`windows_endpoint`, `listener`, `transport`, `broker`, `gateway`, `agent_service`,
`windows_inheritance`, `command_backends`, `windows_vendor`, `launch_probe`, `question_bindings`,
`questions_answer`, `authority`, `persistence`, `snapshot`, `terminal`, `session`, `local_owner`,
`input_lease`, `fence`, `desktop`, `performance`, `host`, `binder`, `channels`, `connectors` and
`attention_source` suites) and does not run `cargo test -p kr-worker` with every suite, because the
worker's other integration suites are the ones described above as compiled and not run. It also
runs the protocol's library and a named set of the control daemon's cases and suites, among them
its `project`, `network_project`, `shell`, `privacy` and `descriptions` suites, in steps of the
workflow.
Nothing has to be set for the link: `.cargo/config.toml` carries what the MSVC targets need, which
is to leave the static C runtime out of the image and to stop the linker reporting the vendored C
library's missing debug database once per object file. Setting `RUSTFLAGS` in the environment
replaces those flags rather than adding to them, so a Windows build is run without it.

`cargo test -p kr-worker --test windows` is the platform suite: it opens a pseudo-console, starts
PowerShell 7 inside it, resizes it and reads the new geometry back from the application, drains
what the application wrote after it has gone, checks that text needing more than one byte a
character survives the console and the reads it is split across, delivers the interrupt, checks
that the job holds the shell and the processes it started and that terminating it ends the tree,
checks that closing the last handle to the job ends what it holds, and checks that a process
started outside the job survives the session's closure.

### Seeing Windows from another host

A function whose only caller is `#[cfg(unix)]` is dead code on Windows, and neither a Linux build
nor a macOS one notices: both compile the caller. Twice in two days that reached `main` and turned
the `windows` job red on a line no host but Windows could see. The check that would have caught
both runs anywhere, needs no linker and no Windows machine:

```
cargo clippy --workspace --exclude kr-describe-model --all-targets \
  --target x86_64-pc-windows-gnu -- -D warnings
```

It is a strict superset of compiling the four platform crates' libraries for that target: every
other crate, every test target, and `-D warnings`, which is where dead code is reported.
`kr-describe-model` is left out because its inference runtime vendors C and C++ sources, and
building those for Windows needs a Windows C toolchain that a macOS or Linux host has no reason to
carry; that crate's Windows build is what the `windows` job above compiles natively. The
description service it builds on, `kr-describe`, holds no model and is checked with the rest.
`.cargo/config.toml` sets link flags for the two MSVC targets alone, so the GNU target takes nothing
from them.

What no automated suite here establishes, and a person at this machine has to: an IME composing at
a real keyboard; and Windows Terminal, WSL interop and a nested ConPTY across the release matrix.
A vendor's sandbox running inside the session's job, and the closure ending what it made, is run
against the pinned Codex build by the ignored cases of `crates/kr-worker/tests/windows_vendor.rs`
once `KR_NATIVE_CODEX` names its `codex.exe`; the same cases run with a stand-in vendor in the
windows job.

## WSL and containers

A WSL distribution is a Linux host. It has its own control daemon, its own runtime and state
directories, its own environment identity, its own paired endpoint and its own grants, and the
Linux package is what installs it. Nothing about that changes when Windows also has KalaReach
installed, and a person who only uses the distribution runs the Linux command line there and never
touches the Windows side.

What a native Windows installation adds is discovery and pairing from Windows: a list of the
environments this machine can reach, and one command that runs inside the chosen one. That
convenience is the whole of it. Take the Windows installation away and the distribution keeps
working, because nothing it needs lives on the Windows side.

### The process bridge

Reaching a distribution from Windows is an explicit process bridge, not a socket:

```text
wsl.exe --distribution <name> --user <user> --exec <absolute-kr-path> bridge --stdio
```

and an enrolled container is the equivalent against the container's own identifier:

```text
podman exec --interactive --user <user> -- <container-id> <absolute-helper-path> bridge --stdio
```

The child is `kr bridge --stdio` inside the destination. It authenticates to that environment's
own control daemon or session worker over local IPC, and carries protocol frames on its standard
input and output. Standard error stays diagnostic, so a warning there cannot corrupt the stream.

Five things about that invocation are deliberate.

* **It is an argument vector, never a command line.** A distribution called `My Distro`, a
  container identifier beginning with a dash and a helper path containing a quotation mark each
  cross as one element, unchanged. `--exec` is part of this: without it `wsl.exe` hands the rest of
  the line to the distribution's login shell, which parses it again.
* **No Linux socket is opened from Windows**, and no localhost forwarding mode is assumed. The
  helper runs inside the destination, so the socket it connects to is its own environment's.
* **Frames are bounded.** Both directions use section 9's control-frame maximum, and the declared
  length is checked before a buffer for it exists. A frame past the bound is refused, not
  truncated: half of somebody else's message is worse than none of it.
* **No authority is read from the environment.** The helper's rights inside the destination are
  the rights of the operating-system user the enrolment names, established there by peer
  credentials. A forwarded variable confers nothing.
* **Every wait on a helper is bounded.** A destination that says nothing for twenty seconds ends
  the bridge, and the helper is killed with it. A helper still there five seconds after it was
  killed is not waited for either: a refresh names it by its process identifier as possibly still
  running, and records nothing it established.

### What may cross a bridge

The bridges serve locally authenticated command-line invocations only. A request that arrived on
this host from the network is refused before an argument vector is built, and the helper refuses
the same handshake again on its own side. A remote client reaches the distribution through the
distribution's own paired endpoint, which it has.

The ingress the request originally arrived on travels in the opening frame, and the helper reads it
to decide whether this bridge may carry the request at all. A remote origin is refused there, on
the destination's own side, so no arrangement of hops turns a network device into a local owner.

A request crosses at most one bridge. A handshake that says the request has already been bridged is
refused, and so is a carried request that would open a bridge of its own: the destination serves
what arrives over the helper's local connection as an ordinary local request, so the rule is kept at
the hop that knows one was crossed. This version has no federated proxy.

### Opening a bridge to create or attach

The opening frame an invoker writes says where the invocation began, whether it may start what it
needs, and what to reach: the destination's control daemon, or the worker of one session. The
helper's answer carries the destination's own identity, the user it runs as, the build and protocol
version of the process it reached, and a starting point for a session made through the bridge: the
user's home and the helper's allowlisted variables. An invoker refuses a destination whose build
does not share its protocol level before it sends a request, because the frames that follow are
closed schemas.

The opening also says whether the terminal the invoker attaches from takes the clipboard writes the
session asks for. The helper tells the worker, and the worker enforces it: a write that its lease
holder's terminal does not take is sent to nobody, and is a host event of its own kind in the
session's journal, with the selection and the size and none of the content. Nothing between filters
bytes. The declaration only ever narrows what an attachment is sent. A local attach declares nothing
and is sent what a lease holder is sent.

An SSH host is not a process bridge, and it registers differently. Its helper answers one opening
over ssh, which is ended as soon as it has, and that answer is how this host learns the identity and
the scoped channel the helper holds there. The answer is refused when it is the environment of the
invoker or of any other environment this installation holds, which is what a forwarded socket looks
like, and when the user is not the one the record names. A record that is replaced while its helper
is being asked takes nothing from the answer that comes back.

A container's runtime refuses to run anything in a stopped container, so a create or an attach
starts it first, with the platform's own command, and only where one asked. A distribution is
started by running the helper in it. The container tests in `crates/kr-cli/tests/bridged_session.rs`
run a real container through a bridge, a create and a restart where a container runtime is
installed.

### The enrolled environments, and the cached inventory

An enrolment records the identity the platform issued, the operating-system user the helper runs
as, and the absolute path of the helper installed there. The label is what a person types; it
selects a record and is never compared as an identity, so a container destroyed and recreated under
the same name does not inherit the old record. The environment identifier selects a record too,
which is how two records that share a label are told apart.

A container is recorded by the whole identifier its runtime issued. A name is not an identity, and
neither is a short prefix of an identifier: a runtime resolves either to whichever container
carries it now. Anything typed is put to the runtime first, and the identifier it answers with is
what the record keeps.

The identity of a WSL distribution or a container is either given at enrolment or asked of the
destination. Asking means running the helper inside it, which would start a stopped environment, so
the platform is asked first and a destination that is not running is refused: enrolment starts
nothing, and starting belongs to refresh, create and attach.

`environment.inventory` reads the owner-approved cache. Every row carries the environment identity,
when it was last observed, and an explicit status: `running`, `environment_stopped` or `stale`. A
listing contacts nothing and starts nothing, and a cached row is never evidence that a process is
live: the row says it was read from the cache, and only a refresh that found the environment
running says otherwise. `environment.refresh` is the one that asks the platform, and it starts the
environment it selected only when the request asked it to.

Starting a stopped distribution does not revive what was in it. A session that was closed before it
stopped still answers `SESSION_CLOSED`, and that answer comes from the destination's own closure
record. A file left behind in the destination is not one: a worker writes a session's journal while
that session is running.

A refresh of a running environment reached by a process bridge opens one and looks. The helper
starts inside the destination, authenticates to that environment's own daemon over that
environment's own local channel, and answers with the identity it has there; one read crosses and
comes back, because a handshake alone shows only that a process started. What comes back is the
environment that answered, the user the helper runs as, the protocol version it selected and the
largest frame it will carry. An environment that answers with an identity the record does not name
is refused, and the refresh says so rather than recording the answer.

That exchange is also what records the environment's scoped local channel: the acknowledgement
carries the destination daemon's own connection and boot identity, taken inside the environment the
helper runs in, which a forwarded socket cannot produce.

### Named SSH and container environments

An SSH host and a paired remote host are named environments too, and neither is a process bridge.
An SSH user runs the destination command line under their own login, which is genuine local access
there; a named remote host in the application uses that environment's paired endpoint. Asking for
either as a bridge is refused by name rather than served through a launcher that happens to accept
it.

Both still need a helper installed in the target and a scoped local channel of their own. Those two
conditions are reported separately, because neither implies the other and forwarding a socket
supplies neither.

### Independent environment authorities

Each Windows, WSL and enrolled container installation is its own environment authority. Grouping
them so a person can see them together grants nothing: enrolling one here gives this host's owner
no right inside it, and the keys, grants and session identifiers a standalone distribution already
had are kept. Every row in a grouped listing names its own environment, and none of them is this
host's.

A distribution whose configuration selects the network has an endpoint of its own on it, and each
installation keeps its own keys and records, so pairing a device with that distribution pairs it
with no other. Another distribution holds no record of the device, unless the device was also paired
with it, and ends its connection. The networking mode does not change this. The distributions share
one loopback in both modes, so the check is about the endpoints and not about the bridge. Machine
groups follow the same rule. Joining, splitting or merging the groups of two distributions changes
the record each environment keeps of its own group, and the receipt of the step, and nothing else.
The devices each distribution lists and the grants it lists stay as they were, and each device still
reaches only the distribution it was paired with. The acceptance checks this inside two
distributions, once in each networking mode: it pairs a viewer with each one through that
distribution's own owner, connects each viewer to both, and takes the group steps from Windows over
the process bridge.

### The two networking modes, and what they change

WSL networking has two modes. In NAT the distribution holds an address on a network of WSL's own
and reaches the outside through the Windows host; in mirrored it holds the host's own addresses and
a loopback interface shared with it. Which of them the bridge behaves differently in was settled by
measuring both on a host that offers both, rather than assumed: with each mode in effect and
reported by the distribution itself, a bridge was opened to it and a read was carried to its own
control daemon.

The answer is that the mode changes nothing. The invocation opens no socket, binds no port and
assumes no forwarding, so there is nothing in it for a networking mode to affect, and there is no
automatic behaviour for this host to work out: what reaches a distribution is a process it started
there, in either mode.

Reaching an environment over the network is a separate matter, and one the bridge takes no part in:
a remote client connects to that environment's own paired endpoint.

### Running the acceptance

`scripts/e2e-wsl.sh` runs the whole of this on a Windows host with WSL 2, from Git Bash: two
distributions, each with its own daemon, worker, Linux paths and process identifiers; argument
vectors across `wsl.exe --exec`; the bridge from Windows to each; the cached listing of a stopped
distribution; and the bridge in NAT and in mirrored networking, with a viewer paired with each
distribution's own endpoint in each mode. With only one distribution registered, it makes a second
by exporting and importing the first, removes the installation the copy inherited before anything
starts in it, and removes the copy at the end. In each distribution it keeps, the pairing leaves the
loopback network selected, the installation's first owner, and one viewer for each mode. A
prerequisite it cannot meet is a failure, because a run that could not establish these results has
not established them.

The acceptance also runs on a GitHub-hosted Windows runner. `.github/workflows/wsl-acceptance.yml`
builds the Linux set on Ubuntu 24.04, whose C library matches the Ubuntu 24.04 root file system it
imports as the first distribution on a `windows-2025` runner, installs the set there, and runs the
script, which makes the second distribution itself. The root file system is pinned by its digest. A
Windows Server does not offer mirrored networking, so the hosted run sets
`KR_WSL_NETWORK_MODES=nat`, measures NAT only, and prints that mirrored networking was not measured.
The script's default is both modes, a mode asked for that a host cannot offer is a failure, and the
result of a run is the modes it measured.

Step 3 also checks that nothing of either distribution's daemon or worker is in storage the
distributions share. Each socket the process holds open is read from the kernel's table, its
directory is resolved through links to where it really is, and none may be under `/mnt/wslg` or
`/mnt/wsl`. A daemon or a worker with no named socket fails the step, because its runtime root is
then not known. A worker's open file whose path names the product in that storage is counted among the files
it holds outside the distribution. The self-test covers the listing of a process's sockets,
including one bound through a link.

The acceptance will make changes to the machine it runs on - it will set the default WSL version to
2, it will create and delete a distribution and it will bring WSL down to set the networking mode.
It will restore the `.wslconfig` file to its original state at the end of the run. It will delete
any exported images that it creates. The acceptance will upload an artefact that does not contain
any keys for the Windows daemon. The artefact will be set to expire after 3 days.

`scripts/e2e-wsl.sh --self-test` checks that removal on any Linux host, against trees of its own.
An installation is removed whole and nothing beside it is touched, and a name that holds a newline,
or a root whose own name ends in one, is handled as the name it is. A root is removed only after
every check has passed for it and both roots have been measured, so a refusal while measuring leaves
both alone; a root that is no longer the directory that was measured is left, and one removed before
it stays removed. The removal is refused when an input is set but empty or is not an absolute path;
when the helper names a root outside the directories the run mirrored, a name that is not a plain
path, or a root below a home or XDG directory that is not in a directory named kalareach; when a
root is the image itself, or is or holds the home, an XDG directory or the home's `.local/state` or
`.cache`, by a link or otherwise; when a root leads to storage the image does not carry; and when a
root holds a mount of such storage. The mount needs a namespace of the self-test's own, which root
has and a user namespace gives. Where the host allows neither, the self-test says that case was not
run rather than passing it.

## Machine groups

A machine group is a random identifier that the owner uses to show several environments together. It is not a hardware identity. A host name, a serial number, a user name, a path or the environment's own identity never puts an environment in a group, and the identifier is made from nothing but the platform's secure random source. Each Windows, WSL or container installation, and each operating-system user on a shared host, is its own environment with its own control daemon, so each one records its own group and changes it only by its own owner-approved step. A group exists only as the value its members record, and nothing else creates or lists it.

A group grants nothing. No part of the daemon reads a group to decide a right, a route, what a device may see or whom it may pair with. Performing a step to change the recorded machine group will not affect keys, grants, devices, session identifiers, or the environment identity file in any way. If a device is paired with one environment in a machine group, it will not get any grants, visibility, routing, or pairing on other environments in the same machine group. Enrolling an environment to use for a process bridge does not affect the machine group.

### The record

The control daemon mints a machine group for an environment the first time the environment starts, after acquiring the environment's singleton lock and advancing the generation. This is done by generating a new random group identifier, and recording it in the `machine-group` file in the environment's state directory. The file is a small (at most 4 KiB), owner readable and writable JSON file. It contains the environment identity, the machine group, the revision, and the change that wrote it. The revision is 1 for the initial recording, and is incremented for each step. The change is one of `created`, `joined`, `merged` or `split`. A step also records the group the environment left, the verified actor whose authority approved it, the action it came under and when.

A new record is written to a temporary file in the same directory, flushed, renamed over the record, and then the directory is flushed. The name `machine-group` holds a whole record whenever it resolves: the old one until the rename, the new one after it. On Windows the name can resolve to nothing for an instant while a rename replaces it, so a read by the daemon that finds nothing waits for the step that may be replacing the record, then reads again. A step that fails before the rename leaves the old record and says nothing was written. One whose directory flush fails has published the new record and says that whether it survives a crash is not known. The first record is given its name by a link or a rename that never replaces a record that exists, so two first starts cannot publish two groups. A temporary file that a stopped publication left, whose name begins `.machine-group.` and ends `.tmp`, is never read and is removed when the daemon opens the record.

`host.info` and `environment.list` report the machine group (if present) in an optional `machine` member of the response. This member contains the group, revision, last change, and previous group (if present). This is purely read-only metadata, older versions of the client will ignore it, and it won't be included in the response if the machine group cannot be read. Paired devices will also see this `machine` member in the export format of these answers.

### The three steps

`machine.join` moves the environment into a group the owner names. Any identifier is accepted, including one whose members have all left it, because a group is only the value its members record and this environment cannot see the others. `machine.merge` is the environment's part in merging its group into another. A merge of independent environments is one such step on each environment that records the group being merged away, taken over that environment's own connection, so no environment accepts or forwards a step for another. `machine.split` moves the environment into a fresh group of its own.

Each of these steps is approved against a record, which is a group and a revision that the owner of this environment has seen. If the step is not approved against the latest record, the daemon will refuse it with `DRAFT_CONFLICT` and not write anything, and a join or merge into the group the environment is already in is refused with `INVALID_ARGUMENT`. Undoing a step is a join of the group it left, with the step's own result as the precondition, so an undo never reverses a later change.

The steps need `host.manage` on this environment, held by the owner on the environment's own socket or by a paired device whose grant carries it here. No fresh owner confirmation is asked, because grouping grants nothing. A request that names a session or another environment is refused with `INVALID_ARGUMENT`. A step whose authority is already gone is refused before it reads the record for its precondition, so it is not told whether its precondition still holds.

The step's authority must be valid when the record is replaced, not just when the step is requested. It is checked immediately before each attempt at the replacement, and a withdrawal is excluded while the attempt runs; one operating-system rename that blocks past the deadline is not interrupted. To replace the record, the daemon first writes the new record and flushes it. It then holds the table of registrations, asks whether the connection's registration, the authority revision and the action's deadline still stand, and replaces the record inside that hold. A revocation lands wholly before the check or wholly after the replacement, and a deadline that passes while the new record is being written leaves the old record. Where Windows refuses the replacement for a moment because another program holds the record, each new attempt asks again. A step whose authority was withdrawn, replaced or out of time is refused with `PERMISSION_DENIED`, and a retry of that action is answered with the same refusal.

### Retries and crashes

A step is claimed in the receipt store that holds the other actions of the daemon's own, by the actor, the action identifier and a digest of the request. The daemon performs it, keeps its result under the claim, and answers a retry from that receipt on any connection, regardless of which window the retry arrives in. The same action with another request is `ID_CONFLICT`. A step the daemon refused after it claimed the action, including one that could not write, is kept as that action's refusal, so asking again takes a new action. If the daemon refuses a step before claiming the action, because it cannot use the record or cannot confirm the previous change to it, it does not spend the action. A retry on the same connection, inside its window, is refused the same way while the cause lasts. A retry on another connection finds no claim and is refused for its window, so the owner asks again under a new action once the cause is gone.

A step whose attempt ended after it wrote the record and before it kept the result is answered from the record while the record's last change names that actor and action. Before taking each step, and once at the beginning before serving any steps, the daemon will record this answer in a claim. It flushes the state directory first, so a result is never given for a change that a crash can still take back. If flushing the directory or reading the record fails, it will not take any steps and will refuse steps with `STORAGE_UNAVAILABLE` without claiming them, and will answer retries of an unfinished earlier step with `OUTCOME_UNKNOWN`. A retry of a step that has a recorded result or refusal is answered from that record whether or not recovery works, and a retry of a step still running is told so with `RESOURCE_UNAVAILABLE`. A retry whose receipt cannot be looked up, and a receipt that is kept and cannot be read back, are answered with `OUTCOME_UNKNOWN`: whether an earlier attempt took the step is not known. A retry of an unfinished step waits behind the steps in progress and is answered from what its claim holds when its turn comes. If a claim contains no result and the record does not name the action, the daemon will answer retries with `OUTCOME_UNKNOWN` and never perform the action again.

Two outcomes are answered with no path in them, because an answer can reach a paired device. A step that wrote the record and could not flush its directory is answered `OUTCOME_UNKNOWN`: the record shows the change, but whether it survives a crash is not known, and a retry of the same action will return the answer recorded in the step record once the directory has been flushed. A step that wrote the record and could not keep its receipt is answered with its result. Its claim stays unfinished, and the record, which names the step, answers a retry.

### A record that cannot be used

A record that is damaged, belongs to another environment or cannot be created is refused and left exactly as it is, because a group minted over it would be a change nobody approved. The daemon then serves with no group. `host.info` and `environment.list` leave the member out, every step is refused with `STORAGE_UNAVAILABLE` before it claims anything, and the `machine-group` check of `host.doctor` fails, saying what to do. The cause is in the daemon's log, and the doctor says its class and length, since the cause can quote the file.

There is no command for fixing the machine group. If the record is intact, restarting the daemon will cause it to be read again, so the owner restarts the daemon first. If the file is damaged or belongs to another environment, the owner moves the `machine-group` file aside under a name that does not both begin `.machine-group.` and end `.tmp`, such as `machine-group.damaged`, because the daemon removes names of that shape, and restarts the daemon. A missing record is a first start, so the daemon will mint a new group containing only itself. The owner can then join a known group with `kr host machine join`. The damaged file will never be read again. If the record could not be created, the repair is to make the state directory writable and restart the daemon.

### Backup and restore

A backup carries the sessions' data, the device configuration, the checkpoints and the grants, and it does not carry the machine group, whether it is produced or restored. A restore writes no state directory, so it never mints a group, and it leaves a valid group the environment already records as it is.

## Who may type

A session has one input lease with an epoch. `input.acquire` takes it immediately: the epoch
advances, the previous holder's undelivered bytes are dropped, and nothing waits for that holder to
agree. What has already reached the application cannot be recalled, so the count of discarded bytes
is the limit of what a takeover undoes. A write at any other epoch, or from any other attachment, is
`LEASE_LOST`, and it never takes the lease as a side effect: acquiring is something a controller
asks for.

Whether it may hold the lease is a comparison rather than a label. The canonical grid knows which
keyboard encoding the application has negotiated (the ordinary one, `modifyOtherKeys` at a level,
or the Kitty protocol with a set of flags), and the host compares that against what the controller
can produce. A controller that cannot produce it is refused with `INPUT_INCOMPATIBLE` and keeps
everything else it had: it goes on watching, and its typed actions are unaffected.

| Controller | What it offers |
| --- | --- |
| A semantic attachment | whichever protocol is in force, because it builds each key from the logical key and its modifiers through the shared encoder |
| A terminal that declared what it is | what that terminal is known to implement, from `kr_worker::input::KEYBOARD_PROTOCOLS` |
| The companion's raw terminal view, which declares `kalareach-companion` | `modifyOtherKeys` and the Kitty protocol's disambiguation and event types, which it builds through the shared encoder from what its platform reports of each key; not every key as an escape code, because an input method or a phone's software keyboard gives text with no key to report it by |
| A terminal outside that table, but declared | the ordinary encoding, which every terminal sends |
| A terminal that declared nothing, which is what `--no-probe` chooses | nothing, in either direction: a terminal nobody was allowed to ask about is as likely to have been left in an enhanced protocol by whatever ran before it |

The table rests on the same fact `QUALIFIED_TERMINALS` rests on, and carries the same limit: each
row is what that terminal's own documentation says it implements, and a `TERM` name is the client's
claim about which terminal it is rather than a measurement of it. So the rows are conservative. A
protocol a terminal implements only under a setting is not claimed, because the name does not say
whether the setting is on: WezTerm's Kitty support is behind a configuration option that starts off,
so `wezterm` claims `modifyOtherKeys` and nothing more. Nor is a protocol claimed for something that
is not a terminal: what `tmux` forwards depends on its own extended-keys setting and on whatever is
outside it, so it claims only the ordinary encoding. A controller that advertised a protocol and
then sent another is exactly what section 8 refuses to allow.

A controller that builds its own keys is declared for the flags this build's encoder produces, which
is not all of them: alternate-key reporting asks for the shifted and base forms of a key beside the
one that was pressed, and the encoder reports the key it was given. An application that asks for
that flag is served by no controller here, and says so, rather than being sent an encoding one of
them only advertises.

The encoder has one more limit. The Kitty keyboard protocol identifies a key by the code point of
its unshifted form, so a client that reports a shifted character has to say which key produced it;
one that does not is refused that form rather than served a guess at its layout. What the encoder
cannot detect is a character a *lock* transformed (a capital produced by Caps Lock reports no
modifier at all), so a client that has a layout supplies the base key whether or not it thinks a
modifier was held.

The comparison is made again whenever the application changes the negotiation, which it can do at
any moment and without telling anybody. Parsing the output is what tells the host, so an application
that turns an enhanced protocol on takes the keys from a terminal that cannot send it, and one that
turns it off leaves the ordinary encoding, which any declared terminal can send, so that terminal
is eligible again and can ask for the keys. Nothing gives them back by itself. The release is the
ordinary one (the epoch advances, the fence goes out, a paste the lease had open is closed), and
the holder learns on its next write, which is `LEASE_LOST`.

Such a release has no answer of its own to report in, and neither does a detach, so what it
interrupted is carried instead: the bytes that were accepted and never arrived, and whether a paste
the application was inside had to be closed. The next `input.acquire` reports them with its own, once.
A paste is never completed under another actor's lease, and closing the framing does not undo the
part of it the application already has.

Three things that look like input are not: a focus event, a passive scrollback read and an attached
window that is doing nothing all leave the lease exactly where it was. So does the host's own reply
to a question the application asked, which travels on the same path to the terminal and is not a
lease event.

What reaches the terminal is not a record of what was typed. `input.write` is an ordered stream
rather than an admitted action, so no receipt, intent or result is written for a keystroke and
nothing replays one. Nor is delivery proof of effect: bytes written into a pseudo-terminal whose
application is not reading have reached the terminal and done nothing at all.

## Who owns the size

Size ownership is separate from input ownership, and both are separate from observing the session.
The first eligible geometry claim owns rows and columns; eligibility needs a terminal attachment, a
registered claim and the geometry right together, so reporting a viewport confers none of it and a
conversation view, which is semantic and cannot claim, never competes for it.

| What happens | What it does to the size |
| --- | --- |
| A second terminal attaches | nothing: an existing owner keeps it |
| An attachment reports its viewport | nothing; it decides only how that attachment is shown the session |
| The owner resizes at the current epoch | moves the pseudo-terminal and the canonical grid together |
| The owner detaches or withdraws its claim | the oldest remaining eligible claim succeeds and supplies its own dimensions |
| No eligible claim remains | the last geometry is retained, and the next eligible claimant takes it |
| `terminal.geometry.transfer` at the expected epoch | moves it deliberately, and every attachment learns at once |
| An input takeover | nothing |

Every ownership change advances the geometry epoch, and a change that did not happen does not: a
resize the kernel or the session's budget refused leaves the epoch where it was, so a refusal cannot
invalidate every client's next request. A succession is the exception that proves the rule: the
owner did give up its claim, whatever the kernel then said about the successor's size, so the size
goes back unowned rather than to an attachment that has left or has withdrawn.

Dimensions are validated before anything is allocated, against all three of section 8's constraints
at once: 1 to 2,048 columns, 1 to 1,024 rows and at most 262,144 cells, with checked multiplication
so a product that would overflow is a refusal rather than a wrap. The independent maxima are not
valid together. A refusal names the limit it violated and changes nothing about the grid the session
is running at, its epoch included. A session created without a terminal starts at 120x40. A history
page carries at most 1,000 rows and 1 MiB.

Semantic snapshots are held to section 8's three limits, which `kr_protocol::semantic` states: 16
MiB across the parts, sixteen levels of depth and twenty thousand nodes. `agent.snapshot` reads an
agent's retained history, a flat list of at most 4,096 entries, so its depth is one. A part travels
in one control frame, so it is cut to what the reader's connection said it receives once the rest
of the answer is in it, and an entry larger than that on its own is carried with its text cut,
saying how many bytes it left out. The 16 MiB and the node count are spent by one snapshot's parts
together: for each reader and instance a connection reads, the worker keeps what the parts of that
snapshot have carried, and a request from where that reader's last part ended is paid for out of
what is left, while any other request begins a snapshot. A connection keeps at most 32 such
readings, lets one go when its snapshot ends and all of them when it loses its authority, and past
that ceiling lets go of the one continued longest ago. The part that would pass the total ends
the snapshot with a continuation that names the total, 16 MiB, and the entry it stopped at; asked
from there, the rest is a snapshot of its own, so a reader that follows every continuation still
reads the whole history once, in order. An entry's number is never given twice: a history that has
given its last number refuses the next entry with `RESOURCE_UNAVAILABLE` and records nothing.

Each entry also names the binding revision in force and the turn running when the worker recorded
it, so an entry seen under one execution owner or in one turn is not read as another's. When an
answer is built, the binding of the answer is read, which may be later than the binding of some of
the entries in the answer. It is also possible for an entry, recorded during the building of an
answer, to be of a later revision than that of the answer.

Two types of entry name no turn. One is when the entry is built from a report made by the
application about a thread other than the selected thread. The other is when the entry is built from
a report whose hook was started before the report which started the current revision, that is,
before the last change to the selection. On platforms which do not record the start time of a hook,
only the thread is compared. Both of these types of entry may arrive after the selection has changed
and the running turn is not the turn to which the entry belongs. The report which ends a thread is
recorded as part of the revision after the thread has ended. A cut entry keeps both members.

## Action windows and the dispatch lease

Both are the transport's own components (`kr_transport::window`, `kr_transport::lease`), used
directly rather than reimplemented for the local path, and both are measured on the transport's
suspend-aware continuous clock (`kr_transport::clock`).

* The daemon and each worker issue one action window per authenticated connection, bound to that
  connection and to the host's boot. A window is replaced on the live connection at half its
  validity, without being asked for, and arrives as `ControlEvent::ActionWindowRenewed`. A window
  from another connection, or from before a restart, first-admits nothing.
* The accepted deadline of a mutation is the earliest of the window's expiry, receipt time plus the
  requested lifetime, and any applicable authority deadline. What one host process forwards to
  another is what *remains* of it, as a duration: two processes measure on their own continuous
  clocks and neither clock's origin means anything to the other.
* Remote dispatch additionally needs a live lease from the current generation and revision. The
  daemon takes it at the moment it forwards, not when the request arrived, and the lease's own
  remaining time bounds the deadline the worker is given.

### The admission a mutation carries

A deadline checked before a service takes its store lock proves the deadline stood before the
wait, which is not the question. So the daemon builds one **admission** when it accepts a mutation:
the accepted deadline, the authority revision it was admitted under, and the connection it arrived
on. The mutation carries it into its own transaction.

Every service in this host follows one rule, in this order:

1. Take the service's own store lock.
2. Take the daemon's registry lock. Admission and revocation both take these two in this order, so
   none of the three can interleave.
3. Check the admission. It is refused when the accepted deadline has passed, when the authority
   revision has advanced past the one the mutation was admitted under, or when the connection's
   registration has been withdrawn.
4. Write, with nothing awaited between the check and the write.

`Controller::enter_admitted` is steps 2 to 4 as one operation: a service in another crate holds its
own store lock, calls it, and writes inside the closure, so the registry lock is held across the
check and the write and a revocation cannot land between them. `kr_controller::authority::AdmittedMutation`
is what the mutation carries from the moment the daemon accepted it.

`session.create` checks it inside the same critical section as the transition to `spawned`, after
the durable write rather than before it, so a create that queued past its deadline fails its
reservation instead of starting a shell. `session.close` checks it once it holds the worker's
client, which is where the waiting happens.

The authority changes take the two locks the other way round, because the admission is a question
about the registry: they hold the registry guard and take the grant store's lock inside it, and
nothing takes those two in the other order. The check itself is the same, and it happens inside the
grant store's transaction. `grant.create` checks once the parent is resolved and before the grant
and its invitation are written. `grant.revoke` checks once the subtree it is about to withdraw has
been read, which walks every grant this host holds. `device.revoke` withdraws the grants in that
transaction and then marks the device's own record, which is a separate store. When the transaction
withdrew nothing (the paired device whose grant lives in its pairing record), that record is
the whole withdrawal, so the check is repeated before each wait between the two, and a refusal
after the fence has been written down is answered once that fence has run rather than instead of
it. When
the transaction did withdraw something, the rest follows whatever the clock has done since: a
revocation takes authority away rather than granting any, and grants withdrawn beside a device
record still live is the state worth avoiding.

An admission can carry **no deadline at all**, and that is not the same as one whose deadline has
passed. A retry of an action this host may already hold has no freshness: section 9 keeps a receipt
readable after the window that admitted it is gone, so the daemon forwards such a mutation with a
spent deadline and lets the process that owns the record answer it. The authority half still
applies, because disclosing a retained result under withdrawn authority is exactly what the
registration check exists to stop.

Such an admission may be *answered* and may not **write**: `Controller::enter_admitted` refuses it
outright, because what the freshness admitted was the action and nothing can admit a new one
without it. A mutation this daemon performs itself has its retained record here, so a window that
admits nothing has already been past its own answer.

### The revocation barrier

A revocation is complete for a worker when that worker has acknowledged installing the revision
**and** fencing the undispatched actions it affects, or when its execution is confirmed ended.
Nothing else completes it, and nothing ends a process to make it complete: a worker that will not
answer stays `pending`, and the daemon says so.

The acknowledgement carries two lists, because the fence produces two answers:

* the undispatched intents it rejected, which are now `rejected(revoked)`;
* the actions whose dispatch transition had already won the serial race, which are **named** rather
  than counted. The set is defined by the race rather than by the outcome, so an action that
  settled while the revocation queued behind it is named too, and each one's receipt state says how
  much is known about what it did.

Both lists are retained. An acknowledgement lost on the way back is the ordinary case, so the
worker replays what its fence found for a repeat of the same revision, and the daemon accumulates
across passes rather than replacing: a fence that ran in two goes has to have all of it named.

The evidence is bounded, because the acknowledgement that carries it is one control frame. A fence
names at most `kr_protocol::action::MAX_NAMED_FENCED_ACTIONS` actions of each kind and reports how
many more it holds; every one of them keeps its own receipt in the worker's journal, which is where
the complete record lives either way. A revocation whose evidence would not encode is worse than
one whose evidence is partly counted.

The names live in the worker's journal, in a `fence_evidence` row per named action, and not in its
memory, and the position the last completed fence reached is a row of its own in `fence_state`.
That is what lets a revocation's result survive what memory does not: a fence that failed part way,
an acknowledgement lost on the way back, a page whose exchange failed, collection taking the
receipt the name refers to, and the worker's own restart.

A revision advancing is not what finishes a revocation's names. They are kept until the daemon has
taken them, however many revisions have been installed since, because the actions a fence could not
take back are named in the *result*. What the daemon holds is a fact the worker has: an
announcement asks for the page after the names it already has, and that is what the worker writes
down, against the controller generation that said it. A replacement controller holds none of what
its predecessor collected, so a later generation's count replaces the figure rather than being
compared with it, and only a count the generation asking now made is what finishes a revocation's
names.

Keeping them for a daemon that stopped asking would grow the journal a revocation at a time, so at
most `kr_worker::journal::MAX_HELD_REVOCATIONS` revocations have names in it at once, counting the
one a fence is about to name. Past that the oldest go, and the count of what went takes their place
in `FenceEvidence.omitted`, so a page that carries nothing because nothing is left says how much is
missing rather than reading as a fence that named nothing. Those counts are bounded in the same
way, and a revocation older than the oldest count is answered with no evidence at all rather than
with an empty page: absent evidence and empty evidence are different statements, and the daemon
reads the difference. The boundary is written down before the count it replaces goes, so a failure
between the two leaves the conservative answer rather than none.

The daemon keeps its reports the same way, one per revocation rather than one per worker. An older
revocation's result names what that revocation's fence named, and a newer one's lists are a
different question's answer. It also asks again for the pages an older revocation still owes: the
revision in force comes first, and the unfinished ones after it, out of one page budget per
announcement.

A rejection and its name are one transaction. A rejection committed without its name would be an
action the result owes and cannot produce, and the next pass would not find it: a pass selects
intents that are still accepted, and that one is not.

The evidence is delivered a page at a time. One acknowledgement carries at most
`kr_protocol::action::MAX_NAMED_FENCED_ACTIONS` names and says how many remain; the daemon asks
again from where the page ended, through `AuthorityRevisionNotice.evidence_from`, until nothing
remains or it has collected as many pages as one announcement collects, and each of those
exchanges is bounded like the first. The barrier holds on the first
page, because that page *is* the acknowledgement; what the later ones complete is the naming, and
`WorkerBarrier.names_pending` says how much of it has not arrived rather than letting a partial
report read as a complete one.

An announcement that arrives while the worker is inside a dispatch transition is answered with a
refusal that says to come back, and the daemon reports that worker `pending`. The fence takes the
same serial boundary a dispatch does, which is what makes its two answers two answers: it reads an
action either before its dispatch marker, and rejects it, or after it, and names it, never between
the acceptance and the marker. The refused revision is recorded, and the worker's own maintenance
runs the fence inside that boundary, so the fence does not wait on the daemon asking again.

A worker that reports **no** evidence is a third case, and it is not a barrier that holds. Such a
worker has installed the revision and said nothing about its fence, which is half of what section 9
asks for, so the revocation stays `pending` for it with a report that says which half is missing.
Absent evidence and empty evidence are different values on the wire for this reason.

Membership is the registry's durable worker rows, not the verified directory. A worker whose
challenge failed, or that a replacement daemon has never reached, is still recorded and still
pending: a revocation is not complete for a worker nobody can account for. Each announcement is
bounded, because waiting is the opposite of completion, and a worker that runs out is reported
`pending` while the announcement carries on to the next one.

The barrier holds a record of a worker only while something can still ask about it. The worker is
added to the barrier by the daemon when it binds to the worker's control path; the registry is
locked at that point, and the worker is added if the session has no closure on record. A closure
tells the barrier in the same registry section that writes it, so a bind and a closure cannot pass
each other, and a request dropped part way through a closure cannot leave a worker that never ends.

Workers are removed from the barrier when it can be determined that the worker has ended, and no
announcement or exchange that began while it ran is still going. If the worker named actions, its
record is kept until no report at the revision in force (or at the revision a running announcement
carries) would list them. A retry of a revocation whose answer was lost therefore names them again.
At most 1,024 such workers stay at once; if this limit is exceeded then the oldest are removed. This
will cause `workers_total` in replies to be higher than the number of workers listed; only ended
workers are removed so this will not change whether the barrier holds.

`kr_controller::authority::AuthorityBarrier` holds both halves, the lease issuer and the fence
reports, because a lease running out is not a barrier holding and the two are read together.

## The network path

The daemon joins the network once, at the end of its startup, when the `network` section of its
configuration document selects one; the section and its rules are under Configuration above.
`network.enabled` turns it on, and the relay map, the Pkarr publisher, the Pkarr resolver and the
DNS origin are each selected on their own, with nothing inherited from a public service or from
the environment the daemon started in. `network.relay_only` removes the direct paths altogether,
for a deployment where one is not available or not wanted. An edit to the section applies at the
next start. A daemon that selects no network serves its local endpoint alone, which is a supported
deployment rather than a degraded one, and pairs nothing.

### Pairing and the host's owner

A host on the network serves section 23's six pairing methods and the owner-confirmation methods.
The owner's own client reaches `pair.invite`, `pair.confirm`, `pair.cancel` and the owner's form of
`pair.status` over the local socket; an unpaired candidate reaches `pair.redeem`, `pair.finish` and
its own form of `pair.status` on the bounded pre-authorisation surface. An invitation remembers the
owner context that issued it, and only that context confirms, cancels or reads it; since invitations
are issued over local IPC, a paired device is never that context. A candidate whose invitation was
denied, withdrawn or ran out is still told so after the next invitation replaces it: the host keeps
the last 16 such invitations in memory for their candidates. A committed candidate reconnects as the
device it became and reads its own pairing.

**The first owner.** A host starts with no owner. The first owner is established through local IPC
under the logged-in account, by pairing the owner's first device with a personal owner grant: while
the host has no owner, and only for that pairing, an owner confirmation may arrive on the
`local_bootstrap_terminal` channel, signed with a key the local caller presents. That key proves
possession and nothing else. The command line only answers such a challenge at an interactive
controlling terminal outside a KalaReach session, which protects against an agent starting the
ceremony by accident; it is not isolation from other code running under the same account. The
commit that pairs the first owner device writes the owner record in the same transaction, and from
then on the terminal channel is refused for good, even if every owner device is later revoked:
revoking authority must never turn into a weaker way to confirm.

**Owner confirmations.** Six actions need a fresh confirmation bound to the exact action. A caller
asks with `owner.confirmation.request`, naming a subject; the host fills in the action, the digest,
the destination keys and the rights itself. `owner.confirmation.pending` lists what an owner can
still answer, with the full grant and, for a device, its keys and verification value, to the local
owner and to paired devices holding `host.manage`. The project service's location decisions and the
catalogue's two confirmed decisions, trusting a repository root and granting an executable
capability, are confirmed by the same owner devices: their challenges are in the same ledger and
listed the same way, and the proof the caller presents with the decision is checked against the
owner device that signed it and against the answer an owner device already recorded, then spent
into the same acceptance record. `owner.confirmation.complete` verifies a proof
against an enrolled signer (a live paired device holding `host.manage`, on an owner-device channel)
and records the answer, with the caller that completed it and the proof itself. A proof is accepted
once: the same proof completed again under another action, while its challenge is outstanding, is
answered with the acceptance as it stands, and once the challenge is spent it answers nothing. The
sensitive effect then spends the oldest answered challenge whose members equal its own expectation
and whose signer is still an owner device, exactly once; no method takes a confirmation reference.
Session, plugin and contact-tool channels are refused. Confirmations live for two minutes on the
monotonic clock and end with the daemon.

**One action identifier, one answer.** The five pairing mutations, `owner.confirmation.request`,
`owner.confirmation.complete`, `pair.invite`, `pair.confirm` and `pair.cancel`, keep one record of
the actions they answered, keyed by the verified caller and the action identifier, with the digest
of the whole mutation and what it acted on. Each mutation writes its record in the transaction that
writes its effect; an answer that changes nothing, such as a withdrawal of an invitation that had
already ended, writes it before it is given. A repeat is answered from that record and only for the
same payload: the identifier reused with another payload is `ID_CONFLICT`, whichever of the five
methods it was first spent on, and nothing is done under it.

**Authority when an answer is spent.** An owner device's grant is in force under the same time
contract the network admits devices under: a deadline anchored on the continuous clock, a wall
clock that is not trusted once it has gone backwards, and an expiry tombstone that keeps a grant
that ran out from coming back. Revocation, the tombstones and the owner record are read again
inside the transaction that records the effect, before any candidate row is written, and the
anchored deadline is compared there with the clock read at that moment. The mutation's own
admission, its registration and its accepted deadline, is asked in that same transaction, after
every wait before it; a mutation whose admission lapsed writes nothing, and the owner confirms
again.

**Code invitations.** A code invitation reserves a four-character locator at a rendezvous origin,
the one the owner named or this host's default, and shows the ten-character code as
`XXXX-XXX-XXX` beside that origin. The host then keeps a socket open in the locator's room, proving
the reservation's control token, and relays each candidate's attempt to kr-pairing's state machine
under the invitation's one lock: the candidate is admitted with its nonce, the two PAKE messages
cross, the candidate's confirmation tag is verified in the serial path (a match locks the invitation
and closes every competing attempt; a mismatch spends one of five guesses, on disk before the host
answers), the two sealed bundles cross, and the host acknowledges the candidate's bundle. Only then
does the candidate reach the host over iroh, at the endpoint its authenticated bundle pinned, and
bind the transcript with `pair.finish`. The room reads none of what it relays, and a payload that
is not a pairing message ends its attempt on the host before anything behind it is read. The host
releases the locator when the invitation ends, whether the owner confirmed, denied or withdrew it,
its guesses ran out or its deadline passed on the host's own clock; when it ended by itself, the
release waits until the room confirms it closed the last attempts, so the answer a candidate is
owed reaches it first.

**The rendezvous service.** A host contacts the origin a code invitation names, and no other. It
reserves and releases the locator with JSON requests over HTTPS (`POST /api/pair/locator/reserve`
and `POST /api/pair/locator/release`), through the transport the managed services use:
certificates verified against the platform's trust store, finite deadlines (ten seconds for a whole
request), a bounded answer and no redirects. Only the locator travels, never the six secret
characters, and a reservation carries the control token only as its hash. The room socket is a
WebSocket at `wss://<origin>/api/pair/room/<locator>/host`, opened on TLS verified the same way and
proven with the control token in `KR-Pair-Control-Token`; a socket that ends while the invitation is
on offer is opened again a second later. A failure costs the invitation no guess, and is one of two
kinds. It is `RENDEZVOUS_CONFIG_ERROR` only where the answer shows the origin serves no rendezvous:
the service's own `NOT_CONFIGURED`, `NOT_FOUND` or `METHOD_NOT_ALLOWED`; without the service's
envelope, a redirect, a 404 or a 405; or a success that is not the answer to the operation asked.
Everything else is `RENDEZVOUS_UNAVAILABLE`: a name that does not resolve, a connection or TLS
handshake that fails, a deadline, a rate limit, a 5xx page from something in front of the service,
and every other refusal. A host whose platform cannot set up certificate verification has no
rendezvous service and answers a code invitation with `RENDEZVOUS_CONFIG_ERROR`.

**Records.** The pairing records are tables in the registry database, written through the device
directory's connection: `pairing_invitations` (never the code or the direct secret),
`pairing_commitments`, `pairing_events`, `host_owner`, `owner_confirmations`, the acceptance
record of each confirmation answered and the effect that consumed it, and `pairing_actions`, the
action identifiers the pairing mutations were answered under. A completed pairing writes the
device row, its commitment, its security event and its confirmation's consumption in one
transaction. A daemon that starts cancels every invitation it left unfinished before it serves
anything; the consumed state and the failed-confirmation count stay.

**The security outbox.** `pairing_events` holds one immutable row per completed pairing, ordered by
a stable sequence. A row is removed only after every registered consumer has read past it, and none
is removed while no consumer is registered. The environment's attention store is the consumer that
delivers the event to the owner's devices.

Its own network device keys are a separate key set from the environment's controller identity. The
controller identity signs generation tokens to this host's workers; these are the keys a *device*
authenticates, and conflating them would make a worker's view of its daemon and a device's view of
its host the same secret. They live in the platform credential store, with the documented
owner-only directory as the fallback, and are created once: a host that lost them is a host every
paired device would refuse, because its endpoint identity is what an invitation pinned.

What a device reaches, in order:

1. **Unpaired**, it reaches the bounded `pair.*` surface and nothing else. The daemon drives
   `kr-pairing`'s own state machines behind it; the owner ceremony that authorises an invitation and
   approves a candidate is the platform's, and the daemon holds the challenge and the ledger that
   makes it single use.
2. **Paired**, it gets an authorised connection whose actor the daemon constructs: `paired_device`
   ingress, the device, the grant and the revision it was validated at, the controller generation
   that admitted the connection, and the connection's own identity.
3. **Reads the daemon owns** (the host, the environment list, the environment's capability
   records, the diagnostics, the session list, one session's metadata, and the repository and
   workspace metadata) are answered by the daemon, out of the same call a local caller reaches.
   The four host-and-environment reads leave in their export form, with no account name, local
   path or platform message in them; "What a paired device reads of this host" lists what each
   carries instead.
4. **Effects the daemon owns** (creating a session, the repository and workspace mutations, and
   pinning a session's name) are performed by the daemon, on a task that outlives the connection
   that asked. No worker owns them: the first two name no session, and a session's pinned name is
   the environment's metadata, which outlives the session.
5. **Everything a session owns** is forwarded to the worker over a link the daemon opened for that
   connection, under the verified envelope and the deadline the daemon accepted, through the same
   serial barrier a local caller's mutation passes through. That link declares itself a proxy before
   it presents a generation token, so a device's attachment, subscription and input lane belong to a
   connection of their own without displacing the daemon's authority connection.

Each read a paired device may make is decided in one place, method by method: a service answers it,
or it is refused by name with its reason. A test walks the method table and fails on any read the
table admits for a device that is neither served nor refused by name. The reads that go to a
session's worker travel over the one link a connection holds, so a connection reads the questions
and agent state of the session it serves. `question.read` goes to that worker with the history scope
of the device's grant, and the worker holds its answer to that scope through the shared history
filter, as it does for every caller under a grant: a device sees a question asked at or after the
moment its grant reaches back to, in any state, and one its grant names however early it was asked,
while it is open, so a device whose grant keeps no history and names no question sees none. Asking
for one question outside that scope is refused rather than answered empty. The daemon passes the
worker's answer on as the worker gave it, and sends a question read with a scope only to a worker
that says, in its answer to the daemon's hello, that it holds one to it: a worker of an earlier
build answered with every question it held, so a device's question read to one is refused as
`UNSUPPORTED_CAPABILITY` before anything reaches it. The agent reads name their session inside the
subject they read, and that session is the one the grant is checked against and the read is routed
to. `agent.snapshot` and `agent.approval.inspect` carry retained content, so each goes to the worker
with the history scope of the device's grant, and the worker holds the answer to it through the
shared history filter: a snapshot carries what the agent said at or after the moment the grant
reaches back to, and says how much it withheld, and an approval's record from before that moment is
answered as a resource the host does not hold, unless the grant names that approval and it can still
be decided. A worker says in its answer to the daemon's hello that it reads such a scope, one that
names approvals by the broker's resource identity, and one that does not say so is sent none and
refuses both reads itself. `events.subscribe` and `events.snapshot` go to the worker with the same
scope, and the worker holds the resources the broker arbitrates to it by the rule the approval
record follows: a snapshot, every page of it, carries an approval the grant names while it can still
be decided, and any other resource only when it was recorded at or after the moment the grant
reaches back to; a subscription is told a later transition only of a resource it was shown or of one
that rule admits. A grant that keeps no retained history reaches, beside what it names, what is
recorded after the device's first subscription of that attachment began. The local owner, and a read
that comes with no scope, are shown every resource and every transition. `grant.list` answers with
the grants the device issued and everything delegated from them, and it needs `session.share`.

`session.describe` is answered by the daemon from the environment's store of session names,
filtered for the device: the generated text of a description only when the device's grant reaches
back to the session's start, and otherwise the pin or the metadata title (*Session names and
descriptions* has the rule). `privacy.status` is answered by the daemon under `host.manage`.

Three reads are refused as `UNSUPPORTED_CAPABILITY`, with the read and the reason in the message:
`upload.status`, `download.begin` and `download.chunk`, because a transfer's chunks travel on an
attachment-chunk stream and this host opens none on a network connection.

What the grant decides, for every request:

* **Expiry.** A grant that has run out is refused, and once it has been found expired it stays
  expired, so a wall clock stepped backwards revives nothing. What remains of its lifetime is also
  an authority deadline: an action admitted a moment before the expiry cannot dispatch after it.
  Two readings can find it expired: the deadline its connection anchored on the continuous clock,
  and this host's wall clock with the floor under it, which a clock stepped forward or another
  decision can move first. Either way the connection ends with its subscription, and the expiry is
  written to the device's record, so the device cannot connect again. A refusal the wall clock
  decided also writes that floor down. A write that fails is retried by every later decision and
  by the network's record task, and until one lands the floor is owed its record: no decision that
  reads the clock is taken, so a request under a grant that expires, under an organisation's lease,
  under this host's offline bound or on a host enrolled as exclusively organisation-managed is
  refused as unrecorded, while a personal grant that never expires and answers to none of those is
  used as before. A daemon that starts and cannot write its floor starts in the same state, and
  leaves it once a write lands. A daemon that stops before the floor is written starts on the older
  floor; what keeps the device out then is the expiry on its record, which is retried the same way
  until it lands.
* **Selectors.** The environment and the session the request names have to be ones the grant
  admits. A listing names no session, so the *answer* is narrowed instead: a device is told about
  the sessions its grant admits and no others.
* **Rights.** Every right the method requires unconditionally, and every conditional one whose
  condition this request meets: a `session.attach` whose `claim_geometry` registers a claim needs
  `terminal.geometry`. A condition the daemon cannot decide is treated as holding, so the right is
  asked for rather than skipped. *Asking for* a capability is not one of these conditions: it is a
  request the host intersects, described below. The rights are the grant's as this host's policy
  and the rights ceiling its configuration put in force leave them, decided by the one function
  every device request goes through; a right the ceiling removed is refused by its name.
* **Capabilities.** What an attachment is granted is what it asked for intersected with the rights
  this request was decided with, made where the attachment is admitted. See "What an attachment
  may do".
* **History.** Retained history is not served to a device at all: its scope is the grant's lower
  bound, that bound is a moment in time and a history page is a byte range, and a host that cannot
  narrow content to a grant refuses it rather than serving more than the grant allows. The
  session's live screen and the stream that follows it are served when the grant includes them,
  and "the live screen" means the screen that is showing: a device's attachment is drawn the active
  buffer alone, and the rows of the buffer that is not showing are counted among what its
  restoration did not carry. The exception section 10 names is the visible screen, and never the
  inactive buffer, the scrollback or the backing transcript.

What a subscription carries is a read that goes on after it was answered, so the same decision is
taken again, as a subscription to the attached session, before each batch the host writes to it,
and the batch is held to that decision until its last byte goes. A batch can wait: for the
connection's writer, which the keepalive shares, or for a peer that has stopped reading. So every
attempt to hand its bytes over checks that nothing the decision rests on has changed since (any
change to this host's policy or rights ceiling moves an epoch the check reads) and that the
decision's own time bound, the grant's expiry or the end of the offline bound, has not passed:
by this host's reading of UTC, the later of the wall clock and the floor, and by the continuous
clock the offline bound is anchored on. None of these waits for a lock or a disk. The floor is one
value every holder of the policy shares, so a raise made under the policy's lock, a workflow's
decision among them, reaches this check at once. The check also keeps what it reads: its reading
of UTC raises the floor, and a lapse it finds is owed a record, which the relay, the next decision
or the network's record task writes down. Winding the clock back after the check refused changes
nothing, for the batch decided again or for a connection that comes later. While the write waits,
the whole decision is taken again every tenth of a second. A decision that
stops holding before the first byte goes has the batch decided again. One that stops holding once
bytes are moving ends the connection, because a frame left in pieces ends the stream. A batch the
decision no longer allows is not written, and the connection ends with it. Only an expired grant
is written to the device's record; any other refusal leaves the grant alone. A lapsed offline
bound, for one, holds again once the authority feed synchronises, and the device learns why from
the next request it makes.

The bounded offline validity is held on the continuous clock for every device decision, not only
in UTC. The count starts when the policy that holds the bound is restored at start, accepted or
synchronised, whether or not a device ever asks: the daemon notes how long has passed since the
synchronisation, at an instant on the continuous clock. A new maximum keeps the time already spent,
so a shorter bound never ends later than the one it replaces; only a new synchronisation starts the
count again. The time spent is written down for each synchronisation: when the count starts, when
a decision or a relayed write finds the bound run out, and at every mark of the network's record
task. A daemon restarted in the same boot adds the boot clock's time since the record; one started
after a reboot keeps the recorded time and adds only what UTC shows. A wall clock wound back does
not bring the bound back, and neither does a restart: it stays out until the owner changes the
bound or the authority feed synchronises. No grant's expiry is recorded for it, and it moves no
clock floor. The count can only run out early, which is right for a refusal and is no reading of
UTC.

What the subject decides stays the subject's, and the conditional requirements the daemon cannot
evaluate are exactly those: whose subject it is. A device detaches the attachment its own
connection created and nothing else, and it cancels or reads its own action and nothing else,
because the worker enforces both inside its own dispatch barrier: the attachment list is the
connection's, and the receipt journal is keyed by the verified actor and the action together. Whose
attachment a caller may detach is decided before the dispatch marker, so a detach refused for it
is recorded as a rejection; a detach that fails after the marker, as one does when the session's
budget refuses the size the next claim would take, is recorded as an outcome nobody can establish.
The local owner keeps its cross-window detach, because it is the operating-system user the listener
authenticated, acting under no grant; any other caller, one the daemon heard on its local socket
under a grant included, detaches only what its own connection made. An `action.read` names an
action rather than a session, so it is decided over the session the daemon recorded the action's
route to, and goes to that session's worker, which is where the action was performed.

Remote dispatch needs a live lease, and a lease is renewed only after the worker has acknowledged
the authority revision in force. A worker starts having acknowledged nothing, so the daemon asks
*that* worker for its acknowledgement when it opens a proxy link to it and again if a dispatch
finds no lease; asking every worker would make one paused session everybody's wait. The envelope
carries the revision the grant was checked at, and the worker refuses inside its barrier an action
validated under a revision it has since installed past. Local input and stopping owned execution
depend on none of this: neither is remote dispatch.

An action whose fate the daemon cannot establish is reported as unknown rather than as refused. A
frame that reached a worker before the link failed may have been dispatched, so a proxy link that
was interrupted part way through a frame, or that did not answer in time, answers
`OUTCOME_UNKNOWN`: nothing retries it, and the client keeps it on the list of actions whose outcome
it must ask about.

A device that falls behind is told rather than waited for. What the daemon holds for one device is
bounded in bytes, not in messages, at section 9's send queue per peer; a device that reaches that
bound loses its link, which takes its subscription and its attachment with it, and section 8 has it
reconnect and resume from the cursor it holds. Holding the worker's own delivery task instead would
make one slow device everybody's problem.

### What an attachment may do

Section 8 separates three things: observing a session, owning its size and holding its input. What
an attachment is granted is what it asked for intersected with the rights of the grant the request
was checked against, capability by capability:

| Capability | The right that carries it |
| --- | --- |
| `observe_terminal` | `session.view` |
| `observe_semantic` | `session.view` |
| `input` | `terminal.input` |
| `geometry` | `terminal.geometry` |

The table is `kr_protocol::rights::attachment_capability_right`, beside the action vocabulary, so a
right added to the vocabulary has to be decided for the capabilities rather than defaulting into
one. The intersection is made in the worker, where the attachment is admitted, because that is where
the attachment's own record is written, and the summary the caller is given then says what it holds.

Every later operation on that attachment (resizing, transferring the size, acquiring the lease,
writing input) passes two checks, not one. The daemon checks the grant's current rights for the
method, as it does for every request. The worker then checks the capability the attachment was
granted. The second is what the intersection buys: a device whose grant carries `terminal.input`
but whose attachment was admitted without the input capability is refused by the worker, and a
device whose grant has since lost the right is refused by the daemon.

Asking for a capability the grant does not carry is not a refusal. A client that asks for
everything it can use gets an attachment without the parts its grant does not reach, which is what
an intersection is for; registering a geometry claim is the separate thing, and that does need the
right before anything is admitted.

Exactly one caller is not narrowed: a local caller on the worker's own socket holding no grant. Its
peer credentials already proved it is this user and the worker's own authority covers its session.
Everything else is narrowed, so a caller that reached the host some other way and named no grant
receives nothing rather than everything.

### Repositories and working copies over the network

The registry admits a paired device to the ten project and workspace methods, and the daemon serves
what it serves a device through the same call a local caller reaches, so a device's `project.list`
and the owner's are one answer. The four methods that keep the owner's authorised locations are
served on the local socket alone. The mutations take the daemon's own path: the envelope is checked
first (a project acts on a repository or a working copy, so a target naming a session or an
application is refused), then the action's route is recorded with this host named as the owner of
what it produces, and the effect runs on a task a dropped connection cannot cancel part way.
`Controller::project_mutation` is the one place either door reaches the service from, and it asks
about the admission the ingress recorded immediately before the write.

What a device is additionally held to is its grant, and `session.view` for the two listings. A
listing is narrowed to what the grant admits rather than refused: two grants over one host list
different repositories and different working copies, and a working copy's bound sessions are
narrowed the same way. `project.read` and `workspace.read` name one subject and require no right of
their own, so they are refused outright for a subject in an environment the grant does not cover
(a narrowed listing is not a way to find an identifier an unnarrowed read would then answer for),
and the session content they carry is narrowed exactly as the listings' is.

**A paired device is served the five repository operations on a Linux host that has proved it can confine Git, and is refused them on every other host.** The five are `project.init`, `project.clone`, `project.adopt`, `workspace.create` and `workspace.remove`, and each runs the Git program. This host bounds every name it resolves itself to the directories the owner authorised, each reached through a handle it holds. It bounds what Git reaches once Git is running only where it can show that it does. The daemon shows it when it starts and again at each `host.doctor`, by running one Git invocation under the rules a device's invocations run under. That one run needs four things at once: Landlock at filesystem version 3, rules with no ambient read, the loaders and libraries of this host's Git named object by object, and a mount table with nothing mounted beneath a directory the invocation is granted. The door reads the last answer.

A host that has not proved it refuses the five before the project service is reached. That covers macOS and Windows, a kernel older than 6.2, a host that cannot name its support set, and a host whose mount table puts a filesystem beneath a granted directory. The refusal is `PERMISSION_DENIED` with one sentence, which says that this host cannot confine what the Git program reads and so does not run it for a paired device. It names no library, path or mount. `host.doctor` says which of three causes stopped the proof, in sentences this build wrote, and the daemon's own log carries the detail.

Where the five are served, a device reaches only the locations the owner authorised for its own grant. The owner authorises each one on the local socket, and the confirmation is bound to the four public keys of the device that holds the grant, so a device that has not declared all four keys has no location until it declares them with `device.keys.complete`. A device names a location and a name beneath it, never a path. The owner's own locations, another device's locations and a path the device spells out are each refused with the project service's own sentence, and a device never clones a remote, because no location says which providers this host may reach for it. Every Git invocation such an operation causes reads only the directories it is lent and a support set named for this host's Git, and the admission the operation was accepted under is asked again inside the transaction that begins its effect.

The confinement is a promise about what the device's own request can reach through repository content: a symbolic link, an alternate object store or an included configuration file that leads outside the location, and a descriptor left open, are each refused. It does not make the location's tree private. A filesystem mounted beneath a granted directory while Git runs, a program running as this host's user account, an automatic mount that Git's own lookup of a path sets off, and a hard link already inside the tree are all read as part of the tree, and the owner accepts that residual when authorising a location for a device. `crates/kr-project/README.md` states it in full. `host.doctor` reports what it finds of the routes by which a mount could be added, which are unprivileged user namespaces, a setuid `fusermount`, automounts and mount units configured for the account. It reads the mount table, the filesystem table, and the unit directories of the administrator and of the account, and not the units a package installs. It says that these narrow the residual and do not close it.

Every grant keeps the rights it names. A device keeps the four reads, and `project.operation.cancel` for work it started itself.

A paired device is served three of the change-set group's methods: `changeset.read`, `changeset.materialize`, and `diff.read` of a recorded version. None of them runs Git or reads a working tree. `diff.read` and `changeset.materialize` answer from the version's captured content in the change-set store, and `changeset.materialize` writes it into a private directory of the service's own, inside the daemon's hold of the connection's admission, so a grant withdrawn while it waits leaves nothing behind.

A device names a version, and the daemon serves it only when the version is inside the device's grant. `changeset.read` is held to the same check. Its environment has to be one the grant selects. Its session has to be one the grant selects, and where the grant names sessions rather than every session, a version that records no session is out of scope. It has to have been captured at or after the moment the grant's history reaches back to, and a grant with no lower bound retains none. A version outside the grant's environments or sessions and a version that does not exist are refused in the same words, so a device learns nothing about which identifiers exist; a version that is inside them but older than the history reaches is refused with a sentence that says so. A workflow is held to the same rule, with its own scope in place of a grant's.

No answer to a device names the directory of a materialisation. A materialisation is shown by its identity, and the directory's path is replaced by a marker that gives only its class and length. That holds for the answer to `changeset.materialize`, for a repeat of it answered from the record, and for the materialisations that `changeset.read` lists, and a refusal that comes out of the change-set service reaches a device with its code and the class and length of its text.

`changeset.capture`, `diff.apply`, `diff.revert` and `diff.read` of a working copy are refused to a device. Each reads or writes a working tree by running the Git program, and the change-set service does not run it inside the boundary that confines what Git reads for a device's repository operations. The refusal names the method and says so, and it comes before the subject is looked up.

That cancellation carries the device's grant into the project service, so the service knows the
caller is bounded: it reaches only the device's own operations, and it may not name a location to
reconcile an operation through, which is the owner's route to cleaning up after a withdrawn
location. For a caller on the machine's own socket the authority is the user's own over the user's
own filesystem: the five run as they always have, and may be bound to locations the owner
authorised, which `docs/project/README.md` describes.

What a resolution establishes, for the owner, is that the directory it opened is the one the effect
writes into, by the identity it recorded, so nothing is substituted underneath it.

There is one further limit.

* **`action.read` does not answer for a create or a project mutation.** A receipt lives in the
  journal of the session an action was performed on, and a create or a repository mutation belongs
  to no session. What such an action leaves is kept by the service, which is not a receipt in the
  shape that method answers with, so the request is refused and the refusal says how the outcome is
  obtained: submit the action again under the same identifier. That is the recovery section 9 puts
  first, and it works: the service answers the repeat from its own record without performing
  anything twice. The plugin catalogue is the exception, because it keeps its actions' receipts in
  that shape, and `action.read` answers them.

The admission a project mutation carries is asked about three times, and the third is the one
section 9 is about. It is asked once where the daemon accepts it, under the registry lock. It is
asked once inside the service's own blocking work, immediately after it has failed to find a
retained record and immediately before it acts. And it is asked once **inside the transaction that
begins the effect**: the transaction that writes the operation row, the one that writes the
workspace row, and the one that reserves a removal. Each reads the fence this host owes, the
registration and the clock from memory, so asking costs nothing. A withdrawal whose fence could not
be raised leaves every registration standing, which is why the fence is asked there too. Every
service that acts after such a wait asks this same check. A retry never reaches any of them, because
the retained record answered first.

The third answer is what covers the service's own preparation. Resolving a destination, probing it,
opening a repository and surveying it, and taking the journal's lock all happen after the second
answer, and a revocation or an expiry completing in there would otherwise reach an action that then
begins. Inside the transaction there is nothing left to wait for: the journal is held, the check is
answered, and the first durable write follows with nothing awaited between them. An action refused
there claims nothing in the project journal, so there is no half-performed effect to reconcile; the
daemon records the refusal against the action identifier, and a repeat of that identifier is
answered with it rather than performed. Section 9 asks for authority and expiry to be
revalidated immediately before the effect, and that is where they are.

## What the host owes the transport

Two contracts `docs/transport/README.md` names, and where they are kept:

* **Admission and revocation.** The daemon validates the caller's record and registers the
  connection in one critical section, in one lock order that a revocation also takes, so nothing
  can be admitted against authority that has already been replaced. One authority store holds both
  ingresses, so a revocation fences a paired device and a local caller through one table.
  Withdrawing a registration fences that connection's reads, its dispatches and its subscription.
  Every frame a network connection sends is decided and written behind one turn, and a withdrawal
  sets that turn's latch before it closes the connection, so no write begins after the authority
  behind it went; the withdrawal itself never waits for a peer. Revoking a device withdraws its
  registrations and releases what its connections owned at their workers *before* it writes
  anything, because the fence is the step that cannot fail; the record's revocation and the
  authority revision then move in one critical section, so no connection can be admitted between
  the two. What it fences is that device's connections, because nobody else's authority was
  withdrawn. At a worker, binding a newer controller generation withdraws the
  previous connection's registration, which stops the subscription it had already started; the
  connection stays open so its next request can say why it was refused.
* **Work that must complete.** A mutation's effect runs on a task that outlives the connection, so
  a durable commit is never left half done because the caller went away. So does the release of
  what a remote connection owned at its worker, because the handler is dropped the moment the
  control stream ends. The worker's own dispatch path holds no await between the marker and the
  outcome, so it cannot be cancelled part way.

## Journals and the receipt contract

Each worker has its own SQLite journal in write-ahead-logging mode with full synchronisation.

| Table | What it holds |
| --- | --- |
| `receipts` | one row per `(verified_actor_id, action_id)`: method, revision, state, rejection reason, payload digest, subject digest, accepted deadline, the boot and continuous instant it was created at, error, timestamps |
| `fence_evidence` | one row per action a revocation's fence named, in delivery order: the revision, the position, whether it was rejected or is possibly executed, the actor, the action, and for a possibly executed one its method and receipt state |
| `fence_state` | one row: the journal event position the last completed fence reached, which is where the next one starts looking |
| `fence_delivery` | one row per revocation whose names are still accounted for: how many its fence produced, how many the daemon has taken, and the controller generation that took them |
| `fence_forgotten` | one row: the revision up to which this journal can no longer say what a fence named |
| `host_time` | one row: what the host time contract has to survive a restart - the last qualified checkpoint, the trust the clock stands at now, the furthest reading it could prove, and the expiration tombstones |
| `results` | the result a duplicate request must receive back |
| `observations` | additive evidence about an action: its provenance, the subject and version it saw, the source cursor and what it claims |
| `closure` | the session's final record |
| `session` | the session's own summary, so a reader with no worker can still say what the session was |
| `host_events` | an application notice that had no attachment to go to, and where in the output stream it happened |
| `outbox` | the event each state transition committed with: its immutable identifier, the stream, the subsystem, the actor and action, the subject revision and the content class |
| `outbox_cursors` | one row per consumer: how far it has taken the outbox and how much it has taken |
| `journal_gaps` | one row per interval durable writing was unavailable, so no reader reads continuity across it |

The order is the contract. The intent is committed before the caller is told it was accepted. The
dispatch marker is committed before the effect.

**Everything the host can decide is decided before the marker.** There is no
`dispatching -> rejected` edge, because past the marker nothing may imply that an uncertain side
effect did not happen. So a refusal the host is able to reach on its own, a stale geometry epoch, a
lease somebody else holds, a cancellation of an action that has already been dispatched, happens in
the revalidation rather than inside the effect, and the receipt it leaves says `rejected`.

**Recovery is two rules.** A marker with no authoritative outcome becomes `unknown` and is never
dispatched again, because nothing can establish from here whether the effect happened. An accepted
intent with no marker is *rejected*: section 9 lets it proceed only if the revalidation still
passes, and the freshness it was admitted under cannot be revalidated after a restart, because the
deadline was decided on a continuous clock this process no longer has and the connection and the
window that admitted it went with the process that issued them. Rejecting it also releases the
outstanding-mutation capacity it was holding.

**De-duplication records are kept for 30 days**, pruned while the worker runs rather than only when
it starts. Retention is a wall-clock period and the wall clock is the thing that can move, so a
record this boot wrote is kept while a window that could admit its exact original request may still
be live: a window lasts at most five minutes on the continuous clock, and no step of the wall clock
shortens that. A record from an earlier boot needs no such guard, because the windows a host issues
live in its memory and a host that has restarted can admit nothing through them.

An observation is evidence, not an execution state. Only an authoritative answer about an uncertain
outcome moves a receipt, and an inferred screen never does: a screen is what the host parsed, not
what the interface that owns the subject said. "Observed" in a user interface means evidence was
observed.

A new action identifier cannot silently take an uncertain outcome's place. The journal stores a
**subject digest** beside the payload digest: the method and version, the complete target and the
parameters, and nothing that differs between a first attempt and the later request that supersedes
it. So a fresh identifier for a subject that already carries an uncertain outcome is refused unless
its preconditions name that action and the receipt revision the caller read it at. A service that
wanted to hide the uncertainty would have to name the receipt it was hiding.

One actor holds at most eight admitted, unsettled mutations at once, lowered by whatever the
connection negotiated. That is section 9's figure, and what it bounds is durable admissions this
host still owes a decision on. A connection that offers to hold none is refused at the handshake
rather than read as one, and a connection that offers more than eight does not get more. Eight is
this build's ceiling: there is no host configuration that raises or lowers it.

The concurrent-attachment limit is kept per session in this build, while section 23 states it per
host. One session is the whole of what a worker serves, so the two are the same figure for a
single-session host and the per-host bound is the stricter of the two once a host serves several.

Raw input is not in these tables. Section 9 makes it a separate ordered stream keyed by connection,
lease epoch and sequence, with nothing replayed on reconnection.

### What a reader is shown of a retained answer

When a worker performs an action, it stores the result so that a duplicate request and `action.read` can answer from it. Reading it does not change it: an identifier is settled once, and a read writes nothing. Two cases keep no result. The result of `question.create` carries the caller's token, so the worker keeps the receipt without it. Privacy mode removes the result a settled receipt carries. In both cases a repeated identifier gets the receipt as it stands. What a reader is shown is decided when it asks, and for that reader alone.

Owning an action identifier names a receipt. It does not keep access once the grant behind it is narrowed or revoked. A paired device is shown a retained answer only while it holds `session.view` over the session the action was performed on, and a device without it is refused. The daemon decides that again where it writes the answer, so a lease that drops the right while the answer waits gets a refusal instead. Where content is included in the answer, it passes the shared history filter, by the dates the content carries and never by the receipt's later date. A question asked at or after the moment the grant reaches back to is shown. A question the grant names is shown in the first answer while it is open, to a device that holds `session.view`. A retry made after it ended shows it only if the grant's history reaches it.

The caller that performs an action always gets its state in the first answer: the outcome, the identifiers and the revision. A later reader is shown the state under the authority above. Content that is held back is marked as held back, except a close's description, which is left out. A question's resolution carries `question: null`. A receipt's error keeps its code, its retry category and its diagnostic identifier, and its message is replaced and `error_withheld` is set, because a message can quote an upstream or a session and has no date to hold to a bound. The errors that the daemon's own stores and the catalogue retain are the exception: they keep their message, under the decision of the method that kept them. A caller that arrives with no history scope is shown state alone. Only the local owner is shown everything.

Answering a question needs more than the right to answer. The worker refuses a question the caller's history does not reach, with the refusal it gives for a question it does not hold, so the refusal says nothing about the question's state or text.

The archive follows the same rule for a closed session: its receipts go whole to the owner at this machine and as state to anyone else. A close's description of the session reaches a device only when its history reaches back to the session's start, while the daemon keeps the whole description for its own directory. A control daemon speaks to a worker only at its own compatibility level, so a worker at another compatibility level never answers a device through it. [Updating a host](updates.md) says what an update does about that worker's session.

### What each store promises

`kr_worker::persistence::stores::STORES` is that table as data. Each entry says how much of a crash
its store survives, what it keeps and for how long, what class of content it holds, what protects it
where it lies, who removes what it no longer needs, how it is brought back into agreement after a
restart, whether a history byte cap may evict it and whether the archive serves it afterwards. It is
data rather than prose because the rules it states are checkable: a test walks the journal's own
tables and refuses one with no declaration, and another refuses a declaration that would let a byte
cap reach authority or dispatch data.

The rule that does the most work is that last one. **Authority, dispatch and causal-budget data
cannot be evicted under a history byte cap.** A host under output pressure that dropped a dispatch
marker to make room would forget that an action had been sent, and the next retry would send it
again. Only the retained output and the host events an attachment never saw are evictable that way.

### What waits for a flush, and what never does

Section 24 names three commit points that must be durable before something else happens: the
intent before the acknowledgement, the dispatch marker before the effect, and the outcome with its
receipt revision, its event and its outbox record. It permits safe grouped commits to share a
flush; it does not forbid grouping these with each other. **This build commits each of them on its
own**, which is its own policy rather than something the section requires.

They are not the only writes a caller may need to wait for. When a caller turns privacy mode on, it
must wait for the generation to be recorded in the store. Similarly, if the caller creates a session
while privacy mode is on, it must wait for the store to record the session's obligation. Finally, an
answer that says a session has closed waits for the store to record the closure, because in each
case the answer would otherwise claim something the store had not yet taken. Section 24 forbids a
per-keystroke, per-output-byte or ordinary prompt and command telemetry event from waiting for an
fsync, and this host goes further with the first two: a keystroke and an output byte write no
durable row at all. The live parser is in worker memory and the retained output is a bounded indexed
spool.

Grouping is the transaction. A receipt transition writes three rows (the receipt, its event and its
outbox record) in one transaction, so three rows share one flush and either all three are durable or
none of them is. That is what section 24 permits by "safe grouped commits may share a flush", and
the invariant that makes it safe is that a commit point is never grouped with work nobody is waiting
on.

### The outbox, and what reads it

Every state transition commits a small event record in the same transaction. Consumers read the
outbox from a cursor of their own, and delivery is at-least-once: a consumer that takes a page and
dies before recording its cursor takes the same page again. The event carries an immutable
identifier so the consumer can apply it once.

The cursor orders this journal's own events and nothing else. There is no global cross-database
order here and nothing invents one: an event from the transfer journal and an event from this one
are not comparable.

Collection is by delivery rather than by whose receipt an event belongs to. An event goes when it
is past the retention period *and* below every registered consumer's cursor, so a receipt written
thirty days ago whose outcome event was written this minute does not take that event with it. A
consumer that has never registered a cursor has no claim; one that intends to rely on this
registers before it starts.

### When the journal stops answering

A worker whose journal stops answering is not a worker that stops. The condition it publishes is
`kr_worker::persistence::fault::JournalHealth`, and what reads it decides:

| Condition | What proceeds |
| --- | --- |
| healthy | everything |
| faulted | an authorised stop, raw terminal input and interruption under the live lease, and every read |

Everything else is refused before dispatch, which keeps the refusal a rejection rather than an
uncertain outcome: nothing was sent, so the caller is told no rather than told nothing. The two
exceptions are section 7's, which keeps an authorised stop available with `durability=volatile`,
and section 11's, which keeps the native terminal usable. Neither authorises a hidden rich retry.

A fault is classified from the store's own result code rather than from its message: a full store,
a store whose pages are corrupt, a store that is absent, and a write that failed for some other
reason. A full store is told apart from a broken one because a person can act on it.

**Recovery writes the gap down before it clears the condition.** The interval durability was
unavailable becomes a `journal_gaps` row, and only then does the journal call itself healthy; a
recovery whose gap could not be written is not a recovery, because the record would read as
continuous over an interval this host knows it did not write. A store whose *content* could not be
read stays faulted until the store itself says its pages are sound.

### Migrations

Migrations are forward-only, transactional and keyed by a schema version.
`kr_worker::persistence::migration::LADDER` is the list of steps, each one transaction, each moving
one version, and whatever opens a journal brings it forward through them. The ladder is a window: it
starts at version 2. A store a newer build wrote is refused rather than read, because reading it
would mean guessing what a column this build does not know about means. A store older than the
ladder is refused too, wherever it is opened, and the refusal names `kr host import-journals`: the
explicit importer, which reads exactly the two shapes the builds recording version 1 wrote and
brings such a journal to the current schema once, in one transaction, while the environment's daemon
is stopped and no worker can hold it. Whether a worker may still hold one is read from the
registry's worker rows and closures, with the registry read as it is (`Registry::open_to_read`,
which reads the file alone as immutable, writes nothing, not even beside it, and refuses a registry
whose write-ahead log still holds writes or that is reached through a link), and from the
descriptor; a source it cannot read, the registry included, refuses the journal. It checks the
version and every object against the statement one of those builds ran to make it, reads every row
as the running host reads it, names anything it cannot read, and leaves a refused journal exactly as
it was; a failure after it has begun changing the journal goes back with its transaction.
After a migration or an import, the code that reads the worker journal reads one current schema, and
no branch of it reads two. Not every store works that way. The project, delivery, transfer and
grants stores each bring a store that an earlier build wrote forward when they open it, and the
project store also adds any nullable column that a store at its current version lacks. The contact
skill's installation records are still found under the name an earlier build gave a user record. A
comment at each of these paths says what it serves and when it can be removed.

Similarly, the registry moves through its schema versions one step at a time, in order. The step
from version 6 to version 7 takes out of every recorded create request the environment variables its
creator sent, which earlier versions of the registry recorded as part of the reservation, and a
request that is already in the current shape and holds none is left as it is. A request in the shape
that a build from before the launch profile was recorded wrote is rewritten in the current shape,
and a request that is in neither shape cannot be shown to hold no variables, so it is cleared. After
the rewrite the old bytes are still in free pages and in the write-ahead log, so the registry then
runs `VACUUM` and a truncating checkpoint, and only then records version 7. A run that stops before
then is made again from the start, because the step can be repeated. If `VACUUM` cannot finish, the
daemon does not start. The error says why, and when the disk is full it asks for free space in the
registry's directory and in SQLite's temporary directory, each up to the size of the registry file,
and then for a new start. If the log cannot be taken in because another connection has the registry
open, the daemon does not start either, and the error says to stop whatever else has it open and
then start the daemon again.

## Retained output, and what eviction leaves behind

Section 20 gives retained session output three bounds, and all three hold at once: seven days, a
1 GiB host-wide cap and a 128 MiB per-session cap. They are simultaneous upper bounds rather than
reserved capacity, so a session well inside its own 128 MiB is still evicted when the host is over
1 GiB. "The first applicable limit" names which bound is doing the work, which is what a person
looking at a gap is told; it does not mean checking one instead of the others.

The session cap is the spool's own capacity, and it holds before the write: an append gives up the
oldest segments to make room for each piece before that piece is written, so no append stands over
the bound, and the range it gave up reads as a gap whose cause is the session cap. A spool that
cannot make room (a segment it cannot remove or a boundary it cannot write) or cannot open or write
a segment stops taking output at that cursor rather than writing past the cap. It keeps everything
it holds: those segments are still counted, still served, collected by every retention pass and
removed by a purge, and a pass that could not remove one says so. While it is stopped, the resident
window keeps new output only within the room the spool has left, so the two together stay within the
cap, and the range neither keeps reads as a gap with the cause `spool_unavailable`. A retention pass
that finds the spool can make room again writes what the window still holds past the stop and lets
the spool take output again. A boundary that could not be written is tried again by the next append
as well, which does not wait for it, because another program can hold that file for a moment: the
first append after it is let go writes it and gives up the oldest segments.

The host bound is applied on the worker's maintenance tick, from a reading of the environment's
whole spool directory, so two sessions writing at once can take the host past it until the next
tick. It is not a reservation, and it is not enforced ahead of the write.

Eviction is not quiet. A retention pass records the cursor range it took and the bound that took
it, and a reader asking for a cursor inside that range is told both: `history.page` returns the
range as a gap with a cause. A spool that has evicted everything writes down where its output got
to before it deletes what supports that, so a session reopened over an empty directory continues
its cursor and reports the range that went rather than starting again at nought. The boundary it
writes is where the session's output reached, including output the spool did not take.

A hole *inside* the retained range is reported too. A range between two segments that nothing holds,
whether a segment deleted from under the session or lost with its disk or a newest segment gone past
the boundary the spool recorded, reads as missing: a page stops before it, and a page at it returns
the range as a gap, with the cause this host recorded for it or `archive_incomplete`, and goes on to
the bytes after it. A segment file that goes while the session has its spool open is found the same
way when a page reaches it, and the next retention pass forgets it, so the session is no longer
counted as holding it. That pass first lets go of the handle the newest segment is written through,
because Windows keeps a removed file until its last handle closes, and the next write opens the
segment again only where it still is: a segment that has gone is never made again, empty, under its
old name, and the spool stops at that cursor until the next pass forgets it and writes what the
resident window kept into a new segment. A session's retained bytes are what its segments and its
resident window hold together, counted once, and the archive's own account names every hole beside
the range before the oldest cursor.

Removing output because it is old is expiry-based collection, so section 9's rule applies: a host
that cannot prove its wall clock does not do it. The caps still apply, because they are about bytes
rather than about time. The seven-day line is approached from the safe side: a spool segment goes
only when its newest byte is past the deadline, and the resident window advances only to an interval
whose newest byte is past it. Both a segment and a resident interval are bounded in how long they go
on for (an hour and a minute), so what is kept past the deadline is bounded by that rather than
removed early.

An eviction publishes the boundary before it deletes what supports it, and a boundary this host
could not write stops the eviction rather than losing the record of where the output reached. A
boundary that is written and cannot be read back is a host that does not know what it is missing,
and every page it serves says so.

Receipts are not part of any of this. Section 20 gives them a separately budgeted store and 30
days, so history pressure cannot delete a live dispatch barrier or a de-duplication record.

## The archive service

A closed or crashed session's history, final receipts and retained resource references belong to
the environment archive service, which is a controller module and not a surviving worker.

**Ownership is taken, and only after the worker is gone.** The archive asks the kernel whether the
recorded process is the process that was recorded (both the identifier and the start value, because
the kernel reuses identifiers), and only a confirmed ending is death. Then it removes the worker's
published endpoint and descriptor, and only then is anything opened. The order is that way round
because the answer can be *no*: a daemon that fenced before it asked would delete a working
session's socket on the way to finding out that it was working. A query the platform declines is not
death either, and the archive leaves the session alone.

The removal is best effort, and the answer is one value: whether either half went. It does not
say which. What makes the stores safe to open is the death this host confirmed, not the socket
file: a worker the kernel says has ended cannot answer a socket whether or not the file is still
on disk.

A read of a closed session asks the same question first. A session this daemon has verified is
refused with the endpoint to ask; so is one whose registry record names a process the kernel still
describes, because a worker this daemon failed to verify at startup is absent from its directory
and not absent from the machine. Ownership has no token that the read methods require and no lock
that spans one recovery, so it is a rule this daemon keeps rather than one the store enforces, and two reconciliations of one session inside one daemon are not kept apart.
Removing the endpoint is also best effort: a descriptor or a socket this host could not unlink
leaves the fence reported as taken with one of its two halves undone.

**A reader cannot create a worker.** Every read the archive serves is a read of what is already on
disk. A history request never starts an execution, and a retried create is answered from the
reservation the first one made.

**A lost or corrupt journal produces an explicit incomplete archive.** Not an error and not an empty
success: the archive names what it could not account for: a missing journal, one it could not read,
a closure or summary that did not survive, a range of output that is gone, or an interval durable
writing was lost, so a reader is told the record has holes rather than reading continuity into it.
"This session kept nothing" and "this host cannot say what this session kept" are different answers
and a reader is owed the second one.

**A worker crash closes the session.** The controller takes recovery ownership, runs section 9's two
recovery rules over the journal the worker left (a dispatch marker with no authoritative outcome
becomes `unknown` and is never dispatched again, and an accepted intent with no marker is rejected),
then asks what is still owned, and only then records the closure. The closure record carries the
terminated process identities, whatever the fence reached, the resources known to survive, and an
ownership-coverage flag that never claims every application was discovered. Nothing is rebuilt from
terminal history.

**What the fence reaches is nothing, and it says so.** A worker's descendants join the process group
it led, and once the worker has gone the kernel is free to give its number to an unrelated process
whose group would answer to it; the root shell also starts a session of its own, so its jobs need
not be in the worker's group even while the worker lives. Stopping what such a group held would be
stopping somebody else's processes on the strength of a coincidence. The boundary that would work is
the one the platform keeps (the transient unit or Job the supervisor started the worker in, named
from the reservation and unable to name anything else), and this host does not stop one. So the
coverage is incomplete and the record says which part of it this host could not account for.

**A closed session can be collected.** A session with no worker has no maintenance tick, so the
archive has a collection of its own (`ArchiveService::collect`) that applies the bounds belonging
to the session, under recovery ownership and after section 9's recovery rules have settled what
the worker left unfinished: output past seven days and receipts past thirty, each on its own
budget and only on a clock the caller can prove, and the session's own byte cap on any clock. It
refuses a session whose published worker the kernel has not said ended, and it opens only stores
that are there. Output and receipts are reported apart, each with what was removed, what is left
and what could not be removed: a segment that could not be unlinked is still counted and still
served until a later pass removes it. The host-wide cap is not part of it, because that is decided
across the whole environment rather than one session at a time. Nothing runs this collection on a
cadence: a closed session's output and receipts go when it is called.

The transfer service's one retention question is answered here. Section 14 gives a submitted
attachment its session's retention rather than the seven-day unused window, and the archive is
what holds a closed session's record: a session it has a record of keeps what was submitted to it,
one whose journal it cannot read keeps it too, because declining to delete is the answer that
cannot lose a file, and one neither the registry nor the archive knows about keeps nothing.

## The backup service

The producer is `kr-crypto`: it encrypts each object under its own key, wraps the keys, signs the
manifest and builds the public descriptor. Object storage is the storage service's. What the daemon
owns is the part in between, which is the part a crash can lose.

`backup.sqlite` sits beside the registry in the environment's state directory, with the staged
ciphertext in a `backup/` directory next to it. It holds generation records, object rows, each
object's upload in progress, dispatch attempts and the cleanup privacy mode is owed. It holds **no
object key, no plaintext and no filename**: the keys stay with the producer until the generation is
sealed, and the filenames are inside the encrypted manifest. An upload in progress is the identity
the storage service gave it and how many of its parts the service has acknowledged, nothing more.

The store is at schema version 7. A store at version 6 has no upload table, and the first open by
this build adds the table and its rules in one transaction with the new version. That step compares
the result with this build's schema before it commits, so a version-6 store holding anything this
build does not define is refused like any other and stays at version 6.

Every database write changes the state *and* whatever follows from it, in one transaction.
Admitting a generation writes its object rows and its first upload attempt with it. The object that
completes a generation writes the publish attempt with it, exactly once, so a host that recorded the
object and then died does not come back with a complete upload nothing publishes, and a repeated
acknowledgement does not enqueue a second publication.

**Two facts are never allowed to stand in for each other.** Where a generation's production has got
to and what a service holds of it are separate columns, and so are where an object's ciphertext is
and how much of it a service has acknowledged. An acknowledgement never puts a staged file back; a
removal never unsays an acknowledgement; and production being cancelled never deletes the record
that something of the generation reached a service. A generation whose publication had already left
when privacy mode drew its line therefore carries both facts at once: production cancelled, and a
copy at a service this host cannot yet account for.

**A dispatch attempt is immutable.** Its identity, the work it carries and the privacy generation
it was admitted under are fixed when it is enqueued. It moves from queued to dispatched when this
host hands it to a named executor, and from either to terminal when something establishes how that
exact attempt ended; it never moves back. A resumed step is a *new* attempt beside the one that
left, so the attempt that went keeps its place as work still owed an answer instead of being
relabelled as something this host could cancel. An attempt that has ended keeps its row, its
outcome and its executor, which is what lets the host recognise an answer it has already had.

**An attempt that left this host ends only through a call that names it.** The call is a statement
about that one transfer: its executor reports that its upload finished, a service's answer to a
publication names the attempt that carried it, or a caller establishes that a named attempt
stopped. Nothing about an object or a generation ends one. An acknowledgement records what a
service holds of an object; a generation with nothing left outstanding is a fact about its objects,
and a second attempt at the same upload may still be sending what the first has already delivered.
Where a host had written an attempt off and sent a replacement, the answer to the first names the
first, and the replacement keeps its place until it is answered in its own right. Only work this
host still holds queued is ended without an answer, because nothing of it ever went anywhere.

The database refuses the states that rule would never produce, whether the write comes through the
store or round it. An upload ends as accepted only once a service holds every object of its
generation; a publication only once this host has written down that a service holds the archive; an
attempt ends as stopped only once what a service may hold of its generation is written down; and an
attempt this host is still owed an answer for is neither deleted nor has the cleanup naming it
discharged.

Cleanup is protected the same way from the side. An obligation keeps the fence it was written
under, the kind of work it is owed for, the target it names and the moment it was written down;
how often it has been tried and why the last try failed are the only columns that ever change. It
is never written over by an insert either, whether that insert carries its identity or only its
fence, kind and target, because a replacement deletes the row it collides with without the
statement ever mentioning a delete. That refusal is a rule of the database, so it holds for any
connection that opens the file. No statement in the store resolves a conflict that way in the first
place: there is no `REPLACE` clause in it, an insert that would repeat an obligation asks whether
it is already owed, and the store's own connections run the delete rules for a delete that conflict
resolution causes.

What the database cannot tell apart is which caller a legitimate-looking row came from, so that one
call ends one named attempt stays the code's rule. Once a service's answer is written down, direct
SQL can still stop several attempts in one statement: the conditions above are what a settlement
must satisfy, not a statement of who may write one.

**One rule decides whether work may go anywhere**, and the store applies it inside the transaction
that would change state: nothing inhibits production, this host has not moved past the privacy
generation the work was admitted under, and that generation may still produce. Admission asks it,
the publication enqueue asks it, and the dispatch claim asks it again before the work leaves.
Nothing a caller passes takes part: admission stamps the privacy generation from the store's own
durable state, so there is no way to admit, publish or dispatch work carrying a generation
somebody read before a fence went up and came down again.

An answer that arrives after that line is still recorded. A publication a service accepted for work
privacy mode had already stopped is written down as a **retained artifact**: the service holds it,
the attempt that carried it is over, and no descriptor of this host's becomes current. Refusing it
instead would leave an attempt waiting for an answer it had already been given.

Staging the ciphertext is the one step *outside* that transaction, and it goes first: each file is
created exclusively, written, flushed, and every directory made for it up to the staging root
flushed, before any row names it. A committed row therefore never names a file that losing power
took away. The other order would leave rows naming files that are not there, which nothing can
recover from. Exclusive creation is also what stops a second admission of the same generation
writing over ciphertext the first is still accounting for, and that second admission is refused
outright.

The directories are flushed on every platform. Windows flushes a directory only through a handle
that may change it, so there each is opened with the one right its change used: the directory that
holds the file with the right to add a file, and each directory above it, up to the staging root,
with the right to add a directory. A removal of staged ciphertext flushes the same directories, and
is not reported as done until that flush has succeeded.

A crash between the file and the row leaves ciphertext no row claims, and the staging directory is
walked for exactly that. The staging directory is held as an absolute path whatever the caller
gave, so a removal always looks for a file where the row says it is. The daemon owns that directory alone, so a file in it that no object row
names is ciphertext a stop left behind: privacy cleanup writes down a walk of it as one of the
things a fence owes, and each file the walk finds becomes a removal of its own before the walk is
finished with. A directory it cannot read leaves the walk owed rather than reported empty.

### What a restart resolves

Reconciliation runs before anything can add to the store. A generation whose production is over is
left exactly as it is: what privacy mode is owed was written down when its fence went up, one row
per target, and a restart reads those rows back rather than working the answer out again. An
attempt of it that had left this host and was never answered is **not** ended here either. It is
listed as unanswered and nothing about it changes, because reopening a store says nothing about
what a service did with bytes that reached it, and a wait ended on that basis would be a cleanup
reported over work still out there. Only an answer, or the caller establishing that the transfer
stopped, ends such an attempt. For everything still producing there are five answers.

* A generation a service **accepted** the descriptor of is produced, and its production is finished
  here. An answer arrives once, and a host that was told to stop and could not had to withhold
  completion when it did; nothing delivers it again, so a generation left producing would be work
  with nothing to carry it.
* A generation whose *publication* was dispatched and never answered has that written down: its
  production is over, and what a service holds of it is **unknown**. A service may hold it and may
  not, and a host that wrote either answer would be writing something it does not know; section 23
  never retries that automatically, and retiring the writer afterwards does not rewrite an outcome
  this host never learned. A caller establishing that a *publication* stopped writes the same two
  facts for the same reason.
* A generation whose writer this host no longer holds an enrolment **for that archive** is
  **cancelled**. Authority is the pair: an enrolment for one collection does not authorise
  unfinished work for another.
* A generation still producing while this host is stopped by privacy mode stays **fenced**. That is
  a generation admitted before a request whose fence has not gone up yet: a raised fence has
  already prohibited production for everything it covers. A restart does not un-fence either of
  them; raising the fence, and then turning privacy mode off, is what decides what becomes of it.
* Everything else **resumes**, as a fresh attempt beside the one that left. The same object under
  the same identity and hash is the same object, so sending it again is not a second publication;
  the attempt that went is still owed an answer, and it keeps its place until it gets one.

### What a restore checks, and in what order

The caller's own expectation first: the archive it means to restore. Without it, a genuine
enrolment and a genuine publication for a *different* collection of the same owner would pass every
signature check. Then the owner's enrolment, because it is the owner's own signature and it is what
says this writer may publish for this collection at all. Then the writer key the recovery bundle
supplied, which must be the key that enrolment names and must be its own identifier. Then the
publication's structure and its signature under that writer. Then the generation against the
checkpoint the owner trusts, which refuses an archive older than what the owner verified and one
that claims the checkpoint's generation with a different manifest.

`VerifiedRestore` is built by that call and by nothing else, and its fields are private.
`VerifiedRestore::expectation` builds what `kr_crypto::backup::open_archive` is handed, and it takes
no argument: it carries the archive, the exact generation and the encrypted-manifest hash the
publication's signature covered, so the archive that is opened is the one whose authority was
established and a second genuine generation of the same collection cannot be substituted for it.

What a restore puts back is decided by `kr_crypto::backup`'s table, so this host and the device that
made the backup give the same answer: session content, device configuration and generation
checkpoints come back; reusable endpoint and control-signing private keys, the notification
extension's preview key, the recovery seed, this host's own grant and revocation authority and any
revoked grant do not, each with the reason rather than as a silent omission. The table classifies
material a caller names rather than inspecting an object's bytes, so it is the decision and the
caller's export and import paths are the gate. **No path reads an archive back into a host**: the
table is the check an import would make, and no import makes it.

### The uploader

`backup::uploader` is the executor the outbox waits for. It takes the attempts in order, dispatches
each to itself under one executor name, uploads the generation's staged objects through the storage
service and publishes the descriptor through the backup manifest once every object is there. Each
answer is written down as it arrives, under the attempt that carried the work.

An object goes up in 8 MiB parts. The upload's identity and the count of parts the service
acknowledged are recorded before the next part leaves, so after a crash the uploader goes on at the
next part. A part whose answer was lost is sent again and answered as the part the service already
holds, and a completion asked for again gets the result the first one got: nothing is stored twice.
A creation whose answer was lost is the awkward case. The service holds that upload open under an
identity this host never learned and refuses another creation until the upload's lifetime runs
out, and a pass after that creates it again.

A publication is signed at the instant its generation was admitted, so one the service refused,
or one refused on this host before it left, goes again as the same bytes. The exception is a
refusal from a service that already holds a generation of the archive at or above it. The backup
manifest takes no generation at or below the newest it has held, so the attempt stops, and the
report names that generation as the one that carries its content. One that may have left without
an answer is never sent again. The uploader fetches the generation instead and records it
as published if the service holds it. If the service still does not hold it two freshness windows
after the send, the uploader stops waiting: the attempt stops, the outcome is written down as
unknown, the generation's production ends, and the next generation carries the backup. That a
publication may have left is noted before the request goes, so a pass cancelled while it is on its
way leaves the next pass asking. After a restart, `Uploader::settle` makes the same fetch for every
publication an earlier process dispatched, and a daemon calls it before reconciliation, which would
otherwise write the outcome down as unknown. A process that stopped between dispatching a
publication and sending it leaves that generation unknown in the same way.

An unknown generation is never counted as a success. While the uploader still asks about it after a
restart, and once it has stopped asking, the pass reports it by generation and archive as unknown:
not a completed backup, not sent again, and carried by the next generation. Where privacy mode drew
its line under the generation, the report says instead that no later generation carries its
content. An unknown generation changes nothing newer either. The backup manifest refuses a
publication that reaches it after a newer generation is published, and a fetch of the newest still
answers with the newer generation.

What an unknown generation stored is given back. The storage service keeps a stored object until
something deletes it, so once this host holds a newer generation of the archive as published, the
uploader asks whether the service holds the unknown one. If it does, the publication landed before
the newer one: the generation is written down as published and keeps everything. If not, it never
will, so each of its objects is deleted once, and the service gives the storage back after its
tombstone window. Each deletion is written down in `backup.sqlite`'s `releases` table before its
request leaves, and its answer after. An object that another generation this host records also
names is kept, whatever that generation's state, because the service holds one object under one
name and an unknown generation may yet be one the service holds; the store refuses to write a
deletion of such an object down. From the moment a deletion is written down no generation this host
admits names that object, so neither the request, a later one for the same object, nor one delayed
on its way can reach an object admitted after it. Nothing is deleted under privacy mode's line,
whose retained artifacts go only by the person's own action, and nothing of a collection deleted
from the account console. Privacy mode is read again after each answer the service gives.

An attempt ends on evidence about its own work. A collection deleted from the account console
stops the attempt, retires this host's writer for that archive and cancels what it was still
producing there, and the report says the collection was deleted and that backing up again means
enrolling a new collection. A staged object that is gone, or is no longer the ciphertext that was
admitted, stops its generation. Any other refusal, and any failure of the transport, leaves the
attempt for the next pass. When the service refuses a part or a completion as not permitted, the
uploader asks it to abandon the upload: a confirmed abandonment means the object goes up again
under a new upload, and a refused one leaves the upload to go on as it was. An upload nothing
carries any more that the service will not abandon is forgotten, and what the service holds of its
object stays written down as unknown.

Under a privacy fence nothing new leaves, whether a dispatch, a further part, an object or a
publication. The upload in progress is abandoned at the service and its attempt stopped, which is
what lets the fence's cleanup finish. Nothing is sent before the store has reconciled, while a
privacy step this host could not take is outstanding, or while the storage service says backup
storage is off, and a pass with no work asks the service nothing.

### What it does not do

It serves no method. `storage.*` and `backup.manifest` are *service* methods, which this host calls
rather than answers. The daemon does not start the uploader, and it holds no source for the account
token that spends an account's storage beside the host's signature, so a running host sends nothing
to a service.

## Privacy mode

Enabling privacy mode records a **privacy generation** and asks the same four things of every
subsystem it reaches. They are one contract rather than four hooks, because a subsystem that did
three of them would leave the fourth undone somewhere a person could not see.

1. **Fence** what is content-bearing, immediately. Not "stop producing more": stop the queue that
   already holds content from reaching anything outside this host.
2. **Cancel** the work that was admitted and never dispatched. It has not left, so it can be taken
   back rather than followed.
3. **Reject a late result.** Work that had already left is still out there and its answer will
   come back. An answer produced under the generation before this one is refused.
4. **Reconcile** before completion is reported. In-flight cleanup is finished when every subsystem
   says it has nothing outstanding, not when it was asked for.

The generation is written down **before** any subsystem is touched. A generation that was applied
and not recorded would be a boundary a restart could not see, and a late result from before it
would then be published; a host that cannot record it does not enter privacy mode at all.

### Turning it on and off

Privacy mode is one generation for the whole environment, and the control daemon keeps it. Its
record, `privacy.sqlite3` in the state directory, holds the generation, whether privacy mode is on,
and one **obligation** for each session whose own cleanup at that generation has not yet been shown
to be complete. `kr privacy on` and `kr privacy off` reach it through `privacy.set`, which only this
host serves: a paired device whose grant carries `host.manage` reads `privacy.status` and changes
nothing about the host. Both answer one report: the generation, whether the last change has taken
effect, what each session still owes, what the daemon keeps and why, and what had already left this
host.

The act of turning it on writes the record first, in a single transaction that records an obligation
for every session for which the environment has content, including every worker recorded in the
registry, every launch whose worker may still start or may be running without a record (reservation
spawned, reservation claimed, or post-claim fence), and every session for which a journal or spool
remains on disk. The admission the request carries is asked again immediately before that write, so
an action whose deadline passed, or whose authority was withdrawn, while it waited changes nothing.
The write happens inside the backup store's own hold together with the backup fence, so no backup
decision falls between the two, and no exchange with a delivery destination falls between the record
and the moment the new state is published, because the send gate below is held shut across both.
Only then are the daemon's own subsystems taken through the four steps: the backup service, the
delivery outbox and the stored descriptions.

Each session is told the generation by the daemon, on a tick once a second, over the connection the
daemon holds to its worker. The worker raises its attention transition, applies the generation to
the session and answers where its own cleanup stands. The tick tells it again, waiting longer each
time, until it answers that its cleanup is complete, and only that answer ends its obligation. A
session whose worker ended first keeps its obligation, reported as unavailable with the archive
named as what holds its output, because an ended worker is no evidence that what it retained is
gone.

Creating a new session in privacy mode doesn't wait for a tick. The daemon records the new session's
obligation before it asks for the worker. That write waits for whatever holds the record, a change
of privacy mode among it, and if the obligation cannot be written the create starts nothing. A
create whose deadline passes, or whose authority is withdrawn, while it waits starts nothing either.
When the worker's claim is accepted, it is given a launch specification that includes the generation
in force and whether privacy mode is on. The worker writes the generation into its journal and turns
off output retention before launching the shell. If it can't write the generation, it doesn't start.
When the tick's first notice reaches the worker, it already has the generation, and the attention
store joins at that notice. If privacy mode has changed after the specification was read, the worker
learns about it the same way it does for any other session, via the tick.

The report says complete only when every subsystem has nothing outstanding and every obligation has
ended. A step a store refused is owed, with the store's reason, and the tick tries it again on a
schedule of its own, one second doubling to a minute; so is whatever the backup service still has to
clean up. A daemon that stops in the middle reads the record before any subsystem the record drives
does anything, takes every subsystem through the steps again, which each can do any number of times
at one generation, and only then reconciles the backup service, starts delivery and serves anything.
A record it cannot read stops the start rather than leaving the daemon to guess.

Turning it off is refused while a daemon subsystem, or a session whose worker is running or may
still start, owes cleanup, and the refusal names what is owed. A session whose worker has ended does
not hold it back, because nothing resumes in its store, and its obligation stays recorded. A session
counts as ended only when the registry shows its launch is over: it has no reservation, or one whose
launch failed after a worker claimed it, or whose session has closed. A session whose worker has not
reported yet is one this host has not reached, and it holds turning privacy mode off back until its
worker answers that its cleanup is complete, or the registry shows its launch is over. Otherwise the
next generation is recorded first, the backup fence is released under it, the delivery fence is
lifted, and each live session is told until it answers. If a launch never handed a worker its launch
specification, it never ran a shell, so nothing was retained. The registry, the daemon's own creates
and the kernel show this in three cases: the launch failed or was fenced before any worker claimed
it, its launcher exited without claiming it, or its create stopped waiting without recording a
launcher, after which a claim is refused. The obligation for such a launch is deleted from the
record, but the session is not reported as ended. All other launches are still owed and hold privacy
mode on until they come into one of those cases, until the registry shows, after a claim, that their
launch is over, or until the worker that claimed their reservation says its cleanup is complete. In
particular, a reservation that never made it to the `spawned` state (because writing to the registry
failed) will stay owed until the next time the daemon starts and fails it.

**The send gate.** Every exchange the delivery outbox has with a destination, a send or a question
about an earlier one, is admitted under the privacy state the record publishes, and only at the
generation the notification was admitted under. The admission is held until the answer is recorded.
Privacy mode ends the generation every notification that carries content was admitted under, so
while it is on nothing is admitted but the alerts it lets through, and those only at the generation
the fence stands at. Turning privacy mode on waits for exchanges already admitted, and a
notification claimed before the change and presented after it, once a credential renewal that waits
on the gateway has finished, is taken back rather than presented: nothing of it left this host, and
it is settled as cancelled. Anything the outbox has on the wire when privacy mode is turned on stays
outstanding until its answer arrives, and is then listed among what left.

Content-history retention, description inference, sync production and backup production are disabled
prospectively, together. What this host holds itself is removed with them: the retained output goes,
the spool with it, and the content a settled receipt carries (the intent envelope the caller sent
and the result the action produced) is taken out of the journal while the receipt's own metadata
stays. A receipt that has *not* settled keeps its envelope, because recovery reads it and a retry of
an action this host may already have performed is answered from it; when it settles later, the
host's own maintenance takes its content then.

Privacy mode does not reach two stores. The canonical grid keeps its own scrollback, which a client
can still page through, and there is no semantic-history cache or generated-title store in the
worker at all. Neither is described here as though it were done.

A cleanup that could not finish is not a cleanup that finished. A redaction the store refused and
a spool file this host could not unlink are both content privacy mode was asked to remove and has
not, and they are kept apart: each is retried on the host's own maintenance tick and cleared only
by its own success, so a redaction that works does not settle a spool that did not empty. A
session reopened under privacy mode, or one whose privacy state this host could not read, owes
both, because an enabling that was interrupted leaves content behind and nothing on disk says
whether it did.

What stays is named rather than silently retained: the receipt journal's operation metadata, the
minimal local authority this host holds, the envelope of an action that has not settled, live
pending questions and approvals, which keep working under the grants they already have without their
bodies being exported as historical content, and user-pinned labels, which are kept locally unless
explicitly cleared and excluded from later sync while privacy mode is on. A host that claimed a
functioning durable control system wrote no state at all would be claiming something untrue.

The same boundary applies when exporting session content as part of a support bundle:

If `kr doctor --bundle support.tar --include-content` is invoked while privacy mode is enabled, all
sessions will be excluded from the bundle. The same is true for any sessions still awaiting to be
cleaned up by privacy mode, for whatever reason (e.g. the worker was terminated before the cleanup
could complete). In these cases the command will inform the user how many sessions have been
excluded from the bundle, and why. The privacy mode state is checked both prior to reading the list
of sessions, and after. If the privacy mode has been changed in the meantime, all sessions will be
excluded from the bundle. Once the file has been written to disk, it’s yours, and enabling privacy
mode afterwards cannot recall it, just like it cannot recall anything that had already left this
host. See the command-line reference for how to preview and redact the session content.

The text the environment's attention inbox shows is fenced at the control daemon rather than in a
queue of the session's own. A session serves no text from before a transition, and text it answered
with before privacy mode was enabled cannot leave the daemon once the new generation is committed,
whether or not the daemon answered in time. The attention section sets out how, under *Privacy mode
and the text an item carries*.

Backup production is fenced where it is accounted for, and the fence writes down everything it
implies in the same breath as raising itself.

The request comes first and on its own. Privacy mode asking this host to stop is committed as a
**request** before any fence is attempted, together with the single obligation to raise that fence.
From that moment no generation is admitted and no attempt is dispatched, whatever happens next: an
activation that then fails leaves the request and its obligation behind, so the host is stopped,
counts the work, and cannot report a fence it did not raise. Only the activation's own retry ends
it. A store that will not accept even the request leaves no row at all, which is why the enabling
reports failure and the caller keeps the request to replay: nothing can persist a request in the
database that would not take it.

That last case is the one the store owns nothing for, and a **readiness condition** covers it. The
backup service is unready until two things hold: it has reconciled its store since it opened, and
no privacy step it was asked to take is outstanding in this process. Admission and the dispatch
claim both enforce it, so a host that was told to stop and could not produces nothing meanwhile. A
step that failed is remembered with the privacy generation it was for, and only that same step
succeeding, for that request or a newer one, ends it: a repeat of an older request this host had
already applied establishes nothing about the newer one that failed. Keeping the enable request
across a restart, and replaying it, belongs to the caller that delivers it.

Raising the fence is one transaction, and it is the only one that raises a fence. It records the
fence, moves the privacy generation forward without ever moving it back, prohibits further
production for every generation still producing, and writes down **one row per piece of cleanup**
that fence implies: a removal for every staged copy still on this host, a cancellation for every
attempt admitted and never sent, a resolution for every attempt that had already left, the
bookkeeping each generation still needs, and one walk of the staging directory. It reads the rows
as they are rather than any summary, so every generation is covered on the same terms whatever its
production and whatever a service holds of it: if its ciphertext is here, its removal is written
down.

From there a piece of cleanup ends exactly one way. The effect and the row that discharges it
commit together, in the transaction that records the result, and there is no call anywhere that
clears one on its own. A removal reads its obligation, unlinks the file, flushes the directory
entry where the platform allows it, and commits the file's absence and the discharge as one thing.
A flush that fails is not a removal this host may report, because losing power could return the
name and the obligation that would find it again would be gone, so the obligation stays;
a stop in between leaves the obligation, and the retry finds the file already gone, which is
exactly what it expects. A file this host could not unlink keeps its own row, with the reason
written beside it as a diagnostic: the attempt count and the error message are never the identity
and never the clearance condition, so failing to write them changes nothing. There is no count of
cleanup held in memory and no obligation named by a string, because what is owed *is* the set of
rows and what is complete is the absence of them.

A generation's bookkeeping is finished by whichever transaction makes the last thing it waits on
true, rather than by a step somebody has to remember to take. It waits for the staging walk, for
every removal of its own, and for every attempt of it to be settled; only then are its rows taken,
and only for a generation a service holds nothing of. What it removes is production bookkeeping and
nothing else: a generation whose descriptor was published keeps its record, so does one whose
outcome this host could not establish, and so does one whose ciphertext a service acknowledged
before privacy mode cancelled its production. All three are copies somewhere else, and a host that
deleted the acknowledgements with the production would have nothing left to show a person. What a
cleanup pass reports is what it did: bytes it unlinked and rows it deleted, and the two counts are
independent. A pass that keeps a retained artifact's record reports its bytes and no records at all.
A pass can equally report records and no bytes: a removal whose file went before the store could
record it is finished by a later pass, which finds the file already absent and takes only the rows,
and a staging walk that was blocked can release a generation's bookkeeping long after its bytes
went. Absent bytes therefore never imply that nothing more will be reported.

An acknowledgement that arrives late ends no transfer. It records what a service holds of one
object, and a complete set of them says the ciphertext is there and says nothing about whether the
executor that delivered them, or any other, has stopped sending. The transfer ends when the
executor holding it reports that it did, so the cleanup naming that attempt stays owed until then.
An acknowledgement does not put a file back either, because where the ciphertext is and what a
service holds are separate facts, so an object privacy mode has already removed stays removed and
still counts as an object that arrived. It enqueues no publication while a fence stands. And
removing the local copy is not evidence about any transfer: an attempt that left this host keeps
its obligation until an answer about *it* arrives or the caller establishes that *it* stopped.

A publication answer names the attempt it is about, and the archive and generation come from that
attempt's own row. It is recorded against the generation *this host admitted the work under*, which
the store reads from its own rows rather than taking from the caller, so a result relabelled with
the generation in force is refused, and so is an answer for an attempt that never left this host. A
genuine answer that arrives after privacy mode drew its line is not refused: it is recorded as a
retained artifact, the attempt it answers ends, and nothing of this host's becomes current. An
answer for an attempt this host had already written off is recorded too, because what a service
holds is the stronger fact, and the attempt keeps the outcome it was given. Once the archive is at
a service, work this host still holds queued for that generation is taken back rather than left
behind a gate that now refuses it. What stops a publication reaching a service at all is the
dispatch gate rather than any of this, because recording anything afterwards cannot recall
something already sent.

Turning privacy mode off releases the fence, under a generation of its own, and only when nothing
is owed under it. The release names both generations (the fence to bring down and the one
production resumes under), so it can neither clear a newer fence nor move the generation in force
backwards, and it is refused outright while that fence still has cleanup outstanding: new backup
content does not enter a scope this host has not finished clearing, and the caller is told the
resumption is still pending. The rule lives in the database as well as in the code, so a writer
that went round the store cannot release such a fence or delete it instead, and cannot add cleanup
to a fence already released. Nothing the fence cancelled comes back; what is admitted afterwards is
admitted under the new generation.

What has already left the host is shown rather than erased. An uploaded archive is listed by its
archive and generation; so is one whose outcome this host could not establish, because a copy it
cannot account for is still a copy; and so is object ciphertext a service acknowledged for a
generation whose descriptor was never published, because those bytes are there whether or not an
archive was ever completed from them. The backup service marks them **not** deletable, and that
mark is the plain truth about what the host can do: it holds no route through which it could ask a
service to remove a copy, so it offers no deletion action for one and says so instead of offering
an action nothing here can perform. A person who wants such a copy removed asks the service that
holds it. A notification or another artifact this host does hold a reference to is listed with an
action; backup does not silently delete unrelated collections and does not claim a copy somebody
else holds can be recalled. Local deletion is logical cleanup of this host's own records rather
than a
claim of physical secure erase: the files are unlinked and the rows are cleared, and nothing here
says the bytes are unrecoverable from the device they were on.

Turning privacy mode off starts retention again from that moment, under a generation of its own.
It reconstructs nothing, and the new generation is what keeps the private interval's own results
refused afterwards: leaving the generation where it was would make every answer admitted during
privacy mode acceptable the moment privacy mode ended.

A session reopened with privacy mode on does not start retaining again, and one whose privacy
state this host could not read does not either: not knowing whether privacy mode is on is not a
reason to keep output.

### What privacy mode does not reach

Stated here rather than left to be discovered, because the gap between what a mode is called and
what it removes is exactly the thing a person cannot check for themselves.

* **A session whose reservation was fenced after its claim is not reached again.** A second claim on
  a reservation that a worker has already claimed fences it (when the first worker tried to report
  ready it was refused, and it carried on with its session anyway and is never recorded). Note that
  a launch does not normally claim a reservation twice. If, however, privacy mode was on when the
  worker was launched or is turned on afterwards, the session owes its cleanup like any other: the
  report lists it, and `kr privacy off` stays refused until its worker says its cleanup is complete.
  A worker that was never recorded is told nothing after its launch specification, and nothing
  records a closure for it, not even a restart of the daemon, so for that session the refusal is for
  good. A worker that was recorded remains in the directory, and is told its generation, until the
  daemon's next start; at that start it is left out of the directory and, unless the host has
  rebooted, which closes every recorded worker, is in the same situation as a worker that was never
  recorded.

* **A worker that claims its reservation and then fails keeps its obligation.** A worker that
  reports it could not start after it claimed its reservation, or that ended before it said its
  cleanup was complete, is taken for ended. Its obligation is preserved, and the report names the
  archive as what holds whatever it kept. Differently, a launch that fails before any claim is
  forgotten, since it ran no shell.
* **Transfer previews and sync are not driven.** The transfer service keeps no preview store for
  privacy mode to reach, and sync is the clients' own record; neither is one of the subsystems the
  daemon takes through the steps.
* **The canonical grid keeps its scrollback.** Retention stops at the spool and the resident window;
  the projection's own history is not reached, because removing rows from it while keeping the live
  screen needs an interface the projection does not have.
* **Application notices keep their content.** A notification's title and body are written to the
  host-event store, and privacy cleanup removes neither the rows already there nor later ones.
* **Content that settles is taken in a second step.** An action admitted under privacy mode has
  its receipt content removed where it settles, which is after the transaction that wrote the
  outcome; a crash between the two leaves it, and the early rejection path does not reach that step
  at all.
* **The archive does not enforce any of this.** A session read after its worker has gone is served
  from the store as it stands: the archive neither finishes an unfinished cleanup nor holds a read
  while one is owed.

## Session names and descriptions

Every session has a name from the moment it exists, and it costs nothing: the repository and branch,
the directory, the application, or the display number a person types to reach it. The status beside
it (starting, running, unreachable, awaiting approval, awaiting input, completed, failed or closed)
is the host's own lifecycle record. Neither is text a model produced, and no model can set either.

A host may also run a small CPU-only model locally to say what a session is *doing*. One shared
inference process and one mapped model per execution environment, never one per session. A WSL
distribution reaches a native-host broker only after somebody explicitly chooses to let local data
cross; without that choice it shows deterministic titles. Mobile runs no model to label a host
session. Grouping machines together for display grants nothing: two environments have their own
mapping and their own context.

Nothing about this is on the shell's input, query or resize path. The only way a description job is
created is a meaningful context change (the working directory, the foreground application, the
selected thread, the task intent or completion), and those are the only five things that exist to
send. Changes inside a two-second window become one revision, so a long active turn still receives
text rather than invalidating every job.

Before a model is loaded the host checks that its itemised cost plus a reserve of at least the
larger of 1 GiB or a fifth of physical memory still fits in the memory it can see. When it does not,
the state is `resource_paused` with the reason named, and the titles are unaffected. Battery pauses
inference unless an owner enables it, and a host that cannot read its own power source is treated as
being on battery. Thermal and memory pressure pause it on mains too, and when the pressure clears
the host resumes on its next evaluation without restarting anything.

The queue holds at most one job per session. A session that changes again has its job's content
replaced and its waiting position kept, so a busy session never overtakes a quiet one that has been
waiting longer. Foreground work goes first, and after at most three priority jobs the oldest waiting
ordinary job is served.

A result is validated before it is published, against what is in force at that moment rather than at
admission: a malformed answer, an unknown field, a control character, either codepoint bound, a
wrong session epoch, a changed context or binding, a remapped model, a moved privacy generation and
a pinned name each refuse it. A refused result costs nothing, because the session keeps the title it
had.

Pinned names and each description's provenance live in a store of their own, so they survive the
session closing and the host restarting. Generated text never replaces a pin and never changes the
status shown beside it. Under privacy mode, description processing stops at once, every queued job
is taken back, every generated description is removed, pins are kept, and titles come from metadata
from the instant the fence goes up. `docs/describe/README.md` has the whole of it.

The control daemon serves both methods from that store, on its local socket and to a paired device.
`session.describe` is a read under `session.view`, filtered for whoever asks: the pin when there is
one, otherwise generated text, otherwise the title built from the session's display number and the
directory it started in. Generated text, with its activity line and its provenance, is served only
while privacy mode is off, only when it was produced under the generation in force, and only to a
caller whose history reaches the whole session: the owner at this machine, or a device whose grant's
history bound is at or before the session's start. A grant with no history bound retains no history,
so its device is shown the pin or the metadata title. The answer also carries the state of inference
on the host, the reason it is paused when it is, the cadence the host runs at and the age of the
session's queued job. These come from the description host the daemon starts when it starts; a
daemon whose description host did not start says that inference is paused because this environment
runs no model, and carries no queue age. `session.rename` needs `session.rename`: it pins a title of
at most 64 codepoints, or clears the pin with no title, records who set it, and answers the title it
now shows: the pin, or the title built from the session's metadata after a clearing. It never
answers generated text, which is `session.describe`'s, under its own right and filter, so the record
a rename's action keeps for a retry holds none and the removal privacy mode makes has nothing of it
to reach. The right to rename a session is not the right to view it, so a device that may rename and
may not view is answered the first time and is not answered again from the record: a retry, whether
the rename was done or refused, goes back only under present view authority over the session it
names.

## What an idle session wakes for

A session with nothing happening in it should cost nothing, and twenty of them are measured
together. KR-PERF-003 puts the whole host under one per cent of one processor core, averaged over
five minutes: twenty idle sessions, thirty-two attached views, the allocated grids with their
caches, and the daemon. A host that asked the kernel ten times a second, for every session, whether
anything had happened yet would spend most of that allowance on the questions alone.

So every wait in a worker is on something that happens rather than on a clock.

| What is watched | What wakes the host | What is left on a clock |
| --- | --- | --- |
| the application's output | the terminal's own descriptor, which reports output and a hangup alike | a one-minute safety net, for a platform that reports neither |
| room for the application's input | the same descriptor | nothing; a write with no room waits on it |
| the root shell's exit | the child signal the kernel sends the worker | a thirty-second sweep, in case a signal is lost. Windows reports a process ending on its handle rather than by a signal, so there a hundred-millisecond check is the whole answer |
| the processes the session owns | input the session accepted and output it produced, which is where a new process usually comes from | the same sweep, for everything that comes from neither |
| the login a desktop-bound session is tied to | nothing this host can subscribe to, so it is asked on every wake: one kernel query about the process that owns the login session, at most once a second | the same sweep |
| a held paste prefix | its own deadline, which exists only while a prefix is held | nothing |
| an attached view | the frames its connection carries | one keepalive per connection every ten seconds, which section 23 requires of a local connection |

The sweep is a window rather than a guarantee, and it is worth saying exactly what that costs. A
process that starts and ends between two observations of the ownership boundary is not in the
closure record's list of what was stopped. The record never claims every application was discovered,
and the coverage flag says which boundary produced it.

The session's own traffic keeps that window narrow when the session is visibly doing something, and
it is a hint rather than a proof. An application that is already running can start and collect
children on its own timer, on a filesystem event or on something that arrived over a network, and
print nothing while it does; and input is marked as it is queued for the terminal, so a process the
application starts after reading it, and finishes before anything else is marked, is in no reading
at all. Silence here is therefore not evidence of idleness: idle means a verified idle shell with no
pending request and no active owned work, which is a different question asked elsewhere. What a
closure rests on instead is the boundary observed again as the processes are asked to stop, as
whatever is left is forced, and as the record is written.

## The transfer service

The daemon hosts the environment's transfer service, which owns `transfers.sqlite` and a private
staging directory under the state directory. The daemon owns four things about it: admission, the
endpoints, the retention and the end of a closed session's insertions.

Admission is the ordinary path. A transfer read is checked against current authority before and
after it runs. A transfer mutation carries an action window, is checked against the method registry,
and runs on a task a dropped connection cannot cancel part way. The admission is checked again where
the work begins and once more inside the service, because everything in between can wait for a
thread, a lock or a transaction. The check is the one every service asks from inside its work: first
whether this host owes a fence it could not raise, then whether the connection's registration still
stands under the revision the mutation was admitted at, then whether its accepted deadline has
passed. The service asks it under its own lock at each place a mutation starts a new effect, and
every commit that makes such an effect durable runs while the daemon's connection table is held,
from the check to the end of the commit. This way any withdrawal of the connection will either be
committed before the check or after the commit of the mutation. If the check fails, nothing the
action began becomes durable or visible, and the refusal is not kept as its answer: the same action
sent again under an admission that stands is decided as a first admission. Finishing an effect that
is already begun, such as completing a publication or a cancellation whose claim is committed, and
the recovery at startup are not new effects, and the service does not ask again for them. A request
whose envelope names a different session from the object its parameters name is refused, because the
receipt would otherwise name a session the effect never touched. A retry after a lost reply is
answered from the retained record before the freshness window is considered, because the retry
carries the window it was first admitted under.

A 1 MiB attachment chunk does not fit a control frame, so chunk traffic has its own endpoint,
`t.sock`, framed at the attachment bound. Everything else about that connection is the control
connection's: the same handshake, the same peer credentials and the same action windows. The two
endpoints carry disjoint sets of methods, so the larger bound is not a second admission: a chunk on
the control endpoint and an ordinary request on the chunk endpoint are both refused. The daemon
process binds both and owns the tasks that serve them, so a restart releases the addresses before it
binds them again.

The service cannot know which sessions this host still retains, so the daemon answers for them, and
the answer is the union of two records: a session the registry has a reservation or a worker row
for, in any launch phase, keeps what was submitted to it, and so does a session only the archive
knows about whose archive retains submissions. That preserves files rather than losing them. An
hourly sweep expires
unfinished uploads after twenty-four hours, unused attachments after seven days, and download
snapshots at their own expiry. At startup the service resolves any publication an earlier daemon
left between its two commits, so a handle never names a file this host has not found.

A session whose worker has ended has no agent to take what was offered to it. When the daemon
records the closure it ends that session's insertions: each binding no upstream evidence confirmed
becomes `failed`, and a binding or the record of a new prompt for a draft of the session is refused
with `SESSION_CLOSED` from then on. The completed upload keeps its identity. The write runs on its own
task, so a closure does not wait for it. The daemon repeats it for every closure the registry holds
at each start, before it serves a transfer, and at each sweep, which makes up for a write that did
not happen or failed.

Everything beneath an authorised root is reached through `AuthorisedDirectory` and
`AuthorisedFile`, which hold handles rather than names: what a handle is asked about is the
object it was opened on, and no answer depends on resolving a name a second time. A file's own
protection is asked and set the same way, and read and written through handles on every platform:
on Unix its mode bits, the user and group it belongs to and the access-control list beside them; on
Windows its discretionary access-control list, the account it belongs to and its read-only
attribute. That is how a change set replaces a destination without changing who may read it. An
audit list is not carried on Windows and is not claimed to be: reading one needs a privilege this
service neither holds nor asks for, so it asks only for the owner and the discretionary list.
Giving a file to another account needs a privilege this service does not hold either, so a
destination owned by somebody else is left exactly as it was rather than published under an owner
that admits different people. What a Windows object carries itself is kept apart from what it
inherits: a replacement carries the first, and the directory gives the second to the copy as it
gives it to everything made there. Repository work is where the platforms differ: the boundary
every Git invocation runs inside holds on macOS and Linux, and on Windows this host refuses to
start one rather than claim a confinement the platform does not give it.
Publishing itself still names an entry in a directory this host holds open, and what stands at a
name between one operation and the next is what the identity checks and the read-back after a
write are for. `docs/transfer/` has the whole authority model.

`docs/transfer/` has the protocol, the limits, the storage layout and the authority model.

## The project service

The daemon also hosts the environment's project service, which owns `projects.sqlite`, the
repositories the user works in, the working copies selected on them, and every Git invocation this
host makes. The daemon owns two things about it: admission, and the sessions a workspace is bound to.

Admission is the ordinary path. A project read is checked against current authority before and after
it runs. A project mutation carries an action window, is checked against the method registry, and
runs on a task a dropped connection cannot cancel part way. The admission is checked once more
immediately before the write, for the same reason it is for a transfer: everything in between can
wait for a blocking thread or for the journal's lock, and an action whose accepted deadline passed
while it queued does not go on to write. A project acts on neither a session nor a foreground
application, so an envelope that names one is refused before anything runs.

Some of these calls are long. A clone reaches the network and a materialisation copies files, so
they run on blocking tasks and the journal's lock is never held across a subprocess. A cancellation
therefore cannot reach inside a running clone: it sets the operation's flag, and the invocation that
holds the child ends everything *it* started, by the identity this process recorded. On Unix that is
the process group the child leads, which holds every helper the clone spawned; on Windows it is the
job object the child was created inside, which holds them for the same reason and which a process
cannot leave.

### The boundary around a Git invocation

Every Git this host runs is enclosed by the operating system for the length of that one invocation,
and the enclosure is built from the directories this host opened rather than from the paths it was
given. Three things it holds, whatever the repository's configuration says and whoever writes to the
repository while Git is running.

* **Only Git executes.** Git's own program and the helpers under Git's own directory, the approved
  broker's ssh program for a remote that needs one, and the system shell for an invocation that
  reaches a repository over Git's own transport, because Git builds its connection and its call to a
  credential helper as command strings for it. A driver, filter, hook, credential helper, pager or
  filesystem monitor planted anywhere else cannot be executed, whether it was planted before this
  host read the configuration, between that reading and the moment Git started, or while Git was
  running.
* **Only this operation's network.** A local operation reaches no address at all and nothing may
  listen. An operation that reaches a remote may open outbound connections on the ports its
  transport uses and resolve the remote's name, and nothing may listen there either. Which part of
  that each platform enforces, and what it leaves, is in `crates/kr-project/README.md`: the ports
  are enforced on two of the three platforms, and on Linux a socket is made only of what this host
  can account for, so the ports are a guarantee about the protocol the transports use rather than
  about every packet a name resolution sends. A host whose name service cannot fall back from the
  caches it reaches over a local socket to the resolver itself cannot turn a name that needs the
  resolver into an address inside the boundary, and says so; an address written out in full, and a
  name the files answer, are reached either way. A credential broker that would ask another program
  on this machine over a local socket cannot do that inside the boundary, and the operation fails
  rather than the credential being found some other way.
* **Only this operation's directories are written.** The repository's working tree and its Git
  directory, the destination the operation reserved, and one temporary directory that exists for
  the length of the invocation. Everything else is read-only. That temporary directory is taken
  away by the record this host wrote before it made it, and never by descending into it:
  `crates/kr-project/README.md` says what is left behind instead, and why.

The enclosure is what makes the checks around it sufficient rather than advisory. This host reads a
repository's configuration before it runs Git and reads it again afterwards, and it always could; a
writer racing the two readings is what those checks could notice and not prevent. Now the child
starts inside the directory this host opened rather than at a name, so a tree put at that name
afterwards is not the tree Git works in. What the kernels enforce is that opens for writing succeed
only inside the granted root objects' subtrees as they stand at open time, that execution stays
confined, and that the granted roots are re-confirmed by identity before the spawn and after the
run. Neither kernel asks again on each write through a file already open, so a file opened inside a
granted subtree that a same-account writer then moves out of it is still written through that
descriptor, which is an accepted limit: that writer already holds write access to the file. The
re-confirmation after the run is detection: it says a root changed, it does not keep one from
changing. Inside a granted subtree the kernels draw no further line, so a directory put at an
unrecorded name in a tree the operation owns is written to as the tree is; the only writer who could
put it there is a writer under this same account, who could write those files directly.

What it does not confine for the owner's own operations, on the two platforms whose mechanism
separates the two, is reading. Git reads the system's shared libraries, its locale data and its
certificate store, and a read confinement that missed one of those would fail an operation for a
reason that has nothing to do with safety. What such an operation can reach by reading is what the
account this host runs as can reach, exactly as before. An operation performed for a caller bounded
by a grant is confined on Linux: each of its Git invocations reads only the directories it is
granted and a support set named for this host's Git, and it is refused when a filesystem is mounted
beneath a granted directory. On macOS, where no profile tried confined reads and still let the
system's loader start Git, such an invocation is refused. `crates/kr-project/README.md` says what
that caller is promised and what it is not.

Where a guarantee cannot be enforced from outside Git at all, the operation that needs it is refused
rather than run under checks that notice afterwards. Two cases are the exception, and
`crates/kr-project/README.md` names them: a directory Git is given by name is answered after the
fact, with the result the service declares for a changed root, rather than prevented, and a
directory put at an unrecorded name inside a tree the operation owns is outside the guarantee,
because no filesystem confinement that grants a tree can refuse part of it. A kernel too old to
mediate the filesystem rights this rests on runs no Git; one too old to say which addresses a
process may reach runs no remote operation; and **Windows runs no Git at all**, because an
application container cannot keep a repository from being executed from and cannot bound which ports
a remote operation reaches. `crates/kr-project/README.md` says exactly what each platform enforces
and what it leaves.

`docs/project/` and `crates/kr-project/README.md` say which mechanism holds which guarantee on each
platform, and what a platform refuses rather than pretends.

This daemon's project mutations check the accepted deadline and the connection's authority
immediately before the write, as its transfer mutations do, and the admission travels into the
project service so that the last answer is given inside the transaction that begins the effect,
under the journal's own lock, with nothing awaited between the answer and the write.

At startup the service settles whatever an earlier daemon left unfinished, before anything is
served, and it looks at nothing to do so: no descriptor survives a restart, and a recorded path is
not authority. An operation that never recorded the object it staged published nothing, so it is
closed as failed; one that did may have published, so its outcome is recorded as unknown; either
way its staging path is named rather than removed, and the owner reconciles it through a location.
Which name holds the staged object is asked only by the running operation, through the destination
it holds: the operation row carries that object's filesystem identity, and the row's key is the
caller's own action identifier.

The service cannot know which sessions and automation runs are bound to a workspace, so whoever
owns those lifetimes records the binding here and the service enforces it: a workspace a live
session or run still holds refuses removal whatever retention policy the request carries, and
nothing new may hold one whose removal has begun.

`docs/project/` has the ten methods, the identity model, the staged publication, the credential rule
and the restricted Git execution profile.

## The automation service

The daemon hosts the environment's automation service, which manages workflow definitions,
runs, and causal budgets.

Workflows execute as versioned directed acyclic graphs of registered action nodes. Each run is
bound to an explicit grant, an immutable causal root, and a causal budget. The workflow journal
is an environment SQLite store in the environment's state directory that commits triggers, runs,
and budget reservations transactionally before execution dispatches, and that keeps a budget
across a restart and a reboot.

The five methods of the automation group arrive through the daemon's ordinary path, and the grant
each definition names is read from the daemon's own grant store rather than from the request. The
four mutations are actions: each one's effect and the record of what it came to commit in one
transaction of the workflow journal, and the admission the daemon accepted the mutation under is
carried into that transaction and asked immediately before the action's first write: the same check
the project service asks inside its own work, the fence this host may owe, the registration and the
deadline. A repeat is answered from the record before its freshness is considered. The daemon reads
the grant again before every node a run dispatches, so a revocation or an expiry stops the run where
it stands, and a node is dispatched only when that grant carries the right its effect needs. It
decides a workflow's grant with the model it decides a paired device's request with: the configured
rights ceiling narrows the grant, the policy decides it, the offline bound holds on the continuous
clock, and nothing is decided while a floor a refusal stood on is still owed its record. A node's
change-set write is held under its grant inside the change-set service's own transactions: each
transaction that commits the effect takes the daemon's registry, refuses while a fence is owed and
reads the grant as it stands, so a grant withdrawn while the write waits for the store stops it.

A run started through `workflow.run` is an external trigger with a causal root the daemon mints.
The daemon also runs the automation service's trigger dispatcher: when a node succeeds, the event
its action kind fixes is committed with its outcome, and the dispatcher starts the workflows whose
trigger names that event, with the causal root, depth and parent taken from the journal's record of
the node. At startup the daemon recovers the journal before it serves anything: a node that was
running may have been dispatched, so it is settled as unknown and its dependants pause. The
dispatcher starts last, once the start has passed every gate it has, the configuration put into
force among them, and it first resumes the runs a stopped daemon left unfinished. A start that
fails executes nothing.

Admission is decided from the workflow journal: four runs of a workflow at once, a hundred more
waiting as pending, and host-wide and per-grant rates whose admissions the journal keeps, so a
restart is not a way past them. A run's deadline and each action's wait are measured on a reading
of UTC that follows the wall clock while it keeps pace with the continuous clock and runs on at all
but a thousandth of continuous time when a wall clock is set back, and an action that outlives
either is asked to stop and stops its run. A limit exceeded pauses the workflow and records one
attention item. A new chain inherits the session
number admission enforces as a ceiling on the sessions it creates. Breaching a causal budget pauses
the chain with error code `CAUSAL_LIMIT`, rejects further descendants, and commits one attention
record in the same transaction as the pause.

`docs/automation/` has the five methods, graph validation, the budget model, and source workflow coordination.

## The host time contract

`kr_worker::action::time` holds this host's time contract. It rests on three anchors and concludes
only what each one supports.

What asks it is retention: section 9 stops expiry-based collection while the wall clock cannot be
proved, and the session's journal prunes only when the contract says collection may run. The
deadlines that exist besides that, the action window, the dispatch lease and the accepted deadline
of a mutation, are decided on the transport's suspend-aware continuous clock, which is the same
anchor reached by a different route. The contract also has a shape for a signed object that has to
outlive a reboot, `ExpiringObject::signed_across_reboot`: no store holds one, and nothing outside
the contract's own tests builds one.

| Anchor | What it proves |
| --- | --- |
| the recorded boot identity | which boot a continuous reading belongs to; a reading from another boot proves nothing, because the clock restarts |
| a suspend-aware continuous anchor (`kr_ipc::clock`) | how much time has passed, including time the machine spent asleep; a timer that excludes sleep cannot extend authority |
| a trusted UTC deadline | the only thing that can outlive a reboot, and usable only while this host can prove what its wall clock reads |

A wake, a reboot or any other discontinuity owes a revalidation before an expiry-dependent read or
mutation is served. The detector is two clocks rather than a notification: one counts a suspension
and the other does not, so the difference between two deltas of theirs *is* the suspension, with
nothing to subscribe to. On Apple and Linux the second clock is `std::time::Instant`; on Windows
`Instant` is the performance counter, which keeps running through a suspension, so the detector
there is `QueryUnbiasedInterruptTime` beside the biased counter `kr_ipc::clock` reads. A suspension
shorter than the tolerance is not noticed, which is a bound rather than a guarantee.

A wall-clock rollback beyond five seconds marks wall-clock trust unresolved. That stops
expiry-based collection and refuses objects whose expiry cannot otherwise be proved. It does **not**
disable a non-expiring personal owner grant, or a fresh online action bounded by this boot's
continuous clock: neither depends on the wall clock. A forward step expires conservatively, and a
rollback never enlarges a lifetime. A previously expired object never revives, because its
expiration tombstone answers whatever the clock later reads.

The rollback is measured against the furthest point this host could ever *prove* the clock had
reached, projected forward by the continuous time since. Measuring against the previous reading
alone would forgive a little slippage, then forgive the next against the moved mark, and enough of
those would give a deadline back indefinitely. The same proven reading is what a UTC deadline is
compared against, with the platform's own uncertainty bound added to it, so an object expires when
it cannot still be valid rather than when a forgiving clock says so.

The checkpoint, the trust it stood at and the expiration tombstones are what a host writes down.
Without them a restarted host would start trusting a clock it had marked unresolved, and an object
it had already expired could revive; `TimeContract::durable_state` and `TimeContract::restore` are
the two halves. A host with nothing recorded starts trusted only when its own time service says so,
because with no earlier mark that answer is the whole of what it knows.

Returning to trusted needs qualified evidence from the configured host time authority and a new
checkpoint, with the old tombstones retained; without that, the owner performs an explicit
authenticated retrust. An ordinary paired peer's clock is never a time authority.

### The platform time adapter

The adapter records the synchronisation source, its status and a bounded uncertainty, using the
interface the platform supports. Nothing here opens a socket, contacts a time server or signs
anything.

| Platform | What is read |
| --- | --- |
| macOS | `ntp_adjtime(2)` with no modes set: the kernel discipline the system time service maintains, its status word, its maximum and estimated error, and the time state as the return value |
| Linux | `ntp_adjtime(2)`, the adjtimex status, maintained by `systemd-timesyncd`, `chronyd` or `ntpd` |
| Windows | `w32tm /query /status`: the W32Time service's own source, leap indicator, stratum and root dispersion |

The reading half is behind `cfg` because the call is; the classifier is not. `fixtures/time/adapter.json`
records real platform values for all three platforms and the classification each must produce, so
one machine checks every platform's classification while only its own reading comes from the
kernel. A reading the host could not take reports `unavailable` rather than a synchronised clock
with no stated error, because not knowing is its own state.
## Attention, review and what changed since a visit

The environment has one attention store, and the control daemon holds it. It keeps one inbox for
every session the environment runs and for the environment's own workflows, each actor's
acknowledgements, review state, visits and the one quiet-hours window, beside the daemon's other
state as `attention.sqlite3`. It lives with the
daemon because it has to outlive every session: review work a session produced stays after the
session has ended, and a paired device reads one inbox rather than one per session. What a session
records stays in the session's own journal. The store keeps none of a session's text, only where
to read it from, and it reads no clock of its own: every decision that depends on time takes a
reading of the host time contract from the daemon.

### Where its events come from

Two sources in each session's journal reach it: the question ledger, whose events carry the moment
a request became pending, and the journal's host events, which are the terminal side effects that
had no attachment to go to. For each live session the daemon opens a connection of its own to the
session's worker, verified and bound to the daemon's generation like every other, and declared for
attention: it carries the daemon's requests for these records and nothing else, and a newer one
replaces the one before it. The daemon keeps one request for records past the store's cursors
waiting on it. The worker answers that request as soon as it commits a question transition, a host
event or a privacy transition, and after at most thirty seconds otherwise, so a question asked in a
session is in the inbox within moments rather than at some later pass.

A page is read in a fixed order: the moment, then each source's newest record and the records after
the cursor up to it, then the session's privacy record. A page that reaches the newest record of
both sources certifies everything the session committed before the moment it was read, and a timer
of that session is decided only up to its latest certified moment. That is what keeps an answer the
store has not read yet from turning into a reminder. A page that stops short is followed by the
next one at once. A link that stalls or fails certifies nothing more, and that session's timers
wait for it. They are late then, never early. A record that no rule covers moves the cursor and
raises nothing, so a later record is not read as a range retention took.

A page announces nothing by itself, since a question raised and answered inside a backlog is not a
notification to send now; the timer pass that follows a certified page decides what is still owed.
A timer is otherwise decided when it falls due, so a five-minute reminder is five minutes rather
than five minutes rounded up to the next time the host happened to look. What it counts from is
where the host read the record, not where the request started waiting, because the sources this
build reads record when something happened and not where that moment sat on the clock intervals
are measured on. The reminder is late by however long a record waited to be read; the next
paragraph is why that is the direction to err in.

One clock measures every interval, and it is not the wall clock. A wall clock can be set, and a host
that trusts one still trusts it after somebody moves it forward an hour, so two readings it vouches
for are not two readings on one scale. Intervals are measured on the machine's continuous clock
instead: it only goes forward, nobody can set it, and it counts the time the machine spent asleep.
It means nothing outside its own boot, so every interval the host writes down is kept as the
continuous reading it starts from *and* the boot that reading was taken in, and one whose boot has
ended starts again rather than being worked out across the gap. It starts again once, because
opening the store is what restarts it and opening the store writes the new start down, so the next
open finds an interval this boot can measure. An event brings an anchor of its own when its producer
read that clock, separately for each moment it carries, because a request can become pending long
before the record of it is written. Every one of those answers is nought or less than the true wait,
never more: a reminder that comes late is still a reminder, and one raised seconds after a request
because somebody corrected a clock is an interruption nobody earned. The wall clock keeps the two
jobs it can do: deciding quiet hours, and saying when something happened for a person reading the
record. The store keeps the host time contract's own record beside it, so a daemon that restarts
still knows whether the wall clock was ever rolled back.

### A session that ends

The store ends a session's live conditions only on a closure this daemon recorded and could account
for: the worker's own handover, or a closure after a death the host confirmed. It then reads what
is left of both sources from the session's journal, with the same reads a live worker answers
with, and finishes the session in one write. A pending approval, a pending request and its idle
reminder leave the inbox as ended with the session, never as answered, approved or completed.
Review work stays, and so do failed commands, notices and gaps. Finishing a session twice changes
nothing, and a page that arrives for a finished session is not taken.

A closure written over a worker the host could not confirm had ended opens nothing. Its sources
become gaps with no known end, its items stay and are marked uncertain, and its timers are never
decided, because the worker may still be running and writing records nobody will read. A journal
that cannot be read is a gap with no known end too, and then the session is finished. A closure the
store could not write down is kept and tried again every few seconds rather than dropped.

A daemon that restarts opens the store again, finds each session it was reading, and reads it from
its worker or finishes it from its journal. Nothing it rebuilds is announced: an event from an hour
ago is history rather than a notification to send now, so the replay restores each item with the
age it had, where the anchor that age is measured from belongs to this boot, and starts the age
here where it does not. Its timers wait for the first page each session answers with.

### The workflow journal's alerts

The environment has a source of its own beside the sessions': the workflow journal (see *The
automation service*). When one of a workflow revision's own limits is breached, or a causal chain
runs out of budget, the journal commits one attention record with the pause, and when a paused
revision is enabled again it commits one that ends the pause's item. The daemon reads these records
as the journal's registered attention consumer, at its start and every two seconds after. It
registers again before every pass, which also tells it how far the journal records it as having
read. The journal depends on the registration: it removes a record of an attention type only once
every consumer registered for that type has passed it, and never removes a type nobody has
registered for. The store removes nothing from the journal.

A pass reads the records past the store's own cursor, commits what they raise or end, and only then
tells the journal how far the store has read; the journal keeps the furthest position it is told. A
daemon that stops before the store's commit leaves the journal where it was, so the next pass reads
the same records again. One that stops after the commit has nothing left to read, and the next pass
tells the journal all the same, whether or not a later record has arrived. A record is therefore
neither lost nor counted twice. The journal numbers every event it holds in one stream, a run's
events among them, and hands the store only its attention records, so a jump in their numbers is
other events rather than a range retention took.

A journal that records the store as having read further than the store's cursor says the store lost
what it had written, or was put back to an earlier copy. The pass then reads again what the journal
still keeps of that range and, in one write, feeds it, records the whole range as a gap and moves
the cursor to its end. Every automation item still unresolved is uncertain afterwards, because the
journal may have let records of that range go. A pass that stops before that write has written
nothing, and the next one does the recovery again, whole.

Each record that raises an item carries the grant the paused revision or chain acts under, read
from the journal when the store takes the record: the grant the revision names, or the one the
chain's root run acts under. Neither ever changes. An item whose grant the journal cannot name is
the owner's alone. A record announces nothing by itself: once a pass has read to the end of the
journal's records, the timer pass decides what an item it raised is owed, as it does for a session
after a page that reached the head of both its sources. `workflow.read` shows as alerts the
attention records the journal does not yet record the store as having taken.

### The rule set

Nine rules, each with a stable identifier that outlives any change to the wording it produces.

| Rule | What raises it | Starts at | While it stands |
| --- | --- | --- | --- |
| `attention.pending_approval` | An agent is waiting for an approval decision | urgent | announced again every five minutes |
| `attention.pending_input` | A verified source is waiting for an answer | notable | announced once |
| `attention.input_idle_reminder` | A verified request has waited five minutes | urgent | announced again every five minutes |
| `attention.command_failed` | A command exited nonzero | notable | announced once |
| `attention.review_ready` | A turn finished and is waiting to be reviewed | notable | announced once |
| `attention.adapter_failed` | An adapter failed | notable | urgent after five minutes, then every five |
| `attention.host_contact_lost` | Contact with the host was lost | notable | urgent after a minute, then every five |
| `attention.application_notice` | An `OSC 9`, `OSC 99` or `OSC 777` sequence | informational | announced once |
| `attention.automation_paused` | One of its own limits paused a workflow revision or a causal chain | notable | announced once |

The idle reminder counts from the moment the request became pending, not from the last output: a
session printing continuously while a question waits still owes the reminder, and a silent session
with nothing pending does not. A repeat of the same condition inside sixty seconds is counted on
the item rather than announced again.

An approval is one item per session and request: the same upstream identifier in two sessions is
two approvals, because each session's agent is waiting on its own.

A paused workflow is one item per revision, however many refusals the pause produced, and
enabling that revision again ends it. An exhausted causal chain is one item per chain. Nothing
records the end of a chain's exhaustion, so its item stays in the inbox, and each actor
acknowledges it for themselves.

An application notice is the one untrusted rule. Any process writing to the terminal can emit one,
so the item says so and the rule cannot raise any other kind of item; nothing a notice says makes
it a pending approval. A notice the host recorded as a side effect is one that had no attachment to
go to: section 8 sends a notification to the attachment holding the input lease, and a record
exists because nobody held it. With no lease holder there is nobody to send it to, so it goes
through the owner's configured notification policy, and it is retained in Attention. Two notices
that say the same thing are one condition. The store knows what a notice says by a keyed digest the
worker makes under a key the store gives it for that session, sent whether or not the notice's text
is, so the item is the same with privacy mode on or off and nobody without the key can test a guess
at withheld text against it.

### Quiet hours

A quiet-hours window defers an announcement and releases it when the window ends. It never drops
one, and it never takes an item out of the inbox: an urgent pending approval is in the inbox
throughout, with its audible delivery held. The one thing that does take a held announcement away
is the condition it was about ending, which is a cancellation rather than a loss: nothing is
waiting on the person any more.

Setting or clearing the window records it and announces nothing by itself. What the change lets
through is released by the next timer pass, and the change wakes that pass rather than waiting for
its next tick, so the release follows the setting rather than the minute. That is what keeps a
release a decision about the present: announcing inside the setter would decide against whatever
history the host had read at the moment somebody happened to change a setting.

The window is minutes of the UTC day, so the host needs no time-zone database to decide whether it
is inside one. A client converts its own local window before it sets one and may record the zone it
converted from, which the host stores and gives back and never interprets. A host that cannot prove
what its wall clock reads is never inside a window: quiet hours are a time of day, and a
suppression decided on an unprovable clock would withhold a notification at an hour nobody chose.

There is one window for the environment. Setting it is host management rather than session view
authority, because one window suppresses the owner's delivery rather than one actor's.

### Acknowledgement

An acknowledgement is one actor's, and it names each item by its key and the revision it was
read at. An item's revision moves when the item is raised and at each new occurrence of its
condition, so an acknowledgement covers what the actor saw and no more: a later occurrence is
outstanding for that actor again. A key whose item has gone, moved past the named revision or is
outside what the actor may see records nothing and is answered as stale; a revision beyond the
item's own refuses the whole request with nothing written. Each actor has one revision for the
environment, advanced by its acknowledgements of attention, review and visits.

Every change the group makes is the daemon's own action: its record is committed in the same
transaction as its effect, the admission it carries is checked again inside that transaction
before anything is written, an exact repeat is answered from the record, and the same action with
another payload is a conflict. A record is kept for thirty days, and one is only let go of on a
wall clock the host can prove, so a rollback cannot make a live record look expired.

### Review, and what it does not do

A version only goes forward, and each version an event names is weighed on its own. A turn at a
version the host has already reached is a record arriving late rather than new review work: it
moves the source's cursor, so what follows it is not read as a range retention took, and it raises
nothing, reopens no completed review and is not a change since anybody's visit. A change set named
beside that turn is weighed separately, so one arriving at a version the host has not seen is
recorded, is review work again, and is a change since a visit, whatever the turn beside it said.

A review acknowledgement records that one actor read one version of one subject: a completed turn,
or a captured change set. It approves no command, applies no patch and changes no Git state.
Section 14 makes promotion a separate authorised action, and the engine has no operation that
performs one, so that holds by construction rather than by policy.

An acknowledgement binds the version it was made against. When a later version arrives the subject
is outstanding again, because a new change is new review work and an acknowledgement of an earlier
version does not cover it. Acknowledging a subject the host holds no version of is refused, and so
is a version beyond the one it holds, and so is a subject of another session than the one the
request names.

An acknowledgement affects only the actor that made it. It does not stop the host reminding
anybody: the ladder and the repeats belong to the condition, and they end when the condition does.

A refusal the host can decide is decided before anything is dispatched. A subject the store never
held, a version nobody produced, a counter the store could not write down as it was given, a
quiet-hours bound that is not a minute of the day, a log view past its own bounds and one more
actor than the store admits are all rejections, not outcomes nobody can establish.

### Changed since a visit

A visit records how far one actor has read in one session, and never moves backwards. Each session
has a change log of its own, of the last thousand changes and up to sixty-four ranges it has let
go of. The view compares the visit's cursor with that log and answers with three separate things:
the authoritative changes, the ranges that are missing, and a model summary when one covers the
interval. The three never merge. A summary names the interval it was written from and cannot stand
in for an event; a gap is not an absence of changes but a statement that the host cannot say what
was there.

A log view's source offset and its filter travel with the visit. They come back after a reconnect,
each view keeps its own position when a client switches between two, and a view whose range
retention has taken is served from the oldest byte that still exists with the range between stated
as an explicit history gap. A live session's oldest byte comes with each page its worker answers
with, and a finished session's is read from its spool, since retention goes on after the session
has ended.

### The feature store, and what a gap means

What the store decided is a projection of the sessions' records, so that half can be rebuilt from
them: replaying a record the engine has already consumed changes nothing, which is what makes a
rebuild safe to run twice. What people and clients put there is not, and no replay restores it:
the acknowledgements, the per-actor revisions, the visits and their log views, the quiet-hours
window and the identities already given to announcements are records in their own right, and the
store is where they live. It keeps a cursor for each session's two sources and one for the
workflow journal's attention records, and a write changes the rows a decision changed rather than
the whole store.

The daemon is the one owner of the store, for as long as it is running, and the environment's
singleton lock is what makes it one daemon. The store also keeps its own claim, for a second
process that reaches the file some other way. The claim is a row inside the store: opening it
reads that row first of all, and writes its own under the same transaction, so whatever name
reached the database reaches the one claim, and an opener that may not have it is told who holds
it before a row of the state has been read. Every write reads the claim again, inside the
transaction it writes in, so an owner whose store was taken while it was away replaces nothing: it
is told the store is no longer its to write, and whoever opens the store next reads it fresh.

Letting the store go removes that one claim and nothing else (not the state, and not a claim
somebody else now holds), so the next opener does not have to work out that nobody is holding it.
That removal is the best the daemon can do rather than a promise: a file that has gone, or another
holder of it that keeps the write waiting, leaves the claim where it is. An owner that ends without
letting go, one that was killed or a machine that stopped, leaves its claim behind too, and the next
opener is what clears it. A claim from a boot that has ended is not standing, because that boot's
processes are gone with it. A claim from this boot is weighed on the process it names: the owner
records the pair the kernel describes, its number and the start value that tells it apart from
whoever holds that number next, so a claim whose process has gone is taken the moment the next
daemon asks. Where the platform will not answer, the claim's own lease decides instead, and it
stands for ten minutes unrefreshed against an owner that refreshes it on every write and a
maintenance loop that writes at least once a minute. A process the kernel says is running keeps its
store however long it has been idle.

A database is journalled under the name it was opened by, so one file that two names reach can be
journalled twice over by two processes that never see each other's work. The store refuses such a
file outright and says how many names reach it. The count is of the file the store has open rather
than of whatever a name reaches now: on Windows it comes from the store's own handle on the file,
and on the Unix family, where nothing safe describes an open file, the name is described without
opening it (a second descriptor there would drop every lock this process holds on the file), and the
store then asks its own database whether the file it has open is still the one that name reaches.
Those are two answers rather than one, so a name swapped between them is not ruled out; what is
ruled out is every ordinary second name. A host that cannot answer at all is refused rather than
admitted.

Every mutating call writes the new state before it publishes the decision. A write that fails
leaves the engine where it was, so the same event can be offered again and produces the same
answer. The exception is the store being taken: that value holds a state that is no longer the
store's, so it answers nothing more rather than retrying against it, and the daemon serves no
attention until it is started again and opens the store afresh.

A decided announcement stays written down until a delivery consumer says it has taken durable
responsibility for it. Taking one is two steps for that reason: the host offers what is outstanding
without forgetting it, and forgets it only once the consumer has settled it by its own identity,
which is the item and the announcement's number. That number comes from a counter of the store's own
that only goes forward, so it outlives the item it was given for: a condition that ends and returns
is a new item, and an identity a consumer already recorded can never settle a decision made after
the condition came back. A host that died at any point before the settlement offers the announcement
again. What becomes of it afterwards (the destinations, the attempts and the receipts) belongs to
the delivery journal. An announcement names its item's text by where to read it, and a consumer that
sends the text reads it under the same release as a reader does (see *Privacy mode and the text an
item carries* below).

An item holds one outstanding decision at a time. A later announcement about the same condition
replaces the identity waiting to be taken, and the condition ending takes it away, because an
announcement about something that is no longer true is not one anybody wants. So a consumer takes
what is waiting rather than a queue of everything that was ever decided.

A jump in a source's sequence means the records between were evicted. The engine records the range,
names the session it belongs to, marks every unresolved item of that session and source uncertain,
and leaves it in the inbox; an item of another session is not touched by it. The workflow journal's
records are the exception: a jump there is other events, and their only gap is the one a recovery
records. A gap is never an
approval and never a completion: an approval whose answer may have been in the missing range stays
pending and says the host cannot tell. A gap with no known end says that nothing after its start
can be read at all. The store keeps the last sixty-four gaps.

The inbox is a working set rather than a record: the receipts, the question ledger and the retained
output are where the history lives. Past five hundred items the host lets go of its least urgent
and oldest *record* of a condition, and the read says how many it has let go of. An item that has
only just arrived is not one of those: nothing has been decided about it yet, so it is kept until
its decision has gone out, been recorded by a consumer, and outlived the minute in which the same
condition would be folded into it rather than announced again. Weighing what is left by level and
age is what stops a fresh notice displacing an urgent approval.

What the bound never lets go of is a condition somebody or something is still waiting on (an
unanswered approval, an unanswered request, an adapter still down or a host still out of contact) or
a decision about one that is still in flight: one no consumer has settled, one quiet hours are
holding, one nobody has made yet, and one whose sixty-second window is still running, because the
item is the whole of what the host remembers that window by and letting go of it would announce the
same condition twice inside it. When the whole inbox is those, it goes over its bound rather than
answering that nothing is waiting or losing an announcement nothing will offer again, and it comes
back inside its bound on the next timer pass, against what that pass decided and what a consumer
settled meanwhile. A host whose notifications nobody is taking therefore keeps them rather than
silently dropping them.

Review state has no retention at all. A subject nobody has acknowledged is outstanding review work,
and deleting it would answer that there is none; a subject somebody has acknowledged is that
actor's own record of what they read, and nothing can rebuild it from the events, because the
cursor that consumed them has already moved. What is bounded is the answer: a review read returns
at most two hundred subjects and continues after the last one it gave, in the order the host first
heard of each subject, so a new version of one already served does not move it under a page that is
continuing. A subject the caller may not see is refused as a continuation rather than silently
restarting the list.

A feature store admits two hundred and fifty-six actors; past that a new actor's acknowledgement is
refused, before anything is dispatched, rather than an existing actor's being deleted.

### What a caller is served

The owner at this machine sees the whole store. A paired device sees what its grant admits: a
session's items, review state and visits when the grant's selectors admit that session and it
carries `session.view`; a paused workflow revision's or causal chain's item when it carries
`automation.manage` and the revision, or the chain's root run, acts under that same grant, which is
how `workflow.read` decides what a device is shown; and the environment's other items when it
carries `host.manage`. An automation item whose grant the journal could not name is shown to no
device. The same scope bounds a read's items, the gaps it reports and where it may continue from; a
gap in the workflow journal's records is shown to a grant that carries `automation.manage`.
`attention.read` and `attention.acknowledge` are reads of the caller's current view rather than
rights of their own, so a device holding only `host.manage` reads the environment's own items and
none of any session or workflow. A read may name one session to narrow the inbox to it.

An item's text and a change's text come from retained content: a question's wording, a command
line, what an application printed. The store keeps none of it. When the owner reads the inbox, the
daemon asks each session for the text of the items it is about to serve, all at once: the live
worker over its attention connection, or a finished session's journal. A session that does not
answer within three seconds, one closed over a worker the host could not account for, or a record
that is gone serves no text. A question's wording is served only from the
record that created the question: every later transition of the question carries it again, and
serving it from one of those would serve text written before a privacy transition under the one
after it.

Section 10 narrows retained content to the grant that asked for it, and this host cannot narrow a
moment in time to an item's text, which is why it refuses a retained history page to a paired device
outright. An attention item is not a history page, so it is narrowed rather than refused: a caller
that did not arrive over the local socket is served the host's own record of a condition (which
rule, at what level, how often and when) with the text left out and said to be left out, and no
model summary either.

An item's key carries none of that text either. A key has to be derived rather than allocated, so
that rebuilding the inbox from the retained events lands on the items it had before, and it travels
to every caller that may read the inbox at all. So it carries a digest of the subject rather than
the subject: a command line or a notification body cannot reach a caller inside the key of the item
whose text was withheld.

### Privacy mode and the text an item carries

A session serves a record's text only while privacy mode is off, and only for a record written
after the last privacy transition: the transition writes down where each source stood, in the same
transaction, and nothing at or before that point is served again, live or from the session's
journal once it has closed. So text from before privacy mode was enabled, and text written while it
was on, never comes back. A journal with no privacy record serves no text at all.

That covers what a session answers with from now on. Section 24 also asks that no late
old-generation result is published: text a session answered with before privacy mode was enabled
may be in the daemon's hands when the new generation is committed, in a read that has not been
written to its reader yet or in a delivery that has not been sent, and it must not leave the daemon
after the commit. Two things see to that.

Before the worker commits a generation that enables privacy mode, it raises a transition and tells
the daemon so, in a statement on its attention connection. From then on its own answers carry no
text. The daemon applies the statement under the same lock every release of that text takes, held
exclusively, and acknowledges it once applied; from then on it releases none of the session's text
until a later statement settles the transition. Statements carry one order the worker keeps for its
whole life, and the daemon applies one only from the connection that speaks for the session now and
only when it comes after the last it applied from there, so a statement that arrives late cannot
undo a later one. Every new attention connection starts with a statement of where the worker
stands, so a daemon that restarted, or a connection that replaced a lost one, knows about a
transition before it serves anything that connection carries. A statement the worker cannot write
within two seconds ends the connection, and the next one starts with the worker's state as it is
then; so does one that cannot name the generation the session's journal holds, because the worker
cannot read it: such a statement says a transition is in progress, since lowering the barrier
without naming the generation committed would release text decided under the one before. A journal
that holds no privacy record names no generation either, but it was read and serves no text, so its
connection stays. A statement is sent by a task of its own, so a caller that stops waiting for one
does not stop it.

A daemon that does not answer in time cannot be relied on to have stopped anything, so the worker
does not rely on it. Every answer that carries text also carries a lease: the moment, on the
machine's continuous clock, after which the daemon releases none of that text. It is five seconds
from when the worker decided the answer. Without an acknowledgement the worker commits only once
every lease it has issued has ended, and with one, once every lease it issued to any other daemon
has ended, since the acknowledging daemon's barrier holds back only what that daemon holds itself.
No lease is issued after the raise, so the wait for leases is at most one lease, five seconds,
however the daemon behaves. A second transition waits for the first to be settled, and completion
waits for the daemon, as below.

The daemon checks the release before every write to a transport, not once per answer. An answer to
the owner goes to its connection one non-blocking write at a time, each made under the shared lock
right after the check and handing over at most 64 KiB, and the wait for room happens with the lock
let go. On Windows the bound is what limits that: a named pipe takes whatever it is offered whole
and finishes sending it on its own, so what can still go after a check fails is the one piece that
check admitted, as on the Unix family it is what the socket already took. When the check fails, an
answer none of which has gone is taken back and the same answer goes without its text; one the
reader already has part of is not finished, and the connection ends, so the reader asks again. A
read with text from several sessions is stopped by a transition in any of them, and a read that
outlasts the lease of the text it carries is cut the same way. So is text from a session closed over
a worker the host could not account for, from the moment that closure is recorded: such a worker may
still be running and changing its privacy state where the daemon cannot see. The margin the check
keeps before a lease ends, one second, is the time it allows between reading the clock and the write
it admits; a daemon thread held off the processor for longer than that between the two, or a machine
suspended in that instant, is the one case a lease cannot order. A delivery consumer releases the
same way: each transport write of session text is made through the daemon's release, which refuses
it once the check fails, and a consumer whose transport would send held bytes later on its own
cannot carry session text. No sender of this host meets that contract, so none carries any, and a
request already handed to a transport can still leave within that sender's own deadline. Text read
from a finished session's journal needs no lease, because no transition can follow a closure the
host confirmed.

Privacy mode reports complete only once the daemon has recorded the new generation, which a request
on the current attention connection says when it names that generation. Until then the worker's
attention subsystem reports one piece of cleanup outstanding, and with no daemon it stays that way.
One transition is raised at a time: a second waits until the first is settled, and one its caller
abandons is settled when it is dropped. Workers raise a transition when the daemon tells them that a
new generation has turned on privacy mode, and settle it afterwards. If the worker is started while
privacy mode is already active, no transition will be raised, since no attention connection or text
lease exists before its shell is started.

## Notification delivery

An attention decision is not a notification. The engine decides that something wants a person and
offers the decision; the delivery journal takes it, records it durably, and only then tells a
destination.

The store keeps that order. A notification row names the event row it was produced from, and the
reference is a foreign key: a notification for an event nothing has taken cannot be written. Taking
an event and producing from it are two transactions, so a host that stops between them has the event
and no notification, and the pending work is still where a person can see it. The event row carries
the notice it was taken with, so the next pass finishes what the last one started.

The journal keeps the attention store's cursor under a consumer name that carries the store's scope,
so a position in one store is never applied to another. The cursor and the de-duplication record are
committed in the same transaction as the work they describe, and the store is acknowledged only
afterwards, so a host that dies in between is offered the same page again and the event keys absorb
it. The consumer registers before it relies on collection keeping anything for it.

The attention store is the journal's source, and the daemon takes from it on every pass. The
worker's receipt outbox is not a source: no attention rule or alert maps a receipt transition to a
notification. The take is made with the store held, in the producer's order: the announcements are
read, the events and the cursor are committed to the journal, and only then is the store told. An
announcement about a session the daemon is closing is not offered until the store has read the
session's journal to its end. The take is made only while the journal stands where the privacy
state the daemon publishes says: a fence the journal has not reached, or has not yet lifted, takes
nothing, and the store offers the same announcements again. Notifications are then built from the
notices the journal holds, one for each destination whose recipient's grant reaches what the notice
is about.

What travels to a device is an opaque identifier, a preview sealed to that device's own
notification-preview key, an expiry, and a collapse identifier that is a keyed digest. The alert a
locked screen shows is one of six fixed sentences. There is no field for text a producer supplies.

A paired device registers or rotates its notification-preview key under the admission its request
was served under. Both stores are written with the registry held, and the admission is asked again
there, after every wait: its deadline on the continuous clock, the authority it was admitted under,
and the device's own grant on both clocks. The delivery journal is written first, because it can
refuse a rotation the device directory knows nothing about, and once it has taken the registration
the directory is completed without asking again, since refusing the second half would answer a
registration that took effect as one that did not.

The daemon sends on its own. Its start path recovers what an earlier daemon left on the wire and
takes back what is no longer authorised, then a pass runs every second: it takes what the attention
store has announced, produces from what the journal holds, and claims and sends what is due. Every
HTTP exchange goes through the managed transport of the origin it is for: the gateway a delivery
credential names, the address a webhook's owner configured, or Slack's, Discord's or Telegram's own.
Mail goes to the submission server the owner's account names, over TLS the operating system's
verifier checks.

External destinations are different in one respect: their recipients can read what arrives, every
message says so, and nothing in this host claims otherwise. A destination needs a configured address
**and** an explicit rule or grant, and the content is intersected with the recipient's own authority
rather than assumed from the address.

A Slack, Discord, Telegram or email destination sends with a credential: a webhook address that is
itself a bearer secret, a bot token, or a mail submission account. The owner hands it over with
`delivery.destination.secret.set` on this host's own socket, never from a paired device, and the
answer says who will be able to read what the destination delivers. The daemon keeps the credential
in its secret store under the destination's identifier, beside its own keys and nowhere else: not in
the delivery journal, an answer, a log or an error. The journal holds a random stamp in its place,
so a credential replaced under a configured destination never carries a notification admitted
under the old one, and removing the destination deletes the credential with it.

Privacy mode fences the delivery outbox at once, takes back what was never dispatched, removes the
queued content, and does not report complete while a send of content from before the boundary is
still on the wire. A pending question or approval still alerts a paired device, with no preview and
none of its words, and nothing else decided while privacy mode is on is ever sent. Notifications
that already reached a provider are shown as retained artifacts, each saying that this host holds no
way to recall it: there is no deletion action for a copy that is on somebody else's device or in
somebody else's service, and the listing says so rather than offering one that would do nothing.

`docs/delivery/README.md` is the whole of it.

## Closure

`session.close` is a state, not a request to exit.

1. The session moves to `closing` atomically. Input is rejected from that moment.
2. The acceptance is written to the requester **before** anything is signalled, because the
   requester is often a command running inside the process group about to be stopped.
3. The owned process group is asked to stop, and has five seconds.
4. Whatever remains is forced.
5. Output drains for two more seconds.
6. The record is written: the reason, the root shell's exit status or the signal that ended it, the
   process identities that were terminated, and an ownership-coverage flag. The record never claims
   every application was discovered.

Every process in that record is named by its identifier *and* the kernel's record of when it
started, because an identifier alone can belong to something else within milliseconds. One case
cannot have both: a shell that leaves before the host has read it. A session whose shell exits
immediately, because a startup file says so or because the program it named is not there, is a
session that ran, and the host records it as one; macOS stops describing a process the moment it
exits, so there is no start value left to read, and the identity carries a reserved value that says
the reading never happened. Such an identity always reads as ended, which is what it is, and it
never matches a live process that inherits the identifier.

If the journal is unavailable the closure still happens (storage failure must not prevent an
authorised stop), and the reply says `durability=volatile` rather than claiming otherwise.

The control daemon watches a closing worker and writes the tombstone and removes the descriptor
once the kernel agrees the worker has gone. A worker that disappears without a close request is
reconciled the same way and recorded as an abnormal closure. A daemon that merely cannot reach a
worker records nothing: not reaching a process is not evidence that it died.

A worker that has finished its closure stops answering a moment before the kernel says its process
has ended. A `session.read` or `session.list` that meets it then is answered from what the daemon
holds: the session as the worker last described it, `closing`, or `closed` where that was its last
word, with no endpoint and none of the session's content; a list shows a closed one only when it
asks for closed sessions. The worker describes its session in its ready report, in its answer to
each read and in its acceptance of a close, and the daemon keeps the description furthest along
the lifecycle, so a close it passed on, the first time or as a retry, leaves it one to answer with.
Where the daemon holds no word of an end, the read is refused with `RESOURCE_UNAVAILABLE` to be
tried again, and a list gives the session as the registry holds it. A paired device's close answer carries the
worker's description only when the decision it is written under lets the device read the session
(`session.view`).

The session list includes all unclosed sessions from the session registry. A session whose worker cannot answer, a session created but not yet reported for by any worker, and a reservation that recovery has not resolved are each listed from the registry's own rows, as `live`, `creating` or `closing`. If the session was created with a specific shell and/or directory, these will be shown. Size is the requested session size, or the invisible default where the create named none. The daemon asks the workers in turn, and each connected worker that does not respond holds the session list for up to two times 5 seconds.

## Recovery

A replacement daemon takes the environment's singleton lock, advances its persistent generation,
and rebuilds its directory from the registry rows and the published descriptors, never from a list
of process names. Each worker is verified by a fresh challenge. A descriptor that fails is
quarantined and never spawned from. A descriptor whose reservation this host fenced is quarantined
without a challenge: the fence says the worker is not to be reached again, and recovery leaves such
a worker alone for the same reason. No worker is killed because the daemon restarted. A worker the
registry records that did not answer at start is looked for again before a read, a device's link or
a local caller's prompt says its session is unknown.

A worker accepts its current generation again only after a fresh challenge, which fences that
generation's previous connection; it refuses a lower generation and requires a strictly higher one
from a replacement. The daemon's identity key is created once and loaded thereafter: a missing key
on a later start is a recovery condition, not an invitation to make a new one, because every live
worker holds the public half and rotation is a procedure that closes them all.

## Grants, sharing and revocation

A grant is the authority a request is decided against. It names its issuer and its recipient, the
authority revision it was issued under, the environments and sessions it covers, the actions it
permits, how far back it may see, when it stops and which organisation membership it requires.

Two stores hold grants. A pairing writes its grant into the device record.
`crates/kr-controller/src/grants/` holds the grants this daemon issues through the sharing method
group, among them the session shares a device redeems. `grants::decide` is the intersection both are
decided by, and both read the registry's required-rights column, so neither invents a right the
other does not ask for.

**A device acts under one grant.** A paired device's request is decided under a single grant, never
a mix of two, because rights, selectors, history scope and lifetime belong together. A mutation
names the grant it acts under in `grant_id`, and may name only the device's pairing grant or a share
issued to that device; any other grant, a voice grant and an identifier nobody issued are refused
alike. A request that names none is decided under the pairing grant when its selectors admit the
session, and otherwise under the one live share that does. When several shares admit the session
and nothing names one, the request is refused and says to name the grant, which a mutation does and
a read cannot: a client that acts under a share names it in its first mutation, `session.attach`
for a subscription. A request that names no session is decided under the pairing grant.

The pairing grant stays the condition for connecting at all. It has to be unexpired, and it has to
stand under this host's policy, whichever grant a request acts under, so a share is reachable only
while the device's pairing grant lasts. A connection serves one session, and the grant it opened its
link to that session under is the grant it acts under for that session until it ends. The worker
keeps state that belongs to a grant, the history scope a subscription carries and the lease an
attachment holds, and deciding a later request under another grant would leave that state outliving
the grant it was made under. The worker is told which grant a request was decided under, and holds
its answer to that grant's rights and history scope.

A share's own end is a time bound beside the others a decision holds. A share that has run out
refuses what it would decide and ends a subscription it was carrying at the next batch, and it
writes nothing on the device's record: the device was paired under a grant of its own, and is served under it afterwards.

`grants::decide` takes the intersection in this order:

1. The method has to be in the registry and reachable from the caller's ingress class. An unlisted
   name is denied whatever the caller holds.
2. The grant has to be live: not revoked, no revoked ancestor, redeemed, not expired, and claiming
   no revision this host has never issued.
3. The host's own policy has to permit it: the organisation lease it requires, and the bounded
   offline-validity policy when the owner chose one.
4. The selectors have to admit the environment and the session the request names.
5. The intersected rights have to carry every right the method requires under the conditions this
   request meets.

The rights come from `kr_protocol::method::REGISTRY`, which is section 23's table with one entry
per method. Nothing here restates that table: a second copy drifts, and the copy that drifts is
always the one an authorisation check happens to read.

**Expiry does not downgrade.** A grant whose deadline has passed refuses the request. It does not
silently keep serving reads, because continued reads still need valid authority and a narrower grant
is something the person chooses.

**A grant's issuing revision is provenance, not a deadline.** Somebody else's revocation advancing
the host's revision does not invalidate an untouched grant; what stops a grant is revocation or
expiry. A grant claiming a revision this host has never issued is refused, because nothing here
could have issued it.

**Expiry is decided from a clock that does not go backwards.** The host keeps the highest reading it
has decided from and uses the later of that and the current clock, so winding the clock back past a
deadline does not revive a grant the host has already refused.

**A grant's time bound is decided at the effect, on both of its deadlines.** The first time anything
on the host asks about a grant with an expiry in a boot, the host anchors it on the machine's
continuous clock: the time left before its expiry, read against the host's UTC floor under a clock
it trusts. The anchor is written down for that boot, so a daemon restarted in the same boot reads it
back instead of deriving it again. An end found on either clock is written down too, as the grant's
tombstone, and every later boot reads the tombstone before it derives anything. A grant holds while
both deadlines are ahead: the anchor on the continuous clock, and its expiry in UTC under the floor.
A delegation, a redemption and a transfer take the stored grant's anchor before their transaction
and test both deadlines inside the transaction that writes the effect, so a grant that runs out
while the effect waits for the store is found run out there, whichever clock ran out first. While
the floor is owed its record, nothing that can expire is decided. And an expiring grant with no
anchor in this boot is not in force while the clock is distrusted, because nothing proves it; a
grant that does not expire reads no clock at all. Workflows, push delivery and the owner checks read
the same anchors.

**Delegation narrows.** A child grant can never reach further than its parent in rights, resources,
history or lifetime, and it can never drop an organisation requirement its parent carries. The rule
is checked where a grant is composed and again where it is written, so it does not depend on a
caller remembering to ask.

**Revoking a parent revokes its descendants.** The parent link is a column in the store, so the
cascade is a property of the store rather than a loop somebody has to remember to write. A grant
already revoked keeps the moment and the ancestor it was first revoked under.

**Roles are not authority.** Viewer, reviewer, controller and owner compile to explicit actions when
a grant is written, and the grant carries no role afterwards. Only controller and owner include
`question.respond`; a viewer or reviewer receives it through an explicit invitation option that
carries the notice explaining that an answer, including free text, is input the agent may act on
under its own permissions.

**An issuer is shown what it is sharing.** The preview is computed by the same code that writes the
grant, and an invitation that names a question, an approval or the live screen is refused unless
text for that thing arrives with it and the two name the same things. `grant.create` reads that text
from the session's worker before anything is written: a named question's text, its revision and the
moment it was asked, while it is open, and what a named approval asks and when its request arrived,
while it can still be decided, pending or claimed. For the live screen it asks the worker for the
visible lines of the buffer that is showing (`session.screen.preview`, a read only the owner at
this machine makes), cut to the scope the share would carry: the buffer that is not showing and
what has scrolled off are not in it. A screen too large for a preview is not shared, because the
issuer would be shown less than the recipient will read, and a session whose worker is of a build
that cannot show it is not shared either. What an approval asks is its decoder's summary,
or where the decoder gave none, as the Claude Code channel's table gives none, the request as its
upstream wrote it, when that is text of at most 4,096 bytes; an approval with neither cannot be
named, because a preview cut short would show its issuer less than the recipient will read. An
invitation names at most 32 questions and approvals together. One that names anything the worker
holds no current record of is refused with one reason per kind, and nothing is written. A worker
that cannot be asked, or does not answer within five seconds, leaves the share unfinished: nothing
is written, and the request is told the worker could not be reached. A share that was using the
daemon's link to that worker closes it when the link fails, the exchange runs out of time or the
share is abandoned, and the worker's dispatch lease is not renewed until it acknowledges the
authority revision again. A share that only waited for the link, or could not open one, leaves the
link, and the lease, as they were. The request is refused when the notices the issuer states it
accepted are not the ones the grant carries. A shared live screen can hold text printed long before
the invitation, so the preview carries the text rather than a description of it. A new recipient
receives no historical attachment keys.

**Invitations are single use and they expire.** The default is `session.view` for one hour, from the
moment the invitation is issued: the recipient sees the selected live screen and what happens next,
and earlier history is a separate choice. The issuer may choose less than an hour or extend it to at
most 30 days. A lifetime past the bound is refused rather than clamped, because a silently shortened
invitation is one whose issuer believes something untrue about it. Persistent co-owner access is
explicit owner pairing, not a longer invitation.

**A grant is a proposal until its invitation is redeemed.** `grant.create` writes the grant and its
invitation together and the grant authorises nothing. Its answer gives the issuer the invitation's
identity, which the issuer hands to the recipient by its own means; this host sends it to no device.
The device the invitation names redeems it with `grant.redeem` over its own paired connection, and
the redemption activates the grant, once. The activation, the invitation's new state and the answer
to the redeeming action are one commit, so a repeat of the action is answered as it was even when
this host stopped before it replied. Any other action finds the work done and is refused. A device
the invitation does not name is told the same thing whether the invitation exists or not. The
answer is the grant, which names the session and what it reaches, and none of the text the issuer
was shown.

An invitation that was withdrawn or has expired activates nothing. Withdrawing one is revoking the
grant it carries with `grant.revoke`, which settles the invitation as withdrawn in the same commit,
so cancelling is a complete answer rather than a note beside live authority.

**Transfer of control is not a delegation.** The transferring device does not keep what it hands
over: the recipient receives an active grant over the session named in the plan, and the
transferring device's grant is revoked with its descendants, both in one commit. It changes who
holds authority, so it takes the owner's confirmation every time.

The confirmation is accepted against an expectation built from what the caller states this host is:
its device identity, its endpoint, the recipient's public keys, the rights the plan hands over and a
digest covering the whole plan. A challenge that supplied its own answers to those does not satisfy
it. The signer and the outstanding-challenge ledger are the caller's too, so the acceptance is only
as strong as the caller's own enrolment record. What comes out of that acceptance is evidence bound
to the host it was accepted for, to the boot it was accepted in, and to the ceremony's own monotonic
deadline, and the transfer checks all three before it does anything. A confirmation accepted for
another host, in an earlier boot, or past its lifetime authorises nothing.

The transfer hands over no more than the transferring grant carries, and it advances the revision
and fences like any other revocation.

**Nothing is lent through an intermediary.** The rule for a plugin action, an attachment action or a
workflow is the *intersection* of what the actor holds and what the intermediary declares: an
intermediary bounds a call and never funds one. `sharing::roles::effective_rights` and
`check_indirect` are where the host states that rule, for an execution path to apply where it
resolves the actor and the intermediary together.

**Delegating needs the parent and the right to pass it on.** An issuer has to hold the grant it
delegates from (naming one is not holding one), and that grant has to carry `session.share`.
Only this host's own device issues a grant that delegates from nothing.

### Revocation

`Controller::revoke_grant` and `Controller::revoke_device_authority` run in the order a revocation
cannot be correct without:

1. The grants go first, because a grant still in the store is a grant the next request would be
   decided against.
2. The revision advances, which invalidates every outstanding dispatch lease at once and
   deregisters the connections admitted under the authority just withdrawn.
3. The connections holding those registrations are fenced, so a subscription already open is closed
   rather than left reading.
4. The revision is announced to every worker, and what comes back is the per-worker completion
   status.

A revocation is complete for a worker once that worker has acknowledged the revision and fenced the
undispatched actions it affects, or once it is confirmed ended. Anything else is `pending`, and the
answer says which worker and why. Already dispatched effects and content already copied cannot be
undone.

A revocation that withdrew nothing advances no revision.

Every authority change, every voice change and every step of an update's handover is claimed under
its action identifier before its effect, and only the attempt that writes the claim performs it. A
repeat of the action is answered from the claim before its freshness window is considered, so a
caller whose window has closed, or whose daemon has restarted since, is still told what happened:

* the result the change produced, once it has one;
* the refusal it was given, when that refusal's code says the same request cannot succeed if it is
  sent again (a refusal that says it might, such as a store that could not be written, is not kept);
* `RESOURCE_UNAVAILABLE` while the first attempt is still running in this daemon, and the caller
  asks again;
* for an attempt that ended without recording what it did (the daemon stopped, or the attempt's
  task ended, in between), what this host's own records prove it did, and otherwise
  `OUTCOME_UNKNOWN`. A share is answered from the grant and the invitation it wrote, which take
  identities derived from the action. A revocation writes what it withdrew beside its action's
  claim, in the transaction that withdraws, and is answered from that once nothing is left for it
  to do: for a grant revocation, the grant it names stands revoked; for a device revocation, the
  device's own record stands revoked, its last write, and so does every grant the device holds.
  The answer names what the action withdrew, and nothing when another revocation had taken it
  first. Any fence still owed runs before the answer goes back, so its revision and barrier hold.
  That fence withdraws the registration of the connection that asked, as it does every other, so
  that connection is told to open a new one and the retry on it is answered. A claim an earlier
  build left open kept no record of what it withdrew. Nothing else this host keeps names the
  action that changed it: a device's record can hold a preview key because another action
  registered the same one. So a revocation short of that or with no such record, a preview-key
  registration, a destination's credential or a voice change in this state is `OUTCOME_UNKNOWN`.

No attempt takes over a claim, however long ago it was written: an attempt that is still running is
not known to have stopped, and one that stopped may already have reached its effect. So a retry
cannot perform a withdrawal a second time or start a second metered call, and an action identifier
reused with different parameters is a conflict rather than a second change. Callers settling the
fence one withdrawal owes at the same time raise it once: one caller at a time reads the debt,
fences and clears it, and a caller that finds it cleared answers with the revision that fence
advanced to. A fence whose clearing could not be written stays owed, and the next caller raises it
again, because a fence raised twice is safe and a debt dropped unfenced is not.

As with any other voice change, a delegation is claimed under its action identifier, and four things
set it apart. If the action is one that needs the device to sign a challenge, the answer to its
first submission is the challenge, which admits nothing, so the claim is given back and the signed
delegation (the same action carrying a different payload) claims the identifier again. The
delegation's own identifier is spent for that device for the duration of any call it was used in,
and for any later call (even after a restart) as long as the host holds on to its de-duplication
record. In particular, the same delegation under a different action identifier is refused on the
grounds that it has already been submitted. A repeat of an action is answered from the record as
long as the device is still paired with the host.

If an action would normally result in an answer with content that was read from a session, the
answer is not replayed from the record. The read is performed again using the current grants and
history bound. In particular, if the call has ended or a grant has gone, the answer to the action is
a refusal.

The fence this daemon takes is host-wide: every registration is withdrawn and the connections that
kept their authority are re-admitted at the revision now in force. Withdrawing one device's
registration on its own belongs to the network half, which owns those registrations.

### The remote authority feed

A remote owner publishes a signed revocation **request**, which carries no revision. Only the target
host numbers it, from the same sequence its own revocations use, because a device that could number
its own request would be assigning itself a place in the host's order. A record at or below the
revision this host has accepted is refused, so replaying an old feed entry cannot put authority
back, and a different request wearing an identity this host has already applied is refused rather
than answered with somebody else's revision.

Revocation records are retained until every enrolled host has acknowledged them or that host is
explicitly removed; they do not share mailbox expiry or notification coalescing. A settled record is
kept rather than deleted, because its revision is what a device list reports as that host's last
acknowledgement and its identity is what stops the request being applied again. `device.list` shows
each host's last acknowledgement beside the feed's own staleness, because an offline host cannot
apply a revocation it has not received and a list that looked current because nothing had
contradicted it would be worse than no list. The feed records that a synchronisation is owed from
the moment a connection is established until one has happened on it, and an unreachable feed is
reported stale rather than current.

### What the host policy holds

`grants::policy` holds what is true of this host rather than of one grant.

* **Organisation leases.** A signed membership lease lasts at most 15 minutes and is held per
  member account. When `grants::decide` decides a grant that requires membership, the lease is
  checked against the clock rather than against whether a socket is open, so an expired membership
  blocks organisation-mediated reads and mutations while the transport stays connected, and one
  member's lease never answers for another. A paired device's session request is decided at the
  network boundary against the grant its pairing recorded, which is the other of the two stores
  described above.
  A lease longer than 15 minutes, signed under an unpinned key revision, or wider than its role's
  ceiling is not stored at all. Personal local owner access continues through an organisation
  outage unless the host is exclusively organisation-managed.
* **The bounded offline-validity policy.** Optional, and off by default: the non-expiring owner
  grant stays account-free and usable without an authority-feed dependency. An owner who chooses a
  bound gets that bound, measured from the last successful synchronisation, with the stale status
  and the last sync visible beside it.
* **Revalidation after wake and reboot.** The policy, its restrictions, its enrolments and both
  floors are read back from the environment's authority store when the daemon starts, so a restart
  does not return an unrestricted host. Membership leases are not: a lease lasts at most fifteen
  minutes, and a restarted host holds none until the service gives it one. A policy document naming
  a revision at or below the floor is refused, and the floor only rises. A signature proves who
  wrote a policy, not that the policy is the current one.

  The floors live in the same store as the grants they protect, so restoring that store wholesale
  takes them back with it. That is a recovery event rather than a policy document, and the remedy is
  the remote feed, whose revisions this host accepts but never issues on another host's behalf.

### The shared history filter

`crates/kr-worker/src/history_filter/` is where a grant's history lower bound is enforced. It is one
filter with nine named surfaces (event pages, terminal and semantic snapshots, loaded
conversations, attachment references, exports, summaries, changed-since-last-visit and voice context)
and one decision behind all of them, so a surface cannot be served by a rule of its own. The
surface list is closed: content that is not one of them is not filtered here, it is not filtered
anywhere, and adding a surface means adding it to that list.

The worker asks the filter how much of the screen a forwarded caller may be drawn, and installs the
projection it answers with.

Content is admitted by **when it was produced**, never by when it was read, re-read or summarised,
so a summary generated now from an hour-old conversation is an hour-old conversation. Derived data
carries the interval and the resources it was built from; the filter answers with the interval to
rebuild from when that interval crosses the viewer's scope, and with nothing when the whole of it
does. Whether a viewer may read a particular *resource* is a separate question the caller answers:
the filter decides when, and a file's or an attachment's own grant decides what.

A live-only invitation reaches the currently visible screen and nothing else. Snapshot installation
goes through the filtered projection rather than the worker's unrestricted state, so the buffer that
is not showing is neither drawn nor described: not its rows, not its saved cursor, not its keyboard
negotiation. Attachment bytes are a second question from the attachment reference, and need their
own `files.read`. An invitation may name current questions or approval requests explicitly, which
permits those exact decisions and not the conversation they came from.

## The broker

One worker owns one broker, and the broker owns everything an upstream application's meaning is
built out of: the processes it launched, their credentials, the immutable frames they produced,
the pending resources those frames imply, and the arbitration that resolves them.

It is one lock, over the state **and** the durable records together. Every arbitration change is
validated against the state as it is, written to the ledger conditionally on the state that write
expects to find, and only then applied in memory, so a failed or racing write leaves memory exactly
as it was. A method that makes several of those changes in turn (answering an approval claims,
admits and resolves) holds the lock for each of them rather than for all three, and what carries
the rule across them is the durable dispatch marker rather than the lock.

A resource snapshot, the state a view installs when it starts or resynchronises, carries every
resource that can still happen and every settled one whose connection is still open. A settled
resource stays while its connection is open because frames on that connection can still name it:
a second answer, the upstream's own response and a request that reuses its identifier are each
refused from the live record without reading the store, and a view that missed the settlement
installs how it ended. Once the connection has closed and the settlement is written, nothing can
name it and it is forgotten; a settlement made while the journal is faulted is kept until the
recovery writes the gap. The ledger's record then answers for it: a late answer is told the resource
ended, as it was told before. So a session's snapshot grows with what its open connections settled,
not with everything it ever settled.

The durable records live in the worker's own journal file, beside the receipts and the questions,
with their own `broker_schema` version row. A plugin-host crash cannot touch them, because none of
them is in the plugin process.

### Three grants, held apart

A binding holds any of three grants, and holding one is never holding another.

| Grant | What it permits |
| --- | --- |
| Observation | Presenting what the upstream is doing, and inferring status from it |
| Upstream action | Preparing a declared prompt, command, attachment or cancellation |
| Approval interpreter | Reading a native request and encoding an answer to it |

A component that holds observation alone is display-only: it can present a conversation and it
cannot create an approval, whatever its output says about itself. Withdrawing one grant leaves the
others exactly as they were, and withdrawing the interpreter grant also withdraws the decoding
trust that depended on it, because a trust record nobody will act on is one somebody will
eventually read as permission.

The component interface names three kinds of source for an agent's state: a framed message on the
connector's own native connection, a documented machine-readable output, and text read from the
terminal. A source event carries which of the three produced it, because provenance is never guessed
from an event's shape.
Only a native connection can carry an approval, and only the worker's own launch can open one: a
terminal the worker launched, or a native bridge channel. The broker records a pending request when
one of those delivers it, and nothing offers it to a person to answer until a decoder trusted for
that package and method has interpreted it. Machine output and terminal text can be presented but
cannot create a request, however accurate they are, so a permission prompt read from the screen or
from a notification is never an approval.

The order of preference is native protocols and hooks, then documented machine output, then
terminal text. The host does not rank the sources by itself: the grants hold the order. A package
gets the broker's semantic events within the default ceiling, while `terminal.stream`,
`terminal.transcript_tail` and `process.observe` are outside it, so each needs an explicit package
or repository grant, and only a native connection can carry an approval. The reading of terminal
text never turns into approval authority.

### Decoding trust

An installed connector is a semantic trust boundary, and the record that says so names the package
identifier, the publisher, the installed package's hash (the digest of its manifest, which names the
component and every other file of the package by digest), the upstream methods it covers, the
projection schema versions it may write against, how many decisions one projection may offer and
whether it may encode an answer. Trust granted to one package is never another's: a binding whose
package, publisher or digest differs from the record is refused when it is bound, not when it first
decodes something.

The record is derived from what the installation granted and from the installed package's own
connector table, never from anything a component reports. Without `approval.decode` there is none.
The methods are the routes that carry, towards this host, the requests the table's decision
destination answers; a projection offers at most the decisions the destination maps; the schema
versions are `kalareach.decision/1`, and `kalareach.plugin.decoded-request/<WIT version>` as well
for a package that ships a component; and the record encodes an answer only with `approval.respond`.
A request whose method the record does not cover stays recorded and opaque, and the native client
answers it. A table with no decision destination gives no trust at all. That includes a protocol
whose answer is a response to the request itself, such as the Agent Client Protocol's permission
request, which a decision destination cannot name: its requests are recorded, forwarded and
answered by the native client alone.

A request belongs to the package whose table recorded it, and that package is kept with the
request's source. A connection identifier keeps the package it recorded requests under for good,
across a restart too, which reads it back from the ledger: the identifier is never restored under
another package's tables, so any answer to its requests, the native client's included, goes out on
a connection that reads that package's table. Only a binding of that package, at the same bytes,
interprets a request, and a rich answer to it needs the binding that interpreted it to run that
package still: a binding identifier names one package for as long as it is bound, and one bound
again after a restart to another package answers nothing the first interpreted.

Narrowing an installation's grants narrows the record where it is written. `approval.respond`
leaving takes the answer away and leaves the decoding; `approval.decode` leaving withdraws the
interpreter grant and the record with it. What was already interpreted stays visible, and a rich
answer to it is refused at the claim; the native client can still answer it.

The ledger retains, for every request a decoder interpreted: the package and its publisher, the
digest of its bytes, the upstream method and request identifier, the original source bytes whole,
the source generation, the exact decisions offered and the deadline. A request too large to retain
whole never becomes an approval; it is still forwarded opaquely, where nothing depends on this host
being able to reproduce it.

### Action tokens

Every invocation gets a token bound to five things: the verified actor, which of the three grants
authorised it, the application and binding revision it was issued against, the declared action, and
the hash of the parameters. A local caller's grant is null, because its authority is the
operating-system identity the listener authenticated rather than a grant. The token is spent once,
and both the issue and the spend check the present: the binding still exists, still holds that
grant, is not disabled by a component fault, the instance is not suspended, the revision is the one
in force, and the capability the action needs is still usable at the revision the caller read it
at.

The hand-over to a component belongs to the plugin host, which owns the runtime that invokes
`prepare_action`. The broker issues and spends the token around the operation it dispatches itself,
and a `plugin.action.invoke` that would cross into that runtime is refused before the dispatch
marker rather than carried. An action that answers through its connector's decision destination
does not cross into it: no component prepares the answer, so no token is issued, and the broker
writes the answer from the connector's table under the approval's own claim.

### Capability evidence

A per-installation map, not a label on an agent's name: two installations of one agent have two
maps. Each record names the capability and its version, the exact identity it was gathered against
(the binary digest, the schema version, the package, its bytes, its publisher, the signed
qualification profile, the launch profile, the binding and its revision), the state, where the
evidence came from and what makes it stale.

Every field a record names is compared with something this host established itself: the binary
against the launch profile or the managed process's own handle, the package and its publisher
against the binding that loaded them or the table this host pinned, the package bytes against the
binding, and the schema against the upstream version that table was qualified for. A field the host
has nothing to compare against is refused rather than believed, because evidence about a binary or
a package this host cannot identify is a claim about something else.

Evidence is never permission. Only a probe this host ran or a binding that performed the operation
here can say a capability works here; a signed catalogue record is evidence about a version. A
probe declares the operations it will perform and the budget it may spend before it runs, and a
probe with a destructive effect needs its own isolated test context.

Invalidation is by what the change was about. An installed upgrade invalidates the records that
name the binary and leaves a running binding's correctly pinned record exactly as it was. A record
only ever moves forward: a late answer at a revision the host has already passed is refused rather
than allowed to restore availability that was withdrawn.

### Launch profiles

A profile records the resolved executable and its digest, the distribution, the version, the
argument vector, what is known about authentication, and the integration mode. It is written before
the launch, so a refused launch still leaves a record of what was going to be run.

A profile also records how completely the session's closure accounts for what the launch starts, as
`ownership`: `full` or `reduced`. The worker's launch runs the agent under the ownership its profile
records and takes it from nowhere else. Every profile this host writes records `full`, and no edit
to the `agents` section changes that (see *A vendor's own sandbox*). It records `vendor_mode` too:
the word the application's own package read for the mode the application runs in, exactly as the
application printed it, or null. A ledger an earlier build wrote holds profiles without the two
fields. The first open by this build records each as `full` and null, in one transaction with the
schema version (7 to 8), and a ledger with a row it cannot read is left as it was.

A launch intent is prepared against the idle root shell and executed against it. If an application
has taken the foreground, or the prompt has moved, the launch is refused, and refusing is the
whole answer. There is no path in this code that writes the command into whatever is reading the
terminal.

Within a session, one live instance at a time holds a saved conversation. A launch intent that
names a saved conversation is refused, and names the instance that owns it, while that live
instance holds the conversation; an instance in another session is not seen. A native thread
selection moves the reservation with it, so the conversation an instance left is free and the one it
took is not. An instance holds a conversation when its bridge reports that it selected one, and a
program the host adopted from the terminal holds none.

Nothing in the host replaces a running agent with a second run of its saved conversation. An agent
process starts only from the managed shell: from a command the person typed, or from one a client
installed at the empty prompt with `shell.launch`. The broker records no saved conversation for
either, even when the command resumes one, so the guard above covers a launch intent that names a
conversation and a bridge's selection, and not a command line that resumes a conversation by
itself. If a bridge reports that an instance selected a conversation another live instance of the
same session holds, the host refuses the selection: the instance is left with no thread vouched for,
and rich mutations stay suspended until the binding is verified again.

### What a launch reads of its application's mode

A package can declare a launch probe in its manifest: the application's own diagnostic command, the
options of the launch that decide which configuration the diagnostic reads, and where in its output
the mode is. The owner confirms the capability `launch.probe` on every release, because the probe
runs the application's executable with arguments the package chose. Codex 0.155.1 prints `disabled`
where no Windows sandbox is set, `elevated` for its elevated sandbox and `<redacted>` for its
unelevated one, and a package for it reads that word at `/checks/sandbox.helpers/details/sandbox
backend` of `codex doctor --json`. The host reports the word as printed and the worker's launch
records it in the launch's profile; neither interprets it.

The worker's launch runs the probe before it reserves anything, in the launch's own environment
and directory, with no input and no shell. The probe has five seconds and may print 256
KiB, and it runs in a job (a process group on Unix) that ends with it. A nonzero exit status is not
a failure, because the diagnostic reports a problem in the output it prints. A probe that cannot
start, does not finish, prints too much or prints nothing the pointer reaches records no mode and
never stops the launch by itself.

The options the declaration names are copied with their values from the launch's arguments, in the
forms the vendor reads them: `-c v`, `-cv`, `-c=v`, `--config v` and `--config=v`. For Codex they
are `-c`, `--config`, `--enable` and `--disable`, and each of them changes what `doctor` prints.
Codex refuses `-p` and `--profile` before `doctor`, so they are not carried. A package can also list
the modes its application cannot run with in a Windows service session, the session a worker has
when no person is signed in. A launch there whose mode is listed fails by name before anything
starts, where it would otherwise hang.

This host starts no agent through the worker's launch, so on it only the diagnostics read,
`host.doctor`, runs a probe. `kr doctor` makes that read. So do `kr plugin integration enable` and
`disable`, and a paired device may. The read runs the same declaration for the executable the
daemon's own search path names for each granted package. It runs in the daemon's environment, which
a launch's may differ from, and `kr doctor` prints the word it read and where it read it from, or
that it read none, with the class and length of the reason. A package whose installation does not
hold `launch.probe` is reported as not run. A launch through the command route records no mode: the
worker is not given the shell's environment, and that environment decides which configuration the
application reads.

### What a native exit ends

A native terminal application's intentional exit ends its instance and names the backend to stop,
by the full process identity this host recorded. Closing a KalaReach attachment ends nothing: the
application keeps running in the worker's pseudo-terminal. A backend this host did not launch is
never claimed or stopped as owned, however the instance ended.

The terminal is watched as a process, for as long as it runs. A socket reaching end of file and the
process behind it exiting are two events in either order, and neither bounds the other: a terminal
can close its connection and go on running for an hour, and a terminal whose connection stays open
can exit at once. So what decides is the process, and the watch outlives the connection: a terminal
that exits long after its attachment closed still ends its instance and still stops the backend this
host dedicated to it. The backend is asked to stop, given the grace period, forced if it has not
gone, and then waited for, so what is reported is what happened rather than what was signalled.

On Windows, a dedicated backend this host started is held by a job, and the stop is of that job. The
end of the backend's standard input that this host writes is closed, which is how an agent is told
to finish, and any write to it that is blocked is cancelled so that it cannot hold the stop up. Then
a grace period is given to the job, after which the job is terminated if anything in it is left. The
stop is complete only when the job lists nothing: the backend's root process may have exited while
the helpers it started are alive, and the backend is then not yet stopped. If the job could not be
asked at any point, even when a later question was answered, or a termination fails and leaves
something in it, the stop is reported as unresolved. If a caller stops a backend while another
caller's stop of it is in progress, the second caller waits for the first and gets the same answer.

## The gateway

A native terminal reaches its upstream through a path core code alone interprets. The connector
supplies a qualified declarative table: how its protocol frames, which member carries the request
identifier, which carries the method, and what each method does. Nothing on that path calls a
component.

Only an authenticated worker-launched native connection may use it. Opening one requires the
process identity of a launch this host made *and* the private exchange of that launch; a rich
client or a component cannot ask for the native origin at all, so nothing can label itself native
to escape the rich method table.

The table is what the installation qualified, and it is what the core reads frames with. A
connection names the package it speaks for and presents nothing about the protocol, so there is
nothing to compare and nothing to substitute. The table's recorded digest covers everything it says
(the framing, each member name, and every entry's class, response expectation, reverse operation
and answer shape), so a table whose framing, classification or reverse operations were altered
cannot carry the digest of the one that was qualified.

A request the table does not classify is presumed mutation-capable, forwarded exactly as it is, and
suspends that instance's rich mutations until the binding is reconciled. The terminal stays usable
throughout: suspension is a state a client reads, not an error it hits.

Downstream request identifiers are namespaced by connection, so two connections that both call
their first request `1` are two different pending resources, and a restarted worker numbers its
connections above every identifier its ledger holds rather than starting again at one. The
upstream's own identifier is carried in JSON form: a string identifier keeps its quotes, so the
number `11` and the string `"11"` stay two requests. The form is this host's own encoding, so two
spellings of one string are one identifier, and the 256-byte bound is on the value rather than on
what encoding it costs. An upstream identifier never becomes a KalaReach identifier. One resource takes one
response transition, and a response has to be one: a frame that names the table's method member is
a request, a frame that names both or neither of the table's result and error members is neither an
answer nor two of them, and an error that carries no code and message reports no failure. None of
those resolves a resource on the strength of a matching identifier. A table names those members,
and no two of them may share a name.

A frame is read strictly: it is bounded in both directions, it must be a top-level object, and a
frame that names a member twice is refused rather than resolved, because another participant in the
same protocol may resolve it the other way.

The declarative table says how a connector's protocol frames, and the worker reads and writes those
bytes itself: the driver is core code, so a component fault cannot stall it. What a connector
supplies is the qualified table, and the bundled adapters that drive their own upstreams are the
plugins repository's. What this host supplies beside the bytes is everything that decides: the
classification, the recording, the correlation, the arbitration and the admission.

The rich method table is closed and versioned. A method with no entry is rejected; one listed as
unsupported is rejected with its own reason. Both tables are pinned to an upstream protocol version
and refused against another.

Each entry also says which of the core's own operations it is, and that is how an operation is
encoded. Submitting a prompt, queueing one and steering a turn need one right between them, so the
right cannot name the method; the table names one method per operation, and a table that names none
for an operation, or two, sends nothing rather than sending the nearest thing. The operation
travels with the turn it acts on. An approval's answer is written into the member the table names
for that method, so an upstream that reads its decision from `behavior` is answered in `behavior`,
and a method the table says nothing about answering is one this host will not answer at all.

An upstream reverse request for a filesystem or terminal operation is one this host performs
itself, in the agent's own host environment and as the user the agent runs as. Where it runs comes
from the connection and the launch behind it, never from the request, so a request cannot point it
at another application, another environment or another user. How it is performed is described under
[Reverse operations](#reverse-operations).

Every action records how it reached the upstream: a typed remote procedure call, an authenticated
hook response, or terminal input. Terminal input is never an authoritative typed result, and the
vocabulary says so rather than leaving it to a caller's judgement.

## The connection owner

One live connection has one supervised owner. It holds both ends, both byte-bounded queues, the
correlation of both directions and the fate of every frame. Nothing else writes to either end, and
nothing else decides what a write meant.

Three separations are the whole of the contract.

**Direction.** Both parties mint request identifiers and neither knows what the other has used, so
the upstream's request `7` and this host's request `7` are different requests. Every identifier
this host mints carries a reserved prefix, so the two sets are disjoint before anything is looked
up. An upstream that mints one in that namespace is refused before its request is counted,
recorded, retained or allowed to suspend anything, and so is a client that tries.

**Stages of a write.** Queueing a frame, writing its bytes and the upstream acting on it are three
facts, and a later one is never reported for an earlier one. Queueing says the owner has the frame
and has reserved the bytes for it. What reached the socket is what the owner reports once the write
has finished or its deadline has passed. And for a request, the upstream's own reply is what says
it was acted on: a reply that never comes is `UPSTREAM_UNAVAILABLE`, and a receipt says `applied`
for the acknowledgement and for nothing earlier. A frame that goes out in part is uncertainty and
never a success, and it is never written again.

**Queue bounds in bytes.** A queue bounded by frame count accepts an unbounded number of bytes, so
each end bounds what is waiting for it in bytes. A connection whose peer has stopped draining
becomes `UPSTREAM_UNAVAILABLE` rather than a growing buffer.

No reader waits for the other end. A frame bound for a terminal that has stopped reading holds up
that terminal's writer and nothing else: the upstream reader goes on correlating the
acknowledgements behind it, and what the write turns out to be is work the writer does, in the order
the frames were written. That is where a resource is settled from an answer's write, where a client
request's intent is marked with what became of it, and where a write that did not finish ends the
connection rather than silently losing every frame after it.

The native terminal's own traffic has a route. A frame it writes that names a method is its own
request or notification, not an answer, and it goes through the same native admission an upstream
request does: the method is classified with the table this host pinned, the bytes are retained as a
source event of the instance, and the intent is recorded before anything is written. A method the
table does not classify suspends that instance's rich mutations first, so an unclassified request
cannot act while rich mutations are still enabled. A request is then rewritten under an identifier
of this host's, the terminal's own identifier is kept, and the upstream's reply goes back under the
identifier the terminal used. What this host holds for those is bounded and each entry has a
deadline: an upstream that reads requests and never answers them cannot grow that map. A request
this connection cannot take, one whose deadline passes and one still waiting when the connection
ends are each answered to the terminal under its own identifier, rather than left waiting for a
reply that is not coming. A reply that cannot be handed to the terminal ends the connection: a
person who would never learn what their request did is not something to carry on through.

Every durable change a resource undergoes is committed with the record that announces it, in one
transaction, because a crash between the two would lose an event about a change that did happen.
That covers the three the broker makes: recording the request, marking that an answer has gone, and
settling it. The event carries its own identifier, its position in this broker's stream, the
subject and the binding revision it changed under, which of the broker's paths decided it and on
whose behalf, the upstream request it descends from, the event before it about the same resource,
and the resource's own classification and durability. The position continues across a restart above
everything the ledger already holds, and the identifier is what a consumer deduplicates on.

A transition made while the journal is faulted is published and not recorded, exactly as the
resource itself is not: the event says `volatile`, and the gap is what records that the stretch
happened at all.

Publication happens where the transition is committed, so every authorised observer is told in the
order the transitions committed in, and a connection observes the instance it was opened against
and nothing else. An observer that has stopped reading is withdrawn rather than grown.

Those transitions reach the people watching. The connection's subscription is read by the session
it belongs to, and each transition is delivered to every attached view as its own event, in the
order the broker committed it: what changed, what it became, whether its record is durable, the
binding revision it changed under, its place in the broker's stream and the event before it. It
carries no output, so it costs no view its queue and never touches the screen. A consumer that
wants to replay what it missed reads the outbox rather than the live stream.

A view whose subscription came with a grant's history scope, a paired device's, is told only what
that scope reaches, by the rule its snapshot was cut by, and each transition is decided before
anything is queued for the view, so the notifications it is sent are numbered without gaps. A
transition of the snapshot's own run at or below its position is already in the snapshot and is
dropped, whatever it says. After that, a transition reaches the view when its resource is one the
view was shown, so the end of an approval it was shown reaches it, or when the rule admits the
resource as the broker holds it when the transition arrives, which adds the resource to what the
view was shown: a request is decided as an approval once a decoder has interpreted it. A transition
whose resource the broker cannot read reaches only a view that was shown it, and one of another run
of the stream is decided by the rule alone. A resource the scope does not reach is absent from the
pages and the stream alike, as a resource the host does not hold, and nothing counts what was
withheld. A fresh snapshot on the same connection replaces the position and what the view was shown,
and keeps the moment the attachment's first such subscription began.

## Reverse operations

An upstream can ask this host to read or write a file on its behalf. The worker performs such a
request itself, through a directory granted to that instance, and through nothing else.

The grant is a directory opened as the transfer service's handle-based file authority, held for one
instance, for reading only or for reading and writing, with a byte bound for each. With no grant,
every reverse file operation is refused with a reason and nothing is opened. A path in a request is
a name, never a permission: an absolute path is read against the granted directory, a relative one
from it, and what it names is resolved one component at a time through the directory's handle,
following no link. A name that leaves the directory, a link on the way, an object that is not a
regular file, a file that has a second name when it is to be written, and a grant whose handle
belongs to another environment are each refused before anything is written. A file larger than a
read may return is refused rather than cut short, a write over its bound is refused before anything
is opened, and a read returns text. A write replaces the file's content; a file that does not exist
is created, readable and writable by its owner only and never executable.

A launch from the shell is granted the directory the shell reported for its command, for reading
only, when its connector's installation holds `filesystem.read`. The worker opens the directory off
the session's lock once it has established the launch's backend, and grants it only when it is the
directory the launched process works in, as the kernel keeps it: a directory moved away and
replaced at its path before the open is not granted. What is granted is then that directory,
whatever its path names later, and a read that would cross into another mount is refused. The grant
ends with the instance, or with the session. No other launch is granted a directory, and no launch
is granted writing.

On Windows the worker holds the directory's path before it opens the directory. It opens every
component of the path, from the root of the drive to the directory itself, without sharing deletion,
so none of them can be renamed, replaced or deleted while the launch lasts. Only an absolute path on
a local NTFS drive is held. A network path, a verbatim path, a relative path, a drive letter that
names another path, a component that is a link of any kind and a file are each refused by name, and
nothing is granted for them. The launcher reports the directory it works in, which is the string its
program inherits. The worker holds that string the same way and grants only where it reaches the
same directory as the shell's path did, so a launcher started in another directory grants nothing.
The hold lasts until the backend ends. There is one thing the hold cannot stop. A principal that may
write to the empty directory can convert it to a junction in place, whatever is shared, between the
commit and the time the program's loader opens it, and the program then starts in another directory.
The grant does not move: it keeps naming the held directory, and a read through it after the
conversion is refused. The commit reads the directory's attributes again and withdraws the grant
from a directory that has become a link. A principal with write access to the directory's contents
can already change the files the program reads there. A principal that may write only the
directory's attributes cannot, and for it the grant stays confined to the held directory.

The request is recorded, what to do about it is decided, and the one admission to answer it is taken
with the dispatch marker committed, all under the broker's one lock and all before the operation
runs. No native answer and no rich answer can take that admission afterwards, so this host's answer
is the only one the upstream receives. A process that ends after the marker leaves the request
uncertain when it restarts: a reconciliation keeps it uncertain rather than answerable, and the same
request sent again on the restored connection is refused as the request it already is. Nothing
performs it a second time.

The operation runs away from the connection's readers, so a slow or stalled file holds its own
thread and nothing the upstream or the terminal says behind it. It has a deadline, and at the
deadline the upstream is told it did not finish; a write that overran is recorded as an outcome
nobody can establish, and a read that overran changed nothing. A connection runs a bounded number of
operations at once, and an operation holds its place until the platform returns from it, so a
stalled filesystem cannot collect more threads than the bound however many requests arrive; a
request that finds no place is refused without running. The answer goes out through the
connection's writer, and what reached the socket settles the resource: `resolved` when the answer
went and the operation's outcome is known, `uncertain` otherwise. Its event names this host's own
answer as its cause.

While the journal is faulted a reverse write is refused, because its marker cannot be recorded, and a
read still runs under the in-memory arbitration. Terminal operations are not performed for an
upstream at all: the session's terminal takes input through its own lease, and a reverse request is
refused as an operation this host does not perform rather than given a second way in.

## Volatile-native mode

The receipt journal and the broker's ledger live in one store, and they are behind one fence: the
session's journal condition, `kr_worker::persistence::fault::JournalHealth`. The ledger reports
every failure of its store there, where it happens, classified from the store's own result code,
exactly as the receipt journal does. The broker applies the condition before every decision it
takes, so a store that fails under either of them fences rich work on the receipt path and in the
broker alike. The condition also counts the faults it has opened, and the broker applies one it
missed even when the journal has already recovered from it: a fault is a gap whether or not the
broker was asked anything while it lasted, and one that opens during a recovery sends that recovery
back to the fence under a new generation.

When the store fails the gateway enters `native_only_volatile`, atomically and in memory: rich work
is fenced, every unresolved resource is marked volatile, the identifiers already claimed or
dispatched are counted and carried, and the gap is opened. Nothing is written on the way in, and
nothing that holds the broker's lock writes to the store while the fence is up: a write that needs
its record, such as binding a component, changing a grant, a launch profile, an adapter's
checkpoint or an ordinary reconciliation, is refused before the store is reached. So nothing native
waits on the store that failed; the gap is written when the store recovers.

What continues is the qualified native forwarding path and its in-memory arbitration. A native
request, the terminal's answer to one, the terminal's own requests and this host's answers to
reverse requests all go on, and a failure met under one of them is carried on in memory as a
transition of the gap rather than refused. So is the record of something that has already
happened, such as an answer whose bytes went before the store refused its settlement. What stops is
everything rich: a new interpretation, a rich mutation, a rich approval and a rich answer that was
admitted and not yet sent are all refused with `UPSTREAM_UNAVAILABLE`, because the caller needs to
know that this operation cannot reach the upstream now and that no second backend was opened to
make it look as though it did. A reverse write is refused too, because the marker that has to
precede it cannot be recorded; a reverse read still runs. Nothing is relabelled: a rich client is
still a rich client and still cannot forward.

The gap is exposed while it is open, with when it started, why, how many native requests and
responses passed through it, how many rich operations it refused, and how many claimed identifiers
it carried.

Recovery is two steps because it can fail, and rich work comes back at the end of the second. The
host's maintenance drives both. When the store takes writes again the journal writes its own gap and
only then calls the condition healthy; the broker then commits its gap and every resource the gap
touched, in whatever state each reached, including the ones the upstream withdrew inside it. The
broker's half runs off the session's lock and the dispatch barrier, and it writes through a
connection of its own, off the broker's lock, while the fence stays up: native work goes on while
the store takes the write, and what that work changed is written by another pass before the fence
comes down. A failure part way leaves the fence in place, and the next pass starts again. The
gateway is then *recovering*, which admits no rich work; what ends that is reconciling the pending
identifiers with **every** upstream that still had one, and rich work returns with the last of them,
after the gap's final accounting is written. The reconciliations and that final accounting are
written under the broker's lock, because they and the fence coming down are one decision, and they
take the store's lock without waiting for it: a store another connection is writing refuses them at
once, is not counted as failed, and leaves the finish to a later pass.

A connection that stayed open through the whole gap has carried every frame of it in both
directions, so what its upstream still holds is what the host holds for it, unresolved; the host
reconciles it with that once none of its answers is still in flight. A connection that closed at
any point since the fence went up, including one later restored, is reconciled only when its
upstream says what it still holds. A reconciliation prepared under a recovery that failed is
refused before it writes anything, so it changes neither a live resource nor its record.

A worker that dies between the commit and the reconciliation comes back recovering, because what
ends a recovery is an upstream and no upstream has spoken to the new process. Volatile operations
are never replayed to manufacture durable history: a resource that lived through a gap says so for
the rest of its life, and its later transitions are written down like anything else.

## The local listener

A launched agent reaches its worker-owned backend on a private Unix socket inside the owner-only
runtime directory on Unix, and on a named pipe on Windows. On Windows this is a named pipe, which
has an access list that includes only the owner. When connecting to it with a different account,
opening the pipe will fail. An elevated worker's pipe may be owned by the Administrators group, in
which case another elevated administrator can open it, and the first read of that connection refuses
any account that is not the worker's own. On both platforms the kernel names the process at the
other end. The directory's ownership and mode (its access list on Windows, read from the opened
directory) are checked before an address is handed out, and an address something other than this
machine could reach is refused before it is published rather than filtered afterwards, which is what
keeps the listener off iroh.

Binding the socket, accepting on it and serving what connects is one composition. It binds the
endpoint, builds the registration from the address it bound, reads the connecting bridge's first
frame under a deadline, refuses anything a browser would have added, authenticates the owner, the
process and the private exchange, opens the gateway connection against the tables this host pinned,
registers that connection's transport as the instance's own, subscribes the connection to the
resolutions of the instance it speaks for, and serves both ends until one closes. Teardown closes
admission on both ends, lets the writers finish what was already queued, joins them, takes the
transport back, closes the connection and withdraws the subscription. It stops nothing of the
terminal's: what the terminal does is the terminal's own supervision's, and that is still running
when the connection has gone.

Launching is the other half of the same composition, though this host starts no agent through it: an
agent starts from the managed shell (see *Launch profiles*). The launch first asks everything that
can refuse without starting anything: whether this platform can publish the credential file, whether
the runtime directory is the owner's alone, whether a private exchange can be drawn, and whether the
launch intent still holds against the foreground it was prepared against. Only then does it start
the executable the profile names, with the registration path, which names the credential file, in
its environment and nothing secret in its arguments, read back from the kernel what it started,
write the owner-only credential file, register the instance against that record, and write the
registration file last, so a forwarder that reads it reads a complete one and the credential it
names already exists. A launch that fails after the start leaves nothing running and nothing
reserved: the process is ended and waited for before the launch returns, the credential file it
wrote is removed, and the broker gives back the instance and the conversation the launch took, so a
retry is not refused for a launch that never happened.

On Windows the spawned programs must be `.exe` or `.com`: a batch file, a PowerShell script or a
script that a runtime runs is refused by name, because the process that would start is the
interpreter, whose identity is not the program's. The path to the program and its arguments are
joined into one command line by the one quoting rule this host writes every command line with, and
the command line is never passed to a shell. The process is created suspended and put into two jobs
by the creation itself: the session's job, which ends it with the session, and a job of its own,
which lists everything it starts. An agent launched under reduced ownership is put into a job of its
own alone, as *A vendor's own sandbox* says. The worker asks the kernel whether each job holds the process
before its first instruction runs. The process receives three handles and no others: a pipe for its
standard input, a pipe for its standard output, and the null device for its standard error. This
host keeps the other ends of the pipes. The pipe ends are made inheritable only for the call that
creates the process, under a lock that every start this worker makes takes, so a process another
part of the worker starts at the same moment holds none of them. This allows the reader of the
backend's output to see the end of the file when the backend's last process lets go.

A connection carrying any header a browser adds (`origin`, `referer`, `sec-fetch-site`,
`sec-fetch-mode`, `sec-websocket-key`, `access-control-request-method`) is refused. A page that
guesses the address still cannot speak to it.

Registration authenticates against the launch and process binding **and** a private exchange. An
environment-variable session identifier is carried so a person debugging can see what the
application thought it was, and it is never authority. The registration file is the small file
section 11 prefers: where to connect, which launch, which process this host expects. It carries no
credential, and neither does any address a diagnostic prints or any argument vector.

The credential itself travels in an owner-only file the launched process opens. The host, before
writing to it, reads the protection of the directory that it will write to: on Unix it must check
the user that owns the directory and its mode, and on Windows it must check the access list of the
directory it writes to, which can be read from the opened directory. The directory must be
protected, and its list may grant access only to the account running the worker or the account that
owns what the worker creates, the system account, the Administrators group, and the creator-owner
and owner-rights entries; an entry that denies access grants nothing and is not read as a grant. The
forwarder, when opening the credential file, reads the protection of the opened file: on Windows
this is its access list. It presents nothing from a file another account was granted. If the host
cannot ensure that a file will not be readable by other accounts, it must not write a credential to
a file, because a credential in a file whose protection cannot be ensured is worse than no file at
all. A launch there is refused before any process starts, because a launched process that could
never be told its credential would only have to be stopped again.

An executable upgrade affects new launches. An existing binding keeps the binary identity, schema
and adapter version it was bound to, because the identity is pinned when the process starts and
nothing that happens on disk afterwards reaches it.

### Native bridges an application starts

Some applications cannot be proxied: they start their extension processes themselves, over their
own standard streams. For those, a connector package installs a small registration in the
application's own plugin or hook location, and the application starts the core forwarder, `kr-hook`,
by the full path the host wrote into that registration (a package written before the host wrote it
names `kr-hook` alone, and the application finds it by its search path). Each forwarder process
connects to the launch's endpoint and declares which bridge it is: the application, and the registration that started it (a `hook` or a
`channel`).

None of those processes is the process this host launched, so a bridge is admitted by the launch
binding it can prove: the kernel's parent chain from the connecting process reaches the launched
application, with every link checked by its start identity. It must also present the launch's
private exchange, present the process the kernel named, and be the installation this host recorded
for the launch: the application and surface it declares must be ones the installed recipe
registered, and the process must be running the forwarder the installation put in place. A
session identifier in the environment is carried as a diagnostic and decides none of it. A refused
bridge is closed without a word; an admitted one is answered with one admission line.

On Windows a process keeps naming a parent after that parent has exited, so a parent chain proves
nothing there. The launch binding of a bridge is the job the application was started in: the
connecting process must be one that job holds, and a process outside every job, or in another
launch's job, is refused whatever it presents.

What this defends against is another account, a network client, a browser, a plugin and a sandboxed
process with a restricted token. It does not defend against a hostile process of the session's own
account, which the specification places inside the operating system's boundary: such a process can
read the credential file, and on Windows it can enter a launch's job by naming a member of that job
as its parent. This is the same accepted limit as macOS's `setsid` escape.

Such an application can also be launched from the managed shell, when its connector integrates the
command the person typed. The worker then establishes a backend before the shell forks: an
endpoint, a credential and a launch record in a fresh owner-only directory, with nothing reserved.
The forked child runs the installation's `kr-hook launch`, which presents its own process with the
credential. The worker admits it only as the root shell's own child, started after the establish,
running the file the worker hashed with the vector it answered. Then it registers the instance,
publishes the registration naming that process and commits, and only then does the launcher exec
the program in place, so the registration names the program before it runs. Anything short of the
commit runs the command as typed, without the integration's flags. Every bridge of such a launch is
also checked against the running image: the process must still execute what was hashed, and one
mismatch refuses that bridge and every later one. The launcher's contract is in the Claude Code
bridge's documentation.

Windows lacks exec, so there the launcher creates the program itself. It creates it suspended, in
the job the launcher is in, sharing the launcher's console and given its three standard handles. It
then says it is going, naming the program and the directory the program inherits. The worker shows
the program before it commits anything. The program has to be the launcher's own child, it has to
have started after the backend was established, it has to have been created from the file the worker
hashed and has held open since, and it is put in a job of its own before it has run. The instance,
the registration, the transport's record and that job all name the program and never the launcher,
and the registration is published only at this point. The worker lets go of the hashed file when it
commits, so a program that updates itself while it runs is not held to its old file, and the verdict
it took stands for the process. When the backend says the launch is committed, the launcher starts
the program, says that it has, and waits, and it then ends with the program's whole 32-bit exit
code. A program that is committed and not started within four seconds, or whose launcher is gone
before it can be told, is ended with everything in its job, and so is a program shown to the worker
when the launch fails after it. Until the worker commits the launch, a job of the launcher's own
holds the program from the moment it exists and ends it if the launcher ends. A launcher that stops
for any reason before the worker has looked at the program therefore leaves nothing suspended
behind. The launcher lets that job go when the commit arrives, before it starts the program, so once
the launcher has said that it started the program, ending the launcher ends nothing the program
started. A program the launcher runs as typed also gives the launcher its whole 32-bit exit code. If
anything goes wrong before the commit, the program never ran: the launcher ends it and runs the
command as typed. A launcher that cannot create its program says why in its frame, and the worker
keeps the reason on the backend, because no instance exists to keep it. A command typed on Windows
is looked up by the name the file system gives the program, and a shim as the shell's first hit
establishes nothing; the Claude Code bridge's documentation has the rules.

A program the integration did not launch is adopted, never given a gateway after the fact. Four
times a second, while a command has the terminal, the worker reads the terminal's foreground group,
and records a process in it that the root shell started itself, that no instance holds and whose
executable an installed connector recognises. It becomes a native terminal instance with the profile
it was observed running: the kernel's executable and argument vector, its digest, and the bypass
the shell's question was answered with, where there was one. It has no process record and no
credential, so none of its bridges is admitted, and it ends when its process exits. A launched
program is never adopted as well: its launch registered the process that presented itself, which
keeps its identity when it execs the program. Reading a program's image runs on its own, so a slow
reading delays only the next identification, and a program's exit is found at the next look
whatever is being read. Until the worker receives the installed connectors, nothing is recognised
and nothing is adopted.

The session announces each of its agent instances to its attached views: when a launch is committed
or a program adopted, when an instance's bridges are refused and why, and when it ends. It counts
the announcements, keeps the list of live instances and publishes each announcement under its own
lock, and a subscription or a snapshot carries that list with the count of the last announcement it
includes, read under the same lock. A view installs the list and applies the announcements counted
after it, so it holds every live instance once. A session that closes ends the instances of the
programs it is ending, launched or adopted, and announces those ends while its views are still
attached. Nothing about an instance is announced after its end.

An admitted hook sends one observation and waits for this host to apply it and close the connection.
When that exchange completes, the host has the report before the hook answers the application. It
does not when the hook reaches its deadline first, or when the application moves on without waiting,
as Claude Code may while background `SessionStart` hooks still run; the report is then applied late,
or, if the hook has already gone, not at all. Only a hook the launched application process started
itself, as the kernel's parent link says, reports the application's selection; a hook another
process started reports that process's threads and moves nothing. A thread starting selects that
thread and advances the binding revision, even when it is the thread already selected, since a
resume is a new selection; a thread continuing after a compaction changes nothing; a thread ending
leaves none selected. Reports are placed by when the kernel recorded the application starting each
hook, on a clock that only moves forward (Linux's start ticks since boot, macOS's absolute time at
the fork); a bridge whose record the platform keeps but will not give up is not admitted. Two hooks
from one tick are not placed against each other. The newest report decides the thread. An older
report whose hook started after, or in the same tick as, the report that began the binding's current
revision, and that shows the thread changing there, advances the binding to a new revision of what
the newest report says, since a question bound to the old revision may have been asked across that
change; an older one from before the revision began changes nothing. A report that cannot be placed
against the newest, and that would change the binding whichever came first (a start always would),
leaves no thread vouched for, leaves the thread the binding had so nothing bound to it survives, and
suspends rich mutations until a report whose hook started in a later tick settles it. That
suspension is the bridge's own: lifting a suspension placed for another reason does not lift it, and
it lifts no other. Every observation goes into the instance's observed history.

A contact question records, when it is asked, the thread the bridge vouches is selected and its
revision. The hook's report of a finished call names the call by its request identifier, and only a
call that succeeded is reported with one. So while that identifier names this one question on the
instance, its reports are the reports of the call that asked it: when they name the thread recorded
at the asking, the question is bound to that revision, and a later switch of thread invalidates it.
If the reports name another thread or disagree, it stays bound to the application alone. Once the
identifier is used again (an exact retry, or another question of the same instance under the same
identifier, with a recorded thread or none), no later report binds either question; one already
bound by then was bound by its own call's report and stays bound.

An admitted channel is served by this host for as long as it is open, on a gateway connection of its
own kind, and only the launched application's own: its starter must be the process the launch
registered, an instance has one channel open at a time, and the connector's table must be qualified
for the version a signed qualification record names for the executable the launch hashed. What it
relays goes through the same native admission as any upstream request and is recorded as a pending
resource with its source frame; whether that can be answered is decided by the decoding trust and
the arbitration above, as for any connection. A frame its table does not route towards this host
closes it. However it closes, and in any mode, it settles what it relayed as what has already
happened: what was never dispatched is cancelled and what was dispatched is uncertain, so no closed
channel holds a recovery open. The Claude Code bridge is described in
[`docs/bridges/claude-code/README.md`](../bridges/claude-code/README.md).

## Agent methods

The method registry decides what an actor must present. The broker decides everything about the
instance, and the two are separate because a caller can hold every right in the table and still be
acting on a conversation that changed underneath it.

An agent read names one exact application instance. `agent.capabilities` answers with the
installation's capability map; a snapshot and a command list answer with the binding state they
were answered at, and a snapshot says how many entries the history filter withheld and whether the
range the reader asked for had been evicted. A gap is reported, never filled: nothing reconstructs an
unobserved pending approval from a transcript or a screen.

The local owner reads the whole retained agent history, because its authority is the
operating-system identity the listener authenticated and there is no grant to narrow: the same rule
that draws a local attachment the whole screen. Every other caller acts under a grant, whichever
socket the daemon heard it on. Section 10 narrows a grant's history in one place, the shared
host-side filter, and the daemon sends a paired device's read to the worker with the history scope
of the device's grant. The filter admits each entry by the moment it was observed, before the entry
counts against the page, so a withheld entry is counted rather than paid for; a grant that keeps no
retained history reads none of it. A caller under a grant whose scope did not come with its read is
refused as `UNSUPPORTED_CAPABILITY` rather than answered, because an answer could give it more than
its grant covers.

`agent.approval.inspect` reads what the approval ledger keeps for one pending resource of the
instance it names: whose decoder read the request (the plugin, its publisher and the installed
digest), the upstream method and the native request identifier, the request's original bytes,
whole, and their digest, the decisions the decoder offered in the upstream's order, the upstream's
deadline, when the decoder wrote its reading, and where the request stands now. The broker checked
the decoder's grant and trust, the source frame's package, generation and first use, and the
projection's schema policy before the request became answerable. None of that shows the decoder
read the bytes correctly, which is why the bytes come with the reading. The record also carries the
moment the request arrived, when the broker recorded its source frame; the interpretation can come
much later. A resource of another instance, one no decoder interpreted and one this host does not
hold all get the same `STALE_SESSION` refusal, and its text does not say which. The read needs
`session.view`. A paired device reads a record through the session's worker, held to its grant's
history scope at the moment the request arrived: a record from before the moment the grant reaches
back to gets that same refusal, decided before the size of the answer, so neither says the record
exists. A grant names an approval by the broker's resource identity, which picks out exactly one
recorded request; an upstream's own identifier would not, since two connections both call their
first request `1`. A grant that names the approval reaches its record however early the request
arrived, while the approval can still be decided, pending or claimed by an answer on its way, and
with `session.view`; once the approval has ended, the bound decides, as for any other record. A
caller under a grant whose scope did not come with its read is refused as
`UNSUPPORTED_CAPABILITY`, with that reason and nothing of the record. The worker refuses an answer
larger than the control frame declared on the connection it answers, with both sizes, rather than
send it. A paired device's read reaches the worker over the daemon's own link, so for a device that
check is against the frame of that link, not against a smaller one the device negotiated on its own
connection.

The five agent mutations each carry the binding revision they were prepared against. A revision
behind the one in force is `STALE_SESSION`; a draft that moved is `DRAFT_CONFLICT`. A steer or a
cancellation names the turn it acts on and is refused rather than redirected when that turn is not
the one running. An approval answer names a resource that is still open, inside the upstream's own
deadline, interpreted at the current source generation by a decoder that still holds the
approval-interpreter grant, with a decision that interpretation offered; it is checked against the
retained list before the claim is taken, and it happens once.

Every refusal named above is decided before the dispatch marker, so a request this host can refuse
leaves a rejection rather than an outcome nobody can establish. That includes an instance with no
transport bound and one whose every component has had its rich capabilities disabled: both are
refused before anything is marked, for a plugin action as well as for the five mutations. A plugin
action's own authority is checked too: its grant, its binding revision, its capability and the room
to issue its token are all checked before the marker rather than when the token is issued.

The admission itself crosses the marker. The broker admits the mutation before the marker is
written and the same admission is what the effect carries out, so nothing between the two can turn
a refusal this host could have made into an outcome nobody can establish. That includes the
transport: whether this upstream has a method for the operation at all is settled at admission, not
when the bytes were due. A marker this host could not write leaves nothing executable behind it:
the admission is given up, an approval's reservation goes back and a plugin action's token is
retired. What a refusal after the marker still covers is the transport's own failure and a broker
marker this host could not commit, both of which are what `OUTCOME_UNKNOWN` is for.

Reserving a resource and marking it dispatched are two moments. The admission reserves the
resource's one transmission; the durable marker goes in immediately before the bytes. An answer
that is abandoned in between leaves the resource answerable, and a claim with no marker settles
nothing: resolved and uncertain are both statements about an answer that went.

What an admission carries is a permit, taken once. Taking it is what authorises the transmission,
and it carries the answer's own claim with it, so a second caller on one admission transmits
nothing and settles nothing rather than recording the first caller's answer as uncertain.
Claiming a resource, marking it and settling it are the broker's own steps and the admission is
the only way into them: there is no sequence that resolves a pending resource without holding the
permit that carried its answer.
An answer's transport is the one that speaks for the connection whose resource it resolves, chosen
when the answer is admitted; a connection that has gone is `UPSTREAM_UNAVAILABLE` before anything
is claimed. The transport work happens after the session boundary ends, because terminal ingestion
needs that boundary and an upstream that is slow to answer must not stop a person typing. The
transport's own call that takes the operation runs on a thread of its own, and the worker waits for
it and for the upstream's answer for ten seconds at most, so a transport that blocks cannot hold the
caller past them. At that bound an answer's resource is settled as uncertain first, the receipt then
records an outcome nobody can establish, and only then is the caller told `UPSTREAM_UNAVAILABLE`.
What the transport does afterwards settles nothing.

A binding's actions are registered from its package's declarations and from nothing else. The
grant, the effect, the capability, the operation and the rights of each follow from its declared
effect class and implementation, and what an action is called, or labelled, changes none of them.
A declaration this host does not register as an action (decoding, terminal input, an answer a
component would prepare) is left out, with its reason.

`plugin.action.invoke` validates the registered action, the grant that action declares, its effect
class and whether a draft the action needs was named, and then issues the action token that
authorises the one invocation that follows. A caller acting under a grant must hold the rights the
action's class needs (an answer `agent.approval.respond`, a prompt `agent.prompt`, an attachment
`agent.prompt` and `files.upload`), or the call is refused before the dispatch marker; the local
owner on this worker's own socket, naming no grant, is its own authority. An action goes to the
upstream as the rich method its name selects only when the right that method needs is one the class
of the operation it prepares carries, and the transport is asked about that operation as soon as a
plan names it. The declaration is read inside the admission and kept
with it, and the plan the component returns is refused unless the declaration in force is still the
one the invocation was admitted under: a package that re-registered the action while its component
was working has withdrawn the invitation. The draft is resolved before the admission takes its lock
and the snapshot is what the admission binds to; a draft that moved before the plan arrived is
`DRAFT_CONFLICT`. The frame carries that revision beside the draft identifier, because the
identifier on its own denotes whatever the draft holds when the frame lands: an upstream given
only the identifier would act on a draft this host never admitted. The arguments a plan is for are the arguments that will execute: the host
computes their digest itself and compares it with the token's and the plan's, because a hash a
component supplied says only that the component can write a hash. The arguments are read once at
admission and written back in the one form this host will transmit, so the digest covers the bytes
that go; an encoding this host cannot put on the wire is refused there rather than replaced when
the frame is built. Arguments whose top-level object names a member twice are refused for the
reason a native frame that does is: the parse keeps the last one, another reader of the same bytes
may keep the first, and what this host hashed would not be what the upstream acted on. Nested
objects are normalised rather than refused, as a native frame's are. The invocation's own authority is asked again when the plan arrives, because
the token was spent to invite the work and is not proof by the time the work comes back. What
transmits is the plan that was validated: the operation it prepares travels in the frame, carried
in the permit rather than attested by a flag beside it. The draft store itself (whose the draft is
and what else it holds) is not this host's, and what it supplies here is the snapshot.

An action whose implementation is its connector's decision destination is an approval answer, and
`plugin.action.invoke` admits it as one: every check an approval answer meets applies, in the
transaction `agent.approval.respond` uses, with the action's own checks inside it. The call must
name the resource it answers. The action must be registered for this binding with the
`approval.respond` effect, and the binding must still hold that action's grant. This binding must be
the resource's decoder, because the answer carries the decoder's meaning, and the decision, read
from the parameter the action names for it, must be one the interpretation offered. No action token
is issued and no component is asked: the answer is written from the connection's own table under
the approval's claim, and the method answers with its own result, the mutation and the action.

An adapter checkpoints the cursor it consumed, and the cursor survives a restart. A restart resumes
the numbering after it, so a new entry never takes a cursor an adapter has already passed and a
replay from before the restart is a visible gap rather than a silently empty answer. A range that
was evicted rebuilds from what is verifiably retained and says there is a gap.
