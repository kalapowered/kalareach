# Updating a host

A host installed with `kr host install` keeps each release it runs in a directory of its own and
never changes one in place. An update adds the new release beside the old one, makes it current in
one step, and replaces the control daemons. It never replaces a worker: a session keeps running the
release it started from, with that release's shell package and module tree, until it closes.

## The handover

A control daemon is replaced by the release that updates the host, through
`host.update.handover`, which only the owner's own socket may call. It takes one of three steps:

| Step | What the daemon does |
| --- | --- |
| `prepare` | Closes its gate to new sessions, waits up to 45 seconds for the creates it has already started to settle, and answers with its process, the arguments it was started with and the directory it was started in. The gate stays closed for five minutes unless a `stop` or a `resume` comes first. |
| `stop` | Stops. It is refused when the gate is open, so a daemon whose preparation lapsed is never stopped while it is starting sessions. |
| `resume` | Opens the gate again. The update is not going ahead now. |

A create that arrives while the gate is closed is refused with `RESOURCE_UNAVAILABLE`, naming the
release the host is being updated to; the caller creates the session again once the new daemon is
running. Every create the daemon had already started is finished before it answers `prepare`:
whichever release it launched, that worker has taken its own hold on its release by then. A create
that does not settle within the 45 seconds makes the daemon refuse the step, and the update waits.
Nothing a session is doing stops at any step: a worker belongs to the service manager, and the next
daemon finds it again.
