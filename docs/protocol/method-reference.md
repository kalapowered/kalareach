# Method reference

[methods.md](methods.md) lists every method in the registry and links, for each one, the section that describes what it does. Most of those sections are in the guide for the part of the product the method belongs to, such as [the host](../host/README.md), [pairing](../pairing/README.md) or [transfer](../transfer/README.md). This page holds the descriptions of the methods those guides have no section for. A method that a guide already describes in a section of its own is described there; the entries below that name a guide only add what that guide leaves out.

An entry says what a call takes, what it answers and what it does or refuses, in the terms of the types in `crates/kr-protocol/src`. Who may call a method, with which rights, and how a repeat is resolved, is in [the method and authority table](README.md#the-method-and-authority-table) and in `packages/protocol/schema/method-authority.json`, and is not repeated here.

Three terms recur. The *daemon* is the environment's control daemon, which serves the host-level reads and changes. A *worker* is the process that owns one session; a paired device reaches it through the daemon, which forwards the call with the rights of the device's grant. A method is *not served* when the registry lists it, it is a method of the host or a worker, and no program of this build answers it. The methods of the managed service are listed in the registry and answered by the service, not by a program of this build; they are described under [The managed service's methods](#the-managed-services-methods).

## Host and environment reads

`host.info`, `environment.list` and `host.doctor` take no parameters, and the daemon serves them. The owner at this machine is answered in the display form. Every other caller, a paired device included, is answered in the export form, which gives an account name, a path and what the platform said only as their class and length ([What a paired device reads of this host](../host/README.md#what-a-paired-device-reads-of-this-host)).

**`host.info`** says what this host is. The answer names the controller build and the protocol version it implements, the environment the daemon owns, the controller generation and the boot identity, and when this controller process started serving. It counts the sessions that are live or being created and gives the admission limit. It also gives the worker profile a create uses when its request names none, what sleep inhibition is doing, the machine group the environment records for itself, where privacy mode stands (whether it is on, its generation and whether a change is in progress), and the shell mode a create uses when it names none, with the rung of the configuration order that mode came from. The daemon accepts the configuration document before it answers, so the limit and the defaults are the ones in force. A member that a newer host adds is optional, and a client whose schema predates it ignores it.

**`environment.list`** says which environments the host serves. Each entry gives the environment's identity, a label for people, the operating system and the processor architecture, the operating-system user, the runtime directory that holds sockets and worker descriptors, the state directory that holds the registry, journals and spools, the number of live sessions and the machine group. The daemon of this build serves one environment, the one it owns.

**`host.doctor`** answers with the daemon's diagnostics. It gives every check in the order it ran, each with a status, a detail and, where one applies, what to do about it. It says whether the host is healthy, which is true when no check failed. It also gives the effective configuration, with each value, the rung it came from and whether a change to it applies at once; every command integration an admitted release declares and every package the configuration names, with what a session created now gets of each; what each admitted package's launch probe reads of its application, as this daemon runs the probe ([What a launch reads of its application's mode](../host/README.md#what-a-launch-reads-of-its-applications-mode)); and the metrics the host measured about itself. One allowlist names every field that leaves the host, so a credential cannot reach the answer. The metrics are given to the owner and to a paired device whose grant holds `host.manage`; any other caller is told they are withheld.

## Forgetting an environment

**`environment.forget`** takes an environment identifier and removes that environment's enrolment. The daemon deletes the enrolment from its record of enrolled environments together with the cached observation of it and what a bridge established about it, which is the scoped channel and the number of the record it was established for. It answers `forgotten`, true when a record was there to remove. The record is written only when something was removed. `environment.enrol`, `environment.inventory` and `environment.refresh` are described in [The enrolled environments, and the cached inventory](../host/README.md#the-enrolled-environments-and-the-cached-inventory).

## Completing a device's keys

A device has four public keys: the transport identity, the Ed25519 authorisation key, the X25519 stored-envelope key and the X25519 notification-preview key. A device paired before its host kept all four declares the rest once, and **`device.keys.complete`** is that declaration.

The call carries all four keys and a signature over a statement that names the device and the four keys. The device is the one the connection authenticated as, and the parameters name no other. The daemon refuses the declaration with `PERMISSION_DENIED` when it has no pairing with that device, when the declared transport and authorisation keys are not the ones recorded at pairing, or when the signature is not made by the authorisation key recorded for the device. It refuses with `INVALID_ARGUMENT` when the four keys are not four different keys. The answer is the device's identifier and the four keys now on record. A declaration that repeats the keys already on record completes again, and one that names other keys is refused. Another device seals to a device's stored-envelope key only when this host reports it, because the pairing the owner approved is what binds the key to the device.

## Pinning a repository or a package

**`catalogue.pin`** holds an enrolled repository at the generation it is on. It takes the environment, the repository and a generation, or no generation to remove the pin. A generation is accepted only when the repository has an active generation and it is the one named; otherwise the call is refused with `INVALID_ARGUMENT`. While the pin stands, a sync that would activate any other generation is refused, the pinned generation stays usable, and reclaiming space keeps everything the pinned generation references. The answer is the repository as it now stands.

**`plugin.pin`** holds an installation at the package hash it holds. It takes the environment, the package and a hash, or no hash to remove the pin. A hash other than the installed one is refused with `INVALID_ARGUMENT`, and a package that is not installed is not found. While the pin stands, installing a different release over the installation is refused until it is unpinned. The answer is the installation as it now stands.

Both calls are served by the daemon's catalogue module. [The plugin catalogue](../host/README.md#the-plugin-catalogue) describes the rest of the group, and [Repositories and the catalogue](../plugins/catalogue.md) describes what a sync does.

## Reading sessions

**`session.list`** takes an optional environment, where no environment lists every one the caller may see, and `include_closed`. It answers the sessions in display-number order, each as a session summary. A closed session is listed only when the request asks for closed ones. The daemon lists every unclosed session from its registry; a session whose worker cannot answer is listed from the registry's own row as `live`, `creating` or `closing` ([Closure](../host/README.md#closure)).

**`session.read`** takes a session identifier and answers the session's summary together with the endpoint a local client can attach to while the session runs. It also gives three members that are each null where the host does not say, and null is not the same as none or zero. The launch profile is null for a session that has closed and for a worker of a build that reported none; a live session otherwise has one. The most recent command block the session's private hooks reported is null where no hook has reported one, which is every session without a managed root integration, where the caller's grant does not reach it, and for a worker of a build that reported none. The number of `shell.launch` confirmations still waiting on the session's reader is null for a session with no managed root editor, for one that has closed and for a worker of a build that reported no count; zero is a session that could have one and has none. The worker's own answer, on its endpoint, also carries the metrics the worker has counted, left out when it has counted nothing. The daemon's answer to `session.read` carries none. A worker that has finished closing stops answering a moment before its process ends. A read that meets it then is answered from what the daemon holds, with no endpoint and none of the session's content, or is refused with `RESOURCE_UNAVAILABLE` where the daemon holds no word of an end.

## Attachments

**`session.attach`** adds an attachment to a session. It takes the session, the mode, whether the attachment registers a geometry claim, its physical dimensions, the terminal profile it presents and the capabilities it asks for. The mode is `semantic`, for structured application state, or `terminal`, for terminal output as raw bytes or as a projection. A semantic attachment never claims geometry, and a terminal attachment states its dimensions. The attachment is granted the capabilities it asked for narrowed by the rights of the grant it arrived under ([Rights and capabilities are not the same thing](README.md#rights-and-capabilities-are-not-the-same-thing)); the request does not bypass grants and does not acquire a remote input lease. The answer is the new attachment, who owns the geometry after it joined, and the output cursor its stream starts from, which a client subscribes from before it installs a snapshot.

**`session.detach`** removes one attachment from a session. The worker serves it. The call names the attachment. A caller that runs from inside an accepted line, as `kr detach` does, names none and presents the capability that line gave it; the host then removes the attachment whose input the root editor accepted the line under. A request that names neither is refused rather than attributed, and a caller that names nothing and cannot be tied to one attachment gets `AMBIGUOUS_ATTACHMENT`, never a guess. The answer names the attachment that was removed, the geometry after succession and how many attachments remain, which can be none. If the removed attachment owned the size, the oldest remaining eligible claim succeeds to it ([Who owns the size](../host/README.md#who-owns-the-size)).

**`attachment.configure`** takes an attachment and whether it holds a geometry claim after the call, and answers the geometry. Adding a claim needs the attachment to hold the geometry capability, and an attachment that may not claim, such as a semantic one, is refused. Adding a claim never displaces the owner of the size, but it takes the size when nobody owns it. Withdrawing the owner's claim runs succession to the oldest remaining eligible claim. The session identity does not change either way.

`attachment.viewport`, `terminal.resize` and `terminal.geometry.transfer` are described in [Who owns the size](../host/README.md#who-owns-the-size).

## The terminal palette

**`terminal.palette.set`** is in the registry with its authority entry and is not served. A worker has no row for it in the table of the methods it serves, so it refuses the call with `PERMISSION_DENIED` and the message that the method is not reachable from a local caller, before it reads a parameter. The daemon, asked directly, refuses it with `INVALID_ARGUMENT` as a mutation it does not serve. A session's palette is chosen when it is created: `session.create` carries a `palette` member, and null takes the profile default.

## Interrupting the foreground

**`input.interrupt`** asks the worker to deliver the terminal's interrupt. It takes the session, the attachment, the lease epoch the attachment holds and the action, of which the only one accepted is the native interrupt, meaning the interrupt character the session's line discipline defines. On Unix the worker sends the interrupt signal to the terminal's foreground process group, which is what the interrupt key reaches, and a group that is already gone counts as delivered. If that fails, it signals the root shell instead. On Windows it writes the console's interrupt byte through the console. The attachment must hold the input capability, and it must hold the input lease at the epoch it names. Any other attachment or epoch is refused with `LEASE_LOST`, and the call never takes the lease. In a managed session the root editor's state machine decides it and does not hold the interrupt back for a reader transition, since a held interrupt would not be an interrupt. If neither delivery succeeds, the call fails rather than answering as if the interrupt had gone; in a managed session the failure is `RESOURCE_UNAVAILABLE`. The answer is the lease after the call. `input.acquire`, `input.release` and `input.write` are described in [Who may type](../host/README.md#who-may-type).

## The agent methods

Every agent method names a session and the exact application instance in it, never a product name. The worker serves all nine. [Agent methods](../host/README.md#agent-methods) describes how the broker admits them.

**`agent.capabilities`** answers the binding the answer is about and the installation's capability map, which has one record for each capability with the evidence behind it. Evidence is never authority.

**`agent.snapshot`** answers the entries of the bound agent's shared state in the order the connector walked them. An entry carries its node number, its kind, its text after the shared history filter, how many bytes of the text were left out, when it was observed, the binding revision in force then and the turn running then. `from_node` continues a snapshot that a limit stopped, and the answer then carries a continuation. `history_gap` is true when the retained range asked for had been evicted, and `withheld_entries` counts the entries the caller's history filter withheld, so a short answer can be told from a complete one.

**`agent.commands`** answers the commands the bound agent advertises, in the order the upstream advertises them. Each has a name, a summary and the way its parameters are encoded when it is run upstream.

**`agent.prompt.submit`** and **`agent.prompt.queue`** take the same parameters: the mutation target, a draft identifier when the prompt has attachments or was composed elsewhere, and the text when it is short enough to travel inline. Exactly one of the two is given: a call that names both, or neither, is refused with `INVALID_ARGUMENT`. Inline prompt and steering text is 1 to 65,536 bytes; longer content belongs in a draft. They are two upstream operations and two capabilities, `agent.prompt` and `agent.prompt.queue`. Whether the upstream has a method for the operation is settled when the call is admitted.

**`agent.turn.steer`** takes the target, the identifier of the turn being steered and the steering text. **`agent.turn.cancel`** takes the target and the upstream's own identifier for the turn to cancel. Both are refused rather than redirected when that turn is not the one running.

**`agent.approval.respond`** takes the target, the pending resource and the identifier of one of the options the decoder offered. A free-form answer is not accepted, because it would be this host inventing an upstream decision. The answer gives the mutation's result, the resource and its state afterwards.

Each of the five mutations names the binding revision it was prepared against, in its target. A revision behind the one in force is refused with `STALE_SESSION`, and a draft that moved with `DRAFT_CONFLICT`. An accepted mutation answers the revision it was applied at, how it reached the upstream, the upstream's own request identifier where the upstream gave one, and the turn it applies to where the upstream names one.

**`agent.approval.inspect`** takes a session, an instance and a pending resource, and answers what the approval ledger keeps of that resource: the decoder that read the request, the upstream method, the request's original bytes and their digest, the decisions offered, the upstream's deadline and where the request stands now. A resource of another instance, one no decoder interpreted, one this host does not hold and one outside the history scope of the caller's grant are all refused with `STALE_SESSION`, and the text does not say which.

## Alerts

**`alert.create`** raises one alert in a session. An alert reports and asks for nothing. The call is private IPC, made by the contact tool `send_notification` under the caller token of the agent's own verified application, and the worker serves it. It takes the session, a de-duplication identifier of 1 to 256 bytes, the text, of 1 byte to 2 KiB, a severity of `info`, `warning` or `error`, an optional label the caller gives itself, which is unverified and 1 to 128 bytes when present, and an optional link into this host's own session. The alert records the verified source beside the label. The answer is the alert, with its source, severity, link and when it was raised, and `deduplicated`, which is true when an exact repeat returned the existing alert and raised none. [The four tools](../contact/README.md#the-four-tools) describes the contact tools.

## Reading review state

**`review.read`** answers the review state of the subjects the caller may see, for the calling actor. A subject is a completed agent turn or a captured change set. The call may name one subject, in which case the answer is that subject's row, or none where the host holds no such subject in the caller's scope. Otherwise, with or without a session to narrow it to, it takes a page: at most `max_reviews` subjects, never more than 200, oldest first, with `after` naming the subject to continue after. An `after` the host no longer holds, or that is outside the caller's scope, is refused and does not restart the page. Each row gives the subject, its current version, the version this actor acknowledged and when, and whether review work is outstanding. Work is outstanding until a version is acknowledged and again after a newer version appears. `more` says whether subjects remain after the page. The daemon serves it. A paired device is shown the sessions its grant admits, and the state is not narrowed to a moment in time. `review.acknowledge` is described in [Review, and what it does not do](../host/README.md#review-and-what-it-does-not-do).

## Quiet hours and visits

**`attention.quiet_hours`** sets or clears the environment's one quiet-hours window. It takes the window, or null to clear it. A window is the first minute of the UTC day it covers and the first minute after it; an end at or before the start wraps midnight, and equal bounds make a whole day. The call may carry the time zone the client converted from, which the host stores and gives back and never interprets. The answer gives the window now in force, whether the host is inside it now, and whether the host can prove what its wall clock reads. A host that cannot prove it is never inside a window. The call records the window and announces nothing by itself; the next timer pass releases what the change lets through ([Quiet hours](../host/README.md#quiet-hours)).

**`visit.acknowledge`** records how far the calling actor has read a session. It takes the session, the semantic cursor the actor has seen up to and the log views the actor had open, with their offsets and filters. The answer gives the cursor now recorded, the views the host retained after the per-session bound, and the actor's acknowledgement revision. A cursor never goes backwards: an older one than the host holds leaves the host's. `visit.changed` is described in [Changed since a visit](../host/README.md#changed-since-a-visit).

## Reading and cancelling an action

**`action.read`** takes an action identifier and, when the action belongs to a session, the session. It answers the receipt as it now stands and the result the action produced, when it produced one and the result is still retained. Holding the identifier is not authority: the host checks present view authority over what the receipt names before it returns either half. A worker answers for the one session it owns, so a request that reaches a worker needs no session. For a closed session the daemon answers from the environment's archive, and the request says which session; the daemon refuses to answer for a live session's receipt, which is its worker's. A reader that is not the local owner is shown the state of the action and not the receipt whole. A receipt for an effect the host performed itself names no session; the catalogue's receipts are answered by the catalogue to the actor that submitted the action. [Receipt states](README.md#receipt-states) describes the receipt.

**`action.cancel`** takes an action identifier and cancels an action that was accepted and not dispatched. The receipt moves to `rejected` with the reason `cancelled`, and the answer is that receipt. After the dispatch marker there is nothing to cancel here, because the effect may already have happened; cancelling it is a separate upstream action with its own receipt. A receipt in any state but accepted is refused with `INVALID_ARGUMENT` and the state it is in, so a second cancellation is a plain refusal. A caller cancels its own actions. An action of another actor needs host-management authority, which at a worker is the local owner's alone. The worker serves the call, and a session that retains no receipts has none to cancel.

## Events, snapshots and history

**`events.subscribe`** starts a subscription for an attachment to a session. It takes the session, the attachment, the streams wanted and an output cursor to resume from, where null starts at the current position. The streams are lifecycle and application-state changes, raw output with its cursors, attachment changes, input-lease changes and action receipts. The answer gives the identifier that the notifications carry, the cursor the subscription starts from, the oldest cursor the worker can still replay, and a gap when the requested cursor had been evicted, which tells the client to discard its partial state and install a snapshot. It also carries the first page of the session's agent resources and the session's live agent instances, taken at the same moment the queue begins, so a change is either in that state or in the events that follow, never in neither. When the subscription cannot go on from where it was, the worker sends `session.resync` and the client reads again.

**`events.snapshot`** answers the whole present state of a session at a cursor: the summary, the geometry, the input lease, every attachment in join order, the oldest retained output cursor and when the snapshot was taken. It also gives one page of the agent resources the host still arbitrates and the live agent instances. It is state, not a replay, so installing it emits no bell, clipboard write, notification or query. `agent_resources_from` continues paging, and a continuation whose copy of the state has ended is refused with `RESYNC_REQUIRED`.

**`agent.instances`** is the part of a snapshot that a view of an agent needs: one page of the agent resources and the live agent instances, with no screen, geometry, lease or attachment. A grant that holds a session without its live screen is refused `events.snapshot` and can still read this.

**`history.page`** reads retained output from a cursor. It takes the session, the cursor and the largest page the caller will accept, which is at most 1 MiB. The answer gives the cursor the page starts at after any gap, the cursor to ask for next, the bytes, the oldest cursor still retained, and a gap when the range had been evicted. The bytes are raw output and need not be valid UTF-8. A gap states the range and, when the host recorded one, the bound that took it ([Retained output, and what eviction leaves behind](../host/README.md#retained-output-and-what-eviction-leaves-behind)). A live session's output is its worker's. For a closed session the daemon answers from the archive, and for a live one it refuses. A paired device is refused with `PERMISSION_DENIED` by the daemon, and the worker refuses every caller that is not the local owner, including one acting under a grant, because a history page is a byte range and the bound on a device's grant is a moment in time, so the host cannot narrow one to the other.

How the daemon routes the other three reads for a paired device, and the history scope it sends with them, is in [Pairing and the host's owner](../host/README.md#pairing-and-the-hosts-owner).

## The managed service's methods

Fourteen methods are answered by the managed service and by no program of this build. The host and the clients call them through the service clients in `crates/kr-client/src/services`. Every one is signed under the service credential ([The service credential](README.md#the-service-credential)), and the eight storage methods also carry the account token. The service is in the web repository.

### The mailbox

A mailbox holds notifications, state references, action receipts, settings and drafts, encrypted, until a device reads them. It queues no keystroke, command, approval decision or session closure, and it is not a way to reach a host. A mailbox is addressed by the recipient's stored-envelope key, and the service derives the mailbox from the key the request names.

**`mailbox.deliver`** places one sealed envelope in the mailbox. A stored item is at most 1 MiB, and one signed request at most 2 MiB. The answer says whether the item was `stored`, was a `duplicate` because that envelope identifier had already carried it, or was `coalesced` because it replaced an unread item of the same thread. It gives the position the item took, the position it replaced where it replaced one, and the mailbox's usage against its item and byte limits. A repeat is resolved by the envelope identifier.

**`mailbox.read`** takes the recipient's key, an optional position to read after and a limit; the client asks for eight items. The answer gives each item with its position, when the service stored it and the sealed envelope exactly as delivered. The first read of an unclaimed mailbox is answered with a challenge instead: an ephemeral X25519 key and the time the challenge stops being answerable. The reader answers with a value derived from that key and its own stored-envelope private key, in a second read. The claim settles on the key that answered, so one device reads and acknowledges the mailbox and a peer that knows only the public key is refused.

**`mailbox.acknowledge`** takes the recipient's key and a position, and tells the service that the recipient has stored everything through that position durably, so the service may remove it. The replay identifiers outlive the items. [The host's own mailbox](../host/README.md#the-hosts-own-mailbox) describes how the host reads its mailbox.

### The authority feed

**`authority.sync`** is one method with seven members, and a request asks for exactly one. A feed belongs to a host and is addressed by the identifier of the host's authorisation key. The service stores the feed and serves it; it judges no owner's authority, because it holds no host's device records. Only the host issues its own ordered revisions and the acknowledgements that say what it applied.

- `publish` places a signed revocation request from a remote owner in a host's feed, optionally with a sealed announcement.
- `revise` submits the host's own next authority revision.
- `acknowledge` acknowledges one published request with the revision the host issued for it.
- `reject` retires a record the host will not apply, with a reason: no owner authority, an unknown target, or a later request that covers it.
- `delegate` names the keys, at most eight, that may remove the host when the host cannot.
- `read` returns a host's feed from a position, 64 records at a time, or only its summary.
- `remove` removes the host, which ends the retention of everything addressed to it.

Issuing a revision, acknowledging, refusing a record and naming the removal keys are the host's own, so the client refuses them under an installation credential before anything is sent. Publishing and reading need no host key, and a removal may be asked by the host or by a key the host named. A record has no expiry and is never coalesced. The service keeps it until the host acknowledges it as complete, refuses it, or is removed. An acknowledgement that reports the dispatch barrier as pending is progress, and the record stays outstanding. [The remote authority feed](../host/README.md#the-remote-authority-feed) describes the host's side.

### Settings sync

**`sync.compare_exchange`** is one method at one path, and a request asks for exactly one of eight members. An object is encrypted before it is stored and written by compare and swap against a revision for that object. A write that loses the comparison is kept for the person to choose from. Every applied write takes the next place in its collection's order, from a counter the service keeps.

- `exchange` writes one object if the service still holds the revision the writer expects.
- `compare` reads what the collection holds, and the kept copies when they are asked for.
- `resolve` drops the copies the person has chosen about.
- `status` asks what the service recorded about one request identity, from the receipt.
- `fence` ends one request identity, naming the earliest and latest instants its attempts were signed at, so a request can always be ended.
- `keys` reads a collection's key records after a revision.
- `rekey` offers the key record that follows the collection's newest.
- `memberships` lists the shared collections whose newest key record names the signer.

Four of these members, `exchange`, `compare`, `status` and `fence`, also address the owner's recovery bundle, by the locator the recovery kit prints instead of a collection. Each of those requests carries the account token for `backup.write` or, for a device that only reads, `backup.restore`. [Settings sync](../client/README.md#settings-sync) and [Managed services](../client/README.md#managed-services) describe the client's side.

### Managed storage

Backup storage belongs to an account, not to the key that asks. Every storage request carries two proofs, the signature of the key that asks and the account token for `backup.write`, and its body names the installation that key derives. An upload is made of bounded parts: every part is 8 MiB except the last. No storage address reaches the client, so every byte goes through the service in both directions.

The answers below are the service's own and are not protocol objects, so timestamps in them are ISO 8601 strings and a byte count is a decimal string.

**`storage.status`** reports the managed storage the caller's account holds.

**`storage.retention.set`** turns backup storage on or off and, when given, sets how many daily snapshots the account keeps. It is decided against the retention revision the caller last saw. A change decided against a revision the record has left changes nothing, and the refusal carries the retention as it stands.

**`storage.upload.create`** reserves the declared maximum against the allowance and allocates an object key, an upload identity and an immutable part table, before any content is accepted. It takes the archive, the object, the backup generation, the declared maximum, the total size and the hash of the encrypted object. It answers with the upload identity, the bytes reserved, when the upload expires and the part table: the total, the part size, the number of parts and the length of the last. The client holds the table to its own arithmetic and refuses one whose total and part size do not give that count and last length.

**`storage.upload.part`** sends one part with its upload, its number, its length and its SHA-256. The ciphertext is the HTTP body and the signed request travels in a header ([the service credential](README.md#the-service-credential)). The service reads at most the declared length plus one byte and refuses a wrong length or hash before it writes the part's content. It answers `stored` or, for a part repeated by its number, `duplicate` without a second write, with the part number and length and how many parts and bytes the upload holds.

**`storage.upload.complete`** takes the upload identity, the total size and the number of parts, checks every part and the total, and settles the reservation as stored bytes. It answers `stored`, or `duplicate` when it was completed before, with the archive, the generation, the object reference (identifier, hash and length), when it was stored and the bytes now committed. A completion asked for again gets the result the service already gave.

**`storage.upload.abort`** abandons an upload. The answer is `cleaned`, with the bytes released, or `cleaning` when the service has begun and not finished releasing them, in which case the released count is null.

**`storage.object.read`** reads one range of a stored object, given by the archive, the object, an offset and a length. The length is from 1 byte to 8 MiB, and the client refuses another before sending. The answer is the bytes of the range.

**`storage.object.delete`** makes a tombstone for one stored object, given by the archive and the object. The answer is `tombstoned`, or `already_tombstoned`, with when the object was deleted, the time after which it is purged, the bytes still charged until then and the retention in force.

[The carrier](../host/README.md#the-carrier) describes how the host uploads backups through these methods.

### The backup manifest

The backup manifest holds neither an archive's objects nor its encrypted manifest. It holds the public half of each generation: the descriptor, with the manifest key wrapped once for each recipient, under the signature of a writer that the collection's owner enrolled. **`backup.manifest`** has three members.

- `enrol` records a writer. The owner signs the writer's key into the collection and signs the request that carries it with the same key.
- `publish` stores one generation. The writer signs the descriptor and the request that carries it. A publication reserves the account's backup storage for its descriptor, so it also carries the account token for `backup.write`. The same publication sent again is answered as a duplicate, and different content for a generation the service holds is refused.
- `fetch` returns one generation of an archive, or the newest, held to the checkpoint the caller already has: a service that cannot meet the checkpoint answers that it has none rather than an older generation. The publication comes back exactly as it was published, and a restore checks it against a writer from the recovery bundle and never against what the service says.

An enrolment and a fetch spend no storage and carry no token.
