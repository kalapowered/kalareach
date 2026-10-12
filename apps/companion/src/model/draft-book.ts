/**
 * The drafts this device holds, and what keeps them.
 *
 * A draft is the person's own text, and it outlives everything else: the screen it was typed on, the
 * connection to the host, the application itself. So it is kept by native code on this device, and
 * this book is the page's side of that: it holds the draft each session's composer shows, writes
 * every change to the native store, and says plainly when it could not.
 *
 * Five rules decide how:
 *
 * - **A write never waits on typing.** An edit shows at once. Writes to the store go one at a time
 *   for each draft, and a write that follows others saves whatever the draft is by then, so a burst
 *   of keystrokes is a few writes of the newest text, never a queue of old ones.
 * - **A reply is applied to the version it saved.** What the store answers says which stored draft
 *   and which version it holds; text typed meanwhile stays, and is written next.
 * - **Nothing is replaced silently.** When another window of the application changed the stored
 *   draft first, the store keeps this window's text as a separate draft and leaves the other
 *   window's alone. Neither text is lost, and a person chooses between them in the list of kept
 *   drafts. A copy is never put in a composer on its own.
 * - **A draft that was sent is removed only once the host took it.** A prompt sent from a draft
 *   takes the stored draft with it, as it stood when the person pressed Send, and what is typed
 *   after that is a draft of its own. When the host took the prompt, the stored draft is removed.
 *   When the host refused it or its outcome is unknown, the book gives the text back to the
 *   composer if the composer is empty, and otherwise keeps it as a draft apart, so that neither
 *   the text that was sent nor the text written since is replaced by the other. The book does this
 *   itself: it does not wait for the screen the prompt was sent from to be open.
 * - **A window that cannot save says so, and does not act on what it could not save.** A move to
 *   another session or a removal acts on the stored draft, so it first needs the draft's newest
 *   text stored, and goes no further when that fails.
 *
 * Nothing here sends anything.
 */

import type { AttachmentHandle } from '@kalareach/protocol'

import { sendOutcomeOf, type InputState } from './receipts'
import {
  failureCode,
  failureMessage,
  type DraftSaved,
  type HostPort,
  type StoredDraft,
  type StoredMark
} from '../host/port'
import {
  connectionLost,
  retarget as retargeted,
  startDraft,
  type Draft,
  type DraftAttachment,
  type DraftTarget,
  type StoredRef
} from './drafts'

/** Whether the store has been read yet, and whether it could be. */
export type BookStatus =
  /** The store is being read. Composers wait, so nothing typed meanwhile is lost to the reading. */
  | 'opening'
  /** The store is read, and every change is written to it. */
  | 'ready'
  /** The store could not be opened. Drafts live in this window only, and the person is told. */
  | 'memory-only'

/** Why a stored draft is listed apart from a composer. */
export type KeptWhy =
  /** Its session has gone. */
  | 'orphaned'
  /** Its conversation changed, and a person chooses where it goes. */
  | 'conflicted'
  /** Another window changed the draft while this one had it, and this is the text kept beside. */
  | 'copy'
  /** Another draft of a session whose composer holds a different one. */
  | 'other'
  /** The text of a prompt the host did not take, or could not say it took. */
  | 'sent'

/** One draft in the list of kept drafts. */
export interface KeptDraft {
  /** Its identity in the store. */
  readonly id: string
  /** The version of it that is shown, which an act on it names. */
  readonly revision: string
  /** Its session. */
  readonly sessionId: string
  readonly text: string
  /** How many files it holds. */
  readonly files: number
  readonly why: KeptWhy
  readonly updatedAtMs: number
  /** True when a composer holds it and waits for the person to retarget it. */
  readonly inComposer: boolean
}

/** The text of a prompt the host did not take, or could not say it took, that the store will not keep for its size. */
export interface UnstoredPrompt {
  readonly id: string
  readonly sessionId: string
  readonly text: string
  /** How many files were sent with it. */
  readonly files: number
  /** True while its session's composer holds exactly this text, so that a copy is there. */
  readonly inComposer: boolean
}

/** What the book holds at one moment. */
export interface BookSnapshot {
  readonly status: BookStatus
  /** The draft each session's composer shows. At most one for a session. */
  readonly drafts: readonly Draft[]
  /** The stored drafts no composer shows. */
  readonly kept: readonly KeptDraft[]
  /** How many files in the store could not be read. They are left where they are. */
  readonly unreadable: number
  /** The text of prompts the store will not keep, held in this window so that a person can copy it. */
  readonly unstored: readonly UnstoredPrompt[]
  /** Why the newest write failed, or why the store would not open. Null when all is well. */
  readonly problem: string | null
}

/**
 * What the entry to the kept drafts says, or null when there is nothing to enter for.
 *
 * `title` stands alone (a phone's row); `label` and `rest` are the two halves of a sentence whose
 * first half is the control (a desktop's line). Drafts that could not be read are reported too: a
 * person whose drafts are unreadable is told, rather than shown an empty list.
 */
export function keptEntry(
  book: Pick<BookSnapshot, 'kept' | 'unreadable' | 'unstored'>
): { readonly title: string; readonly label: string; readonly rest: string } | null {
  const stored = book.kept.length
  const held = book.unstored.length
  if (stored === 0 && held === 0) {
    return book.unreadable === 0
      ? null
      : { title: 'Some drafts could not be read', label: 'Some drafts', rest: 'could not be read.' }
  }
  if (stored === 0) {
    // Text that is held in this window only, and is lost when the application stops.
    const label = held === 1 ? 'One prompt' : `${String(held)} prompts`
    return { title: `${label} held in this window only`, label, rest: 'held in this window only.' }
  }
  const label = stored === 1 ? 'One kept draft' : `${String(stored)} kept drafts`
  const alone = held === 0 ? '' : ' Some text is held in this window only.'
  return {
    title: held === 0 ? label : `${label}, and text held in this window only`,
    label,
    rest: `${stored === 1 ? 'is' : 'are'} not in a composer.${alone}`
  }
}

/** How a prompt that was sent from a draft ended. */
export type SendOutcome =
  /** The host took it. */
  | 'taken'
  /** The host did not take it. */
  | 'refused'
  /** Nobody knows. */
  | 'unknown'

/** Whether a rejection of a send's claim is the loss of it: another window holds the draft. */
export function claimWasLost(failure: unknown): boolean {
  return typeof failure === 'object' && failure !== null && 'claimLost' in failure
}

/** A prompt on its way. */
export interface SendToken {
  readonly key: string
  /**
   * Settles once the stored draft is this window's to send, and rejects when it is not: another
   * window of the application changed it or sent it first, and this window sends nothing. The
   * rejection is a command's failure, with the code `DRAFT_CONFLICT`.
   */
  readonly claimed: Promise<void>
}

/** A prompt sent from a draft, from the press to the host's answer. */
interface Flight {
  /** Its name among the prompts that have not ended. */
  readonly id: string
  /** The composer it was sent from. */
  readonly composer: string
  /** The draft as it stood when the person pressed Send. */
  readonly sent: Draft
  /** The stored draft that holds exactly that, once there is one. */
  record: StoredRef | null
  /**
   * An older version the composer held in the store when the write of what was sent failed. It says
   * less than what was sent, so it goes once the prompt has ended.
   */
  earlier: StoredRef | null
  /** How the prompt was said to have ended, once it has been: the end itself is made in the composer's turn. */
  endedAs?: SendOutcome
}

/** How a write of a draft ended. */
type Written =
  /** The store holds the draft now. */
  | 'stored'
  /** There was nothing to write: the store already holds it, or the store is not open. */
  | 'unchanged'
  /** The store refused, and the draft is held in this window only. */
  | 'failed'
  /**
   * A claim of the stored draft was lost: another window changed it or removed it first, so what
   * this window holds is kept beside theirs, or as a draft of its own.
   */
  | 'lost'

/** What the writer knows of one draft. */
interface Track {
  /** The content the store holds, or is known to need no write for. */
  savedKey: string | null
  /** True while a retarget the person chose is on its way. */
  retargeting: boolean
  /** The writes of this draft, one after another. */
  chain: Promise<void>
}

/** The files on a draft that a store can hold: completed uploads, without their previews. */
function storable(draft: Draft): readonly AttachmentHandle[] {
  return draft.attachments.flatMap((file) =>
    file.upload === 'uploaded' && file.handle !== null ? [{ ...file.handle, preview: null }] : []
  )
}

/** The mark the store keeps for a draft: detachment is a fact about the connection, not the draft. */
function markOf(draft: Draft): StoredMark {
  return draft.state === 'conflicted' || draft.state === 'orphaned' ? draft.state : 'open'
}

/** Whether the person changed the text or the files of a composer between two looks at it. */
function writtenSince(before: Draft, after: Draft): boolean {
  const content = (draft: Draft) =>
    JSON.stringify([draft.text, draft.attachments.map((file) => [file.localId, file.upload])])
  return before.revision !== after.revision || content(before) !== content(after)
}

/** Whether two drafts hold the same files. */
function sameFiles(a: Draft, b: Draft): boolean {
  const ids = (draft: Draft) => storable(draft).map((handle) => handle.transfer_id)
  return JSON.stringify(ids(a)) === JSON.stringify(ids(b))
}

/** Whether the store has anything to keep of a draft. */
function holdsNothing(draft: Draft): boolean {
  return draft.text.length === 0 && storable(draft).length === 0
}

/**
 * Whether a composer holds nothing at all of the person's: no text and no file, whatever became of
 * the file's upload. A file still uploading, or one that failed, is not something a store can
 * keep, and is still the person's: a composer that holds one is not free to be replaced.
 */
function isEmpty(draft: Draft): boolean {
  return draft.text.length === 0 && draft.attachments.length === 0
}

/** Whether a composer holds a file that no store can keep: its upload has not completed. */
function holdsUnkeptFile(draft: Draft): boolean {
  return draft.attachments.some((file) => file.upload !== 'uploaded' || file.handle === null)
}

/** What a composer's files that no store can keep are doing, in words that open a sentence. */
function unkeptFileWords(draft: Draft): string {
  const uploading = draft.attachments.some((file) => file.upload === 'uploading')
  return uploading
    ? 'A file in the composer has not finished uploading'
    : 'A file in the composer was not uploaded'
}

/** What to do about it: wait for an upload that goes on, remove one that has failed. */
function unkeptFileAdvice(draft: Draft): string {
  return draft.attachments.some((file) => file.upload === 'uploading')
    ? 'Wait for it, or remove it'
    : 'Remove it'
}

/** Whether a composer holds the same text and files as a draft that was sent. */
function holdsWhatWasSent(composer: Draft | undefined, sent: Draft): boolean {
  const files = (draft: Draft): string => storable(draft).map((handle) => handle.transfer_id).join(' ')
  return composer !== undefined && composer.text === sent.text && files(composer) === files(sent)
}

/** What a write of this draft would store: two drafts with one key need no write between them. */
function contentKey(draft: Draft): string {
  return JSON.stringify([
    draft.text,
    draft.target,
    markOf(draft),
    storable(draft).map((handle) => handle.transfer_id)
  ])
}

/** The file a stored handle stands for. */
function fileOf(handle: AttachmentHandle): DraftAttachment {
  return {
    localId: `file-${handle.transfer_id}`,
    transferId: handle.transfer_id,
    name: handle.original_file_name,
    byteLen: Number(handle.byte_len),
    mediaType: handle.declared_media_type,
    presentedAsImage: handle.presented_as_image,
    upload: 'uploaded',
    acceptedUpstream: false,
    handle
  }
}

/** The key a session's composer draft goes by: stable for the session, whatever is stored. */
export function composerKey(sessionId: string): string {
  return `draft-${sessionId}`
}

/**
 * The draft a stored one gives a composer.
 *
 * Nothing is connected when the application starts, so an open draft is detached until the host has
 * said where its conversation stands.
 */
function draftOf(stored: StoredDraft): Draft {
  return {
    draftId: composerKey(stored.sessionId),
    revision: 1,
    text: stored.text,
    target: {
      sessionId: stored.sessionId,
      applicationInstanceId: stored.applicationInstanceId,
      agentBindingRevision: stored.agentBindingRevision
    },
    state: stored.state === 'open' ? 'detached' : stored.state,
    updatedAtMs: Number(stored.updatedAtMs),
    attachmentId: null,
    attachments: stored.attachments.map(fileOf),
    stored: { id: stored.id, revision: stored.revision }
  }
}

/** The newest of several stored drafts: the latest change, then the latest start. */
function newest(drafts: readonly StoredDraft[]): StoredDraft | undefined {
  return [...drafts].sort(
    (a, b) =>
      Number(b.updatedAtMs) - Number(a.updatedAtMs) ||
      Number(b.createdAtMs) - Number(a.createdAtMs) ||
      a.id.localeCompare(b.id)
  )[0]
}

/** The drafts of a window, and the writer that keeps them. */
export class DraftBook {
  readonly #port: HostPort
  #status: BookStatus = 'opening'
  #drafts: readonly Draft[] = []
  #others: readonly StoredDraft[] = []
  #unreadable = 0
  #problem: string | null = null
  readonly #failed = new Map<string, { readonly code: string; readonly message: string }>()
  readonly #tracks = new Map<string, Track>()
  readonly #flights = new Map<string, Flight>()
  /** The prompt each submission carries, by the submission's local identity, while it is open or its outcome is unknown. */
  readonly #byLocal = new Map<string, string>()
  /** Prompts that ended as of unknown outcome, until the host says what became of them. */
  readonly #unknowns = new Map<string, Flight>()
  /** Prompts that ended without their text stored anywhere, kept here until the store takes it. */
  #unsettled: Flight[] = []
  /** Prompts whose text the store will never take, for its size: held here for a person to copy. */
  #unstored: Flight[] = []
  /** Records that should be gone and could not be removed yet, with the name their failure is kept under. */
  #cleanups: { readonly ref: StoredRef; readonly key: string }[] = []
  /** The stored drafts that are the text of a prompt the host did not take. */
  readonly #sentRecords = new Set<string>()
  /** The highest edit number a composer ever showed, so that no number is shown twice. */
  readonly #floor = new Map<string, number>()
  /** The records of listed drafts that an act is working on, out of reach of every read until it ends. */
  readonly #acting = new Set<string>()
  /** How many times a record was removed or moved, so a read that overtaken by one can be told. */
  #moves = 0
  #settling = false
  #sends = 0
  readonly #listeners = new Set<() => void>()
  readonly #notices = new Set<(words: string) => void>()
  #cached: BookSnapshot | null = null
  #inflight = 0
  #idle: (() => void)[] = []

  constructor(port: HostPort) {
    this.#port = port
  }

  /** Subscribes to every change; the returned function unsubscribes. */
  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  /** Subscribes to the passing messages the book has for the person. */
  onNotice(listener: (words: string) => void): () => void {
    this.#notices.add(listener)
    return () => {
      this.#notices.delete(listener)
    }
  }

  /** What the book holds now. The same object until something changes. */
  snapshot = (): BookSnapshot => {
    this.#cached ??= {
      status: this.#status,
      drafts: this.#drafts,
      kept: this.#keptList(),
      unreadable: this.#unreadable,
      unstored: this.#unstored.map((flight) => ({
        id: flight.id,
        sessionId: flight.sent.target.sessionId,
        text: flight.sent.text,
        files: storable(flight.sent).length,
        inComposer: holdsWhatWasSent(this.#find(flight.composer), flight.sent)
      })),
      problem: this.#problem
    }
    return this.#cached
  }

  /**
   * Reads the stored drafts into the composers.
   *
   * A store that cannot be opened leaves the book in memory only: nothing is lost that was in
   * memory, and the person is told that nothing is kept.
   */
  async hydrate(): Promise<void> {
    try {
      const stored = await this.#port.deviceDrafts()
      this.#unreadable = stored.unreadable
      // Before the drafts are read into composers: a record owed for removal is no draft's.
      this.#oweFrom(stored.pendingRemovals)
      this.#merge(stored.drafts)
      this.#status = 'ready'
      this.#problem = null
    } catch (failure) {
      this.#status = 'memory-only'
      this.#problem = failureMessage(failure)
    }
    this.#changed()
    if (this.#status === 'ready') {
      this.#scheduleAll()
      this.#hold(this.#settleAgain())
    }
  }

  /**
   * Reads the store again, keeping every composer that holds something.
   *
   * A read that a removal or a move overtook is not merged: it lists a record where it is no longer,
   * and a composer that took it would show text the store does not hold. It is read again.
   */
  async reload(): Promise<void> {
    if (this.#status !== 'ready') return
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const seen = this.#moves
      try {
        const stored = await this.#port.deviceDrafts()
        // A read that a removal or a move overtook lists a record where it no longer is: it is
        // never merged, so after the last attempt the book is left as it was.
        if (this.#moves !== seen) continue
        this.#unreadable = stored.unreadable
        this.#oweFrom(stored.pendingRemovals)
        this.#merge(stored.drafts)
        this.#changed()
      } catch (failure) {
        this.#problem = failureMessage(failure)
        this.#changed()
      }
      return
    }
  }

  /**
   * The draft a session's composer shows, an empty one the first time it is asked for.
   *
   * The empty draft is not stored and does not announce itself: it has nothing to keep until the
   * person writes in it.
   */
  draft(sessionId: string): Draft {
    const held = this.#drafts.find((draft) => draft.target.sessionId === sessionId)
    if (held) return held
    const key = composerKey(sessionId)
    const fresh = {
      ...startDraft(
        key,
        { sessionId, applicationInstanceId: null, agentBindingRevision: null },
        Date.now()
      ),
      revision: this.#above(key, 1)
    }
    this.#drafts = [...this.#drafts, fresh]
    return fresh
  }

  /** Changes one session's draft. The change is given the draft as it is now. */
  update(sessionId: string, change: (draft: Draft) => Draft): void {
    this.draft(sessionId)
    this.setDrafts((drafts) =>
      drafts.map((draft) => (draft.target.sessionId === sessionId ? change(draft) : draft))
    )
  }

  /** Changes the drafts of every session at once. */
  setDrafts(change: (drafts: readonly Draft[]) => readonly Draft[]): void {
    const before = this.#drafts
    const known = new Set(before.map((draft) => draft.draftId))
    // A composer a caller makes for itself starts above every number the one it replaces showed.
    const after = change(before).map((draft) =>
      known.has(draft.draftId)
        ? draft
        : { ...draft, revision: this.#above(draft.draftId, draft.revision) }
    )
    if (after.length === before.length && after.every((draft, index) => draft === before[index])) {
      return
    }
    this.#drafts = after
    this.#changed()
    for (const draft of after) {
      if (!before.includes(draft)) this.#schedule(draft.draftId)
    }
  }

  /** The connection went away: every draft keeps its text and loses its association. */
  connectionLost(): void {
    this.setDrafts((drafts) => drafts.map(connectionLost))
  }

  /**
   * Sends a draft to a conversation a person chose, which is the one thing that clears a conflict.
   *
   * The page shows it at once. The store is told in its own turn, and when the store refuses, the
   * draft goes back to what it was and the person is told. When the refusal is that another window
   * changed the draft since, this window lets go of that version and keeps what it holds as a draft
   * of its own, so that the person can try again on a draft this window can write.
   */
  retarget(sessionId: string, target: DraftTarget): void {
    const before = this.draft(sessionId)
    this.update(sessionId, (draft) => retargeted(draft, target, draft.attachmentId))
    const stored = before.stored
    if (stored === null) return
    const track = this.#track(before.draftId)
    track.retargeting = true
    this.#enqueue(before.draftId, async () => {
      try {
        const current = this.#find(before.draftId)?.stored ?? stored
        const answered = await this.#port.deviceDraftRetarget({
          id: current.id,
          expectedRevision: current.revision,
          sessionId: target.sessionId,
          applicationInstanceId: target.applicationInstanceId,
          agentBindingRevision: target.agentBindingRevision
        })
        this.#mutate(before.draftId, (draft) => ({
          ...draft,
          stored: { id: answered.id, revision: answered.revision }
        }))
        // The text is written next, against the target the store now holds.
        track.savedKey = null
      } catch (failure) {
        this.#mutate(before.draftId, (draft) => ({
          ...draft,
          target: before.target,
          state: before.state
        }))
        this.#say(`The draft was not moved: ${failureMessage(failure)}`)
        if (failureCode(failure) === 'DRAFT_CONFLICT') this.#letGo(before.draftId)
        this.#hold(this.reload())
      } finally {
        track.retargeting = false
        this.#schedule(before.draftId)
      }
    })
  }

  /**
   * Notes that a prompt is on its way from a session's draft, and takes the stored draft with it.
   *
   * The stored draft is brought up to what is being sent and set apart as the prompt's own: what is
   * typed from now on is a draft of its own. Call this before the composer is cleared, and say how
   * the prompt ended with [`endSend`].
   */
  beginSend(sessionId: string): SendToken {
    const sent = this.draft(sessionId)
    const key = sent.draftId
    this.#sends += 1
    const token = `send-${String(this.#sends)}`
    const flight: Flight = { id: token, composer: key, sent, record: null, earlier: null }
    this.#flights.set(token, flight)
    let claim: { resolve: () => void; reject: (failure: unknown) => void } = {
      resolve: () => undefined,
      reject: () => undefined
    }
    const claimed = new Promise<void>((resolve, reject) => {
      claim = { resolve, reject }
    })
    // A caller that sends nothing more has no use for the rejection, and it is not an unhandled one.
    claimed.catch(() => undefined)
    this.#enqueue(key, async () => {
      if (this.#status === 'ready' && !holdsNothing(sent)) {
        // The save names the version this window holds and always makes a new one, so of two
        // windows that hold the same stored draft only the first can claim it.
        const written = await this.#write(key, sent, true)
        if (written === 'failed') flight.earlier = this.#find(key)?.stored ?? null
        else flight.record = this.#find(key)?.stored ?? null
        if (written === 'lost') {
          this.#say(
            'Another window of this application holds this draft, so it was not sent. It is kept here.'
          )
          claim.reject({
            code: 'DRAFT_CONFLICT',
            message: 'Another window of this application holds this draft, so it was not sent.',
            claimLost: true
          })
        } else {
          claim.resolve()
        }
      } else {
        claim.resolve()
      }
      // The composer lets go of the record: the next thing written is a draft of its own, and a
      // composer that still holds what was sent (a phone keeps it until the answer) needs no write.
      const now = this.#find(key)
      if (now === undefined) return
      this.#mutate(key, (draft) => ({ ...draft, stored: null }))
      this.#track(key).savedKey = contentKey(now) === contentKey(sent) ? contentKey(now) : null
    })
    return { key: token, claimed }
  }

  /**
   * Keeps a prompt open that the host has accepted and not yet applied or refused, under the local
   * identity of the submission that carries it. It ends when [`sendSettled`] is told how; a view
   * going away does not end it, because nothing the view knows could.
   */
  holdSend(token: Pick<SendToken, 'key'>, localId: string): void {
    this.#byLocal.set(localId, token.key)
  }

  /**
   * Says what a submission came to, for the prompt it carries.
   *
   * A prompt still open ends as the state says. A prompt that ended as of unknown outcome and is
   * then said to have been applied loses its stored draft after all, and the composer that shows
   * exactly its text is cleared; one that is said to be refused is as it was, kept.
   */
  sendSettled(localId: string, state: InputState): void {
    const outcome = sendOutcomeOf(state)
    const key = this.#byLocal.get(localId)
    if (outcome === null || key === undefined) return
    const flight = this.#flights.get(key)
    if (flight !== undefined && flight.endedAs === undefined) {
      this.endSend({ key }, outcome, localId)
      return
    }
    // It has ended, or is ending, as of unknown outcome: what the host now says is dealt with in
    // the composer's turn, after the end.
    if (outcome === 'unknown') return
    const ended = flight ?? this.#unknowns.get(key)
    if (ended === undefined) return
    this.#byLocal.delete(localId)
    this.#enqueue(ended.composer, async () => {
      this.#unknowns.delete(key)
      if (outcome === 'taken') await this.#takenLate(ended)
    })
  }

  /**
   * What a prompt that is said to have been applied, after nobody knew, leaves behind: nothing. It
   * runs in the composer's own turn, so it does not wait on a turn of its own.
   */
  async #takenLate(flight: Flight): Promise<void> {
    const id = flight.record?.id
    if (id === undefined) return
    const composer = this.#find(flight.composer)
    try {
      if (composer?.stored?.id === id) {
        // The composer shows the text under that record: both go, unless the person has changed it.
        if (!holdsWhatWasSent(composer, flight.sent)) return
        await this.#port.deviceDraftDiscard({
          id,
          expectedRevision: composer.stored.revision
        })
        this.#moves += 1
        this.#emptied(composer)
        await this.reload()
        return
      }
      const listed = this.#others.find((other) => other.id === id)
      if (listed !== undefined) {
        await this.#port.deviceDraftDiscard({ id, expectedRevision: listed.revision })
        this.#moves += 1
        await this.reload()
      }
    } catch (failure) {
      // Another window changed it: it is theirs now. A store that refuses leaves the removal owed.
      if (failureCode(failure) !== 'DRAFT_CONFLICT') {
        const owed = flight.record
        if (owed !== null) this.#owe(owed, flight.id)
      }
    }
  }

  /** A composer whose draft was removed from the store is empty, as if it had never been written in. */
  #emptied(composer: Draft): void {
    const now = this.#find(composer.draftId)
    this.#retire(now ?? composer)
    this.#mutate(composer.draftId, (draft) => ({
      ...draft,
      revision: draft.revision + 1,
      text: '',
      attachments: [],
      stored: null,
      state: 'bound',
      target: { sessionId: draft.target.sessionId, applicationInstanceId: null, agentBindingRevision: null }
    }))
    this.#track(composer.draftId).savedKey = contentKey(this.#find(composer.draftId) ?? composer)
  }

  /** Says how a prompt that was sent from a draft ended; `localId` names its submission, when it has one. */
  endSend(token: Pick<SendToken, 'key'>, outcome: SendOutcome, localId?: string): void {
    const flight = this.#flights.get(token.key)
    if (flight === undefined) return
    flight.endedAs = outcome
    if (localId !== undefined && outcome === 'unknown') this.#byLocal.set(localId, flight.id)
    else if (localId !== undefined) this.#byLocal.delete(localId)
    this.#enqueue(flight.composer, async () => {
      try {
        if (outcome === 'taken') {
          await this.#dropSent(flight)
          await this.#dropEarlier(flight)
          return
        }
        const stored = await this.#giveBack(flight)
        if (stored) {
          // The text is stored under a record that stands for it, so the older version it grew from
          // says less and goes. Until then it stays: it is all the store holds of this draft.
          await this.#dropEarlier(flight)
        } else {
          this.#unsettled.push(flight)
        }
        // Nobody knows what became of it, and the host may still say: the prompt is remembered
        // for as long as the window is.
        if (outcome === 'unknown' && localId !== undefined) this.#unknowns.set(flight.id, flight)
      } finally {
        this.#flights.delete(flight.id)
      }
    })
  }

  /**
   * Removes a stored record, unless another window changed it since. Says whether it is gone (or is
   * another window's now); false means the store would not remove it, and the failure is kept under
   * `key` until it does.
   */
  async #dropRecord(record: StoredRef, key: string): Promise<boolean> {
    try {
      await this.#port.deviceDraftDiscard({ id: record.id, expectedRevision: record.revision })
      this.#moves += 1
      return true
    } catch (failure) {
      if (failureCode(failure) === 'DRAFT_CONFLICT') {
        // Another window changed it since: it is theirs now.
        this.#moves += 1
        this.#hold(this.reload())
        return true
      }
      this.#fail(key, failure)
      return false
    }
  }

  /** Removes the record of a prompt the host took; one the store will not remove is tried again later. */
  async #dropSent(flight: Flight): Promise<void> {
    const record = flight.record
    if (record === null) return
    if (!(await this.#dropRecord(record, flight.id))) this.#owe(record, flight.id)
  }

  /** Removes the older version a prompt grew from, now that its text stands elsewhere. */
  async #dropEarlier(flight: Flight): Promise<void> {
    const earlier = flight.earlier
    if (earlier === null) return
    // The record stays on the flight, and so out of reach of every read, until it is gone or the
    // cleanups hold it; a read that merged in between would show a ghost of it.
    if (!(await this.#dropRecord(earlier, flight.id))) this.#owe(earlier, flight.id)
    flight.earlier = null
  }

  /**
   * Holds a removal the store would not make, here and in the store's own ledger, so that a start
   * after this one makes it: the text of a prompt the host took does not come back as a draft.
   */
  #owe(ref: StoredRef, key: string): void {
    this.#cleanups.push({ ref, key })
    this.#hold(
      Promise.resolve()
        .then(() => this.#port.deviceDraftMarkRemoval({ id: ref.id, expectedRevision: ref.revision }))
        // A ledger that cannot be written leaves the removal owed in this window only.
        .catch(() => undefined)
    )
  }

  /** Takes up the removals an earlier run began and did not finish. */
  #oweFrom(pending: readonly { readonly id: string; readonly expectedRevision: string }[]): void {
    for (const removal of pending) {
      // A draft can be owed a removal at each of several versions, and each is made or found over.
      if (
        this.#cleanups.some(
          (each) => each.ref.id === removal.id && each.ref.revision === removal.expectedRevision
        )
      ) {
        continue
      }
      this.#cleanups.push({
        ref: { id: removal.id, revision: removal.expectedRevision },
        key: `removal-${removal.id}`
      })
    }
  }

  /**
   * Keeps the text of a prompt the host did not take, and says whether the store holds it.
   *
   * It goes back to the composer when the composer holds nothing, or holds exactly this text. When
   * the composer holds something else, the text of the prompt stays a stored draft of its own and
   * is listed with the kept drafts. The record set apart for the prompt is out of reach of every
   * read of the store until this has decided, so no composer takes it meanwhile.
   */
  async #giveBack(flight: Flight): Promise<boolean> {
    const key = flight.composer
    const sent = flight.sent
    let record = flight.record
    if (record === null && this.#status === 'ready' && !holdsNothing(sent)) {
      // The first write failed, or the draft was never stored: try again now that the text matters.
      record = await this.#keepApart(flight.id, sent)
      flight.record = record
    }
    const composer = this.#find(key)
    const same = composer !== undefined && composer.text === sent.text && sameFiles(composer, sent)
    if (composer === undefined || (composer.stored === null && (isEmpty(composer) || same))) {
      if (record !== null) {
        this.#clearFailure(flight.id)
        this.#adopt(key, sent, composer, record)
        return true
      }
      // Nothing stores it. The composer shows it, and what the store held of this draft before is
      // the record the next write goes over, so that it says all of the text once the store takes it.
      // The failure is the composer's from here: its next good write clears it.
      this.#handOverFailure(flight.id, key)
      this.#adopt(key, sent, composer, flight.earlier)
      flight.earlier = null
      return true
    }
    if (same) {
      // The screen put the text back and it was stored under the composer's own record. The record
      // set apart for the prompt says the same thing, and goes.
      this.#clearFailure(flight.id)
      if (record !== null && composer.stored?.id !== record.id) await this.#dropSent({ ...flight, record })
      return record !== null || composer.stored !== null
    }
    // The text is listed apart from the composer. The record may have been changed or removed by
    // another window while the prompt was on its way, so the text is written to it at the version
    // this window knows: a change gives a copy beside it, a removal gives a draft of its own.
    const listed = await this.#storeSent(flight)
    if (listed === null) {
      if (this.#failed.get(flight.id)?.code === 'QUOTA_EXCEEDED') {
        // The store will never take it, for its size. Nothing stands for it, so the older version it
        // grew from stays; the text is held here, listed with the kept drafts, for a person to copy.
        this.#clearFailure(flight.id)
        this.#hold_unstored(flight)
        return true
      }
      this.#say(
        'The prompt that was sent could not be kept apart from what you have written since. It is held in this window only until this device can keep it.'
      )
      return false
    }
    this.#sentRecords.add(listed.id)
    this.#say(
      'The prompt that was sent is kept in Kept drafts, because you have written something new here since.'
    )
    // Its text is decided: the older version goes and the record is no longer set apart, so that
    // the list shows it.
    this.#clearFailure(flight.id)
    await this.#dropEarlier(flight)
    this.#flights.delete(flight.id)
    await this.reload()
    return true
  }

  /** A failure kept under a prompt's name is over: the text is stored, or another owns it now. */
  #clearFailure(name: string): void {
    if (this.#failed.delete(name)) this.#recompute()
  }

  /** The composer takes over a failure the prompt's name held: its next good write clears it. */
  #handOverFailure(name: string, key: string): void {
    const held = this.#failed.get(name)
    if (held === undefined) return
    this.#failed.delete(name)
    this.#failed.set(key, held)
    this.#recompute()
  }

  /** Holds the text of a prompt the store will not keep, and says so. */
  #hold_unstored(flight: Flight): void {
    flight.earlier = null
    this.#unstored = [...this.#unstored, flight]
    this.#say('The prompt that was sent is too long to keep as a draft. Its text is listed in Kept drafts so that you can copy it.')
    this.#changed()
  }

  /**
   * Puts a copy of the text of an unstored prompt in its session's composer, when the composer holds
   * nothing.
   *
   * The composer is where a person can shorten it and send it again, and where it can be copied
   * from. The prompt stays listed: a composer is a place the text can be lost from (its session can
   * close with nothing stored for it), so the list lets go of the text only when the person says
   * they have what they need. The copy in the composer is held in this window only, with the
   * warning that it is not kept, until it is short enough for the store.
   */
  async useUnstored(id: string): Promise<boolean> {
    const first = this.#unstored.find((each) => each.id === id)
    if (first === undefined) return false
    const key = first.composer
    let put = false
    // After the composer's own writes, so that a record it still holds for what the person cleared
    // has gone, and what is on the screen is what the book holds.
    await this.#enqueueAwait(key, () => {
      const flight = this.#unstored.find((each) => each.id === id)
      if (flight === undefined) return Promise.resolve()
      const composer = this.#find(key)
      if (holdsWhatWasSent(composer, flight.sent)) return Promise.resolve()
      if (composer !== undefined && (composer.text !== '' || composer.attachments.length > 0)) {
        // Whatever state an upload is in, a file is something the person put there.
        this.#say('The composer holds something. Send it or clear it first, then put this prompt there.')
        return Promise.resolve()
      }
      if (composer !== undefined && composer.stored !== null) {
        // A record kept for what the person cleared has not been removed: putting a copy over the
        // composer would leave that record behind as a draft nobody can see.
        this.#say(
          'An earlier draft of this composer is still kept on this device, so the prompt was not put there. Copy it, or try again.'
        )
        return Promise.resolve()
      }
      this.#adopt(key, flight.sent, composer, null)
      put = true
      return Promise.resolve()
    })
    return put
  }

  /** Lets go of the text of a prompt a person has copied or no longer wants. */
  forgetUnstored(id: string): void {
    this.#unstored = this.#unstored.filter((flight) => flight.id !== id)
    this.#changed()
  }

  /**
   * Makes sure the store holds the text of a prompt under a record, and names the record.
   *
   * The record set apart for the prompt is read first. If it is as it was left, nothing is written,
   * so that putting the text away does not make it the newest draft of its session. If another
   * window changed it, the text is written at the version this window knows, which keeps it beside
   * what the other window made; if another window removed it, the text becomes a draft again.
   */
  async #storeSent(flight: Flight): Promise<StoredRef | null> {
    const record = flight.record
    if (record === null) {
      const made = await this.#keepApart(flight.id, flight.sent)
      flight.record = made
      return made
    }
    try {
      const listing = await this.#port.deviceDrafts()
      const held = listing.drafts.find((each) => each.id === record.id)
      if (held?.revision === record.revision && held.text === flight.sent.text) return record
      const saved = await this.#port.deviceDraftSave({
        id: record.id,
        expectedRevision: record.revision,
        sessionId: flight.sent.target.sessionId,
        applicationInstanceId: flight.sent.target.applicationInstanceId,
        agentBindingRevision: flight.sent.target.agentBindingRevision,
        state: markOf(flight.sent),
        text: flight.sent.text,
        attachments: storable(flight.sent)
      })
      flight.record = { id: saved.draft.id, revision: saved.draft.revision }
      return flight.record
    } catch (failure) {
      this.#fail(flight.id, failure)
      return null
    }
  }

  /**
   * Stores the text of prompts that ended with nothing to hold it, now that the store may take it.
   *
   * Each stays set apart until its text is stored, so that the older version it grew from is not
   * taken by a composer meanwhile. A text the store will never take, for its size, is let go.
   */
  async #settleAgain(): Promise<void> {
    if (this.#status !== 'ready' || this.#settling) return
    this.#settling = true
    try {
      for (const cleanup of [...this.#cleanups]) {
        if (await this.#dropRecord(cleanup.ref, cleanup.key)) {
          this.#cleanups = this.#cleanups.filter((each) => each !== cleanup)
          this.#clearFailure(cleanup.key)
        }
      }
      for (const flight of [...this.#unsettled]) {
        const stored = await this.#storeSent(flight)
        if (stored === null) {
          if (this.#failed.get(flight.id)?.code === 'QUOTA_EXCEEDED') {
            this.#clearFailure(flight.id)
            this.#unsettled = this.#unsettled.filter((each) => each !== flight)
            this.#hold_unstored(flight)
            await this.reload()
          }
          continue
        }
        this.#clearFailure(flight.id)
        this.#sentRecords.add(stored.id)
        await this.#dropEarlier(flight)
        this.#unsettled = this.#unsettled.filter((each) => each !== flight)
        await this.reload()
      }
    } finally {
      this.#settling = false
    }
    this.#recompute()
  }

  /** Stores a draft as a record of its own, whatever the composer holds, and says where it is. */
  async #keepApart(key: string, draft: Draft): Promise<StoredRef | null> {
    try {
      const saved = await this.#port.deviceDraftSave({
        id: null,
        expectedRevision: null,
        sessionId: draft.target.sessionId,
        applicationInstanceId: draft.target.applicationInstanceId,
        agentBindingRevision: draft.target.agentBindingRevision,
        state: markOf(draft),
        text: draft.text,
        attachments: storable(draft)
      })
      return { id: saved.draft.id, revision: saved.draft.revision }
    } catch (failure) {
      this.#fail(key, failure)
      return null
    }
  }

  /**
   * Puts the text of a prompt back in a composer that holds nothing else, under a stored record.
   *
   * The record is written to again with the composer's next write, whatever it says: another window
   * may have changed it, or removed it, while the prompt was on its way, and a write names the version
   * it replaces, so what the store holds is then kept beside and not written over.
   */
  #adopt(key: string, sent: Draft, composer: Draft | undefined, record: StoredRef | null): void {
    if (composer) this.#retire(composer)
    // A file the composer gained since the press is the person's, and goes on the draft beside the
    // files that were sent.
    const gained =
      composer?.attachments.filter(
        (file) => !sent.attachments.some((sentFile) => sentFile.localId === file.localId)
      ) ?? []
    const back: Draft = {
      ...sent,
      attachments: [...sent.attachments, ...gained],
      draftId: key,
      revision: this.#above(key, (composer ?? sent).revision + 1),
      // What happened to the conversation since the press is a fact about it, which the text keeps.
      state:
        composer?.state === 'conflicted' || composer?.state === 'orphaned' || composer?.state === 'detached'
          ? composer.state
          : sent.state,
      updatedAtMs: Date.now(),
      stored: record
    }
    this.#drafts = this.#drafts.some((draft) => draft.draftId === key)
      ? this.#drafts.map((draft) => (draft.draftId === key ? back : draft))
      : [...this.#drafts, back]
    this.#track(key).savedKey = null
    this.#changed()
    this.#schedule(key)
  }

  /**
   * Removes a stored draft a person chose to throw away.
   *
   * `shown` is the version the person was shown. A draft a composer holds is the composer's own, so
   * what is removed is what the composer holds now; any other is removed only at the version shown.
   */
  async discard(id: string, shown: string): Promise<void> {
    const pressed = this.#drafts.find((draft) => draft.stored?.id === id)
    const keyed = pressed?.draftId
    const run = async (): Promise<void> => {
      if (keyed !== undefined && pressed !== undefined) await this.#stillThere(keyed, pressed)
      const composer = keyed === undefined ? undefined : this.#find(keyed)
      const target = composer?.stored ?? (await this.#shownOf(id, shown))
      if (target === undefined || target === null) return
      if (composer === undefined) this.#acting.add(target.id)
      try {
        await this.#port.deviceDraftDiscard({ id: target.id, expectedRevision: target.revision })
        this.#moves += 1
      } catch (failure) {
        this.#actFailed(target.id)
        await this.#sawTheirs(composer?.draftId, failure)
        throw failure
      }
      this.#actWorked(target.id, null)
      if (composer) {
        const now = this.#find(composer.draftId)
        if (now !== undefined && writtenSince(composer, now)) {
          // The person wrote in the composer while the store was answering: what they wrote is not
          // what was discarded, so it stays, as a draft of its own.
          this.#say('The composer keeps what you wrote while this was being done.')
          this.#letGo(composer.draftId)
        } else {
          this.#emptied(composer)
        }
      }
      await this.reload()
    }
    if (keyed !== undefined) await this.#enqueueAwait(keyed, run)
    else await run()
  }

  /** Moves a stored draft to a session a person chose; `shown` is as for [`discard`]. */
  async moveTo(id: string, sessionId: string, shown: string): Promise<void> {
    const pressed = this.#drafts.find((draft) => draft.stored?.id === id)
    const keyed = pressed?.draftId
    const run = async (): Promise<void> => {
      if (keyed !== undefined && pressed !== undefined) await this.#stillThere(keyed, pressed)
      const composer = keyed === undefined ? undefined : this.#find(keyed)
      if (composer && holdsUnkeptFile(composer)) {
        // A move takes the composer away, and a file that is not stored would go with it.
        this.#say(
          `${unkeptFileWords(composer)}, so the draft was not moved. ${unkeptFileAdvice(composer)}, then move the draft.`
        )
        return
      }
      // What the composer holds is stored first, so that the move acts on all of it, and on the
      // record it is stored under now: a write can have made a copy of it since the press.
      if (composer && (await this.#write(composer.draftId)) === 'failed') {
        // eslint-disable-next-line @typescript-eslint/only-throw-error -- refused as a command's failure is: data
        throw this.#unsaved(composer.draftId)
      }
      const target = composer ? this.#find(composer.draftId)?.stored : await this.#shownOf(id, shown)
      if (target === undefined || target === null) return
      if (composer === undefined) this.#acting.add(target.id)
      let moved: StoredDraft
      try {
        moved = await this.#port.deviceDraftRetarget({
          id: target.id,
          expectedRevision: target.revision,
          sessionId,
          applicationInstanceId: null,
          agentBindingRevision: null
        })
        this.#moves += 1
      } catch (failure) {
        this.#actFailed(target.id)
        await this.#sawTheirs(composer?.draftId, failure)
        throw failure
      }
      if (composer) {
        const now = this.#find(composer.draftId)
        if (now !== undefined && writtenSince(composer, now)) {
          // Written in while the store was answering: the moved draft is what was pressed on, and
          // what was written since stays in the composer, as a draft of its own.
          this.#say('The composer keeps what you wrote while this was being done.')
          this.#letGo(composer.draftId)
        } else {
          this.#retire(now ?? composer)
          this.#drafts = this.#drafts.filter((draft) => draft.draftId !== composer.draftId)
          this.#tracks.delete(composer.draftId)
        }
      }
      // After the composer let go of it, so that no moment shows the draft twice.
      this.#actWorked(target.id, moved)
      await this.reload()
    }
    if (keyed !== undefined) await this.#enqueueAwait(keyed, run)
    else await run()
  }

  /**
   * Puts a kept draft in the composer of its own session; `shown` is as for [`discard`].
   *
   * The draft becomes an ordinary draft of the session: not a copy, and open. What the composer held
   * is stored first and stays a stored draft, listed with the kept drafts, so neither is lost to the
   * other. A person who writes in the composer while this is being done keeps what they wrote: the
   * kept draft is then listed, not put there.
   */
  async useHere(id: string, shown: string): Promise<void> {
    const sessionId = this.#others.find((other) => other.id === id)?.sessionId
    if (sessionId === undefined) return
    const key = composerKey(sessionId)
    await this.#enqueueAwait(key, async () => {
      const composer = this.#find(key)
      if (composer && holdsUnkeptFile(composer)) {
        // Putting the draft there takes the composer's place, and a file that is not stored cannot
        // be stored first, so it would be lost.
        this.#say(
          `${unkeptFileWords(composer)}, so the kept draft was not put there. It is still listed.`
        )
        return
      }
      // The composer as it is when this begins: anything written in it from here on is the person's
      // newest, and is not put over, whether it is written while the store answers this or the next.
      const edited = composer
      if (composer && !holdsNothing(composer) && (await this.#write(key)) === 'failed') {
        // eslint-disable-next-line @typescript-eslint/only-throw-error -- refused as a command's failure is: data
        throw this.#unsaved(key)
      }
      const target = await this.#shownOf(id, shown)
      if (target === undefined) return
      let moved: StoredDraft
      this.#acting.add(target.id)
      try {
        moved = await this.#port.deviceDraftRetarget({
          id: target.id,
          expectedRevision: target.revision,
          sessionId,
          applicationInstanceId: null,
          agentBindingRevision: null
        })
      } catch (failure) {
        this.#actFailed(target.id)
        await this.#sawTheirs(undefined, failure)
        throw failure
      }
      this.#moves += 1
      const now = this.#find(key)
      if ((now === undefined) !== (edited === undefined) || (now && edited && writtenSince(edited, now))) {
        // The composer changed while the store was answering. What is in it is the person's newest,
        // so the draft stays listed and is not put over it.
        this.#actWorked(target.id, moved)
        this.#say('You wrote in the composer meanwhile, so the kept draft was not put there. It is still listed.')
        await this.reload()
        return
      }
      this.#actWorked(target.id, null)
      if (now) this.#retire(now)
      const chosen = { ...draftOf(moved), revision: this.#above(key, (now?.revision ?? 0) + 1) }
      this.#drafts = now
        ? this.#drafts.map((draft) => (draft.draftId === key ? chosen : draft))
        : [...this.#drafts, chosen]
      this.#track(key).savedKey = contentKey(chosen)
      this.#changed()
      await this.reload()
    })
  }

  /**
   * An act on a listed draft ended without changing it: its row is back in the list.
   *
   * A row is out of the list only while an act works on it, and the act's end decides whether it
   * returns, so a failed read of the store cannot leave it hidden.
   */
  #actFailed(id: string): void {
    this.#acting.delete(id)
    this.#changed()
  }

  /**
   * An act on a listed draft changed it: `now` is what the store answered, or null when the draft
   * is gone from the list, and the list shows that without waiting for a read.
   */
  #actWorked(id: string, now: StoredDraft | null): void {
    this.#acting.delete(id)
    this.#others = [...this.#others.filter((other) => other.id !== id), ...(now === null ? [] : [now])]
    this.#changed()
  }

  /**
   * Refuses an act on a composer's draft when the composer is not the one the person pressed on.
   *
   * A composer put in place of another since (a kept draft put there) is a different draft from the
   * one the row showed, and an act on what it holds now would act on a draft the person did not
   * choose. The list is read again, so the person decides on what is there.
   */
  async #stillThere(key: string, pressed: Draft): Promise<void> {
    if ((this.#floor.get(key) ?? 0) < pressed.revision) return
    await this.reload()
    // eslint-disable-next-line @typescript-eslint/only-throw-error -- refused as a command's failure is: data
    throw {
      code: 'DRAFT_CONFLICT',
      message: 'The composer holds another draft now. The list is shown again; check it and try again.'
    }
  }

  /** The record a row showed, when it is still the one the store holds as far as this window knows. */
  async #shownOf(id: string, shown: string): Promise<StoredRef | undefined> {
    const other = this.#others.find((each) => each.id === id)
    if (other === undefined) return undefined
    if (other.revision !== shown) {
      await this.reload()
      // This window has read the store again since the row was shown: what the person pressed is
      // not what is stored now, and acting on what is stored now would act on something they did
      // not see.
      // eslint-disable-next-line @typescript-eslint/only-throw-error -- refused as a command's failure is: data
      throw {
        code: 'DRAFT_CONFLICT',
        message: 'The draft changed since it was shown. It is shown again; check it and try again.'
      }
    }
    return { id: other.id, revision: other.revision }
  }

  /** Notes the highest edit number a composer showed, so that none that replaces it repeats one. */
  #retire(draft: Draft): void {
    this.#floor.set(draft.draftId, Math.max(this.#floor.get(draft.draftId) ?? 0, draft.revision))
  }

  /** An edit number for a composer that takes the place of another: above every one it showed. */
  #above(key: string, wanted: number): number {
    return Math.max(wanted, (this.#floor.get(key) ?? 0) + 1)
  }

  /**
   * Notes that the store refused an act on a draft.
   *
   * The act is over and its row is back in the list. The list is read again, so the person decides on
   * what is stored now; and when the refusal says another window changed the draft since, a composer
   * that held the old version lets go of it and keeps its text as a draft of its own.
   */
  async #sawTheirs(composer: string | undefined, failure: unknown): Promise<void> {
    if (failureCode(failure) === 'DRAFT_CONFLICT' && composer !== undefined) this.#letGo(composer)
    await this.reload()
  }

  /** A composer lets go of the stored version it holds: its text is written as a draft of its own. */
  #letGo(key: string): void {
    this.#mutate(key, (draft) => ({ ...draft, stored: null }))
    this.#track(key).savedKey = null
    this.#schedule(key)
  }

  /** The failure to give for a draft the store would not take, when a move waits on it. */
  #unsaved(key: string): { readonly code: string; readonly message: string } {
    const failed = this.#failed.get(key)
    return {
      code: failed?.code ?? 'STORAGE_UNAVAILABLE',
      message: `What is in the composer could not be kept first, so nothing was moved: ${failed?.message ?? 'the store refused it'}`
    }
  }

  /** Writes whatever is not written yet, for a window that is about to be hidden or closed. */
  writeAll(): void {
    this.#scheduleAll()
    this.#hold(this.#settleAgain())
  }

  /** Resolves when every write that is on its way has ended. */
  async settled(): Promise<void> {
    if (this.#inflight === 0) return
    await new Promise<void>((resolve) => {
      this.#idle.push(resolve)
    })
  }

  // ----- the writer ---------------------------------------------------------------------------

  #track(key: string): Track {
    let track = this.#tracks.get(key)
    if (!track) {
      track = { savedKey: null, retargeting: false, chain: Promise.resolve() }
      this.#tracks.set(key, track)
    }
    return track
  }

  #find(key: string): Draft | undefined {
    return this.#drafts.find((draft) => draft.draftId === key)
  }

  /** Changes a draft the way the writer does: it announces the change and writes nothing for it. */
  #mutate(key: string, change: (draft: Draft) => Draft): void {
    const before = this.#drafts
    const after = before.map((draft) => (draft.draftId === key ? change(draft) : draft))
    if (after.every((draft, index) => draft === before[index])) return
    this.#drafts = after
    this.#changed()
  }

  /** Runs `task` after the draft's earlier writes, and counts it so that [`settled`] can wait. */
  #enqueue(key: string, task: () => Promise<void>): void {
    void this.#enqueueAwait(key, task)
  }

  #enqueueAwait(key: string, task: () => Promise<void>): Promise<void> {
    const track = this.#track(key)
    this.#inflight += 1
    const run = track.chain.then(task)
    track.chain = run
      .catch(() => undefined)
      .finally(() => {
        this.#leave()
      })
    return run
  }

  /** Counts work that runs beside the writes, so that [`settled`] waits for it too. */
  #hold(work: Promise<void>): void {
    this.#inflight += 1
    void work
      .catch(() => undefined)
      .finally(() => {
        this.#leave()
      })
  }

  #leave(): void {
    this.#inflight -= 1
    if (this.#inflight === 0) {
      const waiting = this.#idle
      this.#idle = []
      for (const resolve of waiting) resolve()
    }
  }

  #schedule(key: string): void {
    if (this.#status !== 'ready') return
    this.#enqueue(key, () => this.#save(key))
  }

  #scheduleAll(): void {
    for (const draft of this.#drafts) this.#schedule(draft.draftId)
  }

  /** Writes a composer's draft if it is not what the store holds, unless a retarget is on its way. */
  async #save(key: string): Promise<void> {
    if (this.#track(key).retargeting) return
    await this.#write(key)
  }

  /**
   * Writes a draft if it is not what the store holds, and says how that went.
   *
   * `draft` is the composer's draft as it is now, unless a caller gives another: the draft as it
   * stood when a prompt was sent is written to the record the composer holds, even though the
   * composer has moved on since.
   */
  async #write(key: string, given?: Draft, claim = false): Promise<Written> {
    if (this.#status !== 'ready') return 'unchanged'
    const track = this.#track(key)
    const draft = given ?? this.#find(key)
    if (draft === undefined) return 'unchanged'
    const wanted = contentKey(draft)
    // A claim is a write even when the store already holds what is written: the new version is
    // what another window's claim of the same one would find taken.
    if (!claim && wanted === track.savedKey) return 'unchanged'
    const stored = this.#find(key)?.stored ?? draft.stored
    if (holdsNothing(draft)) return await this.#removeStored(key, stored, wanted)
    let saved: DraftSaved
    try {
      saved = await this.#port.deviceDraftSave({
        id: stored?.id ?? null,
        expectedRevision: stored?.revision ?? null,
        sessionId: draft.target.sessionId,
        applicationInstanceId: draft.target.applicationInstanceId,
        agentBindingRevision: draft.target.agentBindingRevision,
        state: markOf(draft),
        text: draft.text,
        attachments: storable(draft)
      })
    } catch (failure) {
      this.#fail(key, failure)
      return 'failed'
    }
    track.savedKey = wanted
    this.#recovered(key)
    this.#mutate(key, (current) => ({
      ...current,
      stored: { id: saved.draft.id, revision: saved.draft.revision },
      // What the store holds can be stricter than what this window thought: another window may
      // have marked the draft, and it stays marked until a person retargets it.
      state: stricter(current.state, saved.draft.state)
    }))
    if (saved.outcome === 'copied') {
      // A claim that is lost says so once, in its own words.
      if (!claim) {
        this.#say(
          'Another window of this application changed that draft. What you wrote here is kept as a separate draft.'
        )
      }
      this.#hold(this.reload())
    }
    // A draft another window removed is made again under an identity of its own, which for a claim
    // says the same as a copy: that window sent it or discarded it, and this one is not to send it.
    const lost = saved.outcome === 'copied' || (stored !== null && saved.draft.id !== stored.id)
    return claim && lost ? 'lost' : 'stored'
  }

  async #removeStored(key: string, stored: Draft['stored'], wanted: string): Promise<Written> {
    const track = this.#track(key)
    if (stored === null) {
      // A composer that holds nothing has nothing to keep, and no failure to keep it is left.
      track.savedKey = wanted
      this.#recovered(key)
      return 'unchanged'
    }
    try {
      await this.#port.deviceDraftDiscard({ id: stored.id, expectedRevision: stored.revision })
      this.#moves += 1
    } catch (failure) {
      if (failureCode(failure) !== 'DRAFT_CONFLICT') {
        this.#fail(key, failure)
        return 'failed'
      }
      this.#moves += 1
      // Another window changed the draft since: it is theirs now, and this window lets go of it.
      this.#hold(this.reload())
    }
    track.savedKey = wanted
    this.#recovered(key)
    this.#mutate(key, (draft) => (draft.stored?.id === stored.id ? { ...draft, stored: null } : draft))
    return 'stored'
  }

  #fail(key: string, failure: unknown): void {
    this.#failed.set(key, {
      code: failureCode(failure) ?? 'STORAGE_UNAVAILABLE',
      message: failureMessage(failure)
    })
    this.#problem = failureMessage(failure)
    this.#changed()
  }

  #recovered(key: string): void {
    if (this.#unsettled.length > 0 || this.#cleanups.length > 0) this.#hold(this.#settleAgain())
    if (!this.#failed.delete(key)) return
    this.#recompute()
  }

  /** What the person is told is wrong with keeping drafts: the first failure, else a prompt not stored. */
  #recompute(): void {
    this.#problem =
      [...this.#failed.values()][0]?.message ??
      (this.#unsettled.length > 0
        ? 'The text of a prompt that was sent is held in this window only.'
        : null)
    this.#changed()
  }

  // ----- reading the store --------------------------------------------------------------------

  /**
   * Puts stored drafts in the composers that have nothing of their own, and the rest in the list of
   * kept drafts.
   *
   * A composer that holds something, or is tied to a stored draft, keeps its place. The draft a
   * session's composer takes is the newest one that is not a copy: a copy is another window's
   * or this one's second thought, and a person chooses it, it is never chosen for them.
   */
  #merge(list: readonly StoredDraft[]): void {
    // A record set apart for a prompt that has not ended is out of reach: no composer takes it and
    // no list shows it, until the prompt has ended and decided where its text goes.
    const composed = this.#drafts.flatMap((draft) => (draft.stored ? [draft.stored.id] : []))
    const held = new Set([...composed, ...this.#reserved(), ...this.#acting])
    const next = [...this.#drafts]
    const chosen = new Set<string>()
    const sessions = new Set(list.map((stored) => stored.sessionId))
    for (const sessionId of sessions) {
      const index = next.findIndex((draft) => draft.target.sessionId === sessionId)
      const mine = index === -1 ? undefined : next[index]
      if (mine !== undefined && !(isEmpty(mine) && mine.stored === null)) continue
      const pick = newest(
        list.filter(
          (stored) => stored.sessionId === sessionId && stored.copyOf === null && !held.has(stored.id)
        )
      )
      if (pick === undefined) continue
      if (mine) this.#retire(mine)
      const key = composerKey(sessionId)
      const draft = { ...draftOf(pick), revision: this.#above(key, (mine?.revision ?? 0) + 1) }
      if (index === -1) next.push(draft)
      else next[index] = draft
      chosen.add(pick.id)
      this.#track(draft.draftId).savedKey = contentKey(draft)
    }
    this.#drafts = next
    // A draft an act works on is kept in the list and left out of what the screen shows (`#keptList`)
    // until the act ends, so that the end of the act, not a read, decides whether it is shown.
    const apart = new Set([...composed, ...this.#reserved()])
    this.#others = list.filter((stored) => !apart.has(stored.id) && !chosen.has(stored.id))
  }

  /** The records set apart for prompts that have not ended or whose text is not stored yet. */
  #reserved(): readonly string[] {
    return [
      ...[...this.#flights.values(), ...this.#unsettled].flatMap((flight) => [
        ...(flight.record === null ? [] : [flight.record.id]),
        ...(flight.earlier === null ? [] : [flight.earlier.id])
      ]),
      ...this.#cleanups.map((cleanup) => cleanup.ref.id)
    ]
  }

  #keptList(): readonly KeptDraft[] {
    const why = (stored: StoredDraft): KeptWhy =>
      stored.copyOf !== null
        ? 'copy'
        : stored.state === 'orphaned'
          ? 'orphaned'
          : stored.state === 'conflicted'
            ? 'conflicted'
            : this.#sentRecords.has(stored.id)
              ? 'sent'
              : 'other'
    const apart = this.#others.filter((stored) => !this.#acting.has(stored.id)).map<KeptDraft>((stored) => ({
      id: stored.id,
      revision: stored.revision,
      sessionId: stored.sessionId,
      text: stored.text,
      files: stored.attachments.length,
      why: why(stored),
      updatedAtMs: Number(stored.updatedAtMs),
      inComposer: false
    }))
    const waiting = this.#drafts.flatMap<KeptDraft>((draft) =>
      draft.stored !== null && (draft.state === 'conflicted' || draft.state === 'orphaned')
        ? [
            {
              id: draft.stored.id,
              revision: draft.stored.revision,
              sessionId: draft.target.sessionId,
              text: draft.text,
              files: storable(draft).length,
              why: draft.state,
              updatedAtMs: draft.updatedAtMs,
              inComposer: true
            }
          ]
        : []
    )
    return [...waiting, ...apart].sort((a, b) => b.updatedAtMs - a.updatedAtMs)
  }

  #changed(): void {
    this.#cached = null
    for (const listener of this.#listeners) listener()
  }

  #say(words: string): void {
    for (const listener of this.#notices) listener(words)
  }
}

/** The stricter of two marks: a draft goes from open to conflicted to orphaned, and no other way. */
function stricter(current: Draft['state'], stored: StoredMark): Draft['state'] {
  if (stored === 'orphaned') return 'orphaned'
  if (stored === 'conflicted' && current !== 'orphaned') return 'conflicted'
  return current
}
