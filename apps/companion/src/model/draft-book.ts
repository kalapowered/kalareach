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
   * rejection is a command's failure, with the code `DRAFT_CONFLICT`. It settles with the identity
   * of the stored draft the prompt was sent from, or null when the store holds none for it.
   */
  readonly claimed: Promise<string | null>
}

/** What a phone keeps of a prompt an earlier run sent, so that a later run can find the draft that holds its text. */
export interface EarlierPrompt {
  readonly sessionId: string
  readonly text: string
  /** The stored draft the prompt was sent from. */
  readonly storedDraftId?: string
  /** The conversation it was sent to. */
  readonly sentTo?: { readonly applicationInstanceId: string | null; readonly agentBindingRevision: string | null }
}

/** A prompt sent from a draft, from the press to the host's answer. */
interface Flight {
  /** Its name among the prompts that have not ended. */
  readonly id: string
  /** The composer it was sent from. */
  readonly composer: string
  /** Its number among the sends of this window: 0 for a prompt of an earlier run. */
  readonly order: number
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
  /**
   * True once the prompt's text has been put in the list of kept drafts, where its record is no
   * longer set apart. The prompt has not ended until its end is made, and a report of what became
   * of it in the meantime is dealt with after that.
   */
  apart?: boolean
  /**
   * The older version the prompt grew from, when the store would never take the prompt itself: it
   * stays stored, listed, because nothing stands for the prompt's text. It goes if the prompt is
   * then said to have been applied.
   */
  older?: StoredRef
  /** True once the prompt was said to have been applied after nobody knew: nothing of it is to be stored. */
  consumed?: boolean
  /**
   * True for a prompt of an earlier run, known by the stored draft it was sent from and by nothing
   * else: a composer is cleared only when it holds that draft.
   */
  keyed?: boolean
  /** Told the stored draft that holds the prompt's text, when the prompt has ended and each time that changes. */
  onEnded?: (storedDraftId: string | null) => void
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

/**
 * Whether a composer holds the text of a prompt that was sent, and every file that went with it.
 * Files it holds besides are the person's, whatever state their uploads are in.
 */
function holdsTextSent(composer: Draft | undefined, sent: Draft): boolean {
  if (composer === undefined || composer.text !== sent.text) return false
  // A draft the person has since sent to another conversation is theirs, whatever its words.
  if (
    composer.target.applicationInstanceId !== sent.target.applicationInstanceId ||
    composer.target.agentBindingRevision !== sent.target.agentBindingRevision
  ) {
    return false
  }
  const held = new Set(storable(composer).map((handle) => handle.transfer_id))
  return storable(sent).every((handle) => held.has(handle.transfer_id))
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
  /** The read of the store that [`hydrate`] is making, while it is. */
  #hydrating: Promise<void> | null = null
  /** The failure to open the store, kept while the store is not open. */
  #openFailure: string | null = null
  /** The prompts a recovery is storing the text of right now: their records are set apart until it has decided. */
  readonly #storing = new Set<Flight>()
  /** Prompts of earlier runs that were said to have been applied before the store was read. */
  #earlier: (EarlierPrompt & {
    localId: string
    storedDraftId: string
    /** The sends of this window made when the host's word came: the ones it reaches. */
    upTo: number
    /** The prompts of this window that held the draft while the report waited, which can move its text. */
    held?: Flight[]
  })[] = []

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
  hydrate(): Promise<void> {
    // A second press of "try again" while the store is being read waits for that read: two answers
    // merged one after the other would give a composer a draft the first one's cleanup had removed.
    this.#hydrating ??= this.#hydrate().finally(() => {
      this.#hydrating = null
    })
    return this.#hydrating
  }

  async #hydrate(): Promise<void> {
    try {
      const stored = await this.#port.deviceDrafts()
      this.#unreadable = stored.unreadable
      // Before the drafts are read into composers: a record owed for removal is no draft's.
      this.#oweFrom(stored.pendingRemovals)
      this.#merge(stored.drafts)
      this.#status = 'ready'
      this.#problem = null
      this.#openFailure = null
    } catch (failure) {
      this.#status = 'memory-only'
      this.#problem = failureMessage(failure)
      this.#openFailure = this.#problem
    }
    this.#changed()
    if (this.#status === 'ready') {
      this.#scheduleAll()
      this.#hold(this.#settleAgain())
      this.#settleEarlier()
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
    const flight: Flight = { id: token, composer: key, order: this.#sends, sent, record: null, earlier: null }
    this.#flights.set(token, flight)
    let claim: { resolve: (stored: string | null) => void; reject: (failure: unknown) => void } = {
      resolve: () => undefined,
      reject: () => undefined
    }
    const claimed = new Promise<string | null>((resolve, reject) => {
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
          claim.resolve(flight.record?.id ?? null)
        }
      } else {
        claim.resolve(null)
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
  holdSend(
    token: Pick<SendToken, 'key'>,
    localId: string,
    ended?: (storedDraftId: string | null) => void
  ): void {
    this.#byLocal.set(localId, token.key)
    const flight = this.#flights.get(token.key)
    if (flight !== undefined && ended !== undefined) flight.onEnded = ended
  }

  /**
   * Says what a submission came to, for the prompt it carries.
   *
   * A prompt still open ends as the state says. A prompt that ended as of unknown outcome and is
   * then said to have been applied loses its stored draft after all, and the composer that shows
   * exactly its text is cleared; one that is said to be refused is as it was, kept.
   *
   * A submission this book knows nothing of was sent by an earlier run of the application, which a
   * phone keeps the unresolved submissions of. `earlier` names its session, its text, the stored
   * draft it was sent from and the conversation it was sent to: when it is said to have been applied,
   * that draft goes as above, if it still holds exactly that text for that conversation.
   */
  sendSettled(localId: string, state: InputState, earlier?: EarlierPrompt): void {
    const outcome = sendOutcomeOf(state)
    const key = this.#byLocal.get(localId)
    if (outcome === null) return
    if (key === undefined) {
      if (outcome === 'taken' && earlier !== undefined) this.#takenEarlier(localId, earlier)
      return
    }
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
    // The sends the host's word reaches are the ones made by now, not the ones made while it waits
    // for its turn in the composer's queue.
    const upTo = this.#sends
    this.#enqueue(ended.composer, async () => {
      this.#unknowns.delete(key)
      if (outcome === 'taken') await this.#takenLate(ended, upTo)
    })
  }

  /**
   * What the host's saying that a prompt of an earlier run was applied leaves behind: the stored
   * draft the prompt was sent from, if it still holds exactly the prompt's text, wherever it is by
   * now: in a composer, or listed apart. A draft that is another one, whatever its words, is the
   * person's. It waits until the store has been read, however long that takes.
   */
  #takenEarlier(localId: string, earlier: EarlierPrompt): void {
    // A prompt the store held no draft for left nothing to come back.
    if (earlier.storedDraftId === undefined || earlier.text === '') return
    if (this.#earlier.some((each) => each.localId === localId)) return
    this.#earlier.push({ ...earlier, localId, storedDraftId: earlier.storedDraftId, upTo: this.#sends })
    this.#settleEarlier()
  }

  /** Makes the late end of every prompt of an earlier run that is waiting, once the store has been read. */
  #settleEarlier(): void {
    if (this.#status !== 'ready') return
    const waiting = this.#earlier
    this.#earlier = []
    for (const each of waiting) {
      const key = composerKey(each.sessionId)
      this.#enqueue(key, async () => {
        const composer = this.#find(key)
        // The conversation it was sent to: a draft the person has since sent to another one is theirs.
        const there = (instance: string | null, binding: string | null): boolean =>
          each.sentTo === undefined ||
          (each.sentTo.applicationInstanceId === instance && each.sentTo.agentBindingRevision === binding)
        // The draft the prompt was sent from, and the drafts that the prompts of this window which held
        // it have put its text in since: the text moves when such a prompt ends.
        const names = [each.storedDraftId]
        for (const holder of each.held ?? []) {
          const name = this.#holding(holder)
          if (name !== null && !names.includes(name)) names.push(name)
        }
        let record: StoredRef | null = null
        let listedAs: StoredDraft | undefined
        for (const name of names) {
          if (
            composer?.stored?.id === name &&
            composer.text === each.text &&
            there(composer.target.applicationInstanceId, composer.target.agentBindingRevision)
          ) {
            record = composer.stored
            break
          }
          const listed = this.#others.find((other) => other.id === name)
          if (
            listed !== undefined &&
            listed.sessionId === each.sessionId &&
            listed.text === each.text &&
            there(listed.applicationInstanceId, listed.agentBindingRevision)
          ) {
            record = { id: listed.id, revision: listed.revision }
            listedAs = listed
            break
          }
        }
        if (record === null) {
          // A send of this window that holds the draft decides it when it ends: this waits for that,
          // and then looks for the text where that send put it.
          const pending = (flight: Flight): boolean =>
            this.#flights.has(flight.id) || this.#unsettled.includes(flight) || this.#storing.has(flight)
          const holders = [...this.#flights.values(), ...this.#unsettled, ...this.#storing].filter(
            (flight) => flight.record?.id === each.storedDraftId || flight.earlier?.id === each.storedDraftId
          )
          if (holders.length > 0 || (each.held ?? []).some(pending)) {
            this.#earlier.push({ ...each, held: [...new Set([...(each.held ?? []), ...holders])] })
          }
          return
        }
        const target = composer?.stored?.id === record.id
          ? composer.target
          : {
              sessionId: each.sessionId,
              applicationInstanceId: listedAs?.applicationInstanceId ?? null,
              agentBindingRevision: listedAs?.agentBindingRevision ?? null
            }
        const sent: Draft = { ...startDraft(key, target, Date.now()), text: each.text }
        await this.#takenLate(
          { id: `earlier-${each.localId}`, composer: key, order: 0, sent, record, earlier: null, keyed: true },
          each.upTo
        )
      })
    }
  }

  /**
   * What a prompt that is said to have been applied, after nobody knew, leaves behind: nothing.
   *
   * It does for the text what the end of a taken prompt does, wherever the text is by now: in the
   * composer, kept apart in the store and listed, or held in this window only because the store
   * would not take it. What the person wrote since, and what another window made of the record, are
   * not the prompt's and stay. It runs in the composer's own turn, so it waits on nothing that has a
   * turn of its own.
   */
  async #takenLate(flight: Flight, upTo: number): Promise<void> {
    // The same words sent again from this composer to this conversation, by a person who checked,
    // were done by this prompt. They are the sends that were made when the host's word came, chosen
    // before anything waits: a send made after it is the person's own. A prompt whose words were
    // already done by another does not make more of them done.
    const done = flight.consumed === true
    const same = done ? [] : this.#sameWords(flight, upTo)
    // A recovery that is storing the prompt's text meanwhile finds this and removes what it made.
    flight.consumed = true
    for (const other of same) other.consumed = true
    const composer = this.#find(flight.composer)
    // What the composer holds when a prompt that was already done is said to be applied was written
    // since, whatever its words: only what the prompt itself kept is removed.
    const cleared =
      !done &&
      composer !== undefined &&
      holdsTextSent(composer, flight.sent) &&
      (flight.keyed !== true || composer.stored?.id === flight.record?.id)
        ? await this.#clearSentFrom(composer, flight)
        : null
    await this.#dropKept(flight, cleared)
    await this.#dropEarlier(flight)
    await this.#dropOlder(flight)
    // Whatever the host says of those, their text is not given back for a third send, and what they
    // were holding is not kept.
    for (const other of same) await this.#endConsumed(other)
    // The text is not to be stored after all, nor listed for a person to copy.
    this.#unsettled = this.#unsettled.filter((each) => each !== flight)
    this.#unstored = this.#unstored.filter((each) => each !== flight)
    this.#clearFailure(flight.id)
    await this.reload()
  }

  /**
   * Removes the record under a composer that still holds exactly the text a prompt took, and clears
   * the text, whatever record the composer holds: the one the prompt was set apart under, a copy of
   * it, or none because the store would not take it.
   *
   * A record the store would not remove stays owed, at the version it was asked to remove. What the
   * person wrote in the composer while the store was answering, and every file they added since, are
   * theirs and stay: a prompt carries no file, so a file on the composer is never what was sent. A
   * file the store keeps stays with the composer's own record, and the text goes from it by a write.
   * Answers the record it removed or kept, if any.
   */
  async #clearSentFrom(composer: Draft, flight: Flight): Promise<string | null> {
    const key = composer.draftId
    const stored = composer.stored
    const sentFiles = new Set(storable(flight.sent).map((handle) => handle.transfer_id))
    const theirs = composer.attachments.filter(
      (file) => !(file.handle !== null && file.upload === 'uploaded' && sentFiles.has(file.handle.transfer_id))
    )
    if (theirs.some((file) => file.upload === 'uploaded' && file.handle !== null)) {
      this.#retire(composer)
      this.#mutate(key, (draft) => ({ ...draft, revision: draft.revision + 1, text: '', attachments: theirs }))
      this.#track(key).savedKey = null
      this.#schedule(key)
      this.#clearFailure(key)
      return stored?.id ?? null
    }
    if (stored !== null && !(await this.#dropRecord(stored, flight.id))) this.#owe(stored, flight.id)
    const now = this.#find(key)
    // What the person typed while the store was answering is theirs. An upload that went on or ended
    // meanwhile is not the person writing: the files are taken as they are now.
    if (now !== undefined && (now.text !== composer.text || now.revision !== composer.revision)) {
      this.#say('The composer keeps what you wrote while this was being done.')
      this.#letGo(key)
      return stored?.id ?? null
    }
    this.#retire(now ?? composer)
    let kept = false
    this.#mutate(key, (draft) => {
      // A file the person added since the press is theirs, finished or not.
      const files = draft.attachments.filter(
        (file) => !(file.handle !== null && file.upload === 'uploaded' && sentFiles.has(file.handle.transfer_id))
      )
      kept = files.some((file) => file.upload === 'uploaded' && file.handle !== null)
      return {
        ...draft,
        revision: draft.revision + 1,
        text: '',
        attachments: files,
        stored: null,
        state: 'bound',
        target: { sessionId: draft.target.sessionId, applicationInstanceId: null, agentBindingRevision: null }
      }
    })
    // A file that finished meanwhile has no record to stay in now, and is stored by a write.
    this.#track(key).savedKey = kept ? null : contentKey(this.#find(key) ?? composer)
    if (kept) this.#schedule(key)
    // A failure kept for this composer's text is over: there is nothing left to keep.
    this.#clearFailure(key)
    return stored?.id ?? null
  }

  /**
   * Removes the record a prompt was set apart under, when no composer holds it and it still holds
   * exactly the prompt.
   *
   * A record the list shows is removed at the version the list shows, when its text and files are
   * the prompt's: another window may have put it in its composer and changed it, and then it is
   * theirs. A record the list does not show, because the prompt's text could not be put away, is
   * removed at the version the prompt was stored at, which no change has moved if it is still there.
   * `handled` is a record already removed with the composer's text.
   */
  async #dropKept(flight: Flight, handled: string | null): Promise<void> {
    const record = flight.record
    if (record === null || record.id === handled) return
    const composer = this.#find(flight.composer)
    // A composer that holds it keeps it: the person has written in it since.
    if (composer?.stored?.id === record.id) return
    const listed = this.#others.find((other) => other.id === record.id)
    let ref: StoredRef | null = record
    if (listed !== undefined) {
      const files = (handles: readonly AttachmentHandle[]) => handles.map((handle) => handle.transfer_id).join(' ')
      // Another window may have put it in its composer and changed it, and the person may have moved
      // it to another session: either way it is not the prompt that was sent from this composer.
      const sameText =
        listed.sessionId === flight.sent.target.sessionId &&
        listed.applicationInstanceId === flight.sent.target.applicationInstanceId &&
        listed.agentBindingRevision === flight.sent.target.agentBindingRevision &&
        listed.text === flight.sent.text &&
        files(listed.attachments) === files(storable(flight.sent))
      ref = sameText ? { id: listed.id, revision: listed.revision } : null
    }
    if (ref === null) return
    this.#sentRecords.delete(ref.id)
    if (!(await this.#dropRecord(ref, flight.id))) this.#owe(ref, flight.id)
  }

  /**
   * The other prompts of a composer that carry exactly the words of `flight`, sent to the same
   * conversation, among the first `upTo` sends of this window.
   */
  #sameWords(flight: Flight, upTo: number): Flight[] {
    const files = (draft: Draft): string => storable(draft).map((handle) => handle.transfer_id).join(' ')
    const target = flight.sent.target
    return [...this.#flights.values(), ...this.#unknowns.values(), ...this.#unsettled].filter(
      (other) =>
        other !== flight &&
        other.order <= upTo &&
        other.composer === flight.composer &&
        other.sent.text === flight.sent.text &&
        files(other.sent) === files(flight.sent) &&
        other.sent.target.applicationInstanceId === target.applicationInstanceId &&
        other.sent.target.agentBindingRevision === target.agentBindingRevision
    )
  }

  /**
   * Ends what a prompt whose words were done by another was holding while it waited, wherever that
   * is: its text held in this window only, with its failure, and the records it set apart or kept.
   * A prompt still on its way ends as a taken one when it ends, and a recovery that is storing it
   * ends it when it sees the mark.
   */
  async #endConsumed(flight: Flight): Promise<void> {
    if (this.#flights.has(flight.id) || this.#storing.has(flight)) return
    this.#unsettled = this.#unsettled.filter((each) => each !== flight)
    if (this.#unstored.includes(flight)) {
      this.#unstored = this.#unstored.filter((each) => each !== flight)
      this.#changed()
    }
    this.#clearFailure(flight.id)
    await this.#dropKept(flight, null)
    await this.#dropEarlier(flight)
    await this.#dropOlder(flight)
  }

  /**
   * Whether the words of a prompt that is on its way, or whose outcome nobody knows, were done by
   * another prompt: a send names its prompt by its token, a submission by its local identity.
   */
  textConsumed(prompt: { readonly key: string } | { readonly localId: string }): boolean {
    const key = 'key' in prompt ? prompt.key : this.#byLocal.get(prompt.localId)
    if (key === undefined) return false
    const flight = this.#flights.get(key) ?? this.#unknowns.get(key)
    return flight?.consumed === true
  }

  /** Whether a prompt was said to have been applied: read again after each wait, as it can change in one. */
  #consumed(flight: Flight): boolean {
    return flight.consumed === true
  }

  /** Removes the older version a prompt grew from, which stayed stored because the prompt itself could not be. */
  async #dropOlder(flight: Flight): Promise<void> {
    const older = flight.older
    if (older === undefined) return
    delete flight.older
    // A composer that took it is the person's: it is theirs now, and it stays.
    if (this.#drafts.some((draft) => draft.stored?.id === older.id)) return
    if (!(await this.#dropRecord(older, flight.id))) this.#owe(older, flight.id)
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

  /**
   * Says how a prompt that was sent from a draft ended; `localId` names its submission, when it has
   * one. Once the end is made, `ended` is told the identity of the stored draft that holds the
   * prompt's text (a text the store would not take at the press can be stored by the end), or null
   * when none does.
   */
  endSend(
    token: Pick<SendToken, 'key'>,
    outcome: SendOutcome,
    localId?: string,
    ended?: (storedDraftId: string | null) => void
  ): void {
    const flight = this.#flights.get(token.key)
    if (flight === undefined || flight.endedAs !== undefined) return
    flight.endedAs = outcome
    if (ended !== undefined) flight.onEnded = ended
    if (localId !== undefined && outcome === 'unknown') this.#byLocal.set(localId, flight.id)
    else if (localId !== undefined) this.#byLocal.delete(localId)
    this.#enqueue(flight.composer, async () => {
      try {
        // Words that another prompt was applied for are done, whatever became of this one. Its
        // outcome may still be unknown, and the book goes on answering for it until the host says.
        if (outcome === 'taken' || flight.consumed === true) {
          await this.#dropSent(flight)
          await this.#dropEarlier(flight)
          if (outcome === 'unknown' && localId !== undefined) this.#unknowns.set(flight.id, flight)
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
        flight.onEnded?.(outcome === 'taken' || flight.consumed === true ? null : this.#holding(flight))
        // A prompt of an earlier run that this one held the draft of is settled now.
        if (this.#earlier.length > 0) this.#settleEarlier()
      }
    })
  }

  /** The stored draft that holds a prompt's text now: its own record, or the composer's when the words were put back there. */
  #holding(flight: Flight): string | null {
    if (flight.record !== null) return flight.record.id
    const composer = this.#find(flight.composer)
    return holdsTextSent(composer, flight.sent) ? (composer?.stored?.id ?? null) : null
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
      // It is gone, so the list does not show it, whether or not the store can be read again.
      const listed = this.#others.filter((other) => other.id !== record.id)
      if (listed.length !== this.#others.length) {
        this.#others = listed
        this.#changed()
      }
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
      if (record !== null && composer.stored?.id !== record.id) {
        await this.#dropSent({ ...flight, record })
        // What holds the text now is the composer's own record.
        flight.record = composer.stored
      }
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
      'The prompt is kept in Kept drafts, because you have written something new here since.'
    )
    // Its text is decided: the older version goes and the record is no longer set apart, so that
    // the list shows it.
    this.#clearFailure(flight.id)
    await this.#dropEarlier(flight)
    flight.apart = true
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
    if (flight.earlier !== null) flight.older = flight.earlier
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
        if (this.#consumed(flight)) continue
        this.#storing.add(flight)
        const stored = await this.#storeSent(flight)
        if (this.#consumed(flight)) {
          // The host said the prompt was applied while the store was answering: nothing it holds is
          // kept, whether or not the store took the text now. Its records stay set apart until they
          // are gone, so no read hands them to a composer.
          this.#clearFailure(flight.id)
          await this.#dropSent(flight)
          await this.#dropEarlier(flight)
          this.#storing.delete(flight)
          this.#unsettled = this.#unsettled.filter((each) => each !== flight)
          await this.reload()
          continue
        }
        this.#storing.delete(flight)
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
        flight.onEnded?.(this.#consumed(flight) ? null : stored.id)
        await this.reload()
      }
    } finally {
      this.#settling = false
      // A run makes one prompt's store at a time and ends them all, whatever ended it.
      this.#storing.clear()
    }
    // A prompt of an earlier run that waited for the draft of a prompt stored now is settled.
    if (this.#earlier.length > 0) this.#settleEarlier()
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
      (this.#status === 'memory-only' ? this.#openFailure : null) ??
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
      // While a recovery is storing the text of a prompt, the record it makes is not known yet, so
      // no composer takes a draft from a read: the next read, once it has decided, does.
      if (this.#storing.size > 0) break
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
      ...[...this.#flights.values(), ...this.#unsettled, ...this.#storing]
        .filter((flight) => flight.apart !== true)
        .flatMap((flight) => [
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
