/**
 * The drafts this device holds, and what keeps them.
 *
 * A draft is the person's own text, and it outlives everything else: the screen it was typed on, the
 * connection to the host, the application itself. So it is kept by native code on this device, and
 * this book is the page's side of that: it holds the draft each session's composer shows, writes
 * every change to the native store, and says plainly when it could not.
 *
 * Four rules decide how:
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

/** One draft in the list of kept drafts. */
export interface KeptDraft {
  /** Its identity in the store. */
  readonly id: string
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

/** What the book holds at one moment. */
export interface BookSnapshot {
  readonly status: BookStatus
  /** The draft each session's composer shows. At most one for a session. */
  readonly drafts: readonly Draft[]
  /** The stored drafts no composer shows. */
  readonly kept: readonly KeptDraft[]
  /** How many files in the store could not be read. They are left where they are. */
  readonly unreadable: number
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
  book: Pick<BookSnapshot, 'kept' | 'unreadable'>
): { readonly title: string; readonly label: string; readonly rest: string } | null {
  const count = book.kept.length
  if (count === 0) {
    return book.unreadable === 0
      ? null
      : { title: 'Some drafts could not be read', label: 'Some drafts', rest: 'could not be read.' }
  }
  const label = count === 1 ? 'One kept draft' : `${String(count)} kept drafts`
  return {
    title: label,
    label,
    rest: count === 1 ? 'is not in a composer.' : 'are not in a composer.'
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

/** A prompt on its way. */
export interface SendToken {
  readonly key: string
}

/** A prompt sent from a draft, from the press to the host's answer. */
interface Flight {
  /** The composer it was sent from. */
  readonly composer: string
  /** The draft as it stood when the person pressed Send. */
  readonly sent: Draft
  /** The stored draft that holds exactly that, once there is one. */
  record: StoredRef | null
}

/** How a write of a draft ended. */
type Written =
  /** The store holds the draft now. */
  | 'stored'
  /** There was nothing to write: the store already holds it, or the store is not open. */
  | 'unchanged'
  /** The store refused, and the draft is held in this window only. */
  | 'failed'

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

/** Whether two drafts hold the same files. */
function sameFiles(a: Draft, b: Draft): boolean {
  const ids = (draft: Draft) => storable(draft).map((handle) => handle.transfer_id)
  return JSON.stringify(ids(a)) === JSON.stringify(ids(b))
}

/** Whether the store has anything to keep of a draft. */
function holdsNothing(draft: Draft): boolean {
  return draft.text.length === 0 && storable(draft).length === 0
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
      this.#merge(stored.drafts)
      this.#status = 'ready'
      this.#problem = null
    } catch (failure) {
      this.#status = 'memory-only'
      this.#problem = failureMessage(failure)
    }
    this.#changed()
    if (this.#status === 'ready') this.#scheduleAll()
  }

  /** Reads the store again, keeping every composer that holds something. */
  async reload(): Promise<void> {
    if (this.#status !== 'ready') return
    try {
      const stored = await this.#port.deviceDrafts()
      this.#unreadable = stored.unreadable
      this.#merge(stored.drafts)
      this.#changed()
    } catch (failure) {
      this.#problem = failureMessage(failure)
      this.#changed()
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
    const fresh = startDraft(
      composerKey(sessionId),
      { sessionId, applicationInstanceId: null, agentBindingRevision: null },
      Date.now()
    )
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
    const after = change(before)
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
        void this.reload()
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
    const flight: Flight = { composer: key, sent, record: null }
    const token = `send-${String(this.#sends)}`
    this.#flights.set(token, flight)
    this.#enqueue(key, async () => {
      if (this.#status === 'ready' && !holdsNothing(sent)) {
        const written = await this.#write(key, sent)
        if (written !== 'failed') flight.record = this.#find(key)?.stored ?? null
      }
      // The composer lets go of the record: the next thing written is a draft of its own, and a
      // composer that still holds what was sent (a phone keeps it until the answer) needs no write.
      const now = this.#find(key)
      if (now === undefined) return
      this.#mutate(key, (draft) => ({ ...draft, stored: null }))
      this.#track(key).savedKey = contentKey(now) === contentKey(sent) ? contentKey(now) : null
    })
    return { key: token }
  }

  /** Says how a prompt that was sent from a draft ended. */
  endSend(token: SendToken, outcome: SendOutcome): void {
    const flight = this.#flights.get(token.key)
    if (flight === undefined) return
    this.#enqueue(flight.composer, async () => {
      this.#flights.delete(token.key)
      if (outcome === 'taken') {
        await this.#dropRecord(flight)
        return
      }
      await this.#giveBack(flight)
    })
  }

  /** Removes the stored draft of a prompt the host took, unless another window changed it since. */
  async #dropRecord(flight: Flight): Promise<void> {
    const record = flight.record
    if (record === null) return
    try {
      await this.#port.deviceDraftDiscard({ id: record.id, expectedRevision: record.revision })
    } catch (failure) {
      if (failureCode(failure) === 'DRAFT_CONFLICT') {
        // Another window changed it since: it is theirs now.
        void this.reload()
        return
      }
      this.#fail(flight.composer, failure)
    }
  }

  /**
   * Keeps the text of a prompt the host did not take.
   *
   * It goes back to the composer when the composer holds nothing, or holds exactly this text. When
   * the composer holds something else, the text of the prompt stays a stored draft of its own and is
   * listed with the kept drafts.
   */
  async #giveBack(flight: Flight): Promise<void> {
    const key = flight.composer
    const sent = flight.sent
    let record = flight.record
    if (record === null && this.#status === 'ready' && !holdsNothing(sent)) {
      // The first write failed, or the draft was never stored: try again now that the text matters.
      record = await this.#keepApart(key, sent)
    }
    const composer = this.#find(key)
    const same = composer !== undefined && composer.text === sent.text && sameFiles(composer, sent)
    if (composer === undefined || (composer.stored === null && (holdsNothing(composer) || same))) {
      this.#adopt(key, sent, composer, record)
      return
    }
    if (same) {
      // The screen put the text back and it was stored under the composer's own record: the one set
      // apart for the prompt says the same, and goes.
      if (record !== null) await this.#dropRecord({ ...flight, record })
      return
    }
    if (record === null) {
      this.#say('The prompt that was sent could not be kept apart from what you have written since.')
      return
    }
    this.#say(
      'The prompt that was sent is kept in Kept drafts, because you have written something new here since.'
    )
    await this.reload()
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

  /** Puts the text of a prompt back in a composer that holds nothing else, under its stored record. */
  #adopt(key: string, sent: Draft, composer: Draft | undefined, record: StoredRef | null): void {
    const base = composer ?? sent
    const back: Draft = {
      ...sent,
      draftId: key,
      revision: base.revision + 1,
      // A break in contact since the press is a fact about the connection, which the text keeps.
      state: composer?.state === 'detached' ? 'detached' : sent.state,
      updatedAtMs: Date.now(),
      stored: record
    }
    this.#drafts = this.#drafts.some((draft) => draft.draftId === key)
      ? this.#drafts.map((draft) => (draft.draftId === key ? back : draft))
      : [...this.#drafts, back]
    this.#track(key).savedKey = record === null ? null : contentKey(back)
    this.#changed()
    if (record === null) this.#schedule(key)
  }

  /** Removes a stored draft a person chose to throw away. */
  async discard(id: string): Promise<void> {
    const keyed = this.#drafts.find((draft) => draft.stored?.id === id)?.draftId
    const run = async (): Promise<void> => {
      const composer = this.#drafts.find((draft) => draft.stored?.id === id)
      const revision =
        composer?.stored?.revision ?? this.#others.find((other) => other.id === id)?.revision
      if (revision === undefined) return
      try {
        await this.#port.deviceDraftDiscard({ id, expectedRevision: revision })
      } catch (failure) {
        await this.#sawTheirs(composer?.draftId, failure)
        throw failure
      }
      if (composer) {
        this.#mutate(composer.draftId, (draft) => ({
          ...draft,
          text: '',
          attachments: [],
          stored: null,
          state: 'bound',
          target: { sessionId: draft.target.sessionId, applicationInstanceId: null, agentBindingRevision: null }
        }))
        this.#track(composer.draftId).savedKey = contentKey(this.#find(composer.draftId) ?? composer)
      }
      await this.reload()
    }
    if (keyed !== undefined) await this.#enqueueAwait(keyed, run)
    else await run()
  }

  /** Moves a stored draft to a session a person chose. */
  async moveTo(id: string, sessionId: string): Promise<void> {
    const keyed = this.#drafts.find((draft) => draft.stored?.id === id)?.draftId
    const run = async (): Promise<void> => {
      const composer = this.#drafts.find((draft) => draft.stored?.id === id)
      // What the composer holds is stored first, so that the move acts on all of it.
      if (composer && (await this.#write(composer.draftId)) === 'failed') {
        // eslint-disable-next-line @typescript-eslint/only-throw-error -- refused as a command's failure is: data
        throw this.#unsaved(composer.draftId)
      }
      const held = composer ? this.#find(composer.draftId)?.stored?.revision : undefined
      const revision = held ?? this.#others.find((other) => other.id === id)?.revision
      if (revision === undefined) return
      try {
        await this.#port.deviceDraftRetarget({
          id,
          expectedRevision: revision,
          sessionId,
          applicationInstanceId: null,
          agentBindingRevision: null
        })
      } catch (failure) {
        await this.#sawTheirs(composer?.draftId, failure)
        throw failure
      }
      if (composer) {
        this.#drafts = this.#drafts.filter((draft) => draft.draftId !== composer.draftId)
        this.#tracks.delete(composer.draftId)
      }
      await this.reload()
    }
    if (keyed !== undefined) await this.#enqueueAwait(keyed, run)
    else await run()
  }

  /**
   * Puts a kept draft in the composer of its own session.
   *
   * The draft becomes an ordinary draft of the session: not a copy, and open. What the composer held
   * is stored first and stays a stored draft, listed with the kept drafts, so neither is lost to the
   * other.
   */
  async useHere(id: string): Promise<void> {
    const sessionId = this.#others.find((other) => other.id === id)?.sessionId
    if (sessionId === undefined) return
    const key = composerKey(sessionId)
    await this.#enqueueAwait(key, async () => {
      const composer = this.#find(key)
      if (composer && !holdsNothing(composer) && (await this.#write(key)) === 'failed') {
        // eslint-disable-next-line @typescript-eslint/only-throw-error -- refused as a command's failure is: data
        throw this.#unsaved(key)
      }
      const other = this.#others.find((each) => each.id === id)
      if (other === undefined) return
      let moved: StoredDraft
      try {
        moved = await this.#port.deviceDraftRetarget({
          id,
          expectedRevision: other.revision,
          sessionId,
          applicationInstanceId: null,
          agentBindingRevision: null
        })
      } catch (failure) {
        await this.#sawTheirs(undefined, failure)
        throw failure
      }
      const chosen = draftOf(moved)
      this.#drafts = this.#drafts.some((draft) => draft.draftId === key)
        ? this.#drafts.map((draft) => (draft.draftId === key ? chosen : draft))
        : [...this.#drafts, chosen]
      this.#track(key).savedKey = contentKey(chosen)
      this.#changed()
      await this.reload()
    })
  }

  /**
   * Notes that the store refused an act on a draft because another window changed it since.
   *
   * The list is read again, so the person decides on what is stored now, and a composer that held
   * the old version lets go of it and keeps its text as a draft of its own.
   */
  async #sawTheirs(composer: string | undefined, failure: unknown): Promise<void> {
    if (failureCode(failure) !== 'DRAFT_CONFLICT') return
    if (composer !== undefined) this.#letGo(composer)
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
        this.#inflight -= 1
        if (this.#inflight === 0) {
          const waiting = this.#idle
          this.#idle = []
          for (const resolve of waiting) resolve()
        }
      })
    return run
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
  async #write(key: string, given?: Draft): Promise<Written> {
    if (this.#status !== 'ready') return 'unchanged'
    const track = this.#track(key)
    const draft = given ?? this.#find(key)
    if (draft === undefined) return 'unchanged'
    const wanted = contentKey(draft)
    if (wanted === track.savedKey) return 'unchanged'
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
      this.#say(
        'Another window of this application changed that draft. What you wrote here is kept as a separate draft.'
      )
      void this.reload()
    }
    return 'stored'
  }

  async #removeStored(key: string, stored: Draft['stored'], wanted: string): Promise<Written> {
    const track = this.#track(key)
    if (stored === null) {
      track.savedKey = wanted
      return 'unchanged'
    }
    try {
      await this.#port.deviceDraftDiscard({ id: stored.id, expectedRevision: stored.revision })
    } catch (failure) {
      if (failureCode(failure) !== 'DRAFT_CONFLICT') {
        this.#fail(key, failure)
        return 'failed'
      }
      // Another window changed the draft since: it is theirs now, and this window lets go of it.
      void this.reload()
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
    if (!this.#failed.delete(key)) return
    this.#problem = [...this.#failed.values()][0]?.message ?? null
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
    const held = new Set(this.#drafts.flatMap((draft) => (draft.stored ? [draft.stored.id] : [])))
    const next = [...this.#drafts]
    const chosen = new Set<string>()
    const sessions = new Set(list.map((stored) => stored.sessionId))
    for (const sessionId of sessions) {
      const index = next.findIndex((draft) => draft.target.sessionId === sessionId)
      const mine = index === -1 ? undefined : next[index]
      if (mine !== undefined && !(holdsNothing(mine) && mine.stored === null)) continue
      const pick = newest(
        list.filter(
          (stored) => stored.sessionId === sessionId && stored.copyOf === null && !held.has(stored.id)
        )
      )
      if (pick === undefined) continue
      const draft = draftOf(pick)
      if (index === -1) next.push(draft)
      else next[index] = draft
      chosen.add(pick.id)
      this.#track(draft.draftId).savedKey = contentKey(draft)
    }
    this.#drafts = next
    this.#others = list.filter((stored) => !held.has(stored.id) && !chosen.has(stored.id))
  }

  #keptList(): readonly KeptDraft[] {
    const why = (stored: StoredDraft): KeptWhy =>
      stored.copyOf !== null
        ? 'copy'
        : stored.state === 'orphaned'
          ? 'orphaned'
          : stored.state === 'conflicted'
            ? 'conflicted'
            : 'other'
    const apart = this.#others.map<KeptDraft>((stored) => ({
      id: stored.id,
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
