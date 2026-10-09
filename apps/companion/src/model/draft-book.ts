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
 * - **A draft that was sent is removed only once the host took it.** While a prompt is on its way the
 *   stored draft stays as it was. When the host took the prompt, it is removed (or replaced by
 *   what was typed since); when the host refused it or its outcome is unknown, it stays.
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
  type DraftTarget
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

/** How a prompt that was sent from a draft ended. */
export type SendOutcome =
  /** The host took it. */
  | 'taken'
  /** The host did not take it. */
  | 'refused'
  /** Nobody knows. */
  | 'unknown'

/** A prompt on its way, which holds the draft's writes until it ends. */
export interface SendToken {
  readonly key: string
}

/** What the writer knows of one draft. */
interface Track {
  /** The content the store holds, or is known to need no write for. */
  savedKey: string | null
  /** How many prompts sent from this draft have not ended. */
  holds: number
  /** True while a retarget the person chose is on its way. */
  retargeting: boolean
  /** The writes of this draft, one after another. */
  chain: Promise<void>
}

/** The files on a draft that a store can hold: completed uploads. */
function storable(draft: Draft): readonly AttachmentHandle[] {
  return draft.attachments.flatMap((file) =>
    file.upload === 'uploaded' && file.handle !== null ? [file.handle] : []
  )
}

/** The mark the store keeps for a draft: detachment is a fact about the connection, not the draft. */
function markOf(draft: Draft): StoredMark {
  return draft.state === 'conflicted' || draft.state === 'orphaned' ? draft.state : 'open'
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
  readonly #failed = new Map<string, string>()
  readonly #tracks = new Map<string, Track>()
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
   * draft goes back to what it was and the person is told.
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
        void this.reload()
      } finally {
        track.retargeting = false
        this.#schedule(before.draftId)
      }
    })
  }

  /**
   * Notes that a prompt is on its way from a session's draft.
   *
   * The stored draft is brought up to what is being sent, and then held as it is until
   * [`endSend`] says how the prompt ended. Call this before the composer is cleared.
   */
  beginSend(sessionId: string): SendToken {
    const draft = this.draft(sessionId)
    const track = this.#track(draft.draftId)
    track.holds += 1
    this.#enqueue(draft.draftId, () => this.#save(draft.draftId, draft))
    return { key: draft.draftId }
  }

  /** Says how a prompt that was sent from a draft ended. */
  endSend(token: SendToken, outcome: SendOutcome): void {
    const track = this.#track(token.key)
    this.#enqueue(token.key, async () => {
      track.holds = Math.max(0, track.holds - 1)
      if (track.holds > 0) return
      const draft = this.#find(token.key)
      if (draft === undefined) return
      if (outcome === 'unknown' && holdsNothing(draft)) {
        // The prompt may not have been sent, so what is stored stays. The next thing the person
        // writes replaces it.
        track.savedKey = contentKey(draft)
        return
      }
      if (outcome === 'taken' && holdsNothing(draft)) {
        track.savedKey = null
      }
      await this.#save(token.key)
    })
  }

  /** Removes a stored draft a person chose to throw away. */
  async discard(id: string): Promise<void> {
    const composer = this.#drafts.find((draft) => draft.stored?.id === id)
    const run = async (): Promise<void> => {
      const revision = composer?.stored?.revision ?? this.#others.find((other) => other.id === id)?.revision
      if (revision === undefined) return
      await this.#port.deviceDraftDiscard({ id, expectedRevision: revision })
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
    if (composer) await this.#enqueueAwait(composer.draftId, run)
    else await run()
  }

  /** Moves a stored draft to a session a person chose. */
  async moveTo(id: string, sessionId: string): Promise<void> {
    const composer = this.#drafts.find((draft) => draft.stored?.id === id)
    const run = async (): Promise<void> => {
      if (composer) await this.#save(composer.draftId)
      const revision =
        (composer ? this.#find(composer.draftId)?.stored?.revision : undefined) ??
        this.#others.find((other) => other.id === id)?.revision
      if (revision === undefined) return
      await this.#port.deviceDraftRetarget({
        id,
        expectedRevision: revision,
        sessionId,
        applicationInstanceId: null,
        agentBindingRevision: null
      })
      if (composer) {
        this.#drafts = this.#drafts.filter((draft) => draft.draftId !== composer.draftId)
        this.#tracks.delete(composer.draftId)
      }
      await this.reload()
    }
    if (composer) await this.#enqueueAwait(composer.draftId, run)
    else await run()
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
      track = { savedKey: null, holds: 0, retargeting: false, chain: Promise.resolve() }
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

  /**
   * Writes a draft if it is not what the store holds.
   *
   * `snapshot` is a draft as it stood when a prompt was sent from it: written even though the
   * prompt now holds the writes, because that is what the host was sent.
   */
  async #save(key: string, snapshot?: Draft): Promise<void> {
    if (this.#status !== 'ready') return
    const track = this.#track(key)
    const draft = snapshot ?? this.#find(key)
    if (draft === undefined) return
    if (snapshot === undefined && (track.holds > 0 || track.retargeting)) return
    const wanted = contentKey(draft)
    if (wanted === track.savedKey) return
    const stored = this.#find(key)?.stored ?? draft.stored
    if (holdsNothing(draft)) {
      await this.#removeStored(key, stored, wanted)
      return
    }
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
      return
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
  }

  async #removeStored(
    key: string,
    stored: Draft['stored'],
    wanted: string
  ): Promise<void> {
    const track = this.#track(key)
    if (stored === null) {
      track.savedKey = wanted
      return
    }
    try {
      await this.#port.deviceDraftDiscard({ id: stored.id, expectedRevision: stored.revision })
    } catch (failure) {
      if (failureCode(failure) !== 'DRAFT_CONFLICT') {
        this.#fail(key, failure)
        return
      }
      // Another window changed the draft since: it is theirs now, and this window lets go of it.
      void this.reload()
    }
    track.savedKey = wanted
    this.#recovered(key)
    this.#mutate(key, (draft) => (draft.stored?.id === stored.id ? { ...draft, stored: null } : draft))
  }

  #fail(key: string, failure: unknown): void {
    this.#failed.set(key, failureMessage(failure))
    this.#problem = failureMessage(failure)
    this.#changed()
  }

  #recovered(key: string): void {
    if (!this.#failed.delete(key)) return
    this.#problem = [...this.#failed.values()][0] ?? null
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
      updatedAtMs: Number(stored.updatedAtMs)
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
              updatedAtMs: draft.updatedAtMs
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
