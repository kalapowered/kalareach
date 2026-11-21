/**
 * The files this window sends to a host the device is paired with, and where each stands.
 *
 * The application owns an upload between calls: it goes on when this window stops waiting, pauses
 * when the connection ends, resumes on the next one, and is named by the key the page chose. This
 * class is the page's view of that. It holds one row for each file, answers where it stands in
 * words (`lineOf`), reads the application's own account of the open uploads by asking again while
 * any is going, and finds the ones a restart left.
 *
 * A row's phase has two sources and never lets one overwrite the other. What the application says
 * of an upload that is still going (checking, sending, resuming, paused, waiting, finishing) comes
 * from asking it. What this window knows from its own calls (cancelling, cancelled, adding, bound,
 * kept, refused) is not changed by what the application says afterwards, because the application
 * has by then nothing to say of it.
 */

import type { AttachmentHandle, HandedFile, HostPort, OpenUpload, SessionSubject } from '../host/port'
import { describeBytes } from '../mobile/model/media'
import {
  PUBLISHED_AND_KEPT,
  refusalOf,
  sentence,
  type Refusal
} from './transfer-words'

/** Where one file stands. */
export type Phase =
  /** The file is being read, or the host is being asked to take it. */
  | { readonly kind: 'checking' }
  | { readonly kind: 'sending'; readonly done: number; readonly of: number }
  /** A connection was lost and the application is reading what the host holds. */
  | { readonly kind: 'resuming'; readonly done: number; readonly of: number }
  /** The connection ended; the upload goes on when the host is reached again. */
  | { readonly kind: 'paused'; readonly done: number; readonly of: number }
  /** Kept from before; the host has not been asked about it yet. */
  | { readonly kind: 'waiting' }
  /** Every chunk is held by the host and the handle is being published. */
  | { readonly kind: 'finishing' }
  /** The person cancelled; the host has not answered. */
  | { readonly kind: 'cancelling' }
  /** The host released the reservation, with the bytes it says. */
  | { readonly kind: 'cancelled'; readonly released: string | null }
  /** Sent in full and being added to the draft. */
  | { readonly kind: 'adding' }
  /** Sent in full and on the draft. */
  | { readonly kind: 'bound' }
  /** Sent in full, kept by the host, and not on the draft: `words` says why, or null for a file a restart found. */
  | { readonly kind: 'kept'; readonly words: string | null }
  /** Kept from before and cannot go on: the application's own words. */
  | { readonly kind: 'stuck'; readonly words: string }
  /** The host or the application refused it. */
  | { readonly kind: 'refused'; readonly refusal: Refusal }

export type PhaseKind = Phase['kind']

/** One file of this window, or one a restart found. */
export interface UploadRow {
  /** The key the application names the upload by, and the id of the file on the composer. */
  readonly key: string
  readonly sessionId: string | null
  readonly name: string
  readonly byteLen: number
  readonly phase: Phase
  readonly handle: AttachmentHandle | null
  /** A line under the state: a cancel that found the file sent in full. */
  readonly note: string | null
  /** Whether a call of this window waits for the upload's outcome. */
  readonly awaited: boolean
}

/** The phases the application's account decides. */
const DRIVEN: ReadonlySet<PhaseKind> = new Set([
  'checking',
  'sending',
  'resuming',
  'paused',
  'waiting',
  'finishing'
])

/** The phases in which the person may cancel. */
const CANCELLABLE: ReadonlySet<PhaseKind> = new Set([...DRIVEN, 'stuck'])

/** Whether a person may cancel a file in `phase`. */
export function canCancel(phase: Phase): boolean {
  return CANCELLABLE.has(phase.kind)
}

/** What a row says, how far it is, and how it reads. */
export interface Line {
  readonly text: string
  /** How much of the file the host holds, 0 to 1, or null where nothing is measured. */
  readonly progress: number | null
  readonly tone: 'plain' | 'warning' | 'danger' | 'done'
}

function share(done: number, of: number): number {
  return of > 0 ? Math.min(1, Math.max(0, done / of)) : 0
}

/** The words for a phase, and how far it is. */
export function lineOf(phase: Phase): Line {
  switch (phase.kind) {
    case 'checking':
      return { text: 'Checking with the host', progress: null, tone: 'plain' }
    case 'sending':
      return {
        text: `Sending, ${Math.floor(share(phase.done, phase.of) * 100)}%`,
        progress: share(phase.done, phase.of),
        tone: 'plain'
      }
    case 'resuming':
      return {
        text: `Resuming at chunk ${Math.min(phase.done + 1, Math.max(phase.of, 1))} of ${phase.of}`,
        progress: share(phase.done, phase.of),
        tone: 'plain'
      }
    case 'paused':
      return {
        text: 'Paused: the host is out of reach. Sending resumes when contact returns.',
        progress: share(phase.done, phase.of),
        tone: 'warning'
      }
    case 'waiting':
      return { text: 'Waiting for the host', progress: null, tone: 'plain' }
    case 'finishing':
      return { text: 'Finishing with the host', progress: 1, tone: 'plain' }
    case 'cancelling':
      return { text: 'Cancelling', progress: null, tone: 'plain' }
    case 'cancelled':
      return {
        text:
          phase.released === null
            ? 'Cancelled.'
            : `Cancelled. The host released ${describeBytes(Number(phase.released))}.`,
        progress: null,
        tone: 'plain'
      }
    case 'adding':
      return { text: 'Sent in full. Adding it to this draft', progress: 1, tone: 'plain' }
    case 'bound':
      return { text: 'Added to this draft', progress: null, tone: 'done' }
    case 'kept':
      return {
        text:
          phase.words === null
            ? 'Sent in full and kept by the host. Not added to a draft yet'
            : `Sent in full and kept by the host. It was not added to this draft: ${phase.words}`,
        progress: null,
        tone: 'warning'
      }
    case 'stuck':
      return { text: phase.words, progress: null, tone: 'danger' }
    case 'refused':
      return { text: phase.refusal.words, progress: null, tone: 'danger' }
  }
}

/** What the application's account of an upload says the row is, or null where it says nothing new. */
function phaseOf(view: OpenUpload): Phase {
  const done = view.acknowledgedChunks
  const of = view.chunks
  switch (view.state) {
    case 'sending':
      switch (view.stage) {
        case 'sending':
          return { kind: 'sending', done, of }
        case 'resuming':
          return { kind: 'resuming', done, of }
        case 'publishing':
        case 'published':
          return { kind: 'finishing' }
        default:
          return { kind: 'checking' }
      }
    case 'paused':
      return { kind: 'paused', done, of }
    case 'waiting':
      return { kind: 'waiting' }
    case 'published':
      return { kind: 'kept', words: null }
    case 'cannotResume':
    case 'unrecoverable':
    case 'failed':
      return { kind: 'stuck', words: sentence(view.said ?? '') }
  }
}

/** What to do to bind a published file to the draft: the composer's, since it knows the draft. */
export type Bind = (handle: AttachmentHandle) => Promise<void>

/** One file to send. */
export interface Sending {
  readonly key: string
  readonly sessionId: string
  readonly subject: SessionSubject
  readonly file: HandedFile
}

const DEFAULT_POLL_MS = 500

export class PairedUploads {
  readonly #port: HostPort
  readonly #pollMs: number
  readonly #rows = new Map<string, UploadRow>()
  readonly #listeners = new Set<() => void>()
  #cached: ReadonlyMap<string, UploadRow> | null = null
  #timer: ReturnType<typeof setInterval> | null = null
  #reading = false

  constructor(port: HostPort, pollMs = DEFAULT_POLL_MS) {
    this.#port = port
    this.#pollMs = pollMs
  }

  /** Calls `listener` when a row changes. */
  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  /** Every row by its key. The same object until something changes. */
  snapshot = (): ReadonlyMap<string, UploadRow> => {
    this.#cached ??= new Map(this.#rows)
    return this.#cached
  }

  /**
   * Sends a file and waits for its outcome: the handle once it is published, and then adds it to the
   * draft through `bind`. A file that is published and not added is still the file's outcome, and its
   * row says it was kept; the refusals of the upload itself reject.
   */
  send(input: Sending, bind: Bind): Promise<AttachmentHandle> {
    const { key, sessionId, subject, file } = input
    this.#put({
      key,
      sessionId,
      name: file.name,
      byteLen: file.bytes.length,
      phase: { kind: 'checking' },
      handle: null,
      note: null,
      awaited: true
    })
    this.#poll()
    return this.#port.attachmentUploadBytes(file, subject, key).then(
      async (handle) => {
        this.#patch(key, { handle, phase: { kind: 'adding' }, awaited: false })
        await this.#binding(key, handle, bind)
        return handle
      },
      async (failure: unknown) => {
        const refusal = refusalOf(failure)
        const phase = this.#rows.get(key)?.phase.kind
        // The person's own cancel has said what became of it.
        if (phase !== 'cancelling' && phase !== 'cancelled') {
          if (refusal.kind === 'cancelled') {
            this.#patch(key, { phase: { kind: 'cancelled', released: null }, awaited: false })
          } else {
            // A reservation the application still keeps stays on the screen with what the application
            // says of it, so that it can be cancelled; only an upload it keeps nothing of is refused.
            const kept = await this.#kept(key)
            this.#patch(
              key,
              kept === null
                ? { phase: { kind: 'refused', refusal }, awaited: false }
                : { phase: phaseOf(kept), handle: kept.handle ?? undefined, awaited: false }
            )
          }
        }
        throw failure
      }
    )
  }

  /** What the application keeps of the upload `key`, none when it keeps nothing. */
  async #kept(key: string): Promise<OpenUpload | null> {
    try {
      return (await this.#port.uploadsOpen()).find((view) => view.key === key) ?? null
    } catch {
      return null
    }
  }

  /** Adds a published file to the draft again, or for the first time after a restart. */
  async bind(key: string, handle: AttachmentHandle, bind: Bind): Promise<void> {
    this.#patch(key, { phase: { kind: 'adding' }, handle })
    await this.#binding(key, handle, bind)
  }

  async #binding(key: string, handle: AttachmentHandle, bind: Bind): Promise<void> {
    try {
      await bind(handle)
      this.#patch(key, { phase: { kind: 'bound' } })
    } catch (failure) {
      this.#patch(key, { phase: { kind: 'kept', words: refusalOf(failure).words } })
    }
  }

  /**
   * Cancels a file that has not been sent in full. The row says it is being cancelled until the host
   * answers, and says what was released only from that answer. A file the host already holds in full
   * is not cancelled: the row says so, and the file goes on to the draft.
   */
  async cancel(key: string): Promise<void> {
    const row = this.#rows.get(key)
    if (row === undefined || !canCancel(row.phase)) return
    const before = row.phase
    this.#patch(key, { phase: { kind: 'cancelling' }, note: null })
    try {
      const answer = await this.#port.uploadCancel(key)
      if (answer.state === 'published') {
        const handle = answer.handle ?? this.#rows.get(key)?.handle ?? null
        const waiting = this.#rows.get(key)?.awaited === true
        this.#patch(key, {
          handle,
          note: sentence(PUBLISHED_AND_KEPT),
          phase: waiting ? { kind: 'adding' } : { kind: 'kept', words: null }
        })
        return
      }
      this.#patch(key, {
        phase: {
          kind: 'cancelled',
          released: answer.state === 'cancelled' ? answer.releasedByteLen : null
        },
        awaited: false
      })
    } catch (failure) {
      // The upload goes on: the host was not asked, or did not answer.
      this.#patch(key, { phase: before, note: refusalOf(failure).words })
    }
  }

  /** Drops the row of a file that has left the composer. */
  forget(key: string): void {
    if (this.#rows.delete(key)) this.#changed()
  }

  /** Drops the rows of `sessionId` that are on the draft the prompt just sent. */
  forgetSent(sessionId: string): void {
    for (const [key, row] of this.#rows) {
      if (row.sessionId === sessionId && (row.phase.kind === 'bound' || row.phase.kind === 'adding')) {
        this.#rows.delete(key)
      }
    }
    this.#changed()
  }

  /** Reads the application's account once, adding the uploads this window did not start. */
  async restore(): Promise<void> {
    await this.#read()
    this.#poll()
  }

  /**
   * Notes the files the composer holds that this window has no row for: a draft read back after a
   * restart. `bound` says which of them the host's draft holds.
   */
  noteFiles(files: readonly { readonly row: UploadRow; readonly bound: boolean }[]): void {
    let changed = false
    for (const { row, bound } of files) {
      if (this.#rows.has(row.key)) continue
      this.#rows.set(row.key, { ...row, phase: bound ? { kind: 'bound' } : { kind: 'kept', words: null } })
      changed = true
    }
    if (changed) this.#changed()
  }

  /** The rows of `sessionId` that are not files on the composer: the ones a restart found. */
  found(sessionId: string, onComposer: ReadonlySet<string>): readonly UploadRow[] {
    return [...this.snapshot().values()].filter(
      (row) => row.sessionId === sessionId && !onComposer.has(row.key)
    )
  }

  #put(row: UploadRow): void {
    this.#rows.set(row.key, row)
    this.#changed()
  }

  #patch(key: string, change: Partial<UploadRow>): void {
    const row = this.#rows.get(key)
    if (row === undefined) return
    this.#rows.set(key, { ...row, ...change })
    this.#changed()
  }

  #changed(): void {
    this.#cached = null
    for (const listener of this.#listeners) listener()
    if (!this.#anyDriven() && this.#timer !== null) {
      clearInterval(this.#timer)
      this.#timer = null
    }
  }

  #anyDriven(): boolean {
    for (const row of this.#rows.values()) if (DRIVEN.has(row.phase.kind)) return true
    return false
  }

  /** Asks again every interval while any file is going. */
  #poll(): void {
    if (this.#timer !== null || !this.#anyDriven()) return
    this.#timer = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return
      void this.#read()
    }, this.#pollMs)
  }

  async #read(): Promise<void> {
    if (this.#reading) return
    this.#reading = true
    try {
      const views = await this.#port.uploadsOpen()
      let changed = false
      const set = (row: UploadRow): void => {
        const before = this.#rows.get(row.key)
        if (before === undefined || JSON.stringify(before) !== JSON.stringify(row)) {
          this.#rows.set(row.key, row)
          changed = true
        }
      }
      const seen = new Set<string>()
      for (const view of views) {
        seen.add(view.key)
        const row = this.#rows.get(view.key)
        if (row === undefined) {
          set({
            key: view.key,
            sessionId: view.sessionId,
            name: view.fileName,
            byteLen: view.byteLen,
            phase: phaseOf(view),
            handle: view.handle,
            note: null,
            awaited: false
          })
        } else if (
          DRIVEN.has(row.phase.kind) ||
          row.phase.kind === 'stuck' ||
          (!row.awaited && row.phase.kind === 'kept')
        ) {
          set({ ...row, phase: phaseOf(view), handle: view.handle ?? row.handle })
        }
      }
      // A file the application no longer lists, which no call of this window waits for, has ended.
      for (const [key, row] of this.#rows) {
        const going = DRIVEN.has(row.phase.kind) || row.phase.kind === 'stuck'
        if (!seen.has(key) && !row.awaited && going) {
          this.#rows.delete(key)
          changed = true
        }
      }
      if (changed) this.#changed()
    } catch {
      // Not in contact: the rows stay as they were, and the next interval asks again.
    } finally {
      this.#reading = false
    }
  }
}

/**
 * The transfers the draft this device keeps holds, as the application answers it: each attachment
 * carries the handle it was bound with, and the transfer is the handle's.
 */
export function boundIdsOf(view: unknown): ReadonlySet<string> {
  const attachments =
    (view as { attachments?: readonly { handle?: { transfer_id?: unknown } }[] } | null)?.attachments ?? []
  return new Set(
    attachments.flatMap((each) => (typeof each.handle?.transfer_id === 'string' ? [each.handle.transfer_id] : []))
  )
}
