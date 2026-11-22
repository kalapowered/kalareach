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
  CANCELLED_BEFORE_SENT,
  PUBLISHED_AND_KEPT,
  isNoOpenUpload,
  refusalOf,
  sentence,
  wordsOf,
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
  /** The person cancelled and the application kept the cancel: it is finished when the host can be reached. */
  | { readonly kind: 'cancelAsked'; readonly said: string | null }
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
  /**
   * The upload was refused and the application's list could not be read afterwards, so whether it
   * still holds the upload is not known: the next read of the list settles it.
   */
  readonly unread?: boolean
}

/** What the read of one upload's account answers when the application's list could not be read. */
const UNREAD = Symbol('unread')

/** The phases the application's account decides. */
const DRIVEN: ReadonlySet<PhaseKind> = new Set([
  'checking',
  'sending',
  'resuming',
  'paused',
  'waiting',
  'finishing',
  'cancelAsked'
])

/** The phases in which the person may cancel: a cancel asked is cancelled already. */
const CANCELLABLE: ReadonlySet<PhaseKind> = new Set<PhaseKind>(
  [...DRIVEN, 'stuck' as const].filter((kind) => kind !== 'cancelAsked')
)

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
    case 'cancelAsked':
      return {
        text: 'Cancel asked: no more of this file is sent, and the cancel is finished when the host can be reached.',
        progress: null,
        tone: 'warning'
      }
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
    case 'cancelAsked':
      return { kind: 'cancelAsked', said: null }
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

/**
 * What a call of an earlier cycle ends with: the store was reset after the call began, so what it
 * would have done is no longer wanted. It is not a refusal and is never announced.
 */
export class ResetError extends Error {
  constructor() {
    super('the files of this window were cleared')
    this.name = 'ResetError'
  }
}

/** Whether `failure` is the end of a call that the store's reset made unwanted. */
export function isReset(failure: unknown): boolean {
  return failure instanceof ResetError
}

/** What a screen gives the store to reconcile a session: reading the kept draft, and showing what it holds. */
export interface Reconciler<Read = unknown> {
  /** Reads the draft the device keeps for the session. A read that fails leaves the session not ready. */
  readonly read: () => Promise<Read>
  /** Shows what the read found, in one synchronous step: the files of the kept draft that have no card. */
  readonly apply: (found: Read) => void
}

interface Reconciliation {
  readonly cycle: number
  readonly state: 'pending' | 'done' | 'failed'
  readonly failure?: unknown
}

export class PairedUploads {
  readonly #port: HostPort
  readonly #pollMs: number
  readonly #rows = new Map<string, UploadRow>()
  /** Files cancelled before this store had a row for them: nothing is sent for them. */
  readonly #cancelledEarly = new Set<string>()
  readonly #listeners = new Set<() => void>()
  #cached: ReadonlyMap<string, UploadRow> | null = null
  #timer: ReturnType<typeof setInterval> | null = null
  /** The read of the application's list that is under way and the cycle it was made in, none when no read is. */
  #reading: { readonly cycle: number; readonly list: Promise<readonly OpenUpload[] | null> } | null = null
  /** How many times the store was reset: a call that began in an earlier cycle changes nothing. */
  #cycle = 0
  /** The end of the last turn of each session: a turn starts when the one before it has settled. */
  #turns = new Map<string, Promise<void>>()
  /** The screens that show a session's composer, and how each reads the kept draft and shows what it holds. */
  readonly #attached = new Map<string, Reconciler>()
  /** Where the reconciliation of each session stands in this cycle. */
  #reconciled = new Map<string, Reconciliation>()

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

  /** How many times the store was reset. */
  get cycle(): number {
    return this.#cycle
  }

  /**
   * A check for a call to make at each step after it waited: it throws `ResetError` once the store
   * was reset after this was asked for.
   */
  guard(): () => void {
    const cycle = this.#cycle
    return () => {
      if (cycle !== this.#cycle) throw new ResetError()
    }
  }

  /**
   * Forgets every row, every early cancel and the timer, and starts a new cycle: the calls and the
   * reads that began before it end with `ResetError` and change nothing. Answers how many rows
   * there were.
   */
  reset(): number {
    const rows = this.#rows.size
    this.#cycle += 1
    this.#rows.clear()
    this.#cancelledEarly.clear()
    this.#turns = new Map()
    this.#reconciled = new Map()
    if (this.#timer !== null) {
      clearInterval(this.#timer)
      this.#timer = null
    }
    this.#changed()
    return rows
  }

  /**
   * Sends a file and waits for its outcome: the handle once it is published, and then adds it to the
   * draft through `bind`. A file that is published and not added is still the file's outcome, and its
   * row says it was kept; the refusals of the upload itself reject.
   */
  send(input: Sending, bind: Bind): Promise<AttachmentHandle> {
    const { key, sessionId, subject, file } = input
    const still = this.guard()
    // The person cancelled the file while the page was still reading it: it is never handed over.
    if (this.#cancelledEarly.delete(key)) return Promise.reject(new Error(CANCELLED_BEFORE_SENT))
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
        // A cancel that was asked and found the file published: the file was sent, and the row says so.
        const asked = this.#rows.get(key)?.phase.kind === 'cancelAsked'
        this.#patch(key, {
          handle,
          phase: { kind: 'adding' },
          awaited: false,
          ...(asked ? { note: sentence(PUBLISHED_AND_KEPT) } : {})
        })
        await this.#binding(key, handle, bind, still)
        return handle
      },
      async (failure: unknown) => {
        still()
        const refusal = refusalOf(failure)
        const phase = this.#rows.get(key)?.phase.kind
        // The person's own cancel has said what became of it; a cancel asked is ended only by the
        // application saying it was cancelled.
        if (phase !== 'cancelling' && phase !== 'cancelled' && !(phase === 'cancelAsked' && refusal.kind !== 'cancelled')) {
          if (refusal.kind === 'cancelled') {
            this.#patch(key, { phase: { kind: 'cancelled', released: null }, awaited: false })
          } else {
            // A reservation the application still keeps stays on the screen with what the application
            // says of it, so that it can be cancelled; only an upload it keeps nothing of is refused.
            const kept = await this.#kept(key)
            still()
            if (kept === UNREAD) {
              // Not knowing is not the same as nothing kept: the row says what was refused, and the
              // next read of the list decides whether the application holds the upload.
              this.#patch(key, { phase: { kind: 'refused', refusal }, awaited: false, unread: true })
              this.#poll()
            } else {
              this.#patch(
                key,
                kept === null
                  ? { phase: { kind: 'refused', refusal }, awaited: false }
                  : { phase: phaseOf(kept), handle: kept.handle ?? undefined, awaited: false }
              )
            }
          }
        }
        throw failure
      }
    )
  }

  /** What the application keeps of the upload `key`, none when it keeps nothing, and `UNREAD` when its list cannot be read. */
  async #kept(key: string): Promise<OpenUpload | null | typeof UNREAD> {
    try {
      return (await this.#port.uploadsOpen()).find((view) => view.key === key) ?? null
    } catch {
      return UNREAD
    }
  }

  /** Adds a published file to the draft again, or for the first time after a restart. */
  async bind(key: string, handle: AttachmentHandle, bind: Bind): Promise<void> {
    const still = this.guard()
    this.#patch(key, { phase: { kind: 'adding' }, handle })
    await this.#binding(key, handle, bind, still)
  }

  /**
   * Binds `handle` to the draft, in the turn of the row's session and after the reconciliation of
   * the session has succeeded: a bind that finds none for this cycle starts one first. The turn is
   * taken in the step that made the row `adding`. A store reset before or during the bind ends it
   * with `ResetError`, bound to nothing; a reconciliation that failed leaves the file kept, with the
   * words the read failed with.
   */
  #binding(key: string, handle: AttachmentHandle, bind: Bind, still: () => void): Promise<void> {
    const sessionId = this.#rows.get(key)?.sessionId ?? ''
    this.#reconcileIfNone(sessionId)
    return this.#inTurn(sessionId, async () => {
      try {
        still()
        const reconciled = this.#reconciled.get(sessionId)
        if (this.#attached.has(sessionId) && reconciled?.state !== 'done') {
          // eslint-disable-next-line @typescript-eslint/only-throw-error -- the read's own failure is data
          throw reconciled?.failure ?? new Error('')
        }
        await bind(handle)
        still()
        this.#patch(key, { phase: { kind: 'bound' } })
      } catch (failure) {
        if (isReset(failure)) throw failure
        this.#patch(key, { phase: { kind: 'kept', words: wordsOf(failure) || null } })
      }
    })
  }

  /**
   * Runs `work` after the work before it in the session has settled, whatever that ended with. A
   * bind, an end, a completion and a reconciliation each take a turn, so they run in the order they
   * were asked for.
   */
  #inTurn<T>(sessionId: string, work: () => Promise<T>): Promise<T> {
    const turns = this.#turns
    const run = (turns.get(sessionId) ?? Promise.resolve()).then(work)
    const tail = run.then(
      () => undefined,
      () => undefined
    )
    turns.set(sessionId, tail)
    void tail.then(() => {
      if (turns.get(sessionId) === tail) turns.delete(sessionId)
    })
    return run
  }

  /**
   * Ends the draft the device keeps for `sessionId` with `end`, in the session's turn, and drops the
   * rows that were bound to it when the turn began (the ones that were still being added are in that
   * turn's order, so they are bound or kept by then). Answers their keys. When `end` fails the rows
   * stay and the failure is rethrown. A row that is not bound when the turn begins ends nothing.
   */
  end(sessionId: string, key: string, end: () => Promise<void>): Promise<readonly string[]> {
    const still = this.guard()
    return this.#inTurn(sessionId, async () => {
      still()
      if (this.#rows.get(key)?.phase.kind !== 'bound') return []
      const gone = [...this.#rows]
        .filter(([, row]) => row.sessionId === sessionId && row.phase.kind === 'bound')
        .map(([each]) => each)
      await end()
      still()
      for (const each of gone) this.#rows.delete(each)
      this.#changed()
      return gone
    })
  }

  /**
   * Drops the rows of `sessionId` that went with a prompt the host performed, and only those: a file
   * bound to a new draft since the prompt was pressed keeps its row. Never fails.
   */
  async completeSent(sessionId: string, sentKeys: ReadonlySet<string>): Promise<void> {
    const cycle = this.#cycle
    await this.#inTurn(sessionId, () => {
      if (cycle === this.#cycle) {
        for (const key of sentKeys) {
          if (this.#rows.get(key)?.sessionId === sessionId && this.#rows.get(key)?.phase.kind === 'bound') {
            this.#rows.delete(key)
          }
        }
        this.#changed()
      }
      return Promise.resolve()
    })
  }

  /**
   * Makes `reconciler` the way `sessionId` is reconciled while a screen shows its composer. A session
   * with none has nothing to reconcile. Answers a function that takes it away.
   */
  attach<Read>(sessionId: string, reconciler: Reconciler<Read>): () => void {
    this.#attached.set(sessionId, reconciler as Reconciler)
    this.#reconciled.delete(sessionId)
    this.#notify()
    return () => {
      if (this.#attached.get(sessionId) === reconciler) {
        this.#attached.delete(sessionId)
        this.#reconciled.delete(sessionId)
        this.#notify()
      }
    }
  }

  /**
   * Whether what the device keeps for the session is shown: true when a reconciliation of this cycle
   * succeeded, and for a session no screen reconciles. False while one is pending, after one failed
   * and after a reset until the next.
   */
  ready(sessionId: string): boolean {
    return !this.#attached.has(sessionId) || this.#reconciled.get(sessionId)?.state === 'done'
  }

  /**
   * Reads the draft the device keeps for the session and shows its files that have no card, in the
   * session's turn, and checks the cycle before it shows them. A read that fails leaves the session not
   * ready.
   */
  reconcile(sessionId: string): Promise<void> {
    const reconciler = this.#attached.get(sessionId)
    if (reconciler === undefined) return Promise.resolve()
    const cycle = this.#cycle
    const settle = (next: Reconciliation) => {
      if (cycle !== this.#cycle || this.#attached.get(sessionId) !== reconciler) return
      this.#reconciled.set(sessionId, next)
      this.#notify()
    }
    settle({ cycle, state: 'pending' })
    return this.#inTurn(sessionId, async () => {
      try {
        const found = await reconciler.read()
        if (cycle !== this.#cycle || this.#attached.get(sessionId) !== reconciler) return
        reconciler.apply(found)
        settle({ cycle, state: 'done' })
      } catch (failure) {
        settle({ cycle, state: 'failed', failure })
      }
    })
  }

  /** Starts a reconciliation when the session has none that is pending or done in this cycle. */
  #reconcileIfNone(sessionId: string): void {
    const now = this.#reconciled.get(sessionId)
    if (this.#attached.has(sessionId) && (now === undefined || now.state === 'failed')) void this.reconcile(sessionId)
  }

  /** Tells the screens that what is read from the store, other than its rows, changed. */
  #notify(): void {
    for (const listener of this.#listeners) listener()
  }

  /** Whether a row holds the transfer `transferId`. */
  hasTransfer(transferId: string): boolean {
    for (const row of this.#rows.values()) if (row.handle?.transfer_id === transferId) return true
    return false
  }

  /**
   * Cancels a file that has not been sent in full. The row says it is being cancelled until the host
   * answers, and says what was released only from that answer. A file the host already holds in full
   * is not cancelled: the row says so, and the file goes on to the draft.
   */
  async cancel(key: string): Promise<void> {
    const row = this.#rows.get(key)
    if (row === undefined) {
      // A card is on the screen before the file has been read and handed to the application, and a
      // cancel pressed then is kept for the send that would make the row.
      this.#cancelledEarly.add(key)
      return
    }
    if (!canCancel(row.phase)) return
    const before = row.phase
    const cycle = this.#cycle
    this.#patch(key, { phase: { kind: 'cancelling' }, note: null })
    try {
      const answer = await this.#port.uploadCancel(key)
      if (cycle !== this.#cycle) return
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
      if (answer.state === 'asked') {
        this.#asked(key, answer.said)
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
      if (cycle !== this.#cycle) return
      if (isNoOpenUpload(failure)) {
        // The application holds no such upload: nothing was cancelled, and the file is as it was.
        this.#patch(key, { phase: before, note: refusalOf(failure).words })
      } else {
        // The application records a cancel before it does anything else, so a call that failed after
        // that has cancelled the file: it is never shown as going on.
        this.#asked(key, refusalOf(failure).words)
      }
    }
  }

  /** A cancel the application keeps and has not finished: nothing more is sent, and it is read again. */
  #asked(key: string, said: string | null): void {
    this.#patch(key, { phase: { kind: 'cancelAsked', said }, note: said })
    this.#poll()
  }

  /** Drops the row of a file that has left the composer. */
  forget(key: string): void {
    if (this.#rows.delete(key)) this.#changed()
  }

  /**
   * Reads the application's account once, adding the uploads this window did not start. Answers what
   * the application listed, or null when it could not be read: a call that finds a read of this cycle
   * under way waits for it and answers its list.
   */
  async restore(): Promise<readonly OpenUpload[] | null> {
    const listed = await this.#read()
    this.#poll()
    return listed
  }

  /**
   * Notes the files the composer holds that this window has no row for: a draft read back after a
   * restart. `bound` says which of them the host's draft holds.
   */
  noteFiles(files: readonly { readonly row: UploadRow; readonly bound: boolean }[]): void {
    let changed = false
    for (const { row, bound } of files) {
      // A file is one row: by its key, or by its transfer when another key (a send's) holds it.
      if (this.#rows.has(row.key) || (row.handle !== null && this.hasTransfer(row.handle.transfer_id))) continue
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
    for (const row of this.#rows.values()) if (DRIVEN.has(row.phase.kind) || row.unread === true) return true
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

  /**
   * The one read of the application's list that a cycle makes at a time. A reset starts a new read,
   * and the reply of the old one changes nothing: it neither makes rows nor ends the new read.
   */
  #read(): Promise<readonly OpenUpload[] | null> {
    const cycle = this.#cycle
    if (this.#reading?.cycle === cycle) return this.#reading.list
    const reading = { cycle, list: this.#readList(cycle) }
    this.#reading = reading
    void reading.list.then(() => {
      if (this.#reading === reading) this.#reading = null
    })
    return reading.list
  }

  async #readList(cycle: number): Promise<readonly OpenUpload[] | null> {
    try {
      const views = await this.#port.uploadsOpen()
      // A read that was asked for before a reset describes rows that are gone: it makes none.
      if (cycle !== this.#cycle) return null
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
          row.unread === true ||
          (!row.awaited && row.phase.kind === 'kept')
        ) {
          const next = phaseOf(view)
          // A cancel asked ends as listed published (the file was kept, and the row says so) or as
          // no longer listed; a read that was made before the cancel was recorded changes nothing.
          if (row.phase.kind === 'cancelAsked' && next.kind !== 'cancelAsked' && next.kind !== 'kept') continue
          // A file kept after the draft refused it keeps the reason it was refused for: the
          // application lists it as published and says nothing of why it was not added.
          const phase =
            (row.phase.kind === 'kept' && next.kind === 'kept') ||
            (row.phase.kind === 'cancelAsked' && next.kind === 'cancelAsked')
              ? row.phase
              : next
          const note = row.phase.kind === 'cancelAsked' && next.kind === 'kept' ? sentence(PUBLISHED_AND_KEPT) : row.note
          set({ ...row, phase, handle: view.handle ?? row.handle, note, ...(row.unread === true ? { unread: false } : {}) })
        }
      }
      // A file the application no longer lists, which no call of this window waits for, has ended.
      for (const [key, row] of this.#rows) {
        // A refused file whose list could not be read is now known to be one the application keeps nothing of.
        if (!seen.has(key) && row.unread === true) {
          this.#rows.set(key, { ...row, unread: false })
          changed = true
          continue
        }
        const going = DRIVEN.has(row.phase.kind) || row.phase.kind === 'stuck'
        if (!seen.has(key) && !row.awaited && going) {
          // The cancel was finished: the row says it was cancelled, with nothing released to report.
          if (row.phase.kind === 'cancelAsked') {
            this.#rows.set(key, { ...row, phase: { kind: 'cancelled', released: null }, note: null })
          } else {
            this.#rows.delete(key)
          }
          changed = true
        }
      }
      if (changed) this.#changed()
      return views
    } catch {
      // Not in contact: the rows stay as they were, and the next interval asks again.
      return null
    }
  }
}

/**
 * The files the draft this device keeps holds, each as the handle it was bound with. An attachment
 * that carries only the transfer is left out: it cannot be shown as a card.
 */
export function keptHandlesOf(view: unknown): readonly AttachmentHandle[] {
  const attachments = (view as { attachments?: readonly { handle?: unknown }[] } | null)?.attachments ?? []
  return attachments.flatMap((each) => {
    const handle = each.handle as Partial<AttachmentHandle> | undefined
    return typeof handle?.transfer_id === 'string' && typeof handle.original_file_name === 'string'
      ? [handle as AttachmentHandle]
      : []
  })
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
