/**
 * What the scripted host does with the files a phone sends it as a paired device.
 *
 * The application owns an upload between calls, so the scripted host does too: an upload the page
 * starts stays open, and listed by `uploadsOpen`, until a test moves it on (`progress`, `pause`,
 * `resume`, `finish`, `refuse`) or the page cancels it. A test also says what the application left
 * from an earlier run (`leave`), what the next bind or the next cancel answers, and reads what the
 * page asked: the files started, the cancels, the binds, the texts set and the drafts ended. The
 * draft is the device's own, one for each session, as the application keeps it.
 */

import type {
  AttachmentHandle,
  HandedFile,
  OpenUpload,
  PairedBound,
  PairedText,
  Settled,
  UploadCancelled
} from './port'

/** What a failure carries across the boundary: data, not an `Error`. */
export interface ScriptedFailure {
  readonly code: string
  readonly message: string
}

/** A file the page started. */
export interface StartedUpload {
  readonly key: string
  readonly name: string
  readonly byteLen: number
  readonly sessionId: string | null
}

interface Live {
  readonly key: string
  readonly name: string
  readonly byteLen: number
  readonly sessionId: string | null
  readonly handle: AttachmentHandle
  state: 'sending' | 'paused' | 'cancelAsked'
  stage: NonNullable<OpenUpload['stage']>
  done: number
  of: number
  readonly resolve: (handle: AttachmentHandle) => void
  readonly reject: (failure: ScriptedFailure) => void
}

interface HostDraft {
  readonly draftId: string
  revision: number
  text: string
  readonly attachments: unknown[]
}

/** What the application says to a call whose upload was cancelled. */
const CANCELLED_WORDS = 'this file was cancelled before it was sent in full'

export class FakeUploads {
  readonly started: StartedUpload[] = []
  readonly cancels: string[] = []
  readonly binds: Record<string, unknown>[] = []
  readonly texts: { readonly sessionId: string; readonly text: string }[] = []
  readonly ended: string[] = []
  readonly #live = new Map<string, Live>()
  readonly #drafts = new Map<string, HostDraft>()
  /** The handle of each upload this host published, by transfer: a draft's attachment carries the handle it was bound with. */
  readonly #handles = new Map<string, AttachmentHandle>()
  readonly #make: (file: HandedFile) => AttachmentHandle
  readonly #throw: (failure: ScriptedFailure) => never
  #left: OpenUpload[] = []
  #endRefused: ScriptedFailure | null = null
  #refuseNext: ScriptedFailure | null = null
  #bindRefusal: ScriptedFailure | null = null
  #cancelState: UploadCancelled['state'] = 'cancelled'
  #askedSaid: string | null = null
  #cancelFailure: ScriptedFailure | null = null
  #cancelGate: { readonly promise: Promise<void>; readonly release: () => void } | null = null
  #draftCounter = 0

  constructor(make: (file: HandedFile) => AttachmentHandle, fail: (failure: ScriptedFailure) => never) {
    this.#make = make
    this.#throw = fail
  }

  // What the page asks.

  send(file: HandedFile, sessionId: string | null, key: string): Promise<AttachmentHandle> {
    if (this.#refuseNext !== null) {
      const failure = this.#refuseNext
      this.#refuseNext = null
      this.#throw(failure)
    }
    this.started.push({ key, name: file.name, byteLen: file.bytes.length, sessionId })
    const handle = this.#make(file)
    this.#handles.set(handle.transfer_id, handle)
    return new Promise((resolve, reject) => {
      this.#live.set(key, {
        key,
        name: file.name,
        byteLen: file.bytes.length,
        sessionId,
        handle,
        state: 'sending',
        stage: 'starting',
        done: 0,
        of: 0,
        resolve,
        reject: (failure) => {
          // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- a command's failure is data
          reject(failure)
        }
      })
    })
  }

  open(): readonly OpenUpload[] {
    const live = [...this.#live.values()].map(
      (each): OpenUpload => ({
        key: each.key,
        state: each.state,
        sessionId: each.sessionId,
        fileName: each.name,
        byteLen: each.byteLen,
        acknowledgedChunks: each.done,
        chunks: each.of,
        stage: each.stage,
        handle: null,
        said: null
      })
    )
    return [...live, ...this.#left]
  }

  async cancel(key: string): Promise<UploadCancelled> {
    this.cancels.push(key)
    if (this.#cancelGate !== null) await this.#cancelGate.promise
    const live = this.#live.get(key)
    const left = this.#left.find((each) => each.key === key)
    if (live === undefined && left === undefined) {
      this.#throw({ code: 'INVALID_ARGUMENT', message: 'no open upload has that key' })
    }
    // The application records a cancel first: whatever fails after it, the upload is cancelled, and
    // it is listed as such until the cancel is finished.
    if (this.#cancelState === 'asked' || this.#cancelFailure !== null) {
      this.#markAsked(key)
      if (this.#cancelFailure !== null) {
        const failure = this.#cancelFailure
        this.#cancelFailure = null
        this.#throw(failure)
      }
      return { key, state: 'asked', releasedByteLen: null, handle: null, said: this.#askedSaid }
    }
    this.#left = this.#left.filter((each) => each.key !== key)
    if (this.#cancelState === 'published') {
      const handle = live?.handle ?? left?.handle ?? null
      if (live !== undefined) {
        this.#live.delete(key)
        live.resolve(live.handle)
      }
      return { key, state: 'published', releasedByteLen: null, handle, said: null }
    }
    if (live !== undefined) {
      this.#live.delete(key)
      live.reject({ code: 'PERMISSION_DENIED', message: CANCELLED_WORDS })
    }
    return {
      key,
      state: this.#cancelState,
      releasedByteLen: this.#cancelState === 'cancelled' ? String(live?.byteLen ?? left?.byteLen ?? 0) : null,
      handle: null,
      said: null
    }
  }

  bind(params: Record<string, unknown>): Settled {
    this.binds.push(params)
    if (this.#bindRefusal !== null) {
      const failure = this.#bindRefusal
      this.#bindRefusal = null
      this.#throw(failure)
    }
    const sessionId = String(params.session_id)
    const draft = this.#drafts.get(sessionId) ?? this.#start(sessionId, typeof params.text === 'string' ? params.text : '')
    draft.revision += 1
    // The application's own shape: the attachment carries the handle it was bound with.
    const transfer = String(params.transfer_id)
    const attachment = { handle: this.#handles.get(transfer) ?? { transfer_id: transfer } }
    draft.attachments.push(attachment)
    const value: PairedBound & { readonly attachment: unknown } = {
      draftId: draft.draftId,
      revision: String(draft.revision),
      attachment
    }
    return { receipt: null, action_id: null, value, answer_lost: false }
  }

  /** The draft the device keeps for a session already holds a file: one bound before this window, or by another. */
  keep(sessionId: string, handle: AttachmentHandle): void {
    const draft = this.#drafts.get(sessionId) ?? this.#start(sessionId, '')
    draft.attachments.push({ handle })
  }

  kept(sessionId: string): { made: boolean; draftId: string | null; revision: string | null; attachments: unknown[] } {
    const draft = this.#drafts.get(sessionId)
    return draft === undefined
      ? { made: false, draftId: null, revision: null, attachments: [] }
      : { made: true, draftId: draft.draftId, revision: String(draft.revision), attachments: draft.attachments }
  }

  setText(sessionId: string, text: string): PairedText {
    this.texts.push({ sessionId, text })
    const draft = this.#drafts.get(sessionId)
    if (draft === undefined) {
      this.#throw({ code: 'PERMISSION_DENIED', message: 'this device keeps no draft for this session: add a file to it first' })
    }
    draft.text = text
    draft.revision += 1
    return { draftId: draft.draftId, revision: String(draft.revision), text }
  }

  /** The next end of a draft fails, as one does when the host is out of contact. */
  refuseNextEnd(failure: ScriptedFailure = { code: 'HOST_NOT_CONFIGURED', message: 'the host is not connected' }): void {
    this.#endRefused = failure
  }

  end(sessionId: string): void {
    if (this.#endRefused !== null) {
      const failure = this.#endRefused
      this.#endRefused = null
      this.#throw(failure)
    }
    this.ended.push(sessionId)
    this.#drafts.delete(sessionId)
  }

  /** The prompt named the draft and the host took it: the draft is the session's now. */
  sent(sessionId: string): void {
    this.#drafts.delete(sessionId)
  }

  /** The text the host holds for a session's draft, or null. */
  textOf(sessionId: string): string | null {
    return this.#drafts.get(sessionId)?.text ?? null
  }

  // What a test scripts.

  /** What the application left from an earlier run, as `uploadsOpen` lists it. */
  leave(entries: readonly OpenUpload[]): void {
    this.#left = [...entries]
  }

  progress(key: string, done: number, of: number): void {
    const live = this.#need(key)
    live.state = 'sending'
    live.stage = 'sending'
    live.done = done
    live.of = of
  }

  pause(key: string): void {
    this.#need(key).state = 'paused'
  }

  /** A lost connection came back: the application reads what the host holds before it goes on. */
  resume(key: string): void {
    const live = this.#need(key)
    live.state = 'sending'
    live.stage = 'resuming'
  }

  /** Every chunk is held and the handle is being published. */
  publishing(key: string): void {
    const live = this.#need(key)
    live.state = 'sending'
    live.stage = 'publishing'
    live.done = live.of
  }

  finish(key: string): void {
    const live = this.#need(key)
    this.#live.delete(key)
    live.resolve(live.handle)
  }

  refuse(key: string, failure: ScriptedFailure): void {
    const live = this.#need(key)
    this.#live.delete(key)
    live.reject(failure)
  }

  /** The command fails and the application keeps the upload, paused: a failed journal write does this. */
  refuseRetaining(key: string, failure: ScriptedFailure): void {
    const live = this.#need(key)
    live.state = 'paused'
    live.reject(failure)
  }

  refuseNext(failure: ScriptedFailure): void {
    this.#refuseNext = failure
  }

  refuseNextBind(failure: ScriptedFailure): void {
    this.#bindRefusal = failure
  }

  /** What the next cancels answer: released, already published and kept, kept to be finished, or nothing the host holds. */
  answerCancelsWith(state: UploadCancelled['state'], said: string | null = null): void {
    this.#cancelState = state
    this.#askedSaid = said
  }

  /** The next cancel fails after the application has recorded it, as a call does when the host is out of reach. */
  failNextCancel(failure: ScriptedFailure): void {
    this.#cancelFailure = failure
  }

  /** The application finished the cancel it kept: the host released the reservation and the upload is gone. */
  finishAskedCancel(key: string): void {
    const live = this.#live.get(key)
    if (live !== undefined) {
      this.#live.delete(key)
      live.reject({ code: 'PERMISSION_DENIED', message: CANCELLED_WORDS })
    }
    this.#left = this.#left.filter((each) => each.key !== key)
  }

  /** Holds the host's answer to a cancel until `releaseCancels`. */
  holdCancels(): void {
    let release: () => void = () => undefined
    const promise = new Promise<void>((resolve) => {
      release = resolve
    })
    this.#cancelGate = { promise, release }
  }

  releaseCancels(): void {
    this.#cancelGate?.release()
    this.#cancelGate = null
  }

  #start(sessionId: string, text: string): HostDraft {
    this.#draftCounter += 1
    const draft: HostDraft = {
      draftId: `00000000-0000-4000-8000-${String(this.#draftCounter).padStart(12, '0')}`,
      revision: 1,
      text,
      attachments: []
    }
    this.#drafts.set(sessionId, draft)
    return draft
  }

  #markAsked(key: string): void {
    const live = this.#live.get(key)
    if (live !== undefined) live.state = 'cancelAsked'
    this.#left = this.#left.map((each) => (each.key === key ? { ...each, state: 'cancelAsked' } : each))
  }

  #need(key: string): Live {
    const live = this.#live.get(key)
    if (live === undefined) throw new Error(`no upload ${key} is open`)
    return live
  }
}
