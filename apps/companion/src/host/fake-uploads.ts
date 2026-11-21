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
  state: 'sending' | 'paused'
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
  readonly #make: (file: HandedFile) => AttachmentHandle
  readonly #throw: (failure: ScriptedFailure) => never
  #left: OpenUpload[] = []
  #refuseNext: ScriptedFailure | null = null
  #bindRefusal: ScriptedFailure | null = null
  #cancelState: UploadCancelled['state'] = 'cancelled'
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
    return new Promise((resolve, reject) => {
      this.#live.set(key, {
        key,
        name: file.name,
        byteLen: file.bytes.length,
        sessionId,
        handle: this.#make(file),
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
    this.#left = this.#left.filter((each) => each.key !== key)
    if (this.#cancelState === 'published') {
      const handle = live?.handle ?? left?.handle ?? null
      if (live !== undefined) {
        this.#live.delete(key)
        live.resolve(live.handle)
      }
      return { key, state: 'published', releasedByteLen: null, handle }
    }
    if (live !== undefined) {
      this.#live.delete(key)
      live.reject({ code: 'PERMISSION_DENIED', message: CANCELLED_WORDS })
    }
    return {
      key,
      state: this.#cancelState,
      releasedByteLen: this.#cancelState === 'cancelled' ? String(live?.byteLen ?? left?.byteLen ?? 0) : null,
      handle: null
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
    const attachment = { transfer_id: params.transfer_id }
    draft.attachments.push(attachment)
    const value: PairedBound & { readonly attachment: unknown } = {
      draftId: draft.draftId,
      revision: String(draft.revision),
      attachment
    }
    return { receipt: null, action_id: null, value, answer_lost: false }
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

  end(sessionId: string): void {
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

  refuseNext(failure: ScriptedFailure): void {
    this.#refuseNext = failure
  }

  refuseNextBind(failure: ScriptedFailure): void {
    this.#bindRefusal = failure
  }

  /** What the next cancels answer: released, already published and kept, or nothing the host holds. */
  answerCancelsWith(state: UploadCancelled['state']): void {
    this.#cancelState = state
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

  #need(key: string): Live {
    const live = this.#live.get(key)
    if (live === undefined) throw new Error(`no upload ${key} is open`)
    return live
  }
}
