/**
 * What a person is told about a file sent to a paired host, and how the store of those files moves
 * (KR-REQ-13.12). The application's own sentences are held to the constants in the Rust files that
 * write them, so a change there cannot pass here unseen.
 */

import { describe, expect, it, vi } from 'vitest'

import { fakeHost } from '../src/host/fake'
import type { OpenUpload, UploadCancelled } from '../src/host/port'
import { PairedUploads, boundIdsOf, canCancel, lineOf, type Phase } from '../src/model/paired-uploads'
import * as words from '../src/model/transfer-words'
import openTransfers from '../src-tauri/src/open_transfers.rs?raw'
import pairedDrafts from '../src-tauri/src/paired_drafts.rs?raw'
import organisation from '../../../crates/kr-client/src/organisation.rs?raw'

const RUST: Readonly<Record<string, string>> = {
  'open_transfers.rs': openTransfers,
  'paired_drafts.rs': pairedDrafts
}


/** The string a Rust `pub const NAME: &str` holds, joined across the lines it is written on. */
function rustConstant(file: string, name: string): string {
  const text = RUST[file] ?? ''
  const match = new RegExp(`pub const ${name}: &str\\s*=\\s*((?:"(?:[^"\\\\]|\\\\.)*"\\s*)+);`).exec(text)
  if (match?.[1] === undefined) throw new Error(`${name} is not in ${file}`)
  return [...match[1].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((part) => part[1] ?? '').join('')
}

/** The sentence `kr-client` says for one `LeaseStop`, joined across the lines it is written on. */
function leaseStopSentence(variant: string): string {
  const match = new RegExp(`Self::${variant} => Shown::said\\(\\s*"((?:[^"\\\\]|\\\\[\\s\\S])*)"\\s*,?\\s*\\)`).exec(organisation)
  if (match?.[1] === undefined) throw new Error(`${variant} is not in organisation.rs`)
  // A backslash at the end of a line in a Rust string takes the line break and the next line's indent with it.
  return match[1].replace(/\\\r?\n\s*/g, '')
}

describe("the application's sentences are the ones the page recognises and shows", () => {
  it.each([
    ['open_transfers.rs', 'TOO_MANY_OPEN', words.TOO_MANY_OPEN],
    ['open_transfers.rs', 'CANNOT_RESUME', words.CANNOT_RESUME],
    ['open_transfers.rs', 'KEY_IN_USE', words.KEY_IN_USE],
    ['open_transfers.rs', 'UNRECOVERABLE', words.UNRECOVERABLE],
    ['open_transfers.rs', 'CANCELLED', words.CANCELLED_BEFORE_SENT],
    ['open_transfers.rs', 'NO_OPEN_UPLOAD', words.NO_OPEN_UPLOAD],
    ['paired_drafts.rs', 'GONE', words.DRAFT_GONE],
    ['paired_drafts.rs', 'GONE_FOR_TEXT', words.DRAFT_GONE_FOR_TEXT],
    ['paired_drafts.rs', 'NO_DRAFT', words.NO_DRAFT],
    ['paired_drafts.rs', 'CHANGED_AGAIN', words.CHANGED_AGAIN],
    ['paired_drafts.rs', 'NEWER_DRAFT', words.NEWER_DRAFT],
    ['paired_drafts.rs', 'CREATE_PENDING', words.CREATE_PENDING],
    ['paired_drafts.rs', 'DISCARD_PENDING', words.DISCARD_PENDING],
    ['paired_drafts.rs', 'UPDATE_THE_HOST', words.UPDATE_THE_HOST_TO_END_A_DRAFT]
  ])('%s %s', (file, name, constant) => {
    expect(constant).toBe(rustConstant(file, name))
  })

  it('holds the sign-in sentence to the words kr-client says for a stopped lease', () => {
    expect(words.SIGN_IN_AGAIN).toBe(leaseStopSentence('SignIn'))
  })

  it('states the sentence of a cancel that found the file published as the approved words', () => {
    expect(words.PUBLISHED_AND_KEPT).toBe(
      'this file was already sent in full and the host keeps it: it was not cancelled'
    )
  })

  it('changes only the first letter of a sentence', () => {
    expect(words.sentence(words.TOO_MANY_OPEN)).toBe(
      'Two files are open on this host already: wait for one to finish, or cancel one'
    )
    expect(words.sentence('')).toBe('')
  })
})

describe('what each refusal means to the person, and the words it is shown in', () => {
  const host = (code: string, message: string) => ({ code, message })
  it.each([
    [host('PERMISSION_DENIED', words.CANCELLED_BEFORE_SENT), 'cancelled', 'This file was cancelled before it was sent in full'],
    [host('PERMISSION_DENIED', words.TOO_MANY_OPEN), 'too-many', words.sentence(words.TOO_MANY_OPEN)],
    [host('PERMISSION_DENIED', words.DRAFT_GONE), 'gone', words.sentence(words.DRAFT_GONE)],
    // The application's other refusals come with the code of a missing right, and are not read as one.
    [host('PERMISSION_DENIED', words.CANNOT_RESUME), 'other', words.sentence(words.CANNOT_RESUME)],
    [host('PERMISSION_DENIED', words.KEY_IN_USE), 'other', words.sentence(words.KEY_IN_USE)],
    [host('PERMISSION_DENIED', words.NEWER_DRAFT), 'other', words.sentence(words.NEWER_DRAFT)],
    // The refusal of a command made under another sign-in, or with none, is not a right the device lacks.
    [host('PERMISSION_DENIED', words.SIGN_IN_AGAIN), 'other', words.sentence(words.SIGN_IN_AGAIN)],
    [host('UNSUPPORTED_CAPABILITY', 'unknown method upload.begin'), 'earlier-host', words.EARLIER_HOST],
    [host('UNSUPPORTED_SCHEMA', 'schema'), 'earlier-host', words.EARLIER_HOST],
    [host('PERMISSION_DENIED', 'the device holds no right for files.upload'), 'no-right', words.NO_RIGHT_TO_SEND],
    [host('QUOTA_EXCEEDED', 'staging holds 1073741824 of 2147483648 bytes'), 'no-room', words.NO_ROOM],
    [host('STORAGE_UNAVAILABLE', 'the store is full'), 'no-room', words.NO_ROOM],
    [host('ATTACHMENT_INTEGRITY', 'the file changed or could not be read while it was being sent'), 'file-changed', words.FILE_CHANGED],
    [host('SOURCE_CHANGED', 'the source changed'), 'file-changed', words.FILE_CHANGED],
    [host('RATE_LIMITED', 'slow down'), 'other', 'Slow down']
  ])('%j is %s', (failure, kind, shown) => {
    expect(words.refusalOf(failure)).toEqual({ kind, words: shown })
  })

  it('never puts a total of the host in the words of a full staging area', () => {
    expect(words.NO_ROOM).not.toMatch(/\d/)
  })
})

describe('each state of a file in words (KR-REQ-13.12)', () => {
  const lines: readonly [Phase, string, number | null][] = [
    [{ kind: 'checking' }, 'Checking with the host', null],
    [{ kind: 'sending', done: 3, of: 12 }, 'Sending, 25%', 0.25],
    [{ kind: 'sending', done: 0, of: 0 }, 'Sending, 0%', 0],
    [{ kind: 'resuming', done: 3, of: 12 }, 'Resuming at chunk 4 of 12', 0.25],
    [{ kind: 'resuming', done: 12, of: 12 }, 'Resuming at chunk 12 of 12', 1],
    [
      { kind: 'paused', done: 3, of: 12 },
      'Paused: the host is out of reach. Sending resumes when contact returns.',
      0.25
    ],
    [{ kind: 'waiting' }, 'Waiting for the host', null],
    [{ kind: 'finishing' }, 'Finishing with the host', 1],
    [{ kind: 'cancelling' }, 'Cancelling', null],
    [
      { kind: 'cancelAsked', said: null },
      'Cancel asked: no more of this file is sent, and the cancel is finished when the host can be reached.',
      null
    ],
    [{ kind: 'cancelled', released: null }, 'Cancelled.', null],
    [{ kind: 'cancelled', released: '4404019' }, 'Cancelled. The host released 4.2 MB.', null],
    [{ kind: 'adding' }, 'Sent in full. Adding it to this draft', 1],
    [{ kind: 'bound' }, 'Added to this draft', null],
    [
      { kind: 'kept', words: null },
      'Sent in full and kept by the host. Not added to a draft yet',
      null
    ],
    [
      { kind: 'kept', words: 'The session or the draft is gone' },
      'Sent in full and kept by the host. It was not added to this draft: The session or the draft is gone',
      null
    ],
    [{ kind: 'stuck', words: 'Cannot resume' }, 'Cannot resume', null]
  ]
  it.each(lines)('%j reads %j', (phase, text, progress) => {
    const line = lineOf(phase)
    expect(line.text).toBe(text)
    expect(line.progress).toBe(progress)
  })

  it('lets a person cancel a file until the host has it in full, and not after', () => {
    for (const kind of ['checking', 'sending', 'resuming', 'paused', 'waiting', 'finishing', 'stuck'] as const) {
      const phase = { kind, done: 0, of: 1, words: '' } as Phase
      expect(canCancel(phase), kind).toBe(true)
    }
    for (const kind of ['cancelling', 'cancelAsked', 'cancelled', 'adding', 'bound', 'kept', 'refused'] as const) {
      const phase = { kind, released: null, words: null, said: null, refusal: { kind: 'other', words: '' } } as Phase
      expect(canCancel(phase), kind).toBe(false)
    }
  })
})

describe('the store reads the application, and the application is the one that says how far', () => {
  const file = { name: 'a.pdf', bytes: new Uint8Array(10) }
  const subject = { sessionId: 's-1', sessionEpoch: '1' }
  const wait = async (check: () => boolean) => {
    for (let spent = 0; spent < 1500 && !check(); spent += 5) await new Promise((resolve) => setTimeout(resolve, 5))
    expect(check()).toBe(true)
  }
  const reached = () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: ['files.upload', 'agent.prompt'] })
    const uploads = new PairedUploads(port, 5)
    return { uploads, scripted: controls.pairedUploads }
  }

  it('keeps a file the application still holds, with Cancel, when its command failed', async () => {
    const { uploads, scripted } = reached()
    const sent = uploads.send({ key: 'k-9', sessionId: 's-1', subject, file }, () => Promise.resolve())
    const failed = sent.catch(() => undefined)
    await wait(() => scripted.started.length === 1)
    scripted.refuseRetaining('k-9', {
      code: 'RESOURCE_UNAVAILABLE',
      message: 'this device could not keep a record of the upload: disk full'
    })
    await failed
    const phase = uploads.snapshot().get('k-9')?.phase
    expect(phase?.kind).not.toBe('refused')
    expect(phase !== undefined && canCancel(phase)).toBe(true)
  })

  /** The store with its list of the application's uploads unreadable until `mend()` is called. */
  const unreadable = () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: ['files.upload', 'agent.prompt'] })
    const real = port.uploadsOpen.bind(port)
    let readable = false
    const asked = vi
      .spyOn(port, 'uploadsOpen')
      .mockImplementation(() => (readable ? real() : Promise.reject(new Error('the application cannot be reached'))))
    const uploads = new PairedUploads(port, 5)
    return {
      uploads,
      scripted: controls.pairedUploads,
      asked,
      mend: () => {
        readable = true
      }
    }
  }
  const refusal = {
    code: 'RESOURCE_UNAVAILABLE',
    message: 'this device could not keep a record of the upload: disk full'
  }

  it('does not take a refused file for one the application keeps nothing of when its list cannot be read', async () => {
    const { uploads, scripted, mend } = unreadable()
    const sent = uploads.send({ key: 'k-7', sessionId: 's-1', subject, file }, () => Promise.resolve())
    const failed = sent.catch(() => undefined)
    await wait(() => scripted.started.length === 1)
    scripted.refuseRetaining('k-7', refusal)
    await failed
    // Nothing is known of what the application keeps: the row says what was refused, and asks again.
    expect(uploads.snapshot().get('k-7')?.phase.kind).toBe('refused')
    mend()
    await wait(() => uploads.snapshot().get('k-7')?.phase.kind !== 'refused')
    const phase = uploads.snapshot().get('k-7')?.phase
    expect(phase !== undefined && canCancel(phase)).toBe(true)
  })

  it('stops asking once the list is read and the application keeps nothing of the refused file', async () => {
    const { uploads, scripted, asked, mend } = unreadable()
    const sent = uploads.send({ key: 'k-6', sessionId: 's-1', subject, file }, () => Promise.resolve())
    const failed = sent.catch(() => undefined)
    await wait(() => scripted.started.length === 1)
    scripted.refuse('k-6', refusal)
    await failed
    mend()
    await wait(() => uploads.snapshot().get('k-6')?.unread !== true)
    expect(uploads.snapshot().get('k-6')?.phase.kind).toBe('refused')
    const reads = asked.mock.calls.length
    await new Promise((resolve) => setTimeout(resolve, 60))
    expect(asked.mock.calls.length).toBe(reads)
  })

  it('keeps the reason a finished file was not added when the application is read again', async () => {
    const { uploads, scripted } = reached()
    const refused = { code: 'PERMISSION_DENIED', message: words.DRAFT_GONE }
    const sent = uploads.send({ key: 'k-8', sessionId: 's-1', subject, file }, () => Promise.reject(refused))
    await wait(() => scripted.started.length === 1)
    scripted.finish('k-8')
    const handle = await sent
    const reason = words.sentence(words.DRAFT_GONE)
    expect(uploads.snapshot().get('k-8')?.phase).toEqual({ kind: 'kept', words: reason })
    // The application lists the published file until it is bound, and says nothing of why it was not.
    scripted.leave([
      {
        key: 'k-8',
        state: 'published',
        sessionId: 's-1',
        fileName: 'a.pdf',
        byteLen: 10,
        acknowledgedChunks: 0,
        chunks: 0,
        stage: null,
        handle,
        said: null
      }
    ])
    await uploads.restore()
    expect(uploads.snapshot().get('k-8')?.phase).toEqual({ kind: 'kept', words: reason })
  })

  it('shows the file at once, follows its chunks by asking again, and stops asking when it is done', async () => {
    const { uploads, scripted } = reached()
    const sent = uploads.send({ key: 'k-1', sessionId: 's-1', subject, file }, () => Promise.resolve())
    expect(uploads.snapshot().get('k-1')?.phase).toEqual({ kind: 'checking' })
    await wait(() => scripted.started.length === 1)
    scripted.progress('k-1', 5, 10)
    await wait(() => uploads.snapshot().get('k-1')?.phase.kind === 'sending')
    expect(uploads.snapshot().get('k-1')?.phase).toEqual({ kind: 'sending', done: 5, of: 10 })
    scripted.pause('k-1')
    await wait(() => uploads.snapshot().get('k-1')?.phase.kind === 'paused')
    scripted.resume('k-1')
    await wait(() => uploads.snapshot().get('k-1')?.phase.kind === 'resuming')
    scripted.publishing('k-1')
    await wait(() => uploads.snapshot().get('k-1')?.phase.kind === 'finishing')
    scripted.finish('k-1')
    const handle = await sent
    expect(handle.original_file_name).toBe('a.pdf')
    expect(uploads.snapshot().get('k-1')?.phase).toEqual({ kind: 'bound' })
  })

  it('says a cancel is under way until the host answers, and what was released only from its answer', async () => {
    const { uploads, scripted } = reached()
    const sent = uploads.send({ key: 'k-2', sessionId: 's-1', subject, file }, () => Promise.resolve())
    sent.catch(() => undefined)
    await wait(() => scripted.started.length === 1)
    scripted.holdCancels()
    const cancelling = uploads.cancel('k-2')
    expect(uploads.snapshot().get('k-2')?.phase).toEqual({ kind: 'cancelling' })
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(uploads.snapshot().get('k-2')?.phase).toEqual({ kind: 'cancelling' })
    scripted.releaseCancels()
    await cancelling
    await expect(sent).rejects.toBeDefined()
    expect(uploads.snapshot().get('k-2')?.phase).toEqual({ kind: 'cancelled', released: '10' })
  })

  it('keeps a file the host already holds in full, says so, and adds it to the draft', async () => {
    const { uploads, scripted } = reached()
    const sent = uploads.send({ key: 'k-3', sessionId: 's-1', subject, file }, () => Promise.resolve())
    await wait(() => scripted.started.length === 1)
    scripted.answerCancelsWith('published')
    await uploads.cancel('k-3')
    await sent
    const row = uploads.snapshot().get('k-3')
    expect(row?.phase).toEqual({ kind: 'bound' })
    expect(row?.note).toBe(words.sentence(words.PUBLISHED_AND_KEPT))
  })

  it('keeps a finished upload when the draft refuses it, and adds it again when asked', async () => {
    const { uploads, scripted } = reached()
    let refuse = true
    const bind = () =>
      refuse ? Promise.reject({ code: 'PERMISSION_DENIED', message: words.DRAFT_GONE }) : Promise.resolve()
    const sent = uploads.send({ key: 'k-4', sessionId: 's-1', subject, file }, bind)
    await wait(() => scripted.started.length === 1)
    scripted.finish('k-4')
    const handle = await sent
    expect(uploads.snapshot().get('k-4')?.phase).toEqual({
      kind: 'kept',
      words: words.sentence(words.DRAFT_GONE)
    })
    refuse = false
    await uploads.bind('k-4', handle, bind)
    expect(uploads.snapshot().get('k-4')?.phase).toEqual({ kind: 'bound' })
  })

  const left = (state: 'waiting' | 'cancelAsked' | 'published', handle: OpenUpload['handle'] = null): OpenUpload => ({
    key: 'found-1',
    state,
    sessionId: 's-1',
    fileName: 'left.bin',
    byteLen: 9,
    acknowledgedChunks: 0,
    chunks: 0,
    stage: null,
    handle,
    said: null
  })

  it('says cancel asked, keeps asking, and ends cancelled when the application stops listing the file', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: ['files.upload', 'agent.prompt'] })
    const scripted = controls.pairedUploads
    const uploads = new PairedUploads(port, 5)
    scripted.leave([left('waiting')])
    await uploads.restore()
    scripted.answerCancelsWith('asked')
    await uploads.cancel('found-1')
    expect(uploads.snapshot().get('found-1')?.phase).toEqual({ kind: 'cancelAsked', said: null })
    // No send waits for this row, so only the poll can move it: it asks the application again.
    const asked = vi.spyOn(port, 'uploadsOpen')
    scripted.finishAskedCancel('found-1')
    await wait(() => asked.mock.calls.length > 0)
    await wait(() => uploads.snapshot().get('found-1')?.phase.kind === 'cancelled')
    expect(uploads.snapshot().get('found-1')?.phase).toEqual({ kind: 'cancelled', released: null })
  })

  it('leaves the row cancel asked, with the words, when the call fails after the cancel was sent', async () => {
    const { uploads, scripted } = reached()
    const sent = uploads.send({ key: 'k-5', sessionId: 's-1', subject, file }, () => Promise.resolve())
    sent.catch(() => undefined)
    await wait(() => scripted.started.length === 1)
    scripted.pause('k-5')
    await wait(() => uploads.snapshot().get('k-5')?.phase.kind === 'paused')
    scripted.failNextCancel({ code: 'HOST_NOT_CONFIGURED', message: 'the host is not connected' })
    await uploads.cancel('k-5')
    const row = uploads.snapshot().get('k-5')
    expect(row?.phase).toEqual({ kind: 'cancelAsked', said: 'The host is not connected' })
    expect(lineOf(row?.phase as Phase).text).not.toContain('Sending resumes')
    // Asking again does not turn it back into a paused file.
    await new Promise((resolve) => setTimeout(resolve, 30))
    expect(uploads.snapshot().get('k-5')?.phase.kind).toBe('cancelAsked')
  })

  it('reads a stored cancel as cancel asked and not as waiting', async () => {
    const { uploads, scripted } = reached()
    scripted.leave([left('cancelAsked')])
    await uploads.restore()
    expect(uploads.found('s-1', new Set())[0]?.phase).toEqual({ kind: 'cancelAsked', said: null })
    expect(canCancel(uploads.found('s-1', new Set())[0]?.phase)).toBe(false)
  })

  it('says a cancel asked was not carried out when the upload turns out to be published', async () => {
    const { uploads, scripted } = reached()
    scripted.leave([left('cancelAsked')])
    await uploads.restore()
    const handle = {
      transfer_id: 't-1',
      environment_id: 'e-1',
      byte_len: '9',
      content_digest: 'b'.repeat(64),
      declared_media_type: 'application/octet-stream',
      original_file_name: 'left.bin',
      presented_as_image: false,
      session_id: null,
      preview: null,
      published_at_ms: '1',
      expires_at_ms: '2',
      submitted: false
    }
    scripted.leave([left('published', handle)])
    await wait(() => uploads.snapshot().get('found-1')?.phase.kind === 'kept')
    expect(uploads.snapshot().get('found-1')?.note).toBe(words.sentence(words.PUBLISHED_AND_KEPT))
  })

  it('says it was kept when a send that waited for a cancel asked ends with the file published', async () => {
    const { uploads, scripted } = reached()
    const sent = uploads.send({ key: 'k-6', sessionId: 's-1', subject, file }, () => Promise.resolve())
    await wait(() => scripted.started.length === 1)
    scripted.answerCancelsWith('asked')
    await uploads.cancel('k-6')
    expect(uploads.snapshot().get('k-6')?.phase).toEqual({ kind: 'cancelAsked', said: null })
    scripted.finish('k-6')
    await sent
    const row = uploads.snapshot().get('k-6')
    expect(row?.phase).toEqual({ kind: 'bound' })
    expect(row?.note).toBe(words.sentence(words.PUBLISHED_AND_KEPT))
  })

  it('finds what a restart left on the session it was for, and drops what the application no longer lists', async () => {
    const { uploads, scripted } = reached()
    scripted.leave([
      {
        key: 'found-1',
        state: 'waiting',
        sessionId: 's-1',
        fileName: 'left.bin',
        byteLen: 9,
        acknowledgedChunks: 0,
        chunks: 0,
        stage: null,
        handle: null,
        said: null
      },
      {
        key: 'found-2',
        state: 'cannotResume',
        sessionId: 's-2',
        fileName: 'other.bin',
        byteLen: 9,
        acknowledgedChunks: 0,
        chunks: 0,
        stage: null,
        handle: null,
        said: words.CANNOT_RESUME
      }
    ])
    await uploads.restore()
    expect(uploads.found('s-1', new Set()).map((row) => row.key)).toEqual(['found-1'])
    expect(uploads.found('s-2', new Set())[0]?.phase).toEqual({
      kind: 'stuck',
      words: words.sentence(words.CANNOT_RESUME)
    })
    scripted.leave([])
    await uploads.restore()
    expect(uploads.found('s-1', new Set())).toEqual([])
  })
})

describe('the list of the application is read once at a time', () => {
  /** The port, with every read of the list held until the test lets its reply go. */
  function held() {
    const { port } = fakeHost()
    const view: OpenUpload = {
      key: 'listed-1',
      state: 'published',
      sessionId: 's-1',
      fileName: 'a.pdf',
      byteLen: 10,
      acknowledgedChunks: 0,
      chunks: 0,
      stage: null,
      handle: null,
      said: null
    }
    const replies: (() => void)[] = []
    const open = vi.spyOn(port, 'uploadsOpen').mockImplementation(
      () =>
        new Promise((resolve) => {
          replies.push(() => {
            resolve([view])
          })
        })
    )
    return { uploads: new PairedUploads(port, 60_000), open, replies, view }
  }

  it('J2: makes one read for calls that overlap, and answers each of them with its list', async () => {
    const { uploads, open, replies, view } = held()
    const first = uploads.restore()
    const second = uploads.restore()
    expect(open).toHaveBeenCalledTimes(1)
    replies[0]?.()
    expect(await first).toEqual([view])
    expect(await second).toEqual([view])
  })

  it('J2: starts a new read after a reset, and the reply of the old one clears nothing', async () => {
    const { uploads, open, replies, view } = held()
    const old = uploads.restore()
    uploads.reset()
    const current = uploads.restore()
    expect(open).toHaveBeenCalledTimes(2)
    // The old reply describes rows that are gone: it answers nothing, and the new read is still under way.
    replies[0]?.()
    expect(await old).toBeNull()
    const joined = uploads.restore()
    expect(open).toHaveBeenCalledTimes(2)
    replies[1]?.()
    expect(await current).toEqual([view])
    expect(await joined).toEqual([view])
  })
})

describe('the answer to a cancel applies only to the row that asked it', () => {
  const file = { name: 'a.pdf', bytes: new Uint8Array(10) }
  const subject = { sessionId: 's-1', sessionEpoch: '1' }
  const wait = async (check: () => boolean) => {
    for (let spent = 0; spent < 1500 && !check(); spent += 5) await new Promise((resolve) => setTimeout(resolve, 5))
    expect(check()).toBe(true)
  }
  const answer = (state: UploadCancelled['state'], key: string): UploadCancelled => ({
    key,
    state,
    releasedByteLen: state === 'cancelled' ? '10' : null,
    handle: null,
    said: null
  })

  /** A store whose cancels wait for the test, and answer as it says. */
  function pending() {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: ['files.upload', 'agent.prompt'] })
    const uploads = new PairedUploads(port, 5)
    const replies: { resolve: (answer: UploadCancelled) => void; reject: (failure: unknown) => void }[] = []
    vi.spyOn(port, 'uploadCancel').mockImplementation(
      () =>
        new Promise((resolve, reject) => {
          replies.push({ resolve, reject })
        })
    )
    return { uploads, scripted: controls.pairedUploads, replies }
  }

  it('K1: leaves a bound row bound when a cancel answers published after the file was added', async () => {
    const { uploads, scripted, replies } = pending()
    const sent = uploads.send({ key: 'k-1', sessionId: 's-1', subject, file }, () => Promise.resolve())
    await wait(() => scripted.started.length === 1)
    const cancelling = uploads.cancel('k-1')
    expect(uploads.snapshot().get('k-1')?.phase).toEqual({ kind: 'cancelling' })
    // The upload's result and its bind come first.
    scripted.finish('k-1')
    await sent
    expect(uploads.snapshot().get('k-1')?.phase).toEqual({ kind: 'bound' })
    replies[0]?.resolve(answer('published', 'k-1'))
    await cancelling
    expect(uploads.snapshot().get('k-1')?.phase).toEqual({ kind: 'bound' })
    const end = vi.fn(() => Promise.resolve())
    expect(await uploads.end('s-1', 'k-1', end)).toEqual(['k-1'])
    expect(end).toHaveBeenCalledTimes(1)
  })

  it.each([
    ['cancelled', 'adding'],
    ['asked', 'adding'],
    ['cancelled', 'bound'],
    ['asked', 'bound']
  ] as const)('K2: drops a late %s answer over a row that is %s', async (state, over) => {
    const { uploads, scripted, replies } = pending()
    let added: () => void = () => undefined
    const adding = new Promise<void>((resolve) => {
      added = resolve
    })
    const sent = uploads.send({ key: 'k-2', sessionId: 's-1', subject, file }, () => (over === 'adding' ? adding : Promise.resolve()))
    sent.catch(() => undefined)
    await wait(() => scripted.started.length === 1)
    const cancelling = uploads.cancel('k-2')
    scripted.finish('k-2')
    if (over === 'bound') await sent
    else await wait(() => uploads.snapshot().get('k-2')?.phase.kind === 'adding')
    replies[0]?.resolve(answer(state, 'k-2'))
    await cancelling
    expect(uploads.snapshot().get('k-2')?.phase.kind).toBe(over)
    added()
    await sent
    expect(uploads.snapshot().get('k-2')?.phase.kind).toBe('bound')
  })

  it('K3: an upload failure during cancelling lets the poll end the row', async () => {
    const { uploads, scripted, replies } = pending()
    const sent = uploads.send({ key: 'k-3', sessionId: 's-1', subject, file }, () => Promise.resolve())
    const failed = sent.catch(() => undefined)
    await wait(() => scripted.started.length === 1)
    const cancelling = uploads.cancel('k-3')
    // The upload fails for a reason of its own while the cancel waits for the host.
    scripted.refuse('k-3', { code: 'UNAVAILABLE', message: 'the host went away' })
    await failed
    replies[0]?.resolve(answer('asked', 'k-3'))
    await cancelling
    expect(uploads.snapshot().get('k-3')?.phase).toEqual({ kind: 'cancelAsked', said: null })
    // The application no longer lists the upload: a read of its list ends the row.
    await uploads.restore()
    expect(uploads.snapshot().get('k-3')?.phase).toEqual({ kind: 'cancelled', released: null })
  })

  it('K4: says the file was kept when its result comes while a cancel waits for its answer', async () => {
    const { uploads, scripted, replies } = pending()
    const sent = uploads.send({ key: 'k-4', sessionId: 's-1', subject, file }, () => Promise.resolve())
    await wait(() => scripted.started.length === 1)
    const cancelling = uploads.cancel('k-4')
    scripted.finish('k-4')
    await sent
    expect(uploads.snapshot().get('k-4')?.note).toBe(words.sentence(words.PUBLISHED_AND_KEPT))
    replies[0]?.resolve(answer('published', 'k-4'))
    await cancelling
  })
})

describe('a bind the application refuses for want of a record of the file', () => {
  const handle = {
    transfer_id: 't-1',
    environment_id: 'e-1',
    byte_len: '9',
    content_digest: 'b'.repeat(64),
    declared_media_type: 'application/octet-stream',
    original_file_name: 'left.bin',
    presented_as_image: false,
    session_id: null,
    preview: null,
    published_at_ms: '1',
    expires_at_ms: '2',
    submitted: false
  }
  const left: OpenUpload = {
    key: 'found-1',
    state: 'published',
    sessionId: 's-1',
    fileName: 'left.bin',
    byteLen: 9,
    acknowledgedChunks: 0,
    chunks: 0,
    stage: null,
    handle,
    said: null
  }

  it('Q1d: ends the row as refused, with the words, and no later list moves it', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: ['files.upload', 'agent.prompt'] })
    const uploads = new PairedUploads(port, 60_000)
    controls.pairedUploads.leave([left])
    await uploads.restore()
    expect(uploads.snapshot().get('found-1')?.phase).toEqual({ kind: 'kept', words: null })
    // A read of the list is made before the refusal, and its answer, the published upload, comes after it.
    const real = port.uploadsOpen.bind(port)
    const answers: (() => void)[] = []
    vi.spyOn(port, 'uploadsOpen').mockImplementationOnce(
      () =>
        new Promise((resolve, reject) => {
          answers.push(() => {
            real().then(resolve, reject)
          })
        })
    )
    const delayed = uploads.restore()
    await uploads.bind('found-1', handle, () => Promise.reject({ code: 'INVALID_ARGUMENT', message: words.NO_OPEN_UPLOAD }))
    const refused = { kind: 'refused', refusal: { kind: 'other', words: words.NO_LONGER_HELD } }
    expect(uploads.snapshot().get('found-1')?.phase).toEqual(refused)
    expect(canCancel(uploads.snapshot().get('found-1')?.phase ?? { kind: 'bound' })).toBe(false)
    answers[0]?.()
    expect(await delayed).toHaveLength(1)
    expect(uploads.snapshot().get('found-1')?.phase).toEqual(refused)
    // The application then lists nothing: the row stays, with its words, until the person removes it.
    controls.pairedUploads.leave([])
    await uploads.restore()
    expect(uploads.snapshot().get('found-1')?.phase).toEqual(refused)
    uploads.forget('found-1')
    expect(uploads.snapshot().has('found-1')).toBe(false)
  })
})

describe('the draft the application keeps is read as it answers it', () => {
  it('finds each bound transfer in the handle its attachment carries', () => {
    expect(
      boundIdsOf({ made: true, attachments: [{ handle: { transfer_id: 't-1' }, contribution: {} }] })
    ).toEqual(new Set(['t-1']))
    expect(boundIdsOf({ made: false, attachments: [] })).toEqual(new Set())
    expect(boundIdsOf(null)).toEqual(new Set())
  })
})
