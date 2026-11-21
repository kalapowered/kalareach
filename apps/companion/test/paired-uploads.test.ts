/**
 * What a person is told about a file sent to a paired host, and how the store of those files moves
 * (KR-REQ-13.12). The application's own sentences are held to the constants in the Rust files that
 * write them, so a change there cannot pass here unseen.
 */

import { describe, expect, it } from 'vitest'

import { fakeHost } from '../src/host/fake'
import { PairedUploads, canCancel, lineOf, type Phase } from '../src/model/paired-uploads'
import * as words from '../src/model/transfer-words'
import openTransfers from '../src-tauri/src/open_transfers.rs?raw'
import pairedDrafts from '../src-tauri/src/paired_drafts.rs?raw'

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

describe("the application's sentences are the ones the page recognises and shows", () => {
  it.each([
    ['open_transfers.rs', 'TOO_MANY_OPEN', words.TOO_MANY_OPEN],
    ['open_transfers.rs', 'CANNOT_RESUME', words.CANNOT_RESUME],
    ['open_transfers.rs', 'UNRECOVERABLE', words.UNRECOVERABLE],
    ['open_transfers.rs', 'CANCELLED', words.CANCELLED_BEFORE_SENT],
    ['paired_drafts.rs', 'GONE', words.DRAFT_GONE],
    ['paired_drafts.rs', 'GONE_FOR_TEXT', words.DRAFT_GONE_FOR_TEXT],
    ['paired_drafts.rs', 'NO_DRAFT', words.NO_DRAFT],
    ['paired_drafts.rs', 'UPDATE_THE_HOST', words.UPDATE_THE_HOST_TO_END_A_DRAFT]
  ])('%s %s', (file, name, constant) => {
    expect(constant).toBe(rustConstant(file, name))
  })

  it('states the sentence of a cancel that found the file published as the approved words', () => {
    expect(words.PUBLISHED_AND_KEPT).toBe(
      'this file was already sent in full and the host keeps it: it was not cancelled'
    )
  })

  it('changes only the first letter of a sentence', () => {
    expect(words.sentence(words.TOO_MANY_OPEN)).toBe(
      'Two files are being sent to this host already: wait for one to finish, or cancel one'
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
    for (const kind of ['cancelling', 'cancelled', 'adding', 'bound', 'kept', 'refused'] as const) {
      const phase = { kind, released: null, words: null, refusal: { kind: 'other', words: '' } } as Phase
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
