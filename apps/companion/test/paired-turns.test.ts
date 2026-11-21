/**
 * The order in which what is asked of one session's draft is done, and the reconciliation of the files
 * the device keeps for it (KR-REQ-13.12, 23.41): a bind, an end, a completion and a reconciliation take
 * turns in the order they were asked for, so a Remove takes the files that were being added with the
 * draft, a bind queued behind a Remove waits for the end, and nothing binds before the kept draft's
 * files are shown.
 */

import { describe, expect, it, vi } from 'vitest'

import { fakeHost } from '../src/host/fake'
import type { AttachmentHandle } from '../src/host/port'
import { PairedUploads, type UploadRow } from '../src/model/paired-uploads'
import { NEWER_DRAFT, sentence } from '../src/model/transfer-words'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const subject = { sessionId: SESSION, sessionEpoch: '1' }
const file = { name: 'a.pdf', bytes: new Uint8Array(10) }
const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0))

function deferred<T = void>() {
  let resolve: (value: T) => void = () => undefined
  let reject: (failure: unknown) => void = () => undefined
  const promise = new Promise<T>((yes, no) => {
    resolve = yes
    reject = no
  })
  return { promise, resolve, reject }
}

const handle = (id: string): AttachmentHandle => ({
  transfer_id: id,
  environment_id: 'env',
  byte_len: '10',
  content_digest: 'b'.repeat(64),
  declared_media_type: 'application/pdf',
  original_file_name: `${id}.pdf`,
  presented_as_image: false,
  session_id: null,
  preview: null,
  published_at_ms: '1',
  expires_at_ms: '2',
  submitted: false
})

function window() {
  const { port, controls } = fakeHost()
  controls.reachAsPhone({ rights: ['files.upload', 'agent.prompt'] })
  const uploads = new PairedUploads(port, 1000)
  /** A row as the composer notes it, bound or only kept. */
  const note = (key: string, bound: boolean) => {
    const row: UploadRow = {
      key,
      sessionId: SESSION,
      name: `${key}.pdf`,
      byteLen: 10,
      phase: { kind: 'bound' },
      handle: handle(key),
      note: null,
      awaited: false
    }
    uploads.noteFiles([{ row, bound }])
  }
  const phase = (key: string) => uploads.snapshot().get(key)?.phase.kind
  return { uploads, controls, note, phase }
}

describe('what is asked of a session runs in the order it was asked for', () => {
  it('waits for a bind that was being added, and takes that file with the draft', async () => {
    const { uploads, controls, note, phase } = window()
    note('A', true)
    const bindingB = deferred()
    const sentB = uploads.send({ key: 'B', sessionId: SESSION, subject, file }, () => bindingB.promise)
    await vi.waitFor(() => expect(controls.pairedUploads.started).toHaveLength(1))
    controls.pairedUploads.finish('B')
    await vi.waitFor(() => expect(phase('B')).toBe('adding'))

    const end = vi.fn(() => Promise.resolve())
    const ending = uploads.end(SESSION, 'A', end)
    await tick()
    expect(end).not.toHaveBeenCalled()

    bindingB.resolve()
    await sentB
    expect(await ending).toEqual(['A', 'B'])
    expect(end).toHaveBeenCalledTimes(1)
    expect(uploads.snapshot().size).toBe(0)
  })

  it('makes a bind queued behind a remove wait for the end, and leaves that file out of the end', async () => {
    const { uploads, note, phase } = window()
    note('A', true)
    note('C', false)
    const ended = deferred()
    const ending = uploads.end(SESSION, 'A', () => ended.promise)
    await tick()
    const bind = vi.fn(() => Promise.resolve())
    const binding = uploads.bind('C', handle('C'), bind)
    await tick()
    expect(bind).not.toHaveBeenCalled()
    expect(phase('C')).toBe('adding')

    ended.resolve()
    expect(await ending).toEqual(['A'])
    await binding
    expect(bind).toHaveBeenCalledTimes(1)
    expect(phase('C')).toBe('bound')
    expect(phase('A')).toBeUndefined()
  })

  it('keeps every row when the end fails, and says what failed', async () => {
    const { uploads, note, phase } = window()
    note('A', true)
    const refused = { code: 'HOST_NOT_CONFIGURED', message: 'the host is not connected' }
    await expect(uploads.end(SESSION, 'A', () => Promise.reject(refused))).rejects.toBe(refused)
    expect(phase('A')).toBe('bound')
    // A later turn still runs: a failed one does not hold the queue.
    expect(await uploads.end(SESSION, 'A', () => Promise.resolve())).toEqual(['A'])
  })

  it('deletes only the rows that went with the prompt the host performed', async () => {
    const { uploads, note, phase } = window()
    note('A', true)
    note('C', true)
    await uploads.completeSent(SESSION, new Set(['A']))
    expect(phase('A')).toBeUndefined()
    expect(phase('C')).toBe('bound')
  })
})

describe('the reconciliation of a session with the draft the device keeps', () => {
  const attached = (read: () => Promise<readonly AttachmentHandle[]>) => {
    const w = window()
    const apply = vi.fn()
    w.uploads.attach(SESSION, { read, apply })
    return { ...w, apply }
  }

  it('is not ready until the kept draft is read and shown, and a bind waits for it', async () => {
    const reading = deferred<readonly AttachmentHandle[]>()
    const { uploads, note, phase, apply } = attached(() => reading.promise)
    expect(uploads.ready(SESSION)).toBe(false)
    note('C', false)
    const bind = vi.fn(() => Promise.resolve())
    const reconciling = uploads.reconcile(SESSION)
    const binding = uploads.bind('C', handle('C'), bind)
    await tick()
    expect(bind).not.toHaveBeenCalled()
    expect(uploads.ready(SESSION)).toBe(false)

    reading.resolve([handle('F')])
    await reconciling
    await binding
    expect(apply).toHaveBeenCalledWith([handle('F')])
    expect(uploads.ready(SESSION)).toBe(true)
    expect(bind).toHaveBeenCalledTimes(1)
    expect(phase('C')).toBe('bound')
    // The bind came after what was shown, not before.
    expect(apply.mock.invocationCallOrder[0]).toBeLessThan(bind.mock.invocationCallOrder[0] ?? 0)
  })

  it('stays not ready when the kept draft cannot be read, and binds nothing for it', async () => {
    const failure = { code: 'HOST_NOT_CONFIGURED', message: 'the host is not connected' }
    const { uploads, note, phase, apply } = attached(() => Promise.reject(failure))
    note('C', false)
    const bind = vi.fn(() => Promise.resolve())
    await uploads.reconcile(SESSION)
    expect(uploads.ready(SESSION)).toBe(false)
    await uploads.bind('C', handle('C'), bind)
    expect(bind).not.toHaveBeenCalled()
    expect(apply).not.toHaveBeenCalled()
    expect(uploads.snapshot().get('C')?.phase).toEqual({ kind: 'kept', words: 'The host is not connected' })
    expect(phase('C')).toBe('kept')
  })

  it('says the application’s own words for a kept draft it cannot read, not a right the device lacks', async () => {
    // The application refuses it with the code of a missing right.
    const failure = { code: 'PERMISSION_DENIED', message: NEWER_DRAFT }
    const { uploads, note } = attached(() => Promise.reject(failure))
    note('C', false)
    await uploads.bind('C', handle('C'), () => Promise.resolve())
    expect(uploads.ready(SESSION)).toBe(false)
    expect(uploads.snapshot().get('C')?.phase).toEqual({ kind: 'kept', words: sentence(NEWER_DRAFT) })
  })

  it('starts one for a bind that finds none in this cycle', async () => {
    const read = vi.fn(() => Promise.resolve([] as readonly AttachmentHandle[]))
    const { uploads, note, phase } = attached(read)
    note('C', false)
    await uploads.bind('C', handle('C'), () => Promise.resolve())
    expect(read).toHaveBeenCalledTimes(1)
    expect(phase('C')).toBe('bound')
  })

  it('is not ready after a reset until the session is reconciled again, and shows nothing of a read that began before it', async () => {
    const reading = deferred<readonly AttachmentHandle[]>()
    const { uploads, apply } = attached(() => reading.promise)
    const reconciling = uploads.reconcile(SESSION)
    uploads.reset()
    reading.resolve([handle('F')])
    await reconciling
    expect(apply).not.toHaveBeenCalled()
    expect(uploads.ready(SESSION)).toBe(false)
  })
})
