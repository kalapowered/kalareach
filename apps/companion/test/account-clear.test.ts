/**
 * What the window does when the account signed in changes (KR-REQ-13.12). What native code keeps for
 * an account stays with it; this window's cache of the files goes, on a host that answers to an
 * organisation, and the composer's text is left alone.
 */

import { describe, expect, it, vi, type MockInstance } from 'vitest'

import { followAccountChange } from '../src/app/account-clear'
import { fakeHost } from '../src/host/fake'
import type { AttachmentHandle, HostPort } from '../src/host/port'
import { AccountMark, ConnectedHost, stampedPort } from '../src/host/stamped'
import type { AccountView } from '../src/model/account'
import { DraftBook } from '../src/model/draft-book'
import type { DraftAttachment } from '../src/model/drafts'
import { edit } from '../src/model/drafts'
import { PairedUploads, ResetError } from '../src/model/paired-uploads'
import { FILES_OF_EARLIER_SIGN_IN_REMOVED } from '../src/model/transfer-words'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const subject = { sessionId: SESSION, sessionEpoch: '1' }
const file = { name: 'a.pdf', bytes: new Uint8Array(10) }

const signedIn = (mark: string): AccountView => ({
  state: 'signed_in',
  email: null,
  name: null,
  usage_readable: false,
  generation: 'g',
  mark,
  outcome: null
})
const SIGNED_OUT: AccountView = { state: 'signed_out', outcome: null }

const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0))

/** Waits until every read of the account's status that was asked for has answered and its answer was taken in. */
async function answered(status: MockInstance<HostPort['accountStatus']>): Promise<void> {
  await Promise.all(status.mock.results.map((result) => result.value as Promise<unknown>))
  await tick()
}

function handleOf(id: string): AttachmentHandle {
  return {
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
  }
}

const card = (localId: string, change: Partial<DraftAttachment>): DraftAttachment => ({
  localId,
  transferId: null,
  name: `${localId}.pdf`,
  byteLen: 10,
  mediaType: 'application/pdf',
  presentedAsImage: false,
  upload: 'uploaded',
  acceptedUpstream: false,
  handle: null,
  ...change
})

/**
 * A window that follows the account over the scripted host, once it has read the account and the
 * connection. `publish` sends the window an account event the account's own state does not stand
 * behind, as a publication that is older than the account is.
 */
async function following(options: { organisation: boolean; first?: AccountView }) {
  const { port: raw, controls } = fakeHost()
  if (options.first !== undefined) controls.account.set(options.first)
  controls.reachAsPhone({ rights: ['files.upload', 'agent.prompt'], organisation: options.organisation })
  const heard: ((view: AccountView) => void)[] = []
  const port: HostPort = {
    ...raw,
    onAccount: (listener) => {
      heard.push(listener)
      return raw.onAccount(listener)
    }
  }
  const status = vi.spyOn(port, 'accountStatus')
  const mark = new AccountMark()
  const uploads = new PairedUploads(port, 5)
  const drafts = new DraftBook(port)
  const said: string[] = []
  // The page's screens read and hear the connection through the stamped port, which tells the tracker.
  const host = new ConnectedHost()
  const screens = stampedPort(port, mark.read, host.note)
  await screens.onConnection(() => undefined)
  await screens.connectionState()
  const stop = followAccountChange({ port, mark, host, uploads, drafts, say: (text) => said.push(text) })
  await answered(status)
  await tick()
  return {
    port,
    screens,
    controls,
    status,
    mark,
    uploads,
    drafts,
    said,
    stop,
    publish: (view: AccountView) => heard.forEach((listener) => listener(view)),
    /** The account changes, as the account itself says, and the window has read it. */
    async change(view: AccountView) {
      controls.account.set(view)
      await answered(status)
    }
  }
}

describe('the files of an earlier sign-in at a change of the account', () => {
  it('takes the rows and the files off the composers, keeps the text, discards nothing and says so once', async () => {
    const window = await following({ organisation: true, first: signedIn('aa') })
    const { uploads, drafts, port, said, controls } = window
    const discard = vi.spyOn(port, 'deviceDraftDiscard')
    const end = vi.spyOn(port, 'draftEnd')
    const bind = vi.fn(() => Promise.resolve())
    const sent = uploads.send({ key: 'k-1', sessionId: SESSION, subject, file }, bind)
    const failed = sent.catch((failure: unknown) => failure)
    drafts.update(SESSION, (draft) => ({
      ...edit(draft, 'my own words', Date.now()),
      attachments: [
        card('going', { upload: 'uploading' }),
        card('sent', { handle: handleOf('t-1'), transferId: 't-1' }),
        card('failed', { upload: 'failed' })
      ]
    }))
    expect(uploads.snapshot().size).toBe(1)

    await window.change(signedIn('bb'))

    expect(uploads.snapshot().size).toBe(0)
    expect(drafts.draft(SESSION).attachments.map((each) => each.localId)).toEqual(['failed'])
    expect(drafts.draft(SESSION).text).toBe('my own words')
    expect(said).toEqual([FILES_OF_EARLIER_SIGN_IN_REMOVED])
    expect(discard).not.toHaveBeenCalled()
    expect(end).not.toHaveBeenCalled()

    // The upload the earlier sign-in started ends for the page without a row and without a bind.
    await vi.waitFor(() => expect(controls.pairedUploads.started).toHaveLength(1))
    controls.pairedUploads.finish('k-1')
    expect(await failed).toBeInstanceOf(ResetError)
    expect(bind).not.toHaveBeenCalled()
    expect(uploads.snapshot().size).toBe(0)

    // A change with nothing left to take off says nothing more.
    await window.change(signedIn('cc'))
    expect(said).toHaveLength(1)
  })

  it('does nothing at a renewal, at a browser that opens, at a sign-in that finishes or at a status it cannot read', async () => {
    const window = await following({ organisation: true, first: signedIn('aa') })
    window.uploads.send({ key: 'k-1', sessionId: SESSION, subject, file }, () => Promise.resolve()).catch(() => undefined)
    for (const view of [
      signedIn('aa'),
      { state: 'browser_open' } as const,
      { state: 'finishing' } as const,
      { state: 'unreadable' } as const
    ] satisfies AccountView[]) {
      await window.change(view)
    }
    expect(window.uploads.cycle).toBe(0)
    expect(window.uploads.snapshot().size).toBe(1)
    expect(window.said).toEqual([])
  })

  it('takes the first view as a baseline, and clears at a sign-out', async () => {
    const window = await following({ organisation: true, first: signedIn('aa') })
    expect(window.uploads.cycle).toBe(0)
    window.uploads.send({ key: 'k-1', sessionId: SESSION, subject, file }, () => Promise.resolve()).catch(() => undefined)
    await window.change(SIGNED_OUT)
    expect(window.uploads.cycle).toBe(1)
    expect(window.uploads.snapshot().size).toBe(0)
    expect(window.said).toEqual([FILES_OF_EARLIER_SIGN_IN_REMOVED])
    expect(window.mark.current).toBeUndefined()
  })

  it('clears nothing at a publication older than the account: the read that follows it says the account is as it was', async () => {
    const window = await following({ organisation: true, first: signedIn('bb') })
    window.uploads.send({ key: 'k-1', sessionId: SESSION, subject, file }, () => Promise.resolve()).catch(() => undefined)
    // The account is signed in as bb, and a signed-out publication from before that arrives late.
    window.publish(SIGNED_OUT)
    await answered(window.status)
    expect(window.uploads.cycle).toBe(0)
    expect(window.uploads.snapshot().size).toBe(1)
    expect(window.said).toEqual([])
    expect(window.mark.current).toBe('bb')
  })

  it('takes the newest read of the status, and drops an older one that answers after it', async () => {
    const window = await following({ organisation: true, first: signedIn('aa') })
    window.uploads.send({ key: 'k-1', sessionId: SESSION, subject, file }, () => Promise.resolve()).catch(() => undefined)
    let late: (view: AccountView) => void = () => undefined
    window.status.mockImplementationOnce(
      () =>
        new Promise<AccountView>((resolve) => {
          late = resolve
        })
    )
    // The first event's read is slow; the account moves on to bb and the second read says so.
    window.publish(SIGNED_OUT)
    window.controls.account.set(signedIn('bb'))
    await tick()
    await tick()
    expect(window.uploads.cycle).toBe(1)
    late(SIGNED_OUT)
    await tick()
    // The older answer, signed out, changed nothing: bb is still the account, and one clear was made.
    expect(window.uploads.cycle).toBe(1)
    expect(window.mark.current).toBe('bb')
    expect(window.said).toHaveLength(1)
  })

  it('clears nothing on a host that answers to no organisation', async () => {
    const window = await following({ organisation: false, first: signedIn('aa') })
    window.uploads.send({ key: 'k-1', sessionId: SESSION, subject, file }, () => Promise.resolve()).catch(() => undefined)
    window.drafts.update(SESSION, (draft) => ({
      ...draft,
      attachments: [card('sent', { handle: handleOf('t-1'), transferId: 't-1' })]
    }))
    await window.change(signedIn('bb'))
    await window.change(SIGNED_OUT)
    expect(window.uploads.cycle).toBe(0)
    expect(window.uploads.snapshot().size).toBe(1)
    expect(window.drafts.draft(SESSION).attachments).toHaveLength(1)
    expect(window.said).toEqual([])
  })

  it('clears at a sign-out that ended the connection first', async () => {
    const window = await following({ organisation: true, first: signedIn('aa') })
    window.uploads.send({ key: 'k-1', sessionId: SESSION, subject, file }, () => Promise.resolve()).catch(() => undefined)
    // The connection ends, and the host last in use is still the one the account's files belong to.
    await window.port.hostsForget('studio-reference')
    await tick()
    expect((await window.screens.connectionState()).connected).toBe(false)
    await window.change(SIGNED_OUT)
    expect(window.uploads.cycle).toBe(1)
    expect(window.said).toEqual([FILES_OF_EARLIER_SIGN_IN_REMOVED])
  })

  it('leaves the window alone when it moved to the host on this computer before the account changed', async () => {
    const window = await following({ organisation: true, first: signedIn('aa') })
    window.uploads.send({ key: 'k-1', sessionId: SESSION, subject, file }, () => Promise.resolve()).catch(() => undefined)
    window.drafts.update(SESSION, (draft) => ({
      ...edit(draft, 'on this computer', Date.now()),
      attachments: [card('sent', { handle: handleOf('t-1'), transferId: 't-1' })]
    }))
    window.controls.reachAsOwner()
    await tick()
    expect((await window.screens.connectionState()).connected).toBe(true)
    await window.change(signedIn('bb'))
    await window.change(SIGNED_OUT)
    expect(window.uploads.cycle).toBe(0)
    expect(window.uploads.snapshot().size).toBe(1)
    expect(window.drafts.draft(SESSION).attachments.map((each) => each.localId)).toEqual(['sent'])
    expect(window.drafts.draft(SESSION).text).toBe('on this computer')
    expect(window.said).toEqual([])
  })
})

describe('what an earlier cycle was waiting for changes nothing after the clear', () => {
  it('makes no row from a read of the open uploads that was asked for before it, and reads again when asked', async () => {
    const { port: raw, controls } = fakeHost()
    controls.reachAsPhone({ rights: ['files.upload'] })
    let release: (views: Awaited<ReturnType<HostPort['uploadsOpen']>>) => void = () => undefined
    const held = new Promise<Awaited<ReturnType<HostPort['uploadsOpen']>>>((resolve) => {
      release = resolve
    })
    const port: HostPort = { ...raw }
    const open = vi.spyOn(port, 'uploadsOpen').mockImplementationOnce(() => held)
    const uploads = new PairedUploads(port, 1000)
    const old = uploads.restore()
    uploads.reset()
    controls.pairedUploads.leave([
      {
        key: 'found-2',
        state: 'waiting',
        sessionId: SESSION,
        fileName: 'b.pdf',
        byteLen: 5,
        acknowledgedChunks: 0,
        chunks: 0,
        stage: null,
        handle: null,
        said: null
      }
    ])
    // A read after the reset is its own, and is not held back by the one that is still waiting.
    const listed = await uploads.restore()
    expect(open).toHaveBeenCalledTimes(2)
    expect(listed?.map((view) => view.key)).toEqual(['found-2'])
    expect([...uploads.snapshot().keys()]).toEqual(['found-2'])
    // The old read answers with an upload of the earlier cycle: it makes no row.
    release([
      {
        key: 'old-1',
        state: 'waiting',
        sessionId: SESSION,
        fileName: 'a.pdf',
        byteLen: 5,
        acknowledgedChunks: 0,
        chunks: 0,
        stage: null,
        handle: null,
        said: null
      }
    ])
    expect(await old).toBeNull()
    expect([...uploads.snapshot().keys()]).toEqual(['found-2'])
    uploads.reset()
  })

  it('binds nothing for a file whose upload ended after the clear', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: ['files.upload', 'agent.prompt'] })
    const uploads = new PairedUploads(port, 1000)
    const bind = vi.fn(() => Promise.resolve())
    const sent = uploads.send({ key: 'k-1', sessionId: SESSION, subject, file }, bind)
    await vi.waitFor(() => expect(controls.pairedUploads.started).toHaveLength(1))
    uploads.reset()
    controls.pairedUploads.finish('k-1')
    await expect(sent).rejects.toBeInstanceOf(ResetError)
    expect(bind).not.toHaveBeenCalled()
    expect(uploads.snapshot().size).toBe(0)
  })

  it('does not put the files of an earlier sign-in back when a prompt sent before the clear is refused after it', async () => {
    const { port } = fakeHost()
    const drafts = new DraftBook(port)
    await drafts.hydrate()
    drafts.update(SESSION, (draft) => ({
      ...edit(draft, 'read this', Date.now()),
      attachments: [card('sent', { handle: handleOf('t-1'), transferId: 't-1' })]
    }))
    await drafts.settled()
    const token = drafts.beginSend(SESSION)
    // The composer clears when the person presses Send; then the account changes.
    drafts.update(SESSION, (draft) => ({ ...edit(draft, '', Date.now()), attachments: [] }))
    expect(drafts.dropUploads()).toBe(0)
    drafts.endSend(token, 'refused')
    await drafts.settled()
    // The text comes back; the file of the earlier sign-in does not.
    expect(drafts.draft(SESSION).text).toBe('read this')
    expect(drafts.draft(SESSION).attachments).toEqual([])
  })
})
