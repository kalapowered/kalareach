/**
 * The phone's composer at a change of the account (KR-REQ-13.12): a file that was still being read
 * when the account changed is not sent for the new one, and a card the device kept for an earlier
 * sign-in is not offered to the account in force. The host is the scripted one.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, renderHook, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useEffect, type ReactNode } from 'react'

import { AppProvider, useApp } from '../../src/app/state'
import { fakeHost } from '../../src/host/fake'
import type { AttachmentHandle, OpenUpload } from '../../src/host/port'
import { MobileApp } from '../../src/mobile/MobileApp'
import { usePairedFiles } from '../../src/mobile/usePairedFiles'
import type { AccountView } from '../../src/model/account'
import { startDraft, type DraftAttachment } from '../../src/model/drafts'
import { FILES_OF_EARLIER_SIGN_IN_REMOVED, SIGN_IN_AGAIN } from '../../src/model/transfer-words'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const RIGHTS = ['session.view', 'files.upload', 'agent.prompt', 'terminal.input'] as const

afterEach(cleanup)

const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0))

const signedIn = (mark: string): AccountView => ({
  state: 'signed_in',
  email: null,
  name: null,
  usage_readable: false,
  generation: 'g',
  mark,
  outcome: null
})

// The test environment's `File` does not read itself; a phone's web view does.
if (typeof File.prototype.arrayBuffer !== 'function') {
  File.prototype.arrayBuffer = function arrayBuffer(this: File): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => {
        resolve(reader.result as ArrayBuffer)
      }
      reader.onerror = () => {
        reject(new Error('the file was not read'))
      }
      reader.readAsArrayBuffer(this)
    })
  }
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

describe('a file being read when the account changes', () => {
  it('is not sent for the new account, and its card is off the screen with the words for it', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: RIGHTS, organisation: true })
    const status = vi.spyOn(port, 'accountStatus')
    render(
      <AppProvider port={port} uploadPollMs={10}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    const person = userEvent.setup({ applyAccept: false })
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await screen.findByRole('group', { name: 'Add an attachment' })
    // The window has read the account once: what follows is a change.
    await waitFor(() => {
      expect(status).toHaveBeenCalled()
    })
    await Promise.all(status.mock.results.map((result) => result.value as Promise<unknown>))

    let release: () => void = () => undefined
    const read = new Promise<void>((resolve) => {
      release = resolve
    })
    const reading = vi.spyOn(File.prototype, 'arrayBuffer').mockImplementation(() => read.then(() => new ArrayBuffer(12)))
    try {
      const group = screen.getByRole('group', { name: 'Add an attachment' })
      const input = [...(group.parentElement?.querySelectorAll<HTMLInputElement>('input[type="file"]') ?? [])].find(
        (each) => each.getAttribute('accept') === '*/*'
      )
      if (input === undefined) throw new Error('no file input')
      await person.upload(input, new File([new Uint8Array(12)], 'report.pdf', { type: 'application/pdf' }))
      expect(screen.getByText('report.pdf')).toBeInTheDocument()

      controls.account.set(signedIn('aa'))
      expect(await screen.findByText(FILES_OF_EARLIER_SIGN_IN_REMOVED)).toBeInTheDocument()
      await waitFor(() => {
        expect(screen.queryByTestId('m-upload')).toBeNull()
      })

      release()
      // Long enough for the read to end and the upload, were it to start, to reach the host.
      await new Promise((resolve) => setTimeout(resolve, 100))
      expect(controls.pairedUploads.started).toHaveLength(0)
      expect(screen.queryByText(/was not sent/)).toBeNull()
    } finally {
      reading.mockRestore()
    }
  })
})

describe('a card the device kept for an earlier sign-in', () => {
  const card = (id: string): DraftAttachment => ({
    localId: `file-${id}`,
    transferId: id,
    name: `${id}.pdf`,
    byteLen: 10,
    mediaType: 'application/pdf',
    presentedAsImage: false,
    upload: 'uploaded',
    acceptedUpstream: false,
    handle: handleOf(id)
  })

  it('is dropped from the composer unless the application lists it or the kept draft holds it', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: RIGHTS, organisation: true })
    controls.pairedUploads.leave([
      {
        key: 'listed-1',
        state: 'published',
        sessionId: SESSION,
        fileName: 'listed.pdf',
        byteLen: 10,
        acknowledgedChunks: 0,
        chunks: 0,
        stage: null,
        handle: handleOf('t-listed'),
        said: null
      }
    ])
    controls.pairedUploads.bind({ session_id: SESSION, transfer_id: 't-bound', text: '' })
    const attachments = [card('t-listed'), card('t-bound'), card('t-foreign')]
    const draft = { ...startDraft('composer', { sessionId: SESSION, applicationInstanceId: null, agentBindingRevision: null }, 1), attachments }
    const changes: ((files: readonly DraftAttachment[]) => readonly DraftAttachment[])[] = []
    const wrapper = ({ children }: { children: ReactNode }) => <AppProvider port={port}>{children}</AppProvider>
    renderHook(
      () =>
        usePairedFiles({
          active: true,
          sessionId: SESSION,
          draft,
          nameSession: () => Promise.resolve({ sessionId: SESSION, sessionEpoch: '1' }),
          changeFiles: (change) => changes.push(change),
          removed: { current: new Set<string>() }
        }),
      { wrapper }
    )
    await waitFor(() => {
      expect(changes).toHaveLength(1)
    })
    const left = changes[0]?.(attachments) ?? []
    expect(left.map((each) => each.transferId)).toEqual(['t-listed', 't-bound'])
  })

  it('has the kept draft’s other files shown as bound cards by transfer, and no second card for one it has', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: RIGHTS, organisation: true })
    // The kept draft holds a file the composer has (as a card named by an upload key) and one it has not.
    controls.pairedUploads.keep(SESSION, handleOf('t-card'))
    controls.pairedUploads.keep(SESSION, handleOf('t-only-kept'))
    const own: DraftAttachment = { ...card('t-card'), localId: 'an-upload-key' }
    const draft = {
      ...startDraft('composer', { sessionId: SESSION, applicationInstanceId: null, agentBindingRevision: null }, 1),
      attachments: [own]
    }
    const changes: ((files: readonly DraftAttachment[]) => readonly DraftAttachment[])[] = []
    const wrapper = ({ children }: { children: ReactNode }) => <AppProvider port={port}>{children}</AppProvider>
    renderHook(
      () =>
        usePairedFiles({
          active: true,
          sessionId: SESSION,
          draft,
          nameSession: () => Promise.resolve({ sessionId: SESSION, sessionEpoch: '1' }),
          changeFiles: (change) => changes.push(change),
          removed: { current: new Set<string>() }
        }),
      { wrapper }
    )
    await waitFor(() => {
      expect(changes).toHaveLength(1)
    })
    const after = changes[0]?.([own]) ?? []
    expect(after.map((each) => [each.localId, each.transferId])).toEqual([
      ['an-upload-key', 't-card'],
      ['file-t-only-kept', 't-only-kept']
    ])
  })
})

describe('the files the device kept for the account in force, after a change of account', () => {
  it('are shown again as bound cards, once each', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: RIGHTS, organisation: true })
    controls.pairedUploads.keep(SESSION, handleOf('t-kept'))
    const status = vi.spyOn(port, 'accountStatus')
    render(
      <AppProvider port={port} uploadPollMs={10}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    const person = userEvent.setup({ applyAccept: false })
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    // The kept draft's file has a card when the session opens, with nothing sent from this window.
    await waitFor(() => {
      expect(screen.getAllByTestId('m-upload')).toHaveLength(1)
    })
    expect(screen.getByTestId('m-upload')).toHaveTextContent('t-kept.pdf')
    expect(screen.getByTestId('upload-line')).toHaveTextContent('Added to this draft')
    await Promise.all(status.mock.results.map((result) => result.value as Promise<unknown>))

    controls.account.set(signedIn('aa'))
    expect(await screen.findByText(FILES_OF_EARLIER_SIGN_IN_REMOVED)).toBeInTheDocument()
    // What the application keeps for the account is shown again, once.
    await waitFor(() => {
      expect(screen.getAllByTestId('m-upload')).toHaveLength(1)
    })
    expect(screen.getByTestId('m-upload')).toHaveTextContent('t-kept.pdf')
    expect(screen.getByTestId('upload-line')).toHaveTextContent('Added to this draft')
  })
})

describe('a submission whose commands wait while the account changes', () => {
  /**
   * The composer of a session whose kept draft holds a file, signed in as `aa`, with the text typed.
   * Native code refuses a command whose mark is no longer the account signed in: the scripted
   * commands that carry a mark do the same, and keep the marks they were made with.
   */
  async function composer() {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: RIGHTS, organisation: true })
    controls.pairedUploads.keep(SESSION, handleOf('t-kept'))
    const status = vi.spyOn(port, 'accountStatus')
    render(
      <AppProvider port={port} uploadPollMs={10}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    // The window has read the account once; A signs in, and its status is read.
    await waitFor(() => {
      expect(status).toHaveBeenCalled()
    })
    await Promise.all(status.mock.results.map((result) => result.value as Promise<unknown>))
    controls.account.set(signedIn('aa'))
    await waitFor(() => {
      expect(status.mock.calls.length).toBeGreaterThanOrEqual(2)
    })
    await Promise.all(status.mock.results.map((result) => result.value as Promise<unknown>))
    const person = userEvent.setup({ applyAccept: false })
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await waitFor(() => {
      expect(screen.getAllByTestId('m-upload')).toHaveLength(1)
    })
    await person.type(screen.getByRole('textbox', { name: 'Message this session' }), 'read the file')
    const signedInNow = { mark: 'aa' }
    const refusal = { code: 'PERMISSION_DENIED', message: SIGN_IN_AGAIN }
    const setText = port.draftSetText.bind(port)
    const submit = port.composerSubmit.bind(port)
    const marks = { setText: [] as (string | undefined)[], submit: [] as (string | undefined)[] }
    const held = { setText: null as (() => void) | null, claim: null as (() => void) | null }
    return {
      port,
      controls,
      person,
      marks,
      held,
      signIn: (mark: string) => {
        signedInNow.mark = mark
        controls.account.set(signedIn(mark))
      },
      /** The next claim of the stored draft waits for the test. */
      holdTheClaim: () => {
        const save = port.deviceDraftSave.bind(port)
        let holding = true
        vi.spyOn(port, 'deviceDraftSave').mockImplementation((request) => {
          if (!holding) return save(request)
          holding = false
          return new Promise((resolve, reject) => {
            held.claim = () => {
              save(request).then(resolve, reject)
            }
          })
        })
      },
      /** The text is set on the draft, and the reply to it waits for the test. */
      holdTheTextsReply: () => {
        vi.spyOn(port, 'draftSetText').mockImplementation(async (subject, sessionId, text, mark) => {
          marks.setText.push(mark)
          // eslint-disable-next-line @typescript-eslint/only-throw-error -- native code's refusal is data
          if (mark !== signedInNow.mark) throw refusal
          const answer = await setText(subject, sessionId, text, mark)
          await new Promise<void>((resolve) => {
            held.setText = resolve
          })
          return answer
        })
        vi.spyOn(port, 'composerSubmit').mockImplementation((params, opening, supersedes, mark) => {
          marks.submit.push(mark)
          if (mark !== signedInNow.mark) return Promise.reject(refusal)
          return submit(params, opening, supersedes, mark)
        })
      },
      /** Both commands are scripted as native code answers them, with no reply held. */
      refusingOtherAccounts: () => {
        vi.spyOn(port, 'draftSetText').mockImplementation((subject, sessionId, text, mark) => {
          marks.setText.push(mark)
          if (mark !== signedInNow.mark) return Promise.reject(refusal)
          return setText(subject, sessionId, text, mark)
        })
        vi.spyOn(port, 'composerSubmit').mockImplementation((params, opening, supersedes, mark) => {
          marks.submit.push(mark)
          if (mark !== signedInNow.mark) return Promise.reject(refusal)
          return submit(params, opening, supersedes, mark)
        })
      }
    }
  }

  it('G1a: carries the mark it was pressed under to the command that waited for the claim', async () => {
    const { controls, person, marks, held, signIn, holdTheClaim, refusingOtherAccounts } = await composer()
    refusingOtherAccounts()
    holdTheClaim()
    await person.click(screen.getByRole('button', { name: /^Send/ }))
    await waitFor(() => {
      expect(held.claim).not.toBeNull()
    })
    // B signs in while the claim waits: the window drops what it held for A.
    signIn('bb')
    expect(await screen.findByText(FILES_OF_EARLIER_SIGN_IN_REMOVED)).toBeInTheDocument()
    held.claim?.()
    // The command is made once the claim is let go: whatever mark it carries is what is asserted.
    await waitFor(() => {
      expect(marks.setText).toHaveLength(1)
    })
    expect(marks.setText).toEqual(['aa'])
    await tick()
    expect(marks.submit).toEqual([])
    expect(controls.promptParams).toHaveLength(0)
    expect(await screen.findByText(SIGN_IN_AGAIN)).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Message this session' })).toHaveValue('read the file')
  })

  it('G1b: carries the mark it was pressed under to the command that follows one whose reply waited', async () => {
    const { controls, person, marks, held, signIn, holdTheTextsReply } = await composer()
    holdTheTextsReply()
    await person.click(screen.getByRole('button', { name: /^Send/ }))
    await waitFor(() => {
      expect(held.setText).not.toBeNull()
    })
    signIn('bb')
    expect(await screen.findByText(FILES_OF_EARLIER_SIGN_IN_REMOVED)).toBeInTheDocument()
    held.setText?.()
    // The second command is made once the first one's reply is let go.
    await waitFor(() => {
      expect(marks.submit).toHaveLength(1)
    })
    expect(marks.setText).toEqual(['aa'])
    expect(marks.submit).toEqual(['aa'])
    expect(controls.promptParams).toHaveLength(0)
    expect(await screen.findByText(SIGN_IN_AGAIN)).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Message this session' })).toHaveValue('read the file')
  })
})

describe('a stored card, when the list of uploads cannot be read', () => {
  const stored = (id: string): DraftAttachment => ({
    localId: `file-${id}`,
    transferId: id,
    name: `${id}.pdf`,
    byteLen: 10,
    mediaType: 'application/pdf',
    presentedAsImage: false,
    upload: 'uploaded',
    acceptedUpstream: false,
    handle: handleOf(id)
  })

  /** The listed upload of `id`, published. */
  const listed = (id: string): OpenUpload => ({
    key: `listed-${id}`,
    state: 'published',
    sessionId: SESSION,
    fileName: `${id}.pdf`,
    byteLen: 10,
    acknowledgedChunks: 0,
    chunks: 0,
    stage: null,
    handle: handleOf(id),
    said: null
  })

  /** The hook on a composer that holds a stored card of the transfer `id`, whose list cannot be read at first. */
  function composerWith(id: string) {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: RIGHTS, organisation: true })
    const listing = vi.spyOn(port, 'uploadsOpen').mockRejectedValue(new Error('not in contact'))
    const add = vi.spyOn(port, 'draftAddAttachment')
    const attachments = [stored(id)]
    const draft = {
      ...startDraft('composer', { sessionId: SESSION, applicationInstanceId: null, agentBindingRevision: null }, 1),
      attachments
    }
    const changes: ((files: readonly DraftAttachment[]) => readonly DraftAttachment[])[] = []
    const wrapper = ({ children }: { children: ReactNode }) => <AppProvider port={port}>{children}</AppProvider>
    const app: { uploads: ReturnType<typeof useApp>['uploads'] | null } = { uploads: null }
    const { result } = renderHook(
      () => {
        app.uploads = useApp().uploads
        return usePairedFiles({
          active: true,
          sessionId: SESSION,
          draft,
          nameSession: () => Promise.resolve({ sessionId: SESSION, sessionEpoch: '1' }),
          changeFiles: (change) => changes.push(change),
          removed: { current: new Set<string>() }
        })
      },
      { wrapper }
    )
    const uploads = app.uploads
    if (uploads === null) throw new Error('the store was not read')
    /**
     * Asks for one more reconciliation and waits for it: the one the hook asked for is in the same
     * turn order, so when this has settled, that one has too.
     */
    const reconcile = () =>
      act(async () => {
        await uploads.reconcile(SESSION)
      })
    return { listing, add, attachments, changes, uploads, result, reconcile }
  }

  it('J1: is neither offered nor dropped while the list cannot be read, and is settled by the next list that can be', async () => {
    const { listing, add, attachments, changes, uploads, reconcile } = composerWith('t-stored')
    await reconcile()
    expect(listing).toHaveBeenCalled()
    expect(uploads.snapshot().has('file-t-stored')).toBe(false)
    expect(uploads.ready(SESSION)).toBe(false)
    expect(changes).toHaveLength(0)
    expect(add).not.toHaveBeenCalled()
    // A list that can be read and does not hold the card drops it.
    listing.mockResolvedValue([])
    await reconcile()
    expect(uploads.ready(SESSION)).toBe(true)
    expect(changes).toHaveLength(1)
    expect(changes[0]?.(attachments)).toEqual([])
  })

  it('J1: is kept, to be added, by a list that holds it', async () => {
    const { listing, add, changes, uploads, reconcile } = composerWith('t-stored')
    await reconcile()
    expect(uploads.ready(SESSION)).toBe(false)
    listing.mockResolvedValue([listed('t-stored')])
    await reconcile()
    expect(uploads.ready(SESSION)).toBe(true)
    expect(changes).toHaveLength(0)
    const row = [...uploads.snapshot().values()].find((each) => each.handle?.transfer_id === 't-stored')
    expect(row?.phase.kind).toBe('kept')
    expect(add).not.toHaveBeenCalled()
  })
})

const SIGNED_OUT: AccountView = { state: 'signed_out', outcome: null }

type App = ReturnType<typeof useApp>

/** Hands a test the window's own state, which the screens share: its draft book. */
function Keep({ onApp }: { readonly onApp: (app: App) => void }) {
  const app = useApp()
  useEffect(() => {
    onApp(app)
  })
  return null
}

/** Waits until every read of the account's status that was asked for has answered and was taken in. */
async function settled(status: { readonly mock: { readonly results: readonly { readonly value: unknown }[] } }) {
  await Promise.all(status.mock.results.map((result) => result.value as Promise<unknown>))
  await tick()
}

describe('the host the window was last connected to, as the phone follows the connection', () => {
  /** A file of the earlier sign-in on a composer, sent to the host `environment`. */
  const sentTo = (environment: string): DraftAttachment => ({
    localId: 'sent',
    transferId: 't-sent',
    name: 't-sent.pdf',
    byteLen: 10,
    mediaType: 'application/pdf',
    presentedAsImage: false,
    upload: 'uploaded',
    acceptedUpstream: false,
    handle: { ...handleOf('t-sent'), environment_id: environment }
  })

  it('is the host the connection feed showed, with no session opened: an account change after a reload clears its files', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: RIGHTS, organisation: true })
    controls.account.set(signedIn('aa'))
    const status = vi.spyOn(port, 'accountStatus')
    const kept: { app: App | null } = { app: null }
    render(
      <AppProvider port={port} uploadPollMs={10}>
        <MobileApp surface="ios" storage={null} />
        <Keep
          onApp={(app) => {
            kept.app = app
          }}
        />
      </AppProvider>
    )
    // The page was loaded while native code was already connected to the host: no session is opened.
    await waitFor(() => {
      expect(kept.app).not.toBeNull()
      expect(port.connectionLatest()?.connected).toBe(true)
    })
    await waitFor(() => {
      expect(status).toHaveBeenCalled()
    })
    await settled(status)
    const environment = port.connectionLatest()?.environment_id ?? ''
    kept.app?.drafts.update(SESSION, (draft) => ({ ...draft, attachments: [sentTo(environment)] }))

    controls.account.set(signedIn('bb'))
    expect(await screen.findByText(FILES_OF_EARLIER_SIGN_IN_REMOVED)).toBeInTheDocument()
    expect(kept.app?.drafts.draft(SESSION).attachments).toEqual([])
  })

  it('is the host last connected to: a move to a host that answers to no organisation, with no session open, leaves a sign-out nothing to clear', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: RIGHTS, organisation: true })
    controls.account.set(signedIn('aa'))
    const status = vi.spyOn(port, 'accountStatus')
    const kept: { app: App | null } = { app: null }
    render(
      <AppProvider port={port} uploadPollMs={10}>
        <MobileApp surface="ios" storage={null} />
        <Keep
          onApp={(app) => {
            kept.app = app
          }}
        />
      </AppProvider>
    )
    const person = userEvent.setup({ applyAccept: false })
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await screen.findByRole('group', { name: 'Add an attachment' })
    await waitFor(() => {
      expect(status).toHaveBeenCalled()
    })
    await settled(status)
    const environment = port.connectionLatest()?.environment_id ?? ''
    kept.app?.drafts.update(SESSION, (draft) => ({ ...draft, attachments: [sentTo(environment)] }))

    // The person leaves the session for the Hosts tab, which has no screen of its own that listens to the
    // connection, and the phone moves to a host that answers to no organisation.
    await person.click(screen.getByRole('button', { name: /^Hosts/ }))
    controls.reachAsPhone({ rights: RIGHTS, organisation: false })
    await waitFor(() => {
      expect(port.connectionLatest()?.organisation).toBe(false)
    })
    await tick()

    controls.account.set(SIGNED_OUT)
    await settled(status)
    expect(screen.queryByText(FILES_OF_EARLIER_SIGN_IN_REMOVED)).toBeNull()
    expect(kept.app?.drafts.draft(SESSION).attachments).toHaveLength(1)
  })
})
