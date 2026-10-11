/**
 * A file attached to a draft is sent to the host on this computer and given a path there, which the
 * person gives to their agent themselves (KR-REQ-13.14, 24.09).
 *
 * These render the real application against the scripted host, whose draft for files applies the
 * rules the host applies: a binding names the revision of the draft it expects, a refusal changes
 * nothing, and an answer the page never hears can still have been applied. Nothing here inserts
 * anything into an agent, and the only insertion method the page declares is the manual one.
 */

import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import { useEffect } from 'react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'

import { App } from '../src/App'
import { AppProvider, useApp } from '../src/app/state'
import { AttachmentPaths } from '../src/components/AttachmentPaths'
import { AttachmentThumb } from '../src/components/AttachmentThumb'
import { fakeHost } from '../src/host/fake'
import type { AttachmentHandle } from '../src/host/port'
import { ManualPaths } from '../src/model/manual-paths'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'

afterEach(cleanup)

/** The application on the main session. */
function openSession() {
  const host = fakeHost()
  render(
    <AppProvider
      port={host.port}
      initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
    >
      <App />
    </AppProvider>
  )
  return host
}

/** A file the person drops on the window. */
function drop(controls: ReturnType<typeof fakeHost>['controls'], name = 'diagram.png') {
  controls.dropFiles([{ name, media_type: 'image/png', byte_len: 10, path: `/tmp/${name}` }])
}

describe('the path a dropped file can be read at', () => {
  it('is shown as text to select, with when it stops holding and that it is not quoted for a shell', async () => {
    const { controls } = openSession()
    await screen.findByTestId('composer-queue')

    drop(controls)

    const path = await screen.findByTestId('attachment-path')
    expect(path.tagName).toBe('CODE')
    expect(path).toHaveTextContent('/var/kalareach/attachments/')
    expect(path).toHaveTextContent('diagram.png')
    const row = screen.getByTestId('attachment-path-row')
    expect(row).toHaveTextContent(/not quoted for any shell/)
    expect(row).toHaveTextContent(/good until/)
    // The host drafted it for the session, with no application instance, and the only way the page
    // declared to insert the file is the manual one.
    expect(controls.hostDrafts.made).toHaveLength(1)
    expect(controls.hostDrafts.made[0]).toMatchObject({
      session_id: SESSION_MAIN,
      application_instance_id: null
    })
    expect(controls.hostDrafts.bound.map((each) => each.insertion_method)).toEqual([
      'manual_terminal_workflow'
    ])
  })

  it('binds a second file to the same host draft at the revision the first left', async () => {
    const { controls } = openSession()
    await screen.findByTestId('composer-queue')

    drop(controls, 'one.png')
    await screen.findByTestId('attachment-path')
    drop(controls, 'two.png')
    await waitFor(() => {
      expect(screen.getAllByTestId('attachment-path')).toHaveLength(2)
    })

    expect(controls.hostDrafts.made).toHaveLength(1)
    expect(controls.hostDrafts.bound.map((each) => each.expected_revision)).toEqual(['1', '2'])
  })

  it('says the path has expired once it has, and asks the host for a new one when the person asks', async () => {
    const person = userEvent.setup()
    const { controls } = openSession()
    await screen.findByTestId('composer-queue')
    // The host gives a path that is already past its time.
    controls.hostDrafts.setGrantLifetime(-1)
    drop(controls)

    expect(await screen.findByText(/has expired/)).toBeInTheDocument()
    expect(screen.queryByTestId('attachment-path')).toBeNull()

    controls.hostDrafts.setGrantLifetime(15 * 60_000)
    await person.click(screen.getByRole('button', { name: 'Get a new path' }))
    expect(await screen.findByTestId('attachment-path')).toBeInTheDocument()
    expect(controls.hostDrafts.bound).toHaveLength(2)
    // The same host draft, bound again as a new attempt at the revision the first left.
    expect(controls.hostDrafts.made).toHaveLength(1)
    expect(controls.hostDrafts.bound[1]?.expected_revision).toBe('2')
  })

  it('is not asked for over a host this device is paired with, and no file is sent', async () => {
    const { controls } = openSession()
    await screen.findByTestId('composer-queue')
    await act(async () => {
      controls.reachAsPairedDevice()
      await Promise.resolve()
    })

    drop(controls)

    expect(await screen.findByTestId('insertion-refusal')).toHaveTextContent(/takes no file/)
    expect(controls.uploaded).toEqual([])
    expect(controls.hostDrafts.made).toEqual([])
    expect(screen.queryByTestId('attachment-paths')).toBeNull()
  })

  it('is not asked for by a connection that does not hold the rights for a file', async () => {
    const { controls } = openSession()
    await screen.findByTestId('composer-queue')
    await act(async () => {
      controls.setRights(['session.view', 'agent.prompt'])
      await Promise.resolve()
    })

    drop(controls)

    expect(await screen.findByTestId('insertion-refusal')).toHaveTextContent(/not granted/)
    expect(controls.uploaded).toEqual([])
  })

  it('is refused in the host’s words when its session has ended, and the file stays on the draft', async () => {
    const person = userEvent.setup()
    const { controls } = openSession()
    await screen.findByTestId('composer-queue')
    controls.hostDrafts.refuseBinds({ code: 'SESSION_CLOSED', message: 'this session ended' })

    drop(controls)

    const refusal = await screen.findByTestId('attachment-path-refusal')
    expect(refusal).toHaveTextContent(/session has ended/)
    expect(refusal).not.toHaveTextContent('SESSION_CLOSED')
    // The file is still the draft's, and a prompt is still held back until the person removes it.
    expect(within(screen.getByTestId('draft-attachments')).getByText('Uploaded')).toBeInTheDocument()
    await person.type(screen.getByTestId('composer-input'), 'Look at this')
    expect(screen.getByTestId('composer-send')).toBeDisabled()
  })

  it('is refused in two steps when the session ended after the host draft was made, and the file stays', async () => {
    const person = userEvent.setup()
    const { controls } = openSession()
    await screen.findByTestId('composer-queue')
    // The closure moved the host's draft on, so the revision the window saw is stale.
    controls.hostDrafts.refuseBinds({ code: 'DRAFT_CONFLICT', message: 'the draft moved' })

    drop(controls)

    expect(await screen.findByTestId('attachment-path-refusal')).toHaveTextContent(
      /record of this session’s files changed/
    )
    // A new host draft for the ended session is refused as the session's closure.
    controls.hostDrafts.refuseBinds(null)
    controls.hostDrafts.refuseCreates({ code: 'SESSION_CLOSED', message: 'this session ended' })
    await person.click(screen.getByRole('button', { name: 'Try again' }))
    await waitFor(() => {
      expect(screen.getByTestId('attachment-path-refusal')).toHaveTextContent(/session has ended/)
    })
    expect(controls.hostDrafts.made).toHaveLength(1)
    expect(within(screen.getByTestId('draft-attachments')).getByText('Uploaded')).toBeInTheDocument()
  })

  it('says it was not told when the host did not confirm, and tries again from a new host draft', async () => {
    const person = userEvent.setup()
    const { controls } = openSession()
    await screen.findByTestId('composer-queue')
    controls.hostDrafts.leaveNextUnconfirmed('bind')

    drop(controls)

    expect(await screen.findByText(/did not say whether it gave this file a path/)).toBeInTheDocument()
    expect(screen.queryByTestId('attachment-path')).toBeNull()

    await person.click(screen.getByRole('button', { name: 'Try again' }))
    expect(await screen.findByTestId('attachment-path')).toBeInTheDocument()
    // The first draft's revision is not known to the window, so the second attempt made another.
    expect(controls.hostDrafts.made).toHaveLength(2)
    expect(controls.hostDrafts.bound[1]?.draft_id).toBe(controls.hostDrafts.made[1]?.draft_id)
    expect(controls.hostDrafts.bound[1]?.expected_revision).toBe('1')
  })
})

describe('what the chip and the path say of a file', () => {
  it('shows the picture the host made of an image, beside its name', async () => {
    const { controls } = openSession()
    await screen.findByTestId('composer-queue')

    drop(controls)

    const thumb = await screen.findByTestId('attachment-thumb')
    expect(thumb.getAttribute('src')).toMatch(/^data:image\/png;base64,[A-Za-z0-9+/]+=*$/)
    expect(thumb.getAttribute('alt')).toBe('')
    // In the chip of the file it is the picture of.
    expect(thumb.closest('.attachment-chip')).toHaveTextContent('diagram.png')
  })

  it('writes a thumbnail’s bytes as the address of a picture, whatever alphabet and padding the protocol gave them', () => {
    const base = {
      localId: 'file-1',
      transferId: 't',
      name: 'a.png',
      byteLen: 1,
      mediaType: 'image/png',
      presentedAsImage: true,
      upload: 'uploaded' as const,
      acceptedUpstream: false
    }
    const handle = (thumbnail: string) =>
      ({
        preview: { thumbnail }
      }) as unknown as AttachmentHandle
    // Unpadded base64url with both of its own characters, two bytes short of a whole group.
    render(<AttachmentThumb attachment={{ ...base, handle: handle('ab-_cd') }} />)
    expect(screen.getByTestId('attachment-thumb').getAttribute('src')).toBe(
      'data:image/png;base64,ab+/cd=='
    )
    cleanup()
    // No preview, no picture.
    render(<AttachmentThumb attachment={{ ...base, handle: { preview: null } as unknown as AttachmentHandle }} />)
    expect(screen.queryByTestId('attachment-thumb')).toBeNull()
  })

  it('shows a file sent for another session no path, whatever the window was given for it before', async () => {
    const host = fakeHost()
    const sent = await host.port.attachmentUpload('/tmp/moved.png', { sessionId: SESSION_MAIN })
    const file = (handle: AttachmentHandle) => ({
      localId: 'file-1',
      transferId: sent.transfer_id,
      name: 'moved.png',
      byteLen: 10,
      mediaType: 'image/png',
      presentedAsImage: true,
      upload: 'uploaded' as const,
      acceptedUpstream: false,
      handle
    })
    // The window's own book is given the path, by the file's first screen.
    function Primed({ handle }: { readonly handle: AttachmentHandle }) {
      const { paths } = useApp()
      useEffect(() => {
        void paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, sent)
      }, [paths])
      return (
        <AttachmentPaths
          sessionId={SESSION_MAIN}
          subject={{ sessionId: SESSION_MAIN }}
          attachments={[file(handle)]}
        />
      )
    }
    const view = render(
      <AppProvider port={host.port}>
        <Primed handle={sent} />
      </AppProvider>
    )
    expect(await screen.findByTestId('attachment-path')).toBeInTheDocument()

    // The draft moved to another session; the handle still says where the file was sent.
    view.rerender(
      <AppProvider port={host.port}>
        <Primed handle={{ ...sent, session_id: SESSION_BUILD }} />
      </AppProvider>
    )

    expect(await screen.findByTestId('attachment-path-refusal')).toHaveTextContent(/another session/)
    expect(screen.queryByTestId('attachment-path')).toBeNull()
  })
})

describe('the host’s draft for a session’s files', () => {
  const handle = (transfer: string, over: Partial<AttachmentHandle> = {}): AttachmentHandle => ({
    transfer_id: transfer,
    environment_id: '3f1a2c40-11aa-4b2c-9d3e-000000000001',
    byte_len: '10',
    content_digest: 'a'.repeat(64),
    declared_media_type: 'image/png',
    original_file_name: `${transfer}.png`,
    presented_as_image: true,
    session_id: null,
    preview: null,
    published_at_ms: '1',
    expires_at_ms: '2',
    submitted: false,
    ...over
  })

  /** A host with the handles of two published files, as an upload leaves them. */
  async function twoFiles() {
    const host = fakeHost()
    const one = await host.port.attachmentUpload('/tmp/one.png', { sessionId: SESSION_MAIN })
    const two = await host.port.attachmentUpload('/tmp/two.png', { sessionId: SESSION_MAIN })
    return { ...host, one, two, paths: new ManualPaths(host.port) }
  }

  it('is let go of after any failed call, so the next file starts from another draft', async () => {
    const { controls, one, two, paths } = await twoFiles()
    controls.hostDrafts.refuseBinds({ code: 'QUOTA_EXCEEDED', message: 'the host holds all it will' })
    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, one)
    expect(paths.snapshot().get(one.transfer_id)).toMatchObject({ kind: 'refused' })

    // A draft only grows and the window cannot read it, so a refusal leaves no draft in use.
    controls.hostDrafts.refuseBinds(null)
    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, one)
    expect(paths.snapshot().get(one.transfer_id)).toMatchObject({ kind: 'ready' })
    expect(controls.hostDrafts.made).toHaveLength(2)

    // A conflict says the window's view of the draft is wrong; the next attempt starts again too.
    controls.hostDrafts.refuseBinds({ code: 'DRAFT_CONFLICT', message: 'the draft moved' })
    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, two)
    controls.hostDrafts.refuseBinds(null)
    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, two)
    expect(controls.hostDrafts.made).toHaveLength(3)
    expect(paths.snapshot().get(two.transfer_id)).toMatchObject({ kind: 'ready' })
  })

  it('takes eight files, and binds the ninth to a draft of its own, with every path given', async () => {
    const host = fakeHost()
    const handles: AttachmentHandle[] = []
    for (let each = 0; each < 9; each += 1) {
      handles.push(await host.port.attachmentUpload(`/tmp/file-${String(each)}.png`, { sessionId: SESSION_MAIN }))
    }
    const paths = new ManualPaths(host.port)

    for (const each of handles) await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, each)

    for (const each of handles) {
      expect(paths.snapshot().get(each.transfer_id), each.original_file_name).toMatchObject({ kind: 'ready' })
    }
    expect(host.controls.hostDrafts.made).toHaveLength(2)
    expect(host.controls.hostDrafts.bound.at(-1)?.expected_revision).toBe('1')
  })

  it('gives a file asked for again its own draft’s next revision, not a new draft', async () => {
    const { controls, one, paths } = await twoFiles()
    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, one)
    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, one)

    expect(controls.hostDrafts.made).toHaveLength(1)
    expect(controls.hostDrafts.bound.map((each) => each.expected_revision)).toEqual(['1', '2'])
  })

  it('shows no path from a draft the host made and then did not confirm, and none from an answer with no grant', async () => {
    const { controls, one, two, paths } = await twoFiles()
    controls.hostDrafts.leaveNextUnconfirmed('create')
    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, one)
    expect(paths.snapshot().get(one.transfer_id)).toEqual({ kind: 'unconfirmed' })
    expect(controls.hostDrafts.bound).toEqual([])

    // The retry makes a draft of its own and binds at its first revision.
    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, one)
    expect(controls.hostDrafts.made).toHaveLength(2)
    expect(controls.hostDrafts.bound[0]).toMatchObject({
      draft_id: controls.hostDrafts.made[1]?.draft_id,
      expected_revision: '1'
    })

    controls.hostDrafts.leaveNextGrantless()
    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, two)
    expect(paths.snapshot().get(two.transfer_id)).toMatchObject({ kind: 'refused' })
    // The host did confirm the bind, so the retry names the same draft at its next revision.
    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, two)
    expect(paths.snapshot().get(two.transfer_id)).toMatchObject({ kind: 'ready' })
    expect(controls.hostDrafts.bound.at(-1)).toMatchObject({
      draft_id: controls.hostDrafts.made[1]?.draft_id,
      expected_revision: '3'
    })
    expect(controls.hostDrafts.made).toHaveLength(2)
  })

  it('shows no path from a grant that names another file or another method', async () => {
    const { controls, one, two, paths } = await twoFiles()
    // The host answers each bind with a draft, so the words are the window's own: the grant it gave
    // names another file, or another method.
    controls.hostDrafts.giveNextGrantTo({ transfer_id: two.transfer_id })
    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, one)
    expect(paths.snapshot().get(one.transfer_id)).toMatchObject({
      kind: 'refused',
      words: expect.stringContaining('gave no path') as string
    })

    controls.hostDrafts.giveNextGrantTo({ insertion_method: 'typed_submission' })
    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, two)
    expect(paths.snapshot().get(two.transfer_id)).toMatchObject({
      kind: 'refused',
      words: expect.stringContaining('gave no path') as string
    })
  })

  it('says a paired host takes no file, and asks the host for nothing', async () => {
    const { controls, one, paths } = await twoFiles()
    controls.reachAsPairedDevice()

    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, one)

    expect(paths.snapshot().get(one.transfer_id)).toMatchObject({
      kind: 'refused',
      words: 'A host this device is paired with takes no file from it, so this file gets no path here.'
    })
    expect(controls.hostDrafts.made).toEqual([])
  })

  it('is not made for a file that was sent for another session', async () => {
    const { controls, paths } = await twoFiles()
    const foreign = handle('99999999-9999-4999-8999-0000000000aa', { session_id: SESSION_BUILD })

    await paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, foreign)

    expect(paths.snapshot().get(foreign.transfer_id)).toMatchObject({
      kind: 'refused',
      words: expect.stringContaining('another session') as string
    })
    expect(controls.hostDrafts.made).toEqual([])
  })

  it('binds files one at a time, each at the revision the one before left', async () => {
    const { controls, one, two, paths } = await twoFiles()

    await Promise.all([
      paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, one),
      paths.attach(SESSION_MAIN, { sessionId: SESSION_MAIN }, two)
    ])

    expect(controls.hostDrafts.bound.map((each) => each.expected_revision)).toEqual(['1', '2'])
    expect(paths.snapshot().get(one.transfer_id)).toMatchObject({ kind: 'ready' })
    expect(paths.snapshot().get(two.transfer_id)).toMatchObject({ kind: 'ready' })
  })
})
