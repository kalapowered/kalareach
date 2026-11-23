/**
 * The phone's screens for files sent to a host it is paired with (KR-REQ-13.12, 13.17, 23.41): the
 * composer shows where each file stands in words and with a bar, each refusal says what to do, a
 * cancel is shown only from its answer, and the files bound to the draft go with the prompt that
 * names it. The host is the scripted one, which keeps an upload open until a test moves it on.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { ActionRight } from '@kalareach/protocol'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls } from '../../src/host/fake'
import { receivedFailure } from '../../src/host/tauri'
import { MobileApp } from '../../src/mobile/MobileApp'
import { HANDED_FILE_LIMIT } from '../../src/mobile/model/media'
import * as words from '../../src/model/transfer-words'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const RIGHTS = ['session.view', 'files.upload', 'agent.prompt', 'terminal.input'] as const

afterEach(cleanup)

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

async function open(rights: readonly ActionRight[] = RIGHTS): Promise<{ controls: FakeHostControls; person: ReturnType<typeof userEvent.setup>; port: ReturnType<typeof fakeHost>['port'] }> {
  const { port, controls } = fakeHost()
  controls.reachAsPhone({ rights })
  render(
    <AppProvider port={port} uploadPollMs={10}>
      <MobileApp surface="ios" storage={null} />
    </AppProvider>
  )
  const person = userEvent.setup({ applyAccept: false })
  await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
  await person.click(await screen.findByRole('button', { name: /Session 1/ }))
  await screen.findByRole('group', { name: 'Add an attachment' })
  return { controls, person, port }
}

function filesInput(): HTMLInputElement {
  const group = screen.getByRole('group', { name: 'Add an attachment' })
  const input = [...(group.parentElement?.querySelectorAll<HTMLInputElement>('input[type="file"]') ?? [])].find(
    (each) => each.getAttribute('accept') === '*/*'
  )
  if (input === undefined) throw new Error('no file input')
  return input
}

async function pick(person: ReturnType<typeof userEvent.setup>, name = 'report.pdf', size = 12): Promise<void> {
  await person.upload(filesInput(), new File([new Uint8Array(size)], name, { type: 'application/pdf' }))
}

const line = () => screen.getByTestId('upload-line').textContent
const lineOfFile = (name: string) =>
  within(screen.getAllByTestId('m-upload').find((row) => within(row).queryByText(name) !== null) as HTMLElement)

async function started(controls: FakeHostControls, count = 1) {
  await waitFor(() => {
    expect(controls.pairedUploads.started).toHaveLength(count)
  })
  return controls.pairedUploads.started[count - 1]?.key ?? ''
}

describe('a file picked on a phone paired with a host', () => {
  it('is checked with the host at once, with a way to cancel it, and names the session it is for', async () => {
    const { controls, person } = await open()
    await pick(person)
    const key = await started(controls)
    expect(line()).toBe('Checking with the host')
    expect(screen.getByRole('button', { name: 'Cancel sending report.pdf' })).toBeInTheDocument()
    expect(key).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    expect(controls.pairedUploads.started[0]).toMatchObject({ name: 'report.pdf', byteLen: 12, sessionId: SESSION })
  })

  it('starts nothing for a file the person cancelled before the page had read it', async () => {
    const { controls, person } = await open()
    // The page reads the file before the application hears of it, and the card is on the screen,
    // with its Cancel, all that while.
    let release: () => void = () => undefined
    const read = new Promise<void>((resolve) => {
      release = resolve
    })
    const reading = vi.spyOn(File.prototype, 'arrayBuffer').mockImplementation(() => read.then(() => new ArrayBuffer(12)))
    try {
      await pick(person)
      await person.click(screen.getByRole('button', { name: 'Cancel sending report.pdf' }))
      await waitFor(() => {
        expect(line()).toBe('Cancelled.')
      })
      release()
      // Long enough for the read to end and the upload, were it to start, to reach the host.
      await new Promise((resolve) => setTimeout(resolve, 100))
      expect(controls.pairedUploads.started).toHaveLength(0)
      expect(line()).toBe('Cancelled.')
    } finally {
      reading.mockRestore()
    }
  })

  it('shows how far it is in words and in a bar, follows a lost connection, and ends added to the draft', async () => {
    const { controls, person } = await open()
    await pick(person)
    const key = await started(controls)
    const host = controls.pairedUploads

    act(() => {
      host.progress(key, 3, 12)
    })
    await waitFor(() => {
      expect(line()).toBe('Sending, 25%')
    })
    const bar = screen.getByRole('progressbar', { name: 'Sending report.pdf' })
    expect(bar).toHaveAttribute('aria-valuenow', '25')

    act(() => {
      host.pause(key)
    })
    await waitFor(() => {
      expect(line()).toBe('Paused: the host is out of reach. Sending resumes when contact returns.')
    })
    act(() => {
      host.resume(key)
    })
    await waitFor(() => {
      expect(line()).toBe('Resuming at chunk 4 of 12')
    })
    act(() => {
      host.publishing(key)
    })
    await waitFor(() => {
      expect(line()).toBe('Finishing with the host')
    })
    act(() => {
      host.finish(key)
    })
    await waitFor(() => {
      expect(line()).toBe('Added to this draft')
    })
    expect(screen.getByText('report.pdf is sent and added to this draft.')).toBeInTheDocument()
    expect(screen.getByText('12 bytes')).toBeInTheDocument()
    expect(host.binds).toHaveLength(1)
    expect(host.binds[0]).toMatchObject({ session_id: SESSION })
    expect(screen.queryByRole('progressbar')).toBeNull()
  })

  it('shows a cancel only as it is answered: under way first, then what the host released', async () => {
    const { controls, person } = await open()
    await pick(person)
    await started(controls)
    controls.pairedUploads.holdCancels()
    await person.click(screen.getByRole('button', { name: 'Cancel sending report.pdf' }))
    await waitFor(() => {
      expect(line()).toBe('Cancelling')
    })
    // The control keeps its place, and does nothing again while the host has not answered.
    await person.click(screen.getByRole('button', { name: 'Cancel sending report.pdf' }))
    expect(controls.pairedUploads.cancels).toHaveLength(1)
    expect(line()).not.toMatch(/released/)
    act(() => {
      controls.pairedUploads.releaseCancels()
    })
    await waitFor(() => {
      expect(line()).toBe('Cancelled. The host released 12 bytes.')
    })
    expect(screen.getByRole('button', { name: 'Remove report.pdf' })).toBeInTheDocument()
  })

  it('says a file already sent in full and kept by the host was not cancelled, and adds it', async () => {
    const { controls, person } = await open()
    await pick(person)
    await started(controls)
    controls.pairedUploads.answerCancelsWith('published')
    await person.click(screen.getByRole('button', { name: 'Cancel sending report.pdf' }))
    await waitFor(() => {
      expect(line()).toBe('Added to this draft')
    })
    expect(screen.getByTestId('upload-note')).toHaveTextContent(
      'This file was already sent in full and the host keeps it: it was not cancelled'
    )
  })

  it.each([
    ['too many open', { code: 'PERMISSION_DENIED', message: words.TOO_MANY_OPEN }, words.sentence(words.TOO_MANY_OPEN)],
    ['an earlier host', { code: 'UNSUPPORTED_CAPABILITY', message: 'unknown method' }, words.EARLIER_HOST],
    ['staging full', { code: 'QUOTA_EXCEEDED', message: 'staging holds 1 of 2 bytes' }, words.NO_ROOM],
    ['the file changed', { code: 'ATTACHMENT_INTEGRITY', message: 'changed' }, words.FILE_CHANGED],
    ['no right', { code: 'PERMISSION_DENIED', message: 'not allowed' }, words.NO_RIGHT_TO_SEND],
    ['another refusal', { code: 'RATE_LIMITED', message: 'slow down' }, 'Slow down']
  ])('says what to do when the host refuses with %s', async (_name, failure, shown) => {
    const { controls, person } = await open()
    controls.pairedUploads.refuseNext(failure)
    await pick(person)
    await waitFor(() => {
      expect(line()).toBe(shown)
    })
    expect(screen.getByText(`report.pdf was not sent: ${shown}`)).toBeInTheDocument()
    await person.click(screen.getByRole('button', { name: 'Remove report.pdf' }))
    expect(screen.queryByTestId('m-upload')).toBeNull()
  })

  it('refuses a file over the hand-over bound by its name and size, and starts nothing', async () => {
    const { controls, person } = await open()
    const big = new File([new Uint8Array(1)], 'film.mov', { type: 'video/quicktime' })
    Object.defineProperty(big, 'size', { value: HANDED_FILE_LIMIT + 1 })
    await person.upload(filesInput(), big)
    expect(
      await screen.findByText(
        'film.mov is 64.0 MB. This phone sends a picked file of at most 64 MB (a host takes up to 2 GB). Choose a smaller file.'
      )
    ).toBeInTheDocument()
    expect(controls.pairedUploads.started).toHaveLength(0)
  })

  it('keeps the finished upload when the draft refuses it, and adds it again on request', async () => {
    const { controls, person } = await open()
    controls.pairedUploads.refuseNextBind({ code: 'PERMISSION_DENIED', message: words.DRAFT_GONE })
    await pick(person)
    const key = await started(controls)
    act(() => {
      controls.pairedUploads.finish(key)
    })
    await waitFor(() => {
      expect(line()).toBe(
        `Sent in full and kept by the host. It was not added to this draft: ${words.sentence(words.DRAFT_GONE)}`
      )
    })
    await person.click(screen.getByRole('button', { name: 'Add again' }))
    await waitFor(() => {
      expect(line()).toBe('Added to this draft')
    })
    expect(controls.pairedUploads.binds).toHaveLength(2)
  })

  it('shows a file the application kept across a restart on its own session, and adds a published one', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: RIGHTS })
    const handle = {
      transfer_id: '99999999-9999-4999-8999-000000000777',
      environment_id: 'e',
      byte_len: '9',
      content_digest: 'c'.repeat(64),
      declared_media_type: 'application/octet-stream',
      original_file_name: 'kept.bin',
      presented_as_image: false,
      session_id: null,
      preview: null,
      published_at_ms: '1',
      expires_at_ms: '2',
      submitted: false
    }
    const entry = (key: string, state: 'published' | 'cannotResume' | 'waiting', sessionId: string | null, said: string | null) => ({
      key,
      state,
      sessionId,
      fileName: `${key}.bin`,
      byteLen: 9,
      acknowledgedChunks: 0,
      chunks: 0,
      stage: null,
      handle: state === 'published' ? handle : null,
      said
    })
    controls.pairedUploads.leave([
      entry('published-1', 'published', SESSION, null),
      entry('stuck-1', 'cannotResume', SESSION, words.CANNOT_RESUME),
      entry('other-1', 'waiting', '8a7b6c50-22bb-4c3d-8e4f-000000000102', null)
    ])
    render(
      <AppProvider port={port} uploadPollMs={10}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    const person = userEvent.setup({ applyAccept: false })
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await screen.findByTestId('draft-attachments')
    expect(screen.getAllByTestId('m-upload')).toHaveLength(2)
    expect(lineOfFile('published-1.bin').getByTestId('upload-line')).toHaveTextContent(
      'Sent in full and kept by the host. Not added to a draft yet'
    )
    expect(lineOfFile('stuck-1.bin').getByTestId('upload-line')).toHaveTextContent(
      words.sentence(words.CANNOT_RESUME)
    )
    expect(screen.queryByText('other-1.bin')).toBeNull()
    await person.click(within(lineOfFile('published-1.bin').getByTestId('upload-line').parentElement as HTMLElement).getByRole('button', { name: 'Add to draft' }))
    await waitFor(() => {
      expect(controls.pairedUploads.binds).toHaveLength(1)
    })
    await waitFor(() => {
      expect(lineOfFile('published-1.bin').getByTestId('upload-line')).toHaveTextContent('Added to this draft')
    })
  })
})

describe('the draft the application keeps across a restart', () => {
  const handleOf = (id: string) => ({
    transfer_id: id,
    environment_id: 'e',
    byte_len: '9',
    content_digest: 'c'.repeat(64),
    declared_media_type: 'application/pdf',
    original_file_name: `${id}.pdf`,
    presented_as_image: false,
    session_id: null,
    preview: null,
    published_at_ms: '1',
    expires_at_ms: '2',
    submitted: false
  })

  it('has its files shown on the composer as added to it, once each', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: RIGHTS })
    // The application answers a draft with each attachment carrying the handle it was bound with.
    controls.pairedUploads.keep(SESSION, handleOf('kept-1'))
    controls.pairedUploads.keep(SESSION, handleOf('kept-2'))
    render(
      <AppProvider port={port} uploadPollMs={10}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    const person = userEvent.setup({ applyAccept: false })
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await waitFor(() => {
      expect(screen.getAllByTestId('m-upload')).toHaveLength(2)
    })
    for (const name of ['kept-1.pdf', 'kept-2.pdf']) {
      expect(lineOfFile(name).getByTestId('upload-line')).toHaveTextContent('Added to this draft')
    }
  })
})

describe('a card the device stored, before the application has said what it holds', () => {
  it('J3: is checked, with no Cancel and a Remove that only takes it off the composer, while the files cannot be shown', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: RIGHTS })
    await port.deviceDraftSave({
      id: null,
      expectedRevision: null,
      sessionId: SESSION,
      applicationInstanceId: null,
      agentBindingRevision: null,
      state: 'open',
      text: '',
      attachments: [
        {
          transfer_id: 't-stored',
          environment_id: 'e',
          byte_len: '9',
          content_digest: 'c'.repeat(64),
          declared_media_type: 'application/pdf',
          original_file_name: 'stored.pdf',
          presented_as_image: false,
          session_id: null,
          preview: null,
          published_at_ms: '1',
          expires_at_ms: '2',
          submitted: false
        }
      ]
    })
    // The application's list cannot be read, so the files of the session are not shown.
    const listing = vi.spyOn(port, 'uploadsOpen').mockRejectedValue(new Error('not in contact'))
    const cancel = vi.spyOn(port, 'uploadCancel')
    const end = vi.spyOn(port, 'draftEnd')
    render(
      <AppProvider port={port} uploadPollMs={10}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    const person = userEvent.setup({ applyAccept: false })
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    const row = await screen.findByTestId('m-upload')
    await waitFor(() => {
      expect(listing).toHaveBeenCalled()
    })
    expect(within(row).getByTestId('upload-line')).toHaveTextContent('Checking with the host')
    expect(within(row).queryByRole('button', { name: /^Cancel/ })).toBeNull()
    await person.click(within(row).getByRole('button', { name: 'Remove stored.pdf' }))
    expect(screen.queryByTestId('m-upload')).toBeNull()
    expect(cancel).not.toHaveBeenCalled()
    expect(end).not.toHaveBeenCalled()
  })

  it('J3c: an offline stored card says uploaded and offers no remote action', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: RIGHTS })
    const stored = {
      transfer_id: 't-stored',
      environment_id: 'e',
      byte_len: '9',
      content_digest: 'c'.repeat(64),
      declared_media_type: 'application/pdf',
      original_file_name: 'stored.pdf',
      presented_as_image: false,
      session_id: null,
      preview: null,
      published_at_ms: '1',
      expires_at_ms: '2',
      submitted: false
    }
    // The device keeps the draft with the file, and the application holds the same file on its draft.
    controls.pairedUploads.keep(SESSION, stored)
    await port.deviceDraftSave({
      id: null,
      expectedRevision: null,
      sessionId: SESSION,
      applicationInstanceId: null,
      agentBindingRevision: null,
      state: 'open',
      text: '',
      attachments: [stored]
    })
    const cancel = vi.spyOn(port, 'uploadCancel')
    const end = vi.spyOn(port, 'draftEnd')
    render(
      <AppProvider port={port} uploadPollMs={10}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    const person = userEvent.setup({ applyAccept: false })
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await waitFor(() => {
      expect(lineOfFile('stored.pdf').getByTestId('upload-line')).toHaveTextContent('Added to this draft')
    })
    // The host stops answering while the draft is open: the card is drawn from what the device keeps.
    act(() => {
      controls.setConnected(false, 'the host stopped answering')
    })
    const card = await waitFor(() => {
      const found = document.querySelector<HTMLElement>('.m-attachment')
      expect(found).not.toBeNull()
      return within(found as HTMLElement)
    })
    expect(screen.queryByTestId('m-upload')).toBeNull()
    expect(card.getByText(/uploaded/)).toBeInTheDocument()
    expect(card.queryByRole('button', { name: /^Cancel/ })).toBeNull()
    await person.click(card.getByRole('button', { name: 'Remove stored.pdf from this draft' }))
    expect(document.querySelector('.m-attachment')).toBeNull()
    expect(cancel).not.toHaveBeenCalled()
    expect(end).not.toHaveBeenCalled()
  })
})

describe('a file whose bind the application refuses for want of a record of it', () => {
  it('Q1d: keeps the refusal on its card, with Remove and no Add or Cancel, and Remove drops the card without ending the draft', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: RIGHTS })
    controls.pairedUploads.leave([
      {
        key: 'published-1',
        state: 'published',
        sessionId: SESSION,
        fileName: 'published-1.bin',
        byteLen: 9,
        acknowledgedChunks: 0,
        chunks: 0,
        stage: null,
        handle: {
          transfer_id: '99999999-9999-4999-8999-000000000777',
          environment_id: 'e',
          byte_len: '9',
          content_digest: 'c'.repeat(64),
          declared_media_type: 'application/octet-stream',
          original_file_name: 'published-1.bin',
          presented_as_image: false,
          session_id: null,
          preview: null,
          published_at_ms: '1',
          expires_at_ms: '2',
          submitted: false
        },
        said: null
      }
    ])
    controls.pairedUploads.refuseNextBind({ code: 'INVALID_ARGUMENT', message: words.NO_OPEN_UPLOAD })
    const cancel = vi.spyOn(port, 'uploadCancel')
    const end = vi.spyOn(port, 'draftEnd')
    render(
      <AppProvider port={port} uploadPollMs={10}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    const person = userEvent.setup({ applyAccept: false })
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await person.click(await screen.findByRole('button', { name: 'Add to draft' }))
    // The announcement of the outcome comes whatever the row says; then the row's words are read.
    await screen.findByText(/^published-1\.bin: /)
    const row = screen.getByTestId('m-upload')
    expect(within(row).getByTestId('upload-line')).toHaveTextContent(words.NO_LONGER_HELD)
    expect(within(row).queryByRole('button', { name: /^Add/ })).toBeNull()
    expect(within(row).queryByRole('button', { name: /^Cancel/ })).toBeNull()
    await person.click(within(row).getByRole('button', { name: 'Remove published-1.bin' }))
    expect(screen.queryByTestId('m-upload')).toBeNull()
    expect(cancel).not.toHaveBeenCalled()
    expect(end).not.toHaveBeenCalled()
  })
})

describe('what the picker offers on a paired host', () => {
  it('names whom to ask when the device may not send files, and offers none', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone({ rights: ['session.view', 'agent.prompt'] })
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    const person = userEvent.setup({ applyAccept: false })
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    const group = await screen.findByRole('group', { name: 'Add an attachment' })
    expect(await screen.findByTestId('attach-reason')).toHaveTextContent(words.NO_RIGHT_TO_SEND)
    for (const button of within(group).getAllByRole('button')) expect(button).toBeDisabled()
  })
})

describe('the files on the draft go with the prompt that names it', () => {
  it('sets the text on the draft and sends the draft, with no inline text', async () => {
    const { controls, person } = await open()
    await pick(person)
    const key = await started(controls)
    act(() => {
      controls.pairedUploads.finish(key)
    })
    await waitFor(() => {
      expect(line()).toBe('Added to this draft')
    })
    await person.type(screen.getByRole('textbox', { name: 'Message this session' }), 'read the file')
    await person.click(screen.getByRole('button', { name: /^Send/ }))
    await waitFor(() => {
      expect(controls.promptParams).toHaveLength(1)
    })
    expect(controls.pairedUploads.texts).toEqual([{ sessionId: SESSION, text: 'read the file' }])
    const sent = controls.promptParams[0]
    expect(sent?.draft_id).toBe('00000000-0000-4000-8000-000000000001')
    expect(sent?.text).toBeNull()
  })

  it('takes the files that went with a taken prompt off the composer, and keeps the next file', async () => {
    const { controls, person } = await open()
    await pick(person, 'sent.pdf')
    const key = await started(controls)
    act(() => {
      controls.pairedUploads.finish(key)
    })
    await waitFor(() => {
      expect(line()).toBe('Added to this draft')
    })
    await person.type(screen.getByRole('textbox', { name: 'Message this session' }), 'read the file')
    await person.click(screen.getByRole('button', { name: /^Send/ }))
    await waitFor(() => {
      expect(controls.promptParams).toHaveLength(1)
    })
    await waitFor(() => {
      expect(screen.queryByText('sent.pdf')).toBeNull()
    })
    expect(screen.queryByTestId('draft-attachments')).toBeNull()
    // The next file is the person's own, and is not taken with the one that was sent.
    await pick(person, 'next.pdf')
    await started(controls, 2)
    expect(screen.getByText('next.pdf')).toBeInTheDocument()
  })

  it('keeps the files bound to the draft when the host did not confirm the prompt, so taking one off still ends the draft the application keeps', async () => {
    const { controls, person } = await open()
    await pick(person, 'kept.pdf')
    const key = await started(controls)
    act(() => {
      controls.pairedUploads.finish(key)
    })
    await waitFor(() => {
      expect(line()).toBe('Added to this draft')
    })
    // The application keeps the draft, with its file, when nobody knows what became of the prompt.
    // The file is still bound to it on the screen, so that taking it off ends that draft and no
    // later prompt carries a file the person no longer sees.
    controls.leaveNextSendUnconfirmed()
    await person.type(screen.getByRole('textbox', { name: 'Message this session' }), 'read the file')
    await person.click(screen.getByRole('button', { name: /^Send/ }))
    await waitFor(() => {
      expect(controls.promptParams).toHaveLength(1)
    })
    await person.click(await screen.findByRole('button', { name: /^Remove kept.pdf/ }))
    await waitFor(() => {
      expect(controls.pairedUploads.ended).toEqual([SESSION])
    })
  })

  it('sends inline text when no file is bound', async () => {
    const { controls, person } = await open()
    await person.type(screen.getByRole('textbox', { name: 'Message this session' }), 'hello')
    await person.click(screen.getByRole('button', { name: /^Send/ }))
    await waitFor(() => {
      expect(controls.promptParams).toHaveLength(1)
    })
    expect(controls.promptParams[0]).toMatchObject({ draft_id: null, text: 'hello' })
    expect(controls.pairedUploads.texts).toEqual([])
  })

  it('keeps the bound files on the composer when the draft could not be ended, so none goes with a later prompt unseen', async () => {
    const { controls, person } = await open()
    await pick(person, 'one.pdf')
    const first = await started(controls)
    act(() => {
      controls.pairedUploads.finish(first)
    })
    await waitFor(() => {
      expect(screen.getByTestId('upload-line')).toHaveTextContent('Added to this draft')
    })
    controls.pairedUploads.refuseNextEnd()
    await person.click(screen.getByRole('button', { name: /^Remove one.pdf/ }))
    await waitFor(() => {
      expect(controls.pairedUploads.ended).toEqual([])
    })
    expect(screen.getByTestId('upload-line')).toHaveTextContent('Added to this draft')
    // The person is told, in the application's own words, that it was not removed.
    expect(await screen.findByText('The host is not connected')).toBeInTheDocument()
  })

  it('says the file was not removed when the refusal of the end carries no words', async () => {
    const { controls, person } = await open()
    await pick(person, 'one.pdf')
    const first = await started(controls)
    act(() => {
      controls.pairedUploads.finish(first)
    })
    await waitFor(() => {
      expect(screen.getByTestId('upload-line')).toHaveTextContent('Added to this draft')
    })
    controls.pairedUploads.refuseNextEnd({ code: 'HOST_NOT_CONFIGURED', message: '' })
    await person.click(screen.getByRole('button', { name: /^Remove one.pdf/ }))
    expect(await screen.findByText('one.pdf was not removed.')).toBeInTheDocument()
    expect(screen.getByTestId('upload-line')).toHaveTextContent('Added to this draft')
  })

  it('ends the draft when a bound file is removed, and takes every file bound to it off the composer', async () => {
    const { controls, person } = await open()
    await pick(person, 'one.pdf')
    const first = await started(controls)
    act(() => {
      controls.pairedUploads.finish(first)
    })
    await waitFor(() => {
      expect(screen.getByTestId('upload-line')).toHaveTextContent('Added to this draft')
    })
    await pick(person, 'two.pdf')
    const second = await started(controls, 2)
    act(() => {
      controls.pairedUploads.finish(second)
    })
    await waitFor(() => {
      expect(screen.getAllByText('Added to this draft')).toHaveLength(2)
    })
    await person.click(screen.getByRole('button', { name: 'Remove one.pdf and the other files kept with this draft' }))
    await waitFor(() => {
      expect(screen.queryByTestId('m-upload')).toBeNull()
    })
    expect(controls.pairedUploads.ended).toEqual([SESSION])
  })
})

describe('the phone steering the running turn on a paired host (KR-REQ-13.12)', () => {
  it('turns Steer off while the draft carries files, and says that a steer carries text only', async () => {
    const { controls, person } = await open()
    await person.type(screen.getByRole('textbox', { name: 'Message this session' }), 'use the other file')
    const steer = await screen.findByRole('button', { name: 'Steer' })
    expect(steer).toBeEnabled()
    expect(screen.queryByText(/A steer carries text only/)).toBeNull()

    await pick(person)
    const key = await started(controls)
    act(() => {
      controls.pairedUploads.finish(key)
    })
    await waitFor(() => {
      expect(line()).toBe('Added to this draft')
    })

    expect(screen.getByRole('button', { name: 'Steer' })).toBeDisabled()
    expect(
      screen.getByText('A steer carries text only. Remove the files on this draft to steer with it.')
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Steer' })).toHaveAccessibleDescription(
      /A steer carries text only/
    )
  })
})

describe('the phone queueing a prompt with files on a paired host (KR-REQ-13.12)', () => {
  /** Binds one file to the draft and writes the text a prompt would carry. */
  async function withFileAndText(): Promise<Awaited<ReturnType<typeof open>>> {
    const opened = await open()
    await pick(opened.person)
    const key = await started(opened.controls)
    act(() => {
      opened.controls.pairedUploads.finish(key)
    })
    await waitFor(() => {
      expect(line()).toBe('Added to this draft')
    })
    await opened.person.type(screen.getByRole('textbox', { name: 'Message this session' }), 'then read the file')
    return opened
  }

  it('names the draft the application keeps, with no text of its own, and the files go with it', async () => {
    const { controls, person, port } = await withFileAndText()
    const queued = vi.spyOn(port, 'composerQueue')

    await person.click(screen.getByRole('button', { name: 'Queue' }))

    await waitFor(() => {
      expect(controls.queuedParams).toHaveLength(1)
    })
    // The text is set on the draft first; the queued prompt names that draft and carries no text.
    expect(controls.pairedUploads.texts).toEqual([{ sessionId: SESSION, text: 'then read the file' }])
    expect(controls.queuedParams[0]).toMatchObject({ text: null })
    expect(controls.queuedParams[0]?.draft_id).toEqual(expect.any(String))
    expect(controls.promptParams).toHaveLength(0)
    // It is made under the opening of the session, so the host knows which one it is made under.
    expect(queued.mock.calls[0]?.[1]).toEqual(expect.any(String))
    // The host took it as applied: the files are the session's now, and the composer is clear.
    await waitFor(() => {
      expect(screen.queryByTestId('m-upload')).toBeNull()
    })
    expect(controls.pairedUploads.textOf(SESSION)).toBeNull()
    expect(screen.getByRole('textbox', { name: 'Message this session' })).toHaveValue('')
  })

  it('leaves the files bound to the draft and the text where it is when the host refuses it', async () => {
    const { controls, person, port } = await withFileAndText()
    vi.spyOn(port, 'composerQueue').mockRejectedValue(
      receivedFailure({ code: 'DRAFT_CONFLICT', message: 'The conversation moved on.', user_action: 'none', retry: 'no_retry' })
    )

    await person.click(screen.getByRole('button', { name: 'Queue' }))

    expect(await screen.findByText('Refused by the host')).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Message this session' })).toHaveValue('then read the file')
    expect(screen.getAllByTestId('m-upload')).toHaveLength(1)
    expect(controls.pairedUploads.ended).toEqual([])
  })

  it('leaves the files bound to the draft when nobody knows what became of it', async () => {
    const { controls, person } = await withFileAndText()
    controls.leaveNextSendUnconfirmed()

    await person.click(screen.getByRole('button', { name: 'Queue' }))

    expect(await screen.findByText('Outcome unknown')).toBeInTheDocument()
    // The application still holds the draft with its text, and the file is still bound to it.
    expect(screen.getAllByTestId('m-upload')).toHaveLength(1)
    expect(controls.pairedUploads.ended).toEqual([])
  })
})
