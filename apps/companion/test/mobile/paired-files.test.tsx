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

async function open(rights: readonly ActionRight[] = RIGHTS): Promise<{ controls: FakeHostControls; person: ReturnType<typeof userEvent.setup> }> {
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
  return { controls, person }
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
