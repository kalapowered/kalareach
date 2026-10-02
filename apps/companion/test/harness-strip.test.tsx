/**
 * The control strip of the test harness, which a device test drives the scripted host with.
 *
 * It exists only in the harness bundle, which no desktop or phone build carries, and it gives the
 * test the same few controls a browser test has: contact lost and regained, sends held and released,
 * and a reset of what the page keeps, so that no test starts from another's leftovers.
 */

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import { HarnessStrip, TapAwayPutsTheKeyboardAway, applyPendingReset } from '../src/harness-strip'
import { MobileApp } from '../src/mobile/MobileApp'
import { DRAFTS_KEY } from '../src/mobile/model/store'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** What a page sends to put one prompt into the session's agent. */
async function submit(host: ReturnType<typeof fakeHost>, text: string) {
  const agents = await host.port.sessionAgents(SESSION_MAIN)
  const live = agents.instances.instances.find((each) => each.ended_at === null)
  if (live === undefined) throw new Error('the scripted session has no agent')
  const subject = { session_id: SESSION_MAIN, application_instance_id: live.application_instance_id }
  const facts = await host.port.agentCapabilities({ subject })
  return host.port.composerSubmit({
    target: { subject, binding_revision: facts.binding.binding_revision },
    draft_id: null,
    text
  })
}

/** A storage that behaves like the browser's own. */
function fakeStorage(): Storage {
  const values = new Map<string, string>()
  return {
    get length() {
      return values.size
    },
    clear: () => {
      values.clear()
    },
    getItem: (key: string) => values.get(key) ?? null,
    key: (index: number) => [...values.keys()][index] ?? null,
    removeItem: (key: string) => {
      values.delete(key)
    },
    setItem: (key: string, value: string) => {
      values.set(key, value)
    }
  }
}

afterEach(cleanup)

function open(storage: Storage = window.localStorage, reload: () => void = () => undefined) {
  const host = fakeHost()
  render(<HarnessStrip controls={host.controls} storage={storage} reload={reload} />)
  return host
}

describe('the harness control strip', () => {
  it('is collapsed until it is opened, and closes again after each control', async () => {
    const person = userEvent.setup()
    open()
    expect(screen.queryByRole('button', { name: 'Lose contact' })).toBeNull()
    await person.click(screen.getByRole('button', { name: 'Controls' }))
    await person.click(screen.getByRole('button', { name: 'Lose contact' }))
    expect(screen.queryByRole('button', { name: 'Lose contact' })).toBeNull()
  })

  it('loses and regains contact with the host', async () => {
    const person = userEvent.setup()
    const host = open()
    await person.click(screen.getByRole('button', { name: 'Controls' }))
    await person.click(screen.getByRole('button', { name: 'Lose contact' }))
    await expect(host.port.sessionList({})).rejects.toBeDefined()
    await person.click(screen.getByRole('button', { name: 'Controls' }))
    await person.click(screen.getByRole('button', { name: 'Restore contact' }))
    await expect(host.port.sessionList({})).resolves.toBeDefined()
  })

  it('holds sends and releases them, and says how many the host has received', async () => {
    const person = userEvent.setup()
    const host = open()
    await person.click(screen.getByRole('button', { name: 'Controls' }))
    await person.click(screen.getByRole('button', { name: 'Hold sends' }))

    let answered = false
    const pending = submit(host, 'run it').then((outcome) => {
      answered = true
      return outcome
    })
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(host.controls.submissions).toBe(1)
    expect(answered).toBe(false)
    await person.click(screen.getByRole('button', { name: 'Controls' }))
    expect(screen.getByTestId('strip-submissions').textContent).toBe('1')

    await person.click(screen.getByRole('button', { name: 'Release sends' }))
    await pending
    expect(answered).toBe(true)
    await person.click(screen.getByRole('button', { name: 'Controls' }))
    expect(screen.getByTestId('strip-submissions').textContent).toBe('1')
  })

  it('does not lose the sends it holds when it is asked to hold again', async () => {
    const person = userEvent.setup()
    const host = open()
    await person.click(screen.getByRole('button', { name: 'Controls' }))
    await person.click(screen.getByRole('button', { name: 'Hold sends' }))

    let answered = false
    const pending = submit(host, 'run it').then((outcome) => {
      answered = true
      return outcome
    })
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(answered).toBe(false)

    await person.click(screen.getByRole('button', { name: 'Controls' }))
    expect(screen.getByRole('button', { name: 'Hold sends' })).toBeDisabled()
    await person.click(screen.getByRole('button', { name: 'Release sends' }))
    await pending
    expect(answered).toBe(true)
  })

  it('clears what the page keeps of drafts and sends, and reloads, and clears nothing else', async () => {
    const person = userEvent.setup()
    const reload = vi.fn()
    const storage = window.localStorage
    storage.setItem('kr.mobile.drafts', '[]')
    storage.setItem('kr.mobile.submissions', '[]')
    storage.setItem('kalareach-theme', 'dark')
    open(storage, reload)
    await person.click(screen.getByRole('button', { name: 'Controls' }))
    await person.click(screen.getByRole('button', { name: 'Reset' }))
    expect(storage.getItem('kr.mobile.drafts')).toBeNull()
    expect(storage.getItem('kr.mobile.submissions')).toBeNull()
    expect(storage.getItem('kalareach-theme')).toBe('dark')
    expect(reload).toHaveBeenCalledTimes(1)
    storage.removeItem('kalareach-theme')
  })

  it('leaves nothing of the drafts behind when the page it reloads writes them on its way out', async () => {
    const person = userEvent.setup()
    const storage = fakeStorage()
    const session = fakeStorage()
    const host = fakeHost()
    // A browser fires `pagehide` as the page goes, and the page writes what it holds then: the
    // reset has to survive that, whenever the next page starts.
    const reload = () => {
      act(() => {
        window.dispatchEvent(new Event('pagehide'))
      })
    }
    render(
      <AppProvider port={host.port}>
        <MobileApp surface="ios" storage={storage} />
        <HarnessStrip controls={host.controls} storage={storage} session={session} reload={reload} />
      </AppProvider>
    )
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await person.type(await screen.findByLabelText('Message this session'), 'a draft')
    expect(storage.getItem(DRAFTS_KEY)).not.toBeNull()

    await person.click(screen.getByRole('button', { name: 'Controls' }))
    await person.click(screen.getByRole('button', { name: 'Reset' }))
    // The next page, before it shows anything.
    applyPendingReset(storage, session)
    expect(storage.getItem(DRAFTS_KEY)).toBeNull()
    // And only once: a draft written after that is kept.
    storage.setItem(DRAFTS_KEY, '[]')
    applyPendingReset(storage, session)
    expect(storage.getItem(DRAFTS_KEY)).toBe('[]')
  })

  it('puts the keyboard away when a finger lifts from text, and leaves it for a control', () => {
    render(
      <div>
        <TapAwayPutsTheKeyboardAway />
        <textarea aria-label="Field" />
        <button type="button">Control</button>
        <p>Some text</p>
      </div>
    )
    const field = screen.getByLabelText('Field')
    field.focus()
    expect(field).toHaveFocus()
    fireEvent.pointerUp(screen.getByRole('button', { name: 'Control' }))
    expect(field).toHaveFocus()
    fireEvent.pointerUp(field)
    expect(field).toHaveFocus()
    fireEvent.pointerUp(screen.getByText('Some text'))
    expect(field).not.toHaveFocus()
  })
})
