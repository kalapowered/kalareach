/**
 * The control strip of the test harness, which a device test drives the scripted host with.
 *
 * It exists only in the harness bundle, which no desktop or phone build carries, and it gives the
 * test the same few controls a browser test has: contact lost and regained, sends held and released,
 * and a reset of what the page keeps, so that no test starts from another's leftovers.
 */

import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { fakeHost } from '../src/host/fake'
import { HarnessStrip } from '../src/harness-strip'

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
    expect(host.controls.submissions).toBe(0)
    await person.click(screen.getByRole('button', { name: 'Controls' }))
    expect(screen.getByTestId('strip-submissions').textContent).toBe('0')
    await person.click(screen.getByRole('button', { name: 'Release sends' }))
    await person.click(screen.getByRole('button', { name: 'Controls' }))
    expect(screen.getByTestId('strip-submissions').textContent).toBe('0')
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
})
