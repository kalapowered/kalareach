/**
 * The desktop's Account sheet.
 *
 * Section 13: settings are reached without leaving a live session, so the Account entry in the
 * sidebar opens a sheet over whatever is showing, and a sign-in carries on while the sheet is
 * closed. Section 17: the panel shows identity and usage, and nothing to buy.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import { PURCHASE_WORDS, type AccountView } from '../src/model/account'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

function start(initialPlace: Place = { view: 'attention' }) {
  const { port, controls } = fakeHost()
  render(
    <AppProvider port={port} initialPlace={initialPlace}>
      <App />
    </AppProvider>
  )
  return controls
}

describe('the desktop Account sheet', () => {
  it('opens over a live session without leaving it', async () => {
    const person = userEvent.setup()
    start({ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    const heading = await screen.findByText('Session 1 · Waiting for you')
    await person.click(screen.getByRole('button', { name: /^Account/ }))
    const sheet = await screen.findByRole('dialog', { name: 'Account' })
    expect(within(sheet).getByText('Sessions keep running while this is open.')).toBeInTheDocument()
    expect(await within(sheet).findByRole('button', { name: 'Sign in' })).toBeInTheDocument()
    expect(heading).toBeInTheDocument()
  })

  it('carries a sign-in on with the sheet closed, and says who signed in', async () => {
    const person = userEvent.setup()
    const controls = start()
    await person.click(screen.getByRole('button', { name: /^Account/ }))
    const sheet = await screen.findByRole('dialog', { name: 'Account' })
    await person.click(await within(sheet).findByRole('button', { name: 'Sign in' }))
    expect(controls.openedLinks).toEqual([])
    await person.keyboard('{Escape}')
    const item = screen.getByRole('button', { name: /^Account/ })
    expect(item).toHaveTextContent('Signing in…')

    act(() => {
      controls.account.finishSignIn({
        state: 'signed_in',
        email: 'sam@example.com',
        name: null,
        usage_readable: false,
        outcome: null
      })
    })
    expect(await screen.findByText('Signed in as sam@example.com.')).toBeInTheDocument()
    expect(item).toHaveTextContent('sam@example.com')
  })

  it('never shows one sign-in\'s usage for another, however late it answers', async () => {
    const person = userEvent.setup()
    const controls = start()
    controls.account.holdUsage()
    const signedIn = (email: string): AccountView => ({
      state: 'signed_in',
      email,
      name: null,
      usage_readable: true,
      outcome: null
    })
    const line = (used: number) => ({
      state: 'read' as const,
      period_label: 'Usage in September 2026',
      lines: [{ label: 'Relay this month', used, included: 10, unit: 'GB' }]
    })
    await person.click(screen.getByRole('button', { name: /^Account/ }))
    const sheet = await screen.findByRole('dialog', { name: 'Account' })

    act(() => {
      controls.account.set(signedIn('first@example.com'))
    })
    expect(await within(sheet).findByText('Usage has not been read yet.')).toBeInTheDocument()
    act(() => {
      controls.account.set({ state: 'signed_out', outcome: 'signed_out' })
    })
    act(() => {
      controls.account.set(signedIn('second@example.com'))
    })
    await within(sheet).findByText('Signed in as second@example.com.')

    // The second sign-in's usage arrives, then the first's, late.
    await act(async () => {
      controls.account.answerUsage(1, line(2))
      controls.account.answerUsage(0, line(9))
      await Promise.resolve()
    })
    expect(await within(sheet).findByText('2 of 10 GB')).toBeInTheDocument()
    expect(within(sheet).queryByText('9 of 10 GB')).toBeNull()
  })

  it('says a failed sign-out beside the account that stays signed in', async () => {
    const person = userEvent.setup()
    const controls = start()
    await person.click(screen.getByRole('button', { name: /^Account/ }))
    const sheet = await screen.findByRole('dialog', { name: 'Account' })
    await within(sheet).findByRole('button', { name: 'Sign in' })
    act(() => {
      controls.account.set({
        state: 'signed_in',
        email: 'sam@example.com',
        name: null,
        usage_readable: false,
        outcome: null
      })
    })
    controls.account.failSignOut()
    await person.click(await within(sheet).findByRole('button', { name: 'Sign out' }))
    expect(
      await within(sheet).findByText('KalaReach could not remove the sign-in from this device.')
    ).toBeInTheDocument()
    expect(within(sheet).getByText('Signed in as sam@example.com.')).toBeInTheDocument()
    expect(within(sheet).getByRole('button', { name: 'Sign out' })).toBeInTheDocument()
  })

  it('names nothing to buy in any state', async () => {
    const person = userEvent.setup()
    const controls = start()
    await person.click(screen.getByRole('button', { name: /^Account/ }))
    const sheet = await screen.findByRole('dialog', { name: 'Account' })
    const views: AccountView[] = [
      { state: 'signed_out', outcome: 'signed_out_pending' },
      { state: 'browser_open' },
      { state: 'finishing' },
      {
        state: 'signed_in',
        email: 'sam@example.com',
        name: 'Sam',
        usage_readable: false,
        outcome: 'sign_out_failed'
      },
      { state: 'ended' },
      { state: 'unavailable', reason: 'no_returning_browser' }
    ]
    for (const view of views) {
      act(() => {
        controls.account.set(view)
      })
      const text = (sheet.textContent ?? '').toLowerCase()
      for (const word of PURCHASE_WORDS) {
        expect(text, `${view.state}: ${word}`).not.toContain(word)
      }
      expect(sheet.querySelector('a[href]')).toBeNull()
      expect(sheet.querySelector('form')).toBeNull()
    }
  })
})
