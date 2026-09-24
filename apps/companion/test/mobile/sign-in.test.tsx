/**
 * Signing in from the phone application, as a person does it.
 *
 * KR-REQ-17.19: a managed account's passkey ceremony runs on the website's fixed HTTPS origin and
 * relying party, in the system browser. The application's part is to ask its backend to hand the
 * ceremony over, never to open the origin itself: the address the browser opens, and what comes
 * back, stay in the backend. The request and the relying party are checked where the request is
 * built (the backend's own tests); this is the page's half.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AppProvider } from '../../src/app/state'
import { fakeHost } from '../../src/host/fake'
import { MobileApp } from '../../src/mobile/MobileApp'
import { PURCHASE_WORDS } from '../../src/model/account'

function start() {
  const { port, controls } = fakeHost()
  render(
    <AppProvider port={port}>
      <MobileApp surface="ios" storage={null} />
    </AppProvider>
  )
  return controls
}

describe('signing in hands the ceremony to the system browser (KR-REQ-17.19)', () => {
  it('asks the backend once, opens no link itself, and says to continue on the website', async () => {
    const person = userEvent.setup()
    const controls = start()
    await person.click(await screen.findByRole('button', { name: /^Account/ }))
    const account = await screen.findByTestId('mobile-account')
    const signIn = await within(account).findByRole('button', { name: 'Sign in' })
    expect(signIn).toHaveAccessibleDescription(
      'Opens reach.kala.to, where you use a passkey or an email code.'
    )

    await person.click(signIn)
    expect(controls.account.signIns).toBe(1)
    expect(controls.openedLinks).toEqual([])
    expect(
      await within(account).findByText(
        'Continue on reach.kala.to. This screen updates when you finish there.'
      )
    ).toBeInTheDocument()
    expect(within(account).getByRole('button', { name: 'Cancel' })).toHaveFocus()

    act(() => {
      controls.account.setUsage({
        state: 'read',
        generation: 'aaaa',
        period_label: 'Usage in September 2026',
        lines: [{ label: 'Relay this month', used: 1.2, included: 10, unit: 'GB' }]
      })
      controls.account.finishSignIn({
        state: 'signed_in',
        email: 'sam@example.com',
        name: null,
        usage_readable: true,
        generation: 'aaaa',
        outcome: null
      })
    })
    expect(await within(account).findByText('Signed in as sam@example.com.')).toBeInTheDocument()
    expect(await within(account).findByText('1.2 of 10 GB')).toBeInTheDocument()
    expect(within(account).getByRole('meter', { name: 'Relay this month: 1.2 of 10 GB' })).toBeInTheDocument()
    expect(within(account).getByRole('status')).toHaveFocus()
    expect(controls.openedLinks).toEqual([])

    const text = (account.textContent ?? '').toLowerCase()
    for (const word of PURCHASE_WORDS) {
      expect(text).not.toContain(word)
    }
    expect(account.querySelector('a[href]')).toBeNull()
    expect(account.querySelector('form')).toBeNull()
  })

  it('says a cancelled sign-in changed nothing, and offers it again', async () => {
    const person = userEvent.setup()
    const controls = start()
    await person.click(await screen.findByRole('button', { name: /^Account/ }))
    const account = await screen.findByTestId('mobile-account')
    await person.click(await within(account).findByRole('button', { name: 'Sign in' }))
    await person.click(within(account).getByRole('button', { name: 'Cancel' }))
    expect(await within(account).findByText('Sign-in cancelled. Nothing changed.')).toBeInTheDocument()
    expect(within(account).getByRole('button', { name: 'Sign in' })).toBeInTheDocument()
    expect(within(account).getByRole('status')).toHaveFocus()
    expect(controls.openedLinks).toEqual([])
  })

  it('says why no sign-in is offered where no browser can come back', async () => {
    const person = userEvent.setup()
    const controls = start()
    controls.account.set({ state: 'unavailable', reason: 'link_handling_off' })
    await person.click(await screen.findByRole('button', { name: /^Account/ }))
    const account = await screen.findByTestId('mobile-account')
    expect(
      await within(account).findByText(/Turn on opening supported links for KalaReach/)
    ).toBeInTheDocument()
    expect(within(account).queryByRole('button', { name: 'Sign in' })).toBeNull()
  })
})
