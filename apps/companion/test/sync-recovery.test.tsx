/**
 * The sync service and recovery, in the Account sheet and on a phone.
 *
 * The sync service is a setting of its own, shown with a way to change it. Recovery is offered on a
 * desktop: it turns on, shows what stops it and what to do about that, settles a write that got no
 * answer, and saves the kit where the platform's dialog put it. The page never holds the seed, the
 * locator or a token, so nothing here can show one.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import { MobileApp } from '../src/mobile/MobileApp'
import { PURCHASE_WORDS } from '../src/model/account'

const SIGNED_IN = {
  state: 'signed_in',
  email: 'sam@example.com',
  name: null,
  usage_readable: false,
  generation: 'aaaa',
  outcome: null
} as const

async function openSheet() {
  const person = userEvent.setup()
  const { port, controls } = fakeHost()
  render(
    <AppProvider port={port} initialPlace={{ view: 'attention' }}>
      <App />
    </AppProvider>
  )
  await person.click(screen.getByRole('button', { name: /^Account/ }))
  const sheet = await screen.findByRole('dialog', { name: 'Account' })
  return { person, controls, sheet, port }
}

describe('the sync service setting', () => {
  it('is the managed service until another is chosen, and a refused choice leaves it', async () => {
    const { person, sheet } = await openSheet()
    expect(await within(sheet).findByTestId('sync-service')).toHaveTextContent('reach.kala.to')

    await person.click(within(sheet).getByTestId('change-sync-service'))
    const input = within(sheet).getByLabelText('Sync service')
    expect(input).toHaveValue('https://reach.kala.to')

    await person.clear(input)
    await person.type(input, 'http://sync.example')
    await person.click(within(sheet).getByTestId('save-sync-service'))
    expect(await within(sheet).findByText(/needs an https origin/)).toBeInTheDocument()
    expect(within(sheet).getByTestId('sync-service')).toHaveTextContent('reach.kala.to')

    await person.clear(input)
    await person.type(input, 'https://sync.example/')
    await person.click(within(sheet).getByTestId('save-sync-service'))
    expect(await within(sheet).findByText('Sync now goes through sync.example.')).toBeInTheDocument()
    expect(within(sheet).getByTestId('sync-service')).toHaveTextContent('sync.example')
    expect(within(sheet).queryByLabelText('Sync service')).toBeNull()
  })

  it('is shown on a phone, which offers no recovery', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    await person.click(await screen.findByRole('button', { name: /^Account/ }))
    const account = await screen.findByTestId('mobile-account')
    expect(await within(account).findByTestId('sync-service')).toHaveTextContent('reach.kala.to')
    expect(within(account).queryByTestId('recovery')).toBeNull()
  })
})

describe('recovery', () => {
  it('turns on, then saves the kit where the dialog put it', async () => {
    const { person, controls, sheet } = await openSheet()
    act(() => {
      controls.account.set(SIGNED_IN)
    })
    const recovery = await within(sheet).findByTestId('recovery')
    expect(within(recovery).getByText('Recovery is off.')).toBeInTheDocument()
    expect(within(recovery).queryByRole('button', { name: 'Save the recovery kit' })).toBeNull()

    await person.click(within(recovery).getByTestId('recovery-turn-on'))
    expect(
      await within(sheet).findByText('Recovery is on. The bundle is kept at reach.kala.to.')
    ).toBeInTheDocument()
    expect(controls.recovery.turnedOn).toBe(1)
    expect(within(sheet).queryByTestId('recovery-turn-on')).toBeNull()

    await person.click(within(sheet).getByTestId('recovery-save-kit'))
    expect(
      await within(sheet).findByText('Recovery kit saved. Keep it where only you can reach it.')
    ).toBeInTheDocument()
    expect(controls.recovery.kitsSaved).toEqual(['/tmp/kalareach-recovery-kit.txt'])
  })

  it('says what stops it, and offers only what mends that', async () => {
    const { person, controls, sheet } = await openSheet()
    act(() => {
      controls.account.set(SIGNED_IN)
    })
    const recovery = await within(sheet).findByTestId('recovery')

    // The view is read again when the account's standing changes.
    act(() => {
      controls.recovery.set({ blocker: { reason: 'signed_out' } })
      controls.account.set({ state: 'signed_out', outcome: 'signed_out' })
    })
    expect(await within(recovery).findByText(/Sign in to use recovery/)).toBeInTheDocument()
    expect(within(recovery).queryByRole('button')).toBeNull()

    act(() => {
      controls.recovery.set({ blocker: { reason: 'needs_sign_in' } })
      controls.account.set(SIGNED_IN)
    })
    expect(await within(recovery).findByText(/Sign in again to allow it/)).toBeInTheDocument()
    expect(within(recovery).queryByTestId('recovery-turn-on')).toBeNull()
    await person.click(within(recovery).getByTestId('recovery-sign-in'))
    expect(controls.recovery.signedInForRecovery).toBe(1)
    act(() => {
      controls.account.finishSignIn({ ...SIGNED_IN, generation: 'bbbb' })
      controls.recovery.set({ blocker: null })
    })

    act(() => {
      controls.recovery.set({
        blocker: { reason: 'wrong_service', sync_service: 'sync.example', account: 'reach.kala.to' }
      })
      controls.account.set({ ...SIGNED_IN, generation: 'cccc' })
    })
    const words = await within(recovery).findByTestId('recovery-blocker')
    expect(words).toHaveTextContent(
      'The sync service setting names sync.example, which is not the service this device is signed in to (reach.kala.to)'
    )
    expect(within(recovery).queryByRole('button')).toBeNull()
  })

  it('settles a write that got no answer, and asks nothing else of the person first', async () => {
    const { person, controls, sheet } = await openSheet()
    act(() => {
      controls.recovery.set({ state: 'unsettled', kept_at: 'reach.kala.to' })
      controls.account.set(SIGNED_IN)
    })
    const recovery = await within(sheet).findByTestId('recovery')
    expect(
      await within(recovery).findByText(/got no answer, so it is not known whether it landed/)
    ).toBeInTheDocument()
    expect(within(recovery).queryByTestId('recovery-save-kit')).toBeNull()
    await person.click(within(recovery).getByTestId('recovery-settle'))
    expect(controls.recovery.settled).toBe(1)
    expect(
      await within(sheet).findByText('Recovery is on. The bundle is kept at reach.kala.to.')
    ).toBeInTheDocument()
  })

  it('names nothing to buy in any state', async () => {
    const { controls, sheet } = await openSheet()
    for (const state of ['off', 'unfinished', 'on', 'unsettled'] as const) {
      act(() => {
        controls.recovery.set({ state, kept_at: state === 'off' ? null : 'reach.kala.to' })
        controls.account.set({ ...SIGNED_IN, generation: state })
      })
      await within(sheet).findByTestId('recovery')
      const text = (sheet.textContent ?? '').toLowerCase()
      for (const word of PURCHASE_WORDS) {
        expect(text, `${state}: ${word}`).not.toContain(word)
      }
    }
  })
})
