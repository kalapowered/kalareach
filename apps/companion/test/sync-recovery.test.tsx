/**
 * The sync service and recovery, in the Account sheet and on a phone.
 *
 * The sync service is a setting of its own, shown with a way to change it. Recovery is offered on
 * a desktop: it turns on, shows what stops it and what to do about that, settles a write that got
 * no answer, and saves the kit where the platform's dialog put it. The page never holds the seed,
 * the locator or a token, so nothing here can show one. The assertions are on the state each card
 * reports, the controls it offers and the one fact a person needs (a host), not on whole sentences.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
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
    // The refusal is said in the card's status line, the choice stands, and focus stays in the
    // field to correct, marked invalid and described by that line.
    const status = within(sheet).getByTestId('sync-status')
    await waitFor(() => {
      expect(status).toHaveTextContent('https')
    })
    expect(input).toHaveFocus()
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(input).toHaveAttribute('aria-describedby', status.id)
    expect(within(sheet).getByTestId('sync-service')).toHaveTextContent('reach.kala.to')
    expect(within(sheet).getByLabelText('Sync service')).toBeInTheDocument()

    await person.clear(input)
    await person.type(input, 'https://sync.example/')
    await person.click(within(sheet).getByTestId('save-sync-service'))
    await waitFor(() => {
      expect(within(sheet).getByTestId('sync-service')).toHaveTextContent('sync.example')
    })
    expect(within(sheet).queryByLabelText('Sync service')).toBeNull()
    expect(within(sheet).getByTestId('sync-status')).toHaveFocus()
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
  it('turns on, then saves the kit where the dialog put it, with focus on the result each time', async () => {
    const { person, controls, sheet } = await openSheet()
    act(() => {
      controls.account.set(SIGNED_IN)
    })
    const recovery = await within(sheet).findByTestId('recovery')
    expect(recovery).toHaveAttribute('data-state', 'off')
    expect(within(recovery).queryByTestId('recovery-save-kit')).toBeNull()

    // Focus lands once the card has been read again: the line a person is left on says where
    // things now stand, not where they stood.
    const stateAtFocus: (string | null)[] = []
    within(recovery)
      .getByTestId('recovery-status')
      .addEventListener('focus', () => {
        stateAtFocus.push(recovery.getAttribute('data-state'))
      })
    await person.click(within(recovery).getByTestId('recovery-turn-on'))
    await waitFor(() => {
      expect(recovery).toHaveAttribute('data-state', 'on')
    })
    expect(stateAtFocus).toEqual(['on'])
    expect(controls.recovery.turnedOn).toBe(1)
    expect(within(recovery).getByTestId('recovery-status')).toHaveTextContent('reach.kala.to')
    expect(within(recovery).queryByTestId('recovery-turn-on')).toBeNull()
    // The pressed control is gone, so focus is on the line that says what happened.
    expect(within(recovery).getByTestId('recovery-status')).toHaveFocus()

    await person.click(within(recovery).getByTestId('recovery-save-kit'))
    await waitFor(() => {
      expect(within(recovery).getByTestId('recovery-said')).toBeInTheDocument()
    })
    expect(controls.recovery.kitsSaved).toEqual(['/tmp/kalareach-recovery-kit.txt'])
    expect(within(recovery).getByTestId('recovery-status')).toHaveFocus()
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
    expect(await within(recovery).findByTestId('recovery-blocker')).toHaveAttribute(
      'data-reason',
      'signed_out'
    )
    expect(within(recovery).queryByRole('button')).toBeNull()

    act(() => {
      controls.recovery.set({ blocker: { reason: 'needs_sign_in' } })
      controls.account.set(SIGNED_IN)
    })
    await waitFor(() => {
      expect(within(recovery).getByTestId('recovery-blocker')).toHaveAttribute(
        'data-reason',
        'needs_sign_in'
      )
    })
    expect(within(recovery).queryByTestId('recovery-turn-on')).toBeNull()
    await person.click(within(recovery).getByTestId('recovery-sign-in'))
    expect(controls.recovery.signedInForRecovery).toBe(1)
    act(() => {
      controls.account.finishSignIn({ ...SIGNED_IN, generation: 'bbbb' })
      controls.recovery.set({ blocker: null })
    })
    await waitFor(() => {
      expect(within(recovery).getByTestId('recovery-turn-on')).toBeInTheDocument()
    })
    // The account card follows the sign-in from the browser back to its own status line, and
    // recovery leaves focus there.
    const accountPanel = within(sheet).getByTestId('account-panel')
    await waitFor(() => {
      expect(accountPanel).toContainElement(document.activeElement as HTMLElement)
    })
    expect(within(recovery).getByTestId('recovery-status')).not.toHaveFocus()

    act(() => {
      controls.recovery.set({
        blocker: { reason: 'wrong_service', sync_service: 'sync.example', account: 'reach.kala.to' }
      })
      controls.account.set({ ...SIGNED_IN, generation: 'cccc' })
    })
    await waitFor(() => {
      expect(within(recovery).getByTestId('recovery-blocker')).toHaveAttribute(
        'data-reason',
        'wrong_service'
      )
    })
    // Both services are named, so the person knows which setting to change and to what.
    const words = within(recovery).getByTestId('recovery-blocker')
    expect(words).toHaveTextContent('sync.example')
    expect(words).toHaveTextContent('reach.kala.to')
    expect(within(recovery).queryByRole('button')).toBeNull()
  })

  it('settles a write that got no answer, and offers no kit until it is settled', async () => {
    const { person, controls, sheet } = await openSheet()
    act(() => {
      controls.recovery.set({ state: 'unsettled', kept_at: 'reach.kala.to' })
      controls.account.set(SIGNED_IN)
    })
    const recovery = await within(sheet).findByTestId('recovery')
    await waitFor(() => {
      expect(recovery).toHaveAttribute('data-state', 'unsettled')
    })
    expect(within(recovery).queryByTestId('recovery-save-kit')).toBeNull()
    await person.click(within(recovery).getByTestId('recovery-settle'))
    await waitFor(() => {
      expect(recovery).toHaveAttribute('data-state', 'on')
    })
    expect(controls.recovery.settled).toBe(1)
    // The pressed control is gone, so focus is on the line that says what happened.
    await waitFor(() => {
      expect(within(recovery).getByTestId('recovery-status')).toHaveFocus()
    })
  })

  it('says that a bundle stays where it was made when another sync service is chosen', async () => {
    const { person, controls, sheet } = await openSheet()
    act(() => {
      controls.recovery.set({ state: 'on', kept_at: 'reach.kala.to' })
      controls.account.set(SIGNED_IN)
    })
    const recovery = await within(sheet).findByTestId('recovery')
    expect(within(recovery).queryByTestId('recovery-stays-at')).toBeNull()

    await person.click(within(sheet).getByTestId('change-sync-service'))
    const input = within(sheet).getByLabelText('Sync service')
    await person.clear(input)
    await person.type(input, 'https://sync.example')
    await person.click(within(sheet).getByTestId('save-sync-service'))
    const stays = await within(recovery).findByTestId('recovery-stays-at')
    expect(stays).toHaveTextContent('reach.kala.to')
    expect(recovery).toHaveAttribute('data-state', 'on')
  })

  it('says when recovery cannot be read, and asks again on request', async () => {
    const { person, controls, sheet } = await openSheet()
    controls.recovery.failReads('this computer’s recovery record could not be read')
    act(() => {
      controls.account.set(SIGNED_IN)
    })
    const recovery = await within(sheet).findByTestId('recovery')
    expect(await within(recovery).findByTestId('recovery-problem')).toHaveTextContent(
      'recovery record could not be read'
    )
    expect(within(recovery).queryByTestId('recovery-turn-on')).toBeNull()

    controls.recovery.failReads(null)
    await person.click(within(recovery).getByRole('button', { name: 'Try again' }))
    await waitFor(() => {
      expect(recovery).toHaveAttribute('data-state', 'off')
    })
    expect(within(recovery).queryByTestId('recovery-problem')).toBeNull()
    // The control that was pressed is gone, so focus is on the line that says where things stand.
    await waitFor(() => {
      expect(within(recovery).getByTestId('recovery-status')).toHaveFocus()
    })
  })

  it('does not take focus from a field the person went on to type in', async () => {
    const { person, controls, sheet } = await openSheet()
    act(() => {
      controls.account.set(SIGNED_IN)
    })
    const recovery = await within(sheet).findByTestId('recovery')
    const release = controls.recovery.holdTurnOn()
    await person.click(within(recovery).getByTestId('recovery-turn-on'))

    // While the backend is still working, the person opens the other card and types.
    await person.click(within(sheet).getByTestId('change-sync-service'))
    const input = within(sheet).getByLabelText('Sync service')
    await person.clear(input)
    await person.type(input, 'https://sync.exa')
    expect(input).toHaveFocus()

    act(() => {
      release()
    })
    await waitFor(() => {
      expect(recovery).toHaveAttribute('data-state', 'on')
    })
    // The step ended with the person still in the field, and the field kept focus without the
    // person clicking it again.
    await waitFor(() => {
      expect(within(recovery).queryByTestId('recovery-turn-on')).toBeNull()
    })
    expect(input).toHaveFocus()
    expect(within(recovery).getByTestId('recovery-status')).not.toHaveFocus()
    await person.keyboard('mple')
    expect(input).toHaveValue('https://sync.example')
  })

  it('names nothing to buy in any state', async () => {
    const { controls, sheet } = await openSheet()
    for (const state of ['off', 'unfinished', 'on', 'unsettled'] as const) {
      act(() => {
        controls.recovery.set({ state, kept_at: state === 'off' ? null : 'reach.kala.to' })
        controls.account.set({ ...SIGNED_IN, generation: state })
      })
      const recovery = await within(sheet).findByTestId('recovery')
      await waitFor(() => {
        expect(recovery).toHaveAttribute('data-state', state)
      })
      const text = (sheet.textContent ?? '').toLowerCase()
      for (const word of PURCHASE_WORDS) {
        expect(text, `${state}: ${word}`).not.toContain(word)
      }
    }
  })
})
