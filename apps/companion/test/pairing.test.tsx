/**
 * The pairing screen and the owner's confirmations, driven the way a person drives them.
 *
 * The scripted host stands in for native code: it publishes the states native code would, and a
 * test changes them the way an attempt would. What the page draws is what the person sees.
 */

import { describe, expect, it } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost, type FakeHostControls } from '../src/host/fake'
import type { AttemptState, FailureKind, ConfirmationRequest } from '../src/host/port'
import { failureWords } from '../src/pairing/words'

function start(initialPlace: Place = { view: 'pairing' }): { controls: FakeHostControls } {
  const { port, controls } = fakeHost()
  render(
    <AppProvider port={port} initialPlace={initialPlace}>
      <App />
    </AppProvider>
  )
  return { controls }
}

function attempt(controls: FakeHostControls, state: AttemptState): void {
  act(() => {
    controls.setPairing({ state })
  })
}

const IN_FIVE_MINUTES = Date.now() + 5 * 60_000

/** A code attempt through the configured service that ended as `kind`. */
function ended(kind: FailureKind, tries_left: number | null): AttemptState {
  return { state: 'ended', failure: { kind, tries_left }, mode: 'code', service: null }
}

describe('pairing with a host', () => {
  it('starts at the code field, focused, and takes a code exactly as typed', async () => {
    start()
    expect(await screen.findByRole('heading', { name: 'Pair with a host' })).toBeInTheDocument()
    const field = screen.getByLabelText('Pairing code')
    await waitFor(() => {
      expect(document.activeElement).toBe(field)
    })
    expect(field.getAttribute('autocapitalize')).toBe('off')
    expect(field.getAttribute('autocorrect')).toBe('off')
    expect(field.getAttribute('spellcheck')).toBe('false')
    expect(field.getAttribute('enterkeyhint')).toBe('go')
    expect(field.getAttribute('placeholder')).toBe('XXXX-XXX-XXX')
    await userEvent.type(field, 'aB3x-Yz7-9Qw')
    expect((field as HTMLInputElement).value).toBe('aB3x-Yz7-9Qw')
  })

  it('enables Pair at ten valid characters and sends the code to native code once', async () => {
    const { controls } = start()
    const field = await screen.findByLabelText('Pairing code')
    const pair = screen.getByTestId('pair')
    await userEvent.type(field, 'aB3x-Yz7-9Q')
    expect(pair).toBeDisabled()
    await userEvent.type(field, 'w')
    expect(pair).toBeEnabled()
    await userEvent.type(field, '{Enter}')
    expect(controls.startedCodes).toEqual(['aB3x-Yz7-9Qw'])
  })

  it('says inline what is wrong with a character, but not while an input method composes', async () => {
    start()
    const field = await screen.findByLabelText('Pairing code')
    fireEvent.compositionStart(field)
    fireEvent.change(field, { target: { value: 'aB0' } })
    expect(screen.queryByRole('alert')).toBeNull()
    fireEvent.compositionEnd(field)
    expect((await screen.findByRole('alert')).textContent).toMatch(/never contains “0”/)
  })

  it('shows one status line while working, and the value with its grant once the host asks', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, { state: 'working', stage: 'checking_code' })
    expect((await screen.findByTestId('pairing-status')).textContent).toMatch('Checking the code')
    attempt(controls, {
      state: 'awaiting_approval',
      value: 'f3c1 46fd',
      expires_at_ms: IN_FIVE_MINUTES,
      rights: ['session.view'],
      authority: 'view sessions',
      grant_expires_at_ms: null
    })
    const heading = await screen.findByRole('heading', { name: 'Check this value on the host' })
    await waitFor(() => {
      expect(document.activeElement).toBe(heading)
    })
    const value = screen.getByTestId('verification-value')
    expect(value.textContent).toContain('f 3 c 1, 4 6 f d')
    expect(within(value).getAllByText(/^(f3c1|46fd)$/)).toHaveLength(2)
    expect(screen.getByTestId('grant-line').textContent).toBe(
      'If approved, this computer can view sessions.'
    )
    expect(screen.getByTestId('waiting-line').textContent).toMatch(/Waiting for approval, [45] minutes left/)
  })

  it('keeps the value on screen while reconnecting, and shows none before the host confirmed it', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, { state: 'reconnecting', value: null, expires_at_ms: null })
    expect((await screen.findByTestId('pairing-status')).textContent).toBe(
      'Connection lost. Reconnecting.'
    )
    expect(screen.queryByTestId('verification-value')).toBeNull()
    attempt(controls, { state: 'reconnecting', value: 'f3c1 46fd', expires_at_ms: null })
    expect(await screen.findByTestId('verification-value')).toBeInTheDocument()
  })

  it('stops waiting on this computer only, and says the host keeps the request', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, {
      state: 'awaiting_approval',
      value: 'f3c1 46fd',
      expires_at_ms: IN_FIVE_MINUTES,
      rights: [],
      authority: 'view sessions',
      grant_expires_at_ms: null
    })
    await userEvent.click(await screen.findByTestId('stop-waiting'))
    expect(
      await screen.findByText(
        'Stopped. The host keeps the request until it expires or the owner declines it.'
      )
    ).toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: 'Pair with a host' })).toBeInTheDocument()
  })

  it('says what this computer became once paired', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, {
      state: 'paired',
      host: { name: 'r on macos', owner: true, authority: 'manage the host as an owner', grant_expires_at_ms: null }
    })
    expect(await screen.findByRole('heading', { name: 'Paired with r on macos' })).toBeInTheDocument()
    expect(screen.getByTestId('paired-line').textContent).toBe(
      'This computer is an owner of r on macos. It will ask you to confirm changes there.'
    )
  })

  it('gives every failure kind its own sentence and action, with the tries line when charged', async () => {
    const kinds: FailureKind[] = [
      'service_unreachable',
      'service_not_pairing',
      'no_host_answered',
      'not_authenticated',
      'host_tries_used',
      'expired',
      'timed_out',
      'declined',
      'approval_unknown'
    ]
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    for (const kind of kinds) {
      attempt(controls, ended(kind, 3))
      const sentence = await screen.findByTestId('failure-sentence')
      expect(sentence.textContent).toBe(
        `${failureWords(kind, 'reach.kala.to').sentence} 3 tries left on this device.`
      )
    }
    attempt(controls, ended('declined', null))
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(
      'The owner declined this device on the host.'
    )
  })

  it('names the service a pasted code went through when that attempt fails', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, {
      state: 'ended',
      failure: { kind: 'service_unreachable', tries_left: 4 },
      mode: 'code',
      service: 'pair.example.org'
    })
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(
      "pair.example.org could not be reached. Check this device's connection and try again. 4 tries left on this device."
    )
  })

  it('gives a direct invitation that failed its own words, and asks for it again', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, {
      state: 'ended',
      failure: { kind: 'not_authenticated', tries_left: null },
      mode: 'direct',
      service: null
    })
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(
      'The invitation did not work. Ask the host for a new one.'
    )
    const action = screen.getByTestId('failure-action')
    expect(action.textContent).toBe('Paste again')
    await userEvent.click(action)
    // Pasting again reads the clipboard, which holds nothing now.
    expect((await screen.findByTestId('paste-failure')).textContent).toMatch(
      /^The clipboard holds no invitation\./
    )
    attempt(controls, {
      state: 'ended',
      failure: { kind: 'did_not_finish', tries_left: null },
      mode: 'direct',
      service: null
    })
    expect((await screen.findByTestId('failure-action')).textContent).toBe('Paste again')
  })

  it('names an unknown failure kind only as not finished, with the generic action', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, ended('a_kind_from_a_newer_build' as FailureKind, null))
    expect(await screen.findByRole('heading', { name: 'Pairing did not finish' })).toBeInTheDocument()
    expect(screen.getByTestId('failure-sentence').textContent).toMatch(/^Pairing did not finish/)
    expect(screen.getByTestId('failure-action').textContent).toBe('Try again')
  })

  it('returns to the code, selected, after the code did not work', async () => {
    const { controls } = start()
    const field = await screen.findByLabelText('Pairing code')
    await userEvent.type(field, 'aB3x-Yz7-9Qw')
    attempt(controls, ended('not_authenticated', 4))
    await userEvent.click(await screen.findByTestId('failure-action'))
    const again = await screen.findByLabelText('Pairing code')
    await waitFor(() => {
      expect(document.activeElement).toBe(again)
    })
    expect((again as HTMLInputElement).value).toBe('aB3x-Yz7-9Qw')
    expect((again as HTMLInputElement).selectionEnd).toBe('aB3x-Yz7-9Qw'.length)
  })

  it('lets go of the typed code once pairing ends, and keeps it only to try it again', async () => {
    const CODE = 'aB3x-Yz7-9Qw'
    const { controls } = start()
    const typed = async () => {
      const field = await screen.findByLabelText('Pairing code')
      await userEvent.clear(field)
      await userEvent.type(field, CODE)
    }
    const shown = async () =>
      (await screen.findByLabelText<HTMLInputElement>('Pairing code')).value
    const waiting: AttemptState = {
      state: 'awaiting_approval',
      value: 'f3c1 46fd',
      expires_at_ms: IN_FIVE_MINUTES,
      rights: [],
      authority: 'view sessions',
      grant_expires_at_ms: null
    }

    // Paired: the code is spent.
    await typed()
    attempt(controls, waiting)
    attempt(controls, {
      state: 'paired',
      host: { name: 'studio', owner: false, authority: 'view sessions', grant_expires_at_ms: null }
    })
    await userEvent.click(await screen.findByTestId('pairing-done'))
    expect(await shown()).toBe('')

    // Stopped while waiting for the owner.
    await typed()
    attempt(controls, waiting)
    await userEvent.click(await screen.findByTestId('stop-waiting'))
    expect(await shown()).toBe('')

    // Ended in a way no second try of the same code can mend.
    for (const kind of ['host_tries_used', 'declined', 'expired'] as const) {
      await typed()
      attempt(controls, ended(kind, 2))
      await userEvent.click(await screen.findByTestId('failure-action'))
      expect(await shown(), kind).toBe('')
    }

    // Ended in a way the same code may mend: it waits in the field.
    for (const kind of ['service_unreachable', 'no_host_answered', 'service_not_pairing'] as const) {
      await typed()
      attempt(controls, ended(kind, 2))
      await userEvent.click(await screen.findByTestId('failure-action'))
      expect(await shown(), kind).toBe(CODE)
    }
  })

  it('shows a pasted invitation as a summary, and pairs or cancels it', async () => {
    const { controls } = start()
    controls.setPasteboard({
      invitation: {
        mode: 'direct',
        origin_host: null,
        names_another_origin: false,
        rights: ['session.view'],
        authority: 'view sessions',
        grant_expires_at_ms: null,
        expires_at_ms: IN_FIVE_MINUTES
      },
      failure: null,
      cleared: true,
      declined: false
    })
    await userEvent.click(await screen.findByTestId('paste-invitation'))
    expect((await screen.findByTestId('invitation-summary')).textContent).toMatch(
      /^Invitation from a host on this network\. If approved, this computer can view sessions\. It expires in [45] minutes\.$/
    )
    expect(
      await screen.findByText('The invitation was taken from the clipboard and cleared from it.')
    ).toBeInTheDocument()
    await userEvent.keyboard('{Escape}')
    expect(await screen.findByRole('heading', { name: 'Pair with a host' })).toBeInTheDocument()
  })

  it('says when the clipboard holds no invitation', async () => {
    start()
    await userEvent.click(await screen.findByTestId('paste-invitation'))
    expect((await screen.findByTestId('paste-failure')).textContent).toBe(
      'The clipboard holds no invitation. Copy the invitation text from the host, then paste again.'
    )
  })

  it('lists the paired hosts under the entry, and draws no list when there are none', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    expect(screen.queryByTestId('paired-hosts')).toBeNull()
    act(() => {
      controls.setPairing({
        hosts: [
          { name: 'studio', owner: true, authority: 'manage the host as an owner', grant_expires_at_ms: null, in_contact: true },
          { name: 'build box', owner: false, authority: 'view sessions', grant_expires_at_ms: null, in_contact: null }
        ]
      })
    })
    const list = await screen.findByTestId('paired-hosts')
    expect(list.textContent).toContain('Owner')
    expect(list.textContent).toContain('In contact')
    expect(list.textContent).toContain('Can view sessions')
  })

  it('reads the state once it is listening, so a change while it registers is not lost', async () => {
    const { port, controls } = fakeHost()
    const complete = controls.holdRegistrations()
    render(
      <AppProvider port={port} initialPlace={{ view: 'pairing' }}>
        <App />
      </AppProvider>
    )
    act(() => {
      controls.setPairing({ state: { state: 'working', stage: 'checking_code' } })
    })
    await act(async () => {
      complete()
      await Promise.resolve()
    })
    expect((await screen.findByTestId('pairing-status')).textContent).toBe('Checking the code')
  })

  it('changes the service codes go through', async () => {
    start()
    await userEvent.click(await screen.findByTestId('change-service'))
    const input = await screen.findByTestId('service-input')
    await userEvent.clear(input)
    await userEvent.type(input, 'https://pair.example.org')
    await userEvent.click(screen.getByTestId('save-service'))
    await waitFor(() => {
      expect(screen.getByTestId('pairing-service').textContent).toBe('pair.example.org')
    })
  })
})

function request(overrides: Partial<ConfirmationRequest> = {}): ConfirmationRequest {
  return {
    reference: 'r-1',
    host_name: 'studio',
    title: 'Add a device',
    detail: 'Confirm adding Pixel 8 (Android) to studio, which may view sessions for 60 minutes.',
    value: 'f3c1 46fd',
    expires_at_ms: Date.now() + 110_000,
    checkable: true,
    ...overrides
  }
}

describe("the owner's confirmations", () => {
  it('heads Attention, with a button named for this computer’s ceremony', async () => {
    const { controls } = start({ view: 'attention' })
    act(() => {
      controls.setConfirmations({ ceremony: 'touch_id', requests: [request()] })
    })
    const row = await screen.findByTestId('confirmation-row')
    expect(within(row).getByText('Add a device')).toBeInTheDocument()
    expect(within(row).getByTestId('confirm-request').textContent).toBe('Confirm with Touch ID')
    act(() => {
      controls.setConfirmations({ ceremony: 'windows_hello', requests: [request()] })
    })
    expect((await screen.findByTestId('confirm-request')).textContent).toBe(
      'Confirm with Windows Hello'
    )
    act(() => {
      controls.setConfirmations({ ceremony: 'password', requests: [request()] })
    })
    expect((await screen.findByTestId('confirm-request')).textContent).toBe(
      'Confirm with your password'
    )
  })

  it('offers nothing to press on a computer with no ceremony, or for a request it cannot check', async () => {
    const { controls } = start({ view: 'attention' })
    act(() => {
      controls.setConfirmations({ ceremony: 'none', requests: [request()] })
    })
    expect(await screen.findByTestId('no-ceremony')).toBeInTheDocument()
    expect(screen.queryByTestId('confirm-request')).toBeNull()
    act(() => {
      controls.setConfirmations({
        ceremony: 'touch_id',
        requests: [request({ checkable: false, detail: null, value: null })]
      })
    })
    expect(await screen.findByTestId('cannot-check')).toBeInTheDocument()
    expect(screen.queryByTestId('confirm-request')).toBeNull()
  })

  it('reviews by reference alone, and says how it ended', async () => {
    const { controls } = start({ view: 'attention' })
    act(() => {
      controls.setConfirmations({ ceremony: 'touch_id', requests: [request()] })
    })
    await userEvent.click(await screen.findByTestId('confirm-request'))
    await waitFor(() => {
      expect(controls.reviewed).toEqual(['r-1'])
    })
    expect(await screen.findByText('Confirmed. studio can go ahead.')).toBeInTheDocument()
  })

  it('says a review whose answer the host never acknowledged is not known, not that nothing changed', async () => {
    const { controls } = start({ view: 'attention' })
    controls.setReviewOutcome('unknown')
    act(() => {
      controls.setConfirmations({ ceremony: 'touch_id', requests: [request()] })
    })
    await userEvent.click(await screen.findByTestId('confirm-request'))
    expect(
      await screen.findByText(
        'studio did not say whether it took the confirmation. While the request is listed here, it is not confirmed.'
      )
    ).toBeInTheDocument()
    expect(screen.queryByText('Not confirmed. Nothing changed.')).toBeNull()
  })

  it('hides a request with Not now, without answering it', async () => {
    const { controls } = start({ view: 'attention' })
    act(() => {
      controls.setConfirmations({ ceremony: 'touch_id', requests: [request()] })
    })
    await userEvent.click(await screen.findByTestId('not-now'))
    await waitFor(() => {
      expect(screen.queryByTestId('confirmation-row')).toBeNull()
    })
    expect(controls.reviewed).toEqual([])
  })

  it('reads the requests once it is listening, so one asked while it registers is shown', async () => {
    const { port, controls } = fakeHost()
    const complete = controls.holdRegistrations()
    render(
      <AppProvider port={port} initialPlace={{ view: 'attention' }}>
        <App />
      </AppProvider>
    )
    act(() => {
      controls.setConfirmations({ ceremony: 'touch_id', requests: [request()] })
    })
    await act(async () => {
      complete()
      await Promise.resolve()
    })
    expect(await screen.findByTestId('confirmation-row')).toBeInTheDocument()
  })

  it('announces a new request on any screen, and Review opens it in Attention with focus on it', async () => {
    const { controls } = start({ view: 'sessions' })
    act(() => {
      controls.setConfirmations({ ceremony: 'touch_id', requests: [request()] })
    })
    const toast = (await screen.findByText('studio needs your confirmation')).closest<HTMLElement>(
      '[role="status"]'
    )
    expect(toast).not.toBeNull()
    await userEvent.click(within(toast!).getByRole('button', { name: 'Review' }))
    const row = await screen.findByTestId('confirmation-row')
    await waitFor(() => {
      expect(row.contains(document.activeElement)).toBe(true)
    })
    expect(screen.getByRole('heading', { name: 'What needs you' })).toBeInTheDocument()
  })

  it('keeps a request set aside with Not now until it expires, whatever screen comes between', async () => {
    const { controls } = start({ view: 'attention' })
    act(() => {
      controls.setConfirmations({ ceremony: 'touch_id', requests: [request()] })
    })
    await userEvent.click(await screen.findByTestId('not-now'))
    await waitFor(() => {
      expect(screen.queryByTestId('confirmation-row')).toBeNull()
    })
    await userEvent.click(screen.getByRole('button', { name: 'Sessions' }))
    await userEvent.click(screen.getByRole('button', { name: /^Attention/ }))
    expect(await screen.findByRole('heading', { name: 'What needs you' })).toBeInTheDocument()
    expect(screen.queryByTestId('confirmation-row')).toBeNull()
    expect(screen.queryByLabelText(/waiting for confirmation/)).toBeNull()
  })

  it('says the owner’s value one character at a time to a screen reader, and once', async () => {
    const { controls } = start({ view: 'attention' })
    act(() => {
      controls.setConfirmations({ ceremony: 'touch_id', requests: [request()] })
    })
    const row = await screen.findByTestId('confirmation-row')
    const value = within(row).getByTestId('confirmation-value')
    expect(value.textContent).toContain('f 3 c 1, 4 6 f d')
    expect(within(value).getByText('f3c1 46fd').getAttribute('aria-hidden')).toBe('true')
    // Everything a screen reader reads in the row says the value only spelled.
    const read = [...row.querySelectorAll('*')]
      .filter((element) => element.closest('[aria-hidden="true"]') === null)
      .map((element) =>
        [...element.childNodes]
          .filter((node) => node.nodeType === Node.TEXT_NODE)
          .map((node) => node.textContent)
          .join('')
      )
      .join(' ')
    expect(read).not.toContain('f3c1')
  })

  it('fades a request that went in its own row, and takes it away whatever arrives meanwhile', async () => {
    const { controls } = start({ view: 'attention' })
    const first = request({ reference: 'r-1', title: 'Add a device' })
    const second = request({ reference: 'r-2', title: 'Issue an invitation', value: null })
    act(() => {
      controls.setConfirmations({ ceremony: 'touch_id', requests: [first, second] })
    })
    const leaving = (await screen.findByText('Add a device')).closest('li')
    expect(leaving).not.toBeNull()
    act(() => {
      controls.setConfirmations({ ceremony: 'touch_id', requests: [second] })
    })
    // The same row fades: it keeps its place and its identity while it leaves.
    expect(leaving?.isConnected).toBe(true)
    expect(leaving?.getAttribute('data-leaving')).toBe('true')
    // Another update arrives while it fades; it still goes.
    act(() => {
      controls.setConfirmations({
        ceremony: 'touch_id',
        requests: [{ ...second, expires_at_ms: second.expires_at_ms - 1000 }]
      })
    })
    await waitFor(() => {
      expect(screen.queryByText('Add a device')).toBeNull()
    })
    expect(screen.getByText('Issue an invitation')).toBeInTheDocument()
  })

  it('counts waiting confirmations beside Attention', async () => {
    const { controls } = start({ view: 'attention' })
    act(() => {
      controls.setConfirmations({ ceremony: 'touch_id', requests: [request(), request({ reference: 'r-2' })] })
    })
    expect(await screen.findByLabelText('2 waiting for confirmation')).toBeInTheDocument()
  })
})
