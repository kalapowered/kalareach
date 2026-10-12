/**
 * The sharing tab, driven the way a person drives it.
 *
 * These render the real application against the scripted host and check what the screen does with
 * what it is told: which devices an invitation can go to and why not the others, which lifetimes fit
 * inside a pairing, that consent gates Invite and resets with the choice, that a screen the preview
 * cut cannot be shared, that an attempt whose answer was lost is listed as such and never as done,
 * and that a hand-over waits for an owner device. What the host and the application's backend do
 * with a request is checked against a real daemon in the backend's own tests; this file is about
 * what the page shows and refuses.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost, type FakeHostControls } from '../src/host/fake'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** Opens the sharing tab of the main session. */
async function openSharing(): Promise<{
  controls: FakeHostControls
  person: ReturnType<typeof userEvent.setup>
}> {
  const { port, controls } = fakeHost()
  render(
    <AppProvider port={port} initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}>
      <App />
    </AppProvider>
  )
  const person = userEvent.setup()
  await person.click(await screen.findByTestId('open-settings'))
  await person.click(await screen.findByRole('button', { name: 'Sharing' }))
  await screen.findByTestId('share-form')
  await waitFor(() => {
    expect(screen.getByRole('radio', { name: /Sam’s iPhone|Sam's iPhone/ })).toBeInTheDocument()
  })
  return { controls, person }
}

/** Reads the screen's lists again, as the window being focused does. */
async function reread(): Promise<void> {
  await act(async () => {
    window.dispatchEvent(new Event('focus'))
    await Promise.resolve()
  })
}

const PHONE = /Sam’s iPhone|Sam's iPhone/

describe('who an invitation can go to', () => {
  it('offers the devices it can, says why not for the others, and omits a retired one', async () => {
    await openSharing()
    const recipients = screen.getByTestId('recipients')
    expect(within(recipients).getByRole('radio', { name: PHONE })).toBeInTheDocument()
    expect(within(recipients).getByRole('radio', { name: /Guest tablet/ })).toBeInTheDocument()
    expect(within(recipients).queryByRole('radio', { name: /Old phone/ })).toBeNull()
    for (const refused of [/Ricky’s Mac|Ricky's Mac/, /Sam’s iPad|Sam's iPad/, /Lapsed laptop/]) {
      expect(within(recipients).queryByRole('radio', { name: refused })).toBeNull()
    }
    const reasons = screen.getByTestId('not-offered')
    expect(reasons.textContent).toMatch(/An owner device already has every session/)
    expect(reasons.textContent).toMatch(/pairing already opens every session/)
    expect(reasons.textContent).toMatch(/pairing has ended. Pair it again/)
  })

  it('lists the owner device as having access whatever is done to a share', async () => {
    await openSharing()
    const access = screen.getByTestId('access')
    await waitFor(() => {
      expect(within(access).getByText(/Owner device · always has access/)).toBeInTheDocument()
    })
    expect(within(access).getByTestId('access-note').textContent).toMatch(/keeps its own\s+access/)
  })
})

describe('how long an invitation lasts', () => {
  it('offers an hour by default, and only the lifetimes that fit inside the pairing', async () => {
    const { person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: PHONE }))
    const lasts = screen.getByTestId<HTMLSelectElement>('lasts')
    const labels = Array.from(lasts.options).map((each) => each.textContent)
    // The phone's pairing has six days left: seven days and thirty do not fit.
    expect(labels).toEqual(['15 minutes', '1 hour', '1 day', expect.stringMatching(/^Until its pairing ends/)])
    expect(lasts.value).toBe('1h')
  })

  it('ends the list with the pairing and starts from it when an hour does not fit', async () => {
    const { person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: /Guest tablet/ }))
    const lasts = screen.getByTestId<HTMLSelectElement>('lasts')
    const labels = Array.from(lasts.options).map((each) => each.textContent)
    // Forty minutes are left: a quarter of an hour fits, an hour does not.
    expect(labels).toEqual(['15 minutes', expect.stringMatching(/^Until its pairing ends/)])
    expect(lasts.value).toBe('pairing')
    expect(screen.getByTestId('lasts-note').textContent).toMatch(/A share cannot outlast it/)
  })
})

describe('consent', () => {
  it('keeps Invite off until the consequences are understood, and asks again when the choice changes', async () => {
    const { person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: PHONE }))
    const invite = screen.getByTestId('invite')
    // A viewer carries no consequence: nothing to understand.
    await waitFor(() => {
      expect(invite).toBeEnabled()
    })

    await person.click(screen.getByRole('radio', { name: /Controller/ }))
    const consent = await screen.findByRole('checkbox', { name: /I understand this lets Sam/ })
    await waitFor(() => {
      expect(screen.getByTestId('invite')).toBeDisabled()
    })
    await person.click(consent)
    await waitFor(() => {
      expect(screen.getByTestId('invite')).toBeEnabled()
    })
    expect(screen.getByTestId('invitation-carries').textContent).toContain('Resize the terminal')

    // A different role is a different consent.
    await person.click(screen.getByRole('radio', { name: /Owner/ }))
    await waitFor(() => {
      expect(screen.getByRole('checkbox', { name: /I understand this lets Sam/ })).not.toBeChecked()
    })
    expect(screen.getByTestId('invite')).toBeDisabled()
  })

  it('names the host’s own sentence for what a controller can do, before anything is issued', async () => {
    const { person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: /Controller/ }))
    const carries = screen.getByTestId('invitation-carries')
    await waitFor(() => {
      expect(carries.querySelector('[data-notice="account_access"]')).not.toBeNull()
    })
    expect(carries.textContent).toContain('Type into the terminal')
  })
})

describe('the live view', () => {
  it('is off until it is turned on, and says what the recipient will not see', async () => {
    await openSharing()
    expect(screen.getByRole('switch', { name: 'Let them watch the session live' })).toHaveAttribute(
      'aria-checked',
      'false'
    )
    expect(screen.getByTestId('live-explanation').textContent).toMatch(
      /will not see the terminal or a live stream/
    )
  })

  it('shows the screen as it is read, with control and direction characters made visible', async () => {
    const { controls, person } = await openSharing()
    controls.sharing.setScreen(['$ ls', '\u001b[31mred\u001b[0m', 'a‮b', 'bell\u0007'])
    await person.click(screen.getByRole('switch', { name: 'Let them watch the session live' }))
    const card = await screen.findByRole('region', { name: /^Screen at / })
    expect(card.textContent).toContain('$ ls')
    expect(card.textContent).toContain('␛[31mred␛[0m')
    expect(card.textContent).toContain('a‹U+202E›b')
    expect(card.textContent).toContain('bell␇')
    expect(card).toHaveAttribute('tabindex', '0')
    expect(screen.getByTestId('live-explanation').textContent).toMatch(
      /A resize can bring earlier lines into view/
    )
  })

  it('cannot issue an invitation whose screen the preview cut', async () => {
    const { controls, person } = await openSharing()
    controls.sharing.setScreen(['x'.repeat(10)], true)
    await person.click(screen.getByRole('radio', { name: PHONE }))
    await person.click(screen.getByRole('switch', { name: 'Let them watch the session live' }))
    expect(await screen.findByTestId('preview-cut')).toBeInTheDocument()
    expect(screen.getByTestId('invite')).toBeDisabled()

    // The screen shrinks; Refresh reads it again and Invite is possible.
    controls.sharing.setScreen(['x'])
    await person.click(screen.getByTestId('preview-refresh'))
    await waitFor(() => {
      expect(screen.queryByTestId('preview-cut')).toBeNull()
    })
    await waitFor(() => {
      expect(screen.getByTestId('invite')).toBeEnabled()
    })
  })

  it('leaves the switch off with the session’s own words when the screen cannot be read', async () => {
    const { controls, person } = await openSharing()
    controls.sharing.failPreview('no session 3')
    await person.click(screen.getByRole('switch', { name: 'Let them watch the session live' }))
    expect((await screen.findByTestId('preview-failure')).textContent).toMatch(/no session 3/)
    expect(screen.getByRole('switch', { name: 'Let them watch the session live' })).toHaveAttribute(
      'aria-checked',
      'false'
    )
  })

  it('says so when the screen changed between the preview and the write, and shows what was kept', async () => {
    const { controls, person } = await openSharing()
    controls.sharing.setScreen(['before'])
    await person.click(screen.getByRole('radio', { name: PHONE }))
    await person.click(screen.getByRole('switch', { name: 'Let them watch the session live' }))
    await screen.findByRole('region', { name: /^Screen at / })
    controls.sharing.setScreen(['after the program redrew'])
    await person.click(screen.getByTestId('invite'))
    const changed = await screen.findByTestId('screen-changed')
    expect(changed.textContent).toContain('after the program redrew')
    expect(changed.textContent).toMatch(/not\s+what you meant to share/)
  })
})

describe('who has access', () => {
  it('lists an invitation that waits, and withdraws it', async () => {
    const { controls, person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: PHONE }))
    await person.click(screen.getByTestId('invite'))
    const row = await waitFor(() => {
      const found = screen.getByTestId('access').querySelector('[data-state="pending"]')
      expect(found).not.toBeNull()
      return found as HTMLElement
    })
    expect(within(row).getByText('Waiting to be accepted')).toBeInTheDocument()
    expect(row.textContent).toMatch(/Sam’s iPhone|Sam's iPhone/)
    await person.click(within(row).getByTestId('withdraw'))
    await waitFor(() => {
      expect(screen.getByTestId('access').querySelector('[data-state="pending"]')).toBeNull()
    })
    expect(controls.sharing.grants().map((each) => each.state)).toEqual(['revoked'])
  })

  it('keeps a line while a session worker has not confirmed a revocation, until it is checked again', async () => {
    const { controls, person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: PHONE }))
    await person.click(screen.getByTestId('invite'))
    await waitFor(() => {
      expect(controls.sharing.grants()).toHaveLength(1)
    })
    controls.sharing.deviceAccepts(controls.sharing.grants()[0]?.grant.grant_id ?? '')
    await reread()
    const row = await waitFor(() => {
      const found = screen.getByTestId('access').querySelector('[data-state="active"]')
      expect(found).not.toBeNull()
      return found as HTMLElement
    })
    expect(row.textContent).toMatch(/What they already saw stays with them/)

    controls.sharing.holdBarrier(true)
    await person.click(within(row).getByTestId('revoke'))
    const line = await screen.findByTestId('recently-revoked')
    expect(line.textContent).toMatch(/1 session worker has not confirmed yet/)
    await person.click(within(line).getByTestId('check-again'))
    await waitFor(() => {
      expect(screen.getByTestId('recently-revoked').textContent).not.toMatch(/not confirmed yet/)
    })
    expect(controls.sharing.sent().revoke).toBe(2)
  })
})

describe('an attempt whose answer was lost', () => {
  it('is listed as unfinished, says until when, and is asked about and never sent again', async () => {
    const { controls, person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: PHONE }))
    controls.sharing.loseNextAnswer()
    await person.click(screen.getByTestId('invite'))
    const attempt = await screen.findByTestId('attempt')
    expect(attempt).toHaveAttribute('data-phase', 'unfinished')
    expect(attempt.textContent).toMatch(/The host has not said whether it happened/)
    expect(attempt.textContent).toMatch(/It can still happen until/)

    // A second invitation to the same device is not started while this one can still happen.
    await person.click(screen.getByTestId('invite'))
    await waitFor(() => {
      expect(controls.sharing.sent().invite).toBe(1)
    })

    await person.click(within(attempt).getByTestId('attempt-ask'))
    await waitFor(() => {
      expect(screen.queryByTestId('attempt')).toBeNull()
    })
    expect(await screen.findByText(/Invitation ready for Sam/)).toBeInTheDocument()
    expect(controls.sharing.grants()).toHaveLength(1)
    expect(controls.sharing.sent().invite).toBe(1)
  })

  it('stays listed when hidden, and says that something still can happen', async () => {
    const { controls, person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: PHONE }))
    controls.sharing.loseNextAnswer()
    await person.click(screen.getByTestId('invite'))
    const attempt = await screen.findByTestId('attempt')
    await person.click(within(attempt).getByTestId('attempt-hide'))
    await waitFor(() => {
      expect(screen.queryByTestId('attempt')).toBeNull()
    })
    expect(screen.getByTestId('hidden-attempts').textContent).toMatch(/1 hidden attempt can still\s+happen/)
  })

  it('is reported as not done only once the host has shown nothing past the bound, and can then be removed', async () => {
    const { controls, person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: PHONE }))
    controls.sharing.loseNextRequest()
    await person.click(screen.getByTestId('invite'))
    const attempt = await screen.findByTestId('attempt')
    expect(attempt).toHaveAttribute('data-phase', 'unfinished')
    expect(attempt.textContent).not.toMatch(/did not happen/)

    controls.sharing.passTheBound()
    await reread()
    const closed = await waitFor(() => {
      const found = screen.getByTestId('attempt')
      expect(found).toHaveAttribute('data-outcome', 'not_done')
      return found
    })
    expect(closed.textContent).toMatch(/did not happen, as far as the host shows/)
    expect(closed.textContent).toMatch(/safe to try again/)
    await person.click(within(closed).getByTestId('attempt-remove'))
    await waitFor(() => {
      expect(screen.queryByTestId('attempt')).toBeNull()
    })
    expect(controls.sharing.grants()).toHaveLength(0)
  })

  it('is carried on after the command returned, and told once as the success it is', async () => {
    const { controls, person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: PHONE }))
    controls.sharing.loseNextAnswer()
    await person.click(screen.getByTestId('invite'))
    await screen.findByTestId('attempt')
    controls.sharing.recover()
    await reread()
    await waitFor(() => {
      expect(screen.queryByTestId('attempt')).toBeNull()
    })
    expect(await screen.findByText(/Invitation ready for Sam/)).toBeInTheDocument()
  })
})

describe('handing control over', () => {
  /** An owner share the device has accepted, so that there is something to hand over. */
  async function withOwnerShare(): Promise<Awaited<ReturnType<typeof openSharing>>> {
    const opened = await openSharing()
    const { controls, person } = opened
    await person.click(screen.getByRole('radio', { name: PHONE }))
    await person.click(screen.getByRole('radio', { name: /Owner/ }))
    // A quarter of an hour: short enough for the other tablet’s pairing to carry it on.
    await person.selectOptions(screen.getByTestId('lasts'), '15m')
    await person.click(await screen.findByRole('checkbox', { name: /I understand this lets Sam/ }))
    await person.click(screen.getByTestId('invite'))
    await waitFor(() => {
      expect(controls.sharing.grants()).toHaveLength(1)
    })
    controls.sharing.deviceAccepts(controls.sharing.grants()[0]?.grant.grant_id ?? '')
    await reread()
    await screen.findByTestId('hand-over-open')
    return opened
  }

  it('waits for an owner device and sends nothing until it has answered', async () => {
    const { controls, person } = await withOwnerShare()
    await person.click(screen.getByTestId('hand-over-open'))
    const sheet = await screen.findByTestId('hand-over')
    expect(sheet.textContent).toMatch(/An owner\s+device must confirm/)
    // Only a device the share can go to is chosen, and the giver is not one of them.
    expect(within(sheet).getByRole('radio', { name: /Sam’s iPhone|Sam's iPhone/ })).toBeDisabled()
    expect(within(sheet).getByRole('radio', { name: /Ricky’s Mac|Ricky's Mac/ })).toBeDisabled()
    expect(within(sheet).getByRole('radio', { name: /Sam’s iPad|Sam's iPad/ })).toBeDisabled()
    expect(within(sheet).getByRole('radio', { name: /Lapsed laptop/ })).toBeDisabled()
    expect(within(sheet).getByRole('radio', { name: /Guest tablet/ })).toBeEnabled()
    expect(within(sheet).getByTestId('hand-over-ask')).toBeDisabled()

    await person.click(within(sheet).getByRole('radio', { name: /Guest tablet/ }))
    expect(within(sheet).getByTestId('hand-over-ask')).toBeEnabled()
    expect(controls.sharing.sent().transfer).toBe(0)
  })

  it('hands the session over once an owner device has confirmed, and says so', async () => {
    const { controls, person } = await withOwnerShare()
    // The receiving device must be paired for as long as the share lasts.
    await person.click(screen.getByTestId('hand-over-open'))
    const sheet = await screen.findByTestId('hand-over')
    const receivers = within(sheet).getAllByRole<HTMLInputElement>('radio')
    const able = receivers.find((each) => !each.disabled)
    expect(able).toBeDefined()
    await person.click(able as HTMLInputElement)
    await person.click(within(sheet).getByTestId('hand-over-ask'))
    expect(await within(sheet).findByTestId('hand-over-waiting')).toBeInTheDocument()
    expect(controls.sharing.sent().transfer).toBe(1)
    act(() => {
      controls.sharing.ownerAnswers()
    })
    await waitFor(
      () => {
        expect(screen.queryByTestId('hand-over')).toBeNull()
      },
      { timeout: 4000 }
    )
    expect(await screen.findByText(/is now with/)).toBeInTheDocument()
  })

  it('tells the person when the owner devices ran out of time, and offers to ask again', async () => {
    const { controls, person } = await withOwnerShare()
    await person.click(screen.getByTestId('hand-over-open'))
    const sheet = await screen.findByTestId('hand-over')
    const receivers = within(sheet).getAllByRole<HTMLInputElement>('radio')
    await person.click(receivers.find((each) => !each.disabled) as HTMLInputElement)
    await person.click(within(sheet).getByTestId('hand-over-ask'))
    await within(sheet).findByTestId('hand-over-waiting')
    act(() => {
      controls.sharing.challengeRunsOut()
    })
    expect(await within(sheet).findByTestId('hand-over-gone', {}, { timeout: 4000 })).toBeInTheDocument()
    expect(within(sheet).getByTestId('hand-over-again')).toBeInTheDocument()
    expect(controls.sharing.grants().filter((each) => each.state === 'active')).toHaveLength(1)
  })
})
