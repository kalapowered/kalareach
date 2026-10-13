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

/** The scripted host, and the controls a test has over it. */
type Host = ReturnType<typeof fakeHost>

/** The same host reached by a page that has just started: nothing the page remembered is there. */
function started(host: Host): Host {
  return { ...host, port: { ...host.port } }
}

/**
 * Opens the sharing tab of the main session over a host. A test that stops the application and
 * starts it again unmounts the page and opens the same host again: the host keeps what native
 * code kept, and the page starts with nothing.
 */
async function openSharing(host: Host = fakeHost(), phone: RegExp = PHONE): Promise<{
  controls: FakeHostControls
  person: ReturnType<typeof userEvent.setup>
  unmount: () => void
}> {
  const { port, controls } = host
  const view = render(
    <AppProvider port={port} initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}>
      <App />
    </AppProvider>
  )
  const person = userEvent.setup()
  await person.click(await screen.findByTestId('open-settings'))
  await person.click(await screen.findByRole('button', { name: 'Sharing' }))
  await screen.findByTestId('share-form')
  await waitFor(() => {
    expect(screen.getByRole('radio', { name: phone })).toBeInTheDocument()
  })
  return { controls, person, unmount: view.unmount }
}

/** Reads the screen's lists again, as the window being focused does. */
async function reread(): Promise<void> {
  await act(async () => {
    window.dispatchEvent(new Event('focus'))
    await Promise.resolve()
  })
}

const PHONE = /Sam’s iPhone|Sam's iPhone/

/** An owner share the device has accepted, so that there is something to hand over. */
async function withOwnerShare(host: Host = fakeHost()): Promise<Awaited<ReturnType<typeof openSharing>>> {
  const opened = await openSharing(host)
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

/** Opens the hand-over sheet, chooses the device that can receive, and asks the owner devices. */
async function askForHandOver(person: ReturnType<typeof userEvent.setup>): Promise<HTMLElement> {
  await person.click(screen.getByTestId('hand-over-open'))
  const sheet = await screen.findByTestId('hand-over')
  const receivers = within(sheet).getAllByRole<HTMLInputElement>('radio')
  await person.click(receivers.find((each) => !each.disabled) as HTMLInputElement)
  await person.click(within(sheet).getByTestId('hand-over-ask'))
  await within(sheet).findByTestId('hand-over-waiting')
  return sheet
}


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

describe('a hand-over that is sent while the panel has stopped asking', () => {
  it('is told when the host’s answer comes after the panel moved on to sending', async () => {
    const { controls, person } = await withOwnerShare()
    const sheet = await askForHandOver(person)
    const hold = controls.sharing.holdNextFinish()
    act(() => {
      controls.sharing.ownerAnswers()
    })
    await within(sheet).findByTestId('hand-over-sending', {}, { timeout: 4000 })
    // Asked once, and sent once.
    expect(controls.sharing.sent().transfer).toBe(2)

    // The screen reads its lists again while the host has not answered, as it does every few
    // seconds: the sheet stays on what is true, and a later answer is still told.
    await reread()
    expect(screen.getByTestId('hand-over-sending')).toBeInTheDocument()
    act(() => {
      hold.give()
    })
    await waitFor(() => {
      expect(screen.queryByTestId('hand-over')).toBeNull()
    })
    expect(await screen.findByText(/is now with/)).toBeInTheDocument()
  })

  it('goes back to choosing with the host’s own words when the send is refused, and can ask again', async () => {
    const { controls, person } = await withOwnerShare()
    const sheet = await askForHandOver(person)
    const hold = controls.sharing.holdNextFinish()
    act(() => {
      controls.sharing.ownerAnswers()
    })
    await within(sheet).findByTestId('hand-over-sending', {}, { timeout: 4000 })
    act(() => {
      hold.refuse('PERMISSION_DENIED', 'the host would not hand the session over')
    })
    const failure = await within(sheet).findByTestId('hand-over-failure')
    expect(failure.textContent).toMatch(/the host would not hand the session over/)
    expect(within(sheet).queryByTestId('hand-over-sending')).toBeNull()

    // Nothing is left holding the session’s place: another request is asked at once.
    await person.click(within(sheet).getByTestId('hand-over-ask'))
    expect(await within(sheet).findByTestId('hand-over-waiting')).toBeInTheDocument()
    // Asked, sent and refused, and asked again.
    expect(controls.sharing.sent().transfer).toBe(3)
  })

  it('shows how far the session workers have got with the share the giver lost, and checks again', async () => {
    const { controls, person } = await withOwnerShare()
    await askForHandOver(person)
    controls.sharing.holdBarrier(true)
    act(() => {
      controls.sharing.ownerAnswers()
    })
    const line = await screen.findByTestId('recently-revoked', {}, { timeout: 4000 })
    expect(line.textContent).toMatch(/1 session worker has not confirmed yet/)
    await person.click(within(line).getByTestId('check-again'))
    await waitFor(() => {
      expect(screen.getByTestId('recently-revoked').textContent).not.toMatch(/not confirmed yet/)
    })
  })

  it('lets the hand-over go when the panel is left, so nothing holds the session’s place', async () => {
    const { controls, person, unmount } = await withOwnerShare()
    await askForHandOver(person)
    expect(controls.sharing.attempts()).toHaveLength(1)
    unmount()
    await waitFor(() => {
      expect(controls.sharing.attempts()).toHaveLength(0)
    })
    expect(controls.sharing.sent().transfer).toBe(1)
  })

  it('cancels a hand-over whose reference the application lost when it started again', async () => {
    const host = fakeHost()
    const first = await withOwnerShare(host)
    await askForHandOver(first.person)
    first.controls.sharing.restart()
    first.unmount()

    const { person } = await openSharing(started(host))
    const row = await screen.findByTestId('attempt')
    expect(row).toHaveAttribute('data-phase', 'asking')
    // It is not asked about and not hidden away with the session’s place held: it is cancelled.
    expect(within(row).queryByTestId('attempt-ask')).toBeNull()
    expect(within(row).queryByTestId('attempt-hide')).toBeNull()
    await person.click(within(row).getByTestId('attempt-cancel'))
    await waitFor(() => {
      expect(screen.queryByTestId('attempt')).toBeNull()
    })
    expect(host.controls.sharing.attempts()).toHaveLength(0)
  })
})

describe('an attempt the person hid', () => {
  it('is shown again by the one control that says it is hidden, and focus follows', async () => {
    const { controls, person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: PHONE }))
    controls.sharing.loseNextAnswer()
    await person.click(screen.getByTestId('invite'))
    const attempt = await screen.findByTestId('attempt')
    await person.click(within(attempt).getByTestId('attempt-hide'))
    await waitFor(() => {
      expect(screen.queryByTestId('attempt')).toBeNull()
    })
    const show = await screen.findByTestId('attempt-show')
    await waitFor(() => {
      expect(show).toHaveFocus()
    })
    expect(controls.sharing.attempts()[0]?.hidden).toBe(true)

    await person.click(show)
    const back = await screen.findByTestId('attempt')
    await waitFor(() => {
      expect(back).toHaveFocus()
    })
    expect(screen.queryByTestId('hidden-attempts')).toBeNull()
    // Shown again, it can be asked about, and the host answers from its record.
    await person.click(within(back).getByTestId('attempt-ask'))
    await waitFor(() => {
      expect(screen.queryByTestId('attempt')).toBeNull()
    })
    expect(controls.sharing.grants()).toHaveLength(1)
  })
})

describe('the screen the host kept with a live invitation', () => {
  /** An invitation with the live view whose answer is lost after the host wrote it. */
  async function liveInvitationLost(host: Host = fakeHost()) {
    const opened = await openSharing(host)
    const { controls, person } = opened
    controls.sharing.setScreen(['before'])
    await person.click(screen.getByRole('radio', { name: PHONE }))
    await person.click(screen.getByRole('switch', { name: 'Let them watch the session live' }))
    await screen.findByRole('region', { name: /^Screen at / })
    return opened
  }

  it('is compared with the one the person saw when the answer is recovered in the background', async () => {
    const { controls, person } = await liveInvitationLost()
    controls.sharing.setScreen(['after the program redrew'])
    controls.sharing.loseNextAnswer()
    await person.click(screen.getByTestId('invite'))
    await screen.findByTestId('attempt')
    controls.sharing.recover()
    await reread()
    const card = await screen.findByTestId('screen-changed')
    expect(card).toHaveAttribute('data-kind', 'changed')
    expect(card.textContent).toContain('after the program redrew')
    await waitFor(() => {
      expect(screen.queryByTestId('attempt')).toBeNull()
    })
    expect(controls.sharing.attempts()).toHaveLength(0)
  })

  it('says nothing when it is the screen the person saw', async () => {
    const { controls, person } = await liveInvitationLost()
    controls.sharing.loseNextAnswer()
    await person.click(screen.getByTestId('invite'))
    await screen.findByTestId('attempt')
    controls.sharing.recover()
    await reread()
    await waitFor(() => {
      expect(screen.queryByTestId('attempt')).toBeNull()
    })
    expect(await screen.findByText(/Invitation ready for Sam/)).toBeInTheDocument()
    expect(screen.queryByTestId('screen-changed')).toBeNull()
  })

  it('says it could not be compared, and offers to withdraw, when the application started again before the answer', async () => {
    const host = fakeHost()
    const first = await liveInvitationLost(host)
    first.controls.sharing.loseNextAnswer()
    await first.person.click(screen.getByTestId('invite'))
    await screen.findByTestId('attempt')
    // The host’s answer is recovered, and the application stops before the page reads it.
    first.controls.sharing.recover()
    first.controls.sharing.restart()
    first.unmount()

    // A page that starts again is a new page over the same host: it has no memory of what was shown.
    const { person } = await openSharing(started(host))
    const row = await screen.findByTestId('attempt')
    expect(row).toHaveAttribute('data-phase', 'closed')
    expect(within(row).getByTestId('attempt-unverified')).toBeInTheDocument()
    await person.click(within(row).getByTestId('attempt-ask'))
    const card = await screen.findByTestId('screen-changed')
    expect(card).toHaveAttribute('data-kind', 'unverified')
    expect(card.textContent).toContain('before')
    await person.click(within(card).getByTestId('screen-withdraw'))
    await waitFor(() => {
      expect(screen.queryByTestId('screen-changed')).toBeNull()
    })
    expect(host.controls.sharing.grants().map((each) => each.state)).toEqual(['revoked'])
  })
})

describe('a revocation whose answer was lost', () => {
  /** A share the device accepted, ready to be taken back. */
  async function withActiveShare(host: Host = fakeHost()) {
    const opened = await openSharing(host)
    const { controls, person } = opened
    await person.click(screen.getByRole('radio', { name: PHONE }))
    await person.click(screen.getByTestId('invite'))
    await waitFor(() => {
      expect(controls.sharing.grants()).toHaveLength(1)
    })
    controls.sharing.deviceAccepts(controls.sharing.grants()[0]?.grant.grant_id ?? '')
    await reread()
    await waitFor(() => {
      expect(screen.getByTestId('access').querySelector('[data-state="active"]')).not.toBeNull()
    })
    return opened
  }

  it('keeps what the host said of the workers when it is recovered in the background, and checks again', async () => {
    const { controls, person } = await withActiveShare()
    controls.sharing.holdBarrier(true)
    controls.sharing.loseNextAnswer()
    await person.click(screen.getByTestId('revoke'))
    await screen.findByTestId('attempt')
    controls.sharing.recover()
    await reread()
    const line = await screen.findByTestId('recently-revoked')
    expect(line.textContent).toMatch(/1 session worker has not confirmed yet/)
    await person.click(within(line).getByTestId('check-again'))
    // The line the background road made is the one the check changes.
    await waitFor(() => {
      expect(screen.getByTestId('recently-revoked').textContent).not.toMatch(/not confirmed yet/)
    })
    expect(screen.getAllByTestId('recently-revoked')).toHaveLength(1)
  })

  it('keeps what the host said of the workers when the person asks the host', async () => {
    const { controls, person } = await withActiveShare()
    controls.sharing.holdBarrier(true)
    controls.sharing.loseNextAnswer()
    await person.click(screen.getByTestId('revoke'))
    await screen.findByTestId('attempt')
    controls.sharing.passTheBound()
    await reread()
    const row = await waitFor(() => {
      const found = screen.getByTestId('attempt')
      expect(found).toHaveAttribute('data-outcome', 'happened')
      return found
    })
    await person.click(within(row).getByTestId('attempt-ask'))
    const line = await screen.findByTestId('recently-revoked')
    expect(line.textContent).toMatch(/1 session worker has not confirmed yet/)
    expect(within(line).getByTestId('check-again')).toBeInTheDocument()
  })
})

describe('what an invitation is agreed to', () => {
  /** Chooses a viewer who may answer questions, so the invitation carries a consequence. */
  async function consentedTo(person: ReturnType<typeof userEvent.setup>): Promise<HTMLElement> {
    await person.click(screen.getByRole('radio', { name: PHONE }))
    await person.click(screen.getByRole('switch', { name: 'Let a viewer answer questions' }))
    const consent = await screen.findByRole('checkbox', { name: /I understand this lets Sam/ })
    await person.click(consent)
    expect(consent).toBeChecked()
    return consent
  }

  it('is asked for again whenever any choice changes, and not given back by changing it back', async () => {
    const { person } = await openSharing()
    const consent = await consentedTo(person)

    // The earlier activity, the lifetime and the live view each take the tick back.
    await person.selectOptions(screen.getByTestId('history'), 'hour')
    expect(consent).not.toBeChecked()
    await person.click(consent)
    await person.selectOptions(screen.getByTestId('lasts'), '15m')
    expect(consent).not.toBeChecked()
    await person.click(consent)
    await person.click(screen.getByRole('switch', { name: 'Let them watch the session live' }))
    expect(consent).not.toBeChecked()
    expect(screen.getByTestId('invite')).toBeDisabled()

    // Changing a choice back is another change: the earlier tick is not the person’s any more.
    await person.click(consent)
    await person.selectOptions(screen.getByTestId('history'), 'none')
    expect(consent).not.toBeChecked()
    await person.click(consent)
    await person.selectOptions(screen.getByTestId('history'), 'hour')
    await person.selectOptions(screen.getByTestId('history'), 'none')
    expect(consent).not.toBeChecked()
  })

  it('is not restored by changing the role or the device away and back', async () => {
    const { person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: PHONE }))
    await person.click(screen.getByRole('radio', { name: /Controller/ }))
    const consent = await screen.findByRole('checkbox', { name: /I understand this lets Sam/ })
    await person.click(consent)
    expect(consent).toBeChecked()
    await person.click(screen.getByRole('radio', { name: /Owner/ }))
    await person.click(screen.getByRole('radio', { name: /Controller/ }))
    expect(screen.getByRole('checkbox', { name: /I understand this lets/ })).not.toBeChecked()

    await person.click(screen.getByRole('checkbox', { name: /I understand this lets/ }))
    await person.click(screen.getByRole('radio', { name: /Guest tablet/ }))
    await person.click(screen.getByRole('radio', { name: PHONE }))
    expect(screen.getByRole('checkbox', { name: /I understand this lets/ })).not.toBeChecked()
  })
})

describe('a device name that turns text round', () => {
  it('is shown with the character made visible wherever the screen says it', async () => {
    const host = fakeHost()
    const named = {
      ...host,
      port: {
        ...host.port,
        deviceList: async (params: Parameters<typeof host.port.deviceList>[0]) => {
          const listed = await host.port.deviceList(params)
          return {
            ...listed,
            devices: listed.devices.map((each) =>
              each.display_name.startsWith('Sam') && each.platform === 'ios' && !each.all_sessions
                ? { ...each, display_name: 'Sam‮s iPhone' }
                : each
            )
          }
        }
      }
    }
    const { controls, person } = await openSharing(named, /Sam‹U\+202E›s iPhone/)
    const radio = await screen.findByRole('radio', { name: /Sam‹U\+202E›s iPhone/ })
    expect(radio.closest('label')?.textContent).not.toContain('‮')
    await person.click(radio)
    await person.click(screen.getByTestId('invite'))
    const row = await waitFor(() => {
      const found = screen.getByTestId('access').querySelector('[data-state="pending"]')
      expect(found).not.toBeNull()
      return found as HTMLElement
    })
    expect(row.textContent).toContain('Sam‹U+202E›s iPhone')
    expect(row.textContent).not.toContain('‮')
    expect(await screen.findByText(/Invitation ready for Sam‹U\+202E›s iPhone/)).toBeInTheDocument()
    expect(controls.sharing.grants()).toHaveLength(1)
  })
})

describe('what the page keeps of a result after the screen that sent it has gone', () => {
  /** Goes to another settings section and back, which draws the sharing tab anew. */
  async function leaveAndReturn(
    person: ReturnType<typeof userEvent.setup>,
    meanwhile: () => void | Promise<void>
  ): Promise<void> {
    await person.click(screen.getByRole('button', { name: 'Appearance' }))
    await meanwhile()
    await person.click(screen.getByRole('button', { name: 'Sharing' }))
    await screen.findByTestId('share-form')
  }

  it('tells a hand-over’s answer, and keeps its revocation to be checked again, when the person left the tab while it was sent', async () => {
    const { controls, person } = await withOwnerShare()
    await askForHandOver(person)
    const hold = controls.sharing.holdNextFinish()
    controls.sharing.holdBarrier(true)
    act(() => {
      controls.sharing.ownerAnswers()
    })
    await screen.findByTestId('hand-over-sending', {}, { timeout: 4000 })
    await leaveAndReturn(person, async () => {
      act(() => {
        hold.give()
      })
      const told = await screen.findByText(/is now with/)
      expect(told.textContent).toMatch(/1 session worker has not confirmed that Sam.* lost access yet/)
    })
    const line = await screen.findByTestId('recently-revoked')
    expect(line.textContent).toMatch(/1 session worker has not confirmed yet/)
    await person.click(within(line).getByTestId('check-again'))
    await waitFor(() => {
      expect(screen.getByTestId('recently-revoked').textContent).not.toMatch(/not confirmed yet/)
    })
  })

  it('tells the host’s own words when a send is refused after the person left the tab', async () => {
    const { controls, person } = await withOwnerShare()
    await askForHandOver(person)
    const hold = controls.sharing.holdNextFinish()
    act(() => {
      controls.sharing.ownerAnswers()
    })
    await screen.findByTestId('hand-over-sending', {}, { timeout: 4000 })
    await leaveAndReturn(person, async () => {
      act(() => {
        hold.refuse('PERMISSION_DENIED', 'the host would not hand the session over')
      })
      expect(await screen.findByText(/the host would not hand the session over/)).toBeInTheDocument()
    })
    // Nothing is left holding the session’s place.
    expect(controls.sharing.attempts()).toHaveLength(0)
  })

  it('keeps what a recovered invitation owes while the hand-over sheet is open, and shows it when the tab is drawn again', async () => {
    const { controls, person } = await withOwnerShare()
    // A live invitation to another device, whose answer is lost after the host wrote it.
    controls.sharing.setScreen(['before'])
    await person.click(screen.getByRole('radio', { name: /Guest tablet/ }))
    await person.click(screen.getByRole('switch', { name: 'Let them watch the session live' }))
    await screen.findByRole('region', { name: /^Screen at / })
    controls.sharing.setScreen(['after the program redrew'])
    controls.sharing.loseNextAnswer()
    // Another device and another choice of the form is another agreement.
    await person.click(await screen.findByRole('checkbox', { name: /I understand this lets Guest tablet/ }))
    await person.click(screen.getByTestId('invite'))
    await screen.findByTestId('attempt')

    // The sheet is open, so the list is not drawn, when the answer is recovered and told.
    await person.click(screen.getByTestId('hand-over-open'))
    await screen.findByTestId('hand-over')
    controls.sharing.recover()
    await reread()
    await waitFor(() => {
      expect(controls.sharing.attempts()).toHaveLength(0)
    })
    await leaveAndReturn(person, () => undefined)
    const card = await screen.findByTestId('screen-changed')
    expect(card).toHaveAttribute('data-kind', 'changed')
    expect(card.textContent).toContain('after the program redrew')
  })

  it('checks a recovered hand-over’s revocation by the grant that was given up, not by the first one the host lists', async () => {
    const { controls, person } = await withOwnerShare()
    await askForHandOver(person)
    controls.sharing.holdBarrier(true)
    controls.sharing.loseNextAnswer()
    act(() => {
      controls.sharing.ownerAnswers()
    })
    await screen.findByText(/was sent, but the host’s answer did not arrive/, {}, { timeout: 4000 })
    controls.sharing.recover()
    await reread()
    const line = await screen.findByTestId('recently-revoked')
    expect(line.textContent).toMatch(/1 session worker has not confirmed yet/)
    await person.click(within(line).getByTestId('check-again'))
    await waitFor(() => {
      expect(screen.getByTestId('recently-revoked').textContent).not.toMatch(/not confirmed yet/)
    })
  })

  it('takes a result in once, though the screen reads it again and again', async () => {
    const host = fakeHost()
    // The record is not removed, so every drawing of the tab finds the same result in it.
    const stuck = {
      ...host,
      port: { ...host.port, attemptRemove: () => new Promise<void>(() => undefined) }
    } as typeof host
    const { controls, person } = await openSharing(stuck)
    controls.sharing.setScreen(['before'])
    await person.click(screen.getByRole('radio', { name: PHONE }))
    await person.click(screen.getByRole('switch', { name: 'Let them watch the session live' }))
    await screen.findByRole('region', { name: /^Screen at / })
    controls.sharing.loseNextAnswer()
    await person.click(screen.getByTestId('invite'))
    await screen.findByTestId('attempt')
    controls.sharing.recover()
    await reread()
    await screen.findByText(/Invitation ready for Sam/)
    // It is the screen the person saw, so there is nothing to judge. Told a second time, with the
    // lines no longer kept, it would be a screen that could not be compared.
    await person.click(screen.getByRole('button', { name: 'Appearance' }))
    await person.click(screen.getByRole('button', { name: 'Sharing' }))
    await screen.findByTestId('share-form')
    await reread()
    await reread()
    expect(screen.queryByTestId('screen-changed')).toBeNull()
  })
})

describe('where focus goes when a control takes its own row away', () => {
  it('moves to the row beside it, or the heading, and never to the page behind the sheet', async () => {
    const host = fakeHost()
    const first = await withOwnerShare(host)
    await askForHandOver(first.person)
    host.controls.sharing.restart()
    first.unmount()

    const { person } = await openSharing(started(host))
    const row = await screen.findByTestId('attempt')
    await person.click(within(row).getByTestId('attempt-cancel'))
    await waitFor(() => {
      expect(screen.queryByTestId('attempt')).toBeNull()
    })
    expect(document.body).not.toHaveFocus()
    expect(screen.getByTestId('access').closest('.settings-content')?.contains(document.activeElement)).toBe(true)
  })

  it('moves off a screen note that was withdrawn or dismissed', async () => {
    const { controls, person } = await openSharing()
    controls.sharing.setScreen(['before'])
    await person.click(screen.getByRole('radio', { name: PHONE }))
    await person.click(screen.getByRole('switch', { name: 'Let them watch the session live' }))
    await screen.findByRole('region', { name: /^Screen at / })
    controls.sharing.setScreen(['after'])
    await person.click(screen.getByTestId('invite'))
    const card = await screen.findByTestId('screen-changed')
    await person.click(within(card).getByTestId('screen-dismiss'))
    await waitFor(() => {
      expect(screen.queryByTestId('screen-changed')).toBeNull()
    })
    expect(document.body).not.toHaveFocus()
  })

  it('takes the person to the row of the device that now holds the session after a hand-over', async () => {
    const { controls, person } = await withOwnerShare()
    await askForHandOver(person)
    act(() => {
      controls.sharing.ownerAnswers()
    })
    await waitFor(
      () => {
        expect(screen.queryByTestId('hand-over')).toBeNull()
      },
      { timeout: 4000 }
    )
    const replacement = controls.sharing.grants().find((each) => each.state === 'active')
    expect(replacement).toBeDefined()
    const row = await waitFor(() => {
      const found = document.querySelector<HTMLElement>(
        `[data-grant="${replacement?.grant.grant_id ?? ''}"]`
      )
      expect(found).not.toBeNull()
      return found as HTMLElement
    })
    await waitFor(() => {
      expect(row).toHaveFocus()
    })
  })
})

describe('a hand-over whose host cannot be reached for a moment', () => {
  it('goes on waiting for the owner device, and is not ended by one read that failed', async () => {
    const host = fakeHost()
    let failures = 1
    const flaky = {
      ...host,
      port: {
        ...host.port,
        transferAnswered: (reference: string) => {
          if (failures > 0) {
            failures -= 1
            return Promise.reject({
              code: 'RESOURCE_UNAVAILABLE',
              message: 'the host could not be read',
              user_action: 'none'
            })
          }
          return host.port.transferAnswered(reference)
        }
      }
    }
    const { controls, person } = await withOwnerShare(flaky)
    const sheet = await askForHandOver(person)
    // The first read fails; the sheet still waits, and a later one finds the owner device’s answer.
    await waitFor(
      () => {
        expect(failures).toBe(0)
      },
      { timeout: 4000 }
    )
    expect(within(sheet).getByTestId('hand-over-waiting')).toBeInTheDocument()
    expect(within(sheet).queryByTestId('hand-over-failure')).toBeNull()
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
})

describe('what an attempt says when the host has not', () => {
  it('says nothing of until when once that moment has passed, and that only the host can say', async () => {
    const { controls, person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: PHONE }))
    controls.sharing.loseNextRequest()
    await person.click(screen.getByTestId('invite'))
    const attempt = await screen.findByTestId('attempt')
    expect(attempt.textContent).toMatch(/It can still happen until/)
    controls.sharing.lapse()
    await reread()
    await waitFor(() => {
      expect(screen.getByTestId('attempt').textContent).toMatch(/It may have happened; ask the host/)
    })
    expect(screen.getByTestId('attempt').textContent).not.toMatch(/can still happen until/)
  })

  it('tells the person when asking the host got no answer', async () => {
    const { controls, person } = await openSharing()
    await person.click(screen.getByRole('radio', { name: PHONE }))
    controls.sharing.loseNextRequest()
    await person.click(screen.getByTestId('invite'))
    const attempt = await screen.findByTestId('attempt')
    await person.click(within(attempt).getByTestId('attempt-ask'))
    expect(await screen.findByText(/did not say what became of it/)).toBeInTheDocument()
  })

  it('counts the records this build does not read and leaves them as they are', async () => {
    const { controls } = await openSharing()
    controls.sharing.setUnreadable(2)
    await reread()
    const line = await screen.findByTestId('attempts-unreadable')
    expect(line.textContent).toMatch(/2 records kept by another release/)
    expect(line.textContent).toMatch(/left as\s+they are/)
  })
})

describe('what the host says about a device whose name turns text round', () => {
  it('is shown with the character made visible when an invitation is refused', async () => {
    const host = fakeHost()
    const refusing = {
      ...host,
      port: {
        ...host.port,
        grantCreate: () =>
          Promise.reject({
            code: 'PERMISSION_DENIED',
            message: 'An invitation of this session to Sam‮s iPhone is still under way',
            user_action: 'none'
          })
      }
    }
    const { person } = await openSharing(refusing)
    await person.click(screen.getByRole('radio', { name: PHONE }))
    await person.click(screen.getByTestId('invite'))
    const refused = await screen.findByText(/is still under way/)
    expect(refused.textContent).toContain('Sam‹U+202E›s iPhone')
    expect(refused.textContent).not.toContain('\u202e')
  })
})

describe('a hand-over the person cancelled', () => {
  it('sends nothing for an answer to a poll that arrives after Cancel began', async () => {
    const host = fakeHost()
    let polls = 0
    let finishes = 0
    let releasePoll: () => void = () => undefined
    let releaseCancel: () => void = () => undefined
    const gated = {
      ...host,
      port: {
        ...host.port,
        // The first poll is held on its way back, and the cancel is held on its way out.
        transferAnswered: (reference: string) => {
          polls += 1
          if (polls > 1) return host.port.transferAnswered(reference)
          return new Promise<Awaited<ReturnType<typeof host.port.transferAnswered>>>((resolve) => {
            releasePoll = () => {
              resolve(host.port.transferAnswered(reference))
            }
          })
        },
        transferCancel: (reference: string) =>
          new Promise<void>((resolve) => {
            releaseCancel = () => {
              resolve(host.port.transferCancel(reference))
            }
          }),
        transferFinish: (reference: string) => {
          finishes += 1
          return host.port.transferFinish(reference)
        }
      }
    }
    const { controls, person } = await withOwnerShare(gated)
    const sheet = await askForHandOver(person)
    await waitFor(
      () => {
        expect(polls).toBeGreaterThanOrEqual(1)
      },
      { timeout: 4000 }
    )
    await person.click(within(sheet).getByTestId('hand-over-cancel'))
    // The owner device answers, and the answer reaches the sheet after Cancel began.
    act(() => {
      controls.sharing.ownerAnswers()
      releasePoll()
    })
    await Promise.resolve()
    act(() => {
      releaseCancel()
    })
    await waitFor(() => {
      expect(screen.queryByTestId('hand-over')).toBeNull()
    })
    expect(finishes).toBe(0)
    expect(controls.sharing.attempts()).toHaveLength(0)
  })

  it('tells the host’s words when asking for the confirmation failed after the person left the tab', async () => {
    const host = fakeHost()
    let rejectAsk: () => void = () => undefined
    const slow = {
      ...host,
      port: {
        ...host.port,
        transferAsk: () =>
          new Promise<never>((_resolve, reject) => {
            rejectAsk = () => {
               
              reject({
                code: 'RESOURCE_UNAVAILABLE',
                message: 'the host did not answer, so it is not known whether an owner device was asked',
                user_action: 'none'
              })
            }
          })
      }
    } as typeof host
    const { person } = await withOwnerShare(slow)
    await person.click(screen.getByTestId('hand-over-open'))
    const sheet = await screen.findByTestId('hand-over')
    const receivers = within(sheet).getAllByRole<HTMLInputElement>('radio')
    await person.click(receivers.find((each) => !each.disabled) as HTMLInputElement)
    await person.click(within(sheet).getByTestId('hand-over-ask'))
    await person.click(screen.getByRole('button', { name: 'Appearance' }))
    act(() => {
      rejectAsk()
    })
    expect(await screen.findByText(/not known whether an owner device was asked/)).toBeInTheDocument()
  })
})

describe('Check again whose reply was lost', () => {
  it('changes how far the workers have got and nothing else when the answer is recovered', async () => {
    const { controls, person } = await withOwnerShare()
    await askForHandOver(person)
    controls.sharing.holdBarrier(true)
    act(() => {
      controls.sharing.ownerAnswers()
    })
    const line = await screen.findByTestId('recently-revoked', {}, { timeout: 4000 })
    expect(line.textContent).toMatch(/Revoked Sam.*1 session worker has not confirmed yet/)
    controls.sharing.loseNextAnswer()
    await person.click(within(line).getByTestId('check-again'))
    await screen.findByTestId('attempt')
    controls.sharing.recover()
    await reread()
    await waitFor(() => {
      expect(screen.getByTestId('recently-revoked').textContent).not.toMatch(/not confirmed yet/)
    })
    // It is still the line of the device that gave control up, not of "a paired device".
    expect(screen.getByTestId('recently-revoked').textContent).toMatch(/Revoked Sam/)
    expect(screen.getAllByTestId('recently-revoked')).toHaveLength(1)
  })
})

describe('where focus goes when an invitation is withdrawn from the row that is about it', () => {
  it('moves off a screen note to the heading, not to the invitation’s own row, which the withdrawal takes away', async () => {
    const { controls, person } = await openSharing()
    controls.sharing.setScreen(['before'])
    await person.click(screen.getByRole('radio', { name: PHONE }))
    await person.click(screen.getByRole('switch', { name: 'Let them watch the session live' }))
    await screen.findByRole('region', { name: /^Screen at / })
    controls.sharing.setScreen(['after'])
    await person.click(screen.getByTestId('invite'))
    const card = await screen.findByTestId('screen-changed')
    await person.click(within(card).getByTestId('screen-withdraw'))
    await waitFor(() => {
      expect(screen.queryByTestId('screen-changed')).toBeNull()
    })
    await waitFor(() => {
      expect(screen.getByTestId('access').querySelector('[data-state="pending"]')).toBeNull()
    })
    expect(screen.getByRole('heading', { level: 2, name: 'Sharing' })).toHaveFocus()
  })

  it('moves off a row that asks the host about a live invitation to the heading', async () => {
    const host = fakeHost()
    const first = await openSharing(host)
    first.controls.sharing.setScreen(['before'])
    await first.person.click(screen.getByRole('radio', { name: PHONE }))
    await first.person.click(screen.getByRole('switch', { name: 'Let them watch the session live' }))
    await screen.findByRole('region', { name: /^Screen at / })
    first.controls.sharing.loseNextAnswer()
    await first.person.click(screen.getByTestId('invite'))
    await screen.findByTestId('attempt')
    first.controls.sharing.recover()
    first.controls.sharing.restart()
    first.unmount()

    const { person } = await openSharing(started(host))
    const row = await screen.findByTestId('attempt')
    await person.click(within(row).getByTestId('attempt-withdraw'))
    await waitFor(() => {
      expect(screen.queryByTestId('attempt')).toBeNull()
    })
    await waitFor(() => {
      expect(screen.getByTestId('access').querySelector('[data-state="pending"]')).toBeNull()
    })
    expect(document.body).not.toHaveFocus()
    expect(screen.getByRole('heading', { level: 2, name: 'Sharing' })).toHaveFocus()
  })
})
