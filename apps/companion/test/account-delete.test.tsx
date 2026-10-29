/**
 * Deleting the account from the Account panel, as a person does it.
 *
 * The page asks the backend what deleting would do, asks for the emailed code, confirms with it and
 * learns how the removal goes. The backend is the shipped interface with a host that answers
 * without a machine (`fakeHost`), scripted with the answers the service gives. What these hold is
 * the page's half: every step and where it leads, what a refusal does to the field, that nothing
 * the person has not yet confirmed is lost by leaving, that the step survives the signed-out event
 * the backend publishes before it answers, and that the page hands the backend the code and the
 * organisations and nothing else.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { PLAIN_DELETION_PREVIEW, fakeHost } from '../src/host/fake'
import { MobileApp } from '../src/mobile/MobileApp'
import { minimumTarget } from '../src/mobile/platform'
import { DeleteAccount, type DeletionFlow, type DeletionStep } from '../src/components/DeleteAccount'
import { PURCHASE_WORDS, type AccountView } from '../src/model/account'
import {
  describeKept,
  describeProblem,
  describeRefusal,
  STILL_UNKNOWN_LINE,
  type DeletionConfirmAnswer,
  type DeletionPreview,
  type DeletionProblem
} from '../src/model/deletion'

const SIGNED_IN: AccountView = {
  state: 'signed_in',
  email: 'sam@example.com',
  name: null,
  usage_readable: false,
  generation: 'aaaa',
  outcome: null
}

const CODE = '12345678'

/** The phone's Account screen, signed in. */
async function phone() {
  const { port, controls } = fakeHost()
  controls.account.set(SIGNED_IN)
  render(
    <AppProvider port={port}>
      <MobileApp surface="ios" storage={null} />
    </AppProvider>
  )
  const person = userEvent.setup()
  await person.click(await screen.findByRole('button', { name: /^Account/ }))
  const panel = await screen.findByTestId('mobile-account')
  return { person, controls, panel }
}

/** Opens the step and reads it. */
async function reading(setup: Awaited<ReturnType<typeof phone>>) {
  const { person, panel } = setup
  await person.click(await within(panel).findByTestId('delete-account-open'))
  await within(panel).findByTestId('delete-account-before')
}

/** Reads, asks for the code and has the field in front of it. */
async function atTheField(setup: Awaited<ReturnType<typeof phone>>) {
  await reading(setup)
  await setup.person.click(within(setup.panel).getByTestId('delete-account-send-code'))
  return await within(setup.panel).findByTestId('delete-account-code')
}

const step = (panel: HTMLElement) => within(panel).getByTestId('delete-account').getAttribute('data-step')

afterEach(() => {
  vi.useRealTimers()
})

describe('reading what deleting does', () => {
  it('shows the money before the button that sends the code, whether or not a warning came', async () => {
    const setup = await phone()
    await reading(setup)
    const before = within(setup.panel).getByTestId('delete-account-before')
    const send = within(setup.panel).getByTestId('delete-account-send-code')
    // Document order: what is lost comes before the control that goes on.
    expect(before.compareDocumentPosition(send) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(within(before).getAllByRole('listitem')).toHaveLength(3)
    // Everything the service listed is shown, and the lists are real lists.
    expect(
      within(within(setup.panel).getByTestId('delete-account-deleted')).getAllByRole('listitem')
    ).toHaveLength(PLAIN_DELETION_PREVIEW.deleted.length)
    expect(
      within(within(setup.panel).getByTestId('delete-account-kept')).getAllByRole('listitem')
    ).toHaveLength(PLAIN_DELETION_PREVIEW.kept.length + 1)
  })

  it('adds a line for each warning, the organisation owner first', async () => {
    const setup = await phone()
    setup.controls.account.deletion.answerView({
      state: 'ready',
      preview: {
        ...PLAIN_DELETION_PREVIEW,
        warnings: [
          { kind: 'organisation_owner', organisation_id: 'org-1', name: 'Acme', members: 4 },
          { kind: 'subscription' },
          { kind: 'credit' },
          { kind: 'money_owed' }
        ]
      }
    })
    await reading(setup)
    const items = within(within(setup.panel).getByTestId('delete-account-before')).getAllByRole(
      'listitem'
    )
    expect(items).toHaveLength(7)
    expect(items[0]).toHaveTextContent('Acme')
    expect(items[0]).toHaveTextContent('4 members')
  })

  it('goes no further when it cannot show what a warning or a choice means', async () => {
    const setup = await phone()
    setup.controls.account.deletion.answerView({ state: 'cannot_show' })
    await setup.person.click(await within(setup.panel).findByTestId('delete-account-open'))
    await waitFor(() => {
      expect(step(setup.panel)).toBe('cannot_show')
    })
    expect(within(setup.panel).queryByTestId('delete-account-send-code')).toBeNull()
    await setup.person.click(within(setup.panel).getByTestId('delete-account-cancel'))
    expect(within(setup.panel).getByTestId('delete-account-open')).toHaveFocus()
  })

  it('says why it could not read, and tries again', async () => {
    const setup = await phone()
    const { deletion } = setup.controls.account
    deletion.answerView({ state: 'problem', problem: { kind: 'unreachable' } })
    await setup.person.click(await within(setup.panel).findByTestId('delete-account-open'))
    const problem = await within(setup.panel).findByTestId('delete-account-problem')
    expect(problem).toHaveAttribute('data-kind', 'unreachable')
    expect(problem).toHaveTextContent('Nothing changed')
    deletion.answerView({ state: 'ready', preview: PLAIN_DELETION_PREVIEW })
    await setup.person.click(within(setup.panel).getByTestId('delete-account-retry'))
    await within(setup.panel).findByTestId('delete-account-before')
    expect(deletion.views).toBe(2)
  })
})

describe('what stays', () => {
  it('says how long, in years, for everything the service keeps for the account', async () => {
    const setup = await phone()
    await reading(setup)
    const kept = within(setup.panel).getByTestId('delete-account-kept')
    const years = String(PLAIN_DELETION_PREVIEW.kept_records_years)
    const items = within(kept).getAllByRole('listitem')
    for (const kind of [
      'billing_records',
      'relay_records',
      'call_records',
      'reasoning_records',
      'backup_index_rows',
      'device_records'
    ] as const) {
      const words = describeKept(kind, PLAIN_DELETION_PREVIEW)
      expect(words).toContain(`${years} years`)
      expect(words).toContain('then deleted')
      expect(items.some((item) => item.textContent === describeKept(kind, PLAIN_DELETION_PREVIEW))).toBe(true)
    }
    // What belongs to an organisation stays with it, and the service's own copies have their own period.
    expect(describeKept('organisation_records', PLAIN_DELETION_PREVIEW)).not.toContain('years')
    expect(describeKept('recovery_copies', PLAIN_DELETION_PREVIEW)).not.toContain('years')
  })
})

describe('leaving before the code is sent', () => {
  it('puts the panel back as it was, and focus on the button that opened the step', async () => {
    const setup = await phone()
    await reading(setup)
    expect(within(setup.panel).getByRole('status')).toHaveFocus()
    await setup.person.click(within(setup.panel).getByTestId('delete-account-cancel'))
    expect(within(setup.panel).queryByTestId('delete-account')).toBeNull()
    expect(within(setup.panel).getByText(/sam@example\.com/)).toBeVisible()
    expect(within(setup.panel).getByTestId('delete-account-open')).toHaveFocus()
    expect(setup.controls.account.deletion.codesSent).toBe(0)
  })

  it('ends by itself when a different sign-in takes the place of the one it began under', async () => {
    const setup = await phone()
    await reading(setup)
    act(() => {
      setup.controls.account.set({ ...SIGNED_IN, generation: 'bbbb' })
    })
    await waitFor(() => {
      expect(within(setup.panel).queryByTestId('delete-account')).toBeNull()
    })
  })

  it('ends by itself when the sign-in ends while the field is open', async () => {
    const setup = await phone()
    await atTheField(setup)
    act(() => {
      setup.controls.account.set({ state: 'ended' })
    })
    await waitFor(() => {
      expect(within(setup.panel).queryByTestId('delete-account')).toBeNull()
    })
  })
})

describe('the code', () => {
  it('takes digits only, from a paste with a space in it, and goes on only with all eight', async () => {
    const setup = await phone()
    const field = await atTheField(setup)
    const { person, panel } = setup
    expect(field).toHaveFocus()
    expect(field).toHaveAttribute('autocomplete', 'one-time-code')
    expect(field).toHaveAttribute('inputmode', 'numeric')
    const confirm = within(panel).getByTestId('delete-account-confirm')
    expect(confirm).toBeDisabled()
    await person.click(field)
    await person.paste('1234 5678 99')
    expect(field).toHaveValue(CODE)
    expect(confirm).toBeEnabled()
    await person.clear(field)
    await person.type(field, '1234567')
    expect(confirm).toBeDisabled()
    await person.keyboard('{Enter}')
    expect(setup.controls.account.deletion.confirms).toEqual([])
  })

  it('hands the backend the code and the organisations accepted, and nothing else', async () => {
    const setup = await phone()
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    await setup.person.keyboard('{Enter}')
    await within(setup.panel).findByTestId('delete-account-done')
    expect(setup.controls.account.deletion.confirms).toEqual([{ code: CODE, acknowledged: [] }])
  })

  it('is told a refusal beside the field, which is emptied and focused', async () => {
    const setup = await phone()
    const { deletion } = setup.controls.account
    deletion.answerConfirm({ state: 'code_refused', reason: 'wrong', attempts_left: 4 })
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    await setup.person.click(within(setup.panel).getByTestId('delete-account-confirm'))
    const refusal = await within(setup.panel).findByTestId('delete-account-refusal')
    expect(refusal).toHaveAttribute('data-reason', 'wrong')
    expect(refusal).toHaveAttribute('data-left', '4')
    expect(refusal).toHaveTextContent('4 tries')
    const again = within(setup.panel).getByTestId('delete-account-code')
    expect(again).toHaveValue('')
    expect(again).toHaveFocus()
    expect(again).toHaveAttribute('aria-invalid', 'true')
    expect(within(setup.panel).getByTestId('delete-account').querySelector('[role="status"]')).toContainElement(
      refusal
    )
    expect(again).toHaveAccessibleDescription(/not right/)
  })

  it.each(['expired', 'spent'] as const)('says a code that is %s must be replaced', async (reason) => {
    const setup = await phone()
    const { deletion } = setup.controls.account
    deletion.answerConfirm({ state: 'code_refused', reason, attempts_left: 0 })
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    await setup.person.keyboard('{Enter}')
    const refusal = await within(setup.panel).findByTestId('delete-account-refusal')
    expect(refusal).toHaveAttribute('data-reason', reason)
    await setup.person.click(within(setup.panel).getByTestId('delete-account-resend'))
    await waitFor(() => {
      expect(deletion.codesSent).toBe(2)
    })
  })

  it.each([
    [{ kind: 'busy', seconds: 600 }, 'busy', '10 minutes'],
    [{ kind: 'mail_failed' }, 'mail_failed', 'could not be sent'],
    [{ kind: 'needs_sign_in' }, 'needs_sign_in', 'Sign in again']
  ] satisfies [DeletionProblem, string, string][])(
    'tells a failure to send it (%j)',
    async (problem, kind, fact) => {
      const setup = await phone()
      setup.controls.account.deletion.answerSendCode({ state: 'problem', problem })
      await reading(setup)
      await setup.person.click(within(setup.panel).getByTestId('delete-account-send-code'))
      const said = await within(setup.panel).findByTestId('delete-account-problem')
      expect(said).toHaveAttribute('data-kind', kind)
      expect(said).toHaveTextContent(fact)
      // The person is where they were, with the lists in front of them.
      expect(step(setup.panel)).toBe('read')
    }
  )

  it('waits at the field when the email may have been sent', async () => {
    const setup = await phone()
    setup.controls.account.deletion.answerSendCode({ state: 'problem', problem: { kind: 'unsure' } })
    await reading(setup)
    await setup.person.click(within(setup.panel).getByTestId('delete-account-send-code'))
    expect(await within(setup.panel).findByTestId('delete-account-code')).toBeVisible()
    expect(within(setup.panel).getByTestId('delete-account-problem')).toHaveAttribute(
      'data-kind',
      'unsure'
    )
    // It does not claim the email was sent beside the line that says that is not known.
    expect(within(setup.panel).getByTestId('delete-account-lead')).toHaveTextContent('may have been sent')
  })

  it('offers the dangerous control last but for Cancel', async () => {
    const setup = await phone()
    await atTheField(setup)
    const actions = within(setup.panel).getByTestId('delete-account').querySelector('.account-actions')
    const order = Array.from(actions?.querySelectorAll('button') ?? []).map((button) =>
      button.getAttribute('data-testid')
    )
    expect(order).toEqual(['delete-account-resend', 'delete-account-confirm', 'delete-account-cancel'])
  })

  it.each([
    [{ kind: 'unreachable' }, 'unreachable'],
    [{ kind: 'busy', seconds: 30 }, 'busy'],
    [{ kind: 'refused' }, 'refused']
  ] satisfies [DeletionProblem, string][])(
    'keeps what was typed when the confirmation could not be made (%j)',
    async (problem, kind) => {
      const setup = await phone()
      setup.controls.account.deletion.answerConfirm({ state: 'problem', problem })
      const field = await atTheField(setup)
      await setup.person.type(field, CODE)
      await setup.person.keyboard('{Enter}')
      const said = await within(setup.panel).findByTestId('delete-account-problem')
      expect(said).toHaveAttribute('data-kind', kind)
      expect(within(setup.panel).getByTestId('delete-account-code')).toHaveValue(CODE)
    }
  )

  it('names no button the code step lacks when another window holds the deletion', async () => {
    const setup = await phone()
    setup.controls.account.deletion.answerConfirm({
      state: 'problem',
      problem: { kind: 'in_progress' }
    })
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    await setup.person.keyboard('{Enter}')
    const said = await within(setup.panel).findByTestId('delete-account-problem')
    expect(said).toHaveAttribute('data-kind', 'in_progress')
    expect(step(setup.panel)).toBe('code')
    expect(within(setup.panel).queryByTestId('delete-account-check')).toBeNull()
    expect(said).not.toHaveTextContent(/check again/i)
  })
})

describe('an account that owns an organisation', () => {
  it('asks once more, names them, and sends the same code with their identifiers', async () => {
    const setup = await phone()
    const { deletion } = setup.controls.account
    const owned: DeletionConfirmAnswer = {
      state: 'acknowledge',
      organisations: [
        { organisation_id: 'org-1', name: 'Acme', members: 4 },
        { organisation_id: 'org-2', name: 'Initech', members: 1 }
      ]
    }
    // Asked for twice, since the person goes back once; the third try accepts them.
    deletion.answerConfirm(owned, owned, { state: 'closed', finished: true })
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    await setup.person.keyboard('{Enter}')
    const list = await within(setup.panel).findByTestId('delete-account-organisations')
    expect(within(list).getAllByRole('listitem')).toHaveLength(2)

    // Leaving from here puts the panel back as it was.
    expect(within(setup.panel).getByTestId('delete-account-cancel')).toBeVisible()

    // Back goes to the field with the code still there.
    await setup.person.click(within(setup.panel).getByTestId('delete-account-back'))
    expect(within(setup.panel).getByTestId('delete-account-code')).toHaveValue(CODE)
    await setup.person.keyboard('{Enter}')
    await setup.person.click(await within(setup.panel).findByTestId('delete-account-acknowledge'))
    await within(setup.panel).findByTestId('delete-account-done')
    expect(deletion.confirms.at(-1)).toEqual({ code: CODE, acknowledged: ['org-1', 'org-2'] })
  })
})

describe('the result', () => {
  it('survives the signed-out view the backend publishes before it answers', async () => {
    const setup = await phone()
    const { deletion } = setup.controls.account
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    deletion.holdConfirm()
    await setup.person.keyboard('{Enter}')
    await waitFor(() => {
      expect(step(setup.panel)).toBe('confirming')
    })
    expect(within(setup.panel).getByTestId('delete-account-confirm')).toBeDisabled()
    expect(within(setup.panel).queryByTestId('delete-account-cancel')).toBeNull()
    // The device is signed out while the confirmation is out, as the backend does it.
    act(() => {
      setup.controls.account.set({ state: 'signed_out', outcome: null })
    })
    expect(step(setup.panel)).toBe('confirming')
    await act(async () => {
      deletion.releaseConfirm()
      await Promise.resolve()
    })
    await within(setup.panel).findByTestId('delete-account-done')
    expect(within(setup.panel).getByTestId('delete-account-lead')).toHaveTextContent(/is closed/)
    expect(within(setup.panel).getByText(/not get an email/)).toBeVisible()
  })

  it('says the account is deleted at once when the removal had finished, and Done leaves the signed-out panel', async () => {
    const setup = await phone()
    setup.controls.account.deletion.answerConfirm({ state: 'closed', finished: true })
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    await setup.person.keyboard('{Enter}')
    expect(await within(setup.panel).findByText(/is deleted/)).toBeVisible()
    await setup.person.click(within(setup.panel).getByTestId('delete-account-done'))
    expect(within(setup.panel).queryByTestId('delete-account')).toBeNull()
    expect(within(setup.panel).getByRole('button', { name: 'Sign in' })).toBeVisible()
    expect(within(setup.panel).getByRole('status')).toHaveFocus()
    expect(within(setup.panel).queryByTestId('delete-account-open')).toBeNull()
  })

  it('settles a lost answer: check again finds the account closed', async () => {
    const setup = await phone()
    const { deletion } = setup.controls.account
    deletion.answerConfirm({ state: 'unsettled' })
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    await setup.person.keyboard('{Enter}')
    await within(setup.panel).findByTestId('delete-account-check')
    // Not yet known: the person is told so and stays where they are.
    deletion.answerStatus({ state: 'unsettled' })
    await setup.person.click(within(setup.panel).getByTestId('delete-account-check'))
    expect(await within(setup.panel).findByText(/still not known/)).toBeVisible()
    expect(step(setup.panel)).toBe('unsettled')
    deletion.answerStatus({ state: 'open' })
    await setup.person.click(within(setup.panel).getByTestId('delete-account-check'))
    await within(setup.panel).findByTestId('delete-account-done')
  })

  it('leaves the step, claiming nothing, when a check finds this device follows no deletion', async () => {
    const setup = await phone()
    const { deletion } = setup.controls.account
    deletion.answerConfirm({ state: 'unsettled' })
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    await setup.person.keyboard('{Enter}')
    await within(setup.panel).findByTestId('delete-account-check')
    deletion.answerStatus({ state: 'none' })
    await setup.person.click(within(setup.panel).getByTestId('delete-account-check'))
    await waitFor(() => {
      expect(within(setup.panel).queryByTestId('delete-account')).toBeNull()
    })
    expect(within(setup.panel).getByTestId('delete-account-open')).toBeVisible()
  })

  it('has a way out: Close stops the asking and puts the panel back', async () => {
    const setup = await phone()
    const { deletion } = setup.controls.account
    deletion.answerConfirm({ state: 'unsettled' })
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    await setup.person.keyboard('{Enter}')
    await setup.person.click(await within(setup.panel).findByTestId('delete-account-close'))
    await waitFor(() => {
      expect(within(setup.panel).queryByTestId('delete-account')).toBeNull()
    })
    expect(deletion.forgets).toBe(1)
    expect(within(setup.panel).getByText(/sam@example\.com/)).toBeVisible()
    expect(within(setup.panel).getByTestId('delete-account-open')).toHaveFocus()
  })

  it('stays at the step, with the reason, when another window holds the deletion', async () => {
    const setup = await phone()
    const { deletion } = setup.controls.account
    deletion.answerConfirm({ state: 'unsettled' })
    deletion.answerForget({ state: 'problem', problem: { kind: 'in_progress' } })
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    await setup.person.keyboard('{Enter}')
    await setup.person.click(await within(setup.panel).findByTestId('delete-account-close'))
    const said = await within(setup.panel).findByTestId('delete-account-problem')
    expect(said).toHaveAttribute('data-kind', 'in_progress')
    expect(step(setup.panel)).toBe('unsettled')
  })

  it('does not say nothing changed when a try after an unsettled answer cannot reach the service', async () => {
    const setup = await phone()
    const { deletion } = setup.controls.account
    deletion.answerConfirm(
      { state: 'unsettled' },
      { state: 'problem', problem: { kind: 'unreachable' } }
    )
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    await setup.person.keyboard('{Enter}')
    await setup.person.click(await within(setup.panel).findByTestId('delete-account-again'))
    const said = await within(setup.panel).findByTestId('delete-account-problem')
    expect(said).toHaveAttribute('data-kind', 'unreachable')
    expect(said).not.toHaveTextContent('Nothing changed')
    // It is still the step that says it is not known, with the way to settle it.
    expect(step(setup.panel)).toBe('unsettled')
    expect(within(setup.panel).getByTestId('delete-account-check')).toBeVisible()
  })

  it('does not offer to try again while it is looking, so a confirmation is not sent beside the look', async () => {
    const setup = await phone()
    const { deletion } = setup.controls.account
    deletion.answerConfirm({ state: 'unsettled' })
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    await setup.person.keyboard('{Enter}')
    await within(setup.panel).findByTestId('delete-account-check')
    deletion.answerStatus({ state: 'unsettled' })
    deletion.holdStatus()
    await setup.person.click(within(setup.panel).getByTestId('delete-account-check'))
    expect(within(setup.panel).getByTestId('delete-account-again')).toBeDisabled()
    expect(within(setup.panel).getByTestId('delete-account-check')).toBeDisabled()
    await act(async () => {
      deletion.releaseStatus()
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(within(setup.panel).getByTestId('delete-account-again')).toBeEnabled()
    })
  })

  it('tries the same code again from an unsettled answer', async () => {
    const setup = await phone()
    const { deletion } = setup.controls.account
    deletion.answerConfirm({ state: 'unsettled' }, { state: 'closed', finished: false })
    const field = await atTheField(setup)
    await setup.person.type(field, CODE)
    await setup.person.keyboard('{Enter}')
    await setup.person.click(await within(setup.panel).findByTestId('delete-account-again'))
    await within(setup.panel).findByTestId('delete-account-done')
    expect(deletion.confirms).toEqual([
      { code: CODE, acknowledged: [] },
      { code: CODE, acknowledged: [] }
    ])
  })
})

describe('how the removal goes', () => {
  /**
   * Mounts the panel with the clock under the test's hand and walks it, through the screen, to the
   * result of a confirmation that closed the account, with the removal finished or not.
   */
  async function atTheResult(finished: boolean) {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] })
    const { port, controls } = fakeHost()
    controls.account.set(SIGNED_IN)
    controls.account.deletion.answerConfirm({ state: 'closed', finished })
    controls.account.deletion.answerStatus({ state: 'open' })
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10)
    })
    const tab = screen.getByRole('button', { name: /^Account/ })
    await act(async () => {
      tab.click()
      await vi.advanceTimersByTimeAsync(10)
    })
    const panel = screen.getByTestId('mobile-account')
    const click = async (id: string) => {
      await act(async () => {
        within(panel).getByTestId(id).click()
        await vi.advanceTimersByTimeAsync(10)
      })
    }
    await click('delete-account-open')
    await click('delete-account-send-code')
    await act(async () => {
      fireEvent.change(within(panel).getByTestId('delete-account-code'), { target: { value: CODE } })
      await vi.advanceTimersByTimeAsync(10)
    })
    await click('delete-account-confirm')
    return { port, controls, panel }
  }

  it('shows the result of a closed account, and asks again every three seconds until it is done', async () => {
    const { controls, panel } = await atTheResult(false)
    expect(within(panel).getByTestId('delete-account')).toHaveAttribute('data-step', 'result')
    const reads = controls.account.deletion.statusReads
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    expect(controls.account.deletion.statusReads).toBe(reads + 1)
    expect(controls.account.deletion.statusFollowing.at(-1)).toBe(true)
    controls.account.deletion.answerStatus({ state: 'done' })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    expect(within(panel).getByText(/is deleted/)).toBeVisible()
    const after = controls.account.deletion.statusReads
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000)
    })
    expect(controls.account.deletion.statusReads).toBe(after)
  })

  it('shows a removal that had finished inside the confirmation, and asks no more', async () => {
    const { controls, panel } = await atTheResult(true)
    expect(within(panel).getByTestId('delete-account')).toHaveAttribute('data-step', 'result')
    expect(within(panel).getByText(/is deleted/)).toBeVisible()
    const reads = controls.account.deletion.statusReads
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000)
    })
    expect(controls.account.deletion.statusReads).toBe(reads)
  })

  it('stops asking after about two minutes when the asking itself fails, too', async () => {
    const { port, panel } = await atTheResult(false)
    const asked = vi.spyOn(port, 'accountDeletionStatus')
    asked.mockRejectedValue(new Error('the host did not answer'))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2 * 60 * 1000 + 3000)
    })
    const after = asked.mock.calls.length
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000)
    })
    expect(asked.mock.calls.length).toBe(after)
    expect(within(panel).getByTestId('delete-account')).toHaveAttribute('data-step', 'result')
  })

  it('stops asking after about two minutes, and says it is still finishing', async () => {
    const { controls, panel } = await atTheResult(false)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2 * 60 * 1000 + 3000)
    })
    expect(within(panel).getByText(/Still finishing/)).toBeVisible()
    const after = controls.account.deletion.statusReads
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000)
    })
    expect(controls.account.deletion.statusReads).toBe(after)
  })

  it('does not take a record that is gone for a removal that finished: it goes on asking', async () => {
    const { controls, panel } = await atTheResult(false)
    controls.account.deletion.answerStatus({ state: 'none' })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(9000)
    })
    expect(within(panel).getByTestId('delete-account')).toHaveAttribute('data-step', 'result')
    expect(within(panel).queryByText(/is deleted/)).toBeNull()
  })

  it('waits as long as the service asks when it says too many tries, without a message', async () => {
    const { controls, panel } = await atTheResult(false)
    controls.account.deletion.answerStatus({ state: 'problem', problem: { kind: 'busy', seconds: 20 } })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    const reads = controls.account.deletion.statusReads
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000)
    })
    expect(controls.account.deletion.statusReads).toBe(reads)
    expect(within(panel).queryByTestId('delete-account-problem')).toBeNull()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(6000)
    })
    expect(controls.account.deletion.statusReads).toBeGreaterThan(reads)
  })
})

describe('a confirmation that is still out when the panel opens', () => {
  /** Mounts the panel while the backend says a confirmation has no answer yet. */
  async function mounted() {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] })
    const { port, controls } = fakeHost()
    controls.account.set(SIGNED_IN)
    controls.account.deletion.answerStatus({ state: 'unsettled' })
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10)
    })
    const tab = screen.getByRole('button', { name: /^Account/ })
    await act(async () => {
      tab.click()
      await vi.advanceTimersByTimeAsync(10)
    })
    return { controls, panel: screen.getByTestId('mobile-account') }
  }

  it('shows that it is not known, offers no retry it has no code for, and shows the result when it comes', async () => {
    const { controls, panel } = await mounted()
    expect(within(panel).getByTestId('delete-account')).toHaveAttribute('data-step', 'unsettled')
    expect(within(panel).getByTestId('delete-account-check')).toBeVisible()
    expect(within(panel).queryByTestId('delete-account-again')).toBeNull()
    controls.account.deletion.answerStatus({ state: 'open' })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    expect(within(panel).getByTestId('delete-account')).toHaveAttribute('data-step', 'result')
    // The look when the panel opened only asked; the looks that follow the deletion said so.
    expect(controls.account.deletion.statusFollowing[0]).toBe(false)
    expect(controls.account.deletion.statusFollowing.at(-1)).toBe(true)
  })

  it('sends Close after a look that is out, and never beside it', async () => {
    const { controls, panel } = await mounted()
    const { deletion } = controls.account
    deletion.holdStatus()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    await act(async () => {
      within(panel).getByTestId('delete-account-close').click()
      await vi.advanceTimersByTimeAsync(10)
    })
    expect(deletion.forgets).toBe(0)
    // A second press while Close is out would be turned away; it is not offered.
    expect(within(panel).getByTestId('delete-account-close')).toBeDisabled()
    await act(async () => {
      deletion.releaseStatus()
      await vi.advanceTimersByTimeAsync(10)
    })
    expect(deletion.forgets).toBe(1)
    expect(within(panel).queryByTestId('delete-account')).toBeNull()
  })

  it('does not end on its own because the device follows no deletion: that is left to the person', async () => {
    const { controls, panel } = await mounted()
    controls.account.deletion.answerStatus({ state: 'none' })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    expect(within(panel).getByTestId('delete-account')).toHaveAttribute('data-step', 'unsettled')
  })

  it('asks one thing at a time: a look the person asked for and the automatic one are answered in order', async () => {
    const { controls, panel } = await mounted()
    const { deletion } = controls.account
    // Check again goes out and waits; the automatic look is due meanwhile, and is not sent beside it.
    deletion.holdStatus()
    await act(async () => {
      within(panel).getByTestId('delete-account-check').click()
      await vi.advanceTimersByTimeAsync(10)
    })
    const out = deletion.statusReads
    deletion.answerStatus({ state: 'open' })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    expect(deletion.statusReads).toBe(out)
    expect(within(panel).getByTestId('delete-account')).toHaveAttribute('data-step', 'unsettled')
    await act(async () => {
      deletion.releaseStatus()
      await vi.advanceTimersByTimeAsync(10)
    })
    expect(within(panel).getByTestId('delete-account')).toHaveAttribute('data-step', 'result')
  })

  it('keeps the step for a person whose sign-in ended meanwhile, and says nothing of the outcome', async () => {
    const { controls, panel } = await mounted()
    act(() => {
      controls.account.set({ state: 'ended' })
    })
    controls.account.deletion.answerStatus({ state: 'none' })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })
    expect(within(panel).getByTestId('delete-account')).toHaveAttribute('data-step', 'unsettled')
  })

  it('stops looking by itself after about two minutes', async () => {
    const { controls, panel } = await mounted()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2 * 60 * 1000 + 3000)
    })
    const after = controls.account.deletion.statusReads
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000)
    })
    expect(controls.account.deletion.statusReads).toBe(after)
    expect(within(panel).getByTestId('delete-account')).toHaveAttribute('data-step', 'unsettled')
  })
})

describe('a look made when the panel opened', () => {
  it('does not bring a step back that the person has left since it was asked', async () => {
    const { port, controls } = fakeHost()
    controls.account.set(SIGNED_IN)
    controls.account.deletion.answerStatus({ state: 'unsettled' })
    controls.account.deletion.holdStatus()
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    const person = userEvent.setup()
    await person.click(await screen.findByRole('button', { name: /^Account/ }))
    const panel = await screen.findByTestId('mobile-account')
    // The person opens the step and leaves it again while the look is still out.
    await person.click(await within(panel).findByTestId('delete-account-open'))
    await person.click(await within(panel).findByTestId('delete-account-cancel'))
    expect(within(panel).queryByTestId('delete-account')).toBeNull()
    await act(async () => {
      controls.account.deletion.releaseStatus()
      await Promise.resolve()
    })
    expect(within(panel).queryByTestId('delete-account')).toBeNull()
  })

  it.each([
    ['open', /Your account is closed/],
    ['done', /is deleted/]
  ] as const)('shows the person the closure their own look found: %s', async (state, words) => {
    const { port, controls } = fakeHost()
    controls.account.set(SIGNED_IN)
    controls.account.deletion.answerStatus({ state })
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    const person = userEvent.setup()
    await person.click(await screen.findByRole('button', { name: /^Account/ }))
    const panel = await screen.findByTestId('mobile-account')
    const step = await within(panel).findByTestId('delete-account')
    await waitFor(() => {
      expect(step).toHaveAttribute('data-step', 'result')
    })
    expect(within(panel).getByText(words)).toBeVisible()
    // The look only opened the panel; the looks that follow the result say so.
    expect(controls.account.deletion.statusFollowing[0]).toBe(false)
  })
})

describe('the desktop sheet', () => {
  async function sheetAt(person: ReturnType<typeof userEvent.setup>) {
    await person.click(screen.getByRole('button', { name: /^Account/ }))
    return await screen.findByRole('dialog', { name: 'Account' })
  }

  it('shows that the confirmation has no answer yet when the sheet is opened during it, and the result after', async () => {
    const { port, controls } = fakeHost()
    controls.account.set(SIGNED_IN)
    render(
      <AppProvider port={port} initialPlace={{ view: 'attention' }}>
        <App />
      </AppProvider>
    )
    const person = userEvent.setup()
    let sheet = await sheetAt(person)
    await person.click(await within(sheet).findByTestId('delete-account-open'))
    await person.click(await within(sheet).findByTestId('delete-account-send-code'))
    const field = await within(sheet).findByTestId('delete-account-code')
    await person.type(field, CODE)
    controls.account.deletion.holdConfirm()
    await person.keyboard('{Enter}')
    await waitFor(() => {
      expect(controls.account.deletion.confirms).toHaveLength(1)
    })
    await person.keyboard('{Escape}')
    await waitFor(() => {
      expect(screen.queryByRole('dialog', { name: 'Account' })).toBeNull()
    })

    // The sheet is opened while the confirmation is out: the backend says it has no answer yet.
    controls.account.deletion.answerStatus({ state: 'unsettled' })
    sheet = await sheetAt(person)
    await waitFor(() => {
      expect(within(sheet).getByTestId('delete-account')).toHaveAttribute('data-step', 'unsettled')
    })

    // The answer comes, and a look finds the account closed.
    controls.account.deletion.answerStatus({ state: 'open' })
    await act(async () => {
      controls.account.deletion.releaseConfirm()
      await Promise.resolve()
    })
    await person.click(within(sheet).getByTestId('delete-account-check'))
    await waitFor(() => {
      expect(within(sheet).getByTestId('delete-account')).toHaveAttribute('data-step', 'result')
    })
  })

  it('shows recovery as the device left it once the account is closed, though the signed-out view came first', async () => {
    const { port, controls } = fakeHost()
    controls.account.set(SIGNED_IN)
    // Until the result is on the screen, recovery still reads as on: the device clears it after the
    // signed-out view is published and before the confirmation is answered.
    const read = port.recoveryView.bind(port)
    let cleared = false
    vi.spyOn(port, 'recoveryView').mockImplementation(async () => {
      const view = await read()
      cleared ||= screen.queryByTestId('delete-account-done') !== null
      return cleared ? view : { ...view, state: 'on', kept_at: 'sync.example' }
    })
    render(
      <AppProvider port={port} initialPlace={{ view: 'attention' }}>
        <App />
      </AppProvider>
    )
    const person = userEvent.setup()
    const sheet = await sheetAt(person)
    await waitFor(() => {
      expect(within(sheet).getByTestId('recovery')).toHaveAttribute('data-state', 'on')
    })
    await person.click(await within(sheet).findByTestId('delete-account-open'))
    await person.click(await within(sheet).findByTestId('delete-account-send-code'))
    await person.type(await within(sheet).findByTestId('delete-account-code'), CODE)
    await person.keyboard('{Enter}')
    await within(sheet).findByTestId('delete-account-done')
    await waitFor(() => {
      expect(within(sheet).getByTestId('recovery')).toHaveAttribute('data-state', 'off')
    })
    await person.click(within(sheet).getByTestId('delete-account-done'))
    expect(within(sheet).getByTestId('recovery')).toHaveAttribute('data-state', 'off')
  })

  it('keeps Tab inside the step while the cards are hidden', async () => {
    const { port, controls } = fakeHost()
    controls.account.set(SIGNED_IN)
    render(
      <AppProvider port={port} initialPlace={{ view: 'attention' }}>
        <App />
      </AppProvider>
    )
    const person = userEvent.setup()
    const sheet = await sheetAt(person)
    await person.click(await within(sheet).findByTestId('delete-account-open'))
    await within(sheet).findByTestId('delete-account-before')
    const inside = (element: Element | null) => element !== null && sheet.contains(element)
    for (let presses = 0; presses < 12; presses += 1) {
      await person.tab()
      expect(inside(document.activeElement), `Tab ${String(presses)}`).toBe(true)
      expect(
        document.activeElement?.closest('[hidden]'),
        `Tab ${String(presses)} is on a hidden control`
      ).toBeNull()
    }
    await person.tab({ shift: true })
    expect(inside(document.activeElement)).toBe(true)
  })
})

describe('every control meets the minimum target of its surface', () => {
  it('sets it on the buttons and the field of each step', async () => {
    const setup = await phone()
    const target = minimumTarget('ios')
    const sized = (element: HTMLElement) => Number.parseInt(element.style.minBlockSize || '0', 10)
    await reading(setup)
    for (const id of ['delete-account-send-code', 'delete-account-cancel']) {
      expect(sized(within(setup.panel).getByTestId(id)), id).toBeGreaterThanOrEqual(target)
    }
    await setup.person.click(within(setup.panel).getByTestId('delete-account-send-code'))
    for (const id of [
      'delete-account-code',
      'delete-account-confirm',
      'delete-account-resend',
      'delete-account-cancel'
    ]) {
      expect(sized(await within(setup.panel).findByTestId(id)), id).toBeGreaterThanOrEqual(target)
    }
  })
})

describe('the step names nothing to buy and links nowhere (the store-build rule)', () => {
  const EVERYTHING: DeletionPreview = {
    ...PLAIN_DELETION_PREVIEW,
    warnings: [
      { kind: 'organisation_owner', organisation_id: 'org-1', name: 'Acme', members: 4 },
      { kind: 'subscription' },
      { kind: 'credit' },
      { kind: 'money_owed' }
    ],
    unlisted: true
  }
  const PROBLEMS: DeletionProblem[] = [
    { kind: 'needs_sign_in' },
    { kind: 'refused' },
    { kind: 'busy', seconds: 20 },
    { kind: 'busy', seconds: 600 },
    { kind: 'mail_failed' },
    { kind: 'unsure' },
    { kind: 'unreachable' },
    { kind: 'account_changed' },
    { kind: 'in_progress' }
  ]
  const noop = () => undefined
  const flowAt = (at: DeletionStep, over: Partial<DeletionFlow> = {}): DeletionFlow => ({
    step: at,
    open: true,
    preview: EVERYTHING,
    code: '',
    codeSure: true,
    checking: false,
    refusal: null,
    said: null,
    begin: noop,
    cancel: noop,
    setCode: noop,
    sendCode: noop,
    confirm: noop,
    acknowledgeAll: noop,
    back: noop,
    checkAgain: noop,
    giveUp: noop,
    finish: noop,
    ...over
  })

  it('holds in every step and in every line a step can say', () => {
    const steps: DeletionStep[] = [
      { name: 'reading' },
      { name: 'failed' },
      { name: 'cannot_show' },
      { name: 'read' },
      { name: 'sending' },
      { name: 'code' },
      { name: 'confirming' },
      {
        name: 'acknowledge',
        organisations: [{ organisation_id: 'org-1', name: 'Acme', members: 4 }]
      },
      { name: 'unsettled' },
      { name: 'result', progress: 'open' },
      { name: 'result', progress: 'still' },
      { name: 'result', progress: 'done' }
    ]
    const flows: DeletionFlow[] = steps.map((at) => flowAt(at))
    for (const problem of PROBLEMS) {
      for (const stage of ['before', 'unknown', 'after'] as const) {
        flows.push(flowAt({ name: 'code' }, { said: { problem, stage } }))
      }
    }
    flows.push(flowAt({ name: 'code' }, { codeSure: false }))
    flows.push(flowAt({ name: 'unsettled' }, { code: CODE, said: { text: STILL_UNKNOWN_LINE } }))
    for (const reason of ['wrong', 'expired', 'spent'] as const) {
      flows.push(flowAt({ name: 'code' }, { refusal: { reason, attemptsLeft: reason === 'wrong' ? 2 : 0 } }))
    }
    flows.push(flowAt({ name: 'code' }, { said: { text: 'KalaReach could not use this device.' } }))
    for (const flow of flows) {
      const { container, unmount } = render(<DeleteAccount flow={flow} surface="ios" />)
      const text = (container.textContent ?? '').toLowerCase()
      for (const word of PURCHASE_WORDS) {
        expect(text, `${flow.step.name}: ${word}`).not.toContain(word)
      }
      expect(container.querySelector('a[href]')).toBeNull()
      expect(container.querySelector('form')).toBeNull()
      unmount()
    }
    for (const problem of PROBLEMS) {
      for (const stage of ['before', 'unknown', 'after'] as const) {
        const text = describeProblem(problem, stage).toLowerCase()
        for (const word of PURCHASE_WORDS) expect(text, `${problem.kind}: ${word}`).not.toContain(word)
      }
    }
    for (const reason of ['wrong', 'expired', 'spent'] as const) {
      const text = describeRefusal(reason, 0).toLowerCase()
      for (const word of PURCHASE_WORDS) expect(text, `${reason}: ${word}`).not.toContain(word)
    }
  })
})
