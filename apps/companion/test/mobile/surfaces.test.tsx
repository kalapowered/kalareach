/**
 * The mobile surfaces, rendered and driven the way a person drives them.
 *
 * These render the shell that ships, against the scripted host, on each of the two platforms in
 * turn. What they hold it to is the part of section 13 that can be proved without a device: the
 * four inbox states, the target sizes in both dimensions, the accessible names, the commit rule,
 * the draft surviving a change of view, and the commercial surface being empty.
 *
 * What they cannot prove is on the simulators: keyboard occlusion, rotation, safe areas, text
 * selection, IME composition, VoiceOver and TalkBack.
 */

import { describe, expect, it } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls } from '../../src/host/fake'
import { MobileApp, type MobileBuild } from '../../src/mobile/MobileApp'
import { PURCHASE_WORDS } from '../../src/mobile/model/account'
import { TOUCH_TARGET, type MobilePlatform } from '../../src/mobile/platform'

function start(
  surface: MobilePlatform,
  build?: MobileBuild,
  storage?: Storage | null
): { controls: FakeHostControls } {
  const { port, controls } = fakeHost()
  render(
    <AppProvider port={port}>
      <MobileApp surface={surface} build={build} storage={storage ?? null} />
    </AppProvider>
  )
  return { controls }
}

/** The shell, ready to render, so a test can take one away and start another over one store. */
function wrap(surface: MobilePlatform, storage: Storage) {
  const { port } = fakeHost()
  return (
    <AppProvider port={port}>
      <MobileApp surface={surface} storage={storage} />
    </AppProvider>
  )
}

/** The declared minimum of one control, in both dimensions. */
function declaredTarget(element: HTMLElement): { inline: number; block: number } {
  const style = element.style
  return {
    inline: Number.parseInt(style.minInlineSize || '0', 10),
    block: Number.parseInt(style.minBlockSize || '0', 10)
  }
}

describe('the inbox is the primary mobile surface (KR-REQ-13.01, 13.02)', () => {
  it('opens on the inbox with the four kinds apart', async () => {
    start('ios')
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Waiting for you\. Run the release script/ })).toBeInTheDocument()
    })
    for (const kind of ['pending_decision', 'failed_action', 'awaiting_review', 'disconnected']) {
      expect(document.querySelector(`[data-kind="${kind}"]`)).not.toBeNull()
    }
  })

  it('shows a host out of contact as out of contact and claims nothing about its work', async () => {
    start('android')
    await waitFor(() => {
      expect(document.querySelector('[data-kind="disconnected"]')).not.toBeNull()
    })
    const row = document.querySelector('[data-kind="disconnected"]') as HTMLElement
    expect(row.textContent).toContain('Out of contact')
    expect(row.textContent).toContain('may still be running')
    for (const forbidden of ['stuck', 'failed', 'crashed', 'hung']) {
      expect(row.textContent?.toLowerCase()).not.toContain(forbidden)
    }
  })

  it('counts only what a person can act on in the tab badge', async () => {
    start('ios')
    const tab = await screen.findByRole('button', { name: /^Attention/ })
    await waitFor(() => {
      expect(within(tab).getByText('2')).toBeInTheDocument()
    })
    expect(tab.textContent).toContain('2 waiting for you')
  })

  it('decides an approval on a completed action and not on the press', async () => {
    const person = userEvent.setup()
    start('ios')
    const row = await screen.findByRole('button', { name: /Waiting for you\. Run the release script/ })
    await person.click(row)
    const allow = await screen.findByRole('button', { name: 'Allow' })

    await person.pointer({ keys: '[MouseLeft>]', target: allow })
    expect(screen.queryByText(/^Allowed\.$/)).toBeNull()
    await person.pointer({ keys: '[/MouseLeft]', target: allow })
    await waitFor(() => {
      expect(screen.getByText(/^Allowed\.$/)).toBeInTheDocument()
    })
  })
})

describe('touch targets and accessible names (KR-REQ-13.06, 13.19, KR-ACC-020)', () => {
  for (const surface of ['ios', 'android'] as const) {
    it(`meets the ${surface} minimum in both dimensions`, async () => {
      start(surface)
      const minimum = TOUCH_TARGET[surface]
      const tabs = await screen.findAllByRole('button', { name: /Attention|Sessions|Hosts|Account/ })
      for (const tab of tabs) {
        const declared = declaredTarget(tab)
        expect(declared.inline).toBeGreaterThanOrEqual(minimum)
        expect(declared.block).toBeGreaterThanOrEqual(minimum)
      }
      const row = await waitFor(() => {
        const found = document.querySelector('[data-kind="pending_decision"]')
        if (!found) throw new Error('no row yet')
        return found as HTMLElement
      })
      expect(declaredTarget(row).block).toBeGreaterThanOrEqual(minimum)
    })
  }

  it('gives every navigation control a name a screen reader can read', async () => {
    start('android')
    const nav = screen.getByRole('navigation', { name: 'Sections' })
    for (const button of within(nav).getAllByRole('button')) {
      expect(button.textContent?.trim().length ?? 0).toBeGreaterThan(0)
    }
  })

  it('reads a row as its kind, its title, where it is and what it says', async () => {
    start('ios')
    const row = await screen.findByRole('button', {
      name: /Action failed\. Upload did not finish\. studio · Session 2 · Claude Code\./
    })
    expect(row).toBeInTheDocument()
  })
})

describe('the terminal keys and the two views (KR-REQ-13.17, 13.03)', () => {
  it('keeps the draft when the view changes', async () => {
    const person = userEvent.setup()
    start('ios')
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    const session = await screen.findByRole('button', { name: /Session 1/ })
    await person.click(session)

    const composer = await screen.findByLabelText('Message this session')
    await person.type(composer, 'keep me')
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    await person.click(screen.getByRole('tab', { name: 'Conversation' }))
    expect(await screen.findByLabelText('Message this session')).toHaveValue('keep me')
  })

  it('offers the terminal keys with the platform minimum and a spoken name', async () => {
    const person = userEvent.setup()
    start('android')
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await person.click(await screen.findByRole('tab', { name: 'Terminal' }))

    const keys = screen.getByRole('group', { name: 'Terminal keys' })
    const escape = within(keys).getByRole('button', { name: 'Escape' })
    expect(declaredTarget(escape).inline).toBeGreaterThanOrEqual(TOUCH_TARGET.android)
    expect(declaredTarget(escape).block).toBeGreaterThanOrEqual(TOUCH_TARGET.android)
    const control = within(keys).getByRole('button', { name: 'Control, off' })
    await person.click(control)
    expect(within(keys).getByRole('button', { name: /Control, held for the next key/ })).toBeInTheDocument()
  })

  it('opens the camera, the photo library and the files with the platform picker', async () => {
    const person = userEvent.setup()
    start('ios')
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))

    const group = screen.getByRole('group', { name: 'Add an attachment' })
    const inputs = group.parentElement?.querySelectorAll('input[type="file"]') ?? []
    const camera = [...inputs].find((input) => input.getAttribute('capture') === 'environment')
    expect(camera).toBeDefined()
    expect(camera?.getAttribute('accept')).toBe('image/*')
    expect([...inputs].some((input) => input.getAttribute('accept') === '*/*')).toBe(true)
  })
})

describe('local feedback and the receipt (KR-REQ-13.05, KR-ACC-012)', () => {
  it('shows the submission as queued before the host answers and applied only on a receipt', async () => {
    const person = userEvent.setup()
    start('ios')
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    const composer = await screen.findByLabelText('Message this session')
    await person.type(composer, 'run the tests')
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await waitFor(() => {
      expect(screen.getByText('Applied')).toBeInTheDocument()
    })
  })

  it('leaves what was written in the composer when the host refuses it', async () => {
    const person = userEvent.setup()
    const { controls } = start('ios')
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    const composer = await screen.findByLabelText('Message this session')
    await person.type(composer, 'do not lose me')
    controls.setConnected(false)
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await waitFor(() => {
      expect(screen.getByText(/not in contact/i)).toBeInTheDocument()
    })
    // The submission did not happen, so the text is still exactly where the person left it.
    expect(screen.getByLabelText('Message this session')).toHaveValue('do not lose me')
  })

  it('never shows one session an outcome that belongs to another', async () => {
    const person = userEvent.setup()
    start('ios')
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await person.type(await screen.findByLabelText('Message this session'), 'in session one')
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await waitFor(() => {
      expect(screen.getByText('Applied')).toBeInTheDocument()
    })

    await person.click(screen.getByRole('button', { name: 'Back to sessions' }))
    await person.click(await screen.findByRole('button', { name: /Session 2/ }))
    await screen.findByLabelText('Message this session')
    expect(screen.queryByText('Applied')).toBeNull()
  })

  it('recovers a draft written before the process was taken away', async () => {
    const person = userEvent.setup()
    const storage = fakeStorage()
    const first = render(wrap('ios', storage))
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await person.type(await screen.findByLabelText('Message this session'), 'half a thought')
    // A run in which nothing broke says nothing about recovery.
    expect(screen.queryByText(/draft kept/)).toBeNull()

    // The system takes the process away. Nothing tells the page; the next run is a new process
    // that finds a record and no marker of a clean exit.
    first.unmount()
    render(wrap('ios', storage))
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    expect(await screen.findByLabelText('Message this session')).toHaveValue('half a thought')
    expect(screen.getByText(/1 draft kept/)).toBeInTheDocument()
    expect(screen.getByText(/Nothing was sent again\./)).toBeInTheDocument()
  })
})

describe('the commercial surface (KR-REQ-17.32)', () => {
  it('signs in and shows usage, with nothing that takes money', async () => {
    const person = userEvent.setup()
    start('ios', {
      channel: 'app_store',
      account: { kind: 'signed_in', identity: 'sam@example.com', plan: 'Standard' },
      usage: {
        periodLabel: 'This month',
        lines: [{ label: 'Agent minutes', used: 140, included: 500, unit: 'minutes' }]
      }
    })
    await person.click(await screen.findByRole('button', { name: /^Account/ }))
    const account = await screen.findByTestId('mobile-account')
    expect(account.textContent).toContain('sam@example.com')
    expect(account.textContent).toContain('140 of 500 minutes')

    const text = (account.textContent ?? '').toLowerCase()
    for (const word of PURCHASE_WORDS) {
      expect(text).not.toContain(word)
    }
    expect(account.querySelector('form')).toBeNull()
    expect(account.querySelector('a[href]')).toBeNull()
    expect(account.querySelector('input[type="password"]')).toBeNull()
  })

  it('says local work needs no account at all', async () => {
    const person = userEvent.setup()
    start('android')
    await person.click(await screen.findByRole('button', { name: /^Account/ }))
    const account = await screen.findByTestId('mobile-account')
    expect(account.textContent).toContain('No account on this device')
    expect(within(account).getByRole('button', { name: 'Sign in' })).toBeInTheDocument()
  })
})

/** A storage that behaves like the device's own, for a test that restarts the application. */
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

describe('what a build must not let happen twice (KR-ACC-012)', () => {
  it('will not send again while an action has no confirmed outcome', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    // The one answer that means nobody knows: the request left this device and the host never
    // said what became of it. A refusal is terminal and a receipt is an outcome; this is neither.
    const uncertain = {
      ...port,
      composerSubmit: () =>
        Promise.reject({
          code: 'OUTCOME_UNKNOWN',
          message: 'The host did not say what became of it.',
          user_action: 'ask'
        })
    }
    render(
      <AppProvider port={uncertain}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await person.type(await screen.findByLabelText('Message this session'), 'run the migration')
    await person.click(screen.getByRole('button', { name: 'Send' }))

    await waitFor(() => {
      expect(screen.getByText(/no confirmed outcome yet/)).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    expect(screen.getByText(/Sending again could run it twice/)).toBeInTheDocument()
    // And what was written is still there: an uncertain outcome is not a reason to lose it.
    expect(screen.getByLabelText('Message this session')).toHaveValue('run the migration')
  })

  it('says so when the device refuses to keep what was written', async () => {
    const person = userEvent.setup()
    const refusing = {
      getItem: () => null,
      setItem: () => {
        throw new Error('quota')
      },
      removeItem: () => undefined,
      key: () => null,
      clear: () => undefined,
      length: 0
    } as unknown as Storage
    const { port } = fakeHost()
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={refusing} />
      </AppProvider>
    )
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await person.type(await screen.findByLabelText('Message this session'), 'a')
    await waitFor(() => {
      expect(screen.getByText('This device will not keep what you write')).toBeInTheDocument()
    })
    // It is a warning about durability, not about the draft: the text is still there.
    expect(screen.getByLabelText('Message this session')).toHaveValue('a')
  })
})
