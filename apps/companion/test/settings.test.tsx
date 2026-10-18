/**
 * The person's settings in the page: the colour mode, which native code keeps, and settings sync's
 * card in the account sheet.
 *
 * The page holds no copy of the mode of its own. A choice is applied at once and asked for from the
 * backend; one the backend could not keep is taken back and said; a change another device made,
 * which the backend followed, arrives on the listener and is shown as it is. The assertions are on
 * what the document is in, what was asked of the backend and the one fact a person needs, not on
 * whole sentences.
 */

import { beforeEach, describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { ThemeChooser } from '../src/components/ui'
import { fakeHost } from '../src/host/fake'
import type { SettingsView } from '../src/host/port'
import { applyMode } from '../src/theme-init'

describe('the colour mode', () => {
  // The document is the page's one place for the mode, and a case leaves it as it chose.
  beforeEach(() => {
    applyMode('system')
  })

  it('is applied at once, asked for from the backend, and taken back when it was not kept', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    render(<ThemeChooser port={port} />)

    await person.click(screen.getByRole('radio', { name: /Dark/ }))
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(document.documentElement.dataset.preference).toBe('dark')
    expect(controls.settings.colourModesSet).toEqual(['dark'])

    controls.settings.failKeeping('The settings could not be kept on this computer.')
    await person.click(screen.getByRole('radio', { name: /Light/ }))
    await waitFor(() => {
      expect(screen.getByTestId('theme-problem')).toHaveTextContent('kept')
    })
    // The choice that was not kept is not the mode the window stays in.
    expect(document.documentElement.dataset.preference).toBe('dark')
    expect(screen.getByRole('radio', { name: /Dark/ })).toBeChecked()
  })

  it('follows a change another device made, as the backend reports it', async () => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider port={port}>
        <ThemeChooser port={port} />
      </AppProvider>
    )
    await waitFor(() => {
      expect(screen.getByRole('radio', { name: /System/ })).toBeChecked()
    })

    // The listener is registered on the next turn of the port.
    await act(async () => {
      await Promise.resolve()
      controls.settings.change({ colour_mode: 'light' })
    })
    expect(screen.getByRole('radio', { name: /Light/ })).toBeChecked()
    expect(document.documentElement.dataset.preference).toBe('light')
  })
})

describe('the window\'s own mode', () => {
  beforeEach(() => {
    applyMode('system')
  })

  it('follows what native code keeps while no control for it is on screen', async () => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider port={port}>
        <p>Nothing here draws the appearance.</p>
      </AppProvider>
    )
    await act(async () => {
      await Promise.resolve()
      controls.settings.change({ colour_mode: 'dark' })
    })
    expect(document.documentElement.dataset.preference).toBe('dark')
  })

  it('is not undone by a first read that answers after the person chose', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    let answer: (view: SettingsView) => void = () => undefined
    const late = new Promise<SettingsView>((resolve) => {
      answer = resolve
    })
    const slow = { ...port, settingsView: () => late }
    // The press is kept and no event comes of it, so only what was applied tells the first read
    // that it is old.
    const silent = { ...port, settingsSetColourMode: () => new Promise<SettingsView>(() => undefined) }
    render(
      <AppProvider port={slow}>
        <ThemeChooser port={silent} />
      </AppProvider>
    )
    await person.click(screen.getByRole('radio', { name: /Dark/ }))
    expect(document.documentElement.dataset.preference).toBe('dark')

    // What the first read found was true before the press, and is not applied over it.
    const found = await port.settingsView()
    await act(async () => {
      answer({ ...found, colour_mode: 'system' })
      await Promise.resolve()
    })
    expect(document.documentElement.dataset.preference).toBe('dark')
  })

  it('reads after its listener is live, so a change made while it registered is not lost', async () => {
    const { port, controls } = fakeHost()
    const complete = controls.holdRegistrations()
    render(
      <AppProvider port={port}>
        <p>Nothing here draws the appearance.</p>
      </AppProvider>
    )
    await act(async () => {
      await Promise.resolve()
    })
    // Nothing published now reaches a listener; the read has not been made either.
    controls.settings.change({ colour_mode: 'dark' })
    await act(async () => {
      complete()
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(document.documentElement.dataset.preference).toBe('dark')
    })
  })

  it('keeps the radio the person pressed when the chooser\'s first read answers after it', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    let answer: (view: SettingsView) => void = () => undefined
    const late = new Promise<SettingsView>((resolve) => {
      answer = resolve
    })
    const found = await port.settingsView()
    render(
      <ThemeChooser
        port={{
          ...port,
          settingsView: () => late,
          settingsSetColourMode: () => new Promise<SettingsView>(() => undefined)
        }}
      />
    )
    await person.click(screen.getByRole('radio', { name: /Dark/ }))
    await act(async () => {
      answer({ ...found, colour_mode: 'system' })
      await Promise.resolve()
    })
    expect(screen.getByRole('radio', { name: /Dark/ })).toBeChecked()
  })

  it('selects the mode the root applied when the chooser\'s own read answers after it', async () => {
    const { port, controls } = fakeHost()
    controls.settings.change({ colour_mode: 'dark' })
    const found = await port.settingsView()
    // Both first reads are held, the root's and the chooser's, each by a port of its own.
    let answerRoot: (view: SettingsView) => void = () => undefined
    let answerChooser: (view: SettingsView) => void = () => undefined
    const root = {
      ...port,
      settingsView: () =>
        new Promise<SettingsView>((resolve) => {
          answerRoot = resolve
        })
    }
    const chooser = {
      ...port,
      settingsView: () =>
        new Promise<SettingsView>((resolve) => {
          answerChooser = resolve
        })
    }
    render(
      <AppProvider port={root}>
        <ThemeChooser port={chooser} />
      </AppProvider>
    )
    await act(async () => {
      await Promise.resolve()
    })
    await act(async () => {
      answerRoot(found)
      await Promise.resolve()
    })
    expect(document.documentElement.dataset.preference).toBe('dark')
    await act(async () => {
      answerChooser(found)
      await Promise.resolve()
    })
    expect(screen.getByRole('radio', { name: /Dark/ })).toBeChecked()
  })

  it('is the mode native code keeps when the window starts, as a reload finds it', async () => {
    const { port, controls } = fakeHost()
    controls.settings.change({ colour_mode: 'dark' })
    expect(document.documentElement.dataset.preference).toBe('system')
    render(
      <AppProvider port={port}>
        <p>Nothing here draws the appearance.</p>
      </AppProvider>
    )
    await waitFor(() => {
      expect(document.documentElement.dataset.preference).toBe('dark')
    })
  })
})

describe('settings sync in the account sheet', () => {
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
    return { person, controls, card: await within(sheet).findByTestId('settings-sync') }
  }

  it('does not show a failed read next to a change that came after it was asked for', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    let fail: (reason: unknown) => void = () => undefined
    const doomed = new Promise<never>((_, reject) => {
      fail = reject
    })
    const slow = { ...port, settingsView: () => doomed }
    render(
      <AppProvider port={slow} initialPlace={{ view: 'attention' }}>
        <App />
      </AppProvider>
    )
    await person.click(screen.getByRole('button', { name: /^Account/ }))
    const sheet = await screen.findByRole('dialog', { name: 'Account' })
    act(() => {
      controls.settings.change({ sync: { state: 'on', kept_at: 'reach.kala.to', conflicts: 0 } })
    })
    await act(async () => {
      fail(new Error('the settings could not be read'))
      await Promise.resolve()
    })
    const card = await within(sheet).findByTestId('settings-sync')
    expect(card).toHaveAttribute('data-state', 'on')
    expect(within(sheet).queryByTestId('settings-problem')).toBeNull()
  })

  it('does not keep a failed read beside a change that arrives after it', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const failing = {
      ...port,
      settingsView: () => Promise.reject(new Error('the settings could not be read'))
    }
    render(
      <AppProvider port={failing} initialPlace={{ view: 'attention' }}>
        <App />
      </AppProvider>
    )
    await person.click(screen.getByRole('button', { name: /^Account/ }))
    const sheet = await screen.findByRole('dialog', { name: 'Account' })
    await within(sheet).findByTestId('settings-problem')
    act(() => {
      controls.settings.change({ sync: { state: 'on', kept_at: 'reach.kala.to', conflicts: 0 } })
    })
    expect(within(sheet).getByTestId('settings-sync')).toHaveAttribute('data-state', 'on')
    expect(within(sheet).queryByTestId('settings-problem')).toBeNull()
  })

  it('is off until it is turned on, and then says where it keeps the settings', async () => {
    const { person, controls, card } = await openSheet()
    expect(card).toHaveAttribute('data-state', 'off')

    await person.click(within(card).getByTestId('settings-sync-turn-on'))
    await waitFor(() => {
      expect(card).toHaveAttribute('data-state', 'on')
    })
    expect(controls.settings.syncTurnedOn).toBe(1)
    expect(within(card).getByTestId('settings-sync-status')).toHaveTextContent('reach.kala.to')
    expect(within(card).queryByTestId('settings-sync-turn-on')).toBeNull()
    expect(within(card).getByTestId('settings-sync-status')).toHaveFocus()

    await person.click(within(card).getByTestId('settings-sync-now'))
    await waitFor(() => {
      expect(controls.settings.syncRuns).toBe(1)
    })
  })

  it('says when another device changed a setting this one changed too, and replaces nothing', async () => {
    const { controls, card } = await openSheet()
    act(() => {
      controls.settings.change({ sync: { state: 'on', kept_at: 'reach.kala.to', conflicts: 1 } })
    })
    expect(await within(card).findByTestId('settings-sync-conflicts')).toBeInTheDocument()
    expect(card).toHaveAttribute('data-state', 'on')
  })
})

describe('the choice between two versions of the settings', () => {
  const MINE = { colour_mode: 'system', updated_at_ms: 1_700_000_000_000 } as const
  const THEIRS = { conflict_id: 'copy-1', colour_mode: 'light', updated_at_ms: 1_600_000_000_000 } as const

  async function waiting(others: readonly (typeof THEIRS | { conflict_id: string; colour_mode: null; updated_at_ms: number })[] = [THEIRS]) {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    render(
      <AppProvider port={port} initialPlace={{ view: 'attention' }}>
        <App />
      </AppProvider>
    )
    await person.click(screen.getByRole('button', { name: /^Account/ }))
    const sheet = await screen.findByRole('dialog', { name: 'Account' })
    const card = await within(sheet).findByTestId('settings-sync')
    act(() => {
      controls.settings.waitingForAChoice({ mine: MINE, others })
      controls.settings.change({ sync: { state: 'on', kept_at: 'reach.kala.to', conflicts: others.length } })
    })
    await person.click(await within(card).findByTestId('settings-sync-choose'))
    const form = await within(card).findByTestId('settings-choice')
    return { person, controls, card, form }
  }

  it('opens in place with nothing chosen, this device first, and keeps what the person picks', async () => {
    const { person, controls, card, form } = await waiting()
    expect(within(form).getByText(/Nothing has been replaced/)).toBeInTheDocument()
    const options = within(form).getAllByRole('radio')
    expect(options.map((option) => (option as HTMLInputElement).checked)).toEqual([false, false])
    // This device's own is first, though the other version was recorded earlier; no version is
    // placed or marked for being later.
    expect(within(form).getAllByText(/This device|Another device/).map((each) => each.textContent?.split(',')[0])).toEqual([
      'This device',
      'Another device'
    ])
    const keep = within(form).getByTestId('settings-choice-keep')
    expect(keep).toBeDisabled()
    expect(within(form).getByRole('heading', { name: /Which appearance/ })).toHaveFocus()

    await person.click(within(form).getByRole('radio', { name: /Light/ }))
    expect(keep).toBeEnabled()
    expect(keep).toHaveTextContent('Keep Light')
    await person.click(keep)

    await waitFor(() => {
      expect(controls.settings.kept).toEqual([{ choice: 'copy', conflict_id: 'copy-1' }])
    })
    await waitFor(() => {
      expect(within(card).queryByTestId('settings-choice')).toBeNull()
    })
    expect(within(card).queryByTestId('settings-sync-conflicts')).toBeNull()
  })

  it('takes the window to the version that was kept, with no appearance control on screen', async () => {
    const { person, controls, form } = await waiting()
    await person.click(within(form).getByRole('radio', { name: /Light/ }))
    await person.click(within(form).getByTestId('settings-choice-keep'))
    await waitFor(() => {
      expect(controls.settings.kept).toEqual([{ choice: 'copy', conflict_id: 'copy-1' }])
    })
    await waitFor(() => {
      expect(document.documentElement.dataset.preference).toBe('light')
    })
  })

  it('closes without recording anything when the person is not ready', async () => {
    const { person, controls, card, form } = await waiting()
    await person.click(within(form).getByTestId('settings-choice-cancel'))
    expect(within(card).queryByTestId('settings-choice')).toBeNull()
    // Focus goes back to the control that opened the choice, which is where the person was.
    expect(within(card).getByTestId('settings-sync-choose')).toHaveFocus()
    expect(controls.settings.kept).toEqual([])
    // The conflict is still there to come back to.
    expect(within(card).getByTestId('settings-sync-conflicts')).toBeInTheDocument()
  })

  it('says in the appearance control that a choice stays on this device while versions wait', async () => {
    const { port, controls } = fakeHost()
    render(<ThemeChooser port={port} />)
    expect(screen.queryByTestId('theme-waiting')).toBeNull()
    await act(async () => {
      await Promise.resolve()
      controls.settings.change({ sync: { state: 'on', kept_at: 'reach.kala.to', conflicts: 1 } })
    })
    expect(screen.getByTestId('theme-waiting')).toBeInTheDocument()
  })

  it('keeps the note a newer event raised when an older read answers after it', async () => {
    const { port, controls } = fakeHost()
    let answer: (view: SettingsView) => void = () => undefined
    const late = new Promise<SettingsView>((resolve) => {
      answer = resolve
    })
    const found = await port.settingsView()
    render(<ThemeChooser port={{ ...port, settingsView: () => late }} />)
    await act(async () => {
      await Promise.resolve()
      controls.settings.change({ sync: { state: 'on', kept_at: 'reach.kala.to', conflicts: 1 } })
    })
    expect(screen.getByTestId('theme-waiting')).toBeInTheDocument()
    await act(async () => {
      answer(found)
      await Promise.resolve()
    })
    expect(screen.getByTestId('theme-waiting')).toBeInTheDocument()
  })

  it('shows a version it cannot read and does not let the person keep it', async () => {
    const { form } = await waiting([{ conflict_id: 'copy-2', colour_mode: null, updated_at_ms: 0 }])
    const options = within(form).getAllByRole('radio')
    expect(options).toHaveLength(2)
    expect(options[1]).toBeDisabled()
  })
})

describe('drafts in settings sync\'s card', () => {
  async function openOnCard() {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    render(
      <AppProvider port={port} initialPlace={{ view: 'attention' }}>
        <App />
      </AppProvider>
    )
    await person.click(screen.getByRole('button', { name: /^Account/ }))
    const sheet = await screen.findByRole('dialog', { name: 'Account' })
    const card = await within(sheet).findByTestId('settings-sync')
    return { person, controls, card, sheet }
  }

  it('is offered only once settings sync is on, off to begin with, and is turned on and off by one press', async () => {
    const { person, controls, card } = await openOnCard()
    expect(within(card).queryByTestId('drafts-sync')).toBeNull()

    act(() => {
      controls.settings.change({ sync: { state: 'on', kept_at: 'reach.kala.to' } })
    })
    const row = await within(card).findByTestId('drafts-sync')
    const keep = within(row).getByRole('switch', { name: 'Keep drafts in step' })
    expect(keep).toHaveAttribute('aria-checked', 'false')

    await person.click(keep)
    await waitFor(() => {
      expect(keep).toHaveAttribute('aria-checked', 'true')
    })
    expect(controls.settings.draftsSetTo).toEqual([true])

    await person.click(keep)
    await waitFor(() => {
      expect(keep).toHaveAttribute('aria-checked', 'false')
    })
    expect(controls.settings.draftsSetTo).toEqual([true, false])
  })

  it('says which drafts stay on this device and why, host by host, only while it is on', async () => {
    const { controls, card } = await openOnCard()
    act(() => {
      controls.settings.change({
        sync: {
          state: 'on',
          kept_at: 'reach.kala.to',
          drafts: {
            enabled: true,
            problem: null,
            arrivals: 0,
            kept_here: [
              { host: 'studio', why: 'private', detail: null, drafts: 1 },
              { host: 'laptop', why: 'unreadable', detail: 'this computer is not connected to that host', drafts: 2 },
              { host: null, why: 'unknown_host', detail: null, drafts: 1 }
            ]
          }
        }
      })
    })
    const notes = await within(card).findAllByTestId('drafts-kept-here')
    expect(notes).toHaveLength(3)
    expect(notes[0]).toHaveTextContent(/1 draft for studio stays on this device/)
    expect(notes[0]).toHaveTextContent(/privacy mode is on there/)
    expect(notes[1]).toHaveTextContent(/2 drafts for laptop stay on this device/)
    expect(notes[1]).toHaveTextContent(/not connected to that host/)
    expect(notes[2]).toHaveTextContent(/until this device is connected to the host it is for/)

    // Turned off, nothing is said of drafts that are not being kept in step.
    act(() => {
      controls.settings.change({
        sync: { drafts: { enabled: false, problem: null, arrivals: 0, kept_here: [] } }
      })
    })
    await waitFor(() => {
      expect(within(card).queryByTestId('drafts-kept-here')).toBeNull()
    })
  })

  it('says why the backend refused the switch, and leaves it where it was', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const refusing = {
      ...port,
      settingsDraftsSet: () => Promise.reject(new Error('Settings sync is not on any more.'))
    }
    render(
      <AppProvider port={refusing} initialPlace={{ view: 'attention' }}>
        <App />
      </AppProvider>
    )
    await person.click(screen.getByRole('button', { name: /^Account/ }))
    const sheet = await screen.findByRole('dialog', { name: 'Account' })
    const card = await within(sheet).findByTestId('settings-sync')
    act(() => {
      controls.settings.change({ sync: { state: 'on', kept_at: 'reach.kala.to' } })
    })
    const keep = await within(card).findByRole('switch', { name: 'Keep drafts in step' })
    await person.click(keep)
    await waitFor(() => {
      expect(card).toHaveTextContent('Settings sync is not on any more.')
    })
    expect(keep).toHaveAttribute('aria-checked', 'false')
  })
})

describe('the devices that share the settings', () => {
  async function openOnAccount() {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    render(
      <AppProvider port={port} initialPlace={{ view: 'attention' }}>
        <App />
      </AppProvider>
    )
    await person.click(screen.getByRole('button', { name: /^Account/ }))
    const sheet = await screen.findByRole('dialog', { name: 'Account' })
    await within(sheet).findByTestId('settings-sync')
    return { person, controls, sheet }
  }

  const sharing = {
    state: 'on' as const,
    kept_at: 'reach.kala.to',
    devices: {
      can_confirm: true,
      out: false,
      waiting: false,
      members: [{ reference: 'me', name: 'This computer', this_computer: true, vouched: true }],
      candidates: [{ reference: 'phone', name: 'the-phone' }],
      offers: [],
      outcomes: []
    }
  }

  const chosenService = {
    origin: 'https://reach.kala.to',
    host: 'reach.kala.to',
    is_default: true
  }

  it('sends nothing to the sync service while settings sync is off until the person asks to look', async () => {
    const { person, controls, sheet } = await openOnAccount()
    act(() => {
      controls.settings.change({ sync: { service: chosenService } })
    })
    const card = await within(sheet).findByTestId('settings-devices')
    expect(controls.settings.devicesAsked).toEqual([])
    expect(within(card).queryByTestId('settings-devices-members')).toBeNull()
    await person.click(within(card).getByTestId('settings-devices-look'))
    expect(controls.settings.devicesAsked).toEqual(['refresh'])
  })

  it('says, where settings sync starts, that starting a collection of its own cannot be undone by joining', async () => {
    const { controls, sheet } = await openOnAccount()
    act(() => {
      controls.settings.change({
        sync: {
          state: 'off',
          service: chosenService,
          devices: {
            ...sharing.devices,
            members: [],
            candidates: [],
            offers: [{ reference: 'c-1', name: 'the-laptop' }]
          }
        }
      })
    })
    const settings = await within(sheet).findByTestId('settings-sync')
    expect(within(settings).getByTestId('settings-sync-start-own')).toHaveTextContent(/join them in the card below/)
    expect(within(settings).getByTestId('settings-sync-turn-on')).not.toHaveClass('btn-primary')
  })

  it('offers a device the hosts list, shares with it by naming it, and shows it as a member', async () => {
    const { person, controls, sheet } = await openOnAccount()
    act(() => {
      controls.settings.change({ sync: sharing })
    })
    const card = await within(sheet).findByTestId('settings-devices')
    expect(within(card).getByTestId('settings-devices-status')).toHaveTextContent(/not shared/)

    await person.click(within(card).getByRole('button', { name: 'Share settings with the-phone' }))
    expect(controls.settings.devicesAsked).toContain('share phone')
    await waitFor(() => {
      expect(within(card).getByTestId('settings-devices-members')).toHaveTextContent('the-phone')
    })
    expect(within(card).queryByTestId('settings-devices-candidates')).toBeNull()
    expect(within(card).getByTestId('settings-devices-status')).toHaveTextContent(/1 other device/)
  })

  it('asks once before taking a member out, names it in both answers, and keeps it on the safe one', async () => {
    const { person, controls, sheet } = await openOnAccount()
    act(() => {
      controls.settings.change({
        sync: {
          ...sharing,
          devices: {
            ...sharing.devices,
            members: [
              ...sharing.devices.members,
              { reference: 'phone', name: 'the-phone', this_computer: false, vouched: true }
            ],
            candidates: []
          }
        }
      })
    })
    const card = await within(sheet).findByTestId('settings-devices')
    // This computer is a member and has no control for taking itself out.
    expect(within(card).getAllByRole('button', { name: /^Take .* out$/ })).toHaveLength(1)
    const trigger = within(card).getByRole('button', { name: 'Take the-phone out' })
    await person.click(trigger)
    expect(controls.settings.devicesAsked).not.toContain('remove phone')
    expect(within(card).getByTestId('settings-devices-taking-out')).toHaveTextContent('the-phone')
    const keep = within(card).getByRole('button', { name: 'Keep the-phone in' })
    expect(keep).toHaveFocus()

    // Keeping it sends nothing and gives focus back to the control that asked.
    await person.click(keep)
    expect(controls.settings.devicesAsked).not.toContain('remove phone')
    expect(within(card).queryByTestId('settings-devices-taking-out')).toBeNull()
    expect(within(card).getByRole('button', { name: 'Take the-phone out' })).toHaveFocus()

    await person.click(within(card).getByRole('button', { name: 'Take the-phone out' }))
    await person.click(within(card).getByRole('button', { name: 'Take the-phone out now' }))
    expect(controls.settings.devicesAsked).toContain('remove phone')
    await waitFor(() => {
      expect(within(card).getByTestId('settings-devices-members')).not.toHaveTextContent(
        'the-phone'
      )
    })
  })

  it('lets the person back out of the question about a device with Escape', async () => {
    const { person, controls, sheet } = await openOnAccount()
    act(() => {
      controls.settings.change({
        sync: {
          ...sharing,
          devices: {
            ...sharing.devices,
            members: [
              ...sharing.devices.members,
              { reference: 'phone', name: 'the-phone', this_computer: false, vouched: true }
            ],
            candidates: []
          }
        }
      })
    })
    const card = await within(sheet).findByTestId('settings-devices')
    await person.click(within(card).getByRole('button', { name: 'Take the-phone out' }))
    expect(within(card).getByTestId('settings-devices-taking-out')).toBeInTheDocument()
    await person.keyboard('{Escape}')
    expect(within(card).queryByTestId('settings-devices-taking-out')).toBeNull()
    expect(within(card).getByRole('button', { name: 'Take the-phone out' })).toHaveFocus()
    expect(controls.settings.devicesAsked).not.toContain('remove phone')
  })

  it('offers the settings another device shares to a computer that shares none, and joins on a press', async () => {
    const { person, controls, sheet } = await openOnAccount()
    act(() => {
      controls.settings.change({
        sync: {
          devices: { ...sharing.devices, members: [], candidates: [], offers: [{ reference: 'c-1', name: 'the-laptop' }] }
        }
      })
    })
    const card = await within(sheet).findByTestId('settings-devices')
    expect(within(card).getByTestId('settings-devices-offer')).toBeInTheDocument()
    expect(within(card).getByText('Settings started on the-laptop')).toBeInTheDocument()
    await person.click(
      within(card).getByRole('button', { name: 'Join the settings started on the-laptop' })
    )
    expect(controls.settings.devicesAsked).toContain('join c-1')
    await waitFor(() => {
      expect(within(card).queryByTestId('settings-devices-offer')).toBeNull()
    })
  })

  it('offers a computer that cannot ask the person neither a share nor a join, and says where to do it', async () => {
    const { controls, sheet } = await openOnAccount()
    act(() => {
      controls.settings.change({
        sync: {
          ...sharing,
          devices: {
            ...sharing.devices,
            can_confirm: false,
            offers: [{ reference: 'c-1', name: 'the-laptop' }]
          }
        }
      })
    })
    const card = await within(sheet).findByTestId('settings-devices')
    expect(within(card).getByTestId('settings-devices-cannot-confirm')).toHaveTextContent(
      /Mac or a Windows computer/
    )
    expect(within(card).queryByRole('button', { name: /^Share settings with/ })).toBeNull()
    expect(within(card).queryByRole('button', { name: /^Join the settings/ })).toBeNull()
    expect(within(card).queryByTestId('settings-devices-offer')).toBeNull()
  })

  it('says what a change came to until the person dismisses it', async () => {
    const { person, controls, sheet } = await openOnAccount()
    act(() => {
      controls.settings.change({
        sync: {
          ...sharing,
          devices: {
            ...sharing.devices,
            outcomes: [{ what: 'addition', ended: 'refused', name: 'the-phone' }]
          }
        }
      })
    })
    const card = await within(sheet).findByTestId('settings-devices')
    expect(within(card).getByTestId('settings-devices-outcome')).toHaveTextContent('the-phone')
    await person.click(within(card).getByTestId('settings-devices-dismiss'))
    await waitFor(() => {
      expect(within(card).queryByTestId('settings-devices-outcome')).toBeNull()
    })
  })

  it('lists two outcomes that say the same thing, each once', async () => {
    const { controls, sheet } = await openOnAccount()
    act(() => {
      controls.settings.change({
        sync: {
          ...sharing,
          devices: {
            ...sharing.devices,
            outcomes: [
              { what: 'addition', ended: 'refused', name: 'the-phone' },
              { what: 'addition', ended: 'refused', name: 'the-phone' }
            ]
          }
        }
      })
    })
    const card = await within(sheet).findByTestId('settings-devices')
    expect(within(card).getAllByTestId('settings-devices-outcome')).toHaveLength(2)
  })

  it('waits for another device to seal the settings, and says so, when this computer joined after them', async () => {
    const { controls, sheet } = await openOnAccount()
    act(() => {
      controls.settings.change({
        sync: { ...sharing, devices: { ...sharing.devices, waiting: true } }
      })
    })
    const card = await within(sheet).findByTestId('settings-devices')
    expect(within(card).getByTestId('settings-devices-waiting')).toBeInTheDocument()
  })
})
