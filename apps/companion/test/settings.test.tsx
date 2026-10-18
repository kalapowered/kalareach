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
