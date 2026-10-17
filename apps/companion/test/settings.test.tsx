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
