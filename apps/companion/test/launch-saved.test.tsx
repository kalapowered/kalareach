/**
 * The host's saved launch commands on the page (KR-REQ-13.11): the group on the launch surface, the
 * press of a saved command, and the Settings form that keeps the list.
 *
 * The scripted host keeps a list and a revision and takes a save or a remove as the host does:
 * against the revision it names. What is checked is what the page makes of its answers. Every case
 * decides by the host's recorded calls and by what the page draws, never by waiting.
 */

import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import recorded from '../../../fixtures/shell-launch/answers.json'
import { App } from '../src/App'
import { AppProvider, useApp, type Place } from '../src/app/state'
import type { LaunchSurfaceReads } from '../src/app/launch-surface'
import { fakeHost } from '../src/host/fake'
import type { HostPort, LaunchPress } from '../src/host/port'
import { LaunchSurface } from '../src/views/LaunchSurface'
import { LaunchCommands } from '../src/views/LaunchCommands'
import { MobileApp } from '../src/mobile/MobileApp'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const ENVIRONMENT = '3f1a2c40-11aa-4b2c-9d3e-000000000001'

const SAVED = [
  { label: 'Claude Code', program: '/usr/local/bin/claude', arguments: ['--resume', 'two words', ''] },
  { label: 'Codex CLI', program: 'codex', arguments: [] }
]

function open(port: HostPort, pane: 'semantic' | 'terminal', sessionId = SESSION_MAIN): void {
  const place: Place = { view: 'session', sessionId, pane }
  render(
    <AppProvider port={port} initialPlace={place}>
      <App />
    </AppProvider>
  )
}

async function takeControl(person: ReturnType<typeof userEvent.setup>): Promise<void> {
  await screen.findByTestId('palette-provenance')
  await person.click(screen.getByRole('button', { name: 'Take control' }))
  await waitFor(() => {
    expect(screen.getByTestId('terminal-mode')).toHaveTextContent('Control')
  })
}

/** The saved commands' group, once a list has been read and drawn. */
async function group(): Promise<HTMLElement> {
  return await screen.findByTestId('launch-saved')
}

/** The labels of the buttons in the saved commands' group, with the program each one shows. */
function saved(): { label: string | undefined; program: string | null | undefined }[] {
  return within(screen.getByTestId('launch-saved'))
    .getAllByRole('button')
    .map((each) => ({
      label: each.dataset.named,
      program: each.querySelector('.launch-program')?.textContent
    }))
}

/** What the page's toast says now. */
function Said(): ReactNode {
  const { toast } = useApp()
  return <p data-testid="said">{toast?.text ?? ''}</p>
}

function settings(port: HostPort, place: 'desktop' | 'phone' = 'desktop'): void {
  render(
    <AppProvider port={port}>
      <LaunchCommands place={place} />
      <Said />
    </AppProvider>
  )
}

describe('the saved commands on the launch surface', () => {
  it('draws a named group after the installed agents under its heading, each with its program shown', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    open(port, 'terminal')
    await takeControl(person)
    const named = await group()
    expect(within(named).getByText('Saved commands')).toBeInTheDocument()
    expect(saved()).toEqual([
      { label: 'Claude Code', program: '/usr/local/bin/claude' },
      { label: 'Codex CLI', program: 'codex' }
    ])
    const installed = within(screen.getByTestId('launch-surface'))
      .getAllByRole('button')
      .filter((each) => each.dataset.offer !== undefined)
    expect(installed.length).toBeGreaterThan(0)
    for (const each of installed) {
      expect(each.compareDocumentPosition(named) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    }
  })

  it('draws a named label equal to an offers label in the named group with its program', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    open(port, 'terminal')
    await takeControl(person)
    const named = await group()
    // The installed agent has no program line; the saved command of the same label has its own.
    const surface = screen.getByTestId('launch-surface')
    const installed = within(surface)
      .getAllByRole('button')
      .filter((each) => each.dataset.offer !== undefined && each.textContent === 'Claude Code')
    expect(installed).toHaveLength(1)
    expect(installed[0].querySelector('.launch-program')).toBeNull()
    expect(within(named).getByRole('button', { name: /Claude Code/ })).toHaveTextContent(
      '/usr/local/bin/claude'
    )
  })

  it('draws named buttons dark where the installed ones are', async () => {
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    controls.launchScenario('verified_held_elsewhere')
    open(port, 'terminal')
    await group()
    for (const each of within(screen.getByTestId('launch-saved')).getAllByRole('button')) {
      expect(each).toBeDisabled()
    }
    expect(screen.getByTestId('launch-stale')).toHaveTextContent("Another connection holds this terminal's input")
  })

  it('presses a saved command as its vector, quoting the prompt of the newest read', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    open(port, 'terminal')
    await takeControl(person)
    const named = await group()
    await waitFor(() => {
      expect(within(named).getByRole('button', { name: /Claude Code/ })).toBeEnabled()
    })
    await person.click(within(named).getByRole('button', { name: /Claude Code/ }))
    expect(
      await screen.findByText('Submitted the command for "Claude Code" at the prompt.')
    ).toBeInTheDocument()
    expect(controls.launches).toEqual([
      expect.objectContaining({
        sessionId: SESSION_MAIN,
        // The program, then each argument, an empty one and a word with a space as they were saved.
        command: { arguments: ['/usr/local/bin/claude', '--resume', 'two words', ''] },
        promptGeneration: '7'
      })
    ])
  })

  it('refuses a named press when the prompt moved, shows no success and reads the prompt again', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    open(port, 'terminal')
    await takeControl(person)
    const named = await group()
    await waitFor(() => {
      expect(within(named).getByRole('button', { name: /Codex CLI/ })).toBeEnabled()
    })
    const reads = controls.hold('launchSurface')
    act(() => {
      controls.changePromptGeneration()
    })
    await person.click(within(named).getByRole('button', { name: /Codex CLI/ }))
    await waitFor(() => {
      expect(reads.count).toBeGreaterThan(0)
    })
    expect(screen.queryByText('Submitted the command for "Codex CLI" at the prompt.')).toBeNull()
    expect(controls.launches).toEqual([])
    expect(await screen.findByText(/The prompt changed before the launch was installed/)).toBeInTheDocument()
    for (const each of within(screen.getByTestId('launch-saved')).getAllByRole('button')) {
      expect(each).toBeDisabled()
    }
  })

  it('shows a stock shell each saved command with every word quoted', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    const created = await port.sessionCreate(
      {
        environment_id: ENVIRONMENT,
        presentation: 'invisible',
        shell: null,
        shell_mode: 'native_compat',
        cwd: '/Users/rs/work/notes',
        dimensions: null,
        worker_profile: 'desktop_bound',
        environment_snapshot: [],
        palette: null,
        launch_profile: { startup: 'host_default', fenced_launch: false, command_integrations: [] },
        terminal: null
      },
      {}
    )
    open(port, 'semantic', created.value?.session.session_id ?? '')
    const instructions = await screen.findByTestId('launch-instructions')
    await waitFor(() => {
      expect(within(instructions).getByTestId('launch-saved')).toBeInTheDocument()
    })
    await person.click(within(instructions).getByRole('button', { name: /Claude Code.*claude/ }))
    expect(within(instructions).getByTestId('launch-instruction')).toHaveTextContent(
      "Type this at the prompt: '/usr/local/bin/claude' '--resume' 'two words' ''"
    )
    expect(controls.launches).toEqual([])
  })

  it('draws no named group and reads no list for a device without host.manage', async () => {
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    controls.setRights(['session.view', 'terminal.input'])
    controls.launchScenario('verified_held_here')
    open(port, 'terminal')
    await screen.findByTestId('launch-surface')
    expect(screen.queryByTestId('launch-saved')).toBeNull()
    expect(controls.launchCommands.reads).toBe(0)
  })

  it('draws the installed agents and says the list could not be read where the host cannot read it', async () => {
    const { port, controls } = fakeHost()
    controls.launchCommands.scenario = 'unreadable'
    controls.launchScenario('verified_held_here')
    open(port, 'terminal')
    expect(await screen.findByTestId('launch-saved-unread')).toHaveTextContent(
      'The saved launch commands could not be read.'
    )
    expect(screen.queryByTestId('launch-saved')).toBeNull()
    expect(
      within(screen.getByTestId('launch-surface'))
        .getAllByRole('button')
        .filter((each) => each.dataset.offer !== undefined).length
    ).toBeGreaterThan(0)
  })

  it('draws only the installed agents and says nothing for a host that does not serve the list, until the connection changes', async () => {
    const { port, controls } = fakeHost()
    controls.launchCommands.scenario = 'not_served'
    controls.launchCommands.changeElsewhere(SAVED)
    controls.launchScenario('verified_held_here')
    open(port, 'terminal')
    await screen.findByTestId('launch-surface')
    await waitFor(() => {
      expect(controls.launchCommands.reads).toBe(1)
    })
    expect(screen.queryByTestId('launch-saved')).toBeNull()
    expect(screen.queryByTestId('launch-saved-unread')).toBeNull()
    // The host is of another release now, and the connection says so by changing.
    controls.launchCommands.scenario = 'serve'
    act(() => {
      controls.setRights(['session.view', 'terminal.input', 'host.manage'])
    })
    expect(await group()).toBeInTheDocument()
    expect(controls.launchCommands.reads).toBe(2)
  })

  it('leaves the buttons of a command removed elsewhere at the next completed list read', async () => {
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    controls.launchScenario('verified_held_here')
    open(port, 'terminal')
    await group()
    expect(saved().map((each) => each.label)).toEqual(['Claude Code', 'Codex CLI'])
    controls.launchCommands.changeElsewhere(SAVED.slice(0, 1))
    act(() => {
      controls.setRights(['session.view', 'terminal.input', 'host.manage'])
    })
    await waitFor(() => {
      expect(saved().map((each) => each.label)).toEqual(['Claude Code'])
    })
  })

  it('changes nothing while a list read is in flight, and draws the new list when it answers', async () => {
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    controls.launchScenario('verified_held_here')
    open(port, 'terminal')
    await group()
    const reads = controls.hold('launchCommands')
    controls.launchCommands.changeElsewhere([])
    act(() => {
      controls.setRights(['session.view', 'terminal.input', 'host.manage'])
    })
    await waitFor(() => {
      expect(reads.count).toBe(1)
    })
    // The round is out: the group stands as it was, and does not flicker.
    expect(saved().map((each) => each.label)).toEqual(['Claude Code', 'Codex CLI'])
    await act(async () => {
      reads.release()
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(screen.queryByTestId('launch-saved')).toBeNull()
    })
  })

  it('sends nothing for a press of a vector the newest list no longer holds, and reads the list again', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    // The group was drawn from a list that held the command; the newest answer, which the page has
    // not drawn yet, does not.
    const drawnFrom = { revision: '1', commands: SAVED }
    const newest = { revision: '2', commands: SAVED.slice(0, 1) }
    const press = vi.fn<(press: LaunchPress) => Promise<never>>()
    const listAgain = vi.fn()
    const again = vi.fn()
    const reads: LaunchSurfaceReads = {
      reading: { state: 'served', surface: structuredClone(recorded.verified_held_here) as never },
      unread: null,
      number: 1,
      newest: () => 1,
      again,
      dark: false,
      list: { state: 'served', list: drawnFrom },
      listUnread: null,
      listAgain,
      listNow: () => newest
    }
    render(
      <AppProvider port={port}>
        <LaunchSurface reads={reads} mayType connected press={press} />
      </AppProvider>
    )
    const named = await group()
    await person.click(within(named).getByRole('button', { name: /Codex CLI/ }))
    expect(press).not.toHaveBeenCalled()
    expect(listAgain).toHaveBeenCalledTimes(1)
    // A command the newest list holds is pressed.
    press.mockResolvedValue({} as never)
    await person.click(within(named).getByRole('button', { name: /Claude Code/ }))
    expect(press).toHaveBeenCalledTimes(1)
    expect(press.mock.calls[0][0].command).toEqual({
      arguments: ['/usr/local/bin/claude', '--resume', 'two words', '']
    })
  })

  it('sends no launch for a mount, a refresh, a reconnect, a save or a remove', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    open(port, 'terminal')
    await takeControl(person)
    await group()
    act(() => {
      controls.setRights(['session.view', 'terminal.input', 'host.manage'])
    })
    await waitFor(() => {
      expect(controls.launchCommands.reads).toBeGreaterThan(1)
    })
    const revision = controls.launchCommands.current
    await port.launchCommandSave({
      expected_revision: revision,
      command: { label: 'Another', program: 'another', arguments: [] }
    })
    await port.launchCommandRemove({
      expected_revision: controls.launchCommands.current,
      label: 'Another'
    })
    expect(controls.launches).toEqual([])
  })
})

describe('the Settings form for the saved commands', () => {
  it('holds a program and separate arguments, shows a display-only preview and saves them as typed', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    settings(port)
    await person.type(await screen.findByTestId('launch-commands-name'), 'Agent')
    await person.type(screen.getByTestId('launch-commands-program'), 'C:\\tools\\agent.exe')
    await person.click(screen.getByTestId('launch-commands-add-argument'))
    await person.click(screen.getByTestId('launch-commands-add-argument'))
    await person.type(screen.getAllByTestId('launch-commands-argument')[0], 'two words')
    const preview = screen.getByTestId('launch-commands-preview')
    expect(within(preview).getByText('Preview: the saved program and arguments.')).toBeInTheDocument()
    expect(within(preview).getAllByRole('listitem').map((each) => each.textContent)).toEqual([
      '"C:\\tools\\agent.exe"',
      '"two words"',
      '""'
    ])
    expect(within(preview).queryByRole('textbox')).toBeNull()
    await person.click(screen.getByTestId('launch-commands-save'))
    await waitFor(() => {
      expect(controls.launchCommands.writes).toHaveLength(1)
    })
    // A Windows path arrives unchanged and the empty argument is kept.
    expect(controls.launchCommands.writes[0]).toMatchObject({
      kind: 'save',
      command: { label: 'Agent', program: 'C:\\tools\\agent.exe', arguments: ['two words', ''] }
    })
    expect(await screen.findByTestId('said')).toHaveTextContent('Saved the launch command "Agent".')
    expect(await screen.findByTestId('launch-commands-list')).toHaveTextContent('Agent')
    expect(controls.launches).toEqual([])
  })

  it('warns that a save replaces the command whose label matches, in the spelling saved', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    settings(port)
    await person.type(await screen.findByTestId('launch-commands-name'), 'claude code')
    expect(screen.getByTestId('launch-commands-replaces')).toHaveTextContent(
      'A command named "Claude Code" is already saved. Saving this one replaces it.'
    )
    await person.type(screen.getByTestId('launch-commands-program'), 'claude')
    await person.click(screen.getByTestId('launch-commands-save'))
    expect(await screen.findByTestId('said')).toHaveTextContent('Replaced the launch command "claude code".')
    expect(controls.launchCommands.commands.map((each) => each.label)).toEqual(['claude code', 'Codex CLI'])
  })

  it('keeps the revision the person saw, and a round read does not change it', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    settings(port)
    await screen.findByTestId('launch-commands-list')
    const saw = controls.launchCommands.current
    await person.type(screen.getByTestId('launch-commands-name'), 'New')
    await person.type(screen.getByTestId('launch-commands-program'), 'new')
    // The list changes elsewhere, and a round read shows it while the person is still editing.
    controls.launchCommands.changeElsewhere(SAVED.slice(0, 1))
    act(() => {
      controls.setRights(['session.view', 'terminal.input', 'host.manage'])
    })
    await waitFor(() => {
      expect(within(screen.getByTestId('launch-commands-list')).queryByText('Codex CLI')).toBeNull()
    })
    await person.click(screen.getByTestId('launch-commands-save'))
    // The save names the revision the person began from, so it is a conflict, not an overwrite.
    expect(await screen.findByTestId('launch-commands-conflict')).toHaveTextContent(
      'The launch commands changed while you were editing. Look at the list and save again.'
    )
    expect(controls.launchCommands.writes).toHaveLength(1)
    expect(controls.launchCommands.writes[0]).toMatchObject({ kind: 'save', expected_revision: saw })
    expect(controls.launchCommands.commands.map((each) => each.label)).toEqual(['Claude Code'])
    // The list as it stands is shown, and a second save names it and lands.
    await person.click(screen.getByTestId('launch-commands-save'))
    await waitFor(() => {
      expect(controls.launchCommands.commands.map((each) => each.label)).toEqual(['Claude Code', 'New'])
    })
    expect(screen.queryByTestId('launch-commands-conflict')).toBeNull()
  })

  it('holds the form still while a save waits, so an edit made in the meantime is not lost', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    let answer: () => void = () => undefined
    const slow: HostPort = {
      ...port,
      launchCommandSave: (params) =>
        new Promise((resolve) => {
          answer = () => {
            void port.launchCommandSave(params).then(resolve)
          }
        })
    }
    settings(slow)
    await person.type(await screen.findByTestId('launch-commands-name'), 'New')
    await person.type(screen.getByTestId('launch-commands-program'), 'new')
    await person.click(screen.getByTestId('launch-commands-add-argument'))
    await person.click(screen.getByTestId('launch-commands-save'))

    // While the save waits nothing in the form can be edited, so the draft that is cleared when the
    // host answers is the draft that was sent.
    expect(screen.getByTestId('launch-commands-name')).toBeDisabled()
    expect(screen.getByTestId('launch-commands-program')).toBeDisabled()
    expect(screen.getByTestId('launch-commands-argument')).toBeDisabled()
    expect(screen.getByTestId('launch-commands-add-argument')).toBeDisabled()
    expect(screen.getByTestId('launch-commands-remove-argument')).toBeDisabled()

    await act(async () => {
      answer()
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(screen.getByTestId('launch-commands-name')).toBeEnabled()
    })
    expect(screen.getByTestId('launch-commands-name')).toHaveValue('')
  })

  it('says so when the host cannot confirm a save, and reads the list again', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const lost: HostPort = {
      ...port,
      launchCommandSave: () =>
        Promise.resolve({ receipt: null, value: null, action_id: 'a-1', answer_lost: true })
    }
    settings(lost)
    await person.type(await screen.findByTestId('launch-commands-name'), 'New')
    await person.type(screen.getByTestId('launch-commands-program'), 'new')
    const before = controls.launchCommands.reads
    await person.click(screen.getByTestId('launch-commands-save'))
    expect(await screen.findByTestId('launch-commands-unconfirmed')).toHaveTextContent(
      'The host could not confirm the change. Look at the list to see what it holds.'
    )
    await waitFor(() => {
      expect(controls.launchCommands.reads).toBeGreaterThan(before)
    })
  })

  it('removes the command with the revision the person saw, and tells a conflict', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    settings(port)
    const list = await screen.findByTestId('launch-commands-list')
    await person.click(within(list).getByRole('button', { name: 'Remove Codex CLI' }))
    expect(await screen.findByTestId('said')).toHaveTextContent('Removed the launch command "Codex CLI".')
    expect(controls.launchCommands.writes[0]).toMatchObject({ kind: 'remove', label: 'Codex CLI' })
    expect(controls.launchCommands.commands.map((each) => each.label)).toEqual(['Claude Code'])
    // The list moves on between the read and the press: nothing is removed and the person is told.
    const held = controls.hold('launchCommands')
    controls.launchCommands.changeElsewhere(SAVED)
    await person.click(
      within(screen.getByTestId('launch-commands-list')).getByRole('button', { name: 'Remove Claude Code' })
    )
    expect(await screen.findByTestId('launch-commands-conflict')).toHaveTextContent(
      'The launch commands changed since this list was shown. Look at the list, then remove the command again if it is still there.'
    )
    held.release()
    expect(controls.launchCommands.commands.map((each) => each.label)).toEqual(['Claude Code', 'Codex CLI'])
    expect(controls.launches).toEqual([])
  })

  it('tells a stale remove of a label whose case changed elsewhere as a conflict, not as an absent command', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere([{ label: 'Agent', program: 'agent', arguments: [] }])
    settings(port)
    const list = await screen.findByTestId('launch-commands-list')
    // Somewhere else the same command is saved again under a label of another case; the host
    // compares labels in lower case, so it is the same command, and it stays.
    const held = controls.hold('launchCommands')
    controls.launchCommands.changeElsewhere([{ label: 'agent', program: 'agent', arguments: [] }])
    await person.click(within(list).getByRole('button', { name: 'Remove Agent' }))
    expect(await screen.findByTestId('launch-commands-conflict')).toHaveTextContent(
      'The launch commands changed since this list was shown. Look at the list, then remove the command again if it is still there.'
    )
    expect(screen.getByTestId('said')).not.toHaveTextContent('No launch command is named')
    held.release()
    expect(controls.launchCommands.commands.map((each) => each.label)).toEqual(['agent'])
  })

  it('shows the host its words for a refusal the form did not foresee, and saves nothing', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.launchCommands.refuseNext(
      'INVALID_ARGUMENT',
      'A program has 1 to 512 bytes, with no control, format, invisible or line-break characters. Character 1 of the program is U+0085, which is not allowed.'
    )
    settings(port)
    await person.type(await screen.findByTestId('launch-commands-name'), 'New')
    await person.type(screen.getByTestId('launch-commands-program'), 'new')
    await person.click(screen.getByTestId('launch-commands-save'))
    expect(await screen.findByTestId('launch-commands-refused')).toHaveTextContent(
      'Character 1 of the program is U+0085, which is not allowed.'
    )
    expect(controls.launchCommands.commands).toEqual([])
  })

  it('gives feedback for a refused character as it is typed, and sends nothing', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    settings(port)
    await person.type(await screen.findByTestId('launch-commands-name'), 'Agent')
    await person.type(screen.getByTestId('launch-commands-program'), 'ag\u200bent')
    expect(screen.getByTestId('launch-commands-feedback')).toHaveTextContent(
      'A program has 1 to 512 bytes, with no control, format, invisible or line-break characters. Character 3 of the program is U+200B, which is not allowed.'
    )
    await person.click(screen.getByTestId('launch-commands-save'))
    expect(controls.launchCommands.writes).toEqual([])
  })

  it('says a field left empty only once a save is tried', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    settings(port)
    await screen.findByTestId('launch-commands-form')
    expect(screen.queryByTestId('launch-commands-feedback')).toBeNull()
    await person.click(screen.getByTestId('launch-commands-save'))
    expect(screen.getByTestId('launch-commands-feedback')).toHaveTextContent('A name is needed.')
    await person.type(screen.getByTestId('launch-commands-name'), 'Agent')
    expect(screen.getByTestId('launch-commands-feedback')).toHaveTextContent('A program is needed.')
    expect(controls.launchCommands.writes).toEqual([])
  })

  it.each([
    ['powershell', 'a ~ at the start of an argument', 'A program that begins with ~ is looked for under the home folder.'],
    ['zsh', 'a leading ~', null]
  ] as const)(
    'tells the passed-as-written sentence in the form of the session\'s shell: %s',
    async (shell, said, home) => {
      const person = userEvent.setup()
      const { port } = fakeHost({ stockShell: shell })
      const created = await port.sessionCreate(
        {
          environment_id: ENVIRONMENT,
          presentation: 'invisible',
          shell: null,
          shell_mode: 'native_compat',
          cwd: '/Users/rs/work/notes',
          dimensions: null,
          worker_profile: 'desktop_bound',
          environment_snapshot: [],
          palette: null,
          launch_profile: { startup: 'host_default', fenced_launch: false, command_integrations: [] },
          terminal: null
        },
        {}
      )
      open(port, 'semantic', created.value?.session.session_id ?? '')
      await person.click(await screen.findByRole('button', { name: 'Settings' }))
      await person.click(await screen.findByRole('button', { name: 'Launch commands' }))
      const passed = await screen.findByTestId('launch-commands-passed')
      await waitFor(() => {
        expect(passed).toHaveTextContent(said)
      })
      if (home === null) {
        expect(passed).toHaveTextContent(
          "The program and each argument are passed as written: a leading ~ or a $VARIABLE is not expanded, and there are no pipes or redirections. Use a full path, or a program on the shell's path."
        )
      } else {
        expect(passed).toHaveTextContent(
          "The program and each argument are passed as written: a $VARIABLE, or a ~ at the start of an argument, is not expanded, and there are no pipes or redirections. A program that begins with ~ is looked for under the home folder. Use a full path, or a program on the shell's path."
        )
      }
    }
  )

  it('opens with the words that say whose the list is, and tells the host does not serve it, or this device may not see it', async () => {
    const first = fakeHost()
    first.controls.launchCommands.scenario = 'not_served'
    settings(first.port)
    expect(await screen.findByTestId('launch-commands-not-served')).toHaveTextContent(
      'This host does not serve launch commands.'
    )
    expect(screen.getByTestId('launch-commands-whose').textContent).toMatch(
      /^A command is saved as written and shown to this host's owner devices\./
    )
    expect(screen.queryByTestId('launch-commands-form')).toBeNull()
  })

  it('tells a device without host.manage that it may not see the list', async () => {
    const { port, controls } = fakeHost()
    controls.setRights(['session.view'])
    settings(port)
    // No right, no read: the words are said without asking the host.
    expect(await screen.findByTestId('launch-commands-refused')).toHaveTextContent(
      "This device may not see this host's launch commands."
    )
    expect(controls.launchCommands.reads).toBe(0)
    expect(screen.queryByTestId('launch-commands-form')).toBeNull()
  })

  it('lists on a paired host and cannot change it', async () => {
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    controls.reachAsPairedDevice()
    settings(port)
    const list = await screen.findByTestId('launch-commands-list')
    expect(within(list).getAllByRole('listitem')).toHaveLength(2)
    expect(screen.queryByTestId('launch-commands-form')).toBeNull()
    expect(within(list).queryByRole('button')).toBeNull()
    expect(screen.getByTestId('launch-commands-local-only')).toHaveTextContent(
      'Launch commands can be changed only from the local connection to this host. Each environment keeps its own list.'
    )
  })

  it('lists the commands on the phone in Settings and cannot change them', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.launchCommands.changeElsewhere(SAVED)
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await screen.findByLabelText('Message this session')
    await person.click(await screen.findByRole('button', { name: /Settings/ }, { timeout: 2000 }))
    const list = await screen.findByTestId('launch-commands-list')
    expect(within(list).getAllByRole('listitem')).toHaveLength(2)
    expect(screen.queryByTestId('launch-commands-form')).toBeNull()
    expect(within(list).queryByRole('button')).toBeNull()
    expect(screen.getByTestId('launch-commands-local-only')).toBeInTheDocument()
  })
})
