/**
 * Creating a session, and the difference between a managed shell and a stock one.
 *
 * Section 7: a stock shell is an explicit compatibility choice. It keeps creating, attaching,
 * detaching and closing, file transfer, agents and the terminal, and it does not claim the managed
 * empty-prompt Ctrl-D, the launch that installs a command or the reading of the shell's editor.
 * The difference is shown before the session exists and in its status, and a managed shell the
 * host cannot qualify is refused, never replaced with a stock one.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { SessionCreateParams } from '@kalareach/protocol'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { MobileSessions } from '../src/mobile/views/Places'

const ENVIRONMENT = '3f1a2c40-11aa-4b2c-9d3e-000000000001'

function open(port: HostPort, place: Place = { view: 'sessions' }): void {
  render(
    <AppProvider port={port} initialPlace={place}>
      <App />
    </AppProvider>
  )
}

/** Opens the creation sheet from the session list. */
async function startCreating(person: ReturnType<typeof userEvent.setup>): Promise<HTMLElement> {
  await person.click(await screen.findByRole('button', { name: 'New session' }))
  return screen.findByTestId('sheet')
}

/** What a stock shell's creation from this page asks for, in the directory `cwd`. */
function stockCreation(cwd: string): SessionCreateParams {
  return {
    environment_id: ENVIRONMENT,
    presentation: 'invisible',
    shell: null,
    shell_mode: 'native_compat',
    cwd,
    dimensions: null,
    worker_profile: 'desktop_bound',
    environment_snapshot: [],
    palette: null,
    launch_profile: { startup: 'host_default', fenced_launch: false, command_integrations: [] },
    terminal: null
  }
}

describe('creating a session (KR-REQ-07.21)', () => {
  it('offers a new session only once the connection says it may create one', async () => {
    const { port, controls } = fakeHost()
    open(port)
    expect(await screen.findByRole('button', { name: 'New session' })).toBeInTheDocument()
    act(() => {
      controls.setRights(['session.view', 'terminal.input'])
    })
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: 'New session' })).toBeNull()
    })
  })

  it('shows what a stock shell does not do before the session exists, and creates what was chosen', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port)
    const sheet = await startCreating(person)

    // Both shells, side by side, before anything is created: what differs and what does not.
    const difference = within(sheet).getByTestId('shell-difference')
    expect(difference).toHaveTextContent('Ctrl-D at an empty prompt')
    expect(difference).toHaveTextContent('Detaches this view, and the session keeps running')
    expect(difference).toHaveTextContent('Does what the shell does, and can close the session')
    expect(difference).toHaveTextContent('Start the agent at the prompt for you')
    expect(difference).toHaveTextContent('Show the command for you to type')
    expect(difference).toHaveTextContent('Attaching, detaching and closing')
    const managed = within(sheet).getByRole('radio', { name: /Managed shell/ })
    const stock = within(sheet).getByRole('radio', { name: /Stock shell/ })
    expect(managed).toBeChecked()
    expect(difference).toHaveAttribute('data-chosen', 'managed')

    await person.click(stock)
    expect(difference).toHaveAttribute('data-chosen', 'native_compat')
    // Nothing is created without a directory to start in.
    const create = within(sheet).getByRole('button', { name: 'Create session' })
    expect(create).toBeDisabled()
    await person.type(within(sheet).getByRole('textbox', { name: 'Directory' }), '/Users/rs/work/notes')
    await person.click(create)

    await waitFor(() => {
      expect(controls.sessionCreates).toHaveLength(1)
    })
    expect(controls.sessionCreates[0]).toEqual(stockCreation('/Users/rs/work/notes'))
    // The new session opens, and says in its status that its shell is a stock one.
    const status = await screen.findByTestId('shell-mode')
    expect(status).toHaveTextContent('Stock shell')
    expect(status).toHaveTextContent('Ctrl-D can close this session')
    expect(screen.queryByTestId('sheet')).toBeNull()
  })

  it('creates a managed shell by default, with its launch allowed', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port)
    const sheet = await startCreating(person)
    await person.type(within(sheet).getByRole('textbox', { name: 'Directory' }), '/Users/rs/work/web')
    await person.click(within(sheet).getByRole('button', { name: 'Create session' }))
    await waitFor(() => {
      expect(controls.sessionCreates).toHaveLength(1)
    })
    expect(controls.sessionCreates[0]).toEqual({
      ...stockCreation('/Users/rs/work/web'),
      shell_mode: 'managed',
      launch_profile: { startup: 'host_default', fenced_launch: true, command_integrations: [] }
    })
    // A managed session's status says nothing about a stock shell.
    await screen.findByRole('heading', { name: 'web' })
    expect(screen.queryByTestId('shell-mode')).toBeNull()
  })

  it('says why the host refused a managed shell, and a stock shell is only ever the person’s choice', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.withoutQualifiedShell()
    open(port)
    const sheet = await startCreating(person)
    await person.type(within(sheet).getByRole('textbox', { name: 'Directory' }), '/Users/rs/work/notes')
    await person.click(within(sheet).getByRole('button', { name: 'Create session' }))

    expect(await within(sheet).findByText('This host has no managed shell to start')).toBeInTheDocument()
    expect(sheet).toHaveTextContent(
      'no qualified shell packages are installed; KR_SHELL_PACKAGES names none either'
    )
    expect(controls.sessionCreates).toHaveLength(1)

    // Choosing a stock shell here chooses it and creates nothing; the person creates it.
    await person.click(within(sheet).getByRole('button', { name: 'Choose a stock shell' }))
    expect(within(sheet).getByRole('radio', { name: /Stock shell/ })).toBeChecked()
    expect(controls.sessionCreates).toHaveLength(1)
    await person.click(within(sheet).getByRole('button', { name: 'Create session' }))
    await waitFor(() => {
      expect(controls.sessionCreates).toHaveLength(2)
    })
    expect(controls.sessionCreates[1]?.shell_mode).toBe('native_compat')
  })

  it('labels a stock shell in the session list and in the session’s own settings', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    const created = await port.sessionCreate(stockCreation('/Users/rs/work/notes'), {})
    const sessionId = created.value?.session.session_id ?? ''
    open(port)

    const row = await screen.findByTestId('session-row-4')
    expect(within(row).getByText('Stock shell')).toBeInTheDocument()
    // Its root shell is at a prompt, which is the shell in the foreground rather than an agent.
    expect(within(row).getByText('Shell')).toBeInTheDocument()
    expect(within(await screen.findByTestId('session-row-1')).queryByText('Stock shell')).toBeNull()

    await person.click(row)
    await person.click(await screen.findByTestId('open-settings'))
    await person.click(await screen.findByRole('button', { name: 'This session' }))
    const shell = await screen.findByTestId('session-shell')
    expect(shell).toHaveTextContent('Stock shell, /bin/zsh')
    expect(shell).toHaveTextContent('Launch buttons show the command for you to type')
    expect(shell).toHaveTextContent('Detach is always there')
    expect(sessionId).not.toBe('')
  })

  it('shows a stock shell’s launch buttons as the command to type, and types nothing', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    const launched: unknown[] = []
    const watched: HostPort = {
      ...port,
      shellLaunch: (params, subject) => {
        launched.push(params)
        return port.shellLaunch(params, subject)
      }
    }
    const created = await port.sessionCreate(stockCreation('/Users/rs/work/notes'), {})
    open(watched, { view: 'session', sessionId: created.value?.session.session_id ?? '', pane: 'semantic' })

    const surface = await screen.findByTestId('launch-instructions')
    expect(surface).toHaveTextContent('nothing is typed into it for you')
    expect(screen.queryByTestId('launch-surface')).toBeNull()
    await person.click(within(surface).getByRole('button', { name: 'Codex' }))
    expect(within(surface).getByTestId('launch-instruction')).toHaveTextContent('Type this at the prompt: codex')
    await person.click(within(surface).getByRole('button', { name: /Run the test suite/ }))
    expect(within(surface).getByTestId('launch-instruction')).toHaveTextContent(
      'Type this at the prompt: pnpm test'
    )
    // A command that is not installed here has nothing to type.
    expect(within(surface).getByRole('button', { name: 'Kimi' })).toBeDisabled()
    expect(launched).toEqual([])
  })

  it('lists a stock shell as one on the phone', async () => {
    const { port } = fakeHost()
    await port.sessionCreate(stockCreation('/Users/rs/work/notes'), {})
    render(
      <AppProvider port={port}>
        <MobileSessions surface="ios" onOpen={() => undefined} />
      </AppProvider>
    )
    const rows = await screen.findAllByRole('button', { name: /Session/ })
    const stock = rows.find((row) => row.textContent?.includes('Session 4'))
    expect(stock).toHaveTextContent('Stock shell')
    expect(rows.find((row) => row.textContent?.includes('Session 1'))).not.toHaveTextContent('Stock shell')
  })
})
