/**
 * What the launch surface draws, and what a press does (KR-REQ-13.11).
 *
 * The scripted host answers with what a real worker answered in each state a companion can meet
 * (`fixtures/shell-launch`, which the worker's own case holds), and takes a launch as the worker does:
 * only from a view that holds the session's input, and only at the prompt the quote names. What is
 * checked is what the page makes of those answers: a button is lit only at a verified empty prompt
 * on the link that holds the input, every other row of the table is words, and a press whose quote
 * went stale is refused by the host, shows no success, and is followed by a read.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { UNVERIFIED_WORDS } from '../src/model/launch'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const ENVIRONMENT = '3f1a2c40-11aa-4b2c-9d3e-000000000001'

function open(port: HostPort, pane: 'semantic' | 'terminal', sessionId = SESSION_MAIN): void {
  const place: Place = { view: 'session', sessionId, pane }
  render(
    <AppProvider port={port} initialPlace={place}>
      <App />
    </AppProvider>
  )
}

/** The raw view, with the person's press on "Take control" and the session's grant of it. */
async function takeControl(person: ReturnType<typeof userEvent.setup>): Promise<void> {
  await screen.findByTestId('palette-provenance')
  await person.click(screen.getByRole('button', { name: 'Take control' }))
  await waitFor(() => {
    expect(screen.getByTestId('terminal-mode')).toHaveTextContent('Control')
  })
}

/** The buttons that start something, by their labels. */
function buttons(): string[] {
  return within(screen.getByTestId('launch-surface'))
    .getAllByRole('button')
    .filter((each) => each.dataset.offer !== undefined)
    .map((each) => each.textContent ?? '')
}

describe('the rows of the table that are words', () => {
  it('says the host does not serve the read, and draws no button', async () => {
    const { port, controls } = fakeHost()
    controls.launchScenario('not_served')
    open(port, 'semantic')
    expect(await screen.findByTestId('launch-not-served')).toHaveTextContent('not available on this host')
    expect(screen.queryByTestId('launch-surface')).toBeNull()
  })

  it('says to take control of the terminal where nobody holds the input and no fence stands', async () => {
    const { port } = fakeHost()
    open(port, 'semantic')
    expect(await screen.findByTestId('launch-take-control')).toHaveTextContent(
      'Take control of the terminal to start something here'
    )
    expect(screen.queryByTestId('launch-surface')).toBeNull()
  })

  it('says this device can look but not start, whatever the prompt is', async () => {
    const { port, controls } = fakeHost()
    controls.setRights(['session.view'])
    controls.launchScenario('verified_held_here')
    open(port, 'semantic')
    expect(await screen.findByTestId('launch-cannot-start')).toHaveTextContent('can look but not start')
    expect(screen.queryByTestId('launch-surface')).toBeNull()
  })

  it.each([
    ['changed_since_fence', 'changed_since_fence'],
    ['not_at_prompt', 'not_at_prompt'],
    ['launch_in_progress', 'launch_in_progress']
  ] as const)('gives the reason the prompt is not one to start at: %s', async (scenario, reason) => {
    const { port, controls } = fakeHost()
    controls.launchScenario(scenario)
    open(port, 'semantic')
    const line = await screen.findByTestId('launch-unverified')
    expect(line).toHaveAttribute('data-reason', reason)
    expect(line).toHaveTextContent(UNVERIFIED_WORDS[reason])
    expect(screen.queryByTestId('launch-surface')).toBeNull()
  })

  it('shows the command to type at a stock shell, and lights nothing', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
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
    await person.click(within(instructions).getByRole('button', { name: 'Claude Code' }))
    expect(within(instructions).getByTestId('launch-instruction')).toHaveTextContent(
      'Type this at the prompt: claude'
    )
  })
})

describe('the buttons that start something', () => {
  it('are drawn disabled on the conversation, which holds no input', async () => {
    const { port, controls } = fakeHost()
    controls.launchScenario('verified_held_here')
    open(port, 'semantic')
    const surface = await screen.findByTestId('launch-surface')
    expect(buttons()).toEqual(['Claude Code', 'Codex CLI', 'Gemini CLI'])
    for (const each of within(surface).getAllByRole('button')) expect(each).toBeDisabled()
    expect(screen.getByTestId('launch-stale')).toHaveTextContent('terminal view')
  })

  it('are drawn disabled where another connection holds the terminal', async () => {
    const { port, controls } = fakeHost()
    controls.launchScenario('verified_held_elsewhere')
    open(port, 'terminal')
    const surface = await screen.findByTestId('launch-surface')
    expect(buttons()).toEqual(['Claude Code', 'Codex CLI', 'Gemini CLI'])
    for (const each of within(surface).getAllByRole('button')) expect(each).toBeDisabled()
    expect(screen.getByTestId('launch-stale')).toHaveTextContent("Another connection holds this terminal's input")
  })

  it('are lit on the terminal view once the person has taken control, and a press installs the command', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port, 'terminal')
    expect(await screen.findByTestId('launch-take-control')).toBeInTheDocument()
    await takeControl(person)

    const surface = await screen.findByTestId('launch-surface')
    expect(buttons()).toEqual(['Claude Code', 'Codex CLI', 'Gemini CLI'])
    for (const each of within(surface).getAllByRole('button')) expect(each).toBeEnabled()

    await person.click(within(surface).getByRole('button', { name: 'Claude Code' }))
    expect(await screen.findByText('Claude Code started.')).toBeInTheDocument()
    expect(controls.launches).toEqual([
      expect.objectContaining({ sessionId: SESSION_MAIN, command: { arguments: ['claude'] } })
    ])
  })

  // The prompt moved after the read the buttons were drawn from. The press quotes what the read
  // named; the host refuses it, nothing is shown as started, every button is disabled, and a read
  // follows. The read is decided by the host's recorded calls, not by waiting.
  it('are refused when the prompt moved, show no success, and are followed by a read', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port, 'terminal')
    await takeControl(person)
    const surface = await screen.findByTestId('launch-surface')
    await waitFor(() => {
      expect(within(surface).getByRole('button', { name: 'Claude Code' })).toBeEnabled()
    })

    const reads = controls.hold('launchSurface')
    act(() => {
      controls.changePromptGeneration()
    })
    await person.click(within(surface).getByRole('button', { name: 'Claude Code' }))

    await waitFor(() => {
      expect(reads.count).toBeGreaterThan(0)
    })
    expect(screen.queryByText('Claude Code started.')).toBeNull()
    expect(controls.launches).toEqual([])
    expect(await screen.findByText(/The prompt changed before the launch was installed/)).toBeInTheDocument()
    for (const each of within(screen.getByTestId('launch-surface')).getAllByRole('button')) {
      expect(each).toBeDisabled()
    }
    // The read the refusal asked for answers: the prompt is the new one, and the buttons are
    // disabled until the person has looked at it.
    await act(async () => {
      reads.release()
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(screen.getByTestId('launch-stale')).toBeInTheDocument()
    })
  })

  it('stay disabled when the prompt moves, until the person has looked at it', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port, 'terminal')
    await takeControl(person)
    const surface = await screen.findByTestId('launch-surface')
    await waitFor(() => {
      expect(within(surface).getByRole('button', { name: 'Claude Code' })).toBeEnabled()
    })

    act(() => {
      controls.changePromptGeneration()
      // The page is shown again, which reads the surface at once instead of a cadence later.
      document.dispatchEvent(new Event('visibilitychange'))
    })
    await waitFor(() => {
      expect(screen.getByTestId('launch-stale')).toHaveTextContent('The prompt changed')
    })
    expect(within(surface).getByRole('button', { name: 'Claude Code' })).toBeDisabled()

    await person.click(screen.getByTestId('launch-refresh'))
    expect(within(screen.getByTestId('launch-surface')).getByRole('button', { name: 'Claude Code' })).toBeEnabled()
    await person.click(within(screen.getByTestId('launch-surface')).getByRole('button', { name: 'Claude Code' }))
    expect(await screen.findByText('Claude Code started.')).toBeInTheDocument()
  })

  // An editor that could not say what became of the launch is not "nothing was typed": the command
  // may be on the prompt.
  it('say the editor could not confirm, and not that nothing was typed', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port, 'terminal')
    await takeControl(person)
    const surface = await screen.findByTestId('launch-surface')
    await waitFor(() => {
      expect(within(surface).getByRole('button', { name: 'Claude Code' })).toBeEnabled()
    })

    controls.refuseLaunches('OUTCOME_UNKNOWN', 'The reader could not confirm.')
    await person.click(within(surface).getByRole('button', { name: 'Claude Code' }))
    const said = await screen.findByText(/could not confirm whether the launch was installed/)
    expect(said).toBeInTheDocument()
    expect(said.textContent).not.toMatch(/Nothing was typed/)
    expect(screen.queryByText('Claude Code started.')).toBeNull()
  })
})
