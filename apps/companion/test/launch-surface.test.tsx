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

import type { ReactNode } from 'react'
import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider, useApp, type Place } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { UNVERIFIED_WORDS } from '../src/model/launch'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'
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

/** The buttons that start something. */
function offered(): HTMLElement[] {
  return within(screen.getByTestId('launch-surface'))
    .getAllByRole('button')
    .filter((each) => each.dataset.offer !== undefined)
}

/** Every button that starts something is disabled. */
function allDisabled(): void {
  for (const each of offered()) expect(each).toBeDisabled()
}

/** Every button that starts something is lit. */
function allLit(): void {
  for (const each of offered()) expect(each).toBeEnabled()
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
    allDisabled()
    expect(screen.getByTestId('launch-stale')).toHaveTextContent('The last launch was refused')
    expect(screen.queryByTestId('launch-refresh')).toBeNull()
    // The read the refusal asked for answers: the prompt is the new one, and the buttons are
    // disabled until the person has looked at it.
    await act(async () => {
      reads.release()
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(screen.getByTestId('launch-stale')).toHaveTextContent('The prompt changed')
    })
    expect(screen.getByTestId('launch-refresh')).toHaveTextContent('I have looked at the prompt')
    allDisabled()
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

  // A button is advice from a read, and a refusal says the advice was wrong. A read that answered
  // while the press waited was started before the refusal, so it says nothing of what the refusal
  // found: the buttons stay disabled until a read that started after it has landed.
  it('stay disabled while a launch waits, and after it is refused until a read made after it lands', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port, 'terminal')
    await takeControl(person)
    const surface = await screen.findByTestId('launch-surface')
    await waitFor(() => {
      expect(within(surface).getByRole('button', { name: 'Claude Code' })).toBeEnabled()
    })

    controls.refuseLaunches('EDITOR_BUSY', 'The terminal was busy.')
    const presses = controls.hold('launch')
    const reads = controls.hold('launchSurface')
    await person.click(within(surface).getByRole('button', { name: 'Claude Code' }))
    await waitFor(() => {
      expect(presses.count).toBe(1)
    })
    allDisabled()

    // A read is made and answered while the press waits, at the same prompt.
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'))
    })
    await waitFor(() => {
      expect(reads.count).toBe(1)
    })
    await act(async () => {
      reads.answer(0)
      await Promise.resolve()
    })
    allDisabled()

    await act(async () => {
      presses.release()
      await Promise.resolve()
    })
    expect(await screen.findByText(/The terminal was busy, so the launch was not installed/)).toBeInTheDocument()
    // The read the refusal asked for is the first one made after it.
    await waitFor(() => {
      expect(reads.count).toBe(2)
    })
    allDisabled()
    await act(async () => {
      reads.answer(1)
      await Promise.resolve()
    })
    await waitFor(allLit)
  })

  it('stay disabled after a refusal when a read that was on its way lands after it', async () => {
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
      document.dispatchEvent(new Event('visibilitychange'))
    })
    await waitFor(() => {
      expect(reads.count).toBe(1)
    })
    controls.refuseLaunches('EDITOR_BUSY', 'The terminal was busy.')
    await person.click(within(surface).getByRole('button', { name: 'Claude Code' }))
    expect(await screen.findByText(/The terminal was busy, so the launch was not installed/)).toBeInTheDocument()

    // The read on its way was started before the refusal: it does not light the buttons.
    await act(async () => {
      reads.answer(0)
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(reads.count).toBe(2)
    })
    allDisabled()
    await act(async () => {
      reads.answer(1)
      await Promise.resolve()
    })
    await waitFor(allLit)
  })
})

describe('what a read is taken to say', () => {
  /** A way to go to another session's terminal, as the session tabs are. */
  function GoTo({ sessionId }: { readonly sessionId: string }): ReactNode {
    const { go } = useApp()
    return (
      <button
        type="button"
        onClick={() => {
          go({ view: 'session', sessionId, pane: 'terminal' })
        }}
      >
        {`Go to ${sessionId}`}
      </button>
    )
  }

  // The view that read the surface is the one whose answer is shown: returning to a session opens
  // a new view, and the answer to the earlier one is not drawn under it before the new one has read.
  it('does not show an earlier view of the session under a new one', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    render(
      <AppProvider port={port} initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'terminal' }}>
        <App />
        <GoTo sessionId={SESSION_BUILD} />
        <GoTo sessionId={SESSION_MAIN} />
      </AppProvider>
    )
    await takeControl(person)
    await screen.findByTestId('launch-surface')

    const reads = controls.hold('launchSurface')
    const views = controls.terminalViews
    await person.click(screen.getByRole('button', { name: `Go to ${SESSION_BUILD}` }))
    await waitFor(() => {
      expect(views[1]?.launchReads).toBe(1)
    })
    await person.click(screen.getByRole('button', { name: `Go to ${SESSION_MAIN}` }))
    await waitFor(() => {
      expect(views[2]?.launchReads).toBe(1)
    })
    // The new view has read and has not been answered: nothing of the earlier view's answer is drawn.
    expect(screen.queryByTestId('launch-surface')).toBeNull()

    await act(async () => {
      reads.release()
      await Promise.resolve()
    })
    expect(await screen.findByTestId('launch-take-control')).toBeInTheDocument()
  })

  // A view is read only once it is attached: before that it has no link to ask on, and the first
  // thing the surface says must not be that the view is still opening.
  it('does not read a view before it is attached', async () => {
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    open(port, 'terminal')
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    act(() => {
      controls.terminalViews[0]?.attach()
    })
    expect(await screen.findByTestId('launch-take-control')).toBeInTheDocument()
    expect(screen.queryByTestId('launch-unread')).toBeNull()
    expect(controls.terminalViews[0]?.launchReadsWhileOpening).toBe(0)
  })
})
