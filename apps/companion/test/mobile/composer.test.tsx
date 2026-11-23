/**
 * The phone's composer offers what the desktop's composer offers: the agent's slash commands, and
 * queueing, steering and interrupting a prompt, each only where the agent and the host allow it.
 */

import type { ReactNode } from 'react'
import type { Receipt } from '@kalareach/protocol'
import { describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AppProvider, useApp } from '../../src/app/state'
import { fakeHost } from '../../src/host/fake'
import { EVERY_RIGHT } from '../../src/host/fake-state'
import type { HostPort } from '../../src/host/port'
import { receivedFailure } from '../../src/host/tauri'
import { MobileSession } from '../../src/mobile/views/MobileSession'
import { useLifecycle } from '../../src/mobile/useLifecycle'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** The session view on its own, as the phone's shell renders it. */
function OnSession({ sessionId }: { readonly sessionId: string }): ReactNode {
  const lifecycle = useLifecycle(null)
  return (
    <MobileSession
      sessionId={sessionId}
      surface="ios"
      lifecycle={lifecycle}
      connected={true}
      onBack={() => undefined}
    />
  )
}

/** A receipt in which the host says it refused the action. */
function refusedReceipt(method: string): Receipt {
  return {
    action_id: '00000000-0000-4000-8000-00000000abcd',
    actor_id: 'owner:local',
    error: null,
    method,
    method_version: 1,
    payload_digest: '0'.repeat(64),
    reason: null,
    revision: '1',
    state: 'refused',
    updated_at_ms: '0',
    accepted_deadline_ms: null
  }
}

/** What the passing message says, which the shell draws in the app and these cases do without. */
function Said(): ReactNode {
  const { toast } = useApp()
  return <p data-testid="said">{toast?.text ?? ''}</p>
}

/**
 * Opens the session the fake host's agent is in, once its conversation has been read. `through`
 * wraps the host's port, to see what the screen asks of it or to answer it otherwise.
 */
async function open(
  through: (port: HostPort) => HostPort = (port) => port,
  prepare: (host: ReturnType<typeof fakeHost>) => void = () => undefined
): Promise<ReturnType<typeof fakeHost>> {
  const host = fakeHost()
  prepare(host)
  render(
    <AppProvider port={through(host.port)}>
      <OnSession sessionId={SESSION_MAIN} />
      <Said />
    </AppProvider>
  )
  await screen.findByText('Find why the reconnect test is flaky.')
  return host
}

describe("the phone's slash commands (KR-REQ-13.12)", () => {
  it('lists the commands the agent advertises when the draft starts with a slash, and narrows them as it is typed', async () => {
    const person = userEvent.setup()
    await open()
    const field = screen.getByLabelText('Message this session')

    await person.type(field, '/')
    const list = await screen.findByTestId('slash-commands')
    expect(within(list).getAllByRole('button').map((each) => each.textContent)).toEqual([
      '/compactShorten the conversation so far',
      '/modelChange the model for this session',
      '/reviewReview the current change set'
    ])

    await person.type(field, 're')
    expect(within(screen.getByTestId('slash-commands')).getAllByRole('button')).toHaveLength(1)
    expect(screen.getByRole('button', { name: /\/review/ })).toBeInTheDocument()
  })

  it('stands above the field, where a keyboard under it and a composer that scrolls from its top leave it in view', async () => {
    const person = userEvent.setup()
    await open()
    const field = screen.getByLabelText('Message this session')

    await person.type(field, '/')

    const list = await screen.findByTestId('slash-commands')
    expect(list.compareDocumentPosition(field)).toBe(Node.DOCUMENT_POSITION_FOLLOWING)
  })

  it('puts the chosen command in the field and closes the list', async () => {
    const person = userEvent.setup()
    await open()
    const field = screen.getByLabelText('Message this session')

    await person.type(field, '/mo')
    await person.click(screen.getByRole('button', { name: /\/model/ }))

    expect(field).toHaveValue('/model ')
    expect(screen.queryByTestId('slash-commands')).toBeNull()
  })

  it('lists nothing for a slash that no command starts with, and nothing for a draft without one', async () => {
    const person = userEvent.setup()
    await open()
    const field = screen.getByLabelText('Message this session')

    await person.type(field, '/zz')
    expect(screen.queryByTestId('slash-commands')).toBeNull()

    await person.clear(field)
    await person.type(field, 'review the change')
    expect(screen.queryByTestId('slash-commands')).toBeNull()
  })

  it('tells a screen reader which list the field controls and how many commands it holds, and nothing once it closes', async () => {
    const person = userEvent.setup()
    await open()
    const field = screen.getByLabelText('Message this session')
    // A textbox does not take aria-expanded; the list is named by aria-controls while it shows.
    expect(field).not.toHaveAttribute('aria-expanded')
    expect(field).not.toHaveAttribute('aria-controls')
    // The status is a polite one that is there before it has anything to say, so a reader hears it.
    const status = screen.getByTestId('slash-count')
    expect(status).toHaveAttribute('role', 'status')
    expect(status).toHaveClass('visually-hidden')
    expect(status).toHaveTextContent(/^$/)

    await person.type(field, '/')
    const list = await screen.findByTestId('slash-commands')
    expect(field).not.toHaveAttribute('aria-expanded')
    expect(list.id).not.toBe('')
    expect(field).toHaveAttribute('aria-controls', list.id)
    expect(status).toHaveTextContent(/^3 commands$/)

    // The list changes length: one command is "1 command".
    await person.type(field, 're')
    expect(within(screen.getByTestId('slash-commands')).getAllByRole('button')).toHaveLength(1)
    expect(status).toHaveTextContent(/^1 command$/)

    await person.click(screen.getByRole('button', { name: /\/review/ }))
    expect(screen.queryByTestId('slash-commands')).toBeNull()
    expect(field).not.toHaveAttribute('aria-controls')
    expect(status).toHaveTextContent(/^$/)
  })

  it('says nothing of a list where the agent advertises no command', async () => {
    const person = userEvent.setup()
    await open((port) => ({
      ...port,
      agentCommands: async (params, opening) => ({ ...(await port.agentCommands(params, opening)), commands: [] })
    }))
    const field = screen.getByLabelText('Message this session')
    await person.type(field, '/')
    expect(screen.queryByTestId('slash-commands')).toBeNull()
    expect(screen.queryByTestId('slash-count')).toBeNull()
    expect(field).not.toHaveAttribute('aria-expanded')
    expect(field).not.toHaveAttribute('aria-controls')
  })

  it('says in the field that a slash asks for a command, where the agent advertises some', async () => {
    await open()
    expect(screen.getByLabelText('Message this session')).toHaveAttribute(
      'placeholder',
      'Message this session, or type / for a command'
    )
  })
})

describe("the phone's Queue (KR-REQ-13.12)", () => {
  it('is offered where the agent can queue a prompt, and the host is told which opening it is made under', async () => {
    const person = userEvent.setup()
    const queued: { text: string | null; draft: string | null; revision: string; opening: string | undefined }[] = []
    const host = await open((port) => ({
      ...port,
      composerQueue: (params, opening, mark) => {
        queued.push({
          text: params.text,
          draft: params.draft_id,
          revision: params.target.binding_revision,
          opening
        })
        return port.composerQueue(params, opening, mark)
      }
    }))
    const field = screen.getByLabelText('Message this session')
    const submitted = host.controls.submissions

    await person.type(field, 'then run the linter')
    await person.click(await screen.findByRole('button', { name: 'Queue' }))

    await waitFor(() => {
      expect(queued).toHaveLength(1)
    })
    expect(queued[0]).toMatchObject({ text: 'then run the linter', draft: null, revision: '4' })
    expect(typeof queued[0]?.opening).toBe('string')
    // It is a queued prompt, not a submitted one, and it leaves the field empty as a send does.
    expect(host.controls.submissions).toBe(submitted + 1)
    await waitFor(() => {
      expect(field).toHaveValue('')
    })
  })

  it('is not offered where the agent has not said it can queue, or the device was not granted prompting', async () => {
    await open(undefined, (host) => {
      host.controls.records.withoutCapability(SESSION_MAIN, 'agent.prompt.queue')
    })
    expect(screen.queryByRole('button', { name: 'Queue' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Send' })).toBeInTheDocument()
  })

  it('is not offered to a device that holds no right to prompt', async () => {
    const host = await open()
    await screen.findByRole('button', { name: 'Queue' })
    act(() => {
      host.controls.setRights(EVERY_RIGHT.filter((right) => right !== 'agent.prompt'))
    })
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: 'Queue' })).toBeNull()
    })
  })

  it('keeps what was typed when the host refuses the queued prompt', async () => {
    const person = userEvent.setup()
    await open((port) => ({
      ...port,
      composerQueue: () =>
        Promise.reject(
          receivedFailure({
            code: 'DRAFT_CONFLICT',
            message: 'The conversation moved on.',
            user_action: 'none',
            retry: 'no_retry'
          })
        )
    }))
    const field = screen.getByLabelText('Message this session')

    await person.type(field, 'then run the linter')
    await person.click(await screen.findByRole('button', { name: 'Queue' }))

    expect(await screen.findByText('Refused by the host')).toBeInTheDocument()
    expect(field).toHaveValue('then run the linter')
  })

  it('is held with Send while an earlier action has no confirmed outcome', async () => {
    const person = userEvent.setup()
    const host = await open()
    const field = screen.getByLabelText('Message this session')
    host.controls.leaveNextSendUnconfirmed()

    await person.type(field, 'run the migration')
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await screen.findByTestId('composer-send-anyway')
    await person.type(field, 'and then the seed')

    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Queue' })).toBeDisabled()
  })
})

describe("the phone's Steer (KR-REQ-13.12)", () => {
  it('sends the running turn and the text, and leaves the text where it was written', async () => {
    const person = userEvent.setup()
    const steered: { turn: string; text: string; revision: string; opening: string | undefined }[] = []
    await open((port) => ({
      ...port,
      composerSteer: (params, opening) => {
        steered.push({
          turn: params.turn_id,
          text: params.text,
          revision: params.target.binding_revision,
          opening
        })
        return port.composerSteer(params, opening)
      }
    }))
    const field = screen.getByLabelText('Message this session')

    await person.type(field, 'use the other file')
    await person.click(await screen.findByRole('button', { name: 'Steer' }))

    await waitFor(() => {
      expect(steered).toHaveLength(1)
    })
    expect(steered[0]).toMatchObject({ turn: 'turn-9', text: 'use the other file', revision: '4' })
    expect(typeof steered[0]?.opening).toBe('string')
    expect(field).toHaveValue('use the other file')
    expect(screen.getByRole('button', { name: 'Steer' })).toBeEnabled()
  })

  it('is off until something is written to steer with', async () => {
    const person = userEvent.setup()
    await open()
    expect(await screen.findByRole('button', { name: 'Steer' })).toBeDisabled()
    await person.type(screen.getByLabelText('Message this session'), 'x')
    expect(screen.getByRole('button', { name: 'Steer' })).toBeEnabled()
  })

  it('is not offered while no turn runs, and not where the agent has not said it can steer', async () => {
    await open(undefined, (host) => {
      host.controls.records.endTurn(SESSION_MAIN)
    })
    expect(screen.queryByRole('button', { name: 'Steer' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Queue' })).toBeInTheDocument()
    cleanup()

    await open(undefined, (host) => {
      host.controls.records.withoutCapability(SESSION_MAIN, 'agent.steer')
    })
    expect(screen.queryByRole('button', { name: 'Steer' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Queue' })).toBeInTheDocument()
  })

  it('is held with Send while an earlier action has no confirmed outcome', async () => {
    const person = userEvent.setup()
    const host = await open()
    const field = screen.getByLabelText('Message this session')
    host.controls.leaveNextSendUnconfirmed()

    await person.type(field, 'run the migration')
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await screen.findByTestId('composer-send-anyway')
    await person.type(field, 'and then the seed')

    expect(screen.getByRole('button', { name: 'Steer' })).toBeDisabled()
  })
})

describe("the phone's Interrupt (KR-REQ-13.12)", () => {
  const INTERRUPT = 'Interrupt the current turn'

  it('interrupts the running turn, naming the conversation as it is now, and leaves what was written alone', async () => {
    const person = userEvent.setup()
    const interrupted: { turn: string; revision: string; opening: string | undefined }[] = []
    await open((port) => ({
      ...port,
      composerInterrupt: (params, opening) => {
        interrupted.push({
          turn: params.turn_id,
          revision: params.target.binding_revision,
          opening
        })
        return port.composerInterrupt(params, opening)
      }
    }))
    const field = screen.getByLabelText('Message this session')
    await person.type(field, 'half a thought')

    await person.click(await screen.findByRole('button', { name: INTERRUPT }))

    await waitFor(() => {
      expect(interrupted).toHaveLength(1)
    })
    expect(interrupted[0]).toMatchObject({ turn: 'turn-9', revision: '4' })
    expect(typeof interrupted[0]?.opening).toBe('string')
    expect(field).toHaveValue('half a thought')
  })

  it('is offered with nothing written, and not while no turn runs', async () => {
    await open()
    expect(await screen.findByRole('button', { name: INTERRUPT })).toBeEnabled()
    cleanup()

    await open(undefined, (host) => {
      host.controls.records.endTurn(SESSION_MAIN)
    })
    expect(screen.queryByRole('button', { name: INTERRUPT })).toBeNull()
  })

  it('is not offered where the agent has not said it can cancel, or the device was not granted it', async () => {
    await open(undefined, (host) => {
      host.controls.records.withoutCapability(SESSION_MAIN, 'agent.cancel')
    })
    expect(screen.queryByRole('button', { name: INTERRUPT })).toBeNull()
    cleanup()

    const host = await open()
    await screen.findByRole('button', { name: INTERRUPT })
    act(() => {
      host.controls.setRights(EVERY_RIGHT.filter((right) => right !== 'agent.cancel'))
    })
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: INTERRUPT })).toBeNull()
    })
  })

  it('is not held by a prompt on its way to the host, or by an action nobody knows the end of', async () => {
    const person = userEvent.setup()
    const host = await open()
    const field = screen.getByLabelText('Message this session')
    const held = host.controls.holdMutation()

    await person.type(field, 'run the tests')
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await waitFor(() => {
      expect(held.count).toBe(1)
    })
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    expect(screen.getByRole('button', { name: INTERRUPT })).toBeEnabled()
    held.release()

    host.controls.leaveNextSendUnconfirmed()
    await person.type(field, 'and the linter')
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await screen.findByTestId('composer-send-anyway')
    expect(screen.getByRole('button', { name: INTERRUPT })).toBeEnabled()
  })

  it('is sent once while it is on its way, however often it is pressed', async () => {
    const person = userEvent.setup()
    let answer: () => void = () => undefined
    let calls = 0
    await open((port) => ({
      ...port,
      composerInterrupt: (params, opening) => {
        calls += 1
        return new Promise((resolve) => {
          answer = () => {
            resolve(port.composerInterrupt(params, opening))
          }
        })
      }
    }))
    const button = await screen.findByRole('button', { name: INTERRUPT })

    await person.click(button)
    await person.click(button)
    await person.click(button)
    expect(calls).toBe(1)

    act(() => {
      answer()
    })
  })
})

describe("the composer under the phone's terminal (KR-REQ-13.12)", () => {
  /** Opens the terminal view of the session, once the agent has been read. */
  async function underTerminal(
    through: (port: HostPort) => HostPort = (port) => port
  ): Promise<ReturnType<typeof userEvent.setup>> {
    const person = userEvent.setup()
    await open(through)
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    return person
  }

  it('is the field and Send in one line, with Interrupt after them, and leaves Steer and Queue to the conversation', async () => {
    const person = await underTerminal()
    await person.type(screen.getByLabelText('Message this session'), 'ls')

    const send = screen.getByRole('button', { name: 'Send' })
    const interrupt = screen.getByRole('button', { name: 'Interrupt the current turn' })
    expect(interrupt).toBeEnabled()
    expect(screen.queryByRole('button', { name: 'Steer' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Queue' })).toBeNull()
    // The line is one row: the three share a parent, in the order the keyboard reaches them.
    const line = send.parentElement
    expect(interrupt.parentElement).toBe(line)
    expect(screen.getByLabelText('Message this session').parentElement).toBe(line)
    expect(
      [...(line?.children ?? [])].map((each) => (each.tagName === 'TEXTAREA' ? 'field' : each.textContent))
    ).toEqual(['field', 'Send', '■'])
  })

  it('interrupts the running turn from the line', async () => {
    const interrupted: string[] = []
    const person = await underTerminal((port) => ({
      ...port,
      composerInterrupt: (params, opening) => {
        interrupted.push(params.turn_id)
        return port.composerInterrupt(params, opening)
      }
    }))

    await person.click(screen.getByRole('button', { name: 'Interrupt the current turn' }))

    await waitFor(() => {
      expect(interrupted).toEqual(['turn-9'])
    })
  })
})
// The test environment's `File` does not read itself; a phone's web view does.
if (typeof File.prototype.arrayBuffer !== 'function') {
  File.prototype.arrayBuffer = function arrayBuffer(this: File): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => {
        resolve(reader.result as ArrayBuffer)
      }
      reader.onerror = () => {
        reject(new Error('the file was not read'))
      }
      reader.readAsArrayBuffer(this)
    })
  }
}

/** The input that takes any file, in the picker the composer shows. */
function filesInput(): HTMLInputElement {
  const group = screen.getByRole('group', { name: 'Add an attachment' })
  const input = [...(group.parentElement?.querySelectorAll<HTMLInputElement>('input[type="file"]') ?? [])].find(
    (each) => each.getAttribute('accept') === '*/*'
  )
  if (input === undefined) throw new Error('no file input')
  return input
}

describe("the phone's Steer with a file on the draft, on a host it is not paired with (KR-REQ-13.12)", () => {
  const SENTENCE = 'A steer carries text only. Remove the files on this draft to steer with it.'
  const uploads: readonly [string, (port: HostPort) => HostPort][] = [
    ['uploading', (port) => ({ ...port, attachmentUploadBytes: () => new Promise(() => undefined) })],
    ['uploaded and not accepted by the agent', (port) => port],
    [
      'not uploaded',
      (port) => ({ ...port, attachmentUploadBytes: () => Promise.reject(new Error('the upload failed')) })
    ]
  ]

  for (const [state, through] of uploads) {
    it(`is off while a file is ${state}, and says why, as Send is off for it`, async () => {
      const person = userEvent.setup({ applyAccept: false })
      const steered: string[] = []
      await open((port) =>
        through({
          ...port,
          composerSteer: (params, opening) => {
            steered.push(params.text)
            return port.composerSteer(params, opening)
          }
        })
      )
      await person.type(screen.getByLabelText('Message this session'), 'use the other file')
      expect(await screen.findByRole('button', { name: 'Steer' })).toBeEnabled()

      await person.upload(filesInput(), new File([new Uint8Array(12)], 'notes.pdf', { type: 'application/pdf' }))

      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Steer' })).toBeDisabled()
      })
      expect(screen.getByText(SENTENCE)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
      expect(steered).toEqual([])
    })
  }
})

describe('the phone refuses text longer than one prompt carries before it sends it (KR-REQ-13.12)', () => {
  const LONG = 'é'.repeat(40_000)

  for (const action of ['Send', 'Queue', 'Steer'] as const) {
    it(`keeps the text and sends nothing for ${action}`, async () => {
      const person = userEvent.setup()
      const calls: string[] = []
      await open((port) => ({
        ...port,
        composerSubmit: (params, opening, supersedes, mark) => {
          calls.push('submit')
          return port.composerSubmit(params, opening, supersedes, mark)
        },
        composerQueue: (params, opening, mark) => {
          calls.push('queue')
          return port.composerQueue(params, opening, mark)
        },
        composerSteer: (params, opening) => {
          calls.push('steer')
          return port.composerSteer(params, opening)
        }
      }))
      const field = screen.getByLabelText('Message this session')
      // 40,000 accented letters are 80,000 bytes of UTF-8, over the 65,536 that one prompt may be.
      fireEvent.change(field, { target: { value: LONG } })
      await screen.findByRole('button', { name: 'Steer' })

      await person.click(await screen.findByRole('button', { name: action }))
      // The person is told, in the desktop's words, that it was too long and that it is kept.
      await waitFor(() => {
        expect(screen.getByTestId('said')).toHaveTextContent('That is longer than one prompt carries. It is kept here.')
      })
      await new Promise((resolve) => setTimeout(resolve, 50))

      expect(calls).toEqual([])
      expect(field).toHaveValue(LONG)
      expect(screen.queryByText('Queued on this device')).toBeNull()
      // Text that fits goes, so the refusal was about the length.
      fireEvent.change(field, { target: { value: 'é'.repeat(30_000) } })
      await person.click(screen.getByRole('button', { name: action }))
      await waitFor(() => {
        expect(calls).toHaveLength(1)
      })
    })
  }
})


describe("the phone's composer on a window too short for the whole composer (KR-REQ-13.12)", () => {
  /** Lays the session out `lines` lines high, as jsdom lays nothing out. */
  function sessionOf(lines: { height: number }): () => void {
    document.documentElement.style.fontSize = '16px'
    const heights = vi.spyOn(Element.prototype, 'clientHeight', 'get').mockImplementation(function (this: Element) {
      return this.classList.contains('m-session') ? lines.height : 0
    })
    return () => {
      heights.mockRestore()
      document.documentElement.style.removeProperty('font-size')
    }
  }

  it('puts the three actions in a row above the line that holds the field and Send', async () => {
    const person = userEvent.setup()
    const end = sessionOf({ height: 20 * 16 })
    try {
      await open()
      await waitFor(() => {
        expect(document.querySelector('.m-session')).toHaveAttribute('data-composer', 'line')
      })
      await person.type(screen.getByLabelText('Message this session'), 'use the other file')

      const row = document.querySelector('.m-composer-more')
      const line = document.querySelector('.m-composer-line')
      expect(row).not.toBeNull()
      expect(
        [...(row?.querySelectorAll('button') ?? [])].map((each) => each.getAttribute('data-testid'))
      ).toEqual(['composer-interrupt', 'composer-steer', 'composer-queue'])
      expect([...(line?.children ?? [])].map((each) => (each.tagName === 'TEXTAREA' ? 'field' : each.textContent))).toEqual([
        'field',
        'Send'
      ])
      // The row comes first, so it is also what the keyboard reaches first.
      expect(row?.compareDocumentPosition(line as Node)).toBe(Node.DOCUMENT_POSITION_FOLLOWING)
    } finally {
      end()
    }
  })

  it('keeps the focus on an action when the window changes between the two forms', async () => {
    const person = userEvent.setup()
    const size = { height: 40 * 16 }
    const end = sessionOf(size)
    try {
      await open()
      await waitFor(() => {
        expect(document.querySelector('.m-session')).toHaveAttribute('data-composer', 'whole')
      })
      await person.type(screen.getByLabelText('Message this session'), 'use the other file')
      for (const name of ['Interrupt the current turn', 'Steer', 'Queue']) {
        screen.getByRole('button', { name }).focus()
        size.height = 20 * 16
        act(() => {
          window.dispatchEvent(new Event('resize'))
        })
        await waitFor(() => {
          expect(document.querySelector('.m-session')).toHaveAttribute('data-composer', 'line')
        })
        expect(screen.getByRole('button', { name }), `${name} in the line's form`).toHaveFocus()
        size.height = 40 * 16
        act(() => {
          window.dispatchEvent(new Event('resize'))
        })
        await waitFor(() => {
          expect(document.querySelector('.m-session')).toHaveAttribute('data-composer', 'whole')
        })
        expect(screen.getByRole('button', { name }), `${name} in the whole form`).toHaveFocus()
      }
    } finally {
      end()
    }
  })
})

describe("the phone's Interrupt, in the cases that hold its rules (KR-REQ-13.12)", () => {
  it('names the conversation as it is now, not the one the draft was written for', async () => {
    const person = userEvent.setup()
    const interrupted: { turn: string; revision: string }[] = []
    const host = await open((port) => ({
      ...port,
      composerInterrupt: (params, opening) => {
        interrupted.push({ turn: params.turn_id, revision: params.target.binding_revision })
        return port.composerInterrupt(params, opening)
      }
    }))
    await person.type(screen.getByLabelText('Message this session'), 'Keep the timer')

    // The agent moves to another conversation and begins a turn there; the view reads it again.
    host.controls.records.moveBinding(SESSION_MAIN)
    host.controls.records.startTurn(SESSION_MAIN)
    act(() => {
      host.controls.setConnected(true)
    })
    expect(await screen.findByText(/The conversation changed since this was written/)).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Interrupt the current turn' })).toBeEnabled()
    })

    await person.click(screen.getByRole('button', { name: 'Interrupt the current turn' }))

    await waitFor(() => {
      expect(interrupted).toHaveLength(1)
    })
    // The draft was written for revision 4; the conversation is at 5, and so is the interrupt.
    expect(interrupted[0]).toEqual({ turn: 'turn-10', revision: '5' })
    expect(screen.getByLabelText('Message this session')).toHaveValue('Keep the timer')
  })

  it('says that it was the interrupt the host refused, with nothing of what was written', async () => {
    const person = userEvent.setup()
    await open((port) => ({
      ...port,
      composerInterrupt: () =>
        Promise.resolve({ receipt: refusedReceipt('agent.cancel'), value: null, action_id: refusedReceipt('agent.cancel').action_id })
    }))
    await person.type(screen.getByLabelText('Message this session'), 'Keep the timer')

    await person.click(await screen.findByRole('button', { name: 'Interrupt the current turn' }))

    await waitFor(() => {
      expect(screen.getByTestId('said')).toHaveTextContent(/^The host refused the interrupt\.$/)
    })
    // The interrupt carries nothing the person wrote, and what they wrote is where it was.
    expect(screen.getByLabelText('Message this session')).toHaveValue('Keep the timer')
  })

  it('still says that what was written is kept when the host refuses a steer', async () => {
    const person = userEvent.setup()
    await open((port) => ({
      ...port,
      composerSteer: () =>
        Promise.resolve({ receipt: refusedReceipt('agent.steer'), value: null, action_id: refusedReceipt('agent.steer').action_id })
    }))
    await person.type(screen.getByLabelText('Message this session'), 'use the other file')

    await person.click(await screen.findByRole('button', { name: 'Steer' }))

    await waitFor(() => {
      expect(screen.getByTestId('said')).toHaveTextContent('The host refused it. What you wrote is still here.')
    })
  })

  it('can be sent again once the first has ended', async () => {
    const person = userEvent.setup()
    const answers: (() => void)[] = []
    let calls = 0
    await open((port) => ({
      ...port,
      composerInterrupt: () => {
        calls += 1
        return new Promise((resolve) => {
          answers.push(() => {
            resolve({
              receipt: null,
              value: {
                binding_revision: '4',
                provenance: 'upstream_typed_rpc',
                upstream_request_id: `"req-${calls}"`,
                turn_id: 'turn-9'
              },
              action_id: null
            })
          })
        })
      }
    }))
    const interrupt = await screen.findByRole('button', { name: 'Interrupt the current turn' })

    await person.click(interrupt)
    await person.click(interrupt)
    expect(calls).toBe(1)
    act(() => {
      answers[0]?.()
    })
    await screen.findByText('Applied')

    await person.click(interrupt)
    expect(calls).toBe(2)
    act(() => {
      answers[1]?.()
    })
  })
})

describe("the phone's actions made in one tick of the clock (KR-REQ-13.12)", () => {
  it('keeps a queued prompt nobody knows the end of apart from an interrupt made at the same instant', async () => {
    const person = userEvent.setup()
    // The clock does not move between the two presses, as it need not between two events.
    const clock = vi.spyOn(Date, 'now').mockReturnValue(1_800_000_000_000)
    try {
      const host = await open()
      const field = screen.getByLabelText('Message this session')
      host.controls.leaveNextSendUnconfirmed()
      const held = host.controls.holdMutation()

      // The queued prompt is on its way to the host, which has it and has not answered yet.
      await person.type(field, 'run the migration')
      await person.click(screen.getByRole('button', { name: 'Queue' }))
      await waitFor(() => {
        expect(held.count).toBe(1)
      })
      expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()

      // An interrupt is not held back by a prompt on its way, and is answered while that is.
      const interrupt = screen.getByRole('button', { name: 'Interrupt the current turn' })
      expect(interrupt).toBeEnabled()
      await person.click(interrupt)
      await screen.findByText('Applied')

      // The host's answer to the queued prompt then names no outcome: nobody knows its end.
      held.release()
      await screen.findByTestId('composer-send-anyway')

      // Each answer settled its own record. The interrupt is applied, the queued prompt is still one
      // nobody knows the end of, and it still holds the session though an interrupt is applied.
      expect(screen.getAllByText('Applied')).toHaveLength(1)
      expect(screen.getByText(/One action has no confirmed outcome yet/)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Queue' })).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Interrupt the current turn' })).toBeEnabled()
    } finally {
      clock.mockRestore()
    }
  })
})
