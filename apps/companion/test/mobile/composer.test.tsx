/**
 * The phone's composer offers what the desktop's composer offers: the agent's slash commands, and
 * queueing, steering and interrupting a prompt, each only where the agent and the host allow it.
 */

import type { ReactNode } from 'react'
import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AppProvider } from '../../src/app/state'
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
