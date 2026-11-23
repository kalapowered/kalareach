/**
 * The phone's composer offers what the desktop's composer offers: the agent's slash commands, and
 * queueing, steering and interrupting a prompt, each only where the agent and the host allow it.
 */

import type { ReactNode } from 'react'
import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AppProvider } from '../../src/app/state'
import { fakeHost } from '../../src/host/fake'
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

/** Opens the session the fake host's agent is in, once its conversation has been read. */
async function open(): Promise<ReturnType<typeof fakeHost>> {
  const host = fakeHost()
  render(
    <AppProvider port={host.port}>
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
