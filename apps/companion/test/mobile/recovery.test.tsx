/**
 * A draft that came back through a break is bound to its conversation again, once the host says
 * where that conversation stands (KR-ACC-012).
 *
 * The draft is durable and the association is not: a suspension, a network change and a restart
 * each take the association away and leave the text. These render the shell that ships against the
 * scripted host and hold it to the other half: when contact is back the shell asks the host about
 * every draft it is keeping, in or out of the session on screen, and a draft whose conversation is
 * unchanged can be sent from again, a moved one is the person's to settle, and one whose read
 * failed is left exactly as it was. Nothing here ever sends anything on the person's behalf.
 */

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'

import { AppProvider } from '../../src/app/state'
import { fakeHost } from '../../src/host/fake'
import type { HostPort } from '../../src/host/port'
import { MobileApp } from '../../src/mobile/MobileApp'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** A storage that behaves like the device's own, so a test can restart the application over it. */
function fakeStorage(): Storage {
  const values = new Map<string, string>()
  return {
    get length() {
      return values.size
    },
    clear: () => {
      values.clear()
    },
    getItem: (key: string) => values.get(key) ?? null,
    key: (index: number) => [...values.keys()][index] ?? null,
    removeItem: (key: string) => {
      values.delete(key)
    },
    setItem: (key: string, value: string) => {
      values.set(key, value)
    }
  }
}

/** The page coming back to the front, which is what a suspension and a resume look like to it. */
function comeBack(): void {
  act(() => {
    document.dispatchEvent(new Event('visibilitychange'))
  })
}

/** A read of a session that fails the first `times` times it is asked, as a host out of reach does. */
function unreachableAtFirst(port: HostPort, times: number): { port: HostPort; asked: string[] } {
  const asked: string[] = []
  let failures = 0
  return {
    asked,
    port: {
      ...port,
      sessionRead: (params) => {
        asked.push((params as { session_id?: string }).session_id ?? '')
        if (failures < times) {
          failures += 1
          return Promise.reject({ code: 'UNAVAILABLE', message: 'The host did not answer.', user_action: 'retry' })
        }
        return port.sessionRead(params)
      }
    }
  }
}

/** A promise a test settles when it chooses, for a read that is on its way. */
function deferred(): { promise: Promise<void>; release: () => void } {
  let release: () => void = () => undefined
  const promise = new Promise<void>((resolve) => {
    release = resolve
  })
  return { promise, release }
}

/** Lets what a settled promise sets off run, inside the act it is called from. */
async function flush(): Promise<void> {
  for (let tick = 0; tick < 50; tick += 1) {
    await Promise.resolve()
  }
}

async function openMainSession(person: ReturnType<typeof userEvent.setup>): Promise<HTMLElement> {
  await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
  await person.click(await screen.findByRole('button', { name: /Session 1/ }))
  return await screen.findByLabelText('Message this session')
}

function shell(port: HostPort, storage: Storage) {
  return (
    <AppProvider port={port}>
      <MobileApp surface="ios" storage={storage} />
    </AppProvider>
  )
}

afterEach(cleanup)

describe('a draft that came back is bound again when the host has said where it stands (KR-ACC-012)', () => {
  it('binds a draft kept across a restart, and sends nothing to do it', async () => {
    const person = userEvent.setup()
    const storage = fakeStorage()
    const first = fakeHost()
    const run = render(shell(first.port, storage))
    await person.type(await openMainSession(person), 'half a thought')
    run.unmount()

    // The next run is a new process. The host is out of reach for its first read, so the draft is
    // kept and detached, and says so.
    const second = fakeHost()
    const { port, asked } = unreachableAtFirst(second.port, 1)
    render(shell(port, storage))
    expect(await openMainSession(person)).toHaveValue('half a thought')
    await waitFor(() => {
      expect(screen.getByText(/1 draft kept/)).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    expect(screen.getByText(/Not in contact with this host/)).toBeInTheDocument()

    // The host is reached when the application comes back to the front, and the draft binds.
    comeBack()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
    expect(screen.queryByText(/draft kept/)).toBeNull()
    expect(screen.getByLabelText('Message this session')).toHaveValue('half a thought')
    expect(asked).toContain(SESSION_MAIN)
    expect(second.controls.actions).toEqual([])
  })

  it('binds a draft again after a suspension that left the connection up', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    render(shell(port, fakeStorage()))
    await person.type(await openMainSession(person), 'kept through a suspension')
    expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()

    comeBack()
    // The suspension took the association away, and it stays away until the host has been asked.
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
    expect(screen.getByLabelText('Message this session')).toHaveValue('kept through a suspension')
    expect(controls.actions).toEqual([])
  })

  it('asks the host about a draft in a session that is not on screen', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    const counted = unreachableAtFirst(port, 0)
    render(shell(counted.port, fakeStorage()))
    await person.type(await openMainSession(person), 'written in session one')
    await person.click(screen.getByRole('button', { name: 'Back to sessions' }))
    counted.asked.length = 0

    comeBack()

    await waitFor(() => {
      expect(counted.asked).toContain(SESSION_MAIN)
    })
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    expect(await screen.findByLabelText('Message this session')).toHaveValue('written in session one')
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
  })

  it('leaves a moved conversation to the person rather than sending the draft to it', async () => {
    const person = userEvent.setup()
    const storage = fakeStorage()
    const first = fakeHost()
    const run = render(shell(first.port, storage))
    await person.type(await openMainSession(person), 'for the old conversation')
    // The conversation is read once, so the draft learns which one it was written for.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
    run.unmount()

    const second = fakeHost()
    second.controls.records.moveBinding(SESSION_MAIN)
    render(shell(second.port, storage))
    await openMainSession(person)

    await waitFor(() => {
      expect(screen.getByText(/The conversation changed since this was written/)).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    expect(screen.getByText(/1 needs a new destination/)).toBeInTheDocument()
    expect(second.controls.actions).toEqual([])
  })

  it('orphans a draft whose session the host no longer knows', async () => {
    const person = userEvent.setup()
    const storage = fakeStorage()
    const first = fakeHost()
    const run = render(shell(first.port, storage))
    await person.type(await openMainSession(person), 'for a session that went')
    run.unmount()

    const second = fakeHost()
    const gone: HostPort = {
      ...second.port,
      sessionRead: () =>
        Promise.reject({ code: 'UNKNOWN_SESSION', message: 'That session is not on this host.', user_action: 'none' })
    }
    render(shell(gone, storage))
    await openMainSession(person)

    await waitFor(() => {
      expect(screen.getByText(/1 lost its session/)).toBeInTheDocument()
    })
    expect(screen.getByLabelText('Message this session')).toHaveValue('for a session that went')
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
  })

  it('asks again after each suspension that follows a failed read, and not while contact continues', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const { port: flaky, asked } = unreachableAtFirst(port, 2)
    render(shell(flaky, fakeStorage()))
    await person.type(await openMainSession(person), 'kept through two suspensions')

    comeBack()
    await waitFor(() => {
      expect(asked).toHaveLength(1)
    })
    // The read failed, so the draft is as it was, and nothing asks again by itself.
    await act(flush)
    expect(asked).toHaveLength(1)
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()

    // The next suspension is the same kind of resumption as the last, and asks again.
    comeBack()
    await waitFor(() => {
      expect(asked).toHaveLength(2)
    })
    await act(flush)
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()

    comeBack()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
    expect(asked).toHaveLength(3)
    expect(controls.actions).toEqual([])
  })

  it('binds a draft once contact is back after a suspension that came while the host was out of reach', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    render(shell(port, fakeStorage()))
    await person.type(await openMainSession(person), 'kept through a lost connection')

    act(() => {
      controls.setConnected(false)
    })
    comeBack()
    await act(flush)
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()

    act(() => {
      controls.setConnected(true)
    })
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
    expect(controls.actions).toEqual([])
  })

  it('drops an answer that arrives after contact was lost', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const held = deferred()
    const reached = deferred()
    let holding = false
    // The last read of the three answers late, so only its own continuation is left to run.
    const slow: HostPort = {
      ...port,
      agentCapabilities: async (params) => {
        const read = await port.agentCapabilities(params)
        if (holding) {
          reached.release()
          await held.promise
        }
        return read
      }
    }
    render(shell(slow, fakeStorage()))
    await person.type(await openMainSession(person), 'kept through a dropped answer')

    holding = true
    comeBack()
    await reached.promise
    act(() => {
      controls.setConnected(false)
    })
    holding = false
    await act(async () => {
      held.release()
      await flush()
    })
    // The answer was for a connection that is gone, so it binds nothing: the draft is still kept.
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    expect(screen.getByText(/1 draft kept/)).toBeInTheDocument()

    act(() => {
      controls.setConnected(true)
    })
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
  })

  it('keeps what was typed while the host was being asked', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    const held = deferred()
    let holding = false
    const slow: HostPort = {
      ...port,
      sessionRead: async (params) => {
        if (holding) await held.promise
        return await port.sessionRead(params)
      }
    }
    render(shell(slow, fakeStorage()))
    await person.type(await openMainSession(person), 'before')
    holding = true
    comeBack()
    await act(flush)

    await person.type(screen.getByLabelText('Message this session'), ' and after')
    await act(async () => {
      held.release()
      await flush()
    })
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
    expect(screen.getByLabelText('Message this session')).toHaveValue('before and after')
  })

  it('does not let a key pressed as the host answers undo the binding', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    const held = deferred()
    let holding = false
    const slow: HostPort = {
      ...port,
      sessionRead: async (params) => {
        if (holding) await held.promise
        return await port.sessionRead(params)
      }
    }
    render(shell(slow, fakeStorage()))
    await person.type(await openMainSession(person), 'before')
    holding = true
    comeBack()
    await act(flush)

    // The answer is applied and a key press is handled before the page renders either.
    await act(async () => {
      held.release()
      await flush()
      fireEvent.change(screen.getByLabelText('Message this session'), { target: { value: 'before!' } })
    })
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
    expect(screen.getByLabelText('Message this session')).toHaveValue('before!')
  })

  it('orphans a draft whose session the host reports as closed', async () => {
    const person = userEvent.setup()
    const storage = fakeStorage()
    const first = fakeHost()
    const run = render(shell(first.port, storage))
    await person.type(await openMainSession(person), 'for a session that closed')
    run.unmount()

    const second = fakeHost()
    const closed: HostPort = {
      ...second.port,
      sessionRead: async (params) => {
        const read = await second.port.sessionRead(params)
        return { ...read, session: { ...read.session, state: 'closed' } }
      },
      sessionAgents: () =>
        Promise.reject({ code: 'UNKNOWN_SESSION', message: 'No worker holds that session.', user_action: 'none' })
    }
    render(shell(closed, storage))
    await openMainSession(person)

    await waitFor(() => {
      expect(screen.getByText(/1 lost its session/)).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    // The text is kept where it was, and nothing was sent to anywhere on its account.
    expect(screen.getByLabelText('Message this session')).toHaveValue('for a session that closed')
    expect(second.controls.submissions).toBe(0)
  })
})

