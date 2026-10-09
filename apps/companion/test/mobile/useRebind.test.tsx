/**
 * What an answer about a draft's conversation may do once the page has moved on (KR-ACC-012).
 *
 * The shell asks the host where each detached draft stands and binds the drafts the answer clears.
 * An answer belongs to the question it was read for: one read before the application came back to
 * the front again, or before contact was lost, says nothing about the draft as it is now, and it
 * must be dropped even when the page has not yet rendered what changed. These drive the hook with
 * a resumption count of their own, so that moment can be held still.
 */

import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { useState, type ReactNode } from 'react'

import { useRebind } from '../../src/app/drafts'
import { AppProvider, useApp } from '../../src/app/state'
import { fakeHost } from '../../src/host/fake'
import type { HostPort } from '../../src/host/port'
import { connectionLost, edit, startDraft, type Draft } from '../../src/model/drafts'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

afterEach(cleanup)

/** A draft a break detached, written for the conversation the scripted host is in. */
function detachedDraft(): Draft {
  return connectionLost(
    edit(
      startDraft(
        `draft-${SESSION_MAIN}`,
        { sessionId: SESSION_MAIN, applicationInstanceId: null, agentBindingRevision: null },
        0
      ),
      'written before the break',
      1
    )
  )
}

/** The resumptions of the application, which the test declares by hand. */
function resumptions() {
  let count = 0
  return {
    resumption: { resumed: 0, resumedNow: () => count },
    resume: () => {
      count += 1
    }
  }
}

/** A port whose answer to the session read waits for `release`. */
function holdingTheSessionRead(): { port: HostPort; release: () => void } {
  const { port } = fakeHost()
  let release: () => void = () => undefined
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  return {
    release,
    port: {
      ...port,
      sessionRead: async (params) => {
        await gate
        return await port.sessionRead(params)
      }
    }
  }
}

/** The application, with the detached draft already in its book. */
const wrapperFor = (port: HostPort) =>
  function Wrapper({ children }: { readonly children: ReactNode }): ReactNode {
    return (
      <AppProvider port={port}>
        <Seeded>{children}</Seeded>
      </AppProvider>
    )
  }

function Seeded({ children }: { readonly children: ReactNode }): ReactNode {
  const { drafts } = useApp()
  useState(() => {
    drafts.setDrafts(() => [detachedDraft()])
    return null
  })
  return children
}

/** Lets the answer's chain of reads run to its end, which takes the scripted host a few turns. */
async function untilAnswered(): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => {
      setTimeout(resolve, 200)
    })
  })
}

describe('an answer about where a draft stands (KR-ACC-012)', () => {
  it('binds the draft it was read for when nothing came in between', async () => {
    const { port, release } = holdingTheSessionRead()
    const { resumption } = resumptions()
    const { result } = renderHook(
      () => {
        useRebind(true, resumption)
        return useApp().drafts
      },
      { wrapper: wrapperFor(port) }
    )

    release()
    await untilAnswered()

    expect(result.current.snapshot().drafts[0]?.state).toBe('bound')
  })

  it('drops an answer read before the application came back again, though the page has not rendered that', async () => {
    const { port, release } = holdingTheSessionRead()
    const { resumption, resume } = resumptions()
    const { result } = renderHook(
      () => {
        useRebind(true, resumption)
        return useApp().drafts
      },
      { wrapper: wrapperFor(port) }
    )

    // The application comes back to the front again; the page has rendered nothing yet.
    resume()
    release()
    await untilAnswered()

    expect(result.current.snapshot().drafts[0]?.state).toBe('detached')
  })

  it('asks nothing while the host is out of contact', async () => {
    const { port, release } = holdingTheSessionRead()
    const { resumption } = resumptions()
    const { result } = renderHook(
      () => {
        useRebind(false, resumption)
        return useApp().drafts
      },
      { wrapper: wrapperFor(port) }
    )

    release()
    await untilAnswered()

    expect(result.current.snapshot().drafts[0]?.state).toBe('detached')
  })
})
